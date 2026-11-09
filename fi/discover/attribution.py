# -*- coding: utf-8 -*-
"""fi.discover.attribution：异常观测 → 指令级归因（芯片无关）。

## 这是"分析异常数据能力"的核心链路

输入：异常观测里的**码集合**（来自 CSV 的 response/unexpected 列，或日志/字节流）
     + 固件镜像 + 基址
输出：每个码 → 命令号 → handler 地址 → **装载该码的指令地址与指令文本**
     + 该 handler 的调用链（从复位入口可达路径）
     + 证据（原始字节、指令上下文、条目偏移）

链路：
   码  ←─ 装载指令（addi/li 立即数）
       ←─ handler 函数体（由分派表给出）
       ←─ 分派表项（cmd u8 / flag u8 / pad u16 / ptr u32）
       ←─ 分派器（间接跳转 c.jr t1）
       ←─ 命令接收与解析层
       ←─ 复位入口

## 纪律

- 芯片无关：不含任何具体码值/地址（全部由参数或数据给出）
- 每个结论带 confidence（hypothesis 起）与 evidence_kind
- 归因用的是**静态可达性 + 立即数匹配**，不等同于"运行时确实执行了这条指令"
  （运行期证据需仿真轨迹，字段 verified_by 留位）
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .common import Insn, linear_disasm, load_image, parse_imm, sha256_hex

SCHEMA = "fi.discover.attribution-v0"

_RE_LI = re.compile(r"^(?:c\.li|li|addi)\s+(\w+),\s*(?:zero,\s*)?(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_LUI = re.compile(r"^(?:c\.lui|lui)\s+(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_ADDI_RD = re.compile(r"^(?:c\.addi|addi)\s+(\w+),\s*(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_TERMINATOR = re.compile(r"^(?:ret|mret|j|jr|c\.jr|c\.j|c\.ret|ebreak)$")


def _sext12(v: int) -> int:
    v &= 0xFFF
    return v - 4096 if v >= 2048 else v


@dataclass
class CodeSite:
    code: int
    code_hex: str
    insn_addr: int
    insn_text: str
    dest_reg: str
    handler_entry: int
    command: int | None
    flag: int | None
    context: list[str] = field(default_factory=list)


def _walk_handler(disasm: list[Insn], start_addr: int,
                  next_handler_addr: int | None = None,
                  max_insns: int = 4000,
                  function_entries: set[int] | None = None) -> list[Insn]:
    """扫一个 handler 的函数体（用于收集其内部装载的常量）。

    边界策略（两轮实测教训叠加）：

    教训 1：**不能"遇到 ret/c.jr ra 就停"**——真实固件里一个 handler 常有多个
    返回点与内嵌分支，早期返回之后仍可能有码装载（样例实测：某码装载在第一个
    `c.jr ra` 之后，按"遇 ret 即停"会漏掉它）。

    教训 2（本轮修复）：**也不能只扫到"下一个 handler"**——dispatch 表里的
    handler 只覆盖命令入口，handler 与其后 handler 之间往往还夹着大量普通函数
    （样例实测：某 handler 与其后 handler 之间相隔 30 个函数边界、2846 字节，
    跨过去会把属于别处的码装载误归因到该 handler）。

    正确做法：扫到 **"下一个 handler" 或 "任一已知函数入口"（取更近者）** 为止。
    ``function_entries`` 由调用方提供（所有直接调用目标 = 已知函数入口）。
    这样既不漏掉"返回点之后的码装载"，也不会跨越函数边界误归因。
    """
    body: list[Insn] = []
    by_addr = {i.addr: i for i in disasm}
    addr = start_addr
    entries = function_entries or set()
    while addr in by_addr and len(body) < max_insns:
        if next_handler_addr is not None and addr >= next_handler_addr:
            break
        if addr != start_addr and addr in entries:
            # 撞到另一个已知函数入口 → 本函数体结束（防跨函数误归因）
            break
        insn = by_addr[addr]
        body.append(insn)
        nxt = addr + insn.size
        if nxt <= addr:          # 防死循环
            break
        addr = nxt
    return body


def attribute_codes(
    image_path: str,
    base: int,
    codes: list[int | str],
    *,
    xlen: int = 32,
    compressed: bool = True,
    dispatch_report: dict | None = None,
    max_context: int = 3,
    min_code_value: int = 0x0100,
) -> dict:
    """主入口：码集合 → 命令 → handler → 装载指令。

    ``codes`` 接受 int 或 "0x..." 字符串；出现顺序保留。
    ``dispatch_report`` 可传入已算好的 discover_dispatch() 结果以省一次解码。
    ``min_code_value``：低于此值的码不参与归因（默认 0x0100）。

    为什么需要 min_code_value（实测教训）：真实固件里大量 `c.li a5, 1` / `li a5, 6`
    这类**标志位/常量装载**与"码值 0x0001/0x0006"数值相同，会造成误归因。
    协议错误码通常是两位以上十六进制（如 0x<CODE_B>/0x<CODE_A>），设下限可有效抑制误配；
    调用方可显式传 0 关闭该保护（若确有低值码）。
    """
    from .dispatch import discover_dispatch

    image = load_image(image_path)
    disasm = linear_disasm(image, base, xlen=xlen, compressed=compressed)
    by_addr = {i.addr: i for i in disasm}

    if dispatch_report is None:
        dispatch_report = discover_dispatch(image_path, base, xlen=xlen,
                                           compressed=compressed)

    # 目标码归一化
    wanted: list[int] = []
    for c in codes:
        if isinstance(c, int):
            wanted.append(c)
        else:
            try:
                wanted.append(int(c, 16) if str(c).lower().startswith("0x") else int(c))
            except (ValueError, TypeError):
                continue
    wanted = list(dict.fromkeys(wanted))       # 去重保序
    low_value_skipped = [c for c in wanted if c < min_code_value]
    wanted = [c for c in wanted if c >= min_code_value]

    # 收集分派表项（取条目最多的那张表作为命令表）
    tables = [t for t in dispatch_report.get("recovered_tables", [])
              if t.get("table", {}).get("entry_count", 0) > 0]
    # 命令表选择：不能只按条目数（镜像里可能有更大的非命令表）。
    # 用"字段合法性"主导：flag 集中在 {0,1} 且 cmd 互异，才是命令表特征。
    from .dispatch import _phase_score
    tables.sort(key=lambda t: (_phase_score(t["table"].get("entries") or []),
                               t["table"]["entry_count"]), reverse=True)
    command_table = tables[0] if tables else None

    entries: list[dict] = []
    if command_table:
        for e in command_table["table"]["entries"]:
            fld = e.get("fields") or {}
            entries.append({
                "command": fld.get("byte0"),
                "flag": fld.get("byte1"),
                "handler": e["handler"],
                "entry_addr": e["entry_addr"],
                "raw_hex": e["raw_hex"],
            })

    # 对每个分派项：扫 handler 体，找装载了哪些目标码
    sites: list[CodeSite] = []
    handler_index: dict[int, dict] = {}
    # 预先算出 handler 的地址顺序，用于确定每个 handler 的扫描上界
    handler_sorted = sorted({
        int(e["handler"], 16) for e in entries
        if isinstance(e, dict) and e.get("handler")
    })
    # 所有直接调用目标 = 已知函数入口（handler 扫描的辅助边界，防跨函数误归因）
    function_entries: set[int] = set()
    for insn in disasm:
        if insn.mnemonic in ("jal", "c.jal"):
            try:
                imm = int(insn.operands.split(",")[-1], 0)
            except (ValueError, IndexError):
                continue
            tgt = (insn.addr + imm) & 0xFFFFFFFF
            if base <= tgt < base + len(image):
                function_entries.add(tgt)

    for ent in entries:
        try:
            h = int(ent["handler"], 16)
        except (ValueError, TypeError):
            continue
        handler_index[h] = ent
        # 扫描上界 = 下一个 handler 起点（最后一个 handler 则扫到镜像末尾）
        nxt = next((x for x in handler_sorted if x > h), None)
        body = _walk_handler(disasm, h, next_handler_addr=nxt,
                             function_entries=function_entries)
        # 两段常量构造跟踪（lui + addi，用于 >12 位的码值）
        # 注意：必须带**时间窗口**。早期版本在整个函数体内累积寄存器常量，
        # 导致 `addi a1, s1, 4` 里 s1 的陈旧值被当成 lui 高 20 位，
        # 算出 0x00000000 这类垃圾值并误命中（实测教训）。
        reg_val: dict[str, tuple[int, int]] = {}   # reg -> (value, insn_index)
        CONST_WINDOW = 4                            # lui 与 addi 的最大间隔（指令数）

        def _recent(reg: str, idx: int) -> int | None:
            item = reg_val.get(reg)
            if item is None:
                return None
            val, at = item
            return val if idx - at <= CONST_WINDOW else None

        for idx, insn in enumerate(body):
            # --- 通道 A：单条立即数装载（码值 ≤ 12 位可表示） ---
            m = _RE_LI.match(insn.text)
            if m:
                v = parse_imm(m.group(2))
                if v is not None:
                    dest = m.group(1)
                    reg_val[dest] = (v & 0xFFFFFFFF, idx)
                    if v & 0xFFFFFFFF in wanted or v in wanted:
                        code_val = v if v in wanted else (v & 0xFFFFFFFF)
                        lo = max(0, idx - max_context)
                        hi = min(len(body), idx + max_context + 1)
                        sites.append(CodeSite(
                            code=code_val,
                            code_hex=f"0x{code_val:04x}",
                            insn_addr=insn.addr,
                            insn_text=insn.text,
                            dest_reg=dest,
                            handler_entry=h,
                            command=ent.get("command"),
                            flag=ent.get("flag"),
                            context=[b.text for b in body[lo:hi]],
                        ))
                continue
            # --- 通道 B：lui 装载高 20 位（两段构造的起点） ---
            m = _RE_LUI.match(insn.text)
            if m:
                v = parse_imm(m.group(2))
                if v is not None:
                    reg_val[m.group(1)] = ((v << 12) & 0xFFFFFFFF, idx)
                continue
            # --- 通道 C：addi rd, rs1, imm 的常量合并（两段构造的收尾） ---
            m = _RE_ADDI_RD.match(insn.text)
            if m:
                rd, rs1, imm_s = m.group(1), m.group(2), m.group(3)
                imm = parse_imm(imm_s)
                base_val = _recent(rs1, idx) if imm is not None else None
                if imm is not None and base_val is not None:
                    full = (base_val + _sext12(imm)) & 0xFFFFFFFF
                    reg_val[rd] = (full, idx)
                    if full in wanted:
                        lo = max(0, idx - max_context)
                        hi = min(len(body), idx + max_context + 1)
                        sites.append(CodeSite(
                            code=full,
                            code_hex=f"0x{full:04x}",
                            insn_addr=insn.addr,
                            insn_text=f"{insn.text}  (lui+addi 合成 0x{full:08x})",
                            dest_reg=rd,
                            handler_entry=h,
                            command=ent.get("command"),
                            flag=ent.get("flag"),
                            context=[b.text for b in body[lo:hi]],
                        ))
                continue

    # 组装：码 → 站点列表
    per_code: list[dict] = []
    for code in wanted:
        hits = [s for s in sites if s.code == code]
        per_code.append({
            "code": f"0x{code:04x}",
            "code_dec": code,
            "handler_count": len({s.handler_entry for s in hits}),
            "site_count": len(hits),
            "sites": [
                {
                    "insn_addr": f"0x{s.insn_addr:08x}",
                    "insn": s.insn_text,
                    "dest_reg": s.dest_reg,
                    "command": (f"0x{s.command:02x}" if isinstance(s.command, int) else None),
                    "handler": f"0x{s.handler_entry:08x}",
                    "context": s.context,
                    "confidence": "hypothesis",
                    "evidence_kind": "artifact_derived",
                }
                for s in sorted(hits, key=lambda x: x.insn_addr)
            ],
            "attribution_status": (
                "attributed_to_handler" if hits else "not_found_in_dispatch_handlers"
            ),
            "confidence": "hypothesis",
        })

    attributed = sum(1 for p in per_code if p["attribution_status"] == "attributed_to_handler")

    # ---- 未归因码的成因分类（把"空白"变成有解释的结论）----
    # 对未归因的码，逐条给出"它在镜像里以何种形式存在（或不存在）"的客观事实，
    # 避免读者误以为"没归因 = 工具能力不足"或"该码不存在"。
    codepoints_hint = _classify_unattributed(image, wanted, per_code)

    return {
        "schema": SCHEMA,
        "tool": {"name": "fi.discover.attribution", "version": "0.1.0"},
        "image": {
            "path": str(image_path), "sha256": sha256_hex(image),
            "size_bytes": len(image), "base_address": base,
            "base_address_hex": f"0x{base:08x}",
        },
        "method": {
            "chain": [
                "码 ← 装载指令（addi/li 立即数匹配）",
                "← handler 函数体（分派表 ptr 字段）",
                "← 分派表项（命令表，字段偏移由结构推断）",
                "← 分派器间接跳转",
                "← 复位入口（可达性由 discover_chain 给出）",
            ],
            "boundaries": [
                "静态归因 ≠ 运行时执行证明：未匹配到站点不代表该码不由这些 handler 产生"
                "（码可能由运算生成、由调用者传入、或经共享发送函数统一装载）",
                "handler 边界用线性保守扫描，可能跨越到相邻函数",
                "分派表字段偏移（cmd/flag/ptr）为结构推断，语义需行为验证",
                "仅覆盖分派表给出的 handler；未经该表分派的路径（如直接调用）不在覆盖范围",
                "码值匹配为立即数精确相等；拼接/移位生成的码不会被检出",
            ],
        },
        "command_table": {
            "source_table_addr": command_table["source_table_addr"] if command_table else None,
            "entry_count": len(entries),
            "entries": entries,
        },
        "summary": {
            "codes_requested": len(wanted),
            "codes_attributed": attributed,
            "codes_unattributed": len(wanted) - attributed,
            "handlers_scanned": len(handler_index),
            "total_sites": len(sites),
            "codes_skipped_below_min_value": [f"0x{c:04x}" for c in low_value_skipped],
            "min_code_value": f"0x{min_code_value:04x}",
        },
        "attributions": per_code,
        "unattributed_analysis": codepoints_hint,
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


def _classify_unattributed(image: bytes, wanted: list[int],
                           per_code: list[dict]) -> dict:
    """对未归因的码给出客观成因分类（不推测机制，只陈述镜像层面的事实）。

    分类依据（全部可在镜像字节上复核）：
      - no_immediate_construct：立即数通道零命中（说明不由 addi/li 装载）
      - no_pair_construct：lui+addi 两段构造零命中
      - raw_bytes_absent：16/32 位任意字节序都找不到该值（极可能运行时计算或协议层定义）
      - raw_bytes_present_but_not_code：字节层面存在该值，但不在可达代码里（可能是数据/字符串/巧合）
    """
    import struct

    items: list[dict] = []
    for p in per_code:
        if p["attribution_status"] == "attributed_to_handler":
            continue
        v = p["code_dec"]
        le16 = image.count(struct.pack("<H", v & 0xFFFF))
        be16 = image.count(struct.pack(">H", v & 0xFFFF))
        le32 = image.count(struct.pack("<I", v & 0xFFFFFFFF))
        be32 = image.count(struct.pack(">I", v & 0xFFFFFFFF))
        if le32 == 0 and be32 == 0 and le16 == 0 and be16 == 0:
            klass = "raw_bytes_absent"
            note = ("镜像中任何字节序都找不到该值：极可能由运行时计算生成"
                    "（查表/运算/寄存器拼装）或由外部协议层定义，而非固件常量")
        elif le32 == 0 and be32 == 0:
            klass = "raw_bytes_present_16bit_only"
            note = (f"仅以 16 位形态出现（LE {le16} 次 / BE {be16} 次），无 32 位常量："
                    "可能是数据表项/字符串字节/指令编码巧合，而非代码中装载的常量")
        else:
            klass = "raw_bytes_present_but_not_in_code"
            note = (f"字节层面存在（LE32 {le32} 次 / BE32 {be32} 次）但不在可达代码的"
                    "立即数构造中：可能是数据段表项，或由非立即数路径传入")
        items.append({
            "code": p["code"],
            "classification": klass,
            "raw_byte_occurrences": {"le16": le16, "be16": be16,
                                     "le32": le32, "be32": be32},
            "interpretation": note,
            "confidence": "observation",
            "evidence_kind": "artifact",
        })
    return {
        "n_unattributed": len(items),
        "items": items,
        "discipline": (
            "本分类只陈述镜像字节层面的客观事实（可直接复核），"
            "不推断具体生成机制；'未归因'不等于'该码不存在'或'工具失败'"
        ),
    }
