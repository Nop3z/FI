# -*- coding: utf-8 -*-
"""fi.discover.dispatch：运行期分派表恢复（芯片无关）。

## 问题（实测教训，target-chip 样例验证）

ISP 命令分派表在**运行期位于 RAM**（由启动期 memcpy 从 ROM 源表拷贝而来），
分派器用 `lw ptr, 4(table); c.jr ptr` 间接跳转。纯静态扫描镜像数据段时：

  - 扫到的是 ROM 里的**其他**函数指针表（`known_entry_ratio = 0`）；
  - 真正的 19 个命令 handler **全部不在可达集合内**（实测：0x<ADDR> 未发现）；
  - 因此"从异常码反推打了哪条指令"在分派处断链。

## 解法（本模块）

1) 在代码里找**表项宽度/条目数**线索：`c.li aN, <count>` + `c.slli aN, 3`（×8）
   → 推断 entry_size 与 entry_count；
2) 找 memcpy 循环（`lw ... ; sw ... ; addi +size ; bne`）与其**源地址常量**，
   源地址落在镜像内 → 视为 ROM 侧源表；
3) 从源表按推断的 entry_size 解析表项，识别 ptr 字段（落在镜像内的 32 位值）；
4) 输出"命令号 → handler"候选映射（字段语义仍为 hypothesis：
   cmd/flag/pad/ptr 的偏移需人工或行为验证）。

## 纪律

- 芯片无关：无任何具体地址/命令号字面量
- 全部 hypothesis：表结构是结构推断
- 只把"落在镜像内的指针"当作 handler 候选，避免误收数据常量
"""
from __future__ import annotations

import re
import struct

from .common import Insn, linear_disasm, load_image, parse_imm, sha256_hex

SCHEMA = "fi.discover.dispatch-v0"

_RE_LI = re.compile(r"^(?:c\.li|li|addi)\s+(\w+),\s*(?:zero,\s*)?(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_SLLI = re.compile(r"^(?:c\.slli|slli)\s+(\w+),\s*(\w+),\s*(?:0x)?([0-9a-fA-F]+|\d+)$")
_RE_ADD = re.compile(r"^(?:c\.add|add)\s+(\w+),\s*(\w+),\s*(\w+)$")
_RE_LOAD = re.compile(r"^(?:c\.lw|lw|lbu|lhu|lb|lh)\s+(\w+),\s*([^,]*?)\((\w+)\)$")
_RE_STORE = re.compile(r"^(?:c\.sw|sw|sb|sh)\s+(\w+),\s*([^,]*?)\((\w+)\)$")
_RE_ADDI_SP = re.compile(r"^(?:c\.addi|addi)\s+(\w+),\s*(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_BNE = re.compile(r"^(?:c\.bne|bne|c\.bnez|bnez|bne)\s+(.*)$")
_RE_AUIPC = re.compile(r"^auipc\s+(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_LUI = re.compile(r"^(?:c\.lui|lui)\s+(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")


def _is_code_mapped(v: int, base: int, size: int) -> bool:
    return base <= v < base + size


def _find_table_shape(disasm: list[Insn]) -> list[dict]:
    """找 `li count` + `slli x, 3`（×8）组合，推断表项宽度与条目数线索。"""
    out: list[dict] = []
    reg_li: dict[str, tuple[int, int]] = {}
    for idx, insn in enumerate(disasm):
        if insn.text == "<undecoded>":
            continue
        m = _RE_LI.match(insn.text)
        if m:
            v = parse_imm(m.group(2))
            if v is not None and 0 < v < 0x1000:
                reg_li[m.group(1)] = (v, idx)
            continue
        m = _RE_SLLI.match(insn.text)
        if m:
            rd, rs1 = m.group(1), m.group(2)
            sh = parse_imm(m.group(3))
            if sh in (2, 3, 4) and rs1 in reg_li and idx - reg_li[rs1][1] <= 8:
                out.append({
                    "at": f"0x{insn.addr:08x}",
                    "entry_size": 1 << sh,
                    "count": reg_li[rs1][0],
                    "evidence": [disasm[reg_li[rs1][1]].text, insn.text],
                    "confidence": "hypothesis",
                })
    return out


def _find_memcpy_sources(disasm: list[Insn], base: int, size: int) -> list[dict]:
    """找 memcpy 循环的源地址常量：lw src ; sw dst ; addi +N ; bne 回跳。"""
    out: list[dict] = []
    reg_const: dict[str, int] = {}
    for idx, insn in enumerate(disasm):
        if insn.text == "<undecoded>":
            continue
        # 常量跟踪：auipc+lui+addi
        m = _RE_LUI.match(insn.text)
        if m:
            v = parse_imm(m.group(2))
            if v is not None:
                reg_const[m.group(1)] = (v << 12) & 0xFFFFFFFF
            continue
        m = _RE_AUIPC.match(insn.text)
        if m:
            v = parse_imm(m.group(2))
            if v is not None:
                reg_const[m.group(1)] = (insn.addr + ((v << 12) & 0xFFFFFFFF)) & 0xFFFFFFFF
            continue
        m = _RE_ADDI_SP.match(insn.text)
        if m and m.group(2) in reg_const:
            imm = parse_imm(m.group(3))
            if imm is not None:
                reg_const[m.group(1)] = (reg_const[m.group(2)] + imm) & 0xFFFFFFFF
            continue
        # 载入：lw rd, imm(rs1) —— rs1 是已知常量 → 绝对地址
        m = _RE_LOAD.match(insn.text)
        if m:
            rd, imm_s, rs1 = m.group(1), m.group(2), m.group(3)
            imm = parse_imm(imm_s) if imm_s.strip() else 0
            if rs1 in reg_const and imm is not None:
                src = (reg_const[rs1] + imm) & 0xFFFFFFFF
                # 向后 12 条内找 store + addi + branch → 判为拷贝循环
                for j in range(idx + 1, min(len(disasm), idx + 14)):
                    t = disasm[j].text
                    if _RE_STORE.match(t) and _RE_BNE.match(disasm[min(j + 1, len(disasm) - 1)].text):
                        out.append({
                            "src_addr": f"0x{src:08x}",
                            "src_in_image": _is_code_mapped(src, base, size),
                            "load_at": f"0x{insn.addr:08x}",
                            "loop_site": f"0x{disasm[j].addr:08x}",
                            "evidence": [insn.text, t],
                            "confidence": "hypothesis",
                        })
                        break
    # 去重（同一源地址只留一处）
    seen: set[str] = set()
    uniq: list[dict] = []
    for c in out:
        if c["src_addr"] in seen:
            continue
        seen.add(c["src_addr"])
        uniq.append(c)
    return uniq


def _parse_table(image: bytes, base: int, src_addr: int, entry_size: int,
                 max_entries: int, entry_count_hint: int | None) -> dict:
    """从源表解析表项；识别落在镜像内的 32 位指针字段。

    ## 相位判别（实测教训）

    指针游程的起点不一定等于表头：真实布局常见两种
      L1: [ptr u32 @0][cmd u8 @4][flag u8 @5][pad u16 @6]  → 表头 = 指针游程起点
      L2: [cmd u8 @0][flag u8 @1][pad u16 @2][ptr u32 @4]  → 表头 = 指针游程起点 - 4

    样例实测刻线：`10 01 00 00 | 14 15 00 21`（cmd=0x10, flag=1, pad=0, ptr=0x<ADDR>）。
    朴素取"指针游程起点"会得到 L1 的错相位，导致 cmd 与 handler 错配一位。

    本函数对两个候选相位分别解析，用**字段合法性**打分选优：
    flag 字节应集中在 {0,1}；cmd 字节应互不相同（命令表语义）。
    """
    # 1) 在 src_addr 附近搜索"表头"：对每个 4 字节对齐候选位置，用两种布局各解析一遍，
    #    取**条目数最多**的组合作为表头与布局。
    #    理由（实测教训）：memcpy 循环的源地址可能指向表内偏移处（样例实测差 0x7C），
    #    且布局可能是 ptr-first 或 cmd-first；用"能解释最多表项"的假设最稳。
    best: dict | None = None
    base_off = src_addr - base
    # 搜索窗口：±256 字节（覆盖"拷贝源地址指向表内任意位置"的情形；
    # 样例实测：拷贝源 0x<ADDR> 与表头 0x<ADDR> 相差 0x7C）
    for delta in range(-256, 257, 4):
        start_off = base_off + delta
        if start_off < 0:
            continue
        for layout, ptr_off in (("cmd_first", 4), ("ptr_first", 0)):
            res = _parse_slots(image, base, start_off, entry_size, ptr_off,
                               max_entries, entry_count_hint)
            if not res["entries"]:
                continue
            res["layout"] = layout
            res["start_delta"] = delta
            res["score"] = _phase_score(res["entries"])
            # 选优策略（实测教训，三层）：
            #  1) 字段合法性（flag∈{0,1} + cmd 互异）优先 —— 它区分"真命令表"与
            #     "恰好能解析出指针游程"的误配（ptr_first 误配时 flag 全缺失，得 0）；
            #  2) 条目数多者优先；
            #  3) 偏移小者优先（表头应贴近拷贝源）。
            if best is None:
                best = res
                continue
            key_new = (round(res["score"], 3), res["entry_count"], -abs(delta))
            key_best = (round(best["score"], 3), best["entry_count"],
                        -abs(best["start_delta"]))
            if key_new > key_best:
                best = res
    if best is None:
        return {"entries": [], "entry_count": 0, "primary_ptr_offset": None,
                "ptr_offset_histogram": {}, "start_delta": 0, "phase_layout": None}
    best["phase_layout"] = best.pop("layout")
    return best


def _phase_score(entries: list[dict]) -> float:
    """字段合法性打分：flag 集中在 {0,1} + cmd 互异 + 覆盖面。"""
    if not entries:
        return 0.0
    flags = [e["fields"].get("byte1") for e in entries
             if isinstance(e["fields"].get("byte1"), int)]
    cmds = [e["fields"].get("byte0") for e in entries
            if isinstance(e["fields"].get("byte0"), int)]
    if not flags or not cmds:
        return 0.0
    flag_ok = sum(1 for f in flags if f in (0, 1)) / len(flags)
    cmd_unique = len(set(cmds)) / len(cmds)
    return 0.6 * flag_ok + 0.4 * cmd_unique


def _parse_slots(image: bytes, base: int, start_off: int, entry_size: int,
                 ptr_off: int, max_entries: int,
                 entry_count_hint: int | None) -> dict:
    """按指定相位解析连续表项（指针在固定偏移 ptr_off）。"""
    limit = entry_count_hint or max_entries
    entries: list[dict] = []
    for i in range(limit):
        o = start_off + i * entry_size
        if o < 0 or o + entry_size > len(image):
            break
        raw = image[o:o + entry_size]
        if len(raw) < ptr_off + 4:
            break
        pv = struct.unpack_from("<I", raw, ptr_off)[0]
        if not (_is_code_mapped(pv, base, len(image)) and pv % 2 == 0):
            if entries:
                break
            continue
        head = raw[:ptr_off]
        tail = raw[ptr_off + 4:]
        fields: dict[str, object] = {"head_hex": head.hex()}
        if len(head) >= 1:
            fields["byte0"] = head[0]
        if len(head) >= 2:
            fields["byte1"] = head[1]
        if len(head) >= 4:
            fields["word0"] = struct.unpack_from("<I", head, 0)[0]
        if tail:
            fields["tail_hex"] = tail.hex()
            fields["tail_byte0"] = tail[0]
            if len(tail) >= 2:
                fields["tail_byte1"] = tail[1]
        entries.append({
            "index": len(entries),
            "entry_addr": f"0x{base + o:08x}",
            "raw_hex": raw.hex(),
            "fields": fields,
            "ptr_offset": ptr_off,
            "handler": f"0x{pv:08x}",
            "handler_in_image": True,
            "confidence": "hypothesis",
        })
    return {
        "entries": entries,
        "entry_count": len(entries),
        "primary_ptr_offset": ptr_off,
        "ptr_offset_histogram": {str(ptr_off): len(entries)} if entries else {},
    }


def _collect_image_const_addr_refs(disasm: list[Insn], base: int, size: int,
                                   limit: int = 400) -> list[int]:
    """收集代码中**构造出来的、落在镜像内的地址常量**（lui/auipc + addi 链）。

    用途：作为分派表候选源的第二通道。真实固件里分派表可能：
      a) 启动期从 ROM 拷贝到 RAM（靠 memcpy 源捕获），或
      b) 直接在 ROM 里被引用（本通道捕获）。
    两条通道并联，避免只认 memcpy 造成的漏检。
    """
    out: list[int] = []
    reg: dict[str, int] = {}
    for insn in disasm:
        if insn.text == "<undecoded>":
            continue
        m = _RE_LUI.match(insn.text)
        if m:
            v = parse_imm(m.group(2))
            if v is not None:
                val = (v << 12) & 0xFFFFFFFF
                reg[m.group(1)] = val
                # lui 本身可能就是一个有效地址（低 12 位为 0 的情形，如页对齐表基址）
                if _is_code_mapped(val, base, size) and val % 4 == 0:
                    out.append(val)
            continue
        m = _RE_AUIPC.match(insn.text)
        if m:
            v = parse_imm(m.group(2))
            if v is not None:
                val = (insn.addr + ((v << 12) & 0xFFFFFFFF)) & 0xFFFFFFFF
                reg[m.group(1)] = val
                if _is_code_mapped(val, base, size) and val % 4 == 0:
                    out.append(val)
            continue
        m = _RE_ADDI_SP.match(insn.text)
        if m and m.group(2) in reg:
            imm = parse_imm(m.group(3))
            if imm is not None:
                v = (reg[m.group(2)] + imm) & 0xFFFFFFFF
                reg[m.group(1)] = v
                if _is_code_mapped(v, base, size) and v % 4 == 0:
                    out.append(v)
            continue
    # 去重保序、限量
    seen: set[int] = set()
    uniq: list[int] = []
    for v in out:
        if v in seen:
            continue
        seen.add(v)
        uniq.append(v)
        if len(uniq) >= limit:
            break
    return uniq


def discover_dispatch(
    image_path: str,
    base: int,
    *,
    xlen: int = 32,
    compressed: bool = True,
    max_entries: int = 64,
) -> dict:
    """主入口：恢复运行期分派表（源表在镜像内时）。"""
    image = load_image(image_path)
    size = len(image)
    disasm = linear_disasm(image, base, xlen=xlen, compressed=compressed)

    shapes = _find_table_shape(disasm)
    memcpys = _find_memcpy_sources(disasm, base, size)
    in_image_srcs = [m for m in memcpys if m["src_in_image"]]

    # 通道 2（实测补充）：分派表可能**本来就在 ROM 里被直接引用**，不经过 memcpy。
    # 做法：从代码里收集"构造函数引用到的镜像内地址常量"，凡是能在其附近解析出
    # 连续指针表的位置，也纳入候选源。这不依赖 memcpy 的存在。
    code_consts = _collect_image_const_addr_refs(disasm, base, size)
    seen_srcs = {m["src_addr"] for m in in_image_srcs}
    for c in code_consts:
        if c not in seen_srcs:
            in_image_srcs.append({
                "src_addr": f"0x{c:08x}",
                "src_in_image": True,
                "load_at": "unknown",
                "loop_site": "unknown",
                "evidence": ["code-constructed constant reference"],
                "discovery_channel": "code_const_ref",
            })
            seen_srcs.add(c)
    for m in in_image_srcs:
        m.setdefault("discovery_channel", "memcpy_source")

    recovered: list[dict] = []
    for src in in_image_srcs:
        src_addr = int(src["src_addr"], 16)
        best: dict | None = None
        # 尝试所有已知 entry_size；**不把 count 当 hint 传**（hint 会在表尾截断，
        # 实测把 19 项的主表压成 1 项）。count 只作为 sanity 上界使用。
        # 候选 entry_size：shape 推断值 + 常见布局值（8=u8+u8+u16+u32 最常见；
        # 6=u16+u32；12=u32+u32+u32）。实测教训：仅信 shape 推断会漏——样例
        # 推断出 entry_size=4（`li 0x20`+`slli 2`），但真实表项是 8 字节。
        entry_sizes = sorted({sh["entry_size"] for sh in shapes} | {8, 6, 12, 16})
        for es in entry_sizes:
            if es < 8:
                continue          # 指针+命令字段至少 5 字节，<8 的槽装不下
            t = _parse_table(image, base, src_addr, es, max_entries, None)
            if t["entry_count"] == 0:
                continue
            if best is None or t["entry_count"] > best["table"]["entry_count"]:
                shape_hint = next((sh for sh in shapes if sh["entry_size"] == es), None)
                best = {"shape": shape_hint, "table": t}
        if best is None:
            t = _parse_table(image, base, src_addr, 8, max_entries, None)
            best = {"shape": None, "table": t}
        recovered.append({
            "source_table_addr": src["src_addr"],
            "source_in_image": True,
            "copy_loop": {"load_at": src["load_at"], "loop_site": src["loop_site"],
                          "evidence": src["evidence"]},
            "shape_evidence": best["shape"],
            "table": best["table"],
            "confidence": "hypothesis",
            "evidence_kind": "artifact_derived",
            "note": "表结构（entry_size / 字段偏移 / 条目数）为结构推断；"
                    "字段语义（命令号/标志位/填充）需人工或行为验证",
        })

    total_handlers = sum(r["table"]["entry_count"] for r in recovered)

    # 去重：不同拷贝源可能指向同一张表的相邻位置（实测：同一张 19 项命令表
    # 被 3 个源地址各找到一份，条目偏移不同）。按"表项地址集合的重叠度"合并，
    # 保留条目最多的那份，并记录其它源的观测作为佐证。
    deduped: list[dict] = []
    for r in sorted(recovered, key=lambda x: -x["table"]["entry_count"]):
        addrs = {e["entry_addr"] for e in r["table"]["entries"]}
        merged = False
        for d in deduped:
            d_addrs = {e["entry_addr"] for e in d["table"]["entries"]}
            if not d_addrs or not addrs:
                continue
            overlap = len(addrs & d_addrs) / max(1, min(len(addrs), len(d_addrs)))
            if overlap >= 0.5:
                d.setdefault("corroborating_sources", []).append({
                    "source_table_addr": r["source_table_addr"],
                    "entry_count": r["table"]["entry_count"],
                    "overlap_ratio": round(overlap, 3),
                })
                merged = True
                break
        if not merged:
            deduped.append(r)
    recovered = deduped
    total_handlers = sum(r["table"]["entry_count"] for r in recovered)
    return {
        "schema": SCHEMA,
        "tool": {"name": "fi.discover.dispatch", "version": "0.1.0"},
        "image": {
            "path": str(image_path), "sha256": sha256_hex(image),
            "size_bytes": size, "base_address": base,
            "base_address_hex": f"0x{base:08x}",
        },
        "method": {
            "approach": [
                "在代码中找 `li count` + `slli N` → 推断 entry_size 与条目数",
                "在代码中找 memcpy 循环（lw 源 + sw 目标 + addi 步进 + bne 回跳）→ 源地址常量",
                "源地址落在镜像内 → 从该处按 entry_size 解析表项，识别镜像内 32 位指针字段",
            ],
            "why": [
                "运行期分派表常在 RAM（启动期从 ROM 拷贝），静态扫镜像数据段会扫到错误的表；"
                "实测：直接扫镜像得到 known_entry_ratio=0 的伪表，真正的命令 handler 全部不可达",
                "从 memcpy 源表恢复，可在不做动态执行的前提下拿到完整 handler 集合",
            ],
            "boundaries": [
                "仅适用于源表在镜像内（ROM 常量表）的情形；运行期动态构造/加密的表无法恢复",
                "entry_size 与字段偏移为推断值，需人工或行为验证",
                "指针字段识别依赖'值落在镜像内'启发式，数据段中恰好像指针的值可能误收",
                "表条目数可能被后续哨兵项截断或延续，边界未独立确认",
            ],
        },
        "summary": {
            "table_shape_candidates": len(shapes),
            "memcpy_like_loops": len(memcpys),
            "memcpy_with_in_image_source": len(in_image_srcs),
            "recovered_tables": len(recovered),
            "total_handler_candidates": total_handlers,
        },
        "recovered_tables": recovered,
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
