# -*- coding: utf-8 -*-
"""fi.discover.targets：故障注入靶点自动枚举（芯片无关）。

闭环的关键一环（docs/methodology-reverse-first.md 第 5 步）：把"我要打某个功能"
落成**具体可注入的指令地址 + 建议动作**，而不是盲目全扫。

三类靶点（全部结构启发式，无芯片常量）：

  1) **常量装载点**（suggested_action 多为 skip_insn / reg_write）
     形态：`addi rd, zero, imm` / `li rd, imm` / `lui rd,hi + addi rd,rd,lo`。
     立即数范围**由调用方参数化**（`target_values`）——不写死任何芯片的错误码。
     未给 target_values 时自动推断：**装载后短窗口内出现调用**的常量 = "被当作
     参数/返回码消费的常量"，这是与芯片无关的结构信号（错误码/命令号候选）。
     记录：rd、装载值、后续是否有 jal 调用（以及调用目标是否高频共享函数）。

  2) **调用点全景**（suggested_action 用于定位"发送/公共函数"）
     统计每个被 jal/c.jal 直接调用的目标地址的**被调用次数与调用者地址**；
     ≥min_shared_callers 的识别为"高频共享函数"候选（发送/日志/公共子程序）。
     同时对每个共享函数统计其**入参常量谱**（调用前窗口内装进实参寄存器的常量），
     这是"错误码 → 发送函数"的自动配对依据。

  3) **比较分支靶点**（suggested_action 多为 flip_reg_bits）
     beq/bne/blt/bge/bgeu/bltu/bgez/bltz/blez/bgtz + c.beqz/c.bnez，
     记录分支地址、目标、fallthrough、以及**被比较寄存器已知的常量值**
     （来自装载跟踪）。这类点是"改判定结果"的最省力注入位置。

输出（对齐 docs/contracts/schemas/discover-report.schema.json 的 findings.targets 条目）：
    {schema, tool, image, method, summary, targets: [
        {kind, addr, offset, insn, context, suggested_action,
         confidence: "hypothesis", evidence_kind: "artifact_derived", sample_evidence}]}

纪律：confidence 恒为 hypothesis；不写任何芯片实例值；不自动改写 Profile。
"""
from __future__ import annotations

from collections import defaultdict

import capstone

from .common import Insn, load_image, make_disassembler, sha256_hex

#: 建议动作枚举（与 sim-trace / discover-report 契约一致）
SUGGESTED_ACTIONS = ("skip_insn", "flip_reg_bits", "reg_write", "mem_write")

#: 条件分支助记符（含伪指令形态）
COND_BRANCHES = {
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "bltz", "bgez", "blez", "bgtz",
    "c.beqz", "c.bnez",
}
CALL_MNEMONICS = {"jal", "c.jal"}

#: RISC-V ABI 寄存器名（capstone RISC-V reg id：X0=1 … X31=32，ISA 规范常量）
_REG_NAME = {
    1: "zero", 2: "ra", 3: "sp", 4: "gp", 5: "tp", 6: "t0", 7: "t1", 8: "t2",
    9: "s0", 10: "s1", 11: "a0", 12: "a1", 13: "a2", 14: "a3", 15: "a4",
    16: "a5", 17: "a6", 18: "a7", 19: "s2", 20: "s3", 21: "s4", 22: "s5",
    23: "s6", 24: "s7", 25: "s8", 26: "s9", 27: "s10", 28: "s11", 29: "t3",
    30: "t4", 31: "t5", 32: "t6",
}
#: 参数寄存器（ABI 规范）：常量装进这些寄存器意味着"作为参数传给被调函数"
_ARG_REGS = ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7")


class _Insn:
    """轻量指令记录（含结构操作数，供常量跟踪与上下文渲染）。"""

    __slots__ = ("addr", "offset", "size", "mnemonic", "text", "regs", "imms", "mem")

    def __init__(self, addr: int, offset: int, size: int, mnemonic: str, text: str,
                 regs: list[str], imms: list[int], mem: list[tuple[str, int]]):
        self.addr = addr
        self.offset = offset
        self.size = size
        self.mnemonic = mnemonic
        self.text = text
        self.regs = regs
        self.imms = imms
        self.mem = mem


def _decode(image: bytes, base: int, *, xlen: int, compressed: bool) -> list[_Insn]:
    """线性解码（靶点枚举用：需要看到全部常量装载点，包括数据段噪声）。

    噪声抑制在后续步骤做（可达性/调用配对），而不是靠线性扫描本身——
    因为错误码装载点可能位于任何函数内。
    """
    md = make_disassembler(xlen, compressed)
    md.detail = True
    out: list[_Insn] = []
    off = 0
    n = len(image)
    while off < n:
        try:
            insn = next(md.disasm(image[off:off + 4], base + off))
        except StopIteration:
            off += 2
            continue
        regs: list[str] = []
        imms: list[int] = []
        mem: list[tuple[str, int]] = []
        for o in insn.operands:
            if o.type == capstone.riscv.RISCV_OP_REG:
                regs.append(_REG_NAME.get(o.reg, f"x{o.reg - 1}"))
            elif o.type == capstone.riscv.RISCV_OP_IMM:
                imms.append(o.imm)
            elif o.type == capstone.riscv.RISCV_OP_MEM:
                mem.append((_REG_NAME.get(o.mem.base, f"x{o.mem.base - 1}"), o.mem.disp))
        out.append(_Insn(
            addr=insn.address, offset=off, size=insn.size, mnemonic=insn.mnemonic,
            text=f"{insn.mnemonic} {insn.op_str}".strip(),
            regs=regs, imms=imms, mem=mem,
        ))
        off += insn.size
    return out


def _ctx(insns: list[_Insn], idx: int, before: int = 3, after: int = 3) -> list[str]:
    """指令上下文（±N 条文本），供报告可读与人工复核。"""
    lo = max(0, idx - before)
    hi = min(len(insns), idx + after + 1)
    return [f"0x{i.addr:08x}: {i.text}" for i in insns[lo:hi]]


def _loads(insns: list[_Insn]) -> list[dict]:
    """提取全部常量装载点（三个形态），并记录装载后窗口内是否有调用。

    形态：
      - li rd, imm                       （伪指令，capstone 输出 "li"）
      - c.li rd, imm                     （压缩立即数，imm 有符号 6 位）
      - addi rd, zero, imm               （== li 的展开形态）
      - lui/c.lui rd, hi  (+ addi rd,rd,lo)  ← 严格相邻配对
    """
    out: list[dict] = []
    for idx, insn in enumerate(insns):
        m = insn.mnemonic
        rec: dict | None = None
        if m in ("li", "c.li") and len(insn.imms) >= 1 and insn.regs:
            rec = {"rd": insn.regs[0], "value": insn.imms[0] & 0xFFFFFFFF,
                   "form": m, "pair": [insn.text]}
        elif m == "addi" and len(insn.regs) == 2 and len(insn.imms) >= 1:
            if insn.regs[1] in ("zero", "x0"):
                rec = {"rd": insn.regs[0], "value": insn.imms[0] & 0xFFFFFFFF,
                       "form": "addi_zero", "pair": [insn.text]}
        elif m in ("lui", "c.lui") and insn.regs and insn.imms:
            rd, hi = insn.regs[0], insn.imms[0]
            value = (hi << 12) & 0xFFFFFFFF
            pair = [insn.text]
            form = "lui"
            # 严格相邻配对（允许中间夹 1 条无关指令：编译器常见调度）
            for j in range(idx + 1, min(idx + 3, len(insns))):
                nxt = insns[j]
                if (nxt.mnemonic == "addi" and len(nxt.regs) == 2
                        and nxt.regs[0] == rd and nxt.regs[1] == rd and nxt.imms):
                    value = (value + nxt.imms[0]) & 0xFFFFFFFF
                    pair.append(nxt.text)
                    form = "lui_addi"
                    break
            rec = {"rd": rd, "value": value, "form": form, "pair": pair}
        if rec is None:
            continue
        # 后续窗口内的第一个直接调用（错误码/参数被消费的强结构信号）
        call = None
        for j in range(idx + 1, min(idx + 9, len(insns))):
            nxt = insns[j]
            if nxt.mnemonic in CALL_MNEMONICS and nxt.imms:
                call = {"at": nxt.addr, "target": (nxt.addr + nxt.imms[0]) & 0xFFFFFFFF,
                        "delta_insns": j - idx, "insn": nxt.text}
                break
        rec.update({
            "at": insn.addr, "offset": insn.offset, "idx": idx,
            "insn": insn.text,
            "is_arg_reg": rec["rd"] in _ARG_REGS,
            "followed_by_call": call,
            "context": _ctx(insns, idx, 2, 3),
        })
        out.append(rec)
    return out


def _call_graph(insns: list[_Insn]) -> dict[int, list[dict]]:
    """直接调用图：目标函数地址 → [{caller, at, insn}]（只统计直接 jal/c.jal）。"""
    graph: dict[int, list[dict]] = defaultdict(list)
    for insn in insns:
        if insn.mnemonic in CALL_MNEMONICS and insn.imms:
            tgt = (insn.addr + insn.imms[0]) & 0xFFFFFFFF
            graph[tgt].append({"caller": insn.addr, "at": insn.addr, "insn": insn.text})
    return graph


def _load_tracking(insns: list[_Insn]) -> list[dict[str, int]]:
    """线性寄存器常量快照（按指令下标），供比较分支识别"与常量比较"形态。"""
    snap: list[dict[str, int]] = []
    cur: dict[str, int] = {}
    for insn in insns:
        snap.append(dict(cur))
        m = insn.mnemonic
        if m in ("li", "c.li") and len(insn.imms) >= 1 and insn.regs:
            cur[insn.regs[0]] = insn.imms[0] & 0xFFFFFFFF
        elif m == "addi" and len(insn.regs) == 2 and insn.imms:
            if insn.regs[1] in ("zero", "x0"):
                cur[insn.regs[0]] = insn.imms[0] & 0xFFFFFFFF
        elif m in ("lui", "c.lui") and insn.regs and insn.imms:
            cur[insn.regs[0]] = (insn.imms[0] << 12) & 0xFFFFFFFF
        elif m in ("mv", "c.mv") and len(insn.regs) == 2:
            if insn.regs[1] in cur:
                cur[insn.regs[0]] = cur[insn.regs[1]]
    return snap


def discover_targets(
    image_path: str,
    base: int,
    *,
    xlen: int = 32,
    compressed: bool = True,
    target_values: list[int] | None = None,
    target_value_range: tuple[int, int] | None = None,
    min_shared_callers: int = 3,
    call_window: int = 8,
    max_targets_per_kind: int = 400,
    max_shared_functions: int = 60,
    max_auto_values: int = 64,
) -> dict:
    """主入口：镜像 → 注入靶点报告（dict）。

    参数
    ----
    target_values
        显式指定的"关心的常量"（错误码/命令号等）。**不写死任何芯片值**：
        调用方从 Profile 的 error_codes 表读、或命令行传入。
        给定时只枚举装载这些值的点（高精度）。
    target_value_range
        未给 target_values 时的**值域过滤**（如错误码常落 0x100–0xfff）。
        与 target_values 二选一；都不给则自动推断（见下）。
    min_shared_callers
        ≥ 该调用点数即判定为"高频共享函数"候选（发送/日志/公共子程序）。
    call_window
        常量装载后多少条指令内出现调用算"被消费的常量"（自动推断模式用）。

    自动推断（两个参数都不给时）
    ----------------------------
    枚举"装载后 call_window 条内出现直接调用、且装载进实参寄存器（a0-a7）"的常量，
    并要求该常量在镜像内**重复出现 ≥2 次**（错误码/命令号是复用常量，
    单次出现的随机立即数多为地址偏移/长度）。这是芯片无关的结构判别。
    """
    image = load_image(image_path)
    insns = _decode(image, base, xlen=xlen, compressed=compressed)
    graph = _call_graph(insns)
    loads = _loads(insns)
    snaps = _load_tracking(insns)

    shared = {tgt: sites for tgt, sites in graph.items() if len(sites) >= min_shared_callers}

    # ---------- 模式判定：显式值 / 值域 / 自动推断 ----------
    if target_values:
        mode = "explicit_values"
        wanted = {int(v) & 0xFFFFFFFF for v in target_values}
        def _match(v: int) -> bool:
            return v in wanted
    elif target_value_range:
        mode = "value_range"
        lo, hi = target_value_range
        def _match(v: int) -> bool:
            return lo <= v <= hi
    else:
        mode = "auto_inferred"
        counts: dict[int, int] = defaultdict(int)
        calls_by_value: dict[int, list[dict]] = defaultdict(list)
        for rec in loads:
            counts[rec["value"]] += 1
            if (rec["is_arg_reg"] and rec["followed_by_call"]
                    and rec["followed_by_call"]["delta_insns"] <= call_window):
                calls_by_value[rec["value"]].append(rec["followed_by_call"])
        # 评分：被调用消费 + 被调方是高频共享函数（=错误码/命令号被发送函数消费的形态）
        # 值域启发式（芯片无关）：错误码/命令号/字段值通常是**小整数立即数**；
        # 高地址值多为指针/MMIO 基址（0x2xxxxxxx/0x4xxxxxxx/镜像内地址），排除。
        def _code_like(v: int) -> bool:
            if v == 0 or v == 0xFFFFFFFF:
                return False
            if base <= v < base + len(image):
                return False        # 指向镜像自身的地址（指针）
            return v < 0x10000       # 小整数立即数

        scored: list[tuple[int, int, int]] = []
        for v, call_list in calls_by_value.items():
            if counts[v] < 2 or not _code_like(v):
                continue
            shared_hits = sum(1 for c in call_list if c["target"] in shared)
            scored.append((shared_hits, len(call_list), v))
        scored.sort(key=lambda t: (-t[0], -t[1], t[2]))
        inferred = {v for _s, _c, v in scored[:max_auto_values]}
        wanted = inferred
        def _match(v: int) -> bool:
            return v in wanted

    # ---------- 类别 1：常量装载靶点 ----------
    load_targets: list[dict] = []
    for rec in loads:
        if not _match(rec["value"]):
            continue
        call = rec["followed_by_call"]
        is_shared_callee = bool(call and call["target"] in shared)
        detail = {
            "rd": rec["rd"],
            "value": f"0x{rec['value']:x}",
            "load_form": rec["form"],
            "load_pair": rec["pair"],
            "is_arg_register": rec["is_arg_reg"],
            "followed_by_call": bool(call),
        }
        if call:
            detail["call_site"] = f"0x{call['at']:08x}"
            detail["call_target"] = f"0x{call['target']:08x}"
            detail["call_delta_insns"] = call["delta_insns"]
            detail["callee_is_shared_function"] = is_shared_callee
            if is_shared_callee:
                detail["callee_caller_count"] = len(shared[call["target"]])
        # 动作建议（结构推断，非语义断言）：
        #   装载进实参寄存器后有调用 → skip_insn 可模拟"该码未被发出"
        #   否则 → reg_write 改写装载源（rd 即将被写入，等价于改常量）
        action = "skip_insn" if (rec["is_arg_reg"] and call) else "reg_write"
        load_targets.append({
            "kind": "const_load",
            "addr": f"0x{rec['at']:08x}",
            "offset": rec["offset"],
            "insn": rec["insn"],
            "context": rec["context"],
            "suggested_action": action,
            "suggested_action_reason": (
                "常量装载进实参寄存器后被调用消费：跳过该指令可让被调方收到原寄存器值"
                if action == "skip_insn" else
                "常量装载进非实参寄存器或其后无直接调用：改写目标寄存器等价于改常量"
            ),
            "detail": detail,
            "confidence": "hypothesis",
            "evidence_kind": "artifact_derived",
            "sample_evidence": [f"0x{rec['at']:08x}: {rec['insn']}"],
        })

    # ---------- 类别 2：调用点全景（含高频共享函数） ----------
    call_targets: list[dict] = []
    for tgt, sites in sorted(graph.items(), key=lambda kv: -len(kv[1])):
        is_shared = tgt in shared
        # 该被调方的入参常量谱：调用前窗口内装进实参寄存器的常量
        arg_spectrum: dict[str, set[str]] = defaultdict(set)
        for site in sites[:max_targets_per_kind]:
            at = site["at"]
            # 从线性表里定位该调用指令的下标
            idx = next((i for i, x in enumerate(insns) if x.addr == at), None)
            if idx is None:
                continue
            for j in range(max(0, idx - call_window), idx):
                rec_r = insns[j]
                for rec in loads:
                    if rec["at"] != rec_r.addr:
                        continue
                    if rec["is_arg_reg"]:
                        arg_spectrum[rec["rd"]].add(f"0x{rec['value']:x}")
        detail = {
            "callee": f"0x{tgt:08x}",
            "caller_count": len(sites),
            "callers": [f"0x{s['at']:08x}" for s in sites[:min(len(sites), 24)]],
            "shared_function_candidate": is_shared,
            "arg_constant_spectrum": {k: sorted(v) for k, v in arg_spectrum.items()},
        }
        call_targets.append({
            "kind": "shared_function" if is_shared else "call_site",
            "addr": f"0x{tgt:08x}",
            "offset": tgt - base,
            "insn": (f"{len(sites)} direct call sites; first: {sites[0]['insn']}"
                     if sites else ""),
            "context": [sites[0]["insn"]] if sites else [],
            "suggested_action": "skip_insn",
            "suggested_action_reason": (
                "高频共享函数（发送/日志/公共子程序候选）：在其调用点跳过可观察"
                "上层行为变化；直接改其内部会污染所有调用者"
            ),
            "detail": detail,
            "confidence": "hypothesis",
            "evidence_kind": "artifact_derived",
            "sample_evidence": [
                f"0x{s['at']:08x}: {s['insn']} → 0x{tgt:08x}" for s in sites[:3]
            ],
        })

    # ---------- 类别 3：比较分支靶点 ----------
    branch_targets: list[dict] = []
    for idx, insn in enumerate(insns):
        if insn.mnemonic not in COND_BRANCHES:
            continue
        if not insn.imms:
            continue
        tgt = (insn.addr + insn.imms[0]) & 0xFFFFFFFF
        snap = snaps[idx] if idx < len(snaps) else {}
        cmp_info: dict = {"branch_target": f"0x{tgt:08x}",
                          "fallthrough": f"0x{insn.addr + insn.size:08x}"}
        known = {r: f"0x{snap[r]:x}" for r in insn.regs if r in snap}
        if known:
            cmp_info["known_operand_values"] = known
            cmp_info["compares_against_constant"] = True
        else:
            cmp_info["compares_against_constant"] = False
        # 只保留"比较常量"或"比较已知装载值"的分支作为高价值靶点；
        # 其余分支仍登记但标 confidence=hypothesis + 低优先级说明。
        branch_targets.append({
            "kind": "compare_branch",
            "addr": f"0x{insn.addr:08x}",
            "offset": insn.offset,
            "insn": insn.text,
            "context": _ctx(insns, idx, 3, 2),
            "suggested_action": "flip_reg_bits",
            "suggested_action_reason": (
                "比较分支：翻转被比较寄存器位可改变判定走向（扰动最小、语义最直接）"
            ),
            "detail": cmp_info,
            "confidence": "hypothesis",
            "evidence_kind": "artifact_derived",
            "sample_evidence": [f"0x{insn.addr:08x}: {insn.text} → 0x{tgt:08x}"],
        })

    # 分支优先级：比较常量的在前（更可能是"校验判定点"）
    branch_targets.sort(key=lambda t: (not t["detail"].get("compares_against_constant", False),
                                       t["addr"]))
    branch_targets = branch_targets[:max_targets_per_kind]

    targets = load_targets[:max_targets_per_kind] + branch_targets + call_targets[:max_shared_functions]

    # ---------- 汇总 ----------
    value_hist: dict[str, int] = defaultdict(int)
    for t in load_targets:
        value_hist[t["detail"]["value"]] += 1
    shared_sorted = sorted(shared.items(), key=lambda kv: -len(kv[1]))

    return {
        "schema": "fi.discover.target-report-v0",
        "tool": {"name": "fi.discover.targets", "version": "0.1.0"},
        "image": {
            "path": str(image_path),
            "sha256": sha256_hex(image),
            "size_bytes": len(image),
            "base_address": base,
            "base_address_hex": f"0x{base:08x}",
        },
        "method": {
            "channels": [
                "常量装载点：li / c.li / addi rd,zero,imm / lui(+addi 相邻配对)",
                "常量消费关联：装载后 call_window 条内出现直接调用（jal/c.jal）",
                "实参寄存器判别：常量装入 a0-a7 视为「作为参数传给被调方」（ABI 惯例）",
                "调用点全景：统计每个直接调用目标的被调用次数与调用者（≥min 为共享函数候选）",
                "比较分支：条件分支 + 被比较寄存器的已知常量值（线性快照）",
            ],
            "target_value_mode": mode,
            "target_values": sorted(f"0x{v:x}" for v in wanted)[:200],
            "min_shared_callers": min_shared_callers,
            "call_window": call_window,
            "boundaries": [
                "线性解码含数据段：伪指令可能产生假装载/假分支（真实命中需仿真或 Profile 交叉校验）",
                "无数据流分析：寄存器常量用线性快照近似，跨分支/跨基本块不合并 → 比较常量可能漏检或误判",
                "间接调用（jalr/c.jalr）不计入调用点统计 → 共享函数调用点数可能偏低",
                "lui+addi 配对允许夹 1 条指令（编译器调度），仍可能漏配或错配",
                "suggested_action 是结构建议，未验证注入效果（需 fi.sim 试跑）",
                "本报告只产出候选，绝不改写 Profile 中任何 fact 级 claim",
            ],
        },
        "summary": {
            "insn_count": len(insns),
            "distinct_call_targets": len(graph),
            "direct_call_sites": sum(len(v) for v in graph.values()),
            "shared_function_count": len(shared),
            "const_load_total": len(loads),
            "const_load_matched": len(load_targets),
            "distinct_matched_values": len(value_hist),
            "top_matched_values": sorted(
                ({"value": v, "load_sites": c} for v, c in value_hist.items()),
                key=lambda x: -x["load_sites"])[:32],
            "compare_branch_total": sum(1 for i in insns if i.mnemonic in COND_BRANCHES),
            "compare_branch_targets": len(branch_targets),
            "target_count": len(targets),
            "shared_functions": [
                {
                    "callee": f"0x{tgt:08x}",
                    "caller_count": len(sites),
                    "callers": [f"0x{s['at']:08x}" for s in sites[:16]],
                }
                for tgt, sites in shared_sorted[:max_shared_functions]
            ],
        },
        "targets": targets,
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
