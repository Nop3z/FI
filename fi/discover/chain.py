# -*- coding: utf-8 -*-
"""fi.discover.chain：功能级调用链重建（芯片无关，P0「逆向先行」核心工具）。

用途（docs/methodology-reverse-first.md §2–§3）：
    给定"我要打的功能点"（函数地址 / 关键字符串 / 关键常量 / 错误码立即数），
    输出**从入口（复位点）到该功能的可达调用链**：每层函数地址、调用点、
    层内条件分支、常量装载出口、循环嫌疑点、指令数下界（供 delay 估算）。

方法：**递归下降（recursive descent）**，不是线性扫描判边界：
  1) 线性解码全镜像，仅用于两件事：找"已知函数入口"（直接调用 jal/c.jal 目标）
     与提取 ASCII 串（功能锚点）；**不用它判定函数边界**（线性流在数据/对齐
     错位后会产生伪指令与假边界——target-chip 逆向第三轮的教训）；
  2) 从根（复位入口 + 调用方附加入口，如 mtvec 候选）出发递归下降：
       - 条件分支：两侧都继续（无数据流，不判真假）
       - 直接调用：记调用边，把被调方加入函数队列，本地继续顺序后继（返回点）
       - 无条件跳转：目标是"已知函数入口"→ 记为尾调用并入队；否则视为本地跳转继续
       - 间接跳转/调用（jalr/c.jalr/c.jr）：**无法静态解析**→ 登记为 unknown 并停止该路径
       - ret/mret：结束该路径
  3) 每个函数体记录：可达指令数、调用边、尾调用、间接点、条件分支（含比较常量）、
     常量装载、字符串引用、循环嫌疑（向后跳转）、返回点；
  4) 调用图上 BFS 求可达深度，DFS 枚举从根到目标的多条路径 + 指令数下界。

产出 confidence 恒为 hypothesis，evidence_kind=artifact_derived。

边界（全部写进报告 method.boundaries）：
  - 间接调用/函数指针表不可解析 → 可达性可能不完整，逐点登记，绝不假装完整；
  - 无数据流/值集分析：分支不判真假 → "可达"是**结构可达**，非运行时必然；
  - 循环只标嫌疑（向后跳转）→ 指令数是**下界**，不是运行时长；
  - 反汇编从任意目标地址重新同步，若目标落在数据段会解出伪指令（按可达性登记，
    报告中以 reachable/decoded 比例与 in_image 标注提示）。
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

import capstone

from .common import load_image, make_disassembler, sha256_hex

#: 条件分支（RISC-V 全族 + 伪指令形态）
COND_BRANCHES = {
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "bltz", "bgez", "blez", "bgtz",
    "c.beqz", "c.bnez",
}
#: 直接调用（返回地址隐含 ra）
CALL_MNEMONICS = {"jal", "c.jal"}
#: 无条件跳转（rd = x0）
JUMP_MNEMONICS = {"j", "c.j"}
#: 间接跳转/调用（目标不可静态解析）
INDIRECT_MNEMONICS = {"jalr", "c.jalr", "c.jr"}
#: 返回
RET_MNEMONICS = {"ret", "c.ret"}
#: trap 返回
NORETURN_MNEMONICS = {"mret"}

#: RISC-V ABI 寄存器名（capstone 的 RISC-V 寄存器 ID：X0=1 … X31=32，ISA 规范常量）
_REG_ALIAS = {
    1: "zero", 2: "ra", 3: "sp", 4: "gp", 5: "tp", 6: "t0", 7: "t1", 8: "t2",
    9: "s0", 10: "s1", 11: "a0", 12: "a1", 13: "a2", 14: "a3", 15: "a4",
    16: "a5", 17: "a6", 18: "a7", 19: "s2", 20: "s3", 21: "s4", 22: "s5",
    23: "s6", 24: "s7", 25: "s8", 26: "s9", 27: "s10", 28: "s11", 29: "t3",
    30: "t4", 31: "t5", 32: "t6",
}


@dataclass
class Operand:
    """结构化操作数（capstone detail 的最小投影）。"""

    kind: str            # reg | imm | mem
    reg: int | None = None
    imm: int | None = None
    mem_base: int | None = None
    mem_disp: int | None = None

    @property
    def reg_name(self) -> str | None:
        return _REG_ALIAS.get(self.reg) if self.reg is not None else None


@dataclass
class DInsn:
    """带结构操作数的指令。"""

    addr: int
    size: int
    mnemonic: str
    text: str
    operands: list[Operand] = field(default_factory=list)

    @property
    def next_addr(self) -> int:
        return self.addr + self.size


def _decode_at(md: "capstone.Cs", image: bytes, base: int, addr: int) -> DInsn | None:
    """在给定地址解码一条指令（越界/无法解码返回 None）。"""
    off = addr - base
    if off < 0 or off >= len(image):
        return None
    try:
        insn = next(md.disasm(image[off:off + 4], addr))
    except StopIteration:
        return None
    ops: list[Operand] = []
    for o in insn.operands:
        if o.type == capstone.riscv.RISCV_OP_REG:
            ops.append(Operand("reg", reg=o.reg))
        elif o.type == capstone.riscv.RISCV_OP_IMM:
            ops.append(Operand("imm", imm=o.imm))
        elif o.type == capstone.riscv.RISCV_OP_MEM:
            ops.append(Operand("mem", mem_base=o.mem.base, mem_disp=o.mem.disp))
    return DInsn(addr=insn.address, size=insn.size, mnemonic=insn.mnemonic,
                 text=f"{insn.mnemonic} {insn.op_str}".strip(), operands=ops)


def _new_disassembler(xlen: int, compressed: bool) -> "capstone.Cs":
    md = make_disassembler(xlen, compressed)
    md.detail = True
    return md


def _decode_linear(image: bytes, base: int, *, xlen: int, compressed: bool) -> list[DInsn]:
    """线性解码（仅用于收集调用目标与串锚点；不用于函数边界判定）。"""
    md = _new_disassembler(xlen, compressed)
    out: list[DInsn] = []
    off = 0
    while off < len(image):
        insn = _decode_at(md, image, base, base + off)
        if insn is None:
            off += 2
            continue
        out.append(insn)
        off += insn.size
    return out


def _printable_strings(image: bytes, min_len: int = 4) -> list[dict]:
    """提取镜像内可打印 ASCII 串（功能特征锚点：日志/命令标签/错误文本）。"""
    out: list[dict] = []
    i, n = 0, len(image)
    while i < n:
        if 32 <= image[i] < 127:
            j = i
            while j < n and (32 <= image[j] < 127):
                j += 1
            if j - i >= min_len:
                out.append({"offset": i, "text": image[i:j].decode("ascii", "ignore")})
            i = j
        else:
            i += 1
    return out


@dataclass
class FunctionInfo:
    """递归下降得到的一个函数体（只含可达指令）。"""

    start: int
    insns: dict[int, DInsn] = field(default_factory=dict)   # addr -> insn
    calls: list[dict] = field(default_factory=list)         # {at, target, kind}
    tail_calls: list[dict] = field(default_factory=list)    # {at, target}
    indirect: list[dict] = field(default_factory=list)      # {at, insn, reg, kind}
    branches: list[dict] = field(default_factory=list)      # {at, insn, target, fallthrough, cmp}
    const_loads: list[dict] = field(default_factory=list)   # {at, value, reg, form}
    string_refs: list[dict] = field(default_factory=list)   # {at, ptr, text}
    loops: list[dict] = field(default_factory=list)         # {at, target}
    ret_sites: list[int] = field(default_factory=list)
    unresolved_ends: list[dict] = field(default_factory=list)  # 无法继续的路径终点

    @property
    def end(self) -> int:
        if not self.insns:
            return self.start
        last = max(self.insns.values(), key=lambda i: i.addr)
        return last.next_addr

    @property
    def insn_count(self) -> int:
        return len(self.insns)

    @property
    def size_bytes(self) -> int:
        return max(0, self.end - self.start)

    def to_dict(self, *, image_lo: int, image_hi: int) -> dict:
        loads = _value_snapshot_track(self.insns)
        return {
            "addr": f"0x{self.start:08x}",
            "offset": self.start - image_lo,
            "observed_end": f"0x{self.end:08x}",
            "size_bytes": self.size_bytes,
            "insn_count": self.insn_count,
            "calls": [
                {"at": f"0x{c['at']:08x}", "target": f"0x{c['target']:08x}", "kind": c["kind"]}
                for c in sorted(self.calls, key=lambda x: x["at"])
            ],
            "tail_calls": [
                {"at": f"0x{c['at']:08x}", "target": f"0x{c['target']:08x}"}
                for c in sorted(self.tail_calls, key=lambda x: x["at"])
            ],
            "indirect_sites": [
                {"at": f"0x{i['at']:08x}", "insn": i["insn"], "reg": i.get("reg"),
                 "kind": i["kind"], "target": "unknown"}
                for i in sorted(self.indirect, key=lambda x: x["at"])
            ],
            "branches": [
                {
                    "at": f"0x{b['at']:08x}",
                    "insn": b["insn"],
                    "target": f"0x{b['target']:08x}",
                    "fallthrough": f"0x{b['fallthrough']:08x}",
                    **({"cmp": b["cmp"]} if b.get("cmp") else {}),
                }
                for b in sorted(self.branches, key=lambda x: x["at"])
            ],
            "const_loads": [
                {"at": f"0x{c['at']:08x}", "value": f"0x{c['value']:x}",
                 "reg": c["reg"], "form": c["form"]}
                for c in sorted(loads, key=lambda x: x["at"])
            ],
            "string_refs": [
                {"at": f"0x{s['at']:08x}", "ptr": f"0x{s['ptr']:08x}", "text": s["text"]}
                for s in sorted(self.string_refs, key=lambda x: x["at"])
            ],
            "loop_suspects": [
                {"at": f"0x{l['at']:08x}", "target": f"0x{l['target']:08x}"}
                for l in sorted(self.loops, key=lambda x: x["at"])
            ],
            "ret_sites": [f"0x{x:08x}" for x in sorted(self.ret_sites)],
            "unresolved_ends": self.unresolved_ends,
            "in_image": image_lo <= self.start < image_hi,
        }


def _value_snapshot_track(insns: dict[int, DInsn], gp_value: int | None = None) -> list[dict]:
    """按地址序遍历指令，跟踪寄存器常量，返回常量装载清单（含字符串指针）。

    纯函数内线性传播，跨分支不做合并（保守、可复现）；不追踪 load 结果。
    `gp_value`：已推断的全局指针值——给出时 `addi rd, gp, imm` 会被**提升为绝对
    地址**（RAM/外设目标，表基址常在此类指令中），否则只能看到相对偏移。
    """
    loads: list[dict] = []
    reg: dict[str, int] = {"gp": gp_value} if gp_value is not None else {}
    for addr in sorted(insns):
        insn = insns[addr]
        m, ops = insn.mnemonic, insn.operands
        if m in ("auipc", "lui", "c.lui") and len(ops) >= 2 and ops[0].kind == "reg":
            rd = ops[0].reg_name
            imm = next((o.imm for o in ops[1:] if o.kind == "imm"), None)
            if rd is not None and imm is not None:
                reg[rd] = ((insn.addr + (imm << 12)) if m == "auipc" else (imm << 12)) & 0xFFFFFFFF
                loads.append({"at": addr, "value": reg[rd], "reg": rd, "form": m})
        elif m in ("li", "c.li") and len(ops) == 2:
            rd, imm = ops[0].reg_name, ops[1].imm
            if rd is not None and imm is not None:
                reg[rd] = imm & 0xFFFFFFFF
                loads.append({"at": addr, "value": reg[rd], "reg": rd, "form": m})
        elif m in ("addi", "c.addi") and len(ops) == 3:
            rd, rs1, imm = ops[0].reg_name, ops[1].reg_name, ops[2].imm
            if rd is None or rs1 is None or imm is None:
                continue
            if rs1 in ("zero", "x0"):
                reg[rd] = imm & 0xFFFFFFFF
                loads.append({"at": addr, "value": reg[rd], "reg": rd, "form": "addi_zero"})
            elif rs1 in reg:
                reg[rd] = (reg[rs1] + imm) & 0xFFFFFFFF
                loads.append({"at": addr, "value": reg[rd], "reg": rd, "form": "addi"})
        elif m in ("mv", "c.mv") and len(ops) == 2:
            rd, rs = ops[0].reg_name, ops[1].reg_name
            if rd and rs and rs in reg:
                reg[rd] = reg[rs]
        elif m in ("add", "c.add") and len(ops) == 3:
            rd, a, b = ops[0].reg_name, ops[1].reg_name, ops[2].reg_name
            if rd and a in reg and b in reg:
                reg[rd] = (reg[a] + reg[b]) & 0xFFFFFFFF
    return loads


def _string_refs(insns: dict[int, DInsn], strings_at: dict[int, str]) -> list[dict]:
    """从常量装载结果里挑出指向 ASCII 串的引用（功能锚点）。"""
    refs: list[dict] = []
    for load in _value_snapshot_track(insns):
        if load["value"] in strings_at:
            refs.append({"at": load["at"], "ptr": load["value"],
                         "text": strings_at[load["value"]]})
    return refs


def _branch_cmp(insns: dict[int, DInsn], addr: int, ops: list[Operand]) -> dict | None:
    """比较分支的常量识别：取该分支前的寄存器值快照（线性近似）。"""
    reg: dict[str, int] = {}
    for a in sorted(insns):
        if a > addr:
            break
        insn = insns[a]
        m, o = insn.mnemonic, insn.operands
        if m in ("auipc", "lui", "c.lui") and len(o) >= 2 and o[0].kind == "reg":
            imm = next((x.imm for x in o[1:] if x.kind == "imm"), None)
            if imm is not None:
                reg[o[0].reg_name] = ((insn.addr + (imm << 12)) if m == "auipc" else (imm << 12)) & 0xFFFFFFFF
        elif m in ("li", "c.li") and len(o) == 2:
            reg[o[0].reg_name] = o[1].imm & 0xFFFFFFFF
        elif m in ("addi", "c.addi") and len(o) == 3:
            rd, rs1, imm = o[0].reg_name, o[1].reg_name, o[2].imm
            if rs1 in ("zero", "x0"):
                reg[rd] = imm & 0xFFFFFFFF
            elif rs1 in reg:
                reg[rd] = (reg[rs1] + imm) & 0xFFFFFFFF
        elif m in ("mv", "c.mv") and len(o) == 2 and o[1].reg_name in reg:
            reg[o[0].reg_name] = reg[o[1].reg_name]
    if not reg:
        return None
    names = [o.reg_name for o in ops if o.kind == "reg"]
    known = [(n, reg[n]) for n in names if n in reg]
    if not known:
        return None
    return {"regs": names, "known_values": {n: f"0x{v:x}" for n, v in known},
            "note": "线性近似快照（跨分支不合并），仅作常量候选提示"}


def _walk_function(
    md: "capstone.Cs",
    image: bytes,
    base: int,
    start: int,
    known_starts: set[int],
    *,
    max_insns_per_function: int = 20000,
) -> FunctionInfo:
    """从 start 递归下降解码一个函数体（不进入被调用函数）。"""
    info = FunctionInfo(start=start)
    pending: list[int] = [start]
    seen: set[int] = set()
    image_hi = base + len(image)

    while pending and len(seen) < max_insns_per_function:
        a = pending.pop()
        while True:
            if a in seen or not (base <= a < image_hi):
                break
            insn = _decode_at(md, image, base, a)
            if insn is None:
                info.unresolved_ends.append({"at": f"0x{a:08x}", "reason": "undecodable"})
                break
            seen.add(a)
            info.insns[a] = insn
            m, ops = insn.mnemonic, insn.operands

            if m in COND_BRANCHES:
                imm = ops[-1].imm if ops and ops[-1].kind == "imm" else None
                if imm is None:
                    info.unresolved_ends.append({"at": f"0x{a:08x}", "reason": "branch_no_imm"})
                    break
                tgt = (a + imm) & 0xFFFFFFFF
                info.branches.append({
                    "at": a, "insn": insn.text, "target": tgt,
                    "fallthrough": insn.next_addr,
                    "cmp": _branch_cmp(info.insns, a, ops),
                })
                if tgt < a:
                    info.loops.append({"at": a, "target": tgt})
                pending.append(tgt)
                a = insn.next_addr
                continue

            if m in CALL_MNEMONICS:
                imm = ops[0].imm if ops and ops[0].kind == "imm" else None
                if imm is not None:
                    info.calls.append({
                        "at": a, "target": (a + imm) & 0xFFFFFFFF, "kind": m,
                    })
                a = insn.next_addr          # 调用会返回：继续顺序后继
                continue

            if m in JUMP_MNEMONICS:
                imm = ops[0].imm if ops and ops[0].kind == "imm" else None
                if imm is None:
                    info.unresolved_ends.append({"at": f"0x{a:08x}", "reason": "jump_no_imm"})
                    break
                tgt = (a + imm) & 0xFFFFFFFF
                if tgt in known_starts or not (base <= tgt < image_hi):
                    info.tail_calls.append({"at": a, "target": tgt})
                    break
                if tgt < a:
                    info.loops.append({"at": a, "target": tgt})
                a = tgt
                continue

            if m in INDIRECT_MNEMONICS:
                reg = ops[0].reg_name if ops and ops[0].kind == "reg" else None
                is_ret = m == "c.jr" and reg in ("ra", "x1")
                kind = "return" if is_ret else ("call" if "jalr" in m else "jump")
                info.indirect.append({"at": a, "insn": insn.text, "reg": reg, "kind": kind})
                if is_ret:
                    info.ret_sites.append(a)
                else:
                    info.unresolved_ends.append({
                        "at": f"0x{a:08x}",
                        "reason": f"indirect_{kind}_unresolved",
                        "note": "间接跳转目标需运行时解析（函数指针/寄存器），静态不可达",
                    })
                break

            if m in RET_MNEMONICS:
                info.ret_sites.append(a)
                break

            if m in NORETURN_MNEMONICS:
                break

            a = insn.next_addr

    info.calls = [c for c in info.calls if len(c) > 0]
    return info


def _assess_coverage(
    *,
    image_size: int,
    functions: dict[int, FunctionInfo],
    depth: dict[int, int],
    unresolved_end_count: int,
    indirect_site_count: int,
    dispatch_table_count: int,
) -> dict:
    """自评"这次递归下降覆盖够不够"（**防止小镜像上被误读为成功**）。

    为什么要自评（实测教训）：在 168 字节的合成镜像上递归下降只得到 4 个函数、
    30 条指令，摘要看起来"有结果"，但与真实固件（128KB / 217 函数 / 1 万条指令）
    相比覆盖率极低——不加声明会让读者以为"分析已完成"。

    判据（全部结构性、可解释，不猜测）：
      - **指令覆盖率** = 可达指令字节 / 镜像字节；
      - **未解析终点比例** = 因间接跳转/无法解码而停止的路径数 / 函数数；
      - **分派表命中** = 是否解析出表（有表则覆盖率天然受表驱动）。
    """
    reachable_bytes = sum(
        sum(i.size for i in fn.insns.values()) for fn in functions.values()
    )
    instr_coverage = (reachable_bytes / image_size) if image_size else 0.0
    n_fns = max(1, len(functions))
    unresolved_ratio = unresolved_end_count / n_fns

    notes: list[str] = []
    level = "adequate"
    if len(functions) <= 8:
        level = "insufficient_small_graph"
        notes.append(
            f"仅解析出 {len(functions)} 个函数——对真实固件而言明显偏少，"
            "可能原因：入口偏移不对、镜像过小、或大部分代码经间接跳转进入")
    if instr_coverage < 0.05 and image_size > 1024:
        level = "insufficient_low_coverage"
        notes.append(
            f"指令覆盖率仅 {instr_coverage:.1%}（{reachable_bytes}/{image_size} B）——"
            "远低于可用水平，结论不可当作'已分析完整固件'")
    if unresolved_ratio > 0.5 and indirect_site_count > 0:
        if level == "adequate":
            level = "partial_indirect_blocked"
        notes.append(
            f"未解析终点比例 {unresolved_ratio:.1%}（{unresolved_end_count} 处）——"
            "间接跳转是主要阻断原因，可达性不完整")
    if not notes:
        notes.append(
            f"覆盖率自评正常：{len(functions)} 函数 / {reachable_bytes} 可达字节"
            f"（{instr_coverage:.1%}）")
    if dispatch_table_count:
        notes.append(f"已解析 {dispatch_table_count} 张分派表，表驱动的间接目标已并入调用图")

    return {
        "assessment": level,
        "instruction_coverage_ratio": round(instr_coverage, 4),
        "reachable_insn_bytes": reachable_bytes,
        "image_size_bytes": image_size,
        "function_count": len(functions),
        "unresolved_end_ratio": round(unresolved_ratio, 4),
        "dispatch_table_count": dispatch_table_count,
        "usable_for_attribution": level in ("adequate", "partial_indirect_blocked"),
        "reason": "；".join(notes),
        "discipline": (
            "assessment=insufficient_* 表示本次递归下降覆盖不足，"
            "**不得**把本报告的可达集当作完整调用图；"
            "应先用 dispatch/attribute 通道或修正入口偏移"
        ),
    }


def _enclosing(functions: dict[int, FunctionInfo], addr: int) -> int | None:
    for start, fn in functions.items():
        if start <= addr < fn.end:
            return start
    return None


def _global_pointer(image: bytes, base: int, *, xlen: int = 32,
                    compressed: bool = True, window: int = 24) -> dict | None:
    """从复位入口序言推断全局指针 gp 的值（RISC-V ABI 约定的寄存器，非芯片事实）。

    典型形态（可从任意镜像通用识别）：`auipc gp, hi` + `addi gp, gp, lo`
    → gp = pc_of_auipc + (hi<<12) + lo。只读前 `window` 条指令，避免误取后续重写。
    """
    linear = _decode_linear(image, base, xlen=xlen, compressed=compressed)
    head = linear[:window]
    acc: dict[str, int] = {}
    gp_auipc: dict | None = None
    for insn in head:
        m, ops = insn.mnemonic, insn.operands
        if m == "auipc" and len(ops) >= 2 and ops[0].kind == "reg":
            imm = next((o.imm for o in ops[1:] if o.kind == "imm"), None)
            if imm is not None:
                acc[ops[0].reg_name] = (insn.addr + ((imm << 12) & 0xFFFFFFFF)) & 0xFFFFFFFF
                if ops[0].reg_name == "gp":
                    gp_auipc = {"at": f"0x{insn.addr:08x}", "form": "auipc",
                                "insn": insn.text, "partial": acc["gp"]}
        elif m in ("addi", "c.addi") and len(ops) == 3:
            rd, rs1, imm = ops[0].reg_name, ops[1].reg_name, ops[2].imm
            if rd is None or rs1 is None or imm is None:
                continue
            if rs1 in acc:
                acc[rd] = (acc[rs1] + imm) & 0xFFFFFFFF
                if rd == "gp":
                    return {"value": acc["gp"], "at": f"0x{insn.addr:08x}",
                            "form": "auipc_addi", "insn": insn.text,
                            "auipc_at": gp_auipc["at"] if gp_auipc else None,
                            "auipc_insn": gp_auipc["insn"] if gp_auipc else None}
    if gp_auipc is not None:
        # 只见到 auipc 未见 addi：值不完整，显式标注（不猜）
        return {"value": gp_auipc["partial"], "at": gp_auipc["at"],
                "form": "auipc_only", "insn": gp_auipc["insn"],
                "note": "仅见 auipc，未观察到配套 addi；值可能不完整"}
    return None


def _lift_gp_relative(
    image: bytes,
    base: int,
    *,
    gp: dict | None,
    xlen: int = 32,
    compressed: bool = True,
) -> dict:
    """把 `lw/sw/addi rd, off(gp)` 的 gp 相对地址**提升为绝对常量**并回报。

    动机（target-chip 实测）：分派表不在 ROM 里，而是开机时被拷贝到 **RAM**，代码用
    `gp-relative` 偏移访问（`addi a7, gp, -0x388`）。若只跟踪 auipc/lui 常量，
    这类"表基址"永远抓不到 → 间接跳转无法解析。

    返回 {"gp": {...}, "gp_relative_consts": [{value, at, form, insn}],
          "ram_targets": [...]}，全部为结构事实，语义 unknown。
    """
    if not gp or gp.get("value") is None:
        return {"gp": gp, "gp_relative_consts": [], "ram_targets": []}
    gpv = gp["value"]
    linear = _decode_linear(image, base, xlen=xlen, compressed=compressed)
    out: list[dict] = []
    image_hi = base + len(image)
    acc: dict[str, int] = {"gp": gpv}
    for insn in linear:
        m, ops = insn.mnemonic, insn.operands
        if m == "addi" and len(ops) == 3:
            rd, rs1, imm = ops[0].reg_name, ops[1].reg_name, ops[2].imm
            if rd is None or rs1 is None or imm is None:
                continue
            if rs1 in acc:
                val = (acc[rs1] + imm) & 0xFFFFFFFF
                acc[rd] = val
                if rs1 == "gp":
                    out.append({
                        "value": val, "at": f"0x{insn.addr:08x}",
                        "form": "gp_addi", "insn": insn.text,
                        "in_image": base <= val < image_hi,
                        "region_guess": "image" if base <= val < image_hi else "ram_or_mmio",
                    })
        elif m in ("lw", "c.lw", "sw", "c.sw", "lbu", "sb", "lhu", "sh") and ops:
            mem = next((o for o in ops if o.kind == "mem"), None)
            if mem is not None and mem.mem_base in acc:
                ea = (acc[mem.mem_base] + (mem.mem_disp or 0)) & 0xFFFFFFFF
                out.append({
                    "value": ea, "at": f"0x{insn.addr:08x}",
                    "form": "gp_mem", "insn": insn.text,
                    "in_image": base <= ea < image_hi,
                    "region_guess": "image" if base <= ea < image_hi else "ram_or_mmio",
                })
    # 去重（同 value 保留首个证据）
    seen: dict[int, dict] = {}
    for item in out:
        seen.setdefault(item["value"], item)
    consts = sorted(seen.values(), key=lambda x: x["value"])
    return {
        "gp": gp,
        "gp_relative_consts": consts,
        "ram_targets": [c for c in consts if not c["in_image"]],
    }


def _image_constants(image: bytes, base: int, *, xlen: int = 32,
                     compressed: bool = True) -> list[dict]:
    """线性解码全镜像，收集所有**构造出的 32 位常量**（auipc/lui + addi 链）。

    用途：给"指针表扫描"提供**代码侧引用**这一高精度先验——真实分派表的基址
    一定在代码里被构造过；盲扫数据段噪声太大（实测教训）。
    返回 [{value, at, form}]，value 已归一化到 32 位。
    """
    md = _new_disassembler(xlen, compressed)
    linear = _decode_linear(image, base, xlen=xlen, compressed=compressed)
    reg: dict[str, int] = {}
    out: list[dict] = []
    for insn in linear:
        m, ops = insn.mnemonic, insn.operands
        if m in ("auipc",) and len(ops) >= 2 and ops[0].kind == "reg":
            imm = next((o.imm for o in ops[1:] if o.kind == "imm"), None)
            if imm is not None:
                reg[ops[0].reg_name] = (insn.addr + ((imm << 12) & 0xFFFFFFFF)) & 0xFFFFFFFF
        elif m in ("lui", "c.lui") and len(ops) >= 2 and ops[0].kind == "reg":
            imm = next((o.imm for o in ops[1:] if o.kind == "imm"), None)
            if imm is not None:
                reg[ops[0].reg_name] = (imm << 12) & 0xFFFFFFFF
        elif m in ("addi", "c.addi") and len(ops) == 3:
            rd, rs1, imm = ops[0].reg_name, ops[1].reg_name, ops[2].imm
            if rd is None or rs1 is None or imm is None:
                continue
            if rs1 in ("zero", "x0"):
                reg[rd] = imm & 0xFFFFFFFF
            elif rs1 in reg:
                val = (reg[rs1] + imm) & 0xFFFFFFFF
                reg[rd] = val
                out.append({"value": val, "at": insn.addr, "form": "lui_addi"})
    return out


def scan_pointer_tables(
    image: bytes,
    base: int,
    *,
    min_entries: int = 3,
    entry_sizes: tuple[int, ...] = (4, 8, 12, 16),
    interests: set[int] | None = None,
    ptr_align: int = 2,
    seed_addrs: set[int] | None = None,
    max_blind_tables: int = 12,
) -> list[dict]:
    """扫描镜像数据段的**函数指针数组**（间接跳转表候选，芯片无关结构模式）。

    两条通道（精度不同，报告里分别标注）：
      1) **代码引种（高精度，优先）**：`seed_addrs` = 代码里构造过的常量地址
         （见 `_image_constants`）。真实分派表基址必在其中，逐个探测是否构成
         指针数组。这一通道能可靠找到"表在数据段、被代码显式引用"的典型形态。
      2) **盲扫（低精度，兜底）**：数据段逐 4 字节滑窗探测指针数组，用于
         "表地址由复杂运算得出、代码里抓不到常量"的情形；限量返回并标记。

    指针判定：落在 [base, base+len) 且按 `ptr_align` 对齐——**关键**：含 RVC 的
    镜像里函数入口可为 2 字节对齐，用 4 字节对齐会漏掉大量真实表项（实测教训）。

    返回按"是否代码引种 + 表项数 + 已知入口比例"排序。confidence 恒 hypothesis。
    """
    interests = interests or set()
    n = len(image)
    out: list[dict] = []
    image_hi = base + n

    def _ptr_at(off: int) -> int | None:
        if off + 4 > n:
            return None
        v = int.from_bytes(image[off:off + 4], "little")
        if base <= v < image_hi and v % ptr_align == 0:
            return v
        return None

    def _probe_table(off: int, entry_size: int) -> dict | None:
        """从 off 起按 entry_size 连续读取指针表；不足 min_entries 返回 None。"""
        if off < 0 or off + entry_size > n:
            return None
        entries: list[dict] = []
        cur = off
        while cur + entry_size <= n:
            ptr = _ptr_at(cur + entry_size - 4)
            if ptr is None:
                break
            fields = [
                int.from_bytes(image[fo:fo + 4], "little")
                for fo in range(cur, cur + entry_size - 4, 4)
            ]
            entries.append({"entry_addr": base + cur, "fields": fields, "ptr": ptr})
            cur += entry_size
        if len(entries) < min_entries:
            return None
        hits = sum(1 for e in entries if e["ptr"] in interests)
        return {
            "table_addr": base + off,
            "table_addr_hex": f"0x{base + off:08x}",
            "offset": off,
            "entry_size": entry_size,
            "entry_count": len(entries),
            "known_entry_hits": hits,
            "known_entry_ratio": round(hits / len(entries), 3),
            "unique_ptr_count": len({e["ptr"] for e in entries}),
            "entries": [
                {
                    "entry_addr": f"0x{e['entry_addr']:08x}",
                    "fields": [f"0x{f:x}" for f in e["fields"]],
                    "ptr": f"0x{e['ptr']:08x}",
                    "ptr_in_image": True,
                    "known_function": e["ptr"] in interests,
                }
                for e in entries[:64]
            ],
            "confidence": "hypothesis",
            "evidence_kind": "artifact_derived",
        }

    # ---- 通道 1：代码引种（高精度） ----
    if seed_addrs:
        seen: set[tuple[int, int]] = set()
        for addr in sorted(seed_addrs):
            off = addr - base
            if not (0 <= off < n):
                continue
            for es in entry_sizes:
                # 表基址通常按 entry_size 或 4 字节对齐；data 段内以 4 为准
                if addr % 4 not in (0,) and addr % entry_sizes[0] != 0:
                    pass
                t = _probe_table(off, es)
                if t is None:
                    continue
                key = (t["table_addr"], t["entry_size"])
                if key in seen:
                    continue
                seen.add(key)
                t["discovery"] = "code_seeded"
                t["confidence"] = "hypothesis"
                out.append(t)

    # ---- 通道 2：盲扫（低精度兜底） ----
    for es in entry_sizes:
        off = 0
        while off + es <= n:
            if _ptr_at(off + es - 4) is None:
                off += 4
                continue
            t = _probe_table(off, es)
            if t is None:
                off += 4
                continue
            t["discovery"] = "blind_scan"
            out.append(t)
            off += t["entry_count"] * es

    # 去重：同 (table_addr, entry_size) 保留表项最多的一份；优先 code_seeded
    best: dict[tuple[int, int], dict] = {}
    for t in out:
        key = (t["table_addr"], t["entry_size"])
        cur = best.get(key)
        if cur is None:
            best[key] = t
            continue
        prefer = (t.get("discovery") == "code_seeded", t["entry_count"])
        cur_pref = (cur.get("discovery") == "code_seeded", cur["entry_count"])
        if prefer > cur_pref:
            best[key] = t

    # 子表抑制：同 entry_size 下被更大表完全包含且更小的，丢弃（同表局部解读）
    tables = list(best.values())
    kept: list[dict] = []
    for t in sorted(tables, key=lambda x: -x["entry_count"]):
        lo, hi = t["table_addr"], t["table_addr"] + t["entry_count"] * t["entry_size"]
        contained = any(
            k["entry_size"] == t["entry_size"]
            and k["table_addr"] <= lo
            and hi <= k["table_addr"] + k["entry_count"] * k["entry_size"]
            for k in kept
        )
        if not contained:
            kept.append(t)

    # 排序：代码引种优先 → 表项数 → 已知入口比例
    kept.sort(key=lambda t: (
        t.get("discovery") != "code_seeded",
        -t["entry_count"],
        -t["known_entry_ratio"],
        t["table_addr"],
    ))
    # 盲扫通道限量（避免噪声表淹没报告）
    seeded = [t for t in kept if t.get("discovery") == "code_seeded"]
    blind = [t for t in kept if t.get("discovery") != "code_seeded"][:max_blind_tables]
    return seeded + blind


def _as_int(value, default: int = 0) -> int:
    """把地址字段统一成 int。

    链路内部存在两种表示：整数（遍历期）与 '0x...' 字符串（报告期）。
    不做统一会在拼接分派边时炸掉（历史 bug：int() 收到 int 报 TypeError）。
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            return default
    return default


def _detect_dispatch_tables(
    image: bytes,
    base: int,
    functions: dict[int, FunctionInfo],
    *,
    xlen: int = 32,
    compressed: bool = True,
    min_entries: int = 3,
    max_tables: int = 8,
) -> list[dict]:
    """在递归下降得到的函数集合上找"分派表 + 分派器"，并解析间接跳转目标。

    判定（结构启发式，全部 hypothesis）：
      1) 数据段存在 ≥min_entries 项的函数指针表；
      2) 某函数体内引用过该表地址（表基址常量跟踪命中）→ 该函数为"分派器候选"；
      3) 分派器内的间接跳转点（jalr/c.jalr/c.jr）→ 指向表项 ptr 之一。
    这样就把"静态不可解析的间接跳转"变成**可枚举的目标集合**。
    """
    known = set(functions)
    # 代码侧构造过的常量 → 表基址先验（高精度通道）
    consts = _image_constants(image, base)
    seeds = {c["value"] for c in consts if base <= c["value"] < base + len(image)}
    # gp 相对寻址抬升：RAM 中的表（开机从 ROM 拷贝或运行期填充）只能靠 gp 偏移抓到
    gp_info = _global_pointer(image, base, xlen=xlen, compressed=compressed)
    gp_lift = _lift_gp_relative(image, base, gp=gp_info, xlen=xlen, compressed=compressed)
    gp_seeds = {c["value"] for c in gp_lift["gp_relative_consts"]}
    tables = scan_pointer_tables(image, base, min_entries=min_entries,
                                 interests=known, seed_addrs=seeds | gp_seeds)
    resolved: list[dict] = []

    for table in tables[:max_tables]:
        taddr = table["table_addr"]
        targets = []
        for e in table["entries"]:
            p = int(e["ptr"], 16)
            entry_addr = int(e["entry_addr"], 16)
            targets.append({
                "entry_addr": f"0x{entry_addr:08x}",
                "fields": e["fields"],
                "target": f"0x{p:08x}",
                "target_in_image": base <= p < base + len(image),
                "target_is_known_function": p in known,
                "in_recursive_descent": p in known,
            })        # 谁是分派器：函数体内常量装载命中表基址，或含间接跳转且函数体常量接近表
        dispatchers = []
        for start, fn in functions.items():
            loads = _value_snapshot_track(fn.insns)
            if any(abs(l["value"] - taddr) <= 8 for l in loads):
                dispatchers.append({
                    "function": f"0x{start:08x}",
                    "evidence": [
                        {"at": f"0x{l['at']:08x}", "value": f"0x{l['value']:x}"}
                        for l in loads if abs(l["value"] - taddr) <= 8
                    ][:6],
                    "indirect_sites": [
                        {"at": f"0x{i['at']:08x}", "insn": i["insn"]}
                        for i in fn.indirect
                    ][:8],
                })
        resolved.append({
            "table_addr": table["table_addr_hex"],
            "entry_size": table["entry_size"],
            "entry_count": table["entry_count"],
            "known_entry_ratio": table["known_entry_ratio"],
            "dispatcher_candidates": dispatchers,
            "targets": targets,
            "resolved_indirect_targets": sorted(
                {t["target"] for t in targets if t["target_in_image"]}),
            "confidence": "hypothesis",
            "evidence_kind": "artifact_derived",
            "note": "表/分派器为结构识别结果；表项字段语义（命令号/标志位）未知，需人工或行为验证",
        })
    return resolved


def discover_chain(
    image_path: str,
    base: int,
    *,
    xlen: int = 32,
    compressed: bool = True,
    entry_offset: int = 0,
    extra_entries: list[int] | None = None,
    target_addr: int | None = None,
    target_string: str | None = None,
    target_const: int | None = None,
    max_paths: int = 8,
    max_functions: int = 600,
    include_function_details: bool = True,
    max_insns_per_function: int = 20000,
    resolve_indirect_tables: bool = True,
    min_table_entries: int = 3,
    max_tables: int = 8,
) -> dict:
    """主入口：镜像 + 目标特征 → 调用链报告（dict）。

    target_addr   : 目标函数地址（或函数体内任一地址，自动归属所在函数）
    target_string : 目标行为特征字符串（镜像内定位 → 引用该串的函数）
    target_const  : 目标关键常量（如错误码/命令号），找装载该常量的函数
    三者可同时给（交叉定位）；都不给则只输出可达调用图。
    """
    image = load_image(image_path)
    strings = _printable_strings(image)
    strings_at = {base + s["offset"]: s["text"] for s in strings}
    image_hi = base + len(image)

    linear = _decode_linear(image, base, xlen=xlen, compressed=compressed)

    # 已知函数入口 = 直接调用目标（递归下降用它来区分"尾调用"与"本地跳转"）
    known_starts: set[int] = {base + entry_offset}
    for insn in linear:
        if insn.mnemonic in CALL_MNEMONICS:
            for o in insn.operands:
                if o.kind == "imm":
                    tgt = (insn.addr + o.imm) & 0xFFFFFFFF
                    if base <= tgt < image_hi:
                        known_starts.add(tgt)
    for a in (extra_entries or []):
        known_starts.add(a)

    roots = [base + entry_offset] + [a for a in (extra_entries or [])]
    roots = [r for r in roots if base <= r < image_hi]

    # 递归下降：从根出发，遇到调用边就把被调方加入队列
    md = _new_disassembler(xlen, compressed)
    functions: dict[int, FunctionInfo] = {}
    queue: deque[int] = deque(roots)
    while queue and len(functions) < max_functions:
        start = queue.popleft()
        if start in functions or not (base <= start < image_hi):
            continue
        fn = _walk_function(md, image, base, start, known_starts,
                            max_insns_per_function=max_insns_per_function)
        if not fn.insns:
            continue
        fn.string_refs = _string_refs(fn.insns, strings_at)
        functions[start] = fn
        for c in fn.calls + fn.tail_calls:
            tgt = c["target"]
            if base <= tgt < image_hi and tgt not in functions:
                queue.append(tgt)

    callers: dict[int, list[dict]] = defaultdict(list)
    for start, fn in functions.items():
        for c in fn.calls:
            callers[c["target"]].append({"caller": start, "at": c["at"], "kind": c["kind"]})
        for c in fn.tail_calls:
            callers[c["target"]].append({"caller": start, "at": c["at"], "kind": "tail"})

    # ---- 间接跳转解析：数据段函数指针表（分派表）→ 把间接目标并入调用图 ----
    # 动机（target-chip 实测教训）：ISP 命令 handler 全部经"表 + jalr"分派，纯静态递归下降
    # 到达不了；表一旦识别出来，间接跳转就从"不可达"变成"可枚举目标集合"。
    dispatch_tables: list[dict] = []
    indirect_edges: list[dict] = []
    if resolve_indirect_tables:
        dispatch_tables = _detect_dispatch_tables(
            image, base, functions, xlen=xlen, compressed=compressed,
            min_entries=min_table_entries, max_tables=max_tables)
        for table in dispatch_tables:
            taddr = int(table["table_addr"], 16)
            entry_by_addr = {int(t["target"], 16): t for t in table["targets"]}
            for start, fn in functions.items():
                loads = _value_snapshot_track(fn.insns)
                if not any(abs(l["value"] - taddr) <= 8 for l in loads):
                    continue
                for site in fn.indirect:
                    # 分派器的间接跳转 → 表项目标（集合语义，不判定具体哪一项）
                    for tgt, tinfo in entry_by_addr.items():
                        indirect_edges.append({
                            "at": site["at"], "insn": site["insn"],
                            "dispatcher": f"0x{start:08x}",
                            "table": table["table_addr"],
                            "target": f"0x{tgt:08x}",
                            "entry_fields": tinfo["fields"],
                            "kind": "table_dispatch_candidate",
                        })
                        queue.append(tgt)
        # 第二轮展开：把表项目标也递归下降进来
        while queue and len(functions) < max_functions:
            start = queue.popleft()
            if start in functions or not (base <= start < image_hi):
                continue
            fn = _walk_function(md, image, base, start, known_starts,
                                max_insns_per_function=max_insns_per_function)
            if not fn.insns:
                continue
            fn.string_refs = _string_refs(fn.insns, strings_at)
            functions[start] = fn
            for c in fn.calls + fn.tail_calls:
                tgt = c["target"]
                if base <= tgt < image_hi and tgt not in functions:
                    queue.append(tgt)
        # 第二轮后重建调用者索引（第一轮索引已过时）
        callers = defaultdict(list)
        for start, fn in functions.items():
            for c in fn.calls:
                callers[c["target"]].append({"caller": start, "at": c["at"], "kind": c["kind"]})
            for c in fn.tail_calls:
                callers[c["target"]].append({"caller": start, "at": c["at"], "kind": "tail"})

    # 分派边并入深度计算（BFS 沿 calls/tail_calls/indirect 三类边）
    dispatch_targets_by_caller: dict[int, list[int]] = defaultdict(list)
    for e in indirect_edges:
        disp_addr = _as_int(e["dispatcher"])
        target_addr = _as_int(e["target"])
        site_addr = _as_int(e.get("at"))
        dispatch_targets_by_caller[disp_addr].append(target_addr)
        callers[target_addr].append(
            {"caller": disp_addr, "at": site_addr,
             "kind": "table_dispatch"})

    # 可达深度（从根 BFS，仅走已下降到的函数；含表分派边）
    depth: dict[int, int] = {}
    dq: deque[int] = deque()
    for r in roots:
        if r in functions:
            depth[r] = 0
            dq.append(r)
    while dq:
        cur = dq.popleft()
        nexts = [c["target"] for c in functions[cur].calls + functions[cur].tail_calls]
        nexts += dispatch_targets_by_caller.get(cur, [])
        for tgt in nexts:
            if tgt in functions and tgt not in depth:
                depth[tgt] = depth[cur] + 1
                dq.append(tgt)

    # ---- 目标解析 ----
    target_info: dict = {"requested": {
        "addr": f"0x{target_addr:08x}" if target_addr is not None else None,
        "string": target_string,
        "const": f"0x{target_const:x}" if target_const is not None else None,
    }}
    target_fns: list[int] = []
    feature_hits: list[dict] = []

    if target_string is not None:
        matches = [s for s in strings if target_string in s["text"]]
        ptrs = {base + s["offset"] for s in matches}
        for start, fn in functions.items():
            refs = [r for r in fn.string_refs if r["ptr"] in ptrs]
            if refs:
                feature_hits.append({
                    "kind": "string_ref",
                    "function": f"0x{start:08x}",
                    "function_reachable": start in depth,
                    "refs": [{"at": f"0x{r['at']:08x}", "text": r["text"]} for r in refs[:8]],
                })
                target_fns.append(start)
        target_info["string_matches"] = [
            {"offset": s["offset"], "addr": f"0x{base + s['offset']:08x}", "text": s["text"]}
            for s in matches[:20]
        ]

    if target_const is not None:
        for start, fn in functions.items():
            loads = _value_snapshot_track(fn.insns)
            hits = [c for c in loads if c["value"] == target_const]
            if hits:
                feature_hits.append({
                    "kind": "const_load",
                    "function": f"0x{start:08x}",
                    "function_reachable": start in depth,
                    "loads": [{"at": f"0x{h['at']:08x}", "reg": h["reg"], "form": h["form"]}
                              for h in hits[:8]],
                })
                target_fns.append(start)

    if target_addr is not None:
        enclosing = _enclosing(functions, target_addr)
        if enclosing is None:
            target_info["addr_note"] = "目标地址不在任何已递归下降的函数体内（可能仅在间接跳转之后可达）"
        else:
            target_fns.append(enclosing)

    target_fns = sorted(set(target_fns))
    target_info["resolved"] = bool(target_fns)
    target_info["target_functions"] = [f"0x{f:08x}" for f in target_fns]

    # ---- 路径枚举 ----
    def _next_edges(cur: int) -> list[tuple[int, dict]]:
        """一个函数可走出的边（直接调用 / 尾调用 / 表分派）。"""
        out: list[tuple[int, dict]] = []
        for c in functions[cur].calls + functions[cur].tail_calls:
            out.append((c["target"], {"at": f"0x{c['at']:08x}",
                                      "kind": c.get("kind", "call")}))
        for tgt in dispatch_targets_by_caller.get(cur, []):
            out.append((tgt, {"at": "table_dispatch", "kind": "table_dispatch"}))
        return out

    def _paths_to(tgt_fn: int) -> list[dict]:
        out: list[dict] = []
        stack: list[tuple[int, list[int], list[dict]]] = [
            (r, [r], []) for r in roots if r in functions
        ]
        guard = 0
        while stack and len(out) < max_paths and guard < 200000:
            guard += 1
            cur, chain, edges = stack.pop()
            if cur == tgt_fn:
                out.append({"chain": chain, "call_sites": edges})
                continue
            if len(chain) > max(2, depth.get(tgt_fn, 1) + 6):
                continue
            for tgt, edge in _next_edges(cur):
                if tgt in functions and tgt not in chain:
                    stack.append((tgt, chain + [tgt], edges + [edge]))
        return out

    paths: list[dict] = []
    for tf in target_fns:
        for p in _paths_to(tf):
            chain = p["chain"]
            est = sum(functions[a].insn_count for a in chain if a in functions)
            loops = sum(len(functions[a].loops) for a in chain if a in functions)
            unresolved = sum(len(functions[a].unresolved_ends) for a in chain if a in functions)
            strings_in_chain: list[dict] = []
            for a in chain:
                if a in functions:
                    for s in functions[a].string_refs:
                        strings_in_chain.append({"at": f"0x{s['at']:08x}", "text": s["text"]})
            paths.append({
                "target_function": f"0x{tf:08x}",
                "chain": [f"0x{a:08x}" for a in chain],
                "call_sites": p["call_sites"],
                "depth": len(chain) - 1,
                "est_insn_count_lower_bound": est,
                "loop_suspects_in_chain": loops,
                "unresolved_sites_in_chain": unresolved,
                "string_anchors_in_chain": strings_in_chain[:24],
                "est_note": "静态下界（每函数只计一次、不含循环迭代）→ 仅作 delay 下界，不是运行时长",
            })
    paths.sort(key=lambda p: (p["depth"], p["est_insn_count_lower_bound"]))
    paths = paths[:max_paths]

    reachable_list = sorted(depth, key=lambda a: (depth[a], a))
    details = []
    if include_function_details:
        details = [functions[a].to_dict(image_lo=base, image_hi=image_hi)
                   for a in reachable_list]

    coverage = _assess_coverage(
        image_size=len(image),
        functions=functions,
        depth=depth,
        unresolved_end_count=sum(len(f.unresolved_ends) for f in functions.values()),
        indirect_site_count=sum(len(f.indirect) for f in functions.values()),
        dispatch_table_count=len(dispatch_tables),
    )

    return {
        "schema": "fi.discover.chain-report-v0",
        "tool": {"name": "fi.discover.chain", "version": "0.1.0"},
        "coverage": coverage,
        "image": {
            "path": str(image_path), "sha256": sha256_hex(image),
            "size_bytes": len(image), "base_address": base,
            "base_address_hex": f"0x{base:08x}",
        },
        "method": {
            "approach": "recursive descent（从入口真实可达的代码），线性解码仅用于收集调用目标与串锚点",
            "steps": [
                "线性解码全镜像 → 收集直接调用（jal/c.jal）目标 = 已知函数入口",
                "从根（复位入口 + 附加入口）递归下降；调用边入队被调方，本地继续返回点",
                "无条件跳转目标若为已知入口 → 记尾调用；否则视为本地跳转继续",
                "间接跳转/调用 → 登记 unresolved（静态不可解析），停止该路径",
                "**数据段函数指针表扫描**：连续镜像内指针数组 → 表候选；分派器内间接跳转按表项目标展开（把不可解析变可枚举）",
                "调用图 BFS 求可达深度（含表分派边）；DFS 枚举根→目标路径与指令数下界",
            ],
            "target_resolution": [
                "target_addr：归属所在函数（递归下降已覆盖的函数体内任一地址）",
                "target_string：镜像内 ASCII 串 → 引用该串的函数（功能特征锚点）",
                "target_const：装载该常量的函数（错误码/命令号候选）",
            ],
            "boundaries": [
                "仍无法解析的间接调用（目标不在任何已识别表中）逐点登记 unresolved，可达性可能不完整",
                "表识别为结构启发式：entry_size 试 {4,8,12,16}，可能同时给出多种解读；表项字段语义（命令号/标志）未知",
                "表分派边是**集合语义**（分派器可跳到表中任一项），不表示某次运行实际走哪一项",
                "无数据流/值集分析：分支条件不判真假 → 结构可达，非运行时必然",
                "循环只标嫌疑（向后跳转），不做迭代计数 → 指令数只是下界，不是运行时长",
                "常量/串引用跟踪为函数内线性近似（跨分支不合并），可能漏检寄存器间接构造",
            ],
        },
        "entry": {
            "offset": entry_offset,
            "addr": f"0x{base + entry_offset:08x}",
            "extra_entries": [f"0x{a:08x}" for a in (extra_entries or [])],
        },
        "summary": {
            "string_count": len(strings),
            "root_count": len(roots),
            "function_count": len(functions),
            "reachable_function_count": len(depth),
            "call_edge_count": sum(len(f.calls) for f in functions.values()),
            "tail_call_edge_count": sum(len(f.tail_calls) for f in functions.values()),
            "indirect_site_count": sum(len(f.indirect) for f in functions.values()),
            "unresolved_end_count": sum(len(f.unresolved_ends) for f in functions.values()),
            "total_reachable_insns": sum(f.insn_count for f in functions.values()),
            "target_resolved": target_info.get("resolved", False),
            "paths_found": len(paths),
            "max_depth": max(depth.values()) if depth else 0,
            "dispatch_table_count": len(dispatch_tables),
            "dispatch_edge_count": len(indirect_edges),
            "indirect_resolved_count": len({e["target"] for e in indirect_edges}),
        },
        "target": target_info,
        "feature_hits": feature_hits[:20],
        "paths": paths,
        "dispatch_tables": dispatch_tables,
        "dispatch_edges": indirect_edges[:200],
        "functions_reachable": [
            {"addr": f"0x{a:08x}", "depth": depth[a],
             "insn_count": functions[a].insn_count,
             "callers": [f"0x{c['caller']:08x}" for c in callers.get(a, [])][:8]}
            for a in reachable_list
        ],
        "functions": details,
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
