# -*- coding: utf-8 -*-
"""fi.fault.reasoning：观测结果反解（从"看到什么"反推"哪条指令被打成什么"）。

## 输入/输出

输入：观测到的寄存器差异（如 `{"a6": 0x77}`）+ 目标指令地址 + 期望值
输出：能解释该观测的候选集合，每条含
       - 变体指令（位翻转后的机器码与反汇编）
       - 该变体执行后的寄存器效应（用轻量表达式求值，不跑完整仿真）
       - 与观测的匹配程度

## 为什么要"轻量求值"而不直接跑 Unicorn

反解场景要对**成千上万个变体**做候选筛选。逐个起 Unicorn 实例太慢（每个 ~ms 级）。
本模块先用 RISC-V 整数指令的语义直接求值（addi/lui/or/and/slli 等常见形态），
筛出候选后再交仿真器精算。这是性能与精度的分层：
  - 第一层（本模块）：快速筛选，覆盖常见 ALU 指令
  - 第二层（fi.sim）：对少量候选做完整指令级仿真验证

## 纪律

- **允许多解**：多个变体可能产生相同观测，必须全部列出
- 求值失败/不支持的指令形态要显式标注 `evaluated=false`，不得猜
- 全部 `confidence=hypothesis`
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .effects import Variant, enumerate_bitflips

SCHEMA = "fi.fault.reasoning-v0"


def _parse_imm(tok: str) -> int | None:
    t = tok.strip()
    try:
        return int(t, 0)
    except ValueError:
        # 形如 "-0x10" / "0x10"
        return None


_RE_ADDI = re.compile(r"^(?:c\.addi|addi)\s+(\w+),\s*(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_LI = re.compile(r"^(?:c\.li|li)\s+(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_LUI = re.compile(r"^(?:c\.lui|lui)\s+(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$")
_RE_ADD = re.compile(r"^(?:c\.add|add)\s+(\w+),\s*(\w+),\s*(\w+)$")
_RE_SUB = re.compile(r"^sub\s+(\w+),\s*(\w+),\s*(\w+)$")
_RE_AND = re.compile(r"^(?:c\.and|and)\s+(\w+),\s*(\w+),\s*(\w+)$")
_RE_OR = re.compile(r"^(?:c\.or|or)\s+(\w+),\s*(\w+),\s*(\w+)$")
_RE_XOR = re.compile(r"^(?:c\.xor|xor)\s+(\w+),\s*(\w+),\s*(\w+)$")
_RE_SLLI = re.compile(r"^(?:c\.slli|slli)\s+(\w+),\s*(\w+),\s*(?:0x)?([0-9a-fA-F]+|\d+)$")


def _eval_insn(text: str, regs: dict[str, int]) -> tuple[dict[str, int], str]:
    """对一条整数指令做语义求值，返回 (新寄存器字典, 状态说明)。

    状态：ok | unsupported | undecodable
    只覆盖常见 ALU 形态；访存/分支/跳转/CSR 不在此求值（返回 unsupported），
    需交仿真器精算——本层只做快速筛选。
    """
    out = dict(regs)
    m = _RE_ADDI.match(text)
    if m:
        rd, rs1, imm_s = m.group(1), m.group(2), m.group(3)
        imm = _parse_imm(imm_s)
        if imm is None or rs1 not in regs:
            return out, "unsupported"
        imm &= 0xFFF
        if imm >= 2048:
            imm -= 4096
        val = (regs[rs1] + imm) & 0xFFFFFFFF
        if rd != "zero":
            out[rd] = val
        return out, "ok"
    m = _RE_LI.match(text)
    if m:
        rd, imm_s = m.group(1), m.group(2)
        imm = _parse_imm(imm_s)
        if imm is None:
            return out, "unsupported"
        if rd != "zero":
            out[rd] = imm & 0xFFFFFFFF
        return out, "ok"
    m = _RE_LUI.match(text)
    if m:
        rd, imm_s = m.group(1), m.group(2)
        imm = _parse_imm(imm_s)
        if imm is None:
            return out, "unsupported"
        if rd != "zero":
            out[rd] = (imm << 12) & 0xFFFFFFFF
        return out, "ok"
    for rx, fn in ((_RE_ADD, lambda a, b: (a + b) & 0xFFFFFFFF),
                   (_RE_SUB, lambda a, b: (a - b) & 0xFFFFFFFF),
                   (_RE_AND, lambda a, b: a & b),
                   (_RE_OR, lambda a, b: a | b),
                   (_RE_XOR, lambda a, b: a ^ b)):
        m = rx.match(text)
        if m:
            rd, rs1, rs2 = m.group(1), m.group(2), m.group(3)
            if rs1 not in regs or rs2 not in regs:
                return out, "unsupported"
            if rd != "zero":
                out[rd] = fn(regs[rs1], regs[rs2])
            return out, "ok"
    m = _RE_SLLI.match(text)
    if m:
        rd, rs1, sh_s = m.group(1), m.group(2), m.group(3)
        sh = _parse_imm(sh_s)
        if sh is None or rs1 not in regs:
            return out, "unsupported"
        if rd != "zero":
            out[rd] = (regs[rs1] << sh) & 0xFFFFFFFF
        return out, "ok"
    return out, "unsupported"


@dataclass
class Candidate:
    variant: Variant
    predicted_regs: dict[str, int]
    matches_observed: bool
    mismatch: dict[str, dict]
    eval_status: str


def explain_observation(
    *,
    insn_bytes: bytes,
    insn_addr: int,
    pre_regs: dict[str, int],
    observed_regs: dict[str, int],
    max_flips: int = 4,
    flip_mode: str = "one_to_zero",
    focus_regs: list[str] | None = None,
) -> dict:
    """给定"指令执行前的寄存器"与"观测到的寄存器"，反推最可能的损坏变体。

    ``focus_regs``：只关心这些寄存器的差异（默认：所有在 observed_regs 中出现的）。
    返回全部能解释观测的候选（多解全部列出）。
    """
    variants = enumerate_bitflips(insn_bytes, insn_addr, max_flips=max_flips,
                                  flip_mode=flip_mode)
    focus = focus_regs or list(observed_regs.keys())

    candidates: list[Candidate] = []
    unsupported = 0
    for v in variants:
        if not v.mutated_insn:
            continue
        regs_after, status = _eval_insn(v.mutated_insn, pre_regs)
        if status != "ok":
            unsupported += 1
            candidates.append(Candidate(v, {}, False,
                                        {"_eval": {"status": status}}, status))
            continue
        mismatch = {}
        for r in focus:
            exp = observed_regs.get(r)
            got = regs_after.get(r, pre_regs.get(r))
            if exp is not None and got is not None and got != exp:
                mismatch[r] = {"observed": f"0x{exp:08x}", "predicted": f"0x{got:08x}"}
        candidates.append(Candidate(v, {k: regs_after.get(k, 0) for k in focus},
                                    not mismatch, mismatch, status))

    matched = [c for c in candidates if c.eval_status == "ok" and c.matches_observed]
    evaluated = [c for c in candidates if c.eval_status == "ok"]

    def _fmt(c: Candidate) -> dict:
        return {
            "flipped_bit_positions": c.variant.flipped_bit_positions,
            "raw_diff_hex": c.variant.raw_diff_hex,
            "mutated_insn": c.variant.mutated_insn,
            "change_kind": c.variant.change_kind,
            "predicted": {k: f"0x{v:08x}" for k, v in c.predicted_regs.items()},
            "confidence": "hypothesis",
        }

    return {
        "schema": SCHEMA,
        "original_insn": None,      # 由调用方补充（本函数只拿到字节）
        "insn_addr": f"0x{insn_addr:08x}",
        "insn_bytes": insn_bytes.hex(),
        "observation": {k: f"0x{v:08x}" for k, v in observed_regs.items()},
        "pre_state": {k: f"0x{v:08x}" for k, v in pre_regs.items()},
        "physical_assumption": {
            "flip_mode": flip_mode,
            "max_flips": max_flips,
            "note": "假设毛刺把若干位 1→0（crowbar-to-ground 常见效果）；"
                    "不同技术效果可能不同，此为 hypothesis",
        },
        "summary": {
            "variants_considered": len(variants),
            "variants_evaluated": len(evaluated),
            "variants_unsupported": unsupported,
            "matching_candidates": len(matched),
            "multiple_solutions": len(matched) > 1,
        },
        "candidates": [_fmt(c) for c in matched],
        "evaluated_but_not_matching": [_fmt(c) for c in evaluated
                                       if not c.matches_observed][:20],
        "discipline": (
            "多解时全部列出，不得只报一个；候选是 hypothesis 级解释，"
            "需仿真/实测验证；不支持求值的指令形态已计入 variants_unsupported"
        ),
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
