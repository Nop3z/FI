# -*- coding: utf-8 -*-
"""fi.fault：故障效果推演（bit-flip → 语义变化 → 执行结果）。

## 定位（对应 hn security 文章方法论）

`fi.discover` 解决"打中了哪条指令"（静态归因）；
本模块解决**"这条指令被打坏后变成了什么、为什么产生这个观测"**。

三条能力：
  1) **枚举**：给定一条指令的机器码，枚举"1→0"翻转 N 个 bit 后的所有变体，
     反汇编并判语义是否改变（对应文章作者的 opcode_calculator）。
  2) **推演**：把变体指令放进 Unicorn 仿真，算出执行后的寄存器/内存差异
     ——回答"这条损坏指令执行后，a6 会变成多少"。
  3) **反解**：给定观测到的寄存器差异，反推最可能的损坏指令候选集合
     （**允许多解**：多个变体可产生相同观测，必须全部列出并标注）。

## 物理假设（重要，必须显式声明）

crowbar-to-ground 类电压毛刺的常见效果是**把某些位从 1 变成 0**，
而不是"跳过指令"。这是 hypothesis 级物理假设，可用 `flip_mode` 切换为
`one_to_zero` / `zero_to_one` / `both`，不同毛刺方式（EMFI、时钟毛刺）
效果可能不同。

## 纪律

- 全部产出 `confidence=hypothesis`：这是候选解释，不是已证实的物理过程
- 反解结果**不得只报一个解**：必须列出全部能解释观测的候选
- 语义未变的翻转（如改到保留位/RD=x0 等）单独归类，不与"语义改变"混淆
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from itertools import combinations

import capstone

SCHEMA = "fi.fault.effect-v0"

# RISC-V RV32 通用寄存器 ABI 名（ISA 常量，非芯片实例值）
_X_ABI = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
]


def _disasm_one(code: bytes, addr: int, xlen: int = 32) -> str | None:
    """反汇编一条指令（**必须启用 RVC**：2 字节压缩指令是 RISC-V 固件的常态形态）。

    实测教训（2026-11-10）：早期版本只设 `CS_MODE_RISCV32`、未设 `CS_MODE_RISCVC`，
    导致所有 2 字节压缩指令（`c.bnez`/`c.srli`/`c.andi`/`c.jr` 等）**完全无法解码**，
    `orig_text` 为 None、全部变体也都解不出 → 位翻转推演对压缩指令整段失效。
    而门检查这类短小关键函数**几乎全是 2 字节指令**，所以这是致命缺陷。
    """
    md = capstone.Cs(capstone.CS_ARCH_RISCV,
                     (capstone.CS_MODE_RISCV32 if xlen == 32
                      else capstone.CS_MODE_RISCV64) | capstone.CS_MODE_RISCVC)
    md.detail = False
    try:
        insn = next(md.disasm(code, addr))
    except StopIteration:
        return None
    return f"{insn.mnemonic} {insn.op_str}".strip()


@dataclass
class Variant:
    """一条指令的某个位翻转变体。"""
    flipped_bit_positions: list[int]        # 从 LSB 起算的位位置
    mutated_code: bytes
    mutated_insn: str | None                # 反汇编；None = 无法解码
    semantics_changed: bool                 # 与原始指令语义是否不同
    change_kind: str                        # same | rd_changed | rs_changed | imm_changed
                                            #   | opcode_changed | undecodable | nop_like
    raw_diff_hex: str


def _semantic_kind(orig: str, new: str | None) -> tuple[bool, str]:
    """判断语义变化类别（结构比较，不做完整 ISA 模拟）。"""
    if new is None:
        return True, "undecodable"
    if new == orig:
        return False, "same"
    o = orig.split(None, 1)
    n = new.split(None, 1)
    o_mnem, n_mnem = (o[0], o[1] if len(o) > 1 else "") if o else ("", "")
    n_mnem2, n_ops = (n[0], n[1] if len(n) > 1 else "") if n else ("", "")
    # 变成 nop 类
    if n_mnem2 in ("nop", "c.nop"):
        return True, "nop_like"
    if o_mnem != n_mnem2:
        return True, "opcode_changed"
    # 操作数逐字段比较
    o_fields = [t.strip() for t in o_mnem and o[1].split(",") if t.strip()] if len(o) > 1 else []
    n_fields = [t.strip() for t in n_ops.split(",") if t.strip()] if n_ops else []
    if not o_fields or not n_fields or len(o_fields) != len(n_fields):
        return True, "opcode_changed"
    if o_fields[0] != n_fields[0]:
        return True, "rd_changed"
    if len(o_fields) > 1 and o_fields[1] != n_fields[1]:
        return True, "rs_changed"
    if o_fields[-1] != n_fields[-1]:
        return True, "imm_changed"
    return True, "opcode_changed"


def enumerate_bitflips(
    insn_bytes: bytes,
    addr: int,
    *,
    max_flips: int = 4,
    flip_mode: str = "one_to_zero",
    xlen: int = 32,
    include_semantics_unchanged: bool = False,
) -> list[Variant]:
    """枚举一条指令在"1→0"翻转 N 个 bit 后的所有变体。

    ``flip_mode``：
      - ``one_to_zero``（默认）：只翻转当前为 1 的位（crowbar-to-ground 物理假设）
      - ``zero_to_one``：只翻转当前为 0 的位
      - ``both``：任意位
    ``max_flips``：最大同时翻转的位数（文章实测 1-6 位都有，默认 4 控制枚举规模）
    """
    if flip_mode not in ("one_to_zero", "zero_to_one", "both"):
        raise ValueError(f"flip_mode 非法: {flip_mode}")

    n_bits = len(insn_bytes) * 8
    orig_val = int.from_bytes(insn_bytes, "little")
    orig_text = _disasm_one(insn_bytes, addr, xlen)

    candidates: list[int] = []
    for pos in range(n_bits):
        bit = (orig_val >> pos) & 1
        if flip_mode == "one_to_zero" and bit != 1:
            continue
        if flip_mode == "zero_to_one" and bit != 0:
            continue
        candidates.append(pos)

    out: list[Variant] = []
    for k in range(1, min(max_flips, len(candidates)) + 1):
        for combo in combinations(candidates, k):
            new_val = orig_val
            for pos in combo:
                new_val ^= (1 << pos)
            new_bytes = new_val.to_bytes(len(insn_bytes), "little")
            new_text = _disasm_one(new_bytes, addr, xlen)
            changed, kind = _semantic_kind(orig_text or "", new_text)
            if not changed and not include_semantics_unchanged:
                continue
            out.append(Variant(
                flipped_bit_positions=list(combo),
                mutated_code=new_bytes,
                mutated_insn=new_text,
                semantics_changed=changed,
                change_kind=kind,
                raw_diff_hex=(orig_val ^ new_val).to_bytes(len(insn_bytes), "little").hex(),
            ))
    return out


def summarize_variants(variants: list[Variant], insn_text: str | None) -> dict:
    """按变化类别统计，给出"哪些翻转会产生什么样的语义破坏"的分布。"""
    by_kind: dict[str, int] = {}
    for v in variants:
        by_kind[v.change_kind] = by_kind.get(v.change_kind, 0) + 1
    # 只保留"可执行且语义改变"的变体作为主要候选
    effective = [v for v in variants if v.mutated_insn and v.change_kind not in ("same",)]
    return {
        "original_insn": insn_text,
        "n_variants_total": len(variants),
        "n_variants_semantically_changed": len(effective),
        "by_change_kind": by_kind,
        "physical_assumption": (
            "假设毛刺效果为把若干 1 位翻成 0（crowbar-to-ground 常见效果）；"
            "不同毛刺技术（EMFI/时钟毛刺）效果可能不同，此为 hypothesis"
        ),
        "discipline": "变体是候选解释，不是已证实的物理过程；真实毛刺可能同时影响多条指令",
    }


def classify_observation(
    *,
    pc_ok: bool,
    target_reg_ok: bool,
    other_regs_changed: bool,
    restarted: bool,
) -> dict:
    """观测结果五色分类（对齐 hn security 文章的实务分类法）。

    返回 kind ∈ normal | restart | pc_wrong | missed_target | target_hit
    """
    if restarted:
        kind, label, note = "restart", "品红", "CPU 重启：通常毛刺过长/电压跌落过深"
    elif not pc_ok:
        kind, label, note = "pc_wrong", "黄", "PC 错误：未走到目标代码，毛刺影响了更早的路径"
    elif target_reg_ok and not other_regs_changed:
        kind, label, note = "normal", "绿", "正常：PC 与寄存器均符合预期（未命中）"
    elif target_reg_ok and other_regs_changed:
        kind, label, note = "missed_target", "青", "命中了某处但非目标指令：目标寄存器未变，其他寄存器变了"
    else:
        kind, label, note = "target_hit", "红", "**命中目标指令**：PC 正确但目标寄存器值不符预期"
    return {
        "kind": kind,
        "label": label,
        "note": note,
        "is_interesting": kind == "target_hit",
        "confidence": "observation",
    }
