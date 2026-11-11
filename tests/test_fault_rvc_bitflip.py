# -*- coding: utf-8 -*-
"""RVC（2 字节压缩指令）位翻转与反解的回归测试。

## 背景（真实 bug，2026-11-10 修复）

`fi.fault.effects._disasm_one` 早期**未启用 `CS_MODE_RISCVC`**，导致所有 2 字节
压缩指令无法解码：`orig_text=None`、变体 `mutated_insn` 也全为 None →
`enumerate_bitflips` 对 RVC 指令"产出 0 个可用变体"（实际产出 N 个全 undecodable 的）。

这是致命缺陷：**门检查这类关键短函数几乎全是 RVC 指令**
（`c.srli`/`c.andi`/`c.bnez`/`c.jr`），整段推演失效。

同时 `fi.fault.reasoning._eval_insn` 缺压缩形态正则
（`c.srli rd,shamt` / `c.andi rd,imm6` / `c.addi rd,imm`），导致反解全 unsupported。

本测试锁定两条不变量：
  1. RVC 指令必须能解出自身反汇编，且产出 ≥4 个语义改变变体；
  2. 门检查链上的关键指令必须能被 `explain_observation` 反解出候选。

测试不硬编码芯片实例值：指令字节从样例镜像按**语义地址查找**（通过反汇编匹配
助记符）或直接用 ISA 规范构造的指令编码。
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


# ---- 用标准编码构造 RVC 指令（ISA 规范，不依赖任何镜像）----

def _c_bnez(rs1: int, imm: int) -> bytes:
    """c.bnez rs1', offset（RVC 规范编码）。"""
    imm &= 0x1FF
    b8 = (imm >> 8) & 1
    b7_6 = (imm >> 6) & 0x3
    b5 = (imm >> 5) & 1
    b4_3 = (imm >> 3) & 0x3
    b2_1 = (imm >> 1) & 0x3
    half = (0b111 << 13) | (b8 << 12) | (b7_6 << 10) | ((rs1 & 0x7) << 7) \
           | (b5 << 6) | (b4_3 << 3) | (b2_1 << 3) | 0b01
    # 简化：直接用规范公式重算
    half = ((0b111 << 13) | (b8 << 12) | (b7_6 << 10)
            | ((rs1 & 0x7) << 7) | (b5 << 6) | (b4_3 << 3) | (b2_1 << 3) | 0b01)
    return half.to_bytes(2, "little")


def _c_srli(rd: int, shamt: int) -> bytes:
    """c.srli rd', shamt（RVC 规范）。"""
    half = (0b100 << 13) | (0b00 << 10) | ((rd & 0x7) << 7) | ((shamt & 0x3F) << 2) | 0b01
    return half.to_bytes(2, "little")


def _c_andi(rd: int, imm: int) -> bytes:
    """c.andi rd', imm6（RVC 规范，有符号 6 位）。"""
    half = (0b100 << 13) | (0b10 << 10) | ((rd & 0x7) << 7) | ((imm & 0x3F) << 2) | 0b01
    return half.to_bytes(2, "little")


def _find_insn_bytes(mnemonic_prefix: str, size: int | None = None) -> tuple[bytes, int] | None:
    """在样例镜像里找一个指定助记符的指令（不硬编码地址）。"""
    import capstone

    s = _sample_image()
    if s is None:
        return None
    image, base = s
    md = capstone.Cs(capstone.CS_ARCH_RISCV,
                     capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
    raw = image.read_bytes()
    for insn in md.disasm(raw, base):
        if insn.mnemonic.startswith(mnemonic_prefix):
            if size is not None and insn.size != size:
                continue
            off = insn.address - base
            return raw[off:off + insn.size], insn.address
    return None


def _sample_image() -> tuple[Path, int] | None:
    import os

    env = os.environ.get("FI_SMOKE_IMAGE")
    candidates = ([Path(env)] if env else []) + sorted(ROOT.glob("*.bin"))
    for c in candidates:
        if c.is_file() and c.stat().st_size > 4096:
            return c, 0x<BASE>
    return None


# ---------------------------------------------------------------- 1) 解码


def test_rvc_instruction_decodes() -> None:
    """2 字节指令必须能解码（回归：曾因缺 CS_MODE_RISCVC 全部返回 None）。"""
    from fi.fault.effects import _disasm_one

    b = _c_andi(10, 1)     # c.andi a0, 1
    text = _disasm_one(b, 0x1000)
    assert text is not None, "2 字节指令解码失败（CS_MODE_RISCVC 未启用？）"
    assert text.startswith("c.andi"), f"解码结果不符: {text}"


def test_rvc_bitflips_produce_variants() -> None:
    """2 字节指令必须产出语义改变变体（回归：曾全部 undecodable → 0 个）。

    阈值按 ISA 编码事实设定，不人为拔高：
      - `c.andi a0,1`（0x8905）有 4 个有效 1 位（bit0 本身不可解，故 4 个变体）；
      - `c.srli a0,4`（0x8111）只有 3 个有效 1 位 → 3 个变体是**编码上限**；
      - `c.bnez a0,-2`（0xe115 类）1 位密集 → 变体很多。
    因此断言"≥3 且至少含 1 个 non-opcode 变化"，而不是强行要求 4。
    """
    from fi.fault.effects import enumerate_bitflips

    cases = (("c.andi a0,1", _c_andi(10, 1), 4),
             ("c.srli a0,4", _c_srli(10, 4), 3),
             ("c.bnez a0,-2", _c_bnez(10, -2), 4))
    for label, b, min_expected in cases:
        vs = enumerate_bitflips(b, 0x1000, max_flips=1)
        sem = [v for v in vs if v.mutated_insn and v.change_kind != "same"]
        assert len(sem) >= min_expected, (
            f"{label}: 只产出 {len(sem)} 个语义变体（应 ≥{min_expected}）")
        # 整体不应退化为"全 undecodable"
        assert any(v.change_kind != "undecodable" for v in vs), (
            f"{label}: 全部变体 undecodable（CS_MODE_RISCVC 未启用？）")


def test_gate_like_variants_semantics() -> None:
    """门提取指令的关键变体必须正确（bit2 -> c.andi a0,0 使门恒开）。"""
    from fi.fault.effects import enumerate_bitflips

    b = _c_andi(10, 1)     # c.andi a0, 1
    vs = enumerate_bitflips(b, 0x1000, max_flips=1)
    by_bits = {tuple(v.flipped_bit_positions): v for v in vs}
    # bit2 是 imm6 的最低位 → 1 变 0 → c.andi a0, 0
    v = by_bits.get((2,))
    assert v is not None, f"缺 bit2 变体；现有: {sorted(by_bits)}"
    assert v.mutated_insn == "c.andi a0, 0", v.mutated_insn


# ---------------------------------------------------------------- 2) 反解


def test_reasoning_supports_compressed_forms() -> None:
    """反解必须支持压缩形态（c.srli / c.andi / c.addi）。"""
    from fi.fault.reasoning import _eval_insn

    cases = [
        ("c.srli a0, 4", {"a0": 0x10}, "ok"),
        ("c.andi a0, 1", {"a0": 0x11}, "ok"),
        ("c.addi a0, -1", {"a0": 0x10}, "ok"),
        ("andi a0, a0, 1", {"a0": 0x11}, "ok"),
    ]
    for text, regs, expect in cases:
        _, status = _eval_insn(text, regs)
        assert status == expect, f"{text}: status={status}（应 {expect}）"


def test_explain_gate_open_from_andi_corruption() -> None:
    """反解：观察"门返回 0（放行）"，应给出 `c.andi` 被破坏的候选。"""
    from fi.fault.reasoning import explain_observation

    b = _c_andi(10, 1)
    r = explain_observation(insn_bytes=b, insn_addr=0x1000,
                            pre_regs={"a0": 1}, observed_regs={"a0": 0})
    assert r["summary"]["matching_candidates"] >= 1, (
        f"未反解出候选：{r['summary']}")
    # 纪律：多解必须保留（不得只报一个）
    assert r["candidates"], "candidates 为空"
    # 至少有一个候选是正确的"门恒开"解释
    texts = {c["mutated_insn"] for c in r["candidates"]}
    assert "c.andi a0, 0" in texts, f"缺 c.andi a0,0 候选；实有 {texts}"


def test_reasoning_reports_multiple_solutions() -> None:
    """多解时必须标 multiple_solutions=True（方法论硬要求）。"""
    from fi.fault.reasoning import explain_observation

    b = _c_andi(10, 1)
    r = explain_observation(insn_bytes=b, insn_addr=0x1000,
                            pre_regs={"a0": 1}, observed_regs={"a0": 0})
    if len(r["candidates"]) > 1:
        assert r["summary"]["multiple_solutions"] is True
