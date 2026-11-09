# -*- coding: utf-8 -*-
"""帧格式终审工具的自检（纯合成数据，不依赖任何芯片实例）。"""

import struct

import pytest

from fi.analysis.frame_audit import (
    ByteStream,
    audit_frame_claims,
    derive_frame_layout,
    derive_rom_frame_construction,
    extract_frame_candidates,
)
from fi.analysis.trace_bytes import reconstruct_uart_stream_from_trace


# ---------------------------------------------------------------- 帧边界
def test_frame_boundaries_exact_multiple() -> None:
    """8 字节帧区 = 2 个 4 字节帧 → 候选帧长含 4。"""
    s = ByteStream(data=b"\x01\x02\x03\x04\x05\x06\x07\x08", source="synth")
    r = extract_frame_candidates(s, min_len=2, max_len=8)
    assert r["payload_len"] == 8
    assert 4 in r["plausible_frame_lengths"]
    assert 8 in r["plausible_frame_lengths"]
    assert r["trailing_zeros"] == 0


def test_frame_boundaries_trailing_zeros() -> None:
    """帧后多发的零字节必须被识别（长度参数缺陷的指纹）。"""
    s = ByteStream(data=b"\xAA\xBB\xCC\xDD" + b"\x00" * 5, source="synth")
    r = extract_frame_candidates(s, min_len=2, max_len=8)
    assert r["trailing_zeros"] == 5
    assert r["len_without_trailing_zeros"] == 4
    assert 4 in r["plausible_frame_lengths_after_zero_strip"]


def test_frame_boundaries_preamble_stripped() -> None:
    """已知文本前缀应被剥离后再做边界分析。"""
    s = ByteStream(data=b"LOG\r\n" + b"\x11\x22\x33\x44", source="synth", preamble_len=5)
    assert s.framed == b"\x11\x22\x33\x44"
    r = extract_frame_candidates(s)
    assert r["payload_len"] == 4


# ---------------------------------------------------------------- 字段布局
def test_layout_enumerates_both_endiannesses() -> None:
    """布局枚举必须同时给出两种字节序，不得预设一种。"""
    s = ByteStream(data=b"\x46\x4C\x01\x05", source="synth")
    r = derive_frame_layout(s, frame_len=4, observed_code=0x<CODE_A>)
    w = r["windows"][0]
    assert w["u16_le_by_offset"] == ["0x4C46", "0x<CODE_A>"]
    assert w["u16_be_by_offset"] == ["0x464C", "0x0105"]
    assert w["u32_le"] == "0x<CODE_A>4C46"


def test_layout_flags_observed_code_at_correct_offset() -> None:
    """独立观测码应被定位到具体 (offset, endianness)。"""
    s = ByteStream(data=b"\x46\x4C\x01\x05", source="synth")
    r = derive_frame_layout(s, frame_len=4, observed_code=0x<CODE_A>)
    assert r["observed_code_hits"] == [
        {"start": 0, "offset": 2, "endianness": "little", "value": "0x<CODE_A>"}
    ]


def test_layout_big_endian_code_detected() -> None:
    """码按大端排布（0x05,0x01 顺序）时应报 big，不得误判成 little。

    注意：字节 01 05 作为 u16 小端读 = 0x<CODE_A>，因此该排列在两套解释下都"像"
    0x<CODE_A> —— 这正是本测试要钉住的行为：命中判定必须逐个 (offset,endian) 给出，
    由调用方结合其它证据裁决，不能替调用方选一个。
    """
    s = ByteStream(data=b"\x05\x01\x46\x4C", source="synth")
    r = derive_frame_layout(s, frame_len=4, observed_code=0x<CODE_A>)
    assert any(h["endianness"] == "big" and h["offset"] == 0
               for h in r["observed_code_hits"]), r["observed_code_hits"]


# ---------------------------------------------------------------- ROM 推导
def test_rom_derivation_shift_or_pattern() -> None:
    """经典组帧：slli + lui/addi + or → (code << 16) | magic。"""
    ops = [
        {"mnem": "slli", "args": ["a5", "a0", "0x10"]},
        {"mnem": "c.lui", "args": ["a4", "5"]},
        {"mnem": "addi", "args": ["a4", "a4", "-0x3ba"]},
        {"mnem": "c.or", "args": ["a5", "a4"]},
    ]
    r = derive_rom_frame_construction(ops, var_code="a0", var_target="a5")
    sym = r["symbolic_frame"]
    assert sym["known_mask"] == "0x00004C46"
    assert sym["unknown_vars"] == [{"name": "a0", "shift": 16}]
    assert sym["decomposable"] is True


def test_rom_derivation_pure_constant() -> None:
    """纯常量（如成功帧 magic）应可完整求值、无未知变量。"""
    ops = [
        {"mnem": "c.lui", "args": ["a5", "5"]},
        {"mnem": "addi", "args": ["a5", "a5", "-0x4b1"]},
    ]
    r = derive_rom_frame_construction(ops, var_target="a5")
    sym = r["symbolic_frame"]
    assert sym["unknown_vars"] == []
    assert int(sym["known_mask"], 16) == 0x4B4F


def test_rom_derivation_three_operand_or() -> None:
    """三操作数 or 形式与两操作数 c.or 形式必须等价处理。"""
    ops = [
        {"mnem": "slli", "args": ["a5", "a0", "0x10"]},
        {"mnem": "lui", "args": ["a4", "5"]},
        {"mnem": "addi", "args": ["a4", "a4", "-0x3ba"]},
        {"mnem": "or", "args": ["a5", "a5", "a4"]},
    ]
    r = derive_rom_frame_construction(ops, var_target="a5")
    assert r["symbolic_frame"]["known_mask"] == "0x00004C46"
    assert r["symbolic_frame"]["unknown_vars"] == [{"name": "a0", "shift": 16}]


def test_rom_derivation_variable_plus_constant_not_decomposable() -> None:
    """变量+常量（不可分离位域）必须显式标注，而不是硬凑出常量。"""
    ops = [
        {"mnem": "addi", "args": ["a0", "a0", "0x10"]},
    ]
    r = derive_rom_frame_construction(ops, var_target="a0")
    sym = r["symbolic_frame"]
    assert sym["decomposable"] is False
    assert sym["known_mask"] == "0x00000000"


# ---------------------------------------------------------------- claim 判定
def test_claim_audit_requires_basis_and_verifier_for_fact() -> None:
    claims = [
        {"id": "C1", "claim": "x", "evidence_level": "fact", "basis": "", "verified_by": []},
    ]
    r = audit_frame_claims(claims)
    assert r["consistent"] is False
    assert any("basis" in p for p in r["problems"])


def test_claim_audit_overall_is_minimum_level() -> None:
    claims = [
        {"id": "C1", "claim": "x", "evidence_level": "fact",
         "basis": "b", "verified_by": ["v"]},
        {"id": "C2", "claim": "y", "evidence_level": "hypothesis", "basis": "b"},
    ]
    r = audit_frame_claims(claims)
    assert r["overall_evidence_level"] == "hypothesis"
    assert r["upgradable_to_fact"] == ["C1"]
    assert r["must_stay_hypothesis"] == ["C2"]


def test_claim_audit_rejects_unknown_level_below() -> None:
    claims = [
        {"id": "C1", "claim": "x", "evidence_level": "fact",
         "basis": "b", "verified_by": ["v"]},
        {"id": "C2", "claim": "y", "evidence_level": "unknown"},
    ]
    r = audit_frame_claims(claims)
    assert r["overall_evidence_level"] == "unknown"


# ---------------------------------------------------------------- trace 重建
def _write_trace(tmp_path, writes):
    import json
    p = tmp_path / "trace.jsonl"
    lines = [json.dumps({"type": "run_meta", "run_id": "r-test"})]
    seq = 0
    for addr, size, value in writes:
        lines.append(json.dumps({
            "type": "trace", "seq": seq, "pc": 0x1000, "disasm": "sb a5, 0(a7)",
            "mem_access": {"kind": "write", "addr": addr, "size": size,
                           "value": f"{value:02x}" if size == 1 else f"{value:08x}",
                           "stub": False, "region": "uart0"},
        }))
        seq += 1
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_trace_reconstruction_single_bytes(tmp_path) -> None:
    p = _write_trace(tmp_path, [(0x4000A188, 1, 0x46), (0x4000A188, 1, 0x4C)])
    rec = reconstruct_uart_stream_from_trace(p, 0x4000A188, 0x4000A188)
    assert rec.data == b"\x46\x4C"
    assert len(rec.writes) == 2


def test_trace_reconstruction_word_write_expands_le(tmp_path) -> None:
    """sw 写 4 字节时应按小端展开。"""
    p = _write_trace(tmp_path, [(0x4000A188, 4, 0x<CODE_A>4C46)])
    rec = reconstruct_uart_stream_from_trace(p, 0x4000A188, 0x4000A188)
    assert rec.data == b"\x46\x4C\x01\x05"


def test_trace_reconstruction_filters_by_address(tmp_path) -> None:
    """非数据寄存器地址不得计入。"""
    p = _write_trace(tmp_path, [(0x4000A184, 1, 0x99), (0x4000A188, 1, 0x46)])
    rec = reconstruct_uart_stream_from_trace(p, 0x4000A188, 0x4000A188)
    assert rec.data == b"\x46"


def test_trace_reconstruction_filters_by_region(tmp_path) -> None:
    """region 不匹配不得计入。"""
    p = _write_trace(tmp_path, [(0x4000A188, 1, 0x46)])
    rec = reconstruct_uart_stream_from_trace(p, 0x4000A188, 0x4000A188,
                                             region_name="other")
    assert rec.data == b""
