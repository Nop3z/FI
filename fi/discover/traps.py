# -*- coding: utf-8 -*-
"""fi.discover.traps：trap 机制识别（芯片无关）。

识别目标（全部 pattern 化，不含芯片常量）：
  1) mtvec 安装点：csrw/csrrw/csrs 到 mtvec(0x305=773)，及其前的地址常量构造
  2) mcause 读取点：csrr <reg>, mcause(0x342=834)
  3) mret 指令位置
  4) 疑似 handler 区间：mret 之前的寄存器保存帧（连续 sw/sp 相对写）+ 诊断字符串
  5) 未定义指令/非法访问触发点：ei/ebreak/ecall

产出 confidence 恒为 hypothesis（自动发现证据闸门）。
"""
from __future__ import annotations

import re

from .common import (
    ConstHit,
    Insn,
    linear_disasm,
    load_image,
    parse_imm,
    scan_address_constants,
    sha256_hex,
    sext,
)

# RISC-V 标准 CSR 号（ISA 规范常量，非芯片事实）
CSR_MTVEC = 0x305
CSR_MEPC = 0x341
CSR_MCAUSE = 0x342
CSR_MTVAL = 0x343
CSR_MSTATUS = 0x300

CSR_NAMES = {
    CSR_MTVEC: "mtvec", CSR_MEPC: "mepc", CSR_MCAUSE: "mcause",
    CSR_MTVAL: "mtval", CSR_MSTATUS: "mstatus",
}

_RE_CSR_W = re.compile(r"^(csrw|csrrw|csrrs|csrrc|c\.csrw)\s+(.*)$")
_RE_CSR_R = re.compile(r"^(csrr|csrrs|csrrc|c\.csrr)\s+(.*)$")


def _csr_token(tok: str) -> int | None:
    tok = tok.strip()
    if tok in CSR_NAMES.values():
        for num, name in CSR_NAMES.items():
            if name == tok:
                return num
    return parse_imm(tok)


def _find_preceding_address(disasm: list[Insn], idx: int, window: int = 12) -> int | None:
    """在 csrw 之前 window 条内找地址构造（mtvec 基址候选）。

    支持两种通用 RISC-V 地址构造形态：
      - auipc rd, immU + addi rd, rd, immI [+ ori/andi 低位标志]   （PC 相对，最常见）
      - lui rd, immU + addi rd, rd, immI                          （绝对常量）
    返回最后一个构造出的 32 位值（低位标志位做掩码剥离由调用方判断）。
    """
    reg_val: dict[str, int] = {}
    best: int | None = None
    for j in range(max(0, idx - window), idx):
        insn = disasm[j]
        text = insn.text
        m = re.match(r"^(?:c\.lui|lui)\s+(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))", text)
        if m:
            v = parse_imm(m.group(2))
            if v is not None:
                reg_val[m.group(1)] = (v << 12) & 0xFFFFFFFF
                best = reg_val[m.group(1)]
            continue
        m = re.match(r"^auipc\s+(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))", text)
        if m:
            v = parse_imm(m.group(2))
            if v is not None:
                reg_val[m.group(1)] = (insn.addr + ((v << 12) & 0xFFFFFFFF)) & 0xFFFFFFFF
                best = reg_val[m.group(1)]
            continue
        m = re.match(r"^(?:c\.addi|addi)\s+(\w+),\s*(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))", text)
        if m and m.group(2) in reg_val:
            imm = parse_imm(m.group(3))
            if imm is not None:
                v = (reg_val[m.group(2)] + sext(imm, 12)) & 0xFFFFFFFF
                reg_val[m.group(1)] = v
                best = v
            continue
        m = re.match(r"^(ori|andi|xori)\s+(\w+),\s*(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))", text)
        if m and m.group(3) in reg_val:
            imm = parse_imm(m.group(4))
            if imm is not None:
                op, src = m.group(1), reg_val[m.group(3)]
                imm &= 0xFFF
                if op == "ori":
                    v = src | imm
                elif op == "andi":
                    v = src & imm
                else:
                    v = src ^ imm
                reg_val[m.group(2)] = v & 0xFFFFFFFF
                best = reg_val[m.group(2)]
    return best


def _save_frame_size(disasm: list[Insn], idx: int, window: int = 120) -> dict:
    """在 mret/handler 附近统计 sp 相对保存/恢复指令数量（帧布局弱证据）。"""
    saves, restores = 0, 0
    start = max(0, idx - window)
    for j in range(start, min(len(disasm), idx + 1)):
        t = disasm[j].text
        if re.match(r"^(?:c\.sw|c\.swsp|sw|sh|sb)\s+(\w+),\s*(-?0x[0-9a-fA-F]+|-?\d+)\((\w+)\)", t.split(" ", 1)[0] + " " + t.split(" ", 1)[1] if " " in t else t):
            if "sp)" in t.replace(" ", ""):
                saves += 1
        elif re.match(r"^(?:c\.lw|c\.lwsp|lw|lh|lb)\s+(\w+),\s*[^,]*\(sp\)", t):
            restores += 1
    return {"stores_to_sp": saves, "loads_from_sp": restores}


def discover_traps(
    image_path: str,
    base: int,
    *,
    xlen: int = 32,
    compressed: bool = True,
    max_findings_per_kind: int = 40,
) -> dict:
    image = load_image(image_path)
    disasm = linear_disasm(image, base, xlen=xlen, compressed=compressed)

    mtvec_writes: list[dict] = []
    mcause_reads: list[dict] = []
    mepc_accesses: list[dict] = []
    mrets: list[dict] = []
    ecalls: list[dict] = []

    for idx, insn in enumerate(disasm):
        if insn.text == "<undecoded>":
            continue
        text = insn.text
        mnem = insn.mnemonic

        if mnem in ("csrw", "csrrw", "csrrs", "csrrc", "c.csrw"):
            m = _RE_CSR_W.match(text)
            if m:
                toks = [t.strip() for t in m.group(2).split(",")]
                csr = _csr_token(toks[0]) if toks else None
                if csr == CSR_MTVEC:
                    mtvec_writes.append({
                        "at": f"0x{insn.addr:08x}", "offset": insn.offset, "insn": text,
                        "base_candidate": _find_preceding_address(disasm, idx),
                        "context": [disasm[j].text for j in range(max(0, idx - 4), min(len(disasm), idx + 3))],
                    })
                elif csr == CSR_MEPC:
                    mepc_accesses.append({"at": f"0x{insn.addr:08x}", "insn": text, "op": "write"})

        if mnem in ("csrr", "csrrs", "csrrc", "c.csrr"):
            m = _RE_CSR_R.match(text)
            if m:
                parts = [t.strip() for t in m.group(2).split(",")]
                csr = None
                for p in parts[1:]:
                    csr = _csr_token(p)
                    if csr is not None:
                        break
                if csr == CSR_MCAUSE:
                    mcause_reads.append({
                        "at": f"0x{insn.addr:08x}", "offset": insn.offset, "insn": text,
                        "dest": parts[0] if parts else "unknown",
                    })
                elif csr == CSR_MEPC:
                    mepc_accesses.append({"at": f"0x{insn.addr:08x}", "insn": text, "op": "read"})

        if mnem == "mret":
            mrets.append({
                "at": f"0x{insn.addr:08x}", "offset": insn.offset, "insn": text,
                "save_frame_evidence": _save_frame_size(disasm, idx),
                "tail_disasm": [disasm[j].text for j in range(max(0, idx - 6), idx + 1)],
            })
        if mnem in ("ecall", "ebreak"):
            ecalls.append({"at": f"0x{insn.addr:08x}", "insn": text, "kind": mnem})

    # mtvec 基址候选 → 拆分低位模式标志后校验是否落在镜像内
    for w in mtvec_writes:
        cand = w.get("base_candidate")
        if cand is not None:
            w["base_candidate_raw_hex"] = f"0x{cand:08x}"
            # mtvec 低位为 MODE 字段（标准 2 位，实现可能自定义）：剥离后得到入口基址
            base_stripped = cand & ~0x3
            w["base_candidate"] = base_stripped
            w["base_candidate_hex"] = f"0x{cand:08x}"
            w["mode_bits_observed"] = cand & 0x3
            off = base_stripped - base
            w["base_in_image"] = 0 <= off < len(image)
            w["base_image_offset"] = off if 0 <= off < len(image) else None
            if 0 <= off < len(image):
                idx0 = next((i for i, d in enumerate(disasm) if d.offset >= off), None)
                if idx0 is not None:
                    w["base_entry_preview"] = [d.text for d in disasm[idx0:idx0 + 8]]

    return {
        "schema": "fi.discover.trap-report-v0",
        "tool": {"name": "fi.discover.traps", "version": "0.1.0"},
        "image": {
            "path": str(image_path), "sha256": sha256_hex(image),
            "size_bytes": len(image), "base_address": base,
            "base_address_hex": f"0x{base:08x}",
        },
        "method": {
            "patterns": [
                "csrw/csrrw/csrrs/csrrc → mtvec(0x305)",
                "csrr* mcause(0x342) / mepc(0x341)",
                "mret 位置 + 其前 sp 相对保存/恢复统计",
                "ecall/ebreak 触发点",
            ],
            "boundaries": [
                "线性扫描含数据段，可能产生伪指令命中",
                "mtvec 基址由 csrw 前窗口内常量构造启发式推断，可能取到邻近的其他常量",
                "未做可达性分析（复位入口 unknown）",
            ],
        },
        "findings": {
            "mtvec_writes": mtvec_writes[:max_findings_per_kind],
            "mcause_reads": mcause_reads[:max_findings_per_kind],
            "mepc_accesses": mepc_accesses[:max_findings_per_kind],
            "mret_sites": mrets[:max_findings_per_kind],
            "ecall_sites": ecalls[:max_findings_per_kind],
        },
        "summary": {
            "mtvec_write_count": len(mtvec_writes),
            "mcause_read_count": len(mcause_reads),
            "mret_count": len(mrets),
            "ecall_count": len(ecalls),
            "trap_mechanism_present": bool(mtvec_writes or (mcause_reads and mrets)),
        },
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
