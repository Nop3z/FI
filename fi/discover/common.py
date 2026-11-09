# -*- coding: utf-8 -*-
"""fi.discover.common：镜像解码与地址常量提取的公共设施（芯片无关）。

全部函数只依赖 capstone 与传入的镜像/基址参数，不含任何具体芯片常量。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import capstone

_NUM = r"-?(?:0x[0-9a-fA-F]+|\d+)"
_RE_LUI = re.compile(rf"^(?:c\.lui|lui)\s+(\w+),\s*({_NUM})")
_RE_ADDI = re.compile(rf"^(?:c\.addi|c\.addi16sp|addi)\s+(\w+),\s*(\w+),\s*({_NUM})")
_RE_LW_SW = re.compile(
    rf"^(?:c\.(?:lw|lwsp|sw|swsp)|lw|sw|lbu|lhu|lb|lh|sb|sh)\s+"
    rf"(\w+),\s*({_NUM})?\(?(\w+)?\)?"
)
_RE_C_LWSP = re.compile(rf"^(?:c\.lwsp|c\.swsp)\s+(\w+),\s*({_NUM})\((\w+)\)")
_RE_JAL = re.compile(r"^(?:c\.jal|jal|jalr|c\.jalr)\s+(.*)$")
_RE_BRANCH = re.compile(r"^(c\.beqz|c\.bnez|beq|bne|blt|bge|bltu|bgeu|bgez|bltz|bgtz|blez)\s+(.*)$")


def load_image(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_disassembler(xlen: int = 32, compressed: bool = True) -> "capstone.Cs":
    mode = capstone.CS_MODE_RISCV32 if xlen == 32 else capstone.CS_MODE_RISCV64
    if compressed:
        mode |= capstone.CS_MODE_RISCVC
    md = capstone.Cs(capstone.CS_ARCH_RISCV, mode)
    md.detail = False
    return md


@dataclass
class Insn:
    offset: int
    addr: int
    size: int
    raw_hex: str
    text: str

    @property
    def mnemonic(self) -> str:
        if self.text == "<undecoded>":
            return "<undecoded>"
        return self.text.split()[0]

    @property
    def operands(self) -> str:
        parts = self.text.split(None, 1)
        return parts[1] if len(parts) > 1 else ""


def linear_disasm(image: bytes, base: int, xlen: int = 32, compressed: bool = True) -> list[Insn]:
    """线性扫描整个镜像（含数据段；乱码会产出 <undecoded> 或伪指令——这是已知边界）。"""
    md = make_disassembler(xlen, compressed)
    out: list[Insn] = []
    off = 0
    n = len(image)
    while off < n:
        chunk = image[off:off + 4]
        try:
            insn = next(md.disasm(chunk, base + off))
        except StopIteration:
            out.append(Insn(off, base + off, 2, chunk[:2].hex(), "<undecoded>"))
            off += 2
            continue
        raw = image[off:off + insn.size]
        text = f"{insn.mnemonic} {insn.op_str}".strip()
        out.append(Insn(off, insn.address, insn.size, raw.hex(), text))
        off += insn.size
    return out


def sext(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def parse_imm(token: str) -> int | None:
    t = token.strip()
    try:
        return int(t, 0)
    except ValueError:
        return None


@dataclass
class ConstHit:
    """一个地址常量的出现位置与构造形态。"""
    value: int
    offset: int
    addr: int
    form: str          # lui_addi | addi | load_store_abs | jal | word
    insns: list[str] = field(default_factory=list)
    access: str = ""   # read | write | exec | unknown（仅 load/store/jal 有意义）


def scan_address_constants(
    disasm: list[Insn],
    image: bytes,
    base: int,
    *,
    min_addr: int = 0x20000000,
    max_addr: int = 1 << 32,
    lui_window: int = 6,
    word_channel: bool = True,
    word_min_addr: int = 0x20000000,
) -> list[ConstHit]:
    """提取疑似地址常量（芯片无关，纯结构启发式）。

    默认只保留高地址空间（>=0x20000000，通用 RISC-V 惯例的 RAM/外设区间），
    因为低地址命中绝大多数来自数据段伪字与相对偏移噪声。

    通道：
     1) lui rd, immU + addi rd, rd, immI  → 32 位常量，后随 lw/sw 时标注访问类型
     2) 绝对寻址 lw/sw rd, imm(rs1) 且 rs1 保持为 lui 载入的基址
     3) jal/jalr 目标落在高地址区间（直接函数地址）
     4) 原始 32 位小端字落在高地址区间（数据段指针表）
    """
    hits: list[ConstHit] = []

    # --- 通道 1/2：lui 基址寄存器跟踪 ---
    reg_base: dict[str, tuple[int, int]] = {}   # reg -> (value, idx)
    for idx, insn in enumerate(disasm):
        if insn.text == "<undecoded>":
            continue
        m = _RE_LUI.match(insn.text)
        if m:
            immu = parse_imm(m.group(2))
            if immu is not None:
                reg_base[m.group(1)] = ((immu << 12) & 0xFFFFFFFF, idx)
            continue

        m = _RE_ADDI.match(insn.text)
        if m:
            rd, rs1, imm_s = m.group(1), m.group(2), m.group(3)
            imm = parse_imm(imm_s)
            if imm is None:
                continue
            if rs1 in reg_base and idx - reg_base[rs1][1] <= lui_window:
                val = (reg_base[rs1][0] + sext(imm, 12)) & 0xFFFFFFFF
                reg_base[rd] = (val, idx)
                if min_addr <= val < max_addr:
                    hits.append(ConstHit(val, insn.offset, insn.addr, "lui_addi",
                                         [disasm[reg_base[rs1][1]].text, insn.text]))
            continue

        # load/store：rd/rs1 与 imm
        m = _RE_C_LWSP.match(insn.text) or _RE_LW_SW.match(insn.text)
        if m:
            groups = m.groups()
            if len(groups) == 3 and groups[2]:
                imm_s, base_reg = groups[1], groups[2]
                imm = parse_imm(imm_s) if imm_s else 0
                if base_reg in reg_base and imm is not None:
                    # 基址寄存器同样受窗口约束：防止数据段乱码区复用寄存器名造成假命中
                    if idx - reg_base[base_reg][1] > lui_window:
                        continue
                    val = (reg_base[base_reg][0] + sext(imm, 12)) & 0xFFFFFFFF
                    if min_addr <= val < max_addr:
                        mnem = insn.mnemonic[2:] if insn.mnemonic.startswith("c.") else insn.mnemonic
                        access = "write" if mnem.startswith(("sw", "sb", "sh")) else "read"
                        hits.append(ConstHit(val, insn.offset, insn.addr, "load_store_abs",
                                             [disasm[reg_base[base_reg][1]].text, insn.text], access))
            continue

        # --- 通道 3：直接跳转目标 ---
        m = _RE_JAL.match(insn.text)
        if m:
            for tok in re.findall(_NUM, m.group(1)):
                tgt = parse_imm(tok)
                if tgt is not None and min_addr <= tgt < max_addr and tgt % 2 == 0:
                    hits.append(ConstHit(tgt, insn.offset, insn.addr, "jal", [insn.text], "exec"))

    # --- 通道 4：数据段地址字（仅高地址、去重） ---
    if word_channel:
        seen: set[int] = set()
        for off in range(0, max(0, len(image) - 3), 4):
            word = int.from_bytes(image[off:off + 4], "little")
            if word_min_addr <= word < max_addr and word % 4 == 0 and word not in seen:
                seen.add(word)
                hits.append(ConstHit(word, off, base + off, "word", [image[off:off + 4].hex()]))
    return hits


def cluster_values(hits: list[ConstHit], *, page: int = 0x1000) -> list[dict]:
    """按页聚类并汇总：命中次数、访问类型、构造形态、证据地址样例。

    显著性策略（重要）：只有**指令侧证据**（lui_addi / load_store_abs / jal）
    才构成区域候选。数据段字（word 通道）单独出现时是噪声，仅当同一地址值
    也存在指令侧命中时，才作为佐证登记（`word_corroborated`）。
    """
    instr_hits = [h for h in hits if h.form != "word"]
    word_hits = [h for h in hits if h.form == "word"]
    word_values = {h.value for h in word_hits}
    instr_values = {h.value for h in instr_hits}

    buckets: dict[int, list[ConstHit]] = {}
    for h in instr_hits:
        buckets.setdefault(h.value & ~(page - 1), []).append(h)

    out = []
    for page_base, items in sorted(buckets.items()):
        forms = sorted({i.form for i in items})
        accesses = sorted({i.access for i in items if i.access})
        values = {i.value for i in items}
        out.append({
            "page_base": page_base,
            "page_base_hex": f"0x{page_base:08x}",
            "hit_count": len(items),
            "forms": forms,
            "accesses": accesses,
            "distinct_values": len(values),
            "word_corroborated": len(values & word_values),
            "sample_evidence": [
                {"value": f"0x{i.value:08x}", "at": f"0x{i.addr:08x}", "form": i.form,
                 "access": i.access or "unknown", "insns": i.insns}
                for i in items[:5]
            ],
        })
    # 按证据强度排序：命中数 × 访问类型多样性
    out.sort(key=lambda c: (-(c["hit_count"] * (1 + len(c["accesses"]))), c["page_base"]))
    return out
