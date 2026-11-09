# -*- coding: utf-8 -*-
"""错误码 ↔ ROM 代码路径 归因搜索（静态，capstone RV32IMC）。

任务（baseline v2 §M2 / lead 2026-11-09 指令）：
把 CSV 观测错误码（0x<CODE_A>/0x<CODE_B>/0x<CODE_C>/0x<CODE_D>/0x<CODE_F>/0x0001 与长尾码、
非码 token 'OK'/'NONE'）拿到 <ROM_IMAGE> 反汇编里搜立即数/比较值/返回路径，
产出可被 chip-profile 侧同一张表核对的结构化关联数据。

方法与边界（诚实声明）：
- 解码：capstone 5.0.7，RV32IMC（CS_MODE_RISCV32|CS_MODE_RISCVC），基址按用户给定
  0x<BASE>（唯一给定信息）。**线性扫描**：ROM 数据段会产出乱码指令，
  且未做入口/控制流可达性分析（复位入口 unknown）——命中只说明"该值以该形式出现"，
  不证明执行路径。
- 三类搜索，证据分级：
  1) ``imm_operand``：解码指令的操作数立即数等于目标值（含 li 伪指令展开后的 addi）；
  2) ``lui_addi_pair``：lui+c.addi/addi 组合拼出 >12 位立即数（如 0x<CODE_F>）；
  3) ``word_const``：原始 32 位小端字等于目标值（code/data 属性未知）；
  4) ``ascii``：原始字节中的 ASCII 串（'OK'/'NONE' 等非码 token 用此通道）。
- 置信级（本模块只产出"候选证据"，不做终判）：
  ``found_imm_with_context`` > ``found_word_const`` > ``not_found_static``
  （not_found ≠ 不存在于路径：码可能由运算生成（如 mcause 拼位）或由上位机协议定义）。
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

import capstone

# 审计纪律：ROM 基址、目标错误码/token 均为样例值，禁止作为模块默认值；
# 全部经 build_attribution() 显式参数传入（来源：调用方 / Profile 错误码表 /
# 样例运行配置）。本文档字符串中的 0x<BASE>、0x<CODE_A> 等仅为历史样例引用。

_NUM_RE = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+)$")


def load_rom(path: str) -> bytes:
    return Path(path).read_bytes()


def _disassembler() -> "capstone.Cs":
    md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
    md.detail = False
    return md


def linear_disasm(rom: bytes, base: int):
    """线性扫描全 ROM；返回 [(offset, addr, size, bytes_hex, text)]。

    ``base`` 必填（样例值禁止作默认）。
    """
    md = _disassembler()
    out = []
    off = 0
    n = len(rom)
    while off < n:
        chunk = rom[off:off + 4]
        try:
            insn = next(md.disasm(chunk, base + off))
            text = f"{insn.mnemonic} {insn.op_str}".strip()
            out.append((off, insn.address, insn.size, rom[off:off + insn.size].hex(), text))
            off += insn.size
        except StopIteration:
            # 无法解码 → 尝试 2 字节压缩位对齐跳步
            out.append((off, base + off, 2, chunk[:2].hex(), "<undecoded>"))
            off += 2
    return out


def _operand_nums(text: str) -> list[int]:
    vals = []
    for tok in text.split(",")[1:]:
        t = tok.strip()
        if _NUM_RE.match(t):
            try:
                vals.append(int(t, 0))
            except ValueError:
                pass
        else:
            m = re.search(r"(0x[0-9a-fA-F]+|\d+)", t)
            if m:
                try:
                    vals.append(int(m.group(1), 0))
                except ValueError:
                    pass
    return vals


def _sext12(v: int) -> int:
    return v - 4096 if v >= 2048 else v


def _context(disasm: list, idx: int, span: int = 4) -> list[dict]:
    lo = max(0, idx - span)
    hi = min(len(disasm), idx + span + 1)
    ctx = []
    for j in range(lo, hi):
        off, addr, _sz, hx, text = disasm[j]
        ctx.append({
            "addr": f"0x{addr:08x}",
            "offset": off,
            "bytes": hx,
            "text": text,
            "marker": " <== hit" if j == idx else "",
        })
    return ctx


def search_immediates(disasm: list, targets: dict[int, str]) -> dict[int, list]:
    """解码指令操作数立即数匹配（含负显示数补 32 位语义比较）。"""
    hits: dict[int, list] = {v: [] for v in targets}
    for idx, (off, addr, _sz, hx, text) in enumerate(disasm):
        if text == "<undecoded>":
            continue
        mnem = text.split()[0]
        for val in _operand_nums(text):
            for key in (val & 0xFFFFFFFF, val):
                if key in hits:
                    hits[key].append({
                        "offset": off,
                        "addr": f"0x{addr:08x}",
                        "insn": text,
                        "mnemonic": mnem,
                        "context": _context(disasm, idx),
                    })
                    break
    return hits


def search_lui_addi_pairs(disasm: list, targets: dict[int, str]) -> dict[int, list]:
    """lui rd, immU（或 c.lui）与后续同 rd 的 addi/c.addi 组合立即数匹配。

    窗口：pair 间距 ≤ 6 条指令；addi 立即数做 12 位符号扩展。
    值 = (immU << 12) + sext(immI)，按 32 位回绕比较。
    """
    hits: dict[int, list] = {v: [] for v in targets}
    lui_re = re.compile(r"^(c\.lui|lui)\s+(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
    addi_re = re.compile(r"^(c\.addi|c\.addi16sp|addi)\s+(\w+),\s*(\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
    pending: list[tuple[int, int, str, str]] = []  # (idx, immU, rd, text)
    for idx, (off, addr, _sz, hx, text) in enumerate(disasm):
        if text == "<undecoded>":
            continue
        m = lui_re.match(text)
        if m:
            try:
                immu = int(m.group(3), 0)
            except ValueError:
                immu = 0
            pending.append((idx, immu, m.group(2), text))
            # 窗口收缩
            pending = [p for p in pending if idx - p[0] <= 6]
            continue
        m = addi_re.match(text)
        if m and pending:
            rd = m.group(2)
            rs1 = m.group(3)
            try:
                immi = int(m.group(4), 0)
            except ValueError:
                immi = 0
            if rd == rs1:
                val = (immi & 0xFFF)
                val = _sext12(val)
                for (pidx, immu, prd, ptext) in reversed(pending):
                    if prd != rd:
                        continue
                    full = ((immu << 12) + val) & 0xFFFFFFFF
                    if full in hits:
                        hits[full].append({
                            "offset": off,
                            "addr": f"0x{addr:08x}",
                            "pair": [ptext, text],
                            "pair_insn_offset": disasm[pidx][0],
                            "value": f"0x{full:08x}",
                            "context": _context(disasm, idx),
                        })
                    break  # 只取最近同 rd 的 lui
        # 控制pending长度
        if len(pending) > 32:
            pending = pending[-32:]
    return hits


def search_word_consts(rom: bytes, targets: dict[int, str], base: int) -> dict[int, list]:
    """原始 32 位小端字匹配（code/data 属性未知）。``base`` 必填。"""
    hits: dict[int, list] = {v: [] for v in targets}
    for off in range(0, len(rom) - 3, 1):  # 逐字节滑动，捕获非对齐常量
        (w,) = struct.unpack_from("<I", rom, off)
        if w in hits:
            hits[w].append({"offset": off, "addr": f"0x{base + off:08x}",
                            "word": f"0x{w:08x}"})
    return hits


def search_ascii(rom: bytes, tokens: list[str], base: int, min_run: int = 4) -> dict:
    """ASCII token 命中 + 全部可打印串（≥min_run）样例。``base`` 必填。"""
    token_hits: dict[str, list] = {t: [] for t in tokens}
    for t in tokens:
        pat = t.encode("ascii")
        start = 0
        while True:
            i = rom.find(pat, start)
            if i < 0:
                break
            ctx = rom[max(0, i - 8): i + len(pat) + 8]
            token_hits[t].append({
                "offset": i,
                "addr": f"0x{base + i:08x}",
                "context_hex": ctx.hex(),
                "context_repr": "".join(chr(b) if 32 <= b < 127 else "." for b in ctx),
            })
            start = i + 1
    # 可打印串样例（供协议线索；截断防膨胀）
    strings: list[dict] = []
    run: list[int] = []
    run_start = 0
    for i, b in enumerate(rom + b"\x00"):
        if 32 <= b < 127:
            if not run:
                run_start = i
            run.append(b)
        else:
            if len(run) >= min_run:
                s = bytes(run).decode("ascii")
                if len(strings) < 400:
                    strings.append({"offset": run_start,
                                    "addr": f"0x{base + run_start:08x}",
                                    "text": s})
            run = []
    return {"token_hits": token_hits, "printable_strings": strings,
            "n_printable_runs": None}  # n 由调用方 len(strings) 截断说明


def _confidence(hits_imm: int, hits_pair: int, hits_word: int) -> str:
    if hits_imm or hits_pair:
        return "candidate_imm_with_context"
    if hits_word:
        return "candidate_word_const_only"
    return "not_found_static"


def build_attribution(
    rom_path: str,
    csv_code_counts: dict[str, dict],
    *,
    rom_base: int,
    target_codes: list[str],
    target_tokens: list[str],
) -> dict:
    """主入口：全目标搜索 + 与 CSV 端统计拼接，输出 attribution 结构。

    审计纪律：``rom_base`` / ``target_codes`` / ``target_tokens`` 必填显式参数，
    不设样例默认值（来源：调用方 CLI / Profile 错误码表 / 样例运行配置，
    或由 CSV 观测频次推导并标注 derived）。

    ``csv_code_counts``: {code_or_token: {"states": {...}, "total": N}} —— CSV 端角色。
    """
    rom = load_rom(rom_path)
    disasm = linear_disasm(rom, rom_base)
    targets = {int(c, 16): c for c in target_codes}
    hits_imm = search_immediates(disasm, targets)
    hits_pair = search_lui_addi_pairs(disasm, targets)
    hits_word = search_word_consts(rom, targets, rom_base)
    ascii_res = search_ascii(rom, target_tokens, rom_base)

    targets_out: dict[str, dict] = {}
    for code in target_codes:
        v = int(code, 16)
        imm, pair, word = hits_imm.get(v, []), hits_pair.get(v, []), hits_word.get(v, [])
        targets_out[code] = {
            "csv_side": csv_code_counts.get(code, {"total": 0, "states": {}}),
            "imm_operand_hits": imm[:40],
            "lui_addi_pair_hits": pair[:40],
            "word_const_hits": word[:60],
            "hit_counts": {
                "imm_operand": len(imm),
                "lui_addi_pair": len(pair),
                "word_const": len(word),
            },
            "confidence": _confidence(len(imm), len(pair), len(word)),
            "unknowns": [
                "线性扫描含数据段乱码；未做入口/可达性分析（复位入口 unknown）",
                "码可能由运算生成（如 mcause 拼位）或定义于上位机协议层，not_found_static 不等于路径不存在",
            ],
        }
    for tok in target_tokens:
        hits = ascii_res["token_hits"].get(tok, [])
        targets_out[f"token:{tok}"] = {
            "csv_side": csv_code_counts.get(tok, {"total": 0, "states": {}}),
            "ascii_hits": hits[:20],
            "hit_counts": {"ascii": len(hits)},
            "confidence": ("candidate_ascii_string" if hits else "not_found_static"),
            "unknowns": [
                "ASCII 命中不能区分代码字符串/数据/巧合字节",
                "token 与设备协议文本的关系需协议逆向（unknown）",
            ],
        }

    return {
        "rom_file": rom_path,
        "rom_size": len(rom),
        "rom_sha256": __import__("hashlib").sha256(rom).hexdigest(),
        "base": f"0x{rom_base:08x}",
        "base_source": "caller-provided (audit: no sample defaults)",
        "decoder": f"capstone {capstone.__version__} RV32IMC linear sweep",
        "method_boundaries": [
            "线性扫描：数据段产出乱码指令，命中地址不等于可达执行路径",
            "未做复位入口/控制流分析（入口 unknown）；三方交叉验证（ROM/仿真/CSV）后方可升 confidence",
        ],
        "targets": targets_out,
        "printable_strings_sample": ascii_res["printable_strings"],
    }
