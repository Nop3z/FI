# -*- coding: utf-8 -*-
"""错误码位翻转假设检验：把"未归因码是否由已知码被打坏产生"做成可复用分析。

## 为什么需要这个模块（而不是一次性脚本）

"某码能不能由另一码翻转得到"这个问题会在**每一批新数据**上重复出现。
一次性脚本会重复三个错误：
1. 只做值级可达性（漏掉指令编码合法性约束）；
2. 把"可达"当成证据（实际情况相反，见 ``discriminating_power``）；
3. 只报一个解（违反多解全列纪律）。

## 核心方法（三层判别）

1. **编码边界**（最强，可否证）：错误码经 ``addi rd,zero,imm`` 装载，imm 只有
   12 bit。位翻转不能使 ``addi`` 产生超出其立即数编码能力的值 → 超范围即**否证**。
2. **可达性 + 判别力**：枚举 ROM 中全部装载类指令的位翻转，统计每个目标值的
   **路径数**，并换算成"在该分布中的百分位"。**路径数高 = 无判别力**
   （说明是常见常量，任何值都可达）；只有路径数 = 0 才有强判别力。
3. **频率自洽性**：若码 X 由装载点 P 翻转而来，则 P 的"未翻转"版本也应被观测到
   过（除非翻转率 100%，物理上不合理）。用观测频次检验。

## 纪律

- 芯片无关：ROM 路径/基址/目标码/已知码全部由调用方传入，本模块零实例值。
- 多解全列：``verdict`` 只给"是否可达/是否有判别力"，不给"就是它"。
- 全部机制解释 ``evidence_level = hypothesis``；编码边界与路径计数为 ``observation``。
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

__all__ = [
    "FlipScanConfig",
    "scan_flip_reachability",
    "check_addi_encoding_boundary",
    "discriminating_power",
    "frequency_consistency",
    "audit_bitflip_hypothesis",
]

#: RISC-V I-type 立即数字段位宽
ADDI_IMM_BITS = 12
#: addi 可编码的正数上界（符号扩展后的最大值）
ADDI_IMM_MAX_POSITIVE = (1 << (ADDI_IMM_BITS - 1)) - 1     # 0x7FF

#: 装载类指令助记符（能"装入一个常量"的形态）
_LOAD_MNEMONICS = ("addi", "c.addi", "c.li", "li", "lui", "c.lui")

_EVIDENCE_ORDER = {"fact": 3, "hypothesis": 2, "observation": 2.5, "unknown": 1}


@dataclass
class FlipScanConfig:
    """扫描配置（全部由调用方显式传入）。"""

    rom_path: str
    rom_base: int
    max_flips: int = 6
    flip_mode: str = "one_to_zero"
    #: 只统计这些助记符（缺省=全部装载类）
    mnemonics: tuple[str, ...] = _LOAD_MNEMONICS


# ---------------------------------------------------------------------------
# 编码边界（最强判别，不依赖 ROM 扫描）
# ---------------------------------------------------------------------------
def check_addi_encoding_boundary(code_value: int) -> dict:
    """检查一个码值是否可能在 ``addi`` 的立即数编码范围内。

    这是**独立于 ROM 内容**的 ISA 约束：任何 ``addi rd,zero,imm`` 只能装出
    ``-2048..2047``（即 imm12 符号扩展）。超出该范围的值**不可能**由
    ``addi`` 装载，因此也**不可能**由"另一条 addi 的位翻转"产生。

    注意：``lui`` 可装出 ``imm20 << 12``，故超范围值仍可能由 ``lui`` /
    ``lui+addi`` / 运算产生——本函数只否证 ``addi`` 路径。
    """
    in_range = -(1 << (ADDI_IMM_BITS - 1)) <= code_value <= ADDI_IMM_MAX_POSITIVE
    return {
        "code_value": f"0x{code_value:04X}",
        "addi_imm_bits": ADDI_IMM_BITS,
        "addi_encodable_range": [
            -(1 << (ADDI_IMM_BITS - 1)), ADDI_IMM_MAX_POSITIVE],
        "within_addi_range": in_range,
        "verdict": "possible_via_addi" if in_range else "impossible_via_addi",
        "note": ("在 addi 立即数范围内：位翻转路径需进一步枚举"
                 if in_range else
                 "超出 addi 立即数编码范围：**addi 位翻转路径被排除**，"
                 "必须由 lui / lui+addi / 运行时运算 / 寄存器间接 / 帧值层面翻转产生"),
        "evidence_level": "fact",
    }


# ---------------------------------------------------------------------------
# 反汇编辅助
# ---------------------------------------------------------------------------
def _make_disasm():
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_RISCV,
                     capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)

    def disasm(code: bytes, addr: int):
        try:
            out = list(md.disasm(code, addr))
            if not out:
                return None
            return f"{out[0].mnemonic} {out[0].op_str}".strip(), out[0].size
        except StopIteration:
            return None

    return disasm


def _parse_imm(text: str, mnem: str) -> int | None:
    """从指令文本提取"被装入的常量值"（lui 按 <<12 处理）。"""
    if not text or " " not in text:
        return None
    parts = [p.strip() for p in text.split(None, 1)[1].split(",")]
    try:
        if mnem in ("addi", "c.addi") and len(parts) == 3 and parts[1] == "zero":
            return int(parts[2], 0) & 0xFFFFFFFF
        if mnem in ("c.li", "li") and len(parts) == 2:
            return int(parts[1], 0) & 0xFFFFFFFF
        if mnem in ("lui", "c.lui") and len(parts) == 2:
            return (int(parts[1], 0) << 12) & 0xFFFFFFFF
    except ValueError:
        return None
    return None


# ---------------------------------------------------------------------------
# 全 ROM 位翻转可达性扫描
# ---------------------------------------------------------------------------
def scan_flip_reachability(cfg: FlipScanConfig,
                           targets: Sequence[int] | None = None) -> dict:
    """枚举 ROM 中全部装载类指令的位翻转变体，统计每个可达常量值的路径数。

    ``targets``：若给出，只保留这些目标值的详细路径（其余只计数），
    避免返回体过大。

    返回：
    - ``path_counts``：{值: 路径数}（全量，用于计算判别力分布）
    - ``target_paths``：{目标值: [{addr, src_insn, flipped_bits, dst_insn}, ...]}
    - ``distribution``：路径数分布的统计量（min/median/p90/max/n_values/n_paths）
    """
    disasm = _make_disasm()
    rom = Path(cfg.rom_path).read_bytes()
    base = cfg.rom_base

    # 线性反汇编，取装载类指令
    insns = []
    off = 0
    while off < len(rom) - 1:
        r = disasm(rom[off:off + 4], base + off)
        if not r:
            off += 2
            continue
        text, size = r
        mn = text.split()[0]
        if mn in cfg.mnemonics:
            insns.append((off, text, size, mn))
        off += size

    path_counts: dict[int, int] = {}
    target_paths: dict[int, list] = {t: [] for t in (targets or [])}
    target_set = set(targets or [])

    for off, text, size, mn in insns:
        orig_imm = _parse_imm(text, mn)
        val = int.from_bytes(rom[off:off + size], "little")
        if cfg.flip_mode == "one_to_zero":
            flippable = [p for p in range(size * 8) if (val >> p) & 1]
        elif cfg.flip_mode == "zero_to_one":
            flippable = [p for p in range(size * 8) if not (val >> p) & 1]
        else:
            flippable = list(range(size * 8))

        for k in range(1, min(cfg.max_flips, len(flippable)) + 1):
            for combo in itertools.combinations(flippable, k):
                nv = val
                for p in combo:
                    nv ^= (1 << p)
                nb = nv.to_bytes(size, "little")
                r2 = disasm(nb, base + off)
                if not r2:
                    continue
                t2, s2 = r2
                if s2 != size:
                    continue
                mn2 = t2.split()[0]
                if mn2 not in cfg.mnemonics:
                    continue
                imm = _parse_imm(t2, mn2)
                if imm is None or imm == orig_imm:
                    continue
                path_counts[imm] = path_counts.get(imm, 0) + 1
                if imm in target_set and len(target_paths[imm]) < 40:
                    target_paths[imm].append({
                        "rom_offset": off,
                        "addr": f"0x{base + off:08X}",
                        "src_insn": text,
                        "flipped_bit_positions": list(combo),
                        "dst_insn": t2,
                        "dst_value": f"0x{imm:04X}",
                    })

    vals = sorted(path_counts.values())
    n_values = len(vals)
    total_paths = sum(vals)
    distribution = {
        "n_load_instructions": len(insns),
        "n_distinct_values": n_values,
        "n_total_paths": total_paths,
        "mean_paths_per_value": round(total_paths / n_values, 2) if n_values else None,
        "median_paths": vals[n_values // 2] if n_values else None,
        "p90_paths": vals[int(n_values * 0.9)] if n_values else None,
        "max_paths": vals[-1] if n_values else None,
        "max_paths_value": (f"0x{max(path_counts, key=path_counts.get):04X}"
                            if path_counts else None),
    }
    return {
        "config": {
            "rom_path": cfg.rom_path,
            "rom_base": f"0x{cfg.rom_base:08X}",
            "max_flips": cfg.max_flips,
            "flip_mode": cfg.flip_mode,
        },
        "path_counts": path_counts,
        "target_paths": target_paths,
        "distribution": distribution,
        "physical_assumption": (
            "假设毛刺效果为把若干 1 位翻成 0（crowbar-to-ground 常见效果）；"
            "该假设可直接切换 flip_mode 检验，属 hypothesis"
        ),
        "evidence_level": "observation",
    }


# ---------------------------------------------------------------------------
# 判别力（本节是整个模块的核心方法学贡献）
# ---------------------------------------------------------------------------
def discriminating_power(path_count: int, distribution: dict) -> dict:
    """把"路径数"换算成"判别力"。

    **核心洞察**：ROM 有数千条装载类指令，枚举后可达数十万种常量值，
    平均每个值有多条路径。因此"可达"几乎必然 → **可达性本身零信息量**。

    判别力只看两个极端：
    - 路径数 = 0 → ``strong``（该形态下不可达，可否证假设）；
    - 路径数位于分布高位（>99 分位）→ ``none``（属常见常量，无法区分）；
    - 中间区间 → ``weak``（可在其它证据支持下参考，不可单独作证据）。
    """
    n_values = distribution.get("n_distinct_values") or 0
    if path_count <= 0:
        return {
            "path_count": 0,
            "percentile": 0.0,
            "discriminating": "strong",
            "reason": "该形态下不可达（路径数 0）→ 假设被否证",
        }
    if not n_values:
        return {"path_count": path_count, "percentile": None,
                "discriminating": "unknown", "reason": "无分布基线"}
    # 百分位需要全量分布；这里用 median/p90 近似判定（避免传全量列表）
    median = distribution.get("median_paths") or 0
    p90 = distribution.get("p90_paths") or 0
    mean = distribution.get("mean_paths_per_value") or 0
    if path_count <= p90:
        level = "weak"
        reason = "路径数低于 90 分位，有弱判别力（需其它证据支持）"
    elif path_count <= max(p90 * 4, mean * 4):
        level = "low"
        reason = "路径数偏高，判别力低"
    else:
        level = "none"
        reason = ("路径数极高（属常见常量）→ **无判别力**："
                  "任何值都可能被'翻转得到'，可达性不构成证据")
    return {
        "path_count": path_count,
        "median_path": median,
        "p90_path": p90,
        "mean_path": mean,
        "discriminating": level,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# 频率自洽性
# ---------------------------------------------------------------------------
def frequency_consistency(source_code: str, target_code: str,
                          source_count: int, target_count: int) -> dict:
    """检验"目标码由源码翻转而来"在频率上是否自洽。

    逻辑：若注入命中源码装载点 P，则
    - 命中且翻转 → 观测到 target（``target_count`` 次）
    - 命中且不翻转 → 观测到 source（``source_count`` 次）
    若 source_count = 0 而 target_count > 0，则隐含"命中必翻转"，物理上不合理。

    注意：本检验假设"source 码的唯一来源是 P"。若 source 另有原生装载点，
    则本检验失效（应返回 ``inconclusive``）。
    """
    total = source_count + target_count
    if total == 0:
        return {"verdict": "no_data", "implied_flip_rate": None}
    implied = target_count / total
    if source_count == 0 and target_count > 0:
        verdict = "implausible"
        note = ("隐含翻转率 100%（命中必翻转），物理上不合理；"
                "更可能 source 码另有原生装载点，或 target 来自其它路径")
    elif implied > 0.9:
        verdict = "implausible"
        note = f"隐含翻转率 {implied:.0%}，过高；毛刺是随机事件，不应近 100% 翻转特定位"
    else:
        verdict = "plausible"
        note = f"隐含翻转率 {implied:.1%}，在合理范围"
    return {
        "source_code": source_code,
        "target_code": target_code,
        "source_count": source_count,
        "target_count": target_count,
        "implied_flip_rate": round(implied, 6),
        "verdict": verdict,
        "note": note,
        "caveat": "本检验假设 source 码唯一来源于该装载点；若有原生装载点则不适用",
        "evidence_level": "observation",
    }


# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
def audit_bitflip_hypothesis(cfg: FlipScanConfig,
                             known_codes: Sequence[str],
                             unattributed_codes: Sequence[str],
                             csv_counts: dict[str, int],
                             code_pairs: Sequence[dict] | None = None) -> dict:
    """完整审计：编码边界 → 可达性 → 判别力 → 频率自洽（可选）。

    ``known_codes``：ROM 中已归因的码（"源"候选）。
    ``unattributed_codes``：待解释的码（"目标"）。
    ``csv_counts``：{码: 观测次数}（用于判别与频率检验）。
    ``code_pairs``：可选，[{source, target, instruction_addr, flipped_bits}]（来自其它工具）。
    """
    known = [int(c, 16) for c in known_codes]
    unknown = [int(c, 16) for c in unattributed_codes]
    scan = scan_flip_reachability(cfg, targets=list(set(known) | set(unknown)))
    dist = scan["distribution"]
    path_counts = scan["path_counts"]

    per_code = []
    for c in unattributed_codes:
        v = int(c, 16)
        boundary = check_addi_encoding_boundary(v)
        n_paths = path_counts.get(v, 0)
        disc = discriminating_power(n_paths, dist)
        # 从已知码能否 1->0 翻转到达（纯数值，不依赖 ROM）
        src_hits = []
        for k in known:
            # 1→0 翻转：target 必须是 source 的位子集
            if (v & k) == v and v != k:
                flips = bin(k).count("1") - bin(v).count("1")
                src_hits.append({"source": f"0x{k:04X}", "ones_cleared": flips})
        if not boundary["within_addi_range"]:
            verdict = "refuted_by_encoding_boundary"
            level = "fact"
        elif n_paths == 0:
            verdict = "not_reachable_in_scanned_forms"
            level = "observation"
        elif disc["discriminating"] == "none":
            verdict = "reachable_but_no_discriminating_power"
            level = "observation"
        else:
            verdict = "reachable_with_weak_discrimination"
            level = "hypothesis"
        per_code.append({
            "code": c,
            "value": f"0x{v:04X}",
            "csv_count": csv_counts.get(c, 0),
            "encoding_boundary": boundary,
            "flip_paths_total": n_paths,
            "discriminating_power": disc,
            "numeric_superset_sources": src_hits,
            "sample_paths": scan["target_paths"].get(v, [])[:10],
            "verdict": verdict,
            "evidence_level": level,
        })

    freq = []
    for p in (code_pairs or []):
        freq.append({
            "pair": p,
            **frequency_consistency(
                p.get("source", "unknown"), p.get("target", "unknown"),
                csv_counts.get(p.get("source", ""), 0),
                csv_counts.get(p.get("target", ""), 0)),
        })

    levels = [x["evidence_level"] for x in per_code]
    overall = "fact" if levels and all(l == "fact" for l in levels) else (
        "observation" if any(l == "observation" for l in levels) else "hypothesis")
    return {
        "schema": "fi.analysis.bitflip-hypothesis-v1",
        "scan_config": scan["config"],
        "distribution": dist,
        "per_code": per_code,
        "frequency_consistency": freq,
        "method_note": (
            "三层判别：①编码边界（fact，可否证）②可达性判别力"
            "（'可达'本身零信息量，只有路径数 0 或极低才有判别力）"
            "③频率自洽性（隐含翻转率不应接近 100%）"
        ),
        "discipline": (
            "多解全列：本审计只判定'是否可达/是否有判别力'，不宣称'就是该来源'；"
            "全部机制解释为 hypothesis，编码边界与路径计数为 observation/fact"
        ),
        "overall_evidence_level": overall,
    }
