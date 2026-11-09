# -*- coding: utf-8 -*-
"""统一异常分析报告：把分散的分析能力整合为单次可复用的闭环产出。

产出两份文件（同一份内容的两种视图）：
- ``*.anomaly-report.json``  机读（Dashboard / 下游工具消费）
- ``*.anomaly-report.md``    人读（结论 + 证据链 + 待验证清单）

报告骨架（固定六节，换数据集不变）
--------------------------------
1. **数据质量与非平稳性**（强制前置）——任何结论都在这一步之后才允许给出。
   含：行数/跳过行/缺列、状态构成、时间漂移（overdispersion、首末差、趋势）、
   时间轴假设声明。若非平稳，后续所有跨行比较均标注"已扣除时间轴"。
2. **命令面归因**——码表、码族、码↔阶段映射（含 confidence）。
3. **帧格式解析**——仅当数据含字节流；含帧边界、字段布局、claim 矩阵。
4. **统计功效**——MDE 与"看得见/看不见"声明（区分"无窗口"与"设计看不见"）。
5. **待验证矛盾点（unknowns）**——按证据强度排序，附判决方法。
6. **证据链**——每个结论 → 数据行范围 / ROM 地址 / 仿真运行件。

设计原则
--------
- **先检查再结论**：第 1 节不通过（非平稳/缺字段严重）时，第 2–4 节结论自动
  降级并在报告头部明示。
- **零实例值**：标签集/码域/码族/阶段映射/列名全部来自数据集或 config。
- **不丢结论**：三份既有文档的结论以 ``findings`` 形式进入报告，并标注来源。
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from fi.analysis.command_surface import (
    code_key_of,
    code_taxonomy,
    conditional_composition,
    family_profiles,
    phase_constraints,
)
from fi.analysis.dataset import ColumnMapping, CodeRule, Dataset, load_dataset
from fi.analysis.stratify import (
    chi2_wh,
    detrended_delay_profile,
    nonstationarity_verdict,
    pointwise_significance,
    power_analysis,
    time_drift_summary,
    wilson_interval,
)

__all__ = ["AnomalyReportConfig", "build_anomaly_report", "render_markdown"]

#: 非平稳判定的默认参数（统计规则，非数据集值）
DEFAULT_NONSTATIONARITY_ALPHA = 0.05
DEFAULT_MIN_DRIFT_PP = 1.0
DEFAULT_MIN_DRIFT_RELATIVE = 0.05

#: 期望计数低于该值的点，正态近似失效（与 stratify 默认一致）
MIN_EXPECTED_COUNT = 5.0


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
@dataclass
class AnomalyReportConfig:
    """报告生成配置。全部字段可选；缺省的行为必须对任意数据集成立。

    数据集语义（标签含义、码族划分、阶段映射、目标标签）**只能**经此传入，
    不得写进通用代码。
    """

    #: 数据形态
    format: str | None = None
    columns: ColumnMapping = field(default_factory=ColumnMapping)
    code_rule: CodeRule = field(default_factory=CodeRule)

    #: 主扫描 pulse 值；None = 从数据推导（行数最多的 pulse）
    main_pulse: int | None = None
    #: 视为"基线/未改变响应"的状态标签（用于条件构成分析）
    baseline_states: Sequence[str] = ()
    #: 评分/区间目标标签（哪一标签是"成功"是数据集语义）
    target_label: str | None = None

    #: 码族划分 {族名: [码键...]}（来自 ROM 侧逆向；空=不分析码族）
    families: dict[str, list[str]] = field(default_factory=dict)
    #: 码 → 功能阶段映射（来自 ROM 侧逆向；空=unknown）
    code_phase_map: dict[str, dict] = field(default_factory=dict)

    #: 字节流（trace 格式时用于重建）
    byte_data_addr: tuple[int, int] | None = None
    byte_region: str | None = None
    preamble_len: int = 0
    #: 帧长（None = 从字节流推导）
    frame_len: int | None = None
    #: ROM 静态分析（可选）
    rom_path: str | None = None
    rom_base: int | None = None
    rom_construction_sites: dict[str, dict] = field(default_factory=dict)

    #: 时间分段数
    n_time_segments: int = 20
    n_detrend_segments: int = 200
    #: 非平稳判定参数（显著性 α + 效应量下限）
    nonstationarity_alpha: float = DEFAULT_NONSTATIONARITY_ALPHA
    min_drift_pp: float = DEFAULT_MIN_DRIFT_PP
    min_drift_relative: float = DEFAULT_MIN_DRIFT_RELATIVE
    #: 已知的外部结论（来自既有报告），原样并入 findings 以"不丢结论"
    prior_findings: Sequence[dict] = ()
    #: 上游未决问题（含 lead 已派单的矛盾点），并入 unknowns
    known_unknowns: Sequence[dict] = ()
    #: 证据链补充条目（人工维护的"结论→证据"映射）
    evidence_links: Sequence[dict] = ()

    @classmethod
    def from_dict(cls, d: dict | None) -> "AnomalyReportConfig":
        if not d:
            return cls()
        cols = ColumnMapping.from_dict(d.get("columns"))
        cr = CodeRule(
            hex_prefixes=tuple(d.get("code_rule", {}).get("hex_prefixes", ("0x", "0X"))),
            allow_decimal=bool(d.get("code_rule", {}).get("allow_decimal", False)),
            tokens=tuple(d.get("code_rule", {}).get("tokens", ())),
            empty_markers=tuple(d.get("code_rule", {}).get("empty_markers", ())),
        )
        addr = d.get("byte_data_addr")
        return cls(
            format=d.get("format"),
            columns=cols,
            code_rule=cr,
            main_pulse=d.get("main_pulse"),
            baseline_states=tuple(d.get("baseline_states", ())),
            target_label=d.get("target_label"),
            families=d.get("families", {}) or {},
            code_phase_map=d.get("code_phase_map", {}) or {},
            byte_data_addr=(int(addr[0], 0), int(addr[1], 0)) if addr else None,
            byte_region=d.get("byte_region"),
            preamble_len=int(d.get("preamble_len", 0)),
            frame_len=d.get("frame_len"),
            rom_path=d.get("rom_path"),
            rom_base=(int(d["rom_base"], 0) if isinstance(d.get("rom_base"), str)
                      else d.get("rom_base")),
            rom_construction_sites=d.get("rom_construction_sites", {}) or {},
            n_time_segments=int(d.get("n_time_segments", 20)),
            n_detrend_segments=int(d.get("n_detrend_segments", 200)),
            nonstationarity_alpha=float(d.get("nonstationarity_alpha",
                                              DEFAULT_NONSTATIONARITY_ALPHA)),
            min_drift_pp=float(d.get("min_drift_pp", DEFAULT_MIN_DRIFT_PP)),
            min_drift_relative=float(d.get("min_drift_relative",
                                           DEFAULT_MIN_DRIFT_RELATIVE)),
            prior_findings=tuple(d.get("prior_findings", ())),
            known_unknowns=tuple(d.get("known_unknowns", ())),
            evidence_links=tuple(d.get("evidence_links", ())),
        )


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def build_anomaly_report(input_path: str | Path,
                         cfg: AnomalyReportConfig | None = None) -> dict:
    """生成综合异常分析报告（dict，可直接 json.dump）。

    流程严格按六节顺序；第 1 节的结论会门控后续节的可信度标注。
    """
    cfg = cfg or AnomalyReportConfig()
    ds = load_dataset(
        input_path,
        mapping=cfg.columns,
        code_rule=cfg.code_rule,
        fmt=cfg.format,
        byte_data_addr=cfg.byte_data_addr,
        byte_region=cfg.byte_region,
        preamble_len=cfg.preamble_len,
    )
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    quality = _section_quality(ds, cfg)
    command = _section_command_surface(ds, cfg, quality)
    frame = _section_frame(ds, cfg)
    power = _section_power(ds, cfg, command, quality)
    unknowns = _section_unknowns(ds, cfg, quality, command, frame, power)
    evidence = _section_evidence(ds, cfg, input_path, quality, command, frame, power)

    findings = _collect_findings(ds, cfg, quality, command, frame, power)

    return {
        "schema": "fi.analysis.anomaly-report-v1",
        "generated_utc": generated,
        "inputs": {
            "path": str(input_path),
            "format": ds.report.format,
            "n_rows": len(ds.records),
            "has_byte_stream": ds.byte_stream is not None,
            "config_keys": sorted(k for k in (cfg.__dict__ if cfg else {})
                                  if k not in ("columns", "code_rule")),
        },
        "load_report": ds.report.to_dict(),
        "sections": {
            "quality_and_stationarity": quality,
            "command_surface": command,
            "frame_format": frame,
            "statistical_power": power,
            "unknowns": unknowns,
            "evidence_chain": evidence,
        },
        "findings": findings,
        "metadata": {
            "generator": "fi.analysis.anomaly_report",
            "discipline": (
                "结论一律标注 observation/hypothesis/unknown；"
                "第 1 节数据质量检查是所有后续结论的前置门控；"
                "行序=采集时序为假设（见 sections.quality_and_stationarity.time_axis_assumption）"
            ),
        },
    }


# ---------------------------------------------------------------------------
# 第 1 节：数据质量与非平稳性（强制前置）
# ---------------------------------------------------------------------------
def _section_quality(ds: Dataset, cfg: AnomalyReportConfig) -> dict:
    rep = ds.report
    n = len(ds.records)
    out: dict[str, Any] = {
        "gate_passed": True,
        "gate_failures": [],
        "n_rows": n,
        "n_rows_raw": rep.n_rows_raw,
        "skipped": rep.skipped,
        "skip_reasons": rep.skip_reasons,
        "missing_fields": rep.missing_fields,
        "detected_columns": rep.detected_columns,
        "notes": rep.notes,
    }
    if n == 0:
        out["gate_passed"] = False
        out["gate_failures"].append("数据源无结构化记录（可能只含字节流/文本）："
                                    "命令面与统计功效两节不可用")
        out["time_axis_assumption"] = _time_axis_assumption("no_records")
        return out

    states = ds.states
    label_counts: dict[str, int] = {}
    for s in states:
        label_counts[s] = label_counts.get(s, 0) + 1
    labels = sorted(label_counts, key=lambda k: -label_counts[k])
    out["labels"] = labels
    out["label_counts"] = {k: label_counts[k] for k in labels}
    out["label_shares"] = {k: round(label_counts[k] / n, 8) for k in labels}
    out["n_labels"] = len(labels)

    # 参数轴可用性
    delays = [r["delay_raw"] for r in ds.records if r["delay_raw"] is not None]
    pulses = [r["pulse_raw"] for r in ds.records if r["pulse_raw"] is not None]
    out["axis_availability"] = {
        "delay": len(delays) > 0,
        "pulse": len(pulses) > 0,
        "delay_n": len(delays),
        "pulse_n": len(pulses),
        "delay_range": [min(delays), max(delays)] if delays else None,
        "pulse_values": sorted(set(pulses)) if pulses else None,
    }

    # 时间轴
    has_ts = any(r.get("timestamp") for r in ds.records)
    out["time_axis_source"] = "timestamp_column" if has_ts else "row_order"
    out["time_axis_assumption"] = _time_axis_assumption(
        "timestamp_column" if has_ts else "row_order")

    # 非平稳性：显着性（χ²）+ 效应量（首末变化）双条件判定
    drift = time_drift_summary(states, labels=labels, n_segments=cfg.n_time_segments)
    drift_d = drift.to_dict()
    out["time_drift"] = drift_d

    verdict = nonstationarity_verdict(
        drift,
        alpha=cfg.nonstationarity_alpha,
        min_total_change_pp=cfg.min_drift_pp,
        min_relative_change=cfg.min_drift_relative,
    )
    out["nonstationarity_verdict"] = verdict

    nonstationary = []
    for lab in verdict["flagged_labels"]:
        d = drift_d["per_label"][lab]
        nonstationary.append({
            "label": lab,
            "overdispersion_ratio": d.get("overdispersion_ratio"),
            "chi2_p": (d.get("homogeneity_chi2") or {}).get("p_approx"),
            "first_segment_rate": d["rate_first_segment"],
            "last_segment_rate": d["rate_last_segment"],
            "total_change_pp": d.get("segment_total_change_pp"),
            "trend_pearson_r": d["trend_monotonic_pearson_r"],
        })
    out["nonstationary_labels"] = nonstationary
    out["mild_drift_labels"] = [
        {"label": lab, "reason": verdict["per_label"][lab]}
        for lab in verdict["mild_labels"]
    ]
    out["is_stationary"] = (verdict["designation"] == "stationary")

    if verdict["designation"] == "nonstationary":
        worst = max(nonstationary, key=lambda x: abs(x.get("total_change_pp") or 0.0))
        out["stationarity_verdict"] = (
            f"**数据非平稳**：{len(nonstationary)}/{len(labels)} 个标签同时满足"
            f"「χ² 齐性 p < α/K」与「效应量足够」两项条件"
            f"（最严重 {worst['label']}：首末段 {worst['first_segment_rate']:.5f}→"
            f"{worst['last_segment_rate']:.5f}，总变化 {worst['total_change_pp']:+.2f}pp，"
            f"χ² p={worst['chi2_p']:.3g}，过散比 {worst['overdispersion_ratio']}）。"
            "后续一切跨行比较结论均已扣除时间轴（去趋势）；未扣除的比较不得作为机制证据"
        )
        out["post_gate_policy"] = "detrend_required"
    elif verdict["designation"] == "mild_drift":
        out["stationarity_verdict"] = (
            "未判定为非平稳，但有 %d 个标签存在轻微漂移（仅满足显著性条件或仅满足"
            "效应量条件）：%s。这些标签的去趋势画像已给出，跨行比较建议谨慎"
            % (len(verdict["mild_labels"]), ", ".join(verdict["mild_labels"]))
        )
        out["post_gate_policy"] = "detrend_advisory"
    else:
        out["stationarity_verdict"] = (
            "未检出显著非平稳（全部标签 χ² 齐性 p 未过 Bonferroni 阈值，或效应量 < "
            f"{cfg.min_drift_pp:g}pp）：可直接按同分布处理，去趋势步骤为无害的恒等变换"
        )
        out["post_gate_policy"] = "direct"

    # 严重缺字段 → 阻断
    if not delays and not pulses:
        out["gate_passed"] = False
        out["gate_failures"].append("delay/pulse 两轴均不可用：无法做参数维分析")
    if len(labels) < 2:
        out["gate_passed"] = False
        out["gate_failures"].append(f"仅 {len(labels)} 个状态标签：无法做标签对比")
    return out


def _time_axis_assumption(source: str) -> dict:
    return {
        "source": source,
        "claim": ("记录行序 = 采集时序" if source == "row_order"
                  else "timestamp 列 = 采集时序"),
        "evidence_level": "hypothesis",
        "note": ("数据源无时间戳列，行序是唯一可用的时序代理；"
                 "若采集端曾打乱行序，时间漂移结论退化为 unknown"
                 if source == "row_order" else
                 "使用数据自带时间戳；需确认该列语义与时钟源（unknown）"),
    }


# ---------------------------------------------------------------------------
# 第 2 节：命令面归因
# ---------------------------------------------------------------------------
def _section_command_surface(ds: Dataset, cfg: AnomalyReportConfig,
                             quality: dict) -> dict:
    if not ds.records:
        return {"available": False,
                "reason": quality.get("gate_failures") or ["无结构化记录"]}

    rows = ds.records
    n = len(rows)
    labels = quality.get("labels", [])
    bg = labels[0] if labels else None
    out: dict[str, Any] = {"available": True, "n_rows": n, "background_state": bg}

    # 主 pulse 推导
    pulse_counts: dict[int, int] = {}
    for r in rows:
        if r["pulse_raw"] is not None:
            pulse_counts[r["pulse_raw"]] = pulse_counts.get(r["pulse_raw"], 0) + 1
    if cfg.main_pulse is not None:
        main_pulse = cfg.main_pulse
        derived = False
    elif pulse_counts:
        main_pulse = max(pulse_counts, key=lambda k: pulse_counts[k])
        derived = True
    else:
        main_pulse = None
        derived = False
    out["main_pulse"] = main_pulse
    out["main_pulse_derived"] = derived

    # 码表
    tax = code_taxonomy(rows, background_state=bg)
    out["taxonomy"] = tax

    # 码族
    if cfg.families:
        out["families"] = family_profiles(rows, dict(cfg.families))
    else:
        out["families"] = {
            "available": False,
            "reason": "config 未提供 families（码族划分来自 ROM 侧逆向，须显式传入）",
        }

    # 阶段约束
    if cfg.code_phase_map:
        out["phase_constraints"] = phase_constraints(rows, dict(cfg.code_phase_map))
    else:
        out["phase_constraints"] = {
            "available": False,
            "reason": "config 未提供 code_phase_map（码↔功能阶段须由 ROM 侧逆向提供）",
        }

    # 条件构成 + 去趋势 delay 画像（仅主扫描子集）
    main_rows = [r for r in rows if r["pulse_raw"] == main_pulse]
    if main_rows:
        baseline = list(cfg.baseline_states) or ([bg] if bg else [])
        out["baseline_states_used"] = baseline
        out["conditional_composition_by_delay"] = conditional_composition(
            main_rows, axis="delay_raw", baseline_states=baseline)
        axis = [r["delay_raw"] for r in main_rows]
        ridx = list(range(len(main_rows)))
        mstates = [r["state"] for r in main_rows]
        profiles = {}
        for lab in labels:
            if lab not in set(mstates):
                continue
            p = detrended_delay_profile(
                axis, mstates, lab, row_index=ridx,
                n_time_segments=cfg.n_detrend_segments, axis_name="delay_raw")
            profiles[lab] = p.to_dict()
        out["delay_axis_profiles"] = profiles

        # 逐点显著性（含小计数保护）
        by_point: dict[Any, dict[str, int]] = {}
        for r in main_rows:
            cell = by_point.setdefault(r["delay_raw"], {})
            cell[r["state"]] = cell.get(r["state"], 0) + 1
            cell["_n"] = cell.get("_n", 0) + 1
        delays = sorted(k for k in by_point if k is not None)
        sig = {}
        for lab in labels:
            counts = [by_point[d].get(lab, 0) for d in delays]
            ns = [by_point[d]["_n"] for d in delays]
            sig[lab] = pointwise_significance(counts, ns,
                                              min_expected_count=MIN_EXPECTED_COUNT)
        out["pointwise_significance"] = {
            lab: {"n_points": v["n_points"], "pooled_rate": v["pooled_rate"],
                  "fdr": v["fdr"], "low_count_warning": v["low_count_warning"]}
            for lab, v in sig.items()
        }
        out["_sig_full"] = sig  # 供第 4 节功效使用（输出前剥离）
        out["_delays"] = delays
        out["_by_point"] = by_point
    return out


# ---------------------------------------------------------------------------
# 第 3 节：帧格式解析
# ---------------------------------------------------------------------------
def _section_frame(ds: Dataset, cfg: AnomalyReportConfig) -> dict:
    if ds.byte_stream is None:
        return {"available": False,
                "reason": "输入数据不含字节流（CSV/JSONL 无原始字节通道）"}
    from fi.analysis.frame_audit import (
        ByteStream,
        derive_frame_layout,
        extract_frame_candidates,
    )

    stream = ByteStream(data=ds.byte_stream,
                        source=ds.byte_stream_meta.get("source", "unknown"),
                        preamble_len=0,  # 已在 dataset 层剥离
                        evidence_level="observation")
    bounds = extract_frame_candidates(stream)
    frame_len = cfg.frame_len
    derived = False
    if frame_len is None:
        cand = (bounds["plausible_frame_lengths_after_zero_strip"]
                or bounds["plausible_frame_lengths"])
        frame_len = cand[0] if cand else None
        derived = True

    out: dict[str, Any] = {
        "available": True,
        "byte_stream_meta": ds.byte_stream_meta,
        "payload_len": len(ds.byte_stream),
        "payload_hex": ds.byte_stream.hex(),
        "frame_boundaries": bounds,
        "frame_len_used": frame_len,
        "frame_len_derived": derived,
    }
    if frame_len:
        out["field_layout"] = derive_frame_layout(stream, frame_len)

    # ROM 侧算术推导（可选）
    if cfg.rom_path and cfg.rom_base is not None and cfg.rom_construction_sites:
        out["rom_construction"] = _derive_rom_sites(cfg)
        out["three_way_comparison"] = _compare_three_way(
            ds.byte_stream, frame_len, out.get("field_layout"), out["rom_construction"])
    else:
        out["rom_construction"] = {
            "available": False,
            "reason": "config 未提供 rom_path/rom_base/rom_construction_sites",
        }
    return out


def _derive_rom_sites(cfg: AnomalyReportConfig) -> dict:
    import capstone

    rom = Path(cfg.rom_path).read_bytes()
    md = capstone.Cs(capstone.CS_ARCH_RISCV,
                     capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
    from fi.analysis.run_frame_audit import _read_ops
    from fi.analysis.frame_audit import derive_rom_frame_construction

    out = {}
    for name, spec in cfg.rom_construction_sites.items():
        off = spec["offset"]
        off = int(off, 0) if isinstance(off, str) else off
        ops = _read_ops(rom, cfg.rom_base, off, int(spec.get("n_insn", 20)))
        der = derive_rom_frame_construction(
            ops, var_code=spec.get("var_code", "a0"),
            var_target=spec.get("var_target", "a5"))
        der.pop("ops", None)
        der["site_role"] = spec.get("role", "frame_value")
        der["offset"] = hex(off)
        out[name] = der
    return out


def _compare_three_way(payload: bytes, frame_len: int | None,
                       layout: dict | None, rom: dict) -> dict:
    """字节流实际值 vs ROM 符号式的常量位/变量反解。"""
    actual = int.from_bytes(payload[:4], "little") if len(payload) >= 4 else None
    out: dict[str, Any] = {
        "actual_first_4_bytes_hex": payload[:4].hex() if len(payload) >= 4 else None,
        "actual_u32_le": f"0x{actual:08X}" if actual is not None else None,
        "sites": {},
    }
    if actual is None:
        return out
    for name, der in rom.items():
        sym = der.get("symbolic_frame") or {}
        known = sym.get("known_mask")
        known_i = int(known, 16) if isinstance(known, str) else None
        unk = sym.get("unknown_vars") or []
        rec: dict[str, Any] = {
            "symbolic_expr": sym.get("expr"),
            "known_mask": known,
            "unknown_vars": unk,
            "site_role": der.get("site_role"),
        }
        if known_i is not None and der.get("site_role") == "frame_value":
            var_mask = 0
            for v in unk:
                var_mask |= (0xFFFF << int(v["shift"])) & 0xFFFFFFFF
            const_mask = (~var_mask) & 0xFFFFFFFF
            rec["constant_bits_match"] = (
                (actual & const_mask) == (known_i & const_mask))
            rec["const_mask"] = f"0x{const_mask:08X}"
            rec["actual_const_bits"] = f"0x{actual & const_mask:08X}"
            rec["expected_const_bits"] = f"0x{known_i & const_mask:08X}"
            rec["solved_variables"] = {
                v["name"]: {"shift": v["shift"],
                            "solved": f"0x{(actual >> int(v['shift'])) & 0xFFFF:04X}"}
                for v in unk
            }
        out["sites"][name] = rec
    return out


# ---------------------------------------------------------------------------
# 第 4 节：统计功效
# ---------------------------------------------------------------------------
def _section_power(ds: Dataset, cfg: AnomalyReportConfig,
                   command: dict, quality: dict) -> dict:
    if not command.get("available") or not command.get("_delays"):
        return {"available": False, "reason": "无主扫描逐点数据"}

    delays = command["_delays"]
    by_point = command["_by_point"]
    ns = [by_point[d]["_n"] for d in delays]
    mean_n = int(sum(ns) / len(ns)) if ns else 0

    per_label = {}
    for lab, sig in command.get("_sig_full", {}).items():
        p0 = sig.get("pooled_rate")
        if p0 in (None, 0.0, 1.0):
            continue
        pa = power_analysis(p0, mean_n)
        n_sig = sig["fdr"]["n_significant"]
        low_count = sig["fdr"]["n_points_low_count"]
        detect = _detectability_statement(lab, p0, pa, n_sig, low_count)
        per_label[lab] = {
            "baseline_rate": p0,
            "n_per_point": mean_n,
            "mde_abs": pa["mde_abs"],
            "mde_relative_to_baseline": pa["mde_relative_to_p0"],
            "fdr_significant_points": n_sig,
            "n_points": sig["n_points"],
            "n_points_low_count": low_count,
            "detectability": detect["verdict"],
            "detectability_note": detect["note"],
        }
    return {
        "available": True,
        "n_points": len(delays),
        "mean_repeats_per_point": mean_n,
        "per_label": per_label,
        "interpretation": (
            "MDE=在该重复数下（双侧 5%/80% 功效）可检测的最小绝对率差。"
            "若真实窗口的率差小于 MDE，'扫描未见显著点'不等于'不存在窗口'——"
            "这是设计分辨率问题。本表用于区分这两种情形"
        ),
    }


def _detectability_statement(label: str, p0: float, pa: dict,
                             n_sig: int, low_count: int) -> dict:
    mde = pa.get("mde_abs")
    if mde is None:
        return {"verdict": "unknown", "note": "MDE 不可计算"}
    if low_count >= pa.get("n_points", 0) if pa.get("n_points") else False:
        return {"verdict": "low_count_unreliable",
                "note": "全部点期望计数 <5，正态近似失效；显著性结论不可用"}
    if n_sig > 0:
        return {"verdict": "window_detected",
                "note": f"{n_sig} 个点通过 FDR；该标签在当前分辨率下有可检测的结构"}
    return {
        "verdict": "no_structure_at_this_resolution",
        "note": (f"0 点通过 FDR；但本设计只能看见相对基线 "
                 f"{pa['mde_relative_to_p0']:.1%} 以上的率差。"
                 "更小的结构在此分辨率下不可见（未知，非'不存在'）"),
    }


# ---------------------------------------------------------------------------
# 第 5 节：待验证矛盾点
# ---------------------------------------------------------------------------
def _section_unknowns(ds: Dataset, cfg: AnomalyReportConfig, quality: dict,
                      command: dict, frame: dict, power: dict) -> dict:
    items: list[dict] = []

    # 5.1 来自数据质量
    if not quality.get("gate_passed"):
        for f in quality.get("gate_failures", []):
            items.append({"id": "U_quality", "kind": "data_quality",
                          "description": f, "evidence_level": "unknown",
                          "even_if": "补齐数据/配置后可解"})
    if quality.get("nonstationary_labels"):
        items.append({
            "id": "U_nonstationary",
            "kind": "data_quality",
            "description": (
                "数据存在时间漂移，物理原因未知："
                + "；".join(f"{x['label']} 过散 {x['overdispersion_ratio']:.1f}×"
                            for x in quality["nonstationary_labels"])
            ),
            "evidence_level": "unknown",
            "resolve_by": "需要带环境元信息（时间戳/温度/供电/批次）的新数据",
        })
    if quality.get("missing_fields"):
        items.append({
            "id": "U_missing_columns",
            "kind": "data_quality",
            "description": f"配置映射指向的列在数据中不存在：{quality['missing_fields']}",
            "evidence_level": "unknown",
            "resolve_by": "修正 --config 的 columns 映射",
        })

    # 5.2 来自命令面：ROM 侧未解释的码
    tax = command.get("taxonomy") or {}
    phases = command.get("phase_constraints") or {}
    if phases.get("available") and tax.get("codes"):
        declared = set()
        for c in phases.get("constraints", []):
            declared.add(c["code"])
        unexplained = [k for k in tax["codes"]
                       if k not in declared and not k.startswith("no_response")]
        if unexplained:
            items.append({
                "id": "U_codes_without_phase",
                "kind": "attribution_gap",
                "description": (
                    "以下响应码在 config 的阶段映射中无归属（ROM 侧未定位到装载点）："
                    + ", ".join(unexplained)
                ),
                "evidence_level": "unknown",
                "resolve_by": "ROM 侧继续逆向（寄存器间接码/运行时计算值），"
                              "或仿真复现对应调用点",
                "affected_rows": sum(tax["codes"][k]["count"] for k in unexplained),
            })

    # 5.3 来自帧格式
    cmp_ = (frame.get("three_way_comparison") or {}).get("sites") or {}
    for name, rec in cmp_.items():
        if rec.get("site_role") == "frame_value" and rec.get("constant_bits_match") is False:
            items.append({
                "id": f"U_frame_{name}",
                "kind": "frame_mismatch",
                "description": (f"ROM 站点 {name} 的常量位与字节流不一致："
                                f"期望 {rec.get('expected_const_bits')}，"
                                f"实际 {rec.get('actual_const_bits')}"),
                "evidence_level": "unknown",
                "resolve_by": "检查取址范围/指令边界，或该站点不是本次产出帧的构造点",
            })
    if frame.get("available") and not frame.get("rom_construction", {}).get("available", True):
        items.append({
            "id": "U_frame_no_rom",
            "kind": "frame_mismatch",
            "description": "有字节流但未提供 ROM 构造站点：帧格式只能做结构推断，"
                           "无法与静态构造式互证",
            "evidence_level": "hypothesis",
            "resolve_by": "在 config 中提供 rom_path/rom_base/rom_construction_sites",
        })

    # 5.4 来自功效
    if power.get("available"):
        undetectable = [lab for lab, d in power["per_label"].items()
                        if d["detectability"] == "no_structure_at_this_resolution"]
        if undetectable:
            items.append({
                "id": "U_power_limit",
                "kind": "statistical_power",
                "description": (
                    "以下标签在当前重复数下只对 ≥MDE 的效应敏感，"
                    "更小的结构不可见（未知，非'不存在'）：" + ", ".join(undetectable)
                ),
                "evidence_level": "unknown",
                "resolve_by": "提高每点重复数 n 或缩小扫描步长（见 "
                              "sections.statistical_power.per_label.*.mde_abs）",
            })

    # 5.5 来自 config 的已知未决项
    for ku in cfg.known_unknowns:
        items.append(dict(ku))

    return {
        "n_items": len(items),
        "items": items,
        "discipline": ("unknowns 只登记'当前证据不足以判定'的项，不登记'难做'的事；"
                       "每条须给出 resolve_by（判决方法）"),
    }


# ---------------------------------------------------------------------------
# 第 6 节：证据链
# ---------------------------------------------------------------------------
def _section_evidence(ds: Dataset, cfg: AnomalyReportConfig, input_path,
                      quality: dict, command: dict, frame: dict,
                      power: dict) -> dict:
    """每个结论 → 证据来源（数据行范围 / ROM 地址 / 仿真运行件）。"""
    src = Path(input_path)
    links: list[dict] = [{
        "conclusion_id": "data_loaded",
        "conclusion": f"载入 {len(ds.records)} 行（原始 {ds.report.n_rows_raw} 行）",
        "evidence": [{"kind": "data_file", "path": str(src),
                      "format": ds.report.format,
                      "row_range": [0, max(0, len(ds.records) - 1)]}],
        "evidence_level": "observation",
    }]
    if quality.get("time_drift"):
        links.append({
            "conclusion_id": "nonstationarity",
            "conclusion": quality.get("stationarity_verdict", ""),
            "evidence": [{"kind": "data_file", "path": str(src),
                          "row_range": [0, max(0, len(ds.records) - 1)],
                          "computation": "fi.analysis.stratify.time_drift_summary "
                                         f"(n_segments={cfg.n_time_segments})"}],
            "evidence_level": "observation",
        })
    tax = command.get("taxonomy") or {}
    if tax.get("codes"):
        links.append({
            "conclusion_id": "code_taxonomy",
            "conclusion": f"{tax.get('n_codes')} 种响应码/无响应类的频次与占比",
            "evidence": [{"kind": "data_file", "path": str(src),
                          "computation": "fi.analysis.command_surface.code_taxonomy"}],
            "evidence_level": "observation",
        })
    phases = command.get("phase_constraints") or {}
    if phases.get("available"):
        per_phase: dict[str, list] = {}
        for c in phases.get("constraints", []):
            per_phase.setdefault(c.get("phase") or "unknown", []).append(c["code"])
        links.append({
            "conclusion_id": "code_to_phase_mapping",
            "conclusion": "响应码 ↔ 功能阶段映射（阶段语义 hypothesis，"
                          "码↔handler 对应 fact 级由 ROM 静态指令支撑）",
            "evidence": [{"kind": "config", "path": "code_phase_map",
                          "by_phase": per_phase},
                         {"kind": "note",
                          "text": "ROM 侧指令地址见各 constraint 的 handler 字段"}],
            "evidence_level": "hypothesis",
        })
    if frame.get("available"):
        ev = [{"kind": "byte_stream",
               "meta": ds.byte_stream_meta,
               "payload_hex": frame.get("payload_hex")}]
        for name, der in (frame.get("rom_construction") or {}).items():
            if isinstance(der, dict) and der.get("offset"):
                ev.append({"kind": "rom_range", "path": cfg.rom_path,
                           "base": hex(cfg.rom_base) if cfg.rom_base else None,
                           "offset": der["offset"], "site": name,
                           "derived_expr": der.get("frame_expr")})
        links.append({
            "conclusion_id": "frame_format",
            "conclusion": (f"帧长 {frame.get('frame_len_used')}，"
                           f"布局 {list((frame.get('field_layout') or {}).get('windows') or [])[:1]}"),
            "evidence": ev,
            "evidence_level": "observation",
        })
    if power.get("available"):
        links.append({
            "conclusion_id": "statistical_power",
            "conclusion": "各标签的 MDE 与可检测性声明",
            "evidence": [{"kind": "data_file", "path": str(src),
                          "computation": "fi.analysis.stratify.power_analysis"}],
            "evidence_level": "observation",
        })
    for el in cfg.evidence_links:
        links.append(dict(el))
    return {
        "n_links": len(links),
        "links": links,
        "discipline": "每条结论必须可回溯到具体数据文件/行范围、ROM 地址区间或仿真运行件",
    }


# ---------------------------------------------------------------------------
# findings 汇总（含既有报告结论，保证"不丢结论"）
# ---------------------------------------------------------------------------
def _collect_findings(ds: Dataset, cfg: AnomalyReportConfig, quality: dict,
                      command: dict, frame: dict, power: dict) -> list[dict]:
    out: list[dict] = []

    def add(fid, kind, desc, level, refs, source="this_run"):
        out.append({"finding_id": fid, "kind": kind, "description": desc,
                    "evidence_level": level, "supporting_refs": refs,
                    "source": source})

    # 数据质量
    if quality.get("nonstationary_labels"):
        add("F-quality-1", "nonstationarity",
            quality.get("stationarity_verdict", ""), "observation",
            ["sections.quality_and_stationarity.time_drift"])
    else:
        add("F-quality-1", "stationarity",
            quality.get("stationarity_verdict", ""), "observation",
            ["sections.quality_and_stationarity.time_drift"])

    # 命令面
    tax = command.get("taxonomy") or {}
    if tax.get("codes"):
        top = sorted(tax["codes"].items(), key=lambda kv: -kv[1]["count"])[:5]
        add("F-command-1", "code_composition",
            "响应码构成（前 5）：" + "，".join(
                f"{k}={v['count']}({v['rate']:.6f})" for k, v in top),
            "observation", ["sections.command_surface.taxonomy"])
    phases = command.get("phase_constraints") or {}
    if phases.get("available"):
        obs = [c for c in phases.get("constraints", []) if c["csv_verdict"] == "observed"]
        miss = [c for c in phases.get("constraints", [])
                if c["csv_verdict"] == "not_observed_in_csv"]
        add("F-command-2", "code_phase_alignment",
            f"码↔阶段映射：{len(obs)} 个码在数据中有观测，"
            f"{len(miss)} 个码在数据中零观测"
            + (f"（零观测：{', '.join(c['code'] for c in miss[:8])}）" if miss else ""),
            "observation", ["sections.command_surface.phase_constraints"])
    cond = (command.get("conditional_composition_by_delay") or {})
    if cond.get("homogeneity_per_code"):
        homo = cond["homogeneity_per_code"]
        m = len(homo)
        raw_sig = [k for k, v in homo.items()
                   if v.get("p_approx") is not None and v["p_approx"] < 0.05]
        # 多重比较校正（Bonferroni）：13 个码同时检验，单个 p<0.05 不足以下"异质"结论
        bonf = 0.05 / m if m else None
        surviving = [k for k in raw_sig
                     if homo[k]["p_approx"] is not None and homo[k]["p_approx"] < bonf]
        if surviving:
            verdict = ("delay 轴上存在码构成异质（Bonferroni 校正后仍显著）："
                       + ", ".join(surviving))
            level = "observation"
        elif raw_sig:
            verdict = ("delay 轴上有 %d 个码的齐性 p<0.05（%s），但 %d 个码同时检验的 "
                       "Bonferroni 阈值=%.4f 下**无一存活** → 不足以判定存在阶段结构"
                       % (len(raw_sig), ", ".join(raw_sig), m, bonf))
            level = "observation"
        else:
            verdict = ("delay 轴上各码构成齐性（无任何码 p<0.05）——"
                       "该轴未跨越功能阶段边界")
            level = "observation"
        add("F-command-3", "delay_axis_stage_structure", verdict, level,
            ["sections.command_surface.conditional_composition_by_delay"])
    profiles = command.get("delay_axis_profiles") or {}
    if profiles:
        confounded = [k for k, v in profiles.items() if v.get("time_confounding") == "material"]
        add("F-command-4", "detrended_delay_effect",
            "去趋势后的 delay 轴效应："
            + "，".join(f"{k} ρ={v['detrended_spearman']:+.3f}"
                        for k, v in list(profiles.items())[:4])
            + (f"；时间混杂显著需谨慎：{confounded}" if confounded else "；无时间混杂"),
            "observation", ["sections.command_surface.delay_axis_profiles"])

    # 帧
    if frame.get("available"):
        cmp_ = (frame.get("three_way_comparison") or {}).get("sites") or {}
        matched = [k for k, v in cmp_.items() if v.get("constant_bits_match")]
        add("F-frame-1", "frame_parse",
            f"字节流 {frame.get('payload_len')} 字节，帧长 {frame.get('frame_len_used')}"
            f"（{'推导' if frame.get('frame_len_derived') else '配置指定'}）"
            + (f"；ROM 构造式常量位匹配站点：{matched}" if matched else ""),
            "observation", ["sections.frame_format"])

    # 功效
    if power.get("available"):
        items = power["per_label"]
        add("F-power-1", "statistical_power",
            f"每点重复 n≈{power['mean_repeats_per_point']}；"
            + "；".join(
                f"{lab} MDE={d['mde_abs']}（相对 {d['mde_relative_to_baseline']:.1%}），"
                f"{d['detectability']}"
                for lab, d in list(items.items())[:4]),
            "observation", ["sections.statistical_power"])

    # 既有结论（不丢结论）
    for pf in cfg.prior_findings:
        rec = dict(pf)
        rec.setdefault("source", "prior_report")
        rec.setdefault("supporting_refs", [])
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Markdown 渲染
# ---------------------------------------------------------------------------
def render_markdown(report: dict) -> str:
    """把报告渲染为人类可读 Markdown（六节固定骨架）。"""
    sec = report.get("sections", {})
    q = sec.get("quality_and_stationarity", {})
    cmd = sec.get("command_surface", {})
    frm = sec.get("frame_format", {})
    pwr = sec.get("statistical_power", {})
    unk = sec.get("unknowns", {})
    evi = sec.get("evidence_chain", {})
    inp = report.get("inputs", {})
    lr = report.get("load_report", {})

    L: list[str] = []
    L.append("# 异常分析综合报告")
    L.append("")
    L.append(f"- 生成：{report.get('generated_utc', 'unknown')}")
    L.append(f"- 输入：`{inp.get('path')}`（格式 `{inp.get('format')}`，"
             f"{inp.get('n_rows')} 行）")
    L.append(f"- 机读版：同名 `.json`（schema `{report.get('schema')}`）")
    L.append("- 生成器：`fi.analysis.anomaly_report`（骨架固定，换数据集零改代码）")
    L.append("")
    L.append("> 阅读顺序：**先看第 1 节**。第 1 节的数据质量/非平稳性判定门控了后续所有结论的"
             "可信度——数据非平稳时，任何未去趋势的跨行比较都不得作为机制证据。")
    L.append("")

    # ---- 结论摘要
    L.append("## 0. 结论摘要")
    L.append("")
    findings = report.get("findings", [])
    if findings:
        L.append("| ID | 类别 | 结论 | 证据级 | 来源 |")
        L.append("| --- | --- | --- | --- | --- |")
        for f in findings:
            desc = str(f.get("description", "")).replace("|", "\\|")
            if len(desc) > 220:
                desc = desc[:220] + "…"
            L.append(f"| `{f.get('finding_id')}` | {f.get('kind')} | {desc} | "
                     f"**{f.get('evidence_level')}** | {f.get('source', '')} |")
    else:
        L.append("（本次未产出结论）")
    L.append("")

    # ---- 1 质量与非平稳
    L.append("## 1. 数据质量与非平稳性（强制前置）")
    L.append("")
    L.append(f"- 载入行数：{lr.get('n_rows_loaded', 0)} / 原始 {lr.get('n_rows_raw', 0)}")
    L.append(f"- 跳过行：{lr.get('skipped', 0)}"
             + (f"（原因：{lr.get('skip_reasons')}）" if lr.get("skip_reasons") else ""))
    L.append(f"- 检测到的列：{lr.get('detected_columns')}")
    if lr.get("missing_fields"):
        L.append(f"- **配置映射指向但数据缺失的列**：{lr['missing_fields']}")
    L.append(f"- 状态标签（行数降序）：{q.get('labels')}")
    L.append("")
    L.append(f"### 1.1 平稳性判定")
    L.append("")
    nv = q.get("nonstationarity_verdict", {})
    crit = nv.get("criteria", {})
    L.append(f"**判定结果：`{nv.get('designation', 'unknown')}`**（"
             f"非平稳标签 {len(nv.get('flagged_labels') or [])} 个，"
             f"轻微漂移 {len(nv.get('mild_labels') or [])} 个）")
    L.append("")
    L.append(f"判定规则：{crit.get('rule')}；"
             f"α={crit.get('alpha')}，K 个标签的 Bonferroni 阈值="
             f"{crit.get('bonferroni_threshold')}，"
             f"效应量下限={crit.get('min_total_change_pp')}pp 或相对 "
             f"{crit.get('min_relative_change')}")
    L.append("")
    L.append(f"**{q.get('stationarity_verdict', 'unknown')}**")
    L.append("")
    td = q.get("time_drift", {}).get("per_label", {})
    if td:
        L.append("| 标签 | 首段率 | 末段率 | 总变化(pp) | 趋势 r | 过散比 | χ² p | 裁定 |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for lab, d in td.items():
            homo = d.get("homogeneity_chi2") or {}
            p = homo.get("p_approx")
            p_s = "n/a" if p is None else (f"{p:.3g}" if p < 1e-3 else f"{p:.4f}")
            verdict = (nv.get("per_label") or {}).get(lab, {}).get("verdict", "-")
            L.append(f"| {lab} | {d['rate_first_segment']:.6f} | "
                     f"{d['rate_last_segment']:.6f} | "
                     f"{d.get('segment_total_change_pp', 0):+.2f} | "
                     f"{d['trend_monotonic_pearson_r']:+.3f} | "
                     f"{d['overdispersion_ratio']} | {p_s} | {verdict} |")
        L.append("")
    mild = q.get("mild_drift_labels") or []
    if mild:
        L.append("**轻微漂移标签**（未达非平稳双条件，但不应忽略）：")
        for m in mild:
            r = m.get("reason", {})
            L.append(f"- {m['label']}：χ² p={r.get('chi2_p')}，"
                     f"总变化 {r.get('total_change_pp')}pp，"
                     f"相对变化 {r.get('relative_change')}，"
                     f"显著={r.get('statistically_significant')}，"
                     f"效应量足够={r.get('effect_large_enough')}")
        L.append("")
    ta = q.get("time_axis_assumption", {})
    L.append(f"**时间轴假设**（{ta.get('evidence_level')}）：{ta.get('claim')}。"
             f"{ta.get('note', '')}")
    L.append("")
    L.append(f"**后续节的门控策略**：`{q.get('post_gate_policy')}`"
             + ("（跨行比较一律去趋势）" if q.get("post_gate_policy") == "detrend_required" else ""))
    L.append("")

    # ---- 2 命令面
    L.append("## 2. 命令面归因")
    L.append("")
    if not cmd.get("available"):
        L.append(f"不可用：{cmd.get('reason')}")
        L.append("")
    else:
        L.append(f"- 主扫描 pulse：`{cmd.get('main_pulse')}`"
                 f"（{'推导' if cmd.get('main_pulse_derived') else '配置指定'}）")
        L.append(f"- 背景状态（行数最多）：`{cmd.get('background_state')}`")
        if cmd.get("baseline_states_used"):
            L.append(f"- 条件构成基线标签：{cmd['baseline_states_used']}")
        L.append("")
        tax = cmd.get("taxonomy", {})
        L.append("### 2.1 响应码频次表")
        L.append("")
        L.append("| 码/无响应 | 行数 | 占比 | 出现标签 | Wilson 95% |")
        L.append("| --- | --- | --- | --- | --- |")
        for k, v in sorted((tax.get("codes") or {}).items(), key=lambda kv: -kv[1]["count"]):
            w = v.get("share_wilson95")
            L.append(f"| `{k}` | {v['count']} | {v['rate']:.6f} | "
                     f"{v['states']} | {w} |")
        L.append("")
        fam = cmd.get("families", {})
        if fam.get("available"):
            L.append("### 2.2 码族（来自 config 的 ROM 侧划分）")
            L.append("")
            L.append("| 码族 | 码 | 行数 | 占比 |")
            L.append("| --- | --- | --- | --- |")
            for name, d in fam.get("families", {}).items():
                L.append(f"| {name} | {d['codes']} | {d['count']} | {d['rate']:.6f} |")
            L.append("")
        ph = cmd.get("phase_constraints", {})
        if ph.get("available"):
            L.append("### 2.3 码 ↔ 功能阶段映射")
            L.append("")
            L.append("| 码 | 阶段（hypothesis） | ROM handler（fact 级地址） | "
                     "数据频次 | 交叉判定 |")
            L.append("| --- | --- | --- | --- | --- |")
            for c in ph.get("constraints", []):
                L.append(f"| `{c['code']}` | {c.get('phase')} | {c.get('handler')} | "
                         f"{c.get('csv_count')} | {c.get('csv_verdict')} |")
            L.append("")
            bph = ph.get("by_phase", {})
            if bph:
                L.append("按阶段汇总：" + "；".join(
                    f"{p}: {d['total_count']} 行" for p, d in bph.items()))
                L.append("")
        cc = cmd.get("conditional_composition_by_delay", {})
        if cc.get("homogeneity_per_code"):
            L.append("### 2.4 delay 轴上是否存在阶段结构")
            L.append("")
            L.append("| 码 | χ² | dof | p | 合并占比 |")
            L.append("| --- | --- | --- | --- | --- |")
            for k, v in cc["homogeneity_per_code"].items():
                L.append(f"| `{k}` | {v['chi2']} | {v['dof']} | {v['p_approx']} | "
                         f"{v['pooled_share']} |")
            L.append("")
            L.append(f"判读：{cc.get('interpretation')}")
            L.append("")
        pr = cmd.get("delay_axis_profiles", {})
        if pr:
            L.append("### 2.5 去趋势后的参数轴效应")
            L.append("")
            L.append("| 标签 | 原始 ρ | 去趋势 ρ | 时间混杂 | 真实效应 SD (pp) |")
            L.append("| --- | --- | --- | --- | --- |")
            for lab, d in pr.items():
                L.append(f"| {lab} | {d['raw_spearman']:+.3f} | "
                         f"{d['detrended_spearman']:+.3f} | {d['time_confounding']} | "
                         f"{d['true_effect_std'] * 100:.3f} |")
            L.append("")
        ps = cmd.get("pointwise_significance", {})
        if ps:
            L.append("### 2.6 逐点显著性（FDR q=0.05，小计数改用精确泊松）")
            L.append("")
            L.append("| 标签 | 合并率 | 显著点/总点 | 低计数点数 | 警示 |")
            L.append("| --- | --- | --- | --- | --- |")
            for lab, d in ps.items():
                L.append(f"| {lab} | {d['pooled_rate']:.6f} | "
                         f"{d['fdr']['n_significant']}/{d['n_points']} | "
                         f"{d['fdr']['n_points_low_count']} | "
                         f"{d.get('low_count_warning') or '-'} |")
            L.append("")

    # ---- 3 帧
    L.append("## 3. 帧格式解析")
    L.append("")
    if not frm.get("available"):
        L.append(f"不可用：{frm.get('reason')}")
        L.append("")
    else:
        L.append(f"- 字节流：{frm.get('payload_len')} 字节 = `{frm.get('payload_hex')}`")
        L.append(f"- 帧长：`{frm.get('frame_len_used')}`"
                 f"（{'推导' if frm.get('frame_len_derived') else '配置指定'}）")
        b = frm.get("frame_boundaries", {})
        L.append(f"- 帧边界分析：尾随零 {b.get('trailing_zeros')} 个；"
                 f"剥零后整除候选帧长 {b.get('plausible_frame_lengths_after_zero_strip')}")
        lay = frm.get("field_layout", {})
        wins = lay.get("windows") or []
        if wins:
            L.append("")
            L.append("| 窗口起点 | 字节 | u16 小端 | u16 大端 | u32 小端 |")
            L.append("| --- | --- | --- | --- | --- |")
            for w in wins:
                L.append(f"| {w['start']} | `{w['bytes_hex']}` | "
                         f"{w['u16_le_by_offset']} | {w['u16_be_by_offset']} | "
                         f"{w['u32_le']} |")
            L.append("")
        cmp_ = (frm.get("three_way_comparison") or {}).get("sites", {})
        if cmp_:
            L.append("### 3.1 三方比对（字节流 vs ROM 算术）")
            L.append("")
            L.append("| 站点 | 角色 | 符号式 | 常量位匹配 | 变量反解 |")
            L.append("| --- | --- | --- | --- | --- |")
            for name, rec in cmp_.items():
                L.append(f"| {name} | {rec.get('site_role')} | "
                         f"`{rec.get('symbolic_expr')}` | "
                         f"{rec.get('constant_bits_match')} | "
                         f"{rec.get('solved_variables')} |")
            L.append("")
        else:
            L.append(f"- ROM 构造式：{frm.get('rom_construction', {}).get('reason')}")
            L.append("")

    # ---- 4 功效
    L.append("## 4. 统计功效与可检测性声明")
    L.append("")
    if not pwr.get("available"):
        L.append(f"不可用：{pwr.get('reason')}")
        L.append("")
    else:
        L.append(f"每点平均重复数 n = **{pwr.get('mean_repeats_per_point')}**，"
                 f"共 {pwr.get('n_points')} 个参数点。")
        L.append("")
        L.append("| 标签 | 基线率 | MDE（绝对） | MDE 相对 | 显著点 | 可检测性判定 |")
        L.append("| --- | --- | --- | --- | --- | --- |")
        for lab, d in pwr["per_label"].items():
            L.append(f"| {lab} | {d['baseline_rate']:.6f} | {d['mde_abs']} | "
                     f"{d['mde_relative_to_baseline']:.1%} | "
                     f"{d['fdr_significant_points']}/{d['n_points']} | "
                     f"**{d['detectability']}** |")
        L.append("")
        L.append(f"> {pwr.get('interpretation')}")
        L.append("")
        for lab, d in pwr["per_label"].items():
            L.append(f"- **{lab}**：{d['detectability_note']}")
        L.append("")

    # ---- 5 unknowns
    L.append("## 5. 待验证矛盾点（unknowns）")
    L.append("")
    items = unk.get("items", [])
    if not items:
        L.append("（本次数据未留下未决项）")
        L.append("")
    else:
        L.append(f"共 {len(items)} 条。")
        L.append("")
        L.append("| ID | 类别 | 描述 | 证据级 | 判决方法 |")
        L.append("| --- | --- | --- | --- | --- |")
        for it in items:
            desc = str(it.get("description", "")).replace("|", "\\|")
            if len(desc) > 200:
                desc = desc[:200] + "…"
            L.append(f"| `{it.get('id')}` | {it.get('kind')} | {desc} | "
                     f"{it.get('evidence_level')} | {it.get('resolve_by') or it.get('even_if') or '-'} |")
        L.append("")
        L.append(f"> {unk.get('discipline')}")
        L.append("")

    # ---- 6 evidence
    L.append("## 6. 证据链")
    L.append("")
    links = evi.get("links", [])
    for lk in links:
        L.append(f"### `{lk.get('conclusion_id')}`")
        L.append("")
        L.append(f"- 结论：{lk.get('conclusion')}")
        L.append(f"- 证据级：**{lk.get('evidence_level')}**")
        for e in lk.get("evidence", []):
            parts = [f"{k}={v}" for k, v in e.items() if v is not None]
            L.append(f"  - {', '.join(parts)}")
        L.append("")
    L.append(f"> {evi.get('discipline')}")
    L.append("")

    # ---- 复现
    L.append("## 7. 复现")
    L.append("")
    L.append("```")
    L.append(f"python -m fi.analysis.run_anomaly --input <数据文件> "
             f"--config <配置.json> --out-prefix <输出前缀>")
    L.append("```")
    L.append("")
    L.append("报告骨架与六节结构固定；换数据集只需换 `--input` 与 `--config`"
             "（列名/标签/码域/码族/阶段映射全部经 config 传入，通用代码零实例值）。")
    L.append("")
    return "\n".join(L)
