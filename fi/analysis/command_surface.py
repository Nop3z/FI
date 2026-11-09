# -*- coding: utf-8 -*-
"""ISP 命令面反推（CSV 侧）：错误码 ↔ 功能阶段的观测约束。

任务（lead 2026-11-09 P0）：
从历史实验 CSV 观测反推 ISP 命令面结构——每个错误码可能的"功能阶段"归属，
以及 delay/pulse 维是否携带"命令阶段"信息。产出供 chip-profile 的 ROM 侧
调用链逆向做交叉（对得上则升 confidence，对不上即矛盾点）。

方法论要点（与旧报告的差异，重要）
--------------------------------
1. **单码模型**：每次注入只产生一个响应码。因此"某码出现 N 次"= 该码出口在
   注入窗口内被击中的次数，不是"该错误有多常见"。频率 ∝ 该出口对应代码路径
   在注入窗口时间轴上的**时间权重**（均匀注入假设下）。
2. **先分层、再下结论**：CSV 行序含强非平稳漂移（见 ``stratify`` 模块）。
   任何跨码/跨参数点比较必须先扣除时间轴，否则会把漂移误读成机制差异。
3. **阶段假设可证伪**：若某码归属"函数 X 的校验分支"，则它应与"函数 X 的
   其他出口码"在时间权重上相关（同路径），而与别的阶段码不相关；且不应有
   delay 轴上的强结构（除非该阶段本身在 delay 窗口内被扫过边界）。

审计纪律：本模块不含任何芯片实例值——码表/标签/命令表全部由调用方传入。
"""

from __future__ import annotations

import collections
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from fi.analysis.stratify import (
    chi2_wh,
    detrended_delay_profile,
    pointwise_significance,
    power_analysis,
    time_drift_summary,
    wilson_interval,
)

__all__ = [
    "load_typed_jsonl",
    "code_taxonomy",
    "conditional_composition",
    "family_profiles",
    "phase_constraints",
    "run_command_surface",
    "TYPED_FIELDS",
]

#: 分析层规范 JSONL 的必需字段（parser.to_jsonl 产出）
TYPED_FIELDS = ("state", "delay_raw", "pulse_raw", "code_class")


def code_key_of(rec: dict) -> str:
    """取记录的"响应码分类键"。

    兼容两种记录形态：
    - 本包 typed JSONL / run_analysis 产出：字段名 ``code_class``；
    - ``fi.analysis.dataset`` 归一化产出：字段名 ``code_key``（无响应为 None）。

    无响应统一返回 ``"no_response"``（观测分类，不含语义）。
    """
    v = rec.get("code_class", rec.get("code_key"))
    return "no_response" if v in (None, "") else str(v)


def load_typed_jsonl(path: str | Path) -> list[dict]:
    """读取 typed JSONL（一行一实验）。只保留分析所需字段以降内存。"""
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            out.append({k: rec.get(k) for k in TYPED_FIELDS})
    return out


# ---------------------------------------------------------------------------
# 1) 码表（taxonomy）
# ---------------------------------------------------------------------------
def code_taxonomy(rows: Sequence[dict], background_state: str | None = None) -> dict:
    """每个响应码/token 的观测画像。

    返回 ``codes{key: {...}}``：计数、占比、出现的状态标签、delay 范围、
    Wilson 区间、以及"是否为背景"（= 行数最多的状态，观测推导）。
    key 为 ``code_class``（响应值原样；无响应为 ``no_response``）。
    """
    n = len(rows)
    state_counts = collections.Counter(r["state"] for r in rows)
    labels_by_count = [s for s, _ in state_counts.most_common()]
    bg_state = background_state or (labels_by_count[0] if labels_by_count else None)

    by_code: dict[str, dict] = {}
    for r in rows:
        key = code_key_of(r)
        d = by_code.setdefault(key, {
            "count": 0, "states": collections.Counter(),
            "delay_min": None, "delay_max": None,
            "delay_sum": 0, "pulses": collections.Counter(),
        })
        d["count"] += 1
        d["states"][r["state"]] += 1
        dv = r["delay_raw"]
        if dv is not None:
            d["delay_min"] = dv if d["delay_min"] is None else min(d["delay_min"], dv)
            d["delay_max"] = dv if d["delay_max"] is None else max(d["delay_max"], dv)
            d["delay_sum"] += dv
        d["pulses"][r["pulse_raw"]] += 1

    codes = {}
    for key, d in by_code.items():
        states = dict(d["states"])
        codes[key] = {
            "count": d["count"],
            "rate": round(d["count"] / n, 8) if n else None,
            "share_wilson95": wilson_interval(d["count"], n),
            "states": states,
            "is_background": (bg_state in states
                              and d["count"] == max(d["states"].values()) * 1.0
                              and bool(bg_state)),
            "delay_raw_min": d["delay_min"],
            "delay_raw_max": d["delay_max"],
            "delay_raw_mean": round(d["delay_sum"] / d["count"], 2) if d["count"] else None,
            "pulse_values": {str(k): v for k, v in sorted(
                d["pulses"].items(), key=lambda kv: (kv[0] is None, kv[0]))},
        }
    return {
        "n_rows": n,
        "background_state": bg_state,
        "n_codes": len(codes),
        "codes": codes,
    }


# ---------------------------------------------------------------------------
# 2) 条件构成（"给定故障产生了非基线响应，各码如何分摊"）
# ---------------------------------------------------------------------------
def conditional_composition(rows: Sequence[dict], axis: str = "delay_raw",
                            baseline_states: Sequence[str] = (),
                            n_bins: int | None = None) -> dict:
    """沿参数轴分箱，看"非基线响应"内部的码构成是否随轴变化。

    ``baseline_states``：视为"基线/无信息"的状态标签（由调用方从观测推导，
    例如行数最多者）。其余行的码构成即"故障有效事件"的画面。

    若无轴结构（构成不随轴变），说明该轴未跨越功能阶段边界——这是"轴敏感性"
    的直接检验，比"总率平坦"更细。
    """
    baseline = set(baseline_states)
    bins: dict = collections.defaultdict(lambda: collections.Counter())
    bin_n: dict = collections.Counter()
    for r in rows:
        a = r[axis]
        if a is None:
            continue
        bin_n[a] += 1
        if r["state"] in baseline:
            continue
        bins[a][code_key_of(r)] += 1

    keys = sorted(bins)
    if n_bins and len(keys) > n_bins:
        # 等宽合并
        step = max(1, len(keys) // n_bins)
        merged: dict = collections.defaultdict(lambda: collections.Counter())
        merged_n: dict = collections.Counter()
        for i, k in enumerate(keys):
            g = keys[(i // step) * step] if (i // step) * step < len(keys) else keys[-1]
            merged[g].update(bins[k])
            merged_n[g] += bin_n[k]
        keys = sorted(merged)
        bins = merged
        bin_n = merged_n

    all_codes = sorted({c for k in keys for c in bins[k]})
    table = []
    for k in keys:
        tot = sum(bins[k].values())
        table.append({
            "axis_value": k,
            "n_rows": bin_n[k],
            "n_non_baseline": tot,
            "non_baseline_rate": round(tot / bin_n[k], 8) if bin_n[k] else None,
            "composition": {c: round(bins[k].get(c, 0) / tot, 6) if tot else None
                            for c in all_codes},
        })

    # 构成是否随轴齐性（对每个码做 2×K 卡方：该码 vs 其他，按箱）
    homogeneity = {}
    for c in all_codes:
        obs = []
        for k in keys:
            tot = sum(bins[k].values())
            if tot == 0:
                continue
            obs.append((bins[k].get(c, 0), tot))
        if len(obs) < 2:
            continue
        total_k = sum(o[0] for o in obs)
        total_n = sum(o[1] for o in obs)
        p0 = total_k / total_n if total_n else 0.0
        if not (0 < p0 < 1):
            continue
        chi = 0.0
        for k_, n_ in obs:
            e = n_ * p0
            v = n_ * p0 * (1 - p0)
            if v > 0:
                chi += (k_ - e) ** 2 / v
        dof = len(obs) - 1
        homogeneity[c] = {
            "chi2": round(chi, 2), "dof": dof,
            "p_approx": round(chi2_wh(chi, dof), 6),
            "pooled_share": round(p0, 6),
            "n_bins": len(obs),
        }
    return {
        "axis": axis,
        "baseline_states": list(baseline_states),
        "n_bins": len(keys),
        "table": table,
        "homogeneity_per_code": homogeneity,
        "multiple_comparison": _multiple_comparison(homogeneity),
        "interpretation": (
            "homogeneity_per_code 的 p 显著 ⇒ 该码占比随轴变化 ⇒ 轴跨越了功能阶段；"
            "全部不显著 ⇒ 轴在该范围内不携带阶段信息。**注意多重比较**："
            "同时检验 K 个码时，单个 p<0.05 的期望假阳数为 0.05K——"
            "必须以 multiple_comparison.bonferroni_threshold 判定，"
            "单个 p<0.05 不足以支撑'存在阶段结构'"
        ),
    }


def _multiple_comparison(homogeneity: dict) -> dict:
    """对 K 个码的齐性检验做多重比较校正（Bonferroni + BH-FDR）。"""
    tests = [(k, v["p_approx"]) for k, v in homogeneity.items()
             if v.get("p_approx") is not None]
    m = len(tests)
    if m == 0:
        return {"n_tests": 0, "bonferroni_threshold": None,
                "survivors_bonferroni": [], "survivors_bh_fdr": [],
                "expected_false_positives_at_0.05": None}
    bonf = 0.05 / m
    survivors_bonf = [k for k, p in tests if p < bonf]
    # Benjamini–Hochberg (q=0.05)
    ordered = sorted(tests, key=lambda t: t[1])
    n_sig = 0
    for rank, (_k, p) in enumerate(ordered, start=1):
        if p <= 0.05 * rank / m:
            n_sig = rank
    survivors_bh = [k for k, _p in ordered[:n_sig]]
    return {
        "n_tests": m,
        "bonferroni_threshold": round(bonf, 6),
        "survivors_bonferroni": survivors_bonf,
        "survivors_bh_fdr": survivors_bh,
        "expected_false_positives_at_0.05": round(0.05 * m, 2),
        "verdict": (
            "存在阶段结构（校正后仍有码显著）" if survivors_bonf else
            "不足判定存在阶段结构（校正后无码显著；单点 p<0.05 属多重比较预期范围）"
        ),
    }


# ---------------------------------------------------------------------------
# 3) 码族画像（按 ROM 侧命令表分组，交叉用）
# ---------------------------------------------------------------------------
def family_profiles(rows: Sequence[dict], families: dict[str, list[str]],
                    axis: str = "delay_raw") -> dict:
    """按调用方给定的"码族"（如按 ROM handler 簇分组）逐族画像。

    ``families``：{族名: [code_class, ...]}。族划分来自 ROM 侧逆向结论，
    本函数只做 CSV 侧的量化，不判断族划分是否正确。
    """
    n = len(rows)
    out = {}
    for fam, codes in families.items():
        code_set = set(codes)
        sub = [r for r in rows if code_key_of(r) in code_set]
        states = collections.Counter(r["state"] for r in sub)
        out[fam] = {
            "codes": list(codes),
            "count": len(sub),
            "rate": round(len(sub) / n, 8) if n else None,
            "share_wilson95": wilson_interval(len(sub), n),
            "states": dict(states),
            "delay_raw_min": min((r[axis] for r in sub if r[axis] is not None), default=None),
            "delay_raw_max": max((r[axis] for r in sub if r[axis] is not None), default=None),
        }
    return {"n_rows": n, "families": out}


# ---------------------------------------------------------------------------
# 4) 阶段约束（给 ROM 侧的对账口径）
# ---------------------------------------------------------------------------
def phase_constraints(rows: Sequence[dict], code_phase_map: dict[str, dict],
                      n_phases: int | None = None) -> dict:
    """把 ROM 侧的"码 → 功能阶段"映射转成 CSV 侧可检验的约束清单。

    ``code_phase_map``：{code_class: {"phase": str, "handler": str,
    "evidence": "fact|hypothesis", "conditions": [...]}}（由 ROM 侧逆向提供）。

    输出每条约束的 CSV 侧状态：观测频次、是否与观测矛盾、需要什么数据才能判决。
    """
    tax = code_taxonomy(rows)
    constraints = []
    for code, info in code_phase_map.items():
        obs = tax["codes"].get(code)
        phase = info.get("phase")
        constraints.append({
            "code": code,
            "phase": phase,
            "handler": info.get("handler"),
            "rom_evidence": info.get("evidence"),
            "csv_count": (obs or {}).get("count", 0),
            "csv_rate": (obs or {}).get("rate"),
            "csv_states": (obs or {}).get("states"),
            "csv_verdict": ("observed" if obs and obs.get("count") else "not_observed_in_csv"),
            "note": info.get("note", ""),
        })
    by_phase: dict[str, dict] = collections.defaultdict(
        lambda: {"codes": [], "total_count": 0})
    for c in constraints:
        p = c["phase"] or "unknown"
        by_phase[p]["codes"].append(c["code"])
        by_phase[p]["total_count"] += c["csv_count"] or 0
    n = tax["n_rows"]
    for p, d in by_phase.items():
        d["total_rate"] = round(d["total_count"] / n, 8) if n else None
    return {
        "n_phases_declared": len(by_phase),
        "constraints": constraints,
        "by_phase": {
            p: {**d, "codes": d["codes"]} for p, d in by_phase.items()
        },
        "interpretation": (
            "'csv_count=0' 的分支有两种解释：(a) 实验窗口从未进入该分支"
            "（时间权重极小）；(b) ROM 侧阶段归属错误。二者只能用仿真/新实验区分，"
            "不能凭 CSV 单方面判定。"
        ),
    }


# ---------------------------------------------------------------------------
# 5) 一键产出
# ---------------------------------------------------------------------------
def run_command_surface(typed_jsonl: str | Path,
                        families: dict[str, list[str]] | None = None,
                        code_phase_map: dict[str, dict] | None = None,
                        baseline_states: Sequence[str] | None = None,
                        n_time_segments: int = 20) -> dict:
    """完整分析：码表 + 时间漂移 + 去趋势 delay 画像 + 条件构成 + 阶段约束。"""
    rows = load_typed_jsonl(typed_jsonl)
    n = len(rows)

    pulse_counts = collections.Counter(r["pulse_raw"] for r in rows)
    main_pulse = pulse_counts.most_common(1)[0][0] if pulse_counts else None
    main_rows = [r for r in rows if r["pulse_raw"] == main_pulse]

    states = [r["state"] for r in rows]
    labels = [s for s, _ in collections.Counter(states).most_common()]
    drift = time_drift_summary(states, labels=labels, n_segments=n_time_segments)

    bg_state = labels[0] if labels else None
    if baseline_states is None:
        baseline_states = [bg_state] if bg_state else []

    axis = [r["delay_raw"] for r in main_rows]
    ridx = list(range(len(main_rows)))
    main_states = [r["state"] for r in main_rows]
    profiles = {}
    for lab in labels:
        if lab not in set(main_states):
            continue
        p = detrended_delay_profile(axis, main_states, lab, row_index=ridx,
                                    n_time_segments=max(2, n_time_segments * 10),
                                    axis_name="delay_raw")
        profiles[lab] = p.to_dict()

    # 逐点显著性（对主扫描的每个标签）
    by_point = collections.defaultdict(collections.Counter)
    for r in main_rows:
        by_point[r["delay_raw"]][r["state"]] += 1
    delays = sorted(by_point)
    sig = {}
    for lab in labels:
        counts = [by_point[d][lab] for d in delays]
        ns = [sum(by_point[d].values()) for d in delays]
        sig[lab] = pointwise_significance(counts, ns)

    # 功效（每点平均重复数）
    mean_n = int(sum(sum(by_point[d].values()) for d in delays) / len(delays)) if delays else 0
    power = {lab: power_analysis(sig[lab]["pooled_rate"], mean_n) for lab in labels
             if sig[lab]["pooled_rate"] not in (None, 0.0, 1.0)}

    result = {
        "schema": "fi.analysis.isp-command-surface-v1",
        "inputs": {"typed_jsonl": str(typed_jsonl), "n_rows": n,
                   "main_pulse": main_pulse, "n_delay_points": len(delays)},
        "taxonomy": code_taxonomy(rows, background_state=bg_state),
        "time_drift": drift.to_dict(),
        "delay_axis_profiles": profiles,
        "pointwise_significance": {
            lab: {"n_points": v["n_points"], "pooled_rate": v["pooled_rate"],
                  "fdr": v["fdr"]} for lab, v in sig.items()
        },
        "power_analysis": power,
        "conditional_composition_by_delay": conditional_composition(
            main_rows, axis="delay_raw", baseline_states=baseline_states),
        "families": family_profiles(rows, families) if families else "unknown",
        "phase_constraints": (phase_constraints(rows, code_phase_map)
                              if code_phase_map else "unknown"),
        "evidence_level": "observation",
        "discipline": (
            "全部数字为观测级统计；阶段归属/机制解释一律 hypothesis；"
            "行序=采集时序为假设（见 time_drift.row_order_assumption）"
        ),
    }
    return result
