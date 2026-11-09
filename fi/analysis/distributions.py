# -*- coding: utf-8 -*-
"""全量分布事实：状态计数、错误码、直方、逐点率值、分段对比、行序诊断。

统计口径（观测统计，不涉及因果解释）：
- 率值 = 该状态行数 / 该参数点总注入数；
- Wilson 95% 区间（z=1.96）；
- 逐点与整体率比较用 z 分数（正态近似，n≈12k/点）；
- 齐性卡方跨逐点 × 状态矩阵（稀疏标签按 share 阈值剔除）；p 值用
  Wilson–Hilferty 近似（运行环境无 scipy，输出中标注 ``approx``）。

审计纪律（2026-11-09 通用性门禁）：
- 状态标签集合/目标标签/背景码/主 pulse/分段点一律**参数化或从数据推导**，
  代码路径零数据集字面量；推导结果在输出中标注 ``*_derived``。
"""

from __future__ import annotations

from math import erfc, sqrt

import numpy as np
import pandas as pd

from fi.analysis.schema import COL_RESPONSE, COL_STATE, COL_UNEXPECTED, NS_PER_STEP_ASSUMED

#: 类型化整型列名（parser.clean_typed 产出；raw 列为字符串，勿直接数值比较）
D = "delay_i"
P = "pulse_i"

Z95 = 1.959963984540054


def observed_labels(df: pd.DataFrame) -> list[str]:
    """数据中实际出现的状态标签（按行数降序；观测推导，无字面量）。"""
    return [str(k) for k in df[COL_STATE].value_counts().index]


# ---------------------------------------------------------------------------
# 基础表
# ---------------------------------------------------------------------------
def state_counts(df: pd.DataFrame, known_labels=None) -> dict:
    """状态计数与占比。``known_labels``（可选枚举）由调用方传入时才做枚举外检查。"""
    vc = df[COL_STATE].value_counts()
    total = int(vc.sum())
    out = {
        "total_rows": total,
        "states": {
            str(k): {"count": int(v), "share": round(float(v) / total, 8)}
            for k, v in vc.items()
        },
    }
    if known_labels:
        out["labels_not_in_enum"] = sorted(set(vc.index) - set(known_labels))
    return out


def error_code_tables(df: pd.DataFrame) -> dict:
    """response / unexpected 两列频次、冗余性校验、状态 × 码交叉表。"""
    out = {}
    for col in (COL_RESPONSE, COL_UNEXPECTED):
        vc = df[col].fillna("<empty>").value_counts()
        out[col] = {str(k): int(v) for k, v in vc.items()}
        out[f"{col}_top"] = {
            str(k): int(v) for k, v in vc.head(20).items()
        }

    both = df[df[COL_RESPONSE].notna() & df[COL_UNEXPECTED].notna()]
    equal = int((both[COL_RESPONSE] == both[COL_UNEXPECTED]).sum())
    out["coupling_check"] = {
        "rows_with_both_nonempty": int(len(both)),
        "rows_equal": equal,
        "equality_rate": round(equal / len(both), 6) if len(both) else None,
        "interpretation": "两列非空时逐字符相等 → 视为冗余列（假设 A4）",
    }

    # 状态 × code_class 交叉（观测分类，语义 unknown）
    cross = (
        df.groupby([COL_STATE, "code_class"], observed=True)
        .size()
        .unstack(fill_value=0)
    )
    out["state_by_code_class"] = {
        str(state): {str(c): int(v) for c, v in row.items() if v > 0}
        for state, row in cross.iterrows()
    }

    # UNEXPECTED 行为之外：对每个状态给内部码分布（键含原始标签，观测推导）
    out["code_counts_by_state"] = {
        str(state): {
            str(k): int(v)
            for k, v in sub["unexpected_norm"].fillna("<null>").value_counts().items()
        }
        for state, sub in df.groupby(COL_STATE, observed=True)
    }
    return out


def delay_pulse_histograms(df: pd.DataFrame) -> dict:
    """delay / pulse 边际直方（各状态），含原始轴与 ns 轴（假设 A1）。"""
    out = {"delay_axis_ns_assumed": {
        "note": (f"ns = raw * {NS_PER_STEP_ASSUMED:g}（假设 A1，未证实）"),
        "min_raw": int(df[D].min()),
        "max_raw": int(df[D].max()),
    }}
    for state in sorted(df[COL_STATE].unique()):
        sub = df[df[COL_STATE] == state]
        out.setdefault("delay_counts_by_state", {})[str(state)] = {
            str(int(k)): int(v) for k, v in sub[D].value_counts().sort_index().items()
        }
        out.setdefault("pulse_counts_by_state", {})[str(state)] = {
            str(int(k)): int(v) for k, v in sub[P].value_counts().sort_index().items()
        }
    return out


def grid_occupancy(df: pd.DataFrame) -> dict:
    """(delay,pulse) 单元占用：cell × 状态计数（含 ns 坐标，假设 A1）。"""
    g = (
        df.groupby([D, P, COL_STATE], observed=True)
        .size().unstack(fill_value=0)
    )
    cells = []
    for (d, p), row in g.iterrows():
        by_state = {str(s): int(v) for s, v in row.items() if v > 0}
        cells.append({
            "delay_raw": int(d),
            "pulse_raw": int(p),
            "delay_ns": round(int(d) * NS_PER_STEP_ASSUMED, 6),
            "pulse_ns": round(int(p) * NS_PER_STEP_ASSUMED, 6),
            "n": int(row.sum()),
            "by_state": by_state,
        })
    cells.sort(key=lambda c: (c["pulse_raw"], c["delay_raw"]))
    return {
        "cell_definition": "raw 步长为 1 的 (delay,pulse) 单元；ns 轴按假设 A1",
        "n_cells": len(cells),
        "cells": cells,
    }


# ---------------------------------------------------------------------------
# 统计工具
# ---------------------------------------------------------------------------
def wilson_interval(k: int, n: int, z: float = Z95) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    center = p + z * z / (2 * n)
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((center - half) / denom, 6), round((center + half) / denom, 6)]


def chi2_sf_approx(chi2: float, dof: int) -> float:
    """Wilson–Hilferty 近似卡方生存函数（无 scipy 环境的替代，标注 approx）。"""
    if dof <= 0:
        return float("nan")
    q = ((chi2 / dof) ** (1.0 / 3.0) - (1 - 2.0 / (9.0 * dof))) / sqrt(2.0 / (9.0 * dof))
    return 0.5 * erfc(q / sqrt(2.0))


def spearman(x, y) -> float:
    rx = pd.Series(x).rank().to_numpy(dtype=float)
    ry = pd.Series(y).rank().to_numpy(dtype=float)
    return float(np.corrcoef(rx, ry)[0, 1])


# ---------------------------------------------------------------------------
# 逐点率值（核心表）
# ---------------------------------------------------------------------------
def pointwise_rates(
    df: pd.DataFrame,
    main_pulse: int | None = None,
    background_code: str | None = None,
    target_label: str | None = None,
    min_chi2_state_share: float = 0.001,
) -> dict:
    """主扫描 pulse 上的逐 delay 点率值表 + 齐性检验 + 趋势 + pulse 概览。

    审计纪律（均无样例默认值；None → 从数据观测推导并标注 ``*_derived``）：
    - ``main_pulse``：行数最多的 pulse 值；
    - ``background_code``：主扫描中占比最高的 0x 前缀响应码
      （``non_fl_code_counts`` 字段名保留兼容 UI，语义=排除背景码后的错误码构成）；
    - ``target_label``：评分/区间目标标签（如来自调用方配置）；未提供时不出
      ``target_wilson95``（评分字段），只给各标签率值与 z；
    - 齐性卡方只纳入占比 ≥ ``min_chi2_state_share``（默认 0.001）的标签
      （极稀疏标签失真，剔除规则记录在输出）。
    """
    main_pulse_derived = main_pulse is None
    if main_pulse is None:
        pulse_rows = df.groupby(P).size()
        if pulse_rows.empty:
            raise ValueError("输入无 pulse 数据")
        main_pulse = int(pulse_rows.idxmax())
    main = df[df[P] == main_pulse]

    background_derived = background_code is None
    if background_code is None:
        code_vc = main.loc[
            main["code_class"].astype("string").str.startswith("0x", na=False),
            "code_class",
        ]
        background_code = str(code_vc.value_counts().idxmax()) if len(code_vc) else "unknown"

    labels = observed_labels(main)
    ct = (
        main.groupby([D, COL_STATE], observed=True)
        .size().unstack(fill_value=0)
        .reindex(columns=labels, fill_value=0)
        .sort_index()
    )

    n_pts = ct.sum(axis=1).to_numpy()
    p_overall = {s: float(ct[s].sum()) / n_pts.sum() for s in labels}

    points = []
    z_per_label: dict[str, list] = {s: [] for s in labels}
    for i, (d, row) in enumerate(ct.iterrows()):
        n = int(n_pts[i])
        entry = {
            "delay_raw": int(d),
            "delay_ns_assumed": round(int(d) * NS_PER_STEP_ASSUMED, 6),
            "pulse_raw": int(main_pulse),
            "n": n,
        }
        for s in labels:
            k = int(row[s])
            entry[f"{s}_count"] = k
            entry[f"{s}_rate"] = round(k / n, 8)
        if target_label is not None and target_label in labels:
            entry["target_label"] = target_label
            entry["target_wilson95"] = wilson_interval(
                int(row[target_label]), n
            )
        for s in labels:
            se = sqrt(p_overall[s] * (1 - p_overall[s]) / n) if n else None
            z = (row[s] / n - p_overall[s]) / se if se else None
            entry[f"{s}_z_vs_overall"] = round(float(z), 3) if z is not None else None
            z_per_label[s].append(z)
        # 该点排除背景码后的错误码构成（观测分类；字段名保留 non_fl 兼容）
        sub = main[main[D] == d]
        codes = sub.loc[sub["code_class"] != background_code, "code_class"].value_counts()
        entry["non_fl_code_counts"] = {str(k): int(v) for k, v in codes.items()}
        points.append(entry)

    # 齐性卡方（逐点 × 标签；剔除占比过小的稀疏标签）
    chi2_labels = [s for s in labels if p_overall[s] >= min_chi2_state_share]
    excluded = [s for s in labels if s not in chi2_labels]
    obs = ct[chi2_labels].to_numpy(dtype=float)
    row_tot = obs.sum(axis=1, keepdims=True)
    col_tot = obs.sum(axis=0, keepdims=True)
    exp = row_tot @ col_tot / row_tot.sum()
    chi2 = float(((obs - exp) ** 2 / exp).sum())
    dof = (obs.shape[0] - 1) * (obs.shape[1] - 1)

    z_arr = {s: np.array([v if v is not None else 0.0 for v in zs])
             for s, zs in z_per_label.items()}

    trends = {
        s: round(spearman(ct.index.to_numpy(dtype=float), ct[s].to_numpy() / n_pts), 4)
        for s in labels
    }

    # pulse 维概览（供评分/UI：pulse 维几乎未扫描的事实一眼可见）
    by_pulse = {}
    for pv, sub in df.groupby(P, observed=True):
        counts = sub[COL_STATE].value_counts()
        by_pulse[str(int(pv))] = {
            "rows": int(len(sub)),
            "n_points": int(sub.groupby([D, P], observed=True).ngroups),
            "delay_raw_range": [int(sub[D].min()), int(sub[D].max())],
            "state_rates": {str(k): round(float(v) / len(sub), 8)
                            for k, v in counts.items()},
        }

    return {
        "scope": f"pulse_raw == {main_pulse} 的全部行",
        "main_pulse": int(main_pulse),
        "main_pulse_derived": main_pulse_derived,
        "background_code": background_code,
        "background_code_derived": background_derived,
        "labels": labels,
        "target_label": target_label,
        "n_points": len(points),
        "overall_rates": {k: round(v, 8) for k, v in p_overall.items()},
        "points": points,
        "by_pulse": by_pulse,
        "homogeneity_chi2": {
            "chi2": round(chi2, 2),
            "dof": dof,
            "p_approx": round(chi2_sf_approx(chi2, dof), 6),
            "labels_included": chi2_labels,
            "labels_excluded_sparse": excluded,
            "min_state_share": min_chi2_state_share,
            "method": "Pearson chi-square; p 值为 Wilson–Hilferty 近似（运行环境无 scipy）",
        },
        "z_extremes_per_label": {
            s: {
                "min_z": round(float(z_arr[s].min()), 3),
                "max_z": round(float(z_arr[s].max()), 3),
                "points_abs_z_gt2": int((np.abs(z_arr[s]) > 2).sum()),
                "points_abs_z_gt3": int((np.abs(z_arr[s]) > 3).sum()),
            }
            for s in labels
        },
        "expected_abs_z_gt2_under_null": round(len(points) * 0.0455003, 1),  # 2*P(|Z|>2)≈0.0455/点
        "rate_vs_delay_spearman": trends,
    }


# ---------------------------------------------------------------------------
# 分段对比（分割点由调用方/数据推导显式传入；审计：无样例默认值）
# ---------------------------------------------------------------------------
def segment_compare(df: pd.DataFrame, split_low_max: int) -> dict:
    low = df[df[D] <= split_low_max]
    high = df[df[D] > split_low_max]

    def summarize(seg: pd.DataFrame) -> dict:
        cells = (
            seg.groupby([D, P], observed=True).size()
        )
        return {
            "rows": int(len(seg)),
            "by_state": {str(k): int(v) for k, v in seg[COL_STATE].value_counts().items()},
            "delay_raw_range": [int(seg[D].min()), int(seg[D].max())] if len(seg) else None,
            "pulse_values": sorted(int(v) for v in seg[P].unique()),
            "n_cells": int(len(cells)),
            "n_per_cell_min": int(cells.min()) if len(cells) else None,
            "n_per_cell_median": float(cells.median()) if len(cells) else None,
            "n_per_cell_max": int(cells.max()) if len(cells) else None,
        }

    return {
        "split_rule": f"delay_raw <= {split_low_max} → 低段；>= {split_low_max + 1} → 高段",
        "split_source": "caller-provided (audit: no sample defaults)",
        "segment_low": summarize(low),
        "segment_high": summarize(high),
        "gap_observation": {
            "note": "低段是否为独立扫描窗口需结合实验协议确认（unknown）",
        },
    }


# ---------------------------------------------------------------------------
# 行序诊断（扫描协议线索）
# ---------------------------------------------------------------------------
def run_order_diagnostics(df: pd.DataFrame, main_pulse: int | None = None) -> dict:
    """行序诊断。``main_pulse`` 无默认值；None 时按行数最多的 pulse 推导（标注）。"""
    derived = main_pulse is None
    if main_pulse is None:
        pulse_rows = df.groupby(P).size()
        if pulse_rows.empty:
            raise ValueError("输入无 pulse 数据")
        main_pulse = int(pulse_rows.idxmax())
    main = df[df[P] == main_pulse]
    ds = main[D].to_numpy(dtype=float)
    d0 = ds - ds.mean()
    ac1 = float((d0[:-1] * d0[1:]).sum() / (d0 * d0).sum()) if (d0 * d0).sum() else None

    counts = main.groupby(D).size().to_numpy(dtype=float)
    exp_n = counts.mean()
    chi2_n = float(((counts - exp_n) ** 2 / exp_n).sum())

    return {
        "scope": f"pulse_raw == {main_pulse}",
        "main_pulse_derived": derived,
        "n_rows_in_scope": int(len(ds)),
        "lag1_autocorr_of_delay_row_order": round(ac1, 6) if ac1 is not None else None,
        "per_point_n_uniformity": {
            "chi2": round(chi2_n, 1),
            "dof": int(len(counts) - 1),
            "p_approx": round(chi2_sf_approx(chi2_n, int(len(counts) - 1)), 4),
            "n_min": int(counts.min()),
            "n_median": float(np.median(counts)),
            "n_max": int(counts.max()),
        },
        "interpretation_input_only": "自相关≈0 且 n 均匀 → 行序接近随机化采样（观测，供协议推断用）",
    }
