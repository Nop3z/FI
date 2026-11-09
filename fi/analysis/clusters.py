# -*- coding: utf-8 -*-
"""聚集结构：网格密度、连通域聚类、状态间相对位置。

方法说明（无 sklearn 环境，纯 numpy/pandas 实现）：
- 密度：以 raw 步长为 1 的 (delay,pulse) 单元计数矩阵；密度 = 单元计数 / 单元容量
  （本数据 pulse 维度退化，单元容量 = 该单元重复注入数 n，故密度即该单元内状态占比）。
- 聚类：对"占用单元"（计数 > 0）做 4 邻接连通域搜索（BFS），输出簇的边界盒、
  质心、峰值单元。该聚类反映"哪些参数点被该状态命中过"，不反映率值高低；
  率值层面的显著高点单独用 z 分数标出（见 distributions.pointwise_rates）。
- 相对位置：各状态逐点率值曲线之间的 Spearman 秩相关 + 显著点交集。

审计纪律：状态标签集合从数据/pointwise 输入推导（``observed_labels`` 或
``*_z_vs_overall`` 键名解析），代码路径零数据集字面量。
"""

from __future__ import annotations

import re
from collections import deque

import numpy as np
import pandas as pd

from fi.analysis.distributions import spearman
from fi.analysis.schema import COL_DELAY, COL_PULSE, COL_STATE

_Z_KEY_RE = re.compile(r"^(\S+)_z_vs_overall$")


def observed_labels(df: pd.DataFrame) -> list[str]:
    return [str(k) for k in df[COL_STATE].value_counts().index]


def labels_of_pointwise(pointwise: dict) -> list[str]:
    """从 pointwise rates 的键名解析标签集合（观测推导）。"""
    pts = pointwise.get("points") or []
    if not pts:
        return []
    out = []
    for k in pts[0]:
        m = _Z_KEY_RE.match(k)
        if m:
            out.append(m.group(1))
    return sorted(out)


def occupancy_cells(df: pd.DataFrame, state: str) -> dict[tuple[int, int], int]:
    """某状态的 (delay,pulse) → 计数 单元字典。"""
    sub = df[df[COL_STATE] == state]
    g = sub.groupby([COL_DELAY, COL_PULSE], observed=True).size()
    return {(int(d), int(p)): int(c) for (d, p), c in g.items()}


def connected_components(cells: dict[tuple[int, int], int]) -> list[dict]:
    """4 邻接连通域（BFS）。cells: {(delay_raw,pulse_raw): count}。"""
    seen: set[tuple[int, int]] = set()
    clusters = []
    for start in sorted(cells):
        if start in seen:
            continue
        comp = []
        q = deque([start])
        seen.add(start)
        while q:
            cur = q.popleft()
            comp.append(cur)
            d, p = cur
            for nb in ((d - 1, p), (d + 1, p), (d, p - 1), (d, p + 1)):
                if nb in cells and nb not in seen:
                    seen.add(nb)
                    q.append(nb)
        ds = [c[0] for c in comp]
        ps = [c[1] for c in comp]
        peak = max(comp, key=lambda c: cells[c])
        clusters.append({
            "size_cells": len(comp),
            "total_count": int(sum(cells[c] for c in comp)),
            "bbox_delay_raw": [min(ds), max(ds)],
            "bbox_pulse_raw": [min(ps), max(ps)],
            "centroid_raw": [round(float(np.mean(ds)), 2), round(float(np.mean(ps)), 2)],
            "peak_cell": {"delay_raw": peak[0], "pulse_raw": peak[1],
                          "count": cells[peak]},
        })
    clusters.sort(key=lambda c: -c["total_count"])
    for i, c in enumerate(clusters):
        c["cluster_id"] = i
    return clusters


def cluster_state(df: pd.DataFrame, state: str) -> dict:
    cells = occupancy_cells(df, state)
    clusters = connected_components(cells)
    total = sum(cells.values())
    return {
        "state": state,
        "occupied_cells": len(cells),
        "total_count": total,
        "density_in_cells": round(total / len(cells), 2) if cells else None,
        "n_clusters": len(clusters),
        "clusters": clusters,
    }


def significant_points(pointwise: dict, label: str,
                       z_threshold: float = 2.0) -> list[dict]:
    """从 pointwise_rates 输出中抽取某标签 |z|>阈值的参数点（含方向）。"""
    key = f"{label}_z_vs_overall"
    count_key = f"{label}_count"
    rate_key = f"{label}_rate"
    out = []
    for p in pointwise["points"]:
        z = p.get(key)
        if z is not None and abs(z) > z_threshold:
            out.append({
                "delay_raw": p["delay_raw"],
                "delay_ns_assumed": p["delay_ns_assumed"],
                "z": z,
                "direction": "above_overall" if z > 0 else "below_overall",
                "label": label,
                "count": p.get(count_key),
                "n": p["n"],
                "rate": p.get(rate_key),
            })
    return out


def relative_position(pointwise: dict) -> dict:
    """状态率值曲线的 Spearman 相关矩阵与显著点重叠（观测统计）。"""
    pts = pointwise["points"]
    labels = labels_of_pointwise(pointwise)
    curves = {
        s: np.array([p[f"{s}_rate"] for p in pts], dtype=float)
        for s in labels
    }
    delays = np.array([p["delay_raw"] for p in pts], dtype=float)

    corr = {}
    for i, a in enumerate(labels):
        for b in labels[i + 1:]:
            corr[f"{a}_vs_{b}"] = round(spearman(curves[a], curves[b]), 4)
    vs_delay = {s: round(spearman(delays, curves[s]), 4) for s in labels}

    # 显著点（|z|>2）集合与交集
    def sig_set(s):
        key = f"{s}_z_vs_overall"
        return {p["delay_raw"] for p in pts
                if p.get(key) is not None and abs(p[key]) > 2.0}

    sig = {s: sorted(sig_set(s)) for s in labels}
    overlaps = {}
    for i, a in enumerate(labels):
        for b in labels[i + 1:]:
            inter = sorted(set(sig[a]) & set(sig[b]))
            if inter:
                overlaps[f"{a}_∩_{b}"] = inter
    return {
        "labels": labels,
        "spearman_rate_curves": corr,
        "spearman_rate_vs_delay": vs_delay,
        "significant_points_absz_gt2": sig,
        "significant_overlaps": overlaps,
        "note": "秩相关反映单调趋势；|z|>2 交集衡量高点是否共位。全部为观测统计。",
    }


def cluster_summary(df: pd.DataFrame, pointwise: dict) -> dict:
    labels = observed_labels(df)
    out = {"method": "4 邻接连通域 + 单元计数密度；ns 轴按假设 A1",
           "labels": labels,
           "per_state": {},
           "relative_position": relative_position(pointwise)}
    for s in labels:
        out["per_state"][s] = cluster_state(df, s)
    # 显著点单独列出（率值层面，全标签）
    out["significant_points"] = {
        s: significant_points(pointwise, s) for s in labels
    }
    return out
