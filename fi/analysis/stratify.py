# -*- coding: utf-8 -*-
"""分层统计工具：把「运行时间漂移」与「参数轴效应」严格分开。

问题背景（2026-11-09，exp-analysis）：
74 万行量的实验 CSV 逐行回放时，**行序不是无关的**——同一数据文件内部存在
强非平稳漂移（对 <DATE> 样例：首个十分位 FL 率 91.6%，末个十分位 83.6%，
趋势 χ² ≈ 3500, p≈1e-205）。任何"某状态率随 delay 变化"的结论，若不先扣除
这条时间轴，都可能把时间趋势误读成参数效应（或反之）。

本模块提供**芯片无关、标签无关**的方法（全部量由调用方传入，无实例默认值）：

- ``time_drift_summary``：按行序分段估计各标签率，给出漂移幅度、单调性、
  过散比（段间方差 / 二项噪声方差）——判断"数据是否非平稳"。
- ``detrended_delay_profile``：用**分段哑变量 logistic** 吸收任意形状的时间
  漂移，取残差按参数点聚合，得到"扣掉时间后"的参数轴效应；输出原始与去趋势
  的逐点序列、Spearman、真实 SD（扣除二项噪声）、以及去检测量。
- ``pointwise_significance``：逐点率 vs 合并率的二项 z + Wilson 区间 +
  Benjamini–Hochberg FDR 校正（回答"有没有哪个参数点真的不同"）。
- ``power_analysis``：给定每点重复数 n 与基线率 p，算出可检测的最小率差
  （2σ/MDE）——回答"这个扫描设计能看见多大的窗口"。
- ``chi2_wh`` / ``wilson``：无 scipy 环境下的卡方 p 值与 Wilson 区间。

纪律：
- 所有函数的参数轴/标签/重复数均由调用方显式传入；本模块不含任何芯片实例值。
- 时间轴默认取**行序**（数据源给出的记录顺序），这是一个**假设**：
  行序=采集时序。若数据源打乱过行序，结论退化为 unknown——调用方须在
  输出中标注该假设（``row_order_is_acquisition_order``）。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable, Sequence

__all__ = [
    "TimeDriftReport",
    "DetrendedProfile",
    "time_drift_summary",
    "nonstationarity_verdict",
    "detrended_delay_profile",
    "pointwise_significance",
    "power_analysis",
    "wilson_interval",
    "chi2_wh",
    "logistic_fit",
]

Z95 = 1.959963984540054

#: 显式假设标记（输出中透传，供 UI/报告标注）
ROW_ORDER_ASSUMPTION = {
    "claim": "记录行序 = 采集时序（时间轴）",
    "evidence_level": "hypothesis",
    "note": "数据源未提供时间戳时，行序是唯一可用的时序代理；若采集端曾打乱行序，"
            "本模块的时间漂移结论退化为 unknown",
}


# ---------------------------------------------------------------------------
# 基础统计
# ---------------------------------------------------------------------------
def wilson_interval(k: float, n: float, z: float = Z95) -> list[float] | None:
    """Wilson 得分区间（比例）。n=0 → None。"""
    if n <= 0:
        return None
    p = k / n
    denom = 1.0 + z * z / n
    center = p + z * z / (2.0 * n)
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n))
    return [round((center - half) / denom, 6), round((center + half) / denom, 6)]


def chi2_wh(chi2: float, dof: int) -> float:
    """Wilson–Hilferty 近似的卡方生存函数（运行环境无 scipy）。"""
    if dof <= 0:
        return float("nan")
    q = ((chi2 / dof) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * dof))) / math.sqrt(2.0 / (9.0 * dof))
    return 0.5 * math.erfc(q / math.sqrt(2.0))


def _rank(values: Sequence[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def spearman(x: Sequence[float], y: Sequence[float]) -> float:
    if len(x) < 2:
        return 0.0
    rx, ry = _rank(list(x)), _rank(list(y))
    mx = sum(rx) / len(rx)
    my = sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else 0.0


def logistic_fit(X: list[list[float]], y: Sequence[float],
                 max_iter: int = 150, tol: float = 1e-10):
    """纯 Python IRLS logistic 回归。返回 (beta, fitted_p, se)。

    ``X`` 为行列表（第一列建议常数 1）；``y`` ∈ {0,1}。奇异时 se 为 nan。
    """
    n_par = len(X[0])
    beta = [0.0] * n_par
    fitted = [0.0] * len(y)
    for _ in range(max_iter):
        # p = sigmoid(X beta)
        p = []
        for row in X:
            eta = sum(b * x for b, x in zip(beta, row))
            eta = max(-35.0, min(35.0, eta))
            p.append(1.0 / (1.0 + math.exp(-eta)))
        fitted = p
        # 梯度与 Hessian
        grad = [0.0] * n_par
        hess = [[0.0] * n_par for _ in range(n_par)]
        for row, yi, pi in zip(X, y, p):
            w = max(pi * (1.0 - pi), 1e-12)
            r = yi - pi
            for a in range(n_par):
                grad[a] += row[a] * r
                wr = row[a] * w
                for b in range(n_par):
                    hess[a][b] += wr * row[b]
        step = _solve(hess, grad)
        if step is None:
            break
        beta = [b + s for b, s in zip(beta, step)]
        if max(abs(s) for s in step) < tol:
            break
    # 最终 SE
    p = []
    for row in X:
        eta = sum(b * x for b, x in zip(beta, row))
        eta = max(-35.0, min(35.0, eta))
        p.append(1.0 / (1.0 + math.exp(-eta)))
    hess = [[0.0] * n_par for _ in range(n_par)]
    for row, pi in zip(X, p):
        w = max(pi * (1.0 - pi), 1e-12)
        for a in range(n_par):
            wr = row[a] * w
            for b in range(n_par):
                hess[a][b] += wr * row[b]
    cov = _inverse(hess)
    if cov is None:
        se = [float("nan")] * n_par
    else:
        se = [math.sqrt(cov[i][i]) if cov[i][i] > 0 else float("nan") for i in range(n_par)]
    return beta, p, se


def _solve(A: list[list[float]], b: Sequence[float]) -> list[float] | None:
    """高斯消元解 A x = b（部分主元）。奇异返回 None。"""
    n = len(A)
    M = [list(A[i]) + [b[i]] for i in range(n)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(M[r][col]))
        if abs(M[piv][col]) < 1e-12:
            return None
        M[col], M[piv] = M[piv], M[col]
        inv = 1.0 / M[col][col]
        for r in range(col + 1, n):
            f = M[r][col] * inv
            if f:
                for c in range(col, n + 1):
                    M[r][c] -= f * M[col][c]
    x = [0.0] * n
    for r in range(n - 1, -1, -1):
        s = M[r][n] - sum(M[r][c] * x[c] for c in range(r + 1, n))
        x[r] = s / M[r][r]
    return x


def _inverse(A: list[list[float]]) -> list[list[float]] | None:
    n = len(A)
    M = [list(A[i]) + [1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(M[r][col]))
        if abs(M[piv][col]) < 1e-12:
            return None
        M[col], M[piv] = M[piv], M[col]
        inv = 1.0 / M[col][col]
        M[col] = [v * inv for v in M[col]]
        for r in range(n):
            if r == col:
                continue
            f = M[r][col]
            if f:
                M[r] = [a - f * b for a, b in zip(M[r], M[col])]
    return [row[n:] for row in M]


# ---------------------------------------------------------------------------
# 1) 时间漂移摘要
# ---------------------------------------------------------------------------
@dataclass
class TimeDriftReport:
    n_rows: int
    n_segments: int
    labels: list[str]
    per_label: dict = field(default_factory=dict)
    row_order_assumption: dict = field(default_factory=lambda: dict(ROW_ORDER_ASSUMPTION))

    def to_dict(self) -> dict:
        return {
            "n_rows": self.n_rows,
            "n_segments": self.n_segments,
            "labels": self.labels,
            "per_label": self.per_label,
            "row_order_assumption": self.row_order_assumption,
        }


def _segment_homogeneity_chi2(seg_k: Sequence[float], seg_n: Sequence[int]) -> dict:
    """分段率齐性检验：H0 = 所有时间段同率。

    用二项方差构造 Pearson χ²：``Σ (k_i - n_i·p)² / (n_i·p·(1-p))``，
    dof = K-1。返回 chi2 / dof / p（Wilson–Hilferty 近似）。

    **为什么需要这个而不是只看过散比**：过散比 var/二项方差 是效应量描述，
    但"多大算非平稳"没有普适阈值。换一份数据（不同 n、不同漂移形状）时，
    固定阈值会既漏检（真漂移但比值中等）也误检（比值大但样本极小）。
    χ² 检验给出与样本量一致的显著性判定，过散比保留为效应量描述。
    """
    k = list(seg_k)
    ns = list(seg_n)
    tot_k = sum(k)
    tot_n = sum(ns)
    if tot_n <= 0 or len(k) < 2:
        return {"chi2": None, "dof": 0, "p_approx": None}
    p = tot_k / tot_n
    if not (0.0 < p < 1.0):
        return {"chi2": None, "dof": len(k) - 1, "p_approx": None}
    chi2 = 0.0
    for ki, ni in zip(k, ns):
        if ni <= 0:
            continue
        e = ni * p
        v = ni * p * (1.0 - p)
        if v > 0:
            chi2 += (ki - e) ** 2 / v
    dof = len([1 for ni in ns if ni > 0]) - 1
    if dof <= 0:
        return {"chi2": round(chi2, 2), "dof": 0, "p_approx": None}
    return {"chi2": round(chi2, 2), "dof": int(dof), "p_approx": round(chi2_wh(chi2, dof), 8)}


def time_drift_summary(states: Sequence[str], labels: Sequence[str] | None = None,
                       n_segments: int = 20) -> TimeDriftReport:
    """按行序分段，估计各标签率的漂移幅度与显著性。

    ``states``：逐行的标签序列（时间序）。``labels``：要统计的标签集合
    （缺省=出现过的全部标签，按频次降序）。

    每个标签输出两类量：
    - **显著性**：``homogeneity_chi2``（χ²/dof/p）——H0=各段同率；
    - **效应量**：``overdispersion_ratio``（段间方差/二项噪声方差）与
      ``segment_slope_total_change``（首末线性拟合总变化）。

    判定用「显著性 + 最小效应量」双条件（见 ``nonstationarity_verdict``），
    避免两个极端：只看 p 会把 74 万行下 0.1pp 的微小漂移也判为非平稳；
    只看比值会漏掉中等比值但统计极显著的漂移。
    """
    n = len(states)
    if labels is None:
        counts: dict[str, int] = {}
        for s in states:
            counts[s] = counts.get(s, 0) + 1
        labels = sorted(counts, key=lambda k: -counts[k])
    labels = list(labels)

    seg_of = [min(n_segments - 1, i * n_segments // n) for i in range(n)]
    # 单遍统计：段 × 标签 计数矩阵（O(n)，避免对每个标签重扫全量）
    seg_n = [0] * n_segments
    seg_lab = [dict() for _ in range(n_segments)]
    for i, s in enumerate(states):
        k = seg_of[i]
        seg_n[k] += 1
        d = seg_lab[k]
        d[s] = d.get(s, 0) + 1

    per_label: dict[str, dict] = {}
    for lab in labels:
        seg_rate: list[float] = []
        seg_ks: list[float] = []
        seg_ns: list[int] = []
        for k in range(n_segments):
            if seg_n[k] == 0:
                continue
            k_cnt = seg_lab[k].get(lab, 0)
            seg_rate.append(k_cnt / seg_n[k])
            seg_ks.append(k_cnt)
            seg_ns.append(seg_n[k])
        p_bar = sum(1 for s in states if s == lab) / n
        obs_var = _var(seg_rate)
        mean_n = sum(seg_ns) / len(seg_ns)
        binom_var = p_bar * (1.0 - p_bar) / mean_n
        slope = _slope(seg_rate)
        homo = _segment_homogeneity_chi2(seg_ks, seg_ns)
        total_change = slope * (len(seg_rate) - 1)
        per_label[lab] = {
            "rate_overall": round(p_bar, 8),
            "rate_first_segment": round(seg_rate[0], 8),
            "rate_last_segment": round(seg_rate[-1], 8),
            "rate_min": round(min(seg_rate), 8),
            "rate_max": round(max(seg_rate), 8),
            "segment_slope_per_segment": round(slope, 10),
            "segment_slope_total_change": round(total_change, 8),
            "segment_total_change_pp": round(total_change * 100.0, 4),
            "obs_segment_var": obs_var,
            "binomial_expected_var": binom_var,
            "overdispersion_ratio": round(obs_var / binom_var, 2) if binom_var else None,
            "trend_monotonic_pearson_r": round(_pearson(list(range(len(seg_rate))), seg_rate), 4),
            "homogeneity_chi2": homo,
        }
    return TimeDriftReport(n_rows=n, n_segments=n_segments, labels=labels,
                           per_label=per_label)


def nonstationarity_verdict(report: TimeDriftReport,
                            alpha: float = 0.05,
                            min_total_change_pp: float = 1.0,
                            min_relative_change: float = 0.05) -> dict:
    """由时间漂移报告判定"是否非平稳"，并给出每个标签的裁定理由。

    裁定规则（双条件，两项都满足才算非平稳）：
    1. **统计显著**：χ² 齐性检验的 p < ``alpha``/K（Bonferroni，K=标签数）；
    2. **效应量有实质意义**：首末线性拟合总变化 ≥ **自适应阈值**
       ``max(min_total_change_pp, p0 × min_relative_change × 100)`` 个百分点。

    **为什么效应量阈值必须自适应**（实现踩过的坑）：
    若只用固定绝对阈值（如 1pp），会漏掉小基线率标签上的大相对漂移；
    若只用固定相对阈值（如 5%），则小基线率标签会被误判——例如基线 0.6% 的
    标签漂移 0.17pp 就是 27% 相对变化，但在 74 万行规模下这仅是极小扰动，
    对任何结论都无实质影响。

    自适应阈值 = max(绝对下限, 该标签基线率 × 相对下限)：
    - 基线 87% 的标签：阈值 ≈ 4.4pp（7.6pp 的漂移够格）
    - 基线 0.6% 的标签：阈值 = 1.0pp（0.17pp 的漂移不够格）
    - 基线 9.7% 的标签：阈值 = 1.0pp（9.7pp 的漂移够格）

    这样"统计显著"保证不漏真漂移，"自适应效应量"保证不把微小扰动当结构变化。
    """
    labels = report.labels
    K = len(labels)
    thr = alpha / K if K else alpha
    flagged, mild, stable = [], [], []
    per_label = {}
    for lab in labels:
        d = report.per_label[lab]
        homo = d.get("homogeneity_chi2") or {}
        p = homo.get("p_approx")
        change_pp = abs(d.get("segment_total_change_pp") or 0.0)
        base = d.get("rate_overall") or 0.0
        rel = (change_pp / 100.0 / base) if base else 0.0
        # 自适应效应量阈值：绝对下限与基线率比例的较大者
        adaptive_pp = max(min_total_change_pp,
                          base * min_relative_change * 100.0)
        significant = (p is not None and p < thr)
        large = change_pp >= adaptive_pp
        if significant and large:
            verdict, bucket = "nonstationary", flagged
        elif significant and not large:
            verdict, bucket = "statistically_detectable_but_immaterial", mild
        elif large and not significant:
            verdict, bucket = "large_but_not_significant", mild
        else:
            verdict, bucket = "stationary", stable
        bucket.append(lab)
        per_label[lab] = {
            "verdict": verdict,
            "chi2_p": p,
            "bonferroni_threshold": round(thr, 10),
            "statistically_significant": bool(significant),
            "total_change_pp": round(change_pp, 4),
            "relative_change": round(rel, 4),
            "adaptive_threshold_pp": round(adaptive_pp, 4),
            "effect_large_enough": bool(large),
        }
    if flagged:
        desig = "nonstationary"
    elif mild:
        desig = "mild_drift"
    else:
        desig = "stationary"
    return {
        "designation": desig,
        "flagged_labels": flagged,
        "mild_labels": mild,
        "stationary_labels": stable,
        "criteria": {
            "alpha": alpha,
            "bonferroni_threshold": round(thr, 10),
            "min_total_change_pp": min_total_change_pp,
            "min_relative_change": min_relative_change,
            "rule": ("非平稳 = χ² 齐性 p < α/K（K=标签数）且 总变化 ≥ "
                     "max(min_total_change_pp, 基线率×min_relative_change) 个百分点"),
        },
        "per_label": per_label,
    }


def _var(v: Sequence[float]) -> float:
    if len(v) < 2:
        return 0.0
    m = sum(v) / len(v)
    return sum((x - m) ** 2 for x in v) / (len(v) - 1)


def _slope(v: Sequence[float]) -> float:
    n = len(v)
    if n < 2:
        return 0.0
    xs = list(range(n))
    mx, my = sum(xs) / n, sum(v) / n
    num = sum((a - mx) * (b - my) for a, b in zip(xs, v))
    den = sum((a - mx) ** 2 for a in xs)
    return num / den if den else 0.0


def _pearson(x: Sequence[float], y: Sequence[float]) -> float:
    n = len(x)
    if n < 2:
        return 0.0
    mx, my = sum(x) / n, sum(y) / n
    num = sum((a - mx) * (b - my) for a, b in zip(x, y))
    den = math.sqrt(sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y))
    return num / den if den else 0.0


# ---------------------------------------------------------------------------
# 2) 去时间趋势后的参数轴效应
# ---------------------------------------------------------------------------
@dataclass
class DetrendedProfile:
    axis_name: str
    label: str
    points: list[dict]
    raw_spearman: float
    detrended_spearman: float
    raw_std: float
    detrended_std: float
    noise_std: float
    true_std: float
    n_time_segments: int
    row_order_assumption: dict = field(default_factory=lambda: dict(ROW_ORDER_ASSUMPTION))

    def to_dict(self) -> dict:
        return {
            "axis_name": self.axis_name,
            "label": self.label,
            "n_points": len(self.points),
            "raw_spearman": round(self.raw_spearman, 4),
            "detrended_spearman": round(self.detrended_spearman, 4),
            "raw_std": self.raw_std,
            "detrended_std": self.detrended_std,
            "binomial_noise_std": self.noise_std,
            "true_effect_std": self.true_std,
            "time_confounding": ("none" if abs(self.raw_spearman - self.detrended_spearman) < 0.08
                                 else "material"),
            "n_time_segments": self.n_time_segments,
            "points": self.points,
            "row_order_assumption": self.row_order_assumption,
        }


def detrended_delay_profile(axis_values: Sequence[float], states: Sequence[str],
                            label: str, row_index: Sequence[int] | None = None,
                            n_time_segments: int = 200,
                            axis_name: str = "parameter") -> DetrendedProfile:
    """分离「行序（时间）漂移」与「参数轴（如 delay）效应」。

    做法：以**行序**为时间代理，拟合 ``P(state==label) = f(时间分段)``
    （只含时间分段哑变量、不引入参数轴）的饱和模型，取残差 ``y - p_hat``
    按参数点聚合，即"扣掉时间后的参数效应"。

    **解析解（重要实现说明）**：当模型只有一组互斥的分段哑变量（饱和模型）时，
    每个分段的 MLE 就是该分段内的观测率 ``k_seg / n_seg``——无需迭代求解
    （logistic 迭代在此是恒等变换，白费 O(n·K²)）。因此本函数对 74 万行
    规模的耗时是 O(n)，与分段数无关。这也是本实现不使用 ``logistic_fit`` 的原因。

    返回每点的：n、原始率、去趋势残差（加回整体率便于阅读）、Wilson 区间。
    """
    n = len(states)
    if row_index is None:
        row_index = list(range(n))
    y = [1.0 if s == label else 0.0 for s in states]

    seg = [min(n_time_segments - 1, row_index[i] * n_time_segments // n) for i in range(n)]

    # 饱和分段模型的解析 MLE：段内观测率
    seg_k = [0.0] * n_time_segments
    seg_n = [0] * n_time_segments
    for i in range(n):
        seg_k[seg[i]] += y[i]
        seg_n[seg[i]] += 1
    # 空分段的 p_hat 退回全局率（不影响残差，因为该段无样本）
    overall_early = sum(y) / n if n else 0.0
    seg_p = [(seg_k[k] / seg_n[k]) if seg_n[k] else overall_early
             for k in range(n_time_segments)]

    p_hat = [seg_p[seg[i]] for i in range(n)]
    resid = [y[i] - p_hat[i] for i in range(n)]
    overall = sum(y) / n

    by_point: dict[float, dict] = {}
    for i in range(n):
        a = axis_values[i]
        d = by_point.setdefault(a, {"n": 0, "k": 0.0, "resid": 0.0})
        d["n"] += 1
        d["k"] += y[i]
        d["resid"] += resid[i]

    points = []
    for a in sorted(by_point):
        d = by_point[a]
        n_pt = d["n"]
        rate = d["k"] / n_pt
        det = d["resid"] / n_pt + overall
        points.append({
            "axis_value": a,
            "n": n_pt,
            "count": int(d["k"]),
            "rate": round(rate, 8),
            "detrended_rate": round(det, 8),
            "detrended_delta_pp": round((det - overall) * 100.0, 4),
            "wilson95": wilson_interval(d["k"], n_pt),
        })

    xs = [pt["axis_value"] for pt in points]
    raw_rates = [pt["rate"] for pt in points]
    det_rates = [pt["detrended_rate"] for pt in points]
    noise_var = sum(overall * (1 - overall) / pt["n"] for pt in points) / len(points)
    obs_var = _var(raw_rates)
    true_var = max(obs_var - noise_var, 0.0)
    return DetrendedProfile(
        axis_name=axis_name,
        label=label,
        points=points,
        raw_spearman=spearman(xs, raw_rates),
        detrended_spearman=spearman(xs, det_rates),
        raw_std=math.sqrt(obs_var) if obs_var > 0 else 0.0,
        detrended_std=math.sqrt(_var(det_rates)),
        noise_std=math.sqrt(noise_var),
        true_std=math.sqrt(true_var),
        n_time_segments=n_time_segments,
    )


# ---------------------------------------------------------------------------
# 3) 逐点显著性（含 FDR 校正）
# ---------------------------------------------------------------------------
def pointwise_significance(counts: Sequence[int], ns: Sequence[int],
                           labels: Sequence[str] | None = None,
                           min_expected_count: float = 5.0) -> dict:
    """逐点率 vs 合并率的二项 z 检验 + BH-FDR 校正。

    ``counts``/``ns``：每个参数点的目标事件数与总重复数（等长）。
    返回每点 z / 双侧 p / Wilson 区间，以及 FDR 校正后的显著点数
    （回答"扫描范围内是否存在真的不同的参数点"）。

    **小计数保护（重要）**：当某点的期望事件数 ``n_i * p0 < min_expected_count``
    时，正态近似失效（会给出虚假的"显著"），此时改用**精确泊松**双侧 p：
    ``P = 2 * min(P(X>=k), P(X<=k))``，且该点标记 ``method="poisson_exact"``。
    这类极稀疏标签的 FDR 结论不可按字面读——输出 ``low_count_warning`` 提示。
    """
    total_k = sum(counts)
    total_n = sum(ns)
    p0 = total_k / total_n if total_n else 0.0
    items = []
    n_exact = 0
    for i, (k, n) in enumerate(zip(counts, ns)):
        if n <= 0:
            items.append({"index": i, "n": n, "count": k, "rate": None,
                          "z": None, "p_two_sided": None, "wilson95": None,
                          "method": "not_applicable"})
            continue
        rate = k / n
        expected = n * p0
        use_exact = expected < min_expected_count
        if use_exact:
            n_exact += 1
            p_val = _poisson_two_sided(k, expected)
            z = None
            method = "poisson_exact"
        else:
            se = math.sqrt(p0 * (1 - p0) / n) if 0 < p0 < 1 else 0.0
            z = (rate - p0) / se if se else 0.0
            p_val = math.erfc(abs(z) / math.sqrt(2.0))
            method = "normal_approx"
        items.append({
            "index": i, "n": n, "count": k, "rate": round(rate, 8),
            "expected_rate": round(p0, 8),
            "expected_count": round(expected, 4),
            "z": round(z, 4) if z is not None else None,
            "p_two_sided": p_val,
            "wilson95": wilson_interval(k, n),
            "method": method,
        })
    # Benjamini–Hochberg
    valid = [(i, it["p_two_sided"]) for i, it in enumerate(items)
             if it["p_two_sided"] is not None]
    valid.sort(key=lambda t: t[1])
    m = len(valid)
    q = 0.05
    n_sig = 0
    for rank, (i, p_val) in enumerate(valid, start=1):
        if p_val <= q * rank / m:
            n_sig = rank
    for idx, (i, _p) in enumerate(valid, start=1):
        items[i]["bh_rank"] = idx
        items[i]["fdr_significant"] = idx <= n_sig
    for i, it in enumerate(items):
        it.setdefault("fdr_significant", False)
    low_count_warning = None
    if n_exact:
        low_count_warning = (
            f"{n_exact}/{len(items)} 个点的期望事件数 < {min_expected_count:g}，"
            "已改用精确泊松 p 值；这些点（通常是最稀疏的标签）的显著性/FDR "
            "结论不稳定，不得单独作为机制证据"
        )
    return {
        "n_points": len(items),
        "pooled_rate": round(p0, 8),
        "points": items,
        "fdr": {
            "method": "Benjamini–Hochberg",
            "q": q,
            "n_points_tested": m,
            "n_significant": n_sig,
            "expected_false_positives_under_null": round(0.05 * len([1 for it in items
                                                                    if it["p_two_sided"] is not None]), 2),
            "n_points_low_count": n_exact,
        },
        "low_count_warning": low_count_warning,
        "labels": list(labels) if labels else None,
    }


def _poisson_two_sided(k: int, mu: float) -> float:
    """精确泊松双侧 p 值：2 * min(P(X>=k), P(X<=k))，截断到 1。"""
    if mu <= 0:
        return 1.0 if k == 0 else 0.0
    # P(X <= k) 与 P(X >= k)
    # 从众数附近累加，避免大 mu 下溢；k 通常很小，直接累加
    p_le = 0.0
    term = math.exp(-mu)  # P(X=0)
    for j in range(0, k + 1):
        p_le += term
        term *= mu / (j + 1)
    p_ge = 1.0 - p_le + math.exp(-mu) * 0  # P(X >= k) = 1 - P(X <= k-1)
    # 更稳：直接算 P(X>=k) = 1 - P(X<=k) + P(X=k)
    p_k = math.exp(-mu)
    for j in range(1, k + 1):
        p_k *= mu / j
    p_ge = 1.0 - p_le + p_k
    return min(1.0, 2.0 * min(max(p_le, 0.0), max(p_ge, 0.0)))


# ---------------------------------------------------------------------------
# 4) 检验功效（扫描设计能看见多大的窗口）
# ---------------------------------------------------------------------------
def power_analysis(p0: float, n_per_point: int, z_alpha: float = Z95,
                   z_power: float = 0.8416) -> dict:
    """给定基线率 p0 与每点重复数 n，给出可检测的最小率差（MDE）。

    MDE(双侧 α=0.05, power=80%) = (z_{1-α/2} + z_{power}) * sqrt(p0(1-p0)/n)。
    用途：判断"当前扫描分辨率能否看见窗口"——若真实窗口的率差小于 MDE，
    扫不出来是设计问题而非"没有窗口"。
    """
    if n_per_point <= 0 or not (0 < p0 < 1):
        return {"p0": p0, "n_per_point": n_per_point, "mde_abs": None}
    se = math.sqrt(p0 * (1 - p0) / n_per_point)
    mde = (z_alpha + z_power) * se
    return {
        "p0": round(p0, 8),
        "n_per_point": int(n_per_point),
        "se": round(se, 8),
        "mde_abs": round(mde, 8),
        "mde_relative_to_p0": round(mde / p0, 4) if p0 else None,
        "mde_ratio_high_low": round((p0 + mde) / p0, 4) if p0 else None,
        "interpretation": (
            f"每点 n={n_per_point}、基线率 {p0:.5f} 时，双侧 5%/80% 功效可检测的最小"
            f"绝对率差 ≈ {mde:.5f}（相对 {mde / p0:.1%}）；更小的窗口效应扫不出来"
        ) if p0 else None,
    }
