# -*- coding: utf-8 -*-
"""分层统计工具的自检（守恒性 + 已知答案 + 边界）。

这些测试不依赖任何芯片实例数据：用**合成数据**验证数学正确性。
"""

import math

import pytest

from fi.analysis.stratify import (
    chi2_wh,
    detrended_delay_profile,
    pointwise_significance,
    power_analysis,
    spearman,
    time_drift_summary,
    wilson_interval,
)


# ---------------------------------------------------------------- 基础函数
def test_wilson_interval_known_values() -> None:
    # 50/100 的 Wilson 95% 区间（标准答案 ≈ [0.4038, 0.5962]）
    lo, hi = wilson_interval(50, 100)
    assert abs(lo - 0.4038) < 1e-3
    assert abs(hi - 0.5962) < 1e-3
    assert wilson_interval(0, 0) is None


def test_wilson_interval_extremes() -> None:
    lo, hi = wilson_interval(0, 100)
    assert lo == 0.0 and 0 < hi < 0.05
    lo, hi = wilson_interval(100, 100)
    assert hi == 1.0 and 0.95 < lo <= 1.0


def test_chi2_sf_known_values() -> None:
    # chi2=3.841, dof=1 → p≈0.05；chi2=0 → p≈1（Wilson–Hilferty 为近似，不放精确值）
    assert abs(chi2_wh(3.841, 1) - 0.05) < 5e-3
    assert chi2_wh(0.0, 5) == pytest.approx(1.0, abs=1e-4)
    assert math.isnan(chi2_wh(1.0, 0))


def test_spearman_perfect_and_inverse() -> None:
    assert abs(spearman([1, 2, 3, 4], [2, 4, 6, 8]) - 1.0) < 1e-9
    assert abs(spearman([1, 2, 3, 4], [8, 6, 4, 2]) + 1.0) < 1e-9


# ---------------------------------------------------------------- 时间漂移
def test_time_drift_detects_pure_noise_as_stationary() -> None:
    """无漂移的随机序列：过散比应 ≈1（不误判为非平稳）。"""
    import random
    random.seed(42)
    states = ["A" if random.random() < 0.7 else "B" for _ in range(20000)]
    rep = time_drift_summary(states, labels=["A", "B"], n_segments=20)
    ratio = rep.per_label["A"]["overdispersion_ratio"]
    # 20 段、每段 1000 样本 → 过散比在 1 附近波动（宽松上界 3）
    assert 0.2 < ratio < 3.0, f"纯噪声被误判为非平稳: {ratio}"


def test_time_drift_detects_injected_drift() -> None:
    """人为注入单调漂移：过散比应显著 ≫1，且首末段率差正确。"""
    n = 40000
    states = []
    for i in range(n):
        p = 0.9 - 0.4 * (i / n)
        states.append("A" if (i % 100) < p * 100 else "B")
    rep = time_drift_summary(states, labels=["A", "B"], n_segments=20)
    d = rep.per_label["A"]
    assert d["overdispersion_ratio"] > 20, d
    assert d["rate_first_segment"] > d["rate_last_segment"]
    assert d["trend_monotonic_pearson_r"] < -0.9


# ---------------------------------------------------------------- 去趋势
def test_detrending_removes_pure_time_trend() -> None:
    """参数轴与时间无关 + 存在纯时间漂移 → 去趋势后参数效应应≈0。"""
    import random
    random.seed(7)
    n = 30000
    axis = []
    states = []
    for i in range(n):
        a = i % 50                      # 参数轴与时间无关（轮转）
        p = 0.8 - 0.3 * (i / n)         # 纯时间漂移
        axis.append(a)
        states.append("T" if random.random() < p else "O")
    prof = detrended_delay_profile(axis, states, "T", row_index=list(range(n)),
                                   n_time_segments=100, axis_name="axis")
    d = prof.to_dict()
    # 原始相关可能因时间漂移出现假相关，去趋势后应接近 0
    assert abs(d["detrended_spearman"]) < 0.35, d
    # 去趋势后的真实标准差应远小于原始
    assert d["detrended_std"] <= d["raw_std"] * 1.2


def test_detrending_preserves_real_axis_effect() -> None:
    """无时间漂移 + 真实参数效应 → 去趋势后效应应保留。"""
    import random
    random.seed(11)
    n = 60000
    axis = []
    states = []
    for i in range(n):
        a = i % 60
        p = 0.5 + 0.3 * (1 if a < 30 else 0)   # 前 30 点高一档
        axis.append(a)
        states.append("T" if random.random() < p else "O")
    prof = detrended_delay_profile(axis, states, "T", row_index=list(range(n)),
                                   n_time_segments=100, axis_name="axis")
    d = prof.to_dict()
    rates = [pt["detrended_rate"] for pt in d["points"]]
    low = sum(rates[:30]) / 30
    high = sum(rates[30:]) / 30
    assert abs(high - low) > 0.25, f"真实效应被过度消除: {high - low}"


def test_detrended_points_conservation() -> None:
    """去趋势残差在全部点上加权求和应为 0（饱和模型的性质）。"""
    import random
    random.seed(3)
    n = 12000
    axis = [i % 40 for i in range(n)]
    states = ["T" if random.random() < 0.6 else "O" for _ in range(n)]
    prof = detrended_delay_profile(axis, states, "T", row_index=list(range(n)),
                                   n_time_segments=50)
    overall = sum(1 for s in states if s == "T") / n
    weighted = sum((pt["detrended_rate"] - overall) * pt["n"] for pt in prof.points)
    assert abs(weighted) < 1e-6, f"残差总和不为零: {weighted}"


# ---------------------------------------------------------------- 逐点显著性
def test_pointwise_no_false_positive_on_uniform_data() -> None:
    """全部点同率 → FDR 不应报告显著点。"""
    import random
    random.seed(5)
    ns = [2000] * 50
    counts = [sum(1 for _ in range(n) if random.random() < 0.01) for n in ns]
    res = pointwise_significance(counts, ns)
    assert res["fdr"]["n_significant"] == 0, res["fdr"]


def test_pointwise_detects_one_true_outlier() -> None:
    """一个点率明显偏高 → 应被 FDR 检出。"""
    ns = [2000] * 50
    counts = [20] * 49 + [200]     # 1% vs 10%
    res = pointwise_significance(counts, ns)
    assert res["fdr"]["n_significant"] >= 1
    sig = [p for p in res["points"] if p["fdr_significant"]]
    assert any(p["index"] == 49 for p in sig)


def test_pointwise_low_count_uses_exact_poisson() -> None:
    """极稀疏标签（期望计数 < 5）→ 必须走精确泊松，不得报假显著。"""
    ns = [12000] * 61
    counts = [0] * 60 + [1]        # 期望 0.016/点
    res = pointwise_significance(counts, ns)
    assert res["fdr"]["n_points_low_count"] == 61
    assert res["fdr"]["n_significant"] == 0
    assert res["low_count_warning"] is not None
    assert all(p["method"] == "poisson_exact" for p in res["points"])


# ---------------------------------------------------------------- 功效
def test_power_analysis_scales_with_n() -> None:
    """n 增大 → MDE 减小（按 1/sqrt(n)）。"""
    a = power_analysis(0.01, 1000)
    b = power_analysis(0.01, 4000)
    assert abs(b["mde_abs"] - a["mde_abs"] / 2) < 1e-9


def test_power_analysis_reference_value() -> None:
    """p0=0.5, n=100 → MDE ≈ (1.96+0.8416)*0.05 ≈ 0.14。"""
    r = power_analysis(0.5, 100)
    assert abs(r["mde_abs"] - 0.14008) < 1e-3


def test_power_analysis_degenerate_inputs() -> None:
    assert power_analysis(0.0, 100)["mde_abs"] is None
    assert power_analysis(0.5, 0)["mde_abs"] is None
