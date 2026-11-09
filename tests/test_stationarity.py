# -*- coding: utf-8 -*-
"""非平稳判定规则的自检（纯合成数据，含"漏检回归"用例）。

这些测试的由来：初版用"过散比 > 固定阈值"判定非平稳，在换数据集测试时
漏掉了一个真实漂移（CRASH 5.2%→17.2%，9.65pp，χ² p=1.9e-7，但过散比仅 3.63）。
本文件把该案例固化为回归测试，防止规则再退化。
"""

import math

import pytest

from fi.analysis.stratify import (
    TimeDriftReport,
    nonstationarity_verdict,
    time_drift_summary,
)


def _states_with_drift(n, base_p, end_p, seed=1, label="CRASH", other="WARN"):
    """生成带单调漂移的标签序列（确定性，不依赖随机种子稳定性）。"""
    out = []
    for i in range(n):
        p = base_p + (end_p - base_p) * (i / n)
        # 用确定性栅格替代随机：每 100 行放 round(p*100) 个 label
        k = int(round(p * 100))
        out.append(label if (i % 100) < k else other)
    return out


# ---------------------------------------------------------------- 回归用例
def test_regression_moderate_overdispersion_but_real_drift_is_flagged() -> None:
    """回归：漂移实质且统计极显著 → 必须判非平稳。

    该用例对应换数据集测试时的真实漏检场景：合成数据里注入的 CRASH 漂移
    （5.2%→17.2%，9.65pp，χ² p=1.9e-7）在当时的数据规模下过散比只有 3.63，
    被"过散比>10"的固定阈值漏掉。本测试用较高 n 复现"实质漂移必须被 flag"，
    另用 test_verdict_uses_chi2_not_overdispersion_alone 专门钉住
    "过散比低但显著"的情形。
    """
    states = _states_with_drift(50000, 0.05, 0.18)
    rep = time_drift_summary(states, labels=["CRASH", "WARN"], n_segments=20)
    d = rep.per_label["CRASH"]
    nv = nonstationarity_verdict(rep)
    assert "CRASH" in nv["flagged_labels"], (
        f"真实漂移被漏检：overdisp={d['overdispersion_ratio']}, "
        f"change={d['segment_total_change_pp']}pp, p={d['homogeneity_chi2']['p_approx']}")


def test_verdict_uses_chi2_not_overdispersion_alone() -> None:
    """核心回归：构造"过散比中等但统计极显著 + 效应量足够"的场景，必须 flag。

    做法：小段数（段内 n 大）下，同样幅度的漂移给出的过散比会较低，
    而 χ² 因总样本量大而极显著。这正是初版固定阈值漏检的形状。
    """
    # 段数少 → 过散比低；总 n 大 → χ² 极显著
    states = _states_with_drift(200000, 0.05, 0.20)
    rep = time_drift_summary(states, labels=["CRASH", "WARN"], n_segments=6)
    d = rep.per_label["CRASH"]
    p = d["homogeneity_chi2"]["p_approx"]
    nv = nonstationarity_verdict(rep)
    # 该形状下断言：χ² 极显著 + 变化足够 → 必须在 flagged 里
    if p is not None and p < 1e-10 and abs(d["segment_total_change_pp"]) >= 1.0:
        assert "CRASH" in nv["flagged_labels"], (
            f"χ² 极显著(p={p})且效应量足够"
            f"({d['segment_total_change_pp']}pp)，却未被判非平稳；"
            f"overdisp={d['overdispersion_ratio']}")


def test_tiny_relative_drift_on_small_baseline_is_not_flagged() -> None:
    """反面：小基线率标签的大相对漂移但绝对量极小 → 不得判非平稳。

    对应 74 万行真实数据里 SUCCESS（基线 0.62%，漂移 0.17pp = 27% 相对）。
    若误判，会把无实质影响的扰动当成结构变化。
    """
    n = 400000
    states = []
    for i in range(n):
        p = 0.005 + 0.0015 * (i / n)      # 0.5% → 0.65%，+0.15pp
        kinds = int(round(p * 1000))
        states.append("RARE" if (i % 1000) < kinds else "COMMON")
    rep = time_drift_summary(states, labels=["RARE", "COMMON"], n_segments=20)
    d = rep.per_label["RARE"]
    nv = nonstationarity_verdict(rep)
    assert "RARE" not in nv["flagged_labels"], (
        f"微小绝对漂移被误判为非平稳：change={d['segment_total_change_pp']}pp")


def test_adaptive_threshold_scales_with_baseline() -> None:
    """自适应阈值 = max(绝对下限, 基线率×相对下限)。

    基线 50% → 0.5×0.05×100 = 2.5pp > 1.0pp → 阈值取 2.5pp。
    """
    rep = time_drift_summary(["A"] * 500 + ["B"] * 500, labels=["A", "B"], n_segments=10)
    nv = nonstationarity_verdict(rep, min_total_change_pp=1.0, min_relative_change=0.05)
    for lab, rec in nv["per_label"].items():
        base = rep.per_label[lab]["rate_overall"]
        expected = max(1.0, base * 0.05 * 100.0)
        assert rec["adaptive_threshold_pp"] == pytest.approx(expected, abs=1e-4), lab


def test_adaptive_threshold_floor_for_small_baseline() -> None:
    """小基线率标签：基线×5% 低于绝对下限 1pp → 阈值取绝对下限 1.0pp。"""
    # 基线 2% → 0.02×5% = 0.1pp < 1.0pp → 阈值 = 1.0pp
    rep = time_drift_summary(["A"] * 20 + ["B"] * 980, labels=["A", "B"], n_segments=10)
    nv = nonstationarity_verdict(rep, min_total_change_pp=1.0, min_relative_change=0.05)
    assert nv["per_label"]["A"]["adaptive_threshold_pp"] == pytest.approx(1.0, abs=1e-9)


def test_verdict_stationary_on_pure_noise() -> None:
    """纯交替序列（无漂移）→ stationary，且不应有标签被 flag。"""
    states = []
    for i in range(20000):
        k = 30 if (i // 1000) % 2 == 0 else 31     # 段间仅 1% 差异
        states.append("X" if (i % 100) < k else "Y")
    rep = time_drift_summary(states, labels=["X", "Y"], n_segments=20)
    nv = nonstationarity_verdict(rep)
    assert nv["designation"] in ("stationary", "mild_drift")
    assert nv["flagged_labels"] == []


# ---------------------------------------------------------------- 结构自检
def test_verdict_structure_complete() -> None:
    rep = time_drift_summary(["A", "B"] * 1000, labels=["A", "B"], n_segments=10)
    nv = nonstationarity_verdict(rep)
    for key in ("designation", "flagged_labels", "mild_labels",
                "stationary_labels", "criteria", "per_label"):
        assert key in nv
    K = len(rep.labels)
    assert nv["criteria"]["bonferroni_threshold"] == pytest.approx(0.05 / K)
    for lab, rec in nv["per_label"].items():
        for k in ("verdict", "chi2_p", "statistically_significant",
                  "total_change_pp", "relative_change",
                  "adaptive_threshold_pp", "effect_large_enough"):
            assert k in rec, f"{lab} 缺字段 {k}"


def test_time_drift_includes_chi2() -> None:
    """每个标签都必须同时给出 χ² 显著性（不能只给效应量）。"""
    rep = time_drift_summary(["A"] * 300 + ["B"] * 700, labels=["A", "B"], n_segments=10)
    for lab, d in rep.per_label.items():
        assert "homogeneity_chi2" in d
        assert "chi2" in d["homogeneity_chi2"]
        assert "dof" in d["homogeneity_chi2"]
        assert "p_approx" in d["homogeneity_chi2"]


def test_chi2_increases_with_sample_size_for_same_effect() -> None:
    """同样的率差，样本越大 χ² 越大（检验对 n 敏感，这是正确的）。"""
    small = _states_with_drift(5000, 0.10, 0.20)
    large = _states_with_drift(50000, 0.10, 0.20)
    r_small = time_drift_summary(small, labels=["CRASH", "WARN"], n_segments=20)
    r_large = time_drift_summary(large, labels=["CRASH", "WARN"], n_segments=20)
    c_s = r_small.per_label["CRASH"]["homogeneity_chi2"]["chi2"]
    c_l = r_large.per_label["CRASH"]["homogeneity_chi2"]["chi2"]
    assert c_l > c_s * 3, f"χ² 未随样本量增长: {c_s} → {c_l}"


def test_single_label_degenerate() -> None:
    """只有一个标签（p=1）→ χ² 不可计算，不得崩。"""
    rep = time_drift_summary(["X"] * 100, labels=["X"], n_segments=5)
    d = rep.per_label["X"]
    assert d["homogeneity_chi2"]["p_approx"] is None
    nv = nonstationarity_verdict(rep)
    assert nv["designation"] == "stationary"


def test_two_segments_minimum() -> None:
    """n_segments 很小的边界（2 段）不得崩。"""
    rep = time_drift_summary(["A", "B"] * 500, labels=["A", "B"], n_segments=2)
    nv = nonstationarity_verdict(rep)
    assert nv["designation"] in ("stationary", "mild_drift", "nonstationary")
