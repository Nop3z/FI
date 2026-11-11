# -*- coding: utf-8 -*-
"""anomaly 报告在"实机型数据"上的回归测试。

由来（2026-11-10 实机验收）：真实实机数据与历史 CSV 的结构**根本不同**——
- 历史：单一 pulse（占 99.9997%）+ 每 delay 点 ~12,000 次采样
- 实机：11 档 pulse 混合 + 每 delay 点 ~1 次采样

初版 anomaly 管线按"行数最多的 pulse 作主扫描"筛选，在实机数据上把 90%+
的行丢出分析（只剩 17 个 delay 点），并完全错过 pulse 维的唯一真实信号。
本文件把该缺陷固化为回归测试。
"""

import csv

import pytest

from fi.analysis.anomaly_report import AnomalyReportConfig, build_anomaly_report


def _write_csv(tmp_path, rows, columns=("state", "delay", "pulse", "response",
                                        "glitched", "unexpected")):
    p = tmp_path / "live.csv"
    with open(p, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(columns))
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in columns})
    return p


def _live_like_rows():
    """模拟实机数据形状：多 pulse、每 delay 点 1 次、pulse 有阈值效应。"""
    rows = []
    pulses = [1, 5, 10, 20, 25, 50, 100, 150, 200, 250, 300]
    d = 22951
    for p in pulses:
        for _ in range(15):
            # pulse >= 150 → HANG；否则 FL
            if p >= 150:
                rows.append({"state": "HANG", "delay": d, "pulse": p,
                             "response": "", "glitched": "glitched", "unexpected": ""})
            else:
                rows.append({"state": "FL", "delay": d, "pulse": p,
                             "response": "0x<CODE_A>", "glitched": "glitched",
                             "unexpected": ""})
            d += 1
    return rows


# ---------------------------------------------------------------- 回归核心
def test_multi_pulse_uses_all_rows_not_just_dominant(tmp_path) -> None:
    """回归：pulse 分散时不得只看"行数最多的 pulse"，必须用全部行。"""
    rows = _live_like_rows()
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    cmd = rep["sections"]["command_surface"]

    assert cmd["pulse_selection_mode"] == "multi_pulse_all_rows"
    assert cmd["main_pulse"] is None
    # 关键：参数轴分析的行数应等于全量（而非某个 pulse 子集）
    assert cmd["n_rows_in_axis_analysis"] == len(rows)


def test_multi_pulse_detects_threshold_jump(tmp_path) -> None:
    """回归：pulse 维的阈值效应（100→150 突变）必须被检出。"""
    rows = _live_like_rows()
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    pa = rep["sections"]["command_surface"]["pulse_axis"]

    assert pa["available"] is True
    assert pa["n_pulse_values"] == 11
    # 必须有 HANG 的阈值检出，且跨越 100→150
    assert "HANG" in pa["rate_jump_thresholds"]
    jumps = pa["rate_jump_thresholds"]["HANG"]
    assert any(j["between_pulse"] == [100, 150] for j in jumps), jumps
    j = next(j for j in jumps if j["between_pulse"] == [100, 150])
    assert j["delta_pp"] == pytest.approx(100.0, abs=1e-6)


def test_multi_pulse_flags_saturated_cells(tmp_path) -> None:
    """已饱和（100%）的 pulse 档必须被标出，避免后续重复采样。"""
    rows = _live_like_rows()
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    pa = rep["sections"]["command_surface"]["pulse_axis"]
    sat_labels = {(s["label"], s["pulse"]) for s in pa["saturated_cells"]}
    assert ("HANG", 150) in sat_labels
    assert ("FL", 1) in sat_labels


def test_single_pulse_mode_preserved(tmp_path) -> None:
    """历史型数据（单一 pulse 主导）必须仍走"推导主 pulse"路径（不回归）。"""
    rows = []
    for i in range(200):
        d = 3130 + (i % 20)
        pulse = 2 if i < 198 else 6
        rows.append({"state": "FL", "delay": d, "pulse": pulse,
                     "response": "0x<CODE_A>", "glitched": "glitched", "unexpected": ""})
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    cmd = rep["sections"]["command_surface"]
    assert cmd["pulse_selection_mode"] == "derived_dominant_pulse"
    assert cmd["main_pulse"] == 2


def test_low_sampling_is_reported_via_mde(tmp_path) -> None:
    """每点 n≈1 时，功效分析必须明确报告"该分辨率下不可判定"。"""
    rows = _live_like_rows()
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    pwr = rep["sections"]["statistical_power"]
    assert pwr["available"] is True
    assert pwr["mean_repeats_per_point"] <= 2
    for lab, d in pwr["per_label"].items():
        # n 极小时 MDE 应接近或超过可观测范围，且必须标注为不可判定
        assert d["detectability"] in (
            "no_structure_at_this_resolution", "low_count_unreliable"), (lab, d)


def test_two_pulse_values_is_not_analysed(tmp_path) -> None:
    """回归：只有 2 个 pulse 取值时必须 available=False（不得强行分析）。

    由来（2026-11-10 lead 小修）：守卫原为 ``len < 2``，导致历史数据
    pulse∈{2,6} 也放行 → available=True 但分析无意义（两个取值只能比较
    一次，无法建立趋势或阈值结论）。
    """
    rows = []
    for i in range(300):
        pulse = 2 if i < 298 else 6
        rows.append({"state": "FL" if i % 2 else "HANG",
                     "delay": 3130 + i % 20, "pulse": pulse,
                     "response": "0x<CODE_A>" if i % 2 else "",
                     "glitched": "glitched", "unexpected": ""})
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    pa = rep["sections"]["command_surface"]["pulse_axis"]
    assert pa["available"] is False
    assert pa["n_pulse_values"] if "n_pulse_values" in pa else True
    assert "2" in pa["reason"] or "个取值" in pa["reason"]


def test_three_pulse_values_still_unavailable(tmp_path) -> None:
    """3 个取值仍不足阈值 4 → available=False。"""
    rows = []
    for i in range(300):
        pulse = [2, 6, 10][i % 3]
        rows.append({"state": "FL" if i % 2 else "HANG",
                     "delay": 3130 + i % 20, "pulse": pulse,
                     "response": "0x<CODE_A>" if i % 2 else "",
                     "glitched": "glitched", "unexpected": ""})
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    pa = rep["sections"]["command_surface"]["pulse_axis"]
    assert pa["available"] is False


def test_four_pulse_values_available_but_weak(tmp_path) -> None:
    """4 个取值达到可用阈值，但必须标 weak_signal=True。"""
    rows = []
    for i in range(400):
        pulse = [1, 5, 10, 20][i % 4]
        rows.append({"state": "FL" if i % 2 else "HANG",
                     "delay": 100 + i % 20, "pulse": pulse,
                     "response": "0x<CODE_A>" if i % 2 else "",
                     "glitched": "glitched", "unexpected": ""})
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    pa = rep["sections"]["command_surface"]["pulse_axis"]
    assert pa["available"] is True
    assert pa["weak_signal"] is True
    assert pa["weak_signal_note"]


def test_six_pulse_values_not_weak(tmp_path) -> None:
    """≥6 个取值时 weak_signal=False（分析力足够）。"""
    rows = []
    for i in range(600):
        pulse = [1, 5, 10, 20, 25, 50][i % 6]
        rows.append({"state": "FL" if i % 2 else "HANG",
                     "delay": 100 + i % 20, "pulse": pulse,
                     "response": "0x<CODE_A>" if i % 2 else "",
                     "glitched": "glitched", "unexpected": ""})
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    pa = rep["sections"]["command_surface"]["pulse_axis"]
    assert pa["available"] is True
    assert pa["weak_signal"] is False


# ---------------------------------------------------------------- 列结构泛化
def test_different_column_names_work(tmp_path) -> None:
    """换列名（不同芯片/不同上位机）必须零改代码可跑。"""
    rows = []
    for i in range(300):
        rows.append({"status": "PASS" if i % 3 else "FAIL",
                     "d": 100 + i % 30, "p": 7,
                     "err": "" if i % 3 else "0x2A", "hit": "g", "note": ""})
    p = tmp_path / "other.csv"
    with open(p, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["status", "d", "p", "err", "hit", "note"])
        w.writeheader()
        w.writerows(rows)
    cfg = AnomalyReportConfig.from_dict({
        "columns": {"state": "status", "delay": "d", "pulse": "p",
                    "response": "err", "glitched": "hit", "unexpected": "note"},
    })
    rep = build_anomaly_report(p, cfg)
    assert rep["inputs"]["n_rows"] == 300
    labels = rep["sections"]["quality_and_stationarity"]["labels"]
    assert set(labels) == {"PASS", "FAIL"}


def test_decimal_codes_supported(tmp_path) -> None:
    """码值可为十进制（非 0x 前缀）——需 code_rule.allow_decimal。"""
    rows = []
    for i in range(100):
        rows.append({"state": "FL", "delay": 10 + i % 5, "pulse": 1,
                     "response": "1281" if i % 2 else "260",
                     "glitched": "g", "unexpected": ""})
    p = _write_csv(tmp_path, rows)
    cfg = AnomalyReportConfig.from_dict({"code_rule": {"allow_decimal": True}})
    rep = build_anomaly_report(p, cfg)
    codes = rep["sections"]["command_surface"]["taxonomy"]["codes"]
    assert "1281" in codes and "260" in codes


def test_empty_data_does_not_crash(tmp_path) -> None:
    """空数据（只有表头）必须给出明确的 gate_failures，不得崩。"""
    p = _write_csv(tmp_path, [])
    rep = build_anomaly_report(p)
    q = rep["sections"]["quality_and_stationarity"]
    assert q["gate_passed"] is False
    assert q["gate_failures"]
    assert rep["sections"]["command_surface"]["available"] is False


def test_all_same_state_does_not_crash(tmp_path) -> None:
    """只有一个状态标签时不得崩（无对比对象）。"""
    rows = [{"state": "FL", "delay": i, "pulse": 2, "response": "0x<CODE_A>",
             "glitched": "g", "unexpected": ""} for i in range(50)]
    p = _write_csv(tmp_path, rows)
    rep = build_anomaly_report(p)
    q = rep["sections"]["quality_and_stationarity"]
    assert q["gate_passed"] is False
    assert any("标签" in f for f in q["gate_failures"])
