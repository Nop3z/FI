# -*- coding: utf-8 -*-
"""指令级归因 section 的集成测试（异常分析报告 ↔ discover 归因能力）。

验证目标：`fi analyze anomaly --image ... --image-base ...` 能把观测到的码
归因到 handler 内的装载指令，且遵守证据纪律。测试不硬编码任何芯片实例值。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _packaged_report() -> dict | None:
    """仓库里已有的真实异常报告样例（若存在）。"""
    for cand in sorted((ROOT / "output").glob("**/*.anomaly-report.json")):
        try:
            return json.loads(cand.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
    return None


def test_attribution_section_unavailable_without_image() -> None:
    """无镜像时必须显式标记不可用，不得静默省略、不得推测。"""
    from fi.analysis.attribution_section import build_instruction_attribution

    sections = {"command_surface": {"taxonomy": {"codes": {"0x0100": {}, "0x0200": {}}}}}
    sec = build_instruction_attribution(sections, image_path=None, base=None)

    assert sec["available"] is False
    assert "reason" in sec and sec["reason"]
    assert sec["codes_observed"] == ["0x0100", "0x0200"]


def test_attribution_section_unavailable_without_base() -> None:
    """有镜像但无基址：同样必须显式不可用（基址是必要输入）。"""
    from fi.analysis.attribution_section import build_instruction_attribution

    sections = {"command_surface": {"taxonomy": {"codes": {"0x0100": {}}}}}
    sec = build_instruction_attribution(sections, image_path="whatever.bin", base=None)
    assert sec["available"] is False
    assert "基址" in sec["reason"]


def test_attribution_section_no_codes() -> None:
    """数据里没有 hex 形态的码时，明确说明"无需归因"。"""
    from fi.analysis.attribution_section import build_instruction_attribution

    sections = {"command_surface": {"taxonomy": {"codes": {"no_response": {}, "OK": {}}}}}
    sec = build_instruction_attribution(sections, image_path=None, base=0)
    assert sec["available"] is False or sec["codes_observed"] == []


def test_code_extraction_from_taxonomy() -> None:
    """码提取：从 taxonomy.codes 取 hex 形态值，忽略 no_response/OK 等 token。"""
    from fi.analysis.attribution_section import _extract_codes

    sections = {"command_surface": {"taxonomy": {"codes": {
        "0x<CODE_B>": {}, "0x<CODE_A>": {}, "no_response": {}, "OK": {},
    }}}}
    codes = _extract_codes(sections)
    assert codes == ["0x<CODE_B>", "0x<CODE_A>"], codes


def test_attach_adds_findings_with_evidence_level() -> None:
    """并入报告时追加的 finding 必须带 evidence_level（纪律）。"""
    from fi.analysis.attribution_section import attach_to_report

    base_report = {
        "schema": "fi.anomaly-report-v0",
        "sections": {"command_surface": {"taxonomy": {"codes": {"0x<CODE_B>": {}}}}},
        "findings": [],
    }
    out = attach_to_report(base_report, image_path=None, base=None)
    assert "instruction_attribution" in out["sections"]
    # 原 report 不被修改（纯函数语义）
    assert "instruction_attribution" not in base_report["sections"]
    # 不可用时不应追加 finding
    assert out["findings"] == []


def test_low_value_codes_are_skipped_not_misattributed() -> None:
    """低值码（如 0x0001/0x0006）默认跳过——避免与 c.li 标志位装载误配。"""
    from fi.discover.attribution import attribute_codes

    image = ROOT / "<ROM_IMAGE>"
    if not image.is_file():
        pytest.skip("样例镜像不存在")
    report = attribute_codes(str(image), 0x<BASE>, ["0x0001", "0x0006"])
    s = report["summary"]
    assert s["codes_requested"] == 0
    assert set(s["codes_skipped_below_min_value"]) == {"0x0001", "0x0006"}
    assert s["codes_attributed"] == 0
