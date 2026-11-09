"""reverse-report 构造器测试：把三条不变量前移到"构造期就报错"。

契约层的价值在于**让错误的形状不可能被拼出来**，而不是事后校验才发现。
本测试覆盖构造器的每一条护栏。
"""

import pytest

from fi import UNKNOWN
from fi.schemas.reverse_report import (
    INJECTION_ACTIONS,
    TIMING_FORMULA,
    ReverseReportBuildError,
    ReverseReportBuilder,
)
from fi.schemas import validate_instance

TARGET = {
    "id": "sample_feature",
    "title": "样例目标功能（占位，非芯片实例值）",
    "mode": "unknown",
    "description": "用于契约测试的抽象功能描述",
}


def _builder() -> ReverseReportBuilder:
    return ReverseReportBuilder(
        report_id="rev-test-0001",
        target_feature=dict(TARGET),
        tool={"name": "fi.discover.chain", "version": "0.3.0"},
    )


def _minimal_ready() -> tuple[ReverseReportBuilder, str]:
    b = _builder()
    ev = b.add_evidence(
        kind="artifact_derived",
        locator="fi discover chain --image <bin> --base <addr>",
        detail="递归下降得到的调用边",
        verification="fi discover chain ...",
    )
    b.set_timing(
        cycles=12000,
        ns_per_cycle=6.25,
        ns_per_cycle_confidence="hypothesis",
        ns_per_cycle_basis="公开文档标称主频折算（旁证）",
        method="静态指令计数 × 假设 CPI",
    )
    return b, ev


# ---------------------------------------------------------------- 正向


def test_build_minimal_valid_report() -> None:
    b, ev = _minimal_ready()
    b.add_entry_point(kind="reset_vector", addr=0x1000, description="入口", evidence_ref=ev)
    b.add_call_chain_level(
        level=0,
        function_addr=0x1000,
        evidence_ref=ev,
        call_site_insn="jal ra, 0x2000",
        conditions=["命令字匹配"],
    )
    b.add_injection_target(
        addr=0x2020,
        insn="lw a0, 12(sp)",
        expected_undesired_effect="长度字段被翻转 → 边界检查走错误出口",
        rationale="该 load 是长度校验唯一数据来源",
        evidence_ref=ev,
        suggested_action="flip_reg_bits",
        trigger_hint={"mode": "seq", "value": 12000},
    )
    b.add_unknown(topic="帧格式", description="帧头布局未确认")

    report = b.build()
    assert validate_instance("reverse-report", report) == []
    assert report["confidence"] == "hypothesis"
    assert report["timing_estimate"]["ns_estimate"]["value"] == int(round(12000 * 6.25))
    assert report["timing_estimate"]["ns_estimate"]["formula"] == TIMING_FORMULA


def test_empty_report_is_unknown_not_hypothesis() -> None:
    """什么都没有时整体等级必须 unknown（不能拿 hypothesis 假装有结论）。"""
    b, _ev = _minimal_ready()
    report = b.build()
    assert report["confidence"] == "unknown"
    assert report["entry_points"] == []
    assert report["call_chain"] == []


# ---------------------------------------------------------------- 不变量 1：证据引用


def test_rejects_unregistered_evidence_ref_at_build_time() -> None:
    b, _ev = _minimal_ready()
    with pytest.raises(ReverseReportBuildError) as exc:
        b.add_call_chain_level(level=0, function_addr=0x1000, evidence_ref="ev-999")
    assert "ev-999" in str(exc.value)


def test_rejects_error_exit_with_dangling_ref() -> None:
    b, ev = _minimal_ready()
    with pytest.raises(ReverseReportBuildError):
        b.add_call_chain_level(
            level=1,
            function_addr=0x2000,
            evidence_ref=ev,
            error_exits=[{"condition": "越界", "path": "返回错误帧", "evidence_ref": "ev-404"}],
        )


def test_rejects_public_doc_as_observation_evidence() -> None:
    """公开资料只作旁证，不得升 observation（纪律进构造器）。"""
    b = _builder()
    with pytest.raises(ReverseReportBuildError):
        b.add_evidence(kind="public_doc", locator="厂商文档 §1", confidence="observation")


# ---------------------------------------------------------------- 不变量 2：未验证不得标 observation


def test_rejects_observation_without_verified_by() -> None:
    b, ev = _minimal_ready()
    with pytest.raises(ReverseReportBuildError) as exc:
        b.add_call_chain_level(
            level=0, function_addr=0x1000, evidence_ref=ev, confidence="observation"
        )
    assert "verified_by" in str(exc.value)


def test_rejects_verified_by_on_hypothesis() -> None:
    """反向护栏：hypothesis 却给 verified_by 是自相矛盾（升级要么彻底要么不做）。"""
    b, ev = _minimal_ready()
    with pytest.raises(ReverseReportBuildError):
        b.add_call_chain_level(
            level=0,
            function_addr=0x1000,
            evidence_ref=ev,
            confidence="hypothesis",
            verified_by="simulation",
        )


def test_accepts_verified_observation() -> None:
    b, ev = _minimal_ready()
    b.add_call_chain_level(
        level=0,
        function_addr=0x1000,
        evidence_ref=ev,
        confidence="observation",
        verified_by="simulation",
    )
    report = b.build()
    assert validate_instance("reverse-report", report) == []
    assert report["call_chain"][0]["verified_by"] == "simulation"


# ---------------------------------------------------------------- 不变量 3：timing 禁裸数字


def test_timing_computes_ns_centrally() -> None:
    """ns 必须由构造器统一换算（禁各工具自己乘）。"""
    b = _builder()
    b.set_timing(cycles=1000, ns_per_cycle=10.0, ns_per_cycle_confidence="hypothesis")
    report = b.build()
    assert report["timing_estimate"]["ns_estimate"]["value"] == 10000


def test_timing_unknown_cycles_stays_unknown() -> None:
    b = _builder()
    b.set_timing(cycles=UNKNOWN, ns_per_cycle=UNKNOWN, ns_per_cycle_confidence="unknown")
    report = b.build()
    assert report["timing_estimate"]["ns_estimate"]["value"] == UNKNOWN
    assert report["timing_estimate"]["ns_estimate"]["confidence"] == "unknown"
    assert validate_instance("reverse-report", report) == []


def test_timing_requires_assumption_object_via_confidence() -> None:
    """频率假设的证据等级不能凭空写 fact/observation（必须走 Chip Profile 升级）。"""
    b = _builder()
    for bad in ("observation", "whatever"):
        with pytest.raises(ReverseReportBuildError):
            b.set_timing(cycles=1, ns_per_cycle=1.0, ns_per_cycle_confidence=bad)


def test_build_without_timing_fails() -> None:
    b = _builder()
    ev = b.add_evidence(kind="artifact_derived", locator="x")
    b.add_call_chain_level(level=0, function_addr=0x1000, evidence_ref=ev)
    with pytest.raises(ReverseReportBuildError) as exc:
        b.build()
    assert "timing_estimate" in str(exc.value)


# ---------------------------------------------------------------- 动作/入口词汇表


def test_rejects_discover_only_action_in_injection_target() -> None:
    """map_region/stub_read 是发现层动作，不是注入动作——靶点里用即错。"""
    b, ev = _minimal_ready()
    for action in ("map_region", "stub_read", "exploit"):
        with pytest.raises(ReverseReportBuildError):
            b.add_injection_target(
                addr=0x2000,
                insn="nop",
                expected_undesired_effect="x",
                rationale="y",
                evidence_ref=ev,
                suggested_action=action,
            )


def test_injection_actions_match_sim_trace_vocabulary() -> None:
    """靶点动作必须与 sim-trace 的 action.kind 词汇对齐（除发现层两个动作外）。"""
    from fi.schemas import load_schema

    sim_trace = load_schema("sim-trace")
    kinds: set[str] = set()
    for variant in sim_trace["$defs"]["fault_event"]["properties"]["action"]["oneOf"]:
        kinds.add(variant["properties"]["kind"]["const"])
    assert set(INJECTION_ACTIONS) == kinds, (
        f"reverse-report 注入动作 {set(INJECTION_ACTIONS)} 与 sim-trace {kinds} 不一致"
    )


def test_rejects_unknown_entry_point_kind() -> None:
    b, ev = _minimal_ready()
    with pytest.raises(ReverseReportBuildError):
        b.add_entry_point(kind="magic_entry", addr=0, description="x", evidence_ref=ev)
