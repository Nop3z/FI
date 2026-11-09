"""闭环测试：值对象 / CSV 重放注入器 / 仿真注入器 / 编排器端到端。"""

import json
from pathlib import Path

import pytest

from fi import UNKNOWN
from fi.loop.csv_replay import CSVReplayInjector, iter_campaign_records
from fi.loop.orchestrator import GenericLoopOrchestrator
from fi.loop.sim_injector import ParamMappingSpec, SimFaultInjector
from fi.loop.strategies import MinimalGridStrategy
from fi.loop.types import ParamAxis, ParamPoint, ParamWindow
from fi.sim.protocol import SimBackend, SimRunResult
from fi.schemas import validate_instance

SAMPLE_CSV = """state,delay,pulse,response,glitched,unexpected
FL,2640,6,0x<CODE_A>,glitched,
SUCCESS,3130,2,,glitched,OK
HANG,3140,2,,glitched,
UNEXPECTED,3145,3,0x<CODE_B>,glitched,0x<CODE_B>
Fake_Success,3145,2,0x<CODE_D>,glitched,0x<CODE_D>
"""


@pytest.fixture()
def csv_path(tmp_path: Path) -> Path:
    p = tmp_path / "sample.csv"
    p.write_text(SAMPLE_CSV, encoding="utf-8")
    return p


# ---------------------------------------------------------------- 值对象


def test_param_window_grid_and_contract_shape() -> None:
    window = ParamWindow(
        axes=(
            ParamAxis("delay", "raw", 2640, 2650, 5),
            ParamAxis("pulse", "raw", 2, 6, 4),
        )
    )
    points = list(window.grid_points())
    assert len(points) == 6  # 3 delay × 2 pulse
    assert points[0].values == {"delay_raw": 2640, "pulse_raw": 2}
    assert window.contains(ParamPoint({"delay_raw": 2640, "pulse_raw": 6}))
    assert not window.contains(ParamPoint({"delay_raw": 9999, "pulse_raw": 2}))

    contract_window = window.to_contract_window()
    assert validate_instance(
        "experiment-scan",
        {
            "schema_version": "0.2",
            "scan_id": "scan-t",
            "window": contract_window,
            "records_ref": {"path": "x.jsonl", "count": 0},
            "evidence_level": "observation",
        },
    ) == []

    # 无 step 的轴不能网格展开
    open_window = ParamWindow(axes=(ParamAxis("delay", "ns", 27000, 38000, None),))
    with pytest.raises(ValueError):
        list(open_window.grid_points())


# ---------------------------------------------------------------- CSV 重放注入器


def test_csv_replay_exact_and_sequential(csv_path: Path) -> None:
    inj = CSVReplayInjector(csv_path, match="exact")
    out = inj.inject(ParamPoint({"delay_raw": 3145, "pulse_raw": 2}))
    assert out.status == "injected"
    assert out.evidence_level == "observation"
    assert out.state_label == "Fake_Success"
    assert out.response_raw == "0x<CODE_D>"
    assert out.applied_point == {"delay_raw": 3145, "pulse_raw": 2}
    assert out.raw_data_ref is not None and out.raw_data_ref["row_index"] == 4

    seq = CSVReplayInjector(csv_path, match="sequential")
    labels = [seq.inject(ParamPoint({"delay_raw": 0, "pulse_raw": 0})).state_label for _ in range(5)]
    assert labels == ["FL", "SUCCESS", "HANG", "UNEXPECTED", "Fake_Success"]


def test_csv_replay_no_match_and_rejects_silent_ns(csv_path: Path) -> None:
    inj = CSVReplayInjector(csv_path, match="exact")
    out = inj.inject(ParamPoint({"delay_raw": 1, "pulse_raw": 1}))
    assert out.status == "no_match"

    # 纪律：未显式配置 ns_per_raw 时拒绝 ns 参数点（禁止隐式换算）
    ns_out = inj.inject(ParamPoint({"delay_ns": 30000, "pulse_ns": 20}))
    assert ns_out.status == "error"
    assert "ns_per_raw" in ns_out.detail["reason"]


def test_csv_replay_ns_with_explicit_assumption(csv_path: Path) -> None:
    inj = CSVReplayInjector(csv_path, ns_per_raw=10.0, match="exact")
    out = inj.inject(ParamPoint({"delay_ns": 31300, "pulse_ns": 20}))
    assert out.status == "injected"
    assert out.applied_point == {"delay_raw": 3130, "pulse_raw": 2}
    assert out.detail["unit_assumption"]["scale"] == "1 raw unit = 10.0 ns"


# ---------------------------------------------------------------- 仿真注入器


class StubSimBackend(SimBackend):
    """测试桩：记录事件并返回固定运行结果。"""

    name = "stub"

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.reset_called = False

    def load_image(self, image_path, base_address, profile_ref=UNKNOWN):
        pass

    def reset(self) -> None:
        self.reset_called = True

    def apply_fault(self, event: dict) -> str:
        self.events.append(event)
        return event["event_id"]

    def run(self, max_instructions: int) -> SimRunResult:
        return SimRunResult(
            run_id="run-stub-1",
            exit_reason="normal",
            final_pc=553648260,
            instruction_count=5000,
            trace_ref=None,
            final_context={},
            outcome_metrics={"observable_output": "0x<CODE_A>"},
        )


def test_sim_fault_injector_maps_ns_to_event() -> None:
    backend = StubSimBackend()
    mapping = ParamMappingSpec(
        trigger_mode="seq",
        width_mode="instruction_count",
        action_kind="flip_reg_bits",
        flip_target_reg="a0",
    )
    inj = SimFaultInjector(backend, mapping)
    out = inj.inject(ParamPoint({"delay_ns": 3000, "pulse_ns": 2}))

    assert backend.reset_called
    assert out.status == "injected"
    assert out.evidence_level == "hypothesis"
    assert out.response_raw == "0x<CODE_A>"
    event = backend.events[0]
    assert event["trigger"] == {"mode": "seq", "value": 3000, "ns_per_cycle": "unknown"}
    assert event["action"]["kind"] == "flip_reg_bits"
    assert event["action"]["bit_width"] == 2
    assert event["pulse"] == {"mode": "instruction_count", "value": 2}
    # 事件形状必须符合 sim-trace 契约
    assert validate_instance("sim-trace", event) == []

    # cycle_estimate 缺 ns_per_cycle 必须构造报错
    with pytest.raises(ValueError):
        ParamMappingSpec(trigger_mode="cycle_estimate")


# ---------------------------------------------------------------- CampaignRecord 组装


def test_campaign_record_from_outcomes(csv_path: Path) -> None:
    from fi.loop.records import build_campaign_record

    inj = CSVReplayInjector(csv_path, match="exact")
    out = inj.inject(ParamPoint({"delay_raw": 3130, "pulse_raw": 2}))
    rec = build_campaign_record(
        point=out.point,
        outcome=out,
        fault_context_ids=[],
        campaign_id="camp-test-000001",
    )
    assert validate_instance("campaign-record", rec) == []
    assert rec["response"]["state_label"] == "SUCCESS"
    assert rec["response"]["state_label_semantics"] == "unconfirmed-v0.1"
    assert rec["evidence_level"] == "observation"


def test_iter_campaign_records_convert(csv_path: Path) -> None:
    records = list(iter_campaign_records(csv_path, states=["SUCCESS", "Fake_Success"]))
    assert [r["response"]["state_label"] for r in records] == ["SUCCESS", "Fake_Success"]
    for r in records:
        assert validate_instance("campaign-record", r) == []
        assert r["params"]["delay_ns"] == "unknown"  # 未给假设时保持 unknown


def test_responded_shape_rule(tmp_path: Path) -> None:
    """responded 机械定义（lead 终审，观测级零特例）：任一列非空 token→True。"""
    csv_src = tmp_path / "resp.csv"
    csv_src.write_text(
        "state,delay,pulse,response,glitched,unexpected\n"
        "SUCCESS,3130,2,,glitched,OK\n"          # unexpected='OK' 非空 → True
        "FL,2640,6,0x<CODE_A>,glitched,\n"           # response 非空 → True
        "HANG,3140,2,,glitched,\n"               # 两列全空 → False
        "Fake_Success,3145,2,NONE,glitched,NONE\n"  # 'NONE' 非空 token → True（观测级，非解释级）
        "UNEXPECTED,3145,3,,glitched,0x<CODE_B>\n"   # unexpected 非空 → True
        "Fake_Success,3146,2,0x<CODE_D>,glitched,\n" # response 非空 → True
        ,
        encoding="utf-8",
    )
    rows = {r["response"]["state_label"] + str(r["raw_data_ref"]["row_index"]): r
            for r in iter_campaign_records(csv_src)}
    assert rows["SUCCESS0"]["response"]["responded"] is True
    assert rows["FL1"]["response"]["responded"] is True
    assert rows["HANG2"]["response"]["responded"] is False
    assert rows["Fake_Success3"]["response"]["responded"] is True
    assert rows["UNEXPECTED4"]["response"]["responded"] is True
    assert rows["Fake_Success5"]["response"]["responded"] is True


# ---------------------------------------------------------------- 端到端闭环


def test_closed_loop_end_to_end_with_csv_replay(csv_path: Path) -> None:
    """CSV 重放闭环冒烟：窗口 → 策略 → 注入 → 记录 → 收敛。"""
    window = ParamWindow(
        axes=(
            ParamAxis("delay", "raw", 3130, 3140, 5),
            ParamAxis("pulse", "raw", 2, 2, 1),
        )
    )
    injector = CSVReplayInjector(csv_path, match="nearest")
    strategy = MinimalGridStrategy(target_state_label="SUCCESS", max_points=8)
    orchestrator = GenericLoopOrchestrator(max_rounds=3)

    result = orchestrator.run(window, strategy, injector, observers=[])
    assert result.records, "应产出实验记录"
    assert result.stop_reason == "converged"  # 窗口包含 SUCCESS 行，应收敛
    for rec in result.records:
        assert validate_instance("campaign-record", rec) == []
    assert Path(result.records[0]["raw_data_ref"]["path"]).suffix == ".csv"


def test_closed_loop_with_sim_injector(tmp_path: Path) -> None:
    backend = StubSimBackend()
    injector = SimFaultInjector(backend, ParamMappingSpec(trigger_mode="seq"))
    window = ParamWindow(axes=(ParamAxis("delay", "ns", 1000, 3000, 1000),))
    strategy = MinimalGridStrategy(target_state_label="unknown", max_points=2)
    result = GenericLoopOrchestrator(max_rounds=2).run(window, strategy, injector, [])
    assert len(result.records) == 2
    for rec in result.records:
        assert rec["evidence_level"] == "hypothesis"  # 仿真=重建推断
        assert validate_instance("campaign-record", rec) == []
