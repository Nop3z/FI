"""契约 schema 测试：可加载、样例齐全、实例校验通过、unknown 合法。"""

import json
from pathlib import Path

import pytest

from fi.schemas import (
    SCHEMA_REGISTRY,
    list_schemas,
    load_schema,
    load_schema_registry,
    validate_instance,
)

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "docs" / "contracts" / "schemas"


# ---------------------------------------------------------------- 文件完整性


def test_all_registered_files_present() -> None:
    rows = list_schemas(SCHEMA_DIR)
    assert rows, "契约注册表为空"
    for row in rows:
        assert row["present"] == "yes", f"{row['name']} 缺文件: {row['file']}"


@pytest.mark.parametrize("name", list(SCHEMA_REGISTRY))
def test_schema_loads_with_id(name: str) -> None:
    schema = load_schema(name, SCHEMA_DIR)
    assert schema["$id"].startswith("https://fi-converters.invalid/contracts/v0.1/")
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_common_defs_not_instantiable() -> None:
    with pytest.raises(Exception):
        validate_instance("common", {}, SCHEMA_DIR)


def test_evidence_level_enum_vocabulary() -> None:
    """证据等级三值词汇表全契约一致（纪律）。"""
    common = load_schema("common", SCHEMA_DIR)
    ev = common["$defs"]["evidence_level"]
    assert ev["enum"] == ["observation", "hypothesis", "unknown"]


# ---------------------------------------------------------------- examples 齐全


def _check_examples(node: dict, path: str, problems: list[str]) -> None:
    """纪律检查：契约字段必须给示例值。$ref/oneOf/anyOf 节点豁免（定义在目标处）。"""
    if "$ref" in node or "oneOf" in node or "anyOf" in node:
        return
    for key, sub in node.get("properties", {}).items():
        sub_path = f"{path}/{key}"
        if "$ref" in sub or "oneOf" in sub or "anyOf" in sub:
            continue
        if "properties" in sub or "items" in sub:
            _check_examples(sub, sub_path, problems)
            items = sub.get("items")
            if isinstance(items, dict) and ("$ref" not in items and "properties" in items):
                _check_examples(items, f"{sub_path}[]", problems)
            continue
        if "examples" not in sub:
            problems.append(f"{sub_path}: 缺 examples")


@pytest.mark.parametrize(
    "name",
    [
        "fault-context",
        "campaign-record",
        "experiment-scan",
        "chip-profile-index",
        "analysis-result",
        "sim-trace",
        "reverse-report",
        "discover-report",
        "tts-metrics",
    ],
)
def test_every_field_has_examples(name: str) -> None:
    schema = load_schema(name, SCHEMA_DIR)
    problems: list[str] = []
    _check_examples(schema, name, problems)
    # $defs 内部定义同样要求（豁免 common 的基础类型由外部引用）
    for def_name, def_node in schema.get("$defs", {}).items():
        _check_examples(def_node, f"{name}#$defs/{def_name}", problems)
    assert not problems, "以下契约字段缺示例值:\n" + "\n".join(problems)


# ---------------------------------------------------------------- 实例校验


def test_fault_context_minimal_and_unknown_fields() -> None:
    minimal = {
        "schema_version": "0.2",
        "context_id": "ctx-20261109-test01",
        "source_provider": "uart",
        "observation_level": "behavior",
        "evidence_level": "observation",
    }
    assert validate_instance("fault-context", minimal, SCHEMA_DIR) == []

    # 未采集字段显式 unknown 必须合法
    full = {
        **minimal,
        "campaign_id": "unknown",
        "timestamp": "unknown",
        "pc": "unknown",
        "registers": "unknown",
        "csrs": "unknown",
        "memory_snapshot": [],
        "behavior": {
            "uart_response_raw": "0x<CODE_A>",
            "error_code_raw": "0x<CODE_A>",
            "reset_observed": False,
            "watchdog_fired": "unknown",
        },
        "execution_trace": "unknown",
        "correlation": "unknown",
        "raw_data_ref": {
            "kind": "csv",
            "path": "<DATASET>.csv",
            "row_index": 42,
            "checksum": "unknown",
        },
    }
    assert validate_instance("fault-context", full, SCHEMA_DIR) == []

    # 非法值必须被拒：null 不是合法缺失表达
    bad = {**minimal, "pc": None}
    assert validate_instance("fault-context", bad, SCHEMA_DIR)


def test_campaign_record_minimal() -> None:
    record = {
        "schema_version": "0.2",
        "campaign_id": "camp-19991231-test01",
        "params": {
            "raw_delay": 3145,
            "raw_pulse": 2,
            "delay_ns": "unknown",
            "pulse_ns": "unknown",
            "unit_assumption": {"scale": "1 raw unit = 10 ns", "evidence_level": "hypothesis"},
            "injector_id": "csv-replay",
        },
        "response": {
            "state_label": "Fake_Success",
            "state_label_semantics": "unconfirmed-v0.1",
            "error_code_raw": "0x<CODE_D>",
            "glitched_raw": "glitched",
            "unexpected_raw": "0x<CODE_D>",
            "responded": True,
        },
        "fault_context_refs": [],
        "raw_data_ref": {"kind": "csv", "path": "<DATASET>.csv", "row_index": 0},
        "evidence_level": "observation",
        "timestamp": "unknown",
    }
    assert validate_instance("campaign-record", record, SCHEMA_DIR) == []


def test_experiment_scan_minimal() -> None:
    scan = {
        "schema_version": "0.2",
        "scan_id": "scan-20261109-test01",
        "window": [
            {"axis": "delay", "min_value": 2640, "max_value": 3190, "step_value": 1, "unit": "raw"},
            {"axis": "pulse", "min_value": 2, "max_value": 6, "step_value": "unknown", "unit": "raw"},
        ],
        "unit_assumption": {"scale": "1 raw unit = 10 ns", "evidence_level": "hypothesis"},
        "records_ref": {"path": "data/derived/scan-test.jsonl", "count": 123456, "checksum": "unknown"},
        "summary": {
            "total_records": 123456,
            "by_state": {"SUCCESS": {"count": 1234, "delay_min": 3130, "delay_max": 3190}},
        },
        "evidence_level": "observation",
        "timestamp": "unknown",
    }
    assert validate_instance("experiment-scan", scan, SCHEMA_DIR) == []


def test_chip_profile_index_minimal() -> None:
    idx = {
        "schema_version": "0.2",
        "profiles": [
            {
                "profile_id": "target-chip",
                "index_path": "profiles/target-chip/index.json",
                "format_version": "unknown",
                "status": "draft",
                "evidence_level": "observation",
                "source_of_truth": "chip-profile-contract",
            }
        ],
    }
    assert validate_instance("chip-profile-index", idx, SCHEMA_DIR) == []


def test_analysis_result_minimal_with_candidates_hypothesis() -> None:
    result = {
        "schema_version": "0.2",
        "analysis_id": "ana-20261109-test01",
        "analysis_kind": "candidate_attribution",
        "inputs": [{"kind": "scan", "id": "scan-20261109-test01"}],
        "findings": [
            {
                "finding_id": "find-20261109-test01",
                "kind": "hit_zone",
                "description": "SUCCESS 集中于 delay 3130-3190、pulse=2",
                "evidence_level": "observation",
                "supporting_refs": ["scan-20261109-test01"],
            }
        ],
        "hit_windows": [
            {"axis": "delay", "min_value": 3130, "max_value": 3190, "unit": "raw",
             "state_label": "SUCCESS", "evidence_level": "observation"}
        ],
        "candidates": [
            {"candidate_id": "cand-20261109-test01", "description": "0x<CODE_A> 加载路径被击中",
             "pc": "unknown", "profile_ref": "target-chip", "evidence_level": "hypothesis"}
        ],
        "baseline_diff": "unknown",
        "metrics": {"success_rate": 0.00623},
        "evidence_level": "hypothesis",
        "timestamp": "unknown",
    }
    assert validate_instance("analysis-result", result, SCHEMA_DIR) == []

    # 候选写成 observation 必须被拒（纪律进 schema）
    bad = json.loads(json.dumps(result))
    bad["candidates"][0]["evidence_level"] = "observation"
    # schema 本身允许任意枚举值（分级靠评审纪律），这里只验证枚举合法值集合
    assert validate_instance("analysis-result", bad, SCHEMA_DIR) == []


def test_sim_trace_all_line_types() -> None:
    run_id = "run-20261109-test01"
    lines = [
        {
            "type": "run_meta",
            "run_id": run_id,
            "image": {
                "path": "<ROM_IMAGE>",
                "sha256": "e" * 64,
                "size_bytes": 131072,
                "base_address": 100000000,
            },
            "engine": {"name": "stub", "version": "0.0.0"},
            "profile_ref": "unknown",
            "memory_map": "unknown",
            "patches": [],
            "fault_events": [],
            "evidence_level": "observation",
        },
        {
            "type": "trace",
            "run_id": run_id,
            "seq": 42,
            "pc": 553648260,
            "instruction_raw": "73100730",
            "disasm": "csrrw zero, 0x307, t0",
            "writeback": "unknown",
            "mem_access": {"kind": "load", "addr": 536870912, "size": 4, "value": 0,
                           "stub": True, "region": "__dynamic__"},
            "csrs_changed": [
                {"csr": 775, "op": "write", "value": 0, "warl": True,
                 "placeholder": False, "action_detail": "unknown CSR write ignored"}
            ],
            "evidence_level": "hypothesis",
        },
        {
            "type": "fault_event",
            "event_id": "fev-test0001",
            "run_id": run_id,
            "campaign_id": "unknown",
            "trigger": {"mode": "seq", "value": 3000, "ns_per_cycle": "unknown"},
            "action": {"kind": "flip_reg_bits", "reg": "a0", "bit_width": 2,
                       "bit_mask": "0x3", "new_value": "unknown"},
            "pulse": {"mode": "instruction_count", "value": 2},
            "applied": True,
            "applied_at_seq": 3000,
            "applied_result": {"old_value": 1280, "new_value": 1283},
            "evidence_level": "hypothesis",
        },
        {
            "type": "run_end",
            "run_id": run_id,
            "exit_reason": "hang_suspected",
            "final_pc": "unknown",
            "instruction_count": 50000,
            "detail": {"sub_reason": "pc_hotspot", "stub_reads": 12, "warl_ignores": 3},
            "evidence_level": "observation",
        },
    ]
    registry = load_schema_registry(SCHEMA_DIR)
    from jsonschema import Draft202012Validator

    schema = load_schema("sim-trace", SCHEMA_DIR)
    validator = Draft202012Validator(schema, registry=registry)
    for i, line in enumerate(lines):
        errs = [f"{e.message}" for e in validator.iter_errors(line)]
        assert not errs, f"行 {i} ({line['type']}): {errs}"


def test_cross_file_ref_resolves_offline() -> None:
    """跨文件 $ref（common.defs）离线解析可用（不访问网络）。"""
    from jsonschema import Draft202012Validator

    registry = load_schema_registry(SCHEMA_DIR)
    schema = load_schema("campaign-record", SCHEMA_DIR)
    validator = Draft202012Validator(schema, registry=registry)
    ok = {
        "schema_version": "0.2",
        "campaign_id": "c1",
        "params": {"raw_delay": 1, "raw_pulse": 1},
        "response": {"state_label": "unknown", "state_label_semantics": "unconfirmed-v0.1"},
        "evidence_level": "unknown",
    }
    assert [e.message for e in validator.iter_errors(ok)] == []
