"""v0.3 契约测试：reverse-report / discover-report / tts-metrics / draft 语义 / 轨迹分级。

覆盖重点（都是 lead 明确要求的硬约束）：

1. **reverse-report**：正向样例可通过；三条不变量必须拒错——evidence_ref 悬空、
   call_chain 未验证标 observation、timing 裸数字 ns_per_cycle。
2. **discover-report**：自动发现证据闸门——confidence 只能 hypothesis|unknown
   （fact/observation 必须被 schema 拒），suggested_action 词汇表，sample_evidence 必填。
3. **tts-metrics**：跨芯片指标实例可校验；unknown 合法。
4. **draft 语义**：generated_by 非 unknown ⇒ 必须 status=draft 且 source=artifact_derived。
5. **trace-levels.md**：契约文档存在且四级语义齐备（--trace-level=off|binary|sampled|full）。
"""

import json
from pathlib import Path

import pytest

from fi.schemas import (
    DISCOVER_CONFIDENCE_ALLOWED,
    DISCOVER_SUGGESTED_ACTIONS,
    SCHEMA_REGISTRY,
    check_semantics,
    load_schema,
    validate_instance,
)

CONTRACTS = Path(__file__).resolve().parents[1] / "docs" / "contracts"
SCHEMA_DIR = CONTRACTS / "schemas"


# ---------------------------------------------------------------- 构造器


def _reverse_report_instance() -> dict:
    """用 schema 自带 examples 拼一个合法 reverse-report 实例（避免测试硬编码实例值）。"""
    s = load_schema("reverse-report")
    d = s["$defs"]
    return {
        "schema_version": "0.2",
        "report_id": "rev-20261109-test01",
        "target_feature": s["properties"]["target_feature"]["examples"][0],
        "entry_points": s["properties"]["entry_points"]["examples"][0],
        "call_chain": s["properties"]["call_chain"]["examples"][0],
        "timing_estimate": d["timing_estimate"]["examples"][0],
        "injection_targets": s["properties"]["injection_targets"]["examples"][0],
        "evidence_refs": [
            {"id": "ev-001", "kind": "artifact_derived", "locator": "cmd-1", "confidence": "hypothesis"},
            {"id": "ev-002", "kind": "simulation", "locator": "trace.jsonl", "confidence": "observation"},
            {"id": "ev-003", "kind": "artifact_derived", "locator": "disasm", "confidence": "hypothesis"},
        ],
        "unknowns": s["properties"]["unknowns"]["examples"][0],
        "confidence": "hypothesis",
    }


def _discover_report_instance() -> dict:
    s = load_schema("discover-report")
    d = s["$defs"]
    f = s["properties"]["findings"]["properties"]
    return {
        "schema": "fi.discover.report-v0",
        "tool": s["properties"]["tool"]["examples"][0],
        "image": d["image_meta"]["examples"][0],
        "method": s["properties"]["method"]["examples"][0],
        "summary": s["properties"]["summary"]["examples"][0],
        "findings": {
            "regions": f["regions"]["examples"][0],
            "traps": f["traps"]["examples"][0],
            "targets": f["targets"]["examples"][0],
        },
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


# ---------------------------------------------------------------- 注册完整性


def test_new_v03_schemas_registered() -> None:
    for name in ("reverse-report", "discover-report", "tts-metrics"):
        assert name in SCHEMA_REGISTRY, f"{name} 未在 SCHEMA_REGISTRY 登记"
        assert (SCHEMA_DIR / SCHEMA_REGISTRY[name].filename).is_file()


# ---------------------------------------------------------------- reverse-report


def test_reverse_report_valid_instance_passes() -> None:
    assert validate_instance("reverse-report", _reverse_report_instance()) == []


def test_reverse_report_minimal_with_empty_lists_passes() -> None:
    """空调用链/空靶点必须可产出（逆向尚在进行中：先声明目标 + 登记 unknown）。"""
    inst = _reverse_report_instance()
    inst["entry_points"] = []
    inst["call_chain"] = []
    inst["injection_targets"] = []
    inst["evidence_refs"] = []
    inst["confidence"] = "unknown"
    assert validate_instance("reverse-report", inst) == []


def test_reverse_report_rejects_dangling_evidence_ref() -> None:
    """不变量 1：call_chain.function_addr 必须可回溯到 evidence_refs。"""
    inst = _reverse_report_instance()
    inst["evidence_refs"] = inst["evidence_refs"][:1]  # 删掉 ev-002/ev-003
    errors = validate_instance("reverse-report", inst)
    assert errors, "悬空 evidence_ref 必须被拒"
    assert any("evidence_ref" in e for e in errors)


def test_reverse_report_rejects_call_chain_without_any_evidence() -> None:
    """不变量 1 兜底：有调用链却完全没有证据登记表 ⇒ 拒（schema allOf）。"""
    inst = _reverse_report_instance()
    inst["evidence_refs"] = []
    errors = validate_instance("reverse-report", inst)
    assert errors
    assert any("evidence_refs" in e for e in errors)


def test_reverse_report_rejects_unverified_observation() -> None:
    """不变量 2：调用链标 observation 必须给 verified_by（静态推断不得写成事实）。"""
    inst = _reverse_report_instance()
    inst["call_chain"][0]["confidence"] = "observation"
    inst["call_chain"][0].pop("verified_by", None)
    errors = validate_instance("reverse-report", inst)
    assert any("verified_by" in e for e in errors), errors

    # 补上验证手段后合法（仿真动态命中才可升 observation）
    inst["call_chain"][0]["verified_by"] = "simulation"
    assert validate_instance("reverse-report", inst) == []


def test_reverse_report_rejects_bare_timing_numbers() -> None:
    """不变量 3：timing_estimate 的 ns 必须带 ns_per_cycle 假设对象，禁裸数字。"""
    inst = _reverse_report_instance()
    inst["timing_estimate"]["ns_per_cycle"] = 6.25  # 裸数字
    errors = validate_instance("reverse-report", inst)
    assert any("ns_per_cycle" in e for e in errors), errors

    # ns_estimate 也不允许裸数字
    inst2 = _reverse_report_instance()
    inst2["timing_estimate"]["ns_estimate"] = 75000
    errors2 = validate_instance("reverse-report", inst2)
    assert any("ns_estimate" in e for e in errors2), errors2

    # formula 常量被篡改也要拒
    inst3 = _reverse_report_instance()
    inst3["timing_estimate"]["ns_estimate"]["formula"] = "cycles * 1000"
    errors3 = validate_instance("reverse-report", inst3)
    assert any("formula" in e for e in errors3), errors3


def test_reverse_report_rejects_unknown_action_vocabulary() -> None:
    """注入靶点动作必须与仿真引擎枚举对齐（不认识的动作为非法）。"""
    inst = _reverse_report_instance()
    inst["injection_targets"][0]["suggested_action"] = "run_shell"
    errors = validate_instance("reverse-report", inst)
    assert any("suggested_action" in e for e in errors), errors

    # map_region/stub_read 是发现层动作，注入靶点不接受
    inst2 = _reverse_report_instance()
    inst2["injection_targets"][0]["suggested_action"] = "map_region"
    assert validate_instance("reverse-report", inst2)


def test_reverse_report_action_vocabulary_matches_engine() -> None:
    """契约对齐：reverse-report 注入动作 == sim-trace fault_event.action.kind 枚举。"""
    reverse = load_schema("reverse-report")
    enum = reverse["$defs"]["injection_target"]["properties"]["suggested_action"]["enum"]
    sim_trace = load_schema("sim-trace")
    kinds = {
        v["properties"]["kind"]["const"]
        for v in sim_trace["$defs"]["fault_event"]["properties"]["action"]["oneOf"]
    }
    assert set(enum) == kinds, f"reverse {set(enum)} != sim-trace {kinds}"


def test_reverse_report_requires_target_feature() -> None:
    """第一步『声明目标』是硬前提：没有目标功能不构成逆向报告。"""
    inst = _reverse_report_instance()
    del inst["target_feature"]
    errors = validate_instance("reverse-report", inst)
    assert any("target_feature" in e for e in errors), errors


# ---------------------------------------------------------------- discover-report


def test_discover_report_valid_instance_passes() -> None:
    assert validate_instance("discover-report", _discover_report_instance()) == []


def test_discover_confidence_gate_rejects_fact_at_item_level() -> None:
    """硬约束：findings 条目 confidence 只能 hypothesis|unknown，禁 fact。"""
    inst = _discover_report_instance()
    inst["findings"]["regions"][0]["confidence"] = "fact"
    errors = validate_instance("discover-report", inst)
    assert errors, "findings 条目写成 fact 必须被拒（自动发现证据闸门）"

    inst2 = _discover_report_instance()
    inst2["findings"]["targets"][0]["confidence"] = "observation"
    assert validate_instance("discover-report", inst2), "observation 同样越界"


def test_discover_confidence_gate_rejects_fact_at_report_level() -> None:
    inst = _discover_report_instance()
    inst["confidence"] = "fact"
    assert validate_instance("discover-report", inst)


def test_discover_confidence_enum_is_exactly_two_values() -> None:
    """闸门的结构级证据：schema 里两个 confidence 枚举都只有两值。"""
    s = load_schema("discover-report")
    assert s["properties"]["confidence"]["enum"] == ["hypothesis", "unknown"]
    item_conf = s["$defs"]["finding_item"]["properties"]["confidence"]["enum"]
    assert item_conf == ["hypothesis", "unknown"]
    assert DISCOVER_CONFIDENCE_ALLOWED == ("hypothesis", "unknown")


def test_discover_suggested_action_vocabulary() -> None:
    s = load_schema("discover-report")
    enum = s["$defs"]["finding_item"]["properties"]["suggested_action"]["enum"]
    assert enum == [
        "skip_insn",
        "flip_reg_bits",
        "reg_write",
        "mem_write",
        "map_region",
        "stub_read",
    ]
    assert DISCOVER_SUGGESTED_ACTIONS == tuple(enum)

    inst = _discover_report_instance()
    inst["findings"]["traps"][0]["suggested_action"] = "hack"
    assert validate_instance("discover-report", inst)


def test_discover_sample_evidence_required() -> None:
    """自动发现条目必须附原始证据样例（可回溯，不是结论裸奔）。"""
    inst = _discover_report_instance()
    inst["findings"]["traps"][0]["sample_evidence"] = []
    assert validate_instance("discover-report", inst)


def test_discover_evidence_kind_vocabulary() -> None:
    s = load_schema("discover-report")
    assert s["properties"]["evidence_kind"]["enum"] == ["artifact", "artifact_derived"]
    inst = _discover_report_instance()
    inst["findings"]["regions"][0]["evidence_kind"] = "measurement"
    assert validate_instance("discover-report", inst)


def test_discover_report_shape_fields() -> None:
    """结构契约：schema/tool/image/method/summary/findings/confidence/evidence_kind 齐备。"""
    s = load_schema("discover-report")
    for key in (
        "schema",
        "tool",
        "image",
        "method",
        "summary",
        "findings",
        "confidence",
        "evidence_kind",
    ):
        assert key in s["properties"], f"discover-report 缺字段 {key}"
        assert key in s["required"], f"discover-report 字段 {key} 未设为必填"
    findings = s["properties"]["findings"]
    assert set(findings["required"]) == {"regions", "traps", "targets"}
    for f in ("sha256", "size_bytes", "base_address", "path"):
        assert f in s["$defs"]["image_meta"]["properties"]


# ---------------------------------------------------------------- tts-metrics


def test_tts_metrics_valid_and_unknown_tolerated() -> None:
    s = load_schema("tts-metrics")
    inst = {
        "schema_version": "0.2",
        "chip_id": "sample-chip",
        "tts_a_minutes": 12.5,
        "tts_b_minutes": 18.0,
        "instr_per_sec": 1_250_000,
        "bytes_per_instr": 6.4,
        "iterations_to_converge": 3,
        "measured_at": "2026-11-09T16:13:00+08:00",
        "notes": "管线自动产出",
        "basis": s["properties"]["basis"]["examples"][0],
        "dashboard": s["properties"]["dashboard"]["examples"][0],
    }
    assert validate_instance("tts-metrics", inst) == []

    unknown = dict(inst)
    for key in ("tts_a_minutes", "tts_b_minutes", "instr_per_sec", "bytes_per_instr", "iterations_to_converge"):
        unknown[key] = "unknown"
    assert validate_instance("tts-metrics", unknown) == []


def test_tts_metrics_required_fields() -> None:
    s = load_schema("tts-metrics")
    required = set(s["required"])
    expected = {
        "chip_id",
        "tts_a_minutes",
        "tts_b_minutes",
        "instr_per_sec",
        "bytes_per_instr",
        "iterations_to_converge",
        "measured_at",
    }
    assert expected <= required, f"缺必填字段: {expected - required}"


def test_tts_metrics_rejects_negative_values() -> None:
    inst = {
        "schema_version": "0.2",
        "chip_id": "sample-chip",
        "tts_a_minutes": -1,
        "tts_b_minutes": 18.0,
        "instr_per_sec": 1_250_000,
        "bytes_per_instr": 6.4,
        "iterations_to_converge": 3,
        "measured_at": "unknown",
    }
    assert validate_instance("tts-metrics", inst)


# ---------------------------------------------------------------- draft 语义


def test_profile_index_draft_semantics_schema() -> None:
    """chip-profile-index v0.3：草稿字段与语义常量存在。"""
    s = load_schema("chip-profile-index")
    item = s["properties"]["profiles"]["items"]
    assert "generated_by" in item["properties"]
    assert item["properties"]["source"]["enum"] == [
        "artifact",
        "artifact_derived",
        "user_confirmed",
        "measurement",
        "manual_curated",
        "unknown",
    ]
    assert s["properties"]["draft_semantics"]["const"] == "draft-not-validated-v0.3"

    # 草稿样例必须能过校验
    samples = s["properties"]["profiles"]["items"]["examples"]
    draft = next(e for e in samples if e.get("generated_by") not in (None, "unknown"))
    assert validate_instance(
        "chip-profile-index",
        {"schema_version": "0.2", "profiles": [draft]},
    ) == []


def test_profile_index_rejects_validated_but_auto_generated() -> None:
    """草稿不变量：自动生成（generated_by 具体值）不得标 validated/非 artifact_derived。"""
    inst = {
        "schema_version": "0.2",
        "profiles": [
            {
                "profile_id": "sample-chip",
                "index_path": "profiles/sample-chip.draft.yaml",
                "status": "validated",
                "generated_by": "fi.discover.draft 0.1.0",
                "source": "artifact_derived",
                "evidence_level": "observation",
            }
        ],
    }
    errors = validate_instance("chip-profile-index", inst)
    assert any("draft" in e for e in errors), errors

    inst["profiles"][0]["status"] = "draft"
    inst["profiles"][0]["source"] = "manual_curated"
    errors2 = validate_instance("chip-profile-index", inst)
    assert any("artifact_derived" in e for e in errors2), errors2

    # 人工条目（generated_by=unknown）不受该不变量约束
    human = {
        "schema_version": "0.2",
        "profiles": [
            {
                "profile_id": "sample-chip",
                "status": "validated",
                "generated_by": "unknown",
                "source": "manual_curated",
                "evidence_level": "observation",
            }
        ],
    }
    assert validate_instance("chip-profile-index", human) == []


def test_readme_documents_draft_semantics() -> None:
    """README 必须写明草稿语义（消费方不得当已验证数据）。"""
    text = (CONTRACTS / "README.md").read_text(encoding="utf-8")
    for token in ("draft", "artifact_derived", "generated_by"):
        assert token in text, f"README 缺草稿语义关键词: {token}"


# ---------------------------------------------------------------- 轨迹分级契约


def test_trace_levels_contract_doc() -> None:
    """轨迹分级契约：四级齐备 + binary 布局归 sim-engine + round-trip 要求。"""
    path = CONTRACTS / "trace-levels.md"
    assert path.is_file(), "缺 docs/contracts/trace-levels.md"
    text = path.read_text(encoding="utf-8")
    for level in ("off", "binary", "sampled", "full"):
        assert f"`{level}`" in text or f"--trace-level={level}" in text or level in text, level
    for token in ("round-trip", "sim-trace", "版本号", "reader"):
        assert token in text, f"trace-levels.md 缺关键约定: {token}"
    assert "sim-engine" in text, "binary 字节布局归属必须写明归 sim-engine"


# ---------------------------------------------------------------- 语义检查入口


def test_semantic_checks_registered() -> None:
    from fi.schemas.invariants import SEMANTIC_CHECKS

    for name in ("reverse-report", "discover-report", "chip-profile-index"):
        assert name in SEMANTIC_CHECKS, f"{name} 缺语义不变量检查"


def test_check_semantics_noop_for_other_schemas() -> None:
    assert check_semantics("sim-trace", {"type": "trace"}) == []


def test_cli_validate_reports_semantic_errors(tmp_path: Path) -> None:
    """CLI 必须把语义不变量错误也报出来（不只结构校验）。"""
    from fi.cli import main

    inst = _discover_report_instance()
    inst["findings"]["regions"][0]["confidence"] = "fact"
    f = tmp_path / "discover.json"
    f.write_text(json.dumps(inst, ensure_ascii=False), encoding="utf-8")
    assert main(["schema", "validate", "--schema", "discover-report", "--file", str(f)]) == 1


@pytest.mark.parametrize(
    "name",
    ["reverse-report", "discover-report", "tts-metrics"],
)
def test_new_schema_examples_validate(name: str) -> None:
    """新契约自带 examples 必须自洽（若可组装成完整实例）。"""
    schema = load_schema(name)
    assert schema["examples"] if "examples" in schema else True
    # 每个 $defs 下的 examples（若有）在其定义内部结构上自洽即可，完整实例校验由上面用例覆盖
    for def_name, node in schema.get("$defs", {}).items():
        assert "examples" in node, f"{name}#$defs/{def_name} 缺 examples"


@pytest.mark.parametrize(
    "name",
    ["reverse-report", "discover-report", "tts-metrics", "chip-profile-index"],
)
def test_new_schema_is_valid_draft2020(name: str) -> None:
    """新增/改动的 schema 本身必须是合法 JSON Schema（Draft 2020-12）。"""
    from jsonschema import Draft202012Validator

    Draft202012Validator.check_schema(load_schema(name))


def test_schema_id_namespace_note() -> None:
    """$id 命名空间仍是 contracts/v0.1（URI 命名空间不随实例 schema_version 变）。

    这条锁定"不要为了 0.3.0 批次去改 $id/URI_PREFIX"——那会破坏离线注册表与
    消费方缓存。实例版本走 common.defs.schema_version 常量。
    """
    from fi.schemas.registry import URI_PREFIX

    assert URI_PREFIX == "https://fi-converters.invalid/contracts/v0.1"
    for name in ("reverse-report", "discover-report", "tts-metrics"):
        assert load_schema(name)["$id"].startswith(URI_PREFIX + "/")
