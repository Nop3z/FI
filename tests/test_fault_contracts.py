"""v0.4 故障效果推演契约测试：fault-effect / fault-explanation / observation-classification。

覆盖 lead 指定的两条核心纪律（都是"防止把猜测当事实"）：

1. **confidence 闸门**：三者的 confidence 都不得为 fact。
   - fault-effect / fault-explanation 恒 hypothesis（候选解释）；
   - observation-classification 恒 observation（机械比对）。
2. **多解纪律**：fault-explanation 的 candidates 为空必须有 reason；
   multiple_solutions=true 时要求 candidates.length >= 2。

另覆盖：kind↔label 配对、is_interesting 与 kind 一致、位位置越界、
change_kind 与 semantics_changed/undecodable 自洽、CLI 三命令端到端。
"""

import json
from pathlib import Path

import pytest

from fi.schemas import SCHEMA_REGISTRY, load_schema, validate_instance
from fi.schemas.invariants import KIND_LABEL_PAIRS, SEMANTIC_CHECKS


# ---------------------------------------------------------------- 构造器


def _effect_instance() -> dict:
    s = load_schema("fault-effect")
    return {
        "schema_version": "0.2",
        "report_id": "fe-test-0001",
        "original_insn": s["properties"]["original_insn"]["examples"][0],
        "physical_assumption": s["properties"]["physical_assumption"]["examples"][0],
        "variants": s["properties"]["variants"]["examples"][0],
        "summary": s["properties"]["summary"]["examples"][0],
        "confidence": "hypothesis",
    }


def _explanation_instance(n_candidates: int = 1) -> dict:
    s = load_schema("fault-explanation")
    cand = s["$defs"]["candidate"]["examples"][0]
    cands = []
    for i in range(n_candidates):
        c = json.loads(json.dumps(cand))
        c["flipped_bit_positions"] = [i]
        cands.append(c)
    return {
        "schema_version": "0.2",
        "report_id": "fx-test-0001",
        "observation": s["properties"]["observation"]["examples"][0],
        "pre_state": s["properties"]["pre_state"]["examples"][0],
        "candidates": cands,
        "summary": {
            "multiple_solutions": n_candidates > 1,
            "n_candidates": n_candidates,
        },
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


def _classification_instance(kind: str = "target_hit") -> dict:
    s = load_schema("observation-classification")
    label = KIND_LABEL_PAIRS[kind]
    ev = json.loads(json.dumps(s["properties"]["evidence"]["examples"][0]))
    if kind == "target_hit":
        ev.update({"pc_ok": True, "target_reg_ok": False, "other_regs_changed": True,
                   "restarted": False})
    elif kind == "normal":
        ev.update({"pc_ok": True, "target_reg_ok": True, "other_regs_changed": False,
                   "restarted": False})
    elif kind == "restart":
        ev.update({"restarted": True})
    elif kind == "pc_wrong":
        ev.update({"pc_ok": False, "restarted": False})
    elif kind == "missed_target":
        ev.update({"pc_ok": True, "target_reg_ok": True, "other_regs_changed": True,
                   "restarted": False})
    return {
        "schema_version": "0.2",
        "classification_id": "oc-test-0001",
        "kind": kind,
        "label": label,
        "is_interesting": kind == "target_hit",
        "confidence": "observation",
        "evidence": ev,
    }


# ---------------------------------------------------------------- 注册与文件


@pytest.mark.parametrize(
    "name", ["fault-effect", "fault-explanation", "observation-classification"]
)
def test_v04_schemas_registered_and_loadable(name: str) -> None:
    assert name in SCHEMA_REGISTRY
    schema = load_schema(name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    from jsonschema import Draft202012Validator

    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize(
    "name", ["fault-effect", "fault-explanation", "observation-classification"]
)
def test_v04_semantic_checks_registered(name: str) -> None:
    assert name in SEMANTIC_CHECKS


# ---------------------------------------------------------------- fault-effect


def test_fault_effect_valid_instance() -> None:
    assert validate_instance("fault-effect", _effect_instance()) == []


def test_fault_effect_confidence_never_fact() -> None:
    """硬约束：枚举是候选解释，confidence 恒 hypothesis，禁 fact/observation。"""
    inst = _effect_instance()
    for bad in ("fact", "observation", "unknown"):
        inst["confidence"] = bad
        errors = validate_instance("fault-effect", inst)
        assert errors, f"顶层 confidence={bad} 必须被拒"

    inst2 = _effect_instance()
    inst2["variants"][0]["confidence"] = "fact"
    assert validate_instance("fault-effect", inst2), "变体级也不得是 fact"

    # 物理假设同样是 hypothesis
    inst3 = _effect_instance()
    inst3["physical_assumption"]["confidence"] = "observation"
    assert validate_instance("fault-effect", inst3)


def test_fault_effect_required_fields() -> None:
    s = load_schema("fault-effect")
    assert {"original_insn", "physical_assumption", "variants", "summary", "confidence"} <= set(
        s["required"]
    )
    variant_req = set(s["$defs"]["variant"]["required"])
    assert {"flipped_bit_positions", "mutated_code_hex", "change_kind",
            "semantics_changed"} <= variant_req
    # original_insn 三件套
    assert set(s["properties"]["original_insn"]["required"]) == {"bytes_hex", "addr", "disasm"}
    # change_kind 枚举完整（七类）
    enum = s["$defs"]["variant"]["properties"]["change_kind"]["enum"]
    assert enum == ["same", "rd_changed", "rs_changed", "imm_changed",
                    "opcode_changed", "undecodable", "nop_like"]


def test_fault_effect_flip_mode_enum() -> None:
    s = load_schema("fault-effect")
    enum = s["properties"]["physical_assumption"]["properties"]["flip_mode"]["enum"]
    assert enum == ["one_to_zero", "zero_to_one", "both"]


def test_fault_effect_bit_position_out_of_range_rejected() -> None:
    """位位置越界 → 拒（说明算错，不是数据问题）。"""
    inst = _effect_instance()
    inst["variants"][0]["flipped_bit_positions"] = [999]
    errors = validate_instance("fault-effect", inst)
    assert any("越界" in e for e in errors), errors


def test_fault_effect_change_kind_consistency() -> None:
    inst = _effect_instance()
    # undecodable 却给了反汇编 → 拒
    inst["variants"][0].update({"change_kind": "undecodable", "mutated_insn": "addi a0, a0, 2"})
    assert validate_instance("fault-effect", inst)

    # same 却 semantics_changed=true → 拒
    inst2 = _effect_instance()
    inst2["variants"][0].update({"change_kind": "same", "semantics_changed": True})
    assert validate_instance("fault-effect", inst2)

    # imm_changed 却 semantics_changed=false → 拒
    inst3 = _effect_instance()
    inst3["variants"][0].update({"change_kind": "imm_changed", "semantics_changed": False})
    assert validate_instance("fault-effect", inst3)


def test_fault_effect_mutated_code_length_must_match() -> None:
    inst = _effect_instance()
    inst["variants"][0]["mutated_code_hex"] = "12"  # 长度不符
    errors = validate_instance("fault-effect", inst)
    assert any("mutated_code_hex" in e for e in errors), errors


def test_fault_effect_empty_variants_requires_reason() -> None:
    inst = _effect_instance()
    inst["variants"] = []
    inst["summary"] = {
        "by_change_kind": {},
        "n_variants_total": 0,
        "n_variants_semantically_changed": 0,
    }
    errors = validate_instance("fault-effect", inst)
    assert errors, "variants 为空必须有 reason"

    inst["summary"]["reason"] = "max_flips 上限导致组合数截断"
    assert validate_instance("fault-effect", inst) == []


# ---------------------------------------------------------------- fault-explanation


def test_fault_explanation_valid_single_and_multi() -> None:
    assert validate_instance("fault-explanation", _explanation_instance(1)) == []
    assert validate_instance("fault-explanation", _explanation_instance(2)) == []


def test_fault_explanation_confidence_never_fact() -> None:
    inst = _explanation_instance()
    inst["confidence"] = "fact"
    assert validate_instance("fault-explanation", inst)

    inst2 = _explanation_instance()
    inst2["candidates"][0]["confidence"] = "observation"
    assert validate_instance("fault-explanation", inst2)


def test_fault_explanation_multiple_solutions_requires_two_candidates() -> None:
    """硬约束：multiple_solutions=true ⇒ candidates.length ≥ 2。"""
    inst = _explanation_instance(1)
    inst["summary"] = {"multiple_solutions": True, "n_candidates": 1}
    errors = validate_instance("fault-explanation", inst)
    assert errors, "多解标志为 true 但只有 1 条候选必须被拒"
    assert any("candidates" in e or "multiple_solutions" in e for e in errors), errors


def test_fault_explanation_flag_must_match_candidate_count() -> None:
    # 多条候选却声称单解 → 拒
    inst = _explanation_instance(2)
    inst["summary"] = {"multiple_solutions": False, "n_candidates": 2}
    assert validate_instance("fault-explanation", inst)

    # 摘要条数与实际不符 → 拒
    inst2 = _explanation_instance(1)
    inst2["summary"] = {"multiple_solutions": False, "n_candidates": 5}
    assert validate_instance("fault-explanation", inst2)


def test_fault_explanation_empty_candidates_requires_reason() -> None:
    inst = _explanation_instance(0)
    errors = validate_instance("fault-explanation", inst)
    assert errors, "candidates 为空必须有 reason"

    inst["reason"] = "无变体能复现观测（求值层不支持该指令形态）"
    assert validate_instance("fault-explanation", inst) == []


def test_fault_explanation_unknown_reason_not_accepted() -> None:
    """reason 写 unknown 不算解释（等于没给原因）。"""
    inst = _explanation_instance(0)
    inst["reason"] = "unknown"
    assert validate_instance("fault-explanation", inst)


def test_fault_explanation_simulation_flag_consistency() -> None:
    inst = _explanation_instance()
    inst["simulation_verification"] = {
        "executed": False,
        "matches_observation": True,  # 自相矛盾
    }
    errors = validate_instance("fault-explanation", inst)
    assert any("simulation" in e for e in errors), errors


def test_fault_explanation_match_score_range() -> None:
    inst = _explanation_instance()
    inst["candidates"][0]["match_score"] = 1.5
    assert validate_instance("fault-explanation", inst)


def test_fault_explanation_requires_evidence_kind() -> None:
    inst = _explanation_instance()
    del inst["evidence_kind"]
    assert validate_instance("fault-explanation", inst)


# ---------------------------------------------------------------- observation-classification


@pytest.mark.parametrize(
    "kind",
    ["normal", "restart", "pc_wrong", "missed_target", "target_hit"],
)
def test_classification_all_five_kinds(kind: str) -> None:
    inst = _classification_instance(kind)
    assert validate_instance("observation-classification", inst) == [], kind
    assert inst["label"] == KIND_LABEL_PAIRS[kind]


def test_classification_confidence_never_hypothesis_or_fact() -> None:
    """硬约束：五色分类是机械比对，confidence 恒 observation。"""
    inst = _classification_instance()
    for bad in ("hypothesis", "unknown", "fact"):
        inst["confidence"] = bad
        errors = validate_instance("observation-classification", inst)
        assert errors, f"confidence={bad} 必须被拒（分类=机械判定，恒 observation）"


def test_classification_kind_label_pairing_enforced() -> None:
    """kind ↔ label 必须固定配对（错配会让 UI 颜色语义错乱）。"""
    for kind, label in KIND_LABEL_PAIRS.items():
        inst = _classification_instance(kind)
        wrong = next(v for v in KIND_LABEL_PAIRS.values() if v != label)
        inst["label"] = wrong
        assert validate_instance("observation-classification", inst), (kind, wrong)


def test_classification_is_interesting_only_for_target_hit() -> None:
    inst = _classification_instance("normal")
    inst["is_interesting"] = True
    errors = validate_instance("observation-classification", inst)
    assert errors

    inst2 = _classification_instance("target_hit")
    inst2["is_interesting"] = False
    assert validate_instance("observation-classification", inst2)


def test_classification_kind_must_match_evidence() -> None:
    """标签必须与证据（pc_ok/target_reg_ok/...）自洽，不得自相矛盾。"""
    inst = _classification_instance("target_hit")
    inst["evidence"]["target_reg_ok"] = True  # 与 target_hit 矛盾
    errors = validate_instance("observation-classification", inst)
    assert any("kind" in e for e in errors), errors


def test_classification_kind_enum_and_label_enum() -> None:
    s = load_schema("observation-classification")
    assert s["properties"]["kind"]["enum"] == [
        "normal", "restart", "pc_wrong", "missed_target", "target_hit"
    ]
    assert s["properties"]["label"]["enum"] == ["绿", "品红", "黄", "青", "红"]
    assert s["properties"]["confidence"]["const"] == "observation"


def test_classification_kind_label_pairs_def_matches_constants() -> None:
    """契约里的配对表常量必须与代码常量一致（防两处漂移）。"""
    s = load_schema("observation-classification")
    pairs = s["$defs"]["kind_label_pairs"]
    for kind, label in KIND_LABEL_PAIRS.items():
        assert pairs["properties"][kind]["const"] == label, kind


# ---------------------------------------------------------------- 契约构造层


def test_builder_effect_from_module_variants() -> None:
    """构造器把 effects.Variant 转成契约实例并自校验。"""
    pytest.importorskip("capstone", reason="fault.effects 需要 capstone")
    from fi.fault.effects import enumerate_bitflips
    from fi.schemas.fault_report import build_fault_effect

    variants = enumerate_bitflips(bytes.fromhex("13051700"), 0x1000, max_flips=2)
    report = build_fault_effect(
        insn_hex="13051700", addr=0x1000, variants=variants, disasm="addi a0, a0, 1"
    )
    assert validate_instance("fault-effect", report) == []
    assert report["confidence"] == "hypothesis"
    assert report["summary"]["n_variants_total"] == len(variants)


def test_builder_effect_empty_gives_reason() -> None:
    from fi.schemas.fault_report import build_fault_effect

    report = build_fault_effect(insn_hex="00000000", addr=0, variants=[])
    assert report["variants"] == []
    assert report["summary"]["reason"] != "unknown"
    assert validate_instance("fault-effect", report) == []


def test_builder_explanation_multiple_solutions_auto() -> None:
    """多解标志由候选数自动推导，调用方无法伪造单解。"""
    from fi.schemas.fault_report import build_fault_explanation

    base = {
        "flipped_bit_positions": [0],
        "predicted_regs": {"a0": 1},
        "match_score": 1.0,
    }
    one = build_fault_explanation(
        observation={"regs": {"a0": 1}}, pre_state={"regs": {"a0": 0}}, candidates=[base]
    )
    assert one["summary"]["multiple_solutions"] is False
    assert validate_instance("fault-explanation", one) == []

    two = build_fault_explanation(
        observation={"regs": {"a0": 1}},
        pre_state={"regs": {"a0": 0}},
        candidates=[base, {**base, "flipped_bit_positions": [1]}],
    )
    assert two["summary"]["multiple_solutions"] is True
    assert two["summary"]["n_candidates"] == 2
    assert validate_instance("fault-explanation", two) == []


def test_builder_explanation_empty_gives_reason() -> None:
    from fi.schemas.fault_report import build_fault_explanation

    report = build_fault_explanation(
        observation={"regs": {"a0": 1}}, pre_state={"regs": {"a0": 0}}, candidates=[]
    )
    assert report["reason"] != "unknown"
    assert validate_instance("fault-explanation", report) == []


def test_builder_classification_derives_label_from_kind() -> None:
    """label/is_interesting 只能由 kind 推导，调用方无权重写。"""
    from fi.schemas.fault_report import build_observation_classification

    for kind_evidence, expected in (
        ({"pc_ok": True, "target_reg_ok": False}, "target_hit"),
        ({"pc_ok": True, "target_reg_ok": True, "other_regs_changed": False}, "normal"),
        ({"restarted": True}, "restart"),
        ({"pc_ok": False, "restarted": False}, "pc_wrong"),
        ({"pc_ok": True, "target_reg_ok": True, "other_regs_changed": True}, "missed_target"),
    ):
        report = build_observation_classification(**kind_evidence)
        assert report["kind"] == expected, kind_evidence
        assert report["label"] == KIND_LABEL_PAIRS[expected]
        assert report["is_interesting"] is (expected == "target_hit")
        assert report["confidence"] == "observation"
        assert validate_instance("observation-classification", report) == []


# ---------------------------------------------------------------- CLI 端到端


def test_cli_fault_group_registered() -> None:
    from fi.cli import COMMANDS
    from fi.cli_plugins import register_optional_commands

    register_optional_commands()
    for name in ("enumerate", "explain", "classify"):
        assert ("fault", name) in COMMANDS, f"fi fault {name} 未注册"


def test_cli_fault_enumerate_end_to_end(tmp_path: Path) -> None:
    pytest.importorskip("capstone", reason="fault.effects 需要 capstone")
    from fi.cli import main

    out = tmp_path / "effect.json"
    rc = main([
        "fault", "enumerate",
        "--insn-bytes", "13051700",
        "--addr", "0x1000",
        "--max-flips", "2",
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["confidence"] == "hypothesis"
    assert validate_instance("fault-effect", data) == []
    assert data["variants"]


def test_cli_fault_classify_end_to_end(tmp_path: Path) -> None:
    from fi.cli import main

    out = tmp_path / "class.json"
    rc = main([
        "fault", "classify",
        "--pc-ok", "--target-reg-wrong", "--others-changed",
        "--target-reg", "a6",
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["kind"] == "target_hit"
    assert data["label"] == "红"
    assert data["is_interesting"] is True
    assert validate_instance("observation-classification", data) == []


def test_cli_fault_explain_end_to_end(tmp_path: Path) -> None:
    pytest.importorskip("capstone", reason="fault.reasoning 需要 capstone")
    from fi.cli import main

    pre = tmp_path / "pre.json"
    pre.write_text('{"a0": "0x1000"}', encoding="utf-8")
    obs = tmp_path / "obs.json"
    obs.write_text('{"a0": "0x1002"}', encoding="utf-8")
    out = tmp_path / "explain.json"

    rc = main([
        "fault", "explain",
        "--insn-bytes", "13051700",
        "--addr", "0x1000",
        "--pre-regs", f"@{pre}",
        "--observed-regs", f"@{obs}",
        "--max-flips", "2",
        "--no-simulate",
        "--out", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["confidence"] == "hypothesis"
    assert validate_instance("fault-explanation", data) == []
    # 空解必须有 reason（构造器自动填）
    if not data["candidates"]:
        assert data["reason"] != "unknown"


def test_cli_fault_explain_tolerates_bom_json_file(tmp_path: Path) -> None:
    """@file 读 JSON 必须容忍 BOM（Windows 工具常见产物）。"""
    pytest.importorskip("capstone", reason="fault.reasoning 需要 capstone")
    from fi.cli import main

    pre = tmp_path / "pre_bom.json"
    pre.write_text('{"a0": "0x1000"}', encoding="utf-8-sig")  # 带 BOM
    obs = tmp_path / "obs_bom.json"
    obs.write_text('{"a0": "0x1002"}', encoding="utf-8-sig")
    out = tmp_path / "explain_bom.json"

    rc = main([
        "fault", "explain",
        "--insn-bytes", "13051700",
        "--addr", "0x1000",
        "--pre-regs", f"@{pre}",
        "--observed-regs", f"@{obs}",
        "--max-flips", "1",
        "--no-simulate",
        "--out", str(out),
    ])
    assert rc == 0, "带 BOM 的 JSON 文件不应导致解析失败"


def test_cli_fault_enumerate_rejects_bad_hex(tmp_path: Path) -> None:
    from fi.cli import main

    assert main(["fault", "enumerate", "--insn-bytes", "zzzz", "--addr", "0x1000"]) == 1
    assert main(["fault", "enumerate", "--insn-bytes", "", "--addr", "0x1000"]) == 1


def test_cli_fault_classify_requires_both_axes() -> None:
    """缺 PC 或目标寄存器判定 → argparse 用法错误（退出码 2）。"""
    from fi.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["fault", "classify", "--pc-ok"])
    assert exc.value.code == 2
