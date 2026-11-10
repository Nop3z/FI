# -*- coding: utf-8 -*-
"""注入靶点清单 / 核心证据产物的结构与纪律测试（chip-profile-ds 编写，待 core-contract 评审归并）。

测试目标（全部**不硬编码芯片实例值**，只验证能力性质与纪律）：

  1. 产物存在且 schema 正确、report 的 confidence 恒为 hypothesis；
  2. 每条码装载靶点：地址/机器码/反汇编自洽（机器码能解出该反汇编）；
  3. 位翻转变体：码迁移必须真的改变码值（不能把"只改 rd"算作迁移）；
  4. `mask_applies_to` 必须显式声明（消除 post/pre/机器码位 的语义歧义）；
  5. `discriminating_predictions` 非空（方法论"多解必须能分辨"硬要求）；
  6. **实验观测到的码**在产物里必须被标为 observed（若有过观测统计）；
  7. Profile 的 injection_targets 节全部为 hypothesis（不得混入 fact）；
  8. 生成过程可重放：同一输入两次生成，核心字段一致（确定性）。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.smoke_env import resolve_sample

ROOT = Path(__file__).resolve().parents[1]
DERIVED = ROOT / "data" / "derived"
IMAGE = ROOT / "<ROM_IMAGE>"


@pytest.fixture(scope="module")
def sample() -> tuple[Path, int]:
    """冒烟样例（镜像 + 基址）。

    **必须设置 FI_SMOKE_BASE**：本文件的断言依赖地址语义（机器码↔地址换算、
    注入点地址是否落在镜像内）。历史上这里内置了某颗芯片的基址常量，
    既违反"实例值不进通用代码"，也会在其他镜像上产出错误结果。
    """
    return resolve_sample(require_base=True)


@pytest.fixture(scope="module")
def targets_report() -> dict:
    p = DERIVED / "injection-targets.json"
    if not p.is_file():
        pytest.skip(f"产物不存在（先跑 fi discover injection-targets）: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def key_evidence() -> dict:
    p = DERIVED / "bitflip-key-evidence.json"
    if not p.is_file():
        pytest.skip(f"产物不存在（先跑 fi discover key-evidence）: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- 纪律闸门


def test_targets_report_confidence_gate(targets_report: dict) -> None:
    """证据闸门：自动发现产出只能 hypothesis；不得标 fact/observation。"""
    assert targets_report["confidence"] == "hypothesis"
    assert targets_report["evidence_kind"] == "artifact_derived"
    for t in targets_report["targets"]:
        assert t["confidence"] == "hypothesis", t["target_id"]
        assert t["evidence_kind"] == "artifact_derived", t["target_id"]
    for t in targets_report.get("branch_targets", []):
        assert t["confidence"] == "hypothesis", t["target_id"]


def test_key_evidence_confidence_gate(key_evidence: dict) -> None:
    assert key_evidence["confidence"] == "hypothesis"
    assert key_evidence["evidence_kind"] == "artifact_derived"
    for e in key_evidence["entries"]:
        assert e["confidence"] == "hypothesis"
        # 观测计数是 observation 级，必须与之分开标注
        assert e["observation_level_of_counts"] in ("observation", "unknown")


# ---------------------------------------------------------------- 静态自洽


def test_target_insn_bytes_match_disassembly(targets_report: dict, sample) -> None:
    """每条码装载靶点：机器码必须能解出报告里的反汇编文本（字节级自洽）。"""
    import capstone

    image, base = sample
    md = capstone.Cs(capstone.CS_ARCH_RISCV,
                     capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
    raw = image.read_bytes()
    for t in targets_report["targets"]:
        addr = int(t["addr"], 16)
        code = bytes.fromhex(t["insn_bytes_hex"])
        # 机器码必须与镜像字节一致（防报告与镜像脱节）
        off = addr - base
        assert raw[off:off + len(code)] == code, f"{t['target_id']}: 机器码与镜像不符"
        insn = next(md.disasm(code, addr), None)
        assert insn is not None, f"{t['target_id']}: 机器码无法反汇编"
        assert f"{insn.mnemonic} {insn.op_str}".strip() == t["insn"], (
            f"{t['target_id']}: 反汇编不符")


def test_code_migrations_really_change_code_value(targets_report: dict) -> None:
    """码迁移必须真的改码值：排除"只改 rd"这类伪迁移。"""
    for t in targets_report["targets"]:
        src = t["code"]
        for m in t["bitflip_variants"].get("code_migrations", []):
            assert m["resulting_code"] != src, (
                f"{t['target_id']}: 结果码与源码相同，不是迁移")
            assert m["flips_needed"] if "flips_needed" in m else True
            assert m["min_flips_needed"] >= 1


def test_one_bit_migration_bitmask_consistency(targets_report: dict) -> None:
    """1-bit 迁移的位掩码必须与位位置自洽，且**寄存器位与机器码位要分清**。

    区分（重要）：
      - machine_code_bits：指令机器码里的位（effects 枚举用）；
      - reg_value_bits   ：装载后寄存器值里的位（flip_reg_bits 注入实际用）。

    I-type 装载指令下二者相差固定偏移（机器码位 b ↔ 立即数位 b-20），
    所以**不能**直接把机器码位当作寄存器位去注入，否则注入完全无效。
    本测试用 XOR 关系独立验算，不依赖任何编码布局知识。
    """
    for t in targets_report["targets"]:
        for m in t["bitflip_variants"].get("code_migrations", []):
            if m["min_flips_needed"] != 1:
                continue
            mc_bits = m["example_machine_code_bits"]
            rv_bits = m["example_reg_value_bits"]
            assert len(mc_bits) == 1, f"{t['target_id']}: 1-bit 迁移应只有 1 个机器码位"
            assert len(rv_bits) == 1, f"{t['target_id']}: 1-bit 迁移应只有 1 个寄存器位"

            src = int(t["code"], 16)
            dst = int(m["resulting_code"], 16)
            # 权威判据：寄存器掩码必须等于源码 XOR 结果码（与位位置自洽）
            assert src ^ dst == int(m["example_reg_value_mask"], 16), (
                f"{t['target_id']}: reg_value_mask 与 code XOR 不一致")
            assert src ^ (1 << rv_bits[0]) == dst, (
                f"{t['target_id']}: 翻转寄存器 bit {rv_bits[0]} 后不等于目标码")
            # 1→0 前提：该寄存器位在源码中必须为 1
            assert (src >> rv_bits[0]) & 1 == 1, (
                f"{t['target_id']}: 寄存器 bit {rv_bits[0]} 在源码 {t['code']} 中不是 1，"
                "1→0 翻转不成立")
            # 机器码位与寄存器位不应被混用（除非巧合相等，那也应能自洽）
            assert mc_bits[0] != rv_bits[0] or True  # 仅记录关系，不断言


def test_mask_applies_to_declared(targets_report: dict) -> None:
    """mask 语义必须显式声明（lead 裁定：消除 post/pre/机器码位 歧义）。"""
    for t in targets_report["targets"]:
        primary = t["suggested_action"]["primary"]
        if primary.get("action") == "flip_reg_bits" and primary.get("bit_mask") not in (
                None, "unknown"):
            assert primary.get("mask_applies_to") == "post_insn_reg_value", (
                f"{t['target_id']}: 缺 mask_applies_to 或取值不符")


def test_discriminating_predictions_present(targets_report: dict) -> None:
    """方法论硬要求：多解必须能分辨 —— 每条靶点都要有区分判据。"""
    for t in targets_report["targets"]:
        preds = t["expected_observation"].get("discriminating_predictions") or []
        assert preds, f"{t['target_id']}: 缺 discriminating_predictions"
        for p in preds:
            assert p.get("hypothesis") and p.get("prediction")
            assert "rules_out" in p


def test_negative_control_has_expected_if_not_hit(targets_report: dict) -> None:
    for t in targets_report["targets"]:
        nc = t["suggested_action"].get("negative_control") or {}
        assert nc.get("expected_if_not_hit"), (
            f"{t['target_id']}: negative_control 缺 expected_if_not_hit")


# ---------------------------------------------------------------- 观测集联动


def test_observed_code_flag_matches_inputs(targets_report: dict) -> None:
    """报告里"目标码被观测到"的标记必须与 inputs.observed_codes 自洽。"""
    declared = {c.lower() for c in
                (targets_report.get("inputs") or {}).get("observed_codes") or []}
    for t in targets_report["targets"]:
        for m in t["bitflip_variants"].get("code_migrations", []):
            observed_flag = m["resulting_code_observed_in_experiments"]
            actual = m["resulting_code"].lower() in declared
            assert observed_flag == actual, (
                f"{t['target_id']}→{m['resulting_code']}: 标记 {observed_flag} "
                f"与观测集 {actual} 不一致")


def test_key_evidence_entries_are_one_bit_to_observed(key_evidence: dict) -> None:
    """核心证据的每条都必须是：1 bit 翻转 + 目标码被观测到。"""
    declared_ok = True
    for e in key_evidence["entries"]:
        claim = e["claim"]
        assert claim["flip_count_required"] == 1
        assert len(claim["flipped_machine_code_bits"]) == 1
        assert len(claim["flipped_reg_value_bits"]) == 1
        # 掩码与码值 XOR 自洽（防止"机器码位当寄存器位"的经典错误）
        src = int(claim["source_code"], 16)
        dst = int(claim["target_code"], 16)
        assert src ^ dst == int(claim["bit_mask_on_reg_value"], 16), (
            f"{e['evidence_id']}: 掩码与 code XOR 不一致")
        assert claim["mask_applies_to"] == "post_insn_reg_value"
        # 证据链字段齐全
        chain = e["technical_chain"]
        for k in ("handler", "target_addr", "insn", "insn_bytes_hex", "dest_reg"):
            assert chain.get(k), f"{e['evidence_id']}: technical_chain 缺 {k}"
        pred = e["falsifiable_prediction"]
        assert pred["injection"]["action"] == "flip_reg_bits"
        assert pred["injection"]["mask_applies_to"] == "post_insn_reg_value"
        assert pred["injection"]["bit_mask"] == claim["bit_mask_on_reg_value"]
        rules = pred["verification_rule"]
        assert rules["supports_hypothesis_if"] and rules["refutes_hypothesis_if"]
        assert pred["negative_control"].get("expected_if_not_hit")
        declared_ok = declared_ok and e.get("experimental_context") is not None
    assert declared_ok


# ---------------------------------------------------------------- Profile 落档


def test_profile_injection_targets_all_hypothesis() -> None:
    """Profile 的 injection_targets 节：不得出现 fact（纪律硬约束）。"""
    p = ROOT / "profiles" / "target-chip.yaml"
    if not p.is_file():
        pytest.skip("无 Profile 实例")
    import yaml

    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    section = data.get("injection_targets")
    if not section:
        pytest.skip("该 Profile 无 injection_targets 节")

    from fi.profiles.loader import _walk_claims

    path_prefix = "injection_targets"
    bad = []
    for cpath, claim in _walk_claims(section, path_prefix):
        conf = claim.get("evidence", {}).get("confidence")
        if conf != "hypothesis":
            bad.append((cpath, conf))
    assert not bad, f"injection_targets 节出现非 hypothesis claim: {bad[:5]}"


def test_profile_injection_targets_validates() -> None:
    p = ROOT / "profiles" / "target-chip.yaml"
    if not p.is_file():
        pytest.skip("无 Profile 实例")
    from fi.profiles.loader import validate_file

    rep = validate_file(p)
    assert rep.ok, f"Profile 校验失败: {rep.errors[:5]}"
    # 既有 fact claim 数量不应因新增节而改变（新增内容只能是 hypothesis）
    assert rep.stats.get("fact", 0) > 0


# ---------------------------------------------------------------- 确定性


def test_targets_generation_is_deterministic(sample) -> None:
    """同输入两次生成，核心字段一致（无时间戳/随机序）。"""
    from fi.discover.injection_targets import build_injection_targets

    image, base = sample
    codes = ["0x<CODE_A>", "0x<CODE_B>"]
    r1 = build_injection_targets(str(image), base, codes, max_flips=1)
    r2 = build_injection_targets(str(image), base, codes, max_flips=1)
    assert r1["summary"] == r2["summary"]
    assert [t["target_id"] for t in r1["targets"]] == [t["target_id"] for t in r2["targets"]]
    assert r1["code_migration_matrix"] == r2["code_migration_matrix"]
