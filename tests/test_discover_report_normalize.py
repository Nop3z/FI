"""DiscoverReport 归一/构造器测试：真实模块产出 → 契约形状，闸门不破。

覆盖：
- regions / traps / targets 原始形状归一后必须通过契约校验；
- 外部传入越界 confidence（fact/observation）必须被降到 hypothesis；
- 越界 suggested_action 必须被保守降级；
- 缺 sample_evidence 时由构造器合成可回溯文本（不编造结论）；
- merge_reports 合并多模块部分报告；
- 真实 fi.discover.regions / traps 端到端（capstone 缺失则 skip）。
"""

from pathlib import Path

import pytest

from fi import UNKNOWN
from fi.schemas import validate_instance
from fi.schemas.discover_report import (
    CONFIDENCE_ALLOWED,
    build_report,
    merge_reports,
    normalize_module_report,
    regions_to_findings,
    targets_to_findings,
    traps_to_findings,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _fake_regions_raw() -> dict:
    return {
        "schema": "fi.discover.region-report-v0",
        "tool": {"name": "fi.discover.regions", "version": "0.1.0"},
        "image": {
            "path": "firmware.bin",
            "sha256": "e" * 64,
            "size_bytes": 4096,
            "base_address": 0x1000,
            "base_address_hex": "0x00001000",
        },
        "method": {
            "channels": ["lui+addi 常量对", "绝对 lw/sw"],
            "boundaries": ["线性扫描含数据段"],
            "classification": "地址惯例启发式",
        },
        "summary": {"page_candidates": 2},
        "candidates": [
            {
                "page_base": 0x20000000,
                "hit_count": 7,
                "accesses": ["read", "write"],
                "kind": "ram",
                "kind_reason": "读写混合（内存形态）",
                "confidence": "hypothesis",
                "evidence_kind": "artifact_derived",
                "sample_evidence": [
                    {"value": "0x20000010", "at": "0x1004", "form": "lui_addi",
                     "access": "read", "insns": ["lui t0, 0x20000", "lw a0, 16(t0)"]}
                ],
            },
            {
                "page_base": 0x30000000,
                "hit_count": 3,
                "accesses": ["read"],
                "kind": "mmio",
                "kind_reason": "仅见读访问",
                # 故意塞越界值：必须被构造器降到 hypothesis
                "confidence": "fact",
                "evidence_kind": "measurement",
            },
        ],
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


def _fake_traps_raw() -> dict:
    return {
        "schema": "fi.discover.trap-report-v0",
        "tool": {"name": "fi.discover.traps", "version": "0.1.0"},
        "image": {"path": "firmware.bin", "sha256": "e" * 64, "size_bytes": 4096, "base_address": 0x1000},
        "method": {"patterns": ["csrw → mtvec"], "boundaries": ["线性扫描伪指令"]},
        "findings": {
            "mtvec_writes": [
                {
                    "at": "0x10000010",
                    "offset": 16,
                    "insn": "csrw mtvec, t0",
                    "base_candidate": 0x10000020,
                    "base_candidate_hex": "0x10000020",
                    "base_in_image": True,
                    "context": ["lui t0, 0x10000", "addi t0, t0, 32", "csrw mtvec, t0"],
                }
            ],
            "mret_sites": [
                {
                    "at": "0x10000040",
                    "offset": 64,
                    "insn": "mret",
                    "save_frame_evidence": {"stores_to_sp": 8, "loads_from_sp": 8},
                }
            ],
        },
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


def _fake_targets_raw() -> dict:
    return {
        "schema": "fi.discover.target-report-v0",
        "tool": {"name": "fi.discover.targets", "version": "0.1.0"},
        "image": {"path": "firmware.bin", "sha256": "e" * 64, "size_bytes": 4096, "base_address": 0x1000},
        "method": {"patterns": ["错误码装载点"], "boundaries": ["仅静态近邻"]},
        "findings": {
            "error_code_stores": [
                {
                    "addr": "0x10000060",
                    "offset": 96,
                    "insn": "li a1, 0x50",
                    "kind": "error_code_store",
                    # 故意塞发现层不存在的动作：必须被降级
                    "suggested_action": "self_destruct",
                    "confidence": "observation",
                }
            ],
            "shared_send_calls": [
                {"at": "0x10000070", "insn": "jal ra, 0x1200", "kind": "shared_send_call"},
            ],
        },
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


# ---------------------------------------------------------------- findings 归一


def test_regions_findings_normalized() -> None:
    findings = regions_to_findings(_fake_regions_raw())
    assert len(findings) == 2
    for item in findings:
        assert item["confidence"] in CONFIDENCE_ALLOWED
        assert item["sample_evidence"], "每条必须带证据样例"
        assert item["evidence_kind"] in ("artifact", "artifact_derived")
    # 越界的 fact / measurement 被降级
    assert findings[1]["confidence"] == "hypothesis"
    assert findings[1]["evidence_kind"] == "artifact_derived"
    # 缺 insn 时不得编造：给 unknown
    assert findings[1]["insn"] == UNKNOWN
    # 动作按 kind 兜底
    assert findings[0]["suggested_action"] == "map_region"
    assert findings[1]["suggested_action"] == "stub_read"


def test_traps_findings_normalized() -> None:
    findings = traps_to_findings(_fake_traps_raw())
    kinds = {f["kind"] for f in findings}
    assert kinds == {"mtvec_write", "mret_site"}
    mtvec = next(f for f in findings if f["kind"] == "mtvec_write")
    assert mtvec["addr"] == 0x10000010
    assert mtvec["offset"] == 16
    assert any("base_in_image" in e for e in mtvec["sample_evidence"])
    assert mtvec["suggested_action"] == "stub_read"


def test_targets_findings_normalized_and_clamped() -> None:
    findings = targets_to_findings(_fake_targets_raw())
    assert len(findings) == 2
    store = next(f for f in findings if f["kind"] == "error_code_store")
    # 越界 confidence → hypothesis；越界动作 → 该 kind 的保守动作
    assert store["confidence"] == "hypothesis"
    assert store["suggested_action"] == "flip_reg_bits"
    assert store["sample_evidence"]


def test_normalized_reports_validate() -> None:
    for module, raw in (
        ("regions", _fake_regions_raw()),
        ("traps", _fake_traps_raw()),
        ("targets", _fake_targets_raw()),
    ):
        rep = normalize_module_report(raw, module=module)
        errors = validate_instance("discover-report", rep)
        assert errors == [], f"{module}: {errors}"
        assert rep["confidence"] == "hypothesis"
        assert rep["evidence_kind"] == "artifact_derived"


def test_normalize_rejects_unknown_module() -> None:
    with pytest.raises(ValueError):
        normalize_module_report({}, module="magic")


# ---------------------------------------------------------------- 合并


def test_merge_reports_union() -> None:
    merged = merge_reports(
        normalize_module_report(_fake_regions_raw(), module="regions"),
        normalize_module_report(_fake_traps_raw(), module="traps"),
        normalize_module_report(_fake_targets_raw(), module="targets"),
    )
    assert validate_instance("discover-report", merged) == []
    assert merged["summary"]["counts"] == {"regions": 2, "traps": 2, "targets": 2}
    assert set(merged["summary"]["sources"]) == {
        "fi.discover.regions",
        "fi.discover.traps",
        "fi.discover.targets",
    }
    # method 并集去重
    assert len(merged["method"]["channels"]) == len(set(merged["method"]["channels"]))
    assert len(merged["method"]["boundaries"]) == len(set(merged["method"]["boundaries"]))


def test_merge_requires_at_least_one() -> None:
    with pytest.raises(ValueError):
        merge_reports()


# ---------------------------------------------------------------- 真实模块端到端


def _real_image() -> Path | None:
    candidates = sorted(REPO_ROOT.glob("*.bin"))
    return candidates[0] if candidates else None


@pytest.mark.parametrize("module", ["regions", "traps"])
def test_real_module_report_normalizes(module: str) -> None:
    """真实模块产出（可达性/线性扫描）归一后必须过契约 + 闸门。"""
    image = _real_image()
    if image is None:
        pytest.skip("仓库根无 *.bin 样例镜像")
    if module == "regions":
        mod = pytest.importorskip("fi.discover.regions", reason="fi.discover.regions 不可用")
        raw = mod.discover_regions(str(image), 0)
    else:
        mod = pytest.importorskip("fi.discover.traps", reason="fi.discover.traps 不可用")
        raw = mod.discover_traps(str(image), 0)

    rep = normalize_module_report(raw, module=module)
    errors = validate_instance("discover-report", rep)
    assert errors == [], f"{module} 真实产出归一后不合契约:\n" + "\n".join(errors)
    items = rep["findings"][module]
    assert items, f"{module} 真实产出为空（样例镜像应至少产出候选）"
    for item in items:
        assert item["confidence"] in CONFIDENCE_ALLOWED
        assert item["sample_evidence"]


def test_build_report_computes_sha256(tmp_path: Path) -> None:
    """未给 sha256 时必须自己算（防止下游收到假指纹）。"""
    img = tmp_path / "firmware.bin"
    img.write_bytes(b"\x00" * 64)
    rep = build_report(
        tool_name="fi.discover.test",
        tool_version="0.0.1",
        image_path=str(img),
        base_address=0,
        method={"channels": ["c"], "boundaries": ["b"]},
    )
    assert len(rep["image"]["sha256"]) == 64
    assert rep["image"]["size_bytes"] == 0  # 未显式给时保持 0（调用方应显式传）
    assert validate_instance("discover-report", rep) == []


def test_build_report_rejects_invalid_shape(tmp_path: Path) -> None:
    img = tmp_path / "firmware.bin"
    img.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError):
        build_report(
            tool_name="fi.discover.test",
            tool_version="0.0.1",
            image_path=str(img),
            base_address=0,
            regions=[{"kind": "ram"}],  # 缺必填字段
        )


def test_build_report_rejects_missing_image(tmp_path: Path) -> None:
    """镜像不存在时不得用占位指纹糊过去（指纹是证据）。"""
    with pytest.raises(ValueError) as exc:
        build_report(
            tool_name="fi.discover.test",
            tool_version="0.0.1",
            image_path=str(tmp_path / "nope.bin"),
            base_address=0,
        )
    assert "镜像文件不存在" in str(exc.value)
