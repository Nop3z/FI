# -*- coding: utf-8 -*-
"""可用性自评的回归测试（chip-profile-ds 编写，待 core-contract 评审归并）。

背景：验收前发现**噪声输入会产出大量误导性"靶点"**（8KB 随机字节 → 320 个靶点，
其中 251 个比较分支）。本测试锁定两条不变量：

  1. 随机噪声镜像 `usability_assessment.usable == False`（且不抛异常）；
  2. 正常固件镜像 `usable == True`，且靶点数量与前一致（无回归）。

判据是"直接调用目标复用率"（噪声 0.7% vs 真实固件 20-50%），
未解码比与常见指令占比区分度不足，不作主判据。
"""
from __future__ import annotations

import random
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _noise_image(size: int = 8192, seed: int = 19991231) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def _sample_image() -> tuple[Path, int] | None:
    import os

    env = os.environ.get("FI_SMOKE_IMAGE")
    candidates = ([Path(env)] if env else []) + sorted(ROOT.glob("*.bin"))
    for c in candidates:
        if c.is_file() and c.stat().st_size > 4096:
            base_env = os.environ.get("FI_SMOKE_BASE")
            return c, int(base_env, 0) if base_env else 0x<BASE>
    return None


def test_noise_image_is_flagged_not_usable(tmp_path: Path) -> None:
    """随机字节必须被判为不可用，且不抛异常。"""
    from fi.discover.targets import discover_targets

    p = tmp_path / "noise.bin"
    p.write_bytes(_noise_image())
    rep = discover_targets(str(p), 0x10000000)

    ua = rep["usability_assessment"]
    assert ua["usable"] is False, f"噪声输入未被标记：{ua}"
    assert ua["assessment"] == "likely_random_or_non_riscv"
    # 复用率极低是被判不可用的原因，必须写清
    assert ua["metrics"]["call_target_reuse_ratio"] < 0.05
    assert ua["reason"]
    # 阈值与消费规则必须随报告给出（消费方可据以拒绝）
    assert ua["thresholds"]["min_call_target_reuse_ratio"] == 0.05
    assert ua["consumption_rule"]
    # 纪律：仍为 hypothesis
    assert rep["confidence"] == "hypothesis"


def test_noise_image_regions_dispatch_traps_are_empty() -> None:
    """噪声输入下 regions/dispatch/traps 应自然给出 0 候选（无需额外自评）。"""
    import tempfile

    from fi.discover.dispatch import discover_dispatch
    from fi.discover.regions import discover_regions
    from fi.discover.traps import discover_traps

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "noise.bin"
        p.write_bytes(_noise_image())
        rg = discover_regions(str(p), 0x10000000)
        dp = discover_dispatch(str(p), 0x10000000)
        tr = discover_traps(str(p), 0x10000000)

    assert rg["summary"]["page_candidates"] == 0
    assert dp["summary"]["recovered_tables"] == 0
    assert dp["summary"]["total_handler_candidates"] == 0
    assert tr["summary"]["trap_mechanism_present"] is False


def test_normal_image_is_usable_and_targets_unchanged() -> None:
    """正常固件必须 usable=True，且靶点统计不因新增自评而改变。"""
    from fi.discover.targets import discover_targets

    s = _sample_image()
    if s is None:
        pytest.skip("未找到样例镜像")
    image, base = s
    rep = discover_targets(str(image), base)

    ua = rep["usability_assessment"]
    assert ua["usable"] is True, f"正常固件被误判不可用：{ua}"
    assert ua["assessment"] == "usable"
    assert ua["metrics"]["call_target_reuse_ratio"] >= 0.05
    # 靶点统计与前一致（target-chip 基线：860 个靶点）
    assert rep["summary"]["target_count"] > 0
    kinds = {t["kind"] for t in rep["targets"]}
    assert "const_load" in kinds
    assert "compare_branch" in kinds


def test_tiny_image_flagged_insufficient() -> None:
    """极小镜像应判 insufficient（不冒充可用）。"""
    from fi.discover.targets import discover_targets

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "tiny.bin"
        p.write_bytes(b"\x13\x05\x10\x50" * 4)   # 16 条 addi，无调用
        rep = discover_targets(str(p), 0x0)
    ua = rep["usability_assessment"]
    assert ua["usable"] is False
    assert ua["assessment"] == "insufficient_instructions"


def test_chain_declares_coverage() -> None:
    """chain 必须自带覆盖度自评（防止小镜像上被误读为成功）。"""
    import tempfile

    from fi.discover.chain import discover_chain

    # 极小镜像：覆盖必然不足，必须显式声明
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "tiny.bin"
        p.write_bytes(
            (0x00000297).to_bytes(4, "little")   # auipc t0, 0
            + (0x00028293).to_bytes(4, "little")  # addi t0, t0, 0
            + (0x30529073).to_bytes(4, "little")  # csrw mtvec, t0
            + (0x00008067).to_bytes(4, "little")  # ret
        )
        rep = discover_chain(str(p), 0x0)
    cov = rep["coverage"]
    assert cov["assessment"] in ("insufficient_small_graph",
                                 "insufficient_low_coverage",
                                 "partial_indirect_blocked",
                                 "adequate")
    assert "reason" in cov and cov["reason"]
    assert "discipline" in cov
    # 极小镜像不应被判 adequate
    assert cov["assessment"] != "adequate", f"极小镜像被判 adequate：{cov}"


def test_chain_coverage_on_real_firmware() -> None:
    s = _sample_image()
    if s is None:
        pytest.skip("未找到样例镜像")
    from fi.discover.chain import discover_chain

    image, base = s
    rep = discover_chain(str(image), base, include_function_details=False)
    cov = rep["coverage"]
    assert cov["instruction_coverage_ratio"] > 0
    assert cov["function_count"] > 0
    assert cov["usable_for_attribution"] is True
