# -*- coding: utf-8 -*-
"""实机接入层测试（PowerShorter 注入器 + 安全护栏）。

无设备时用 MockPowerShorter 验证全流程；真实设备接口语义以 mock 锁定，
设备到手后只需替换 device 实例。
"""
from __future__ import annotations

import pytest

from fi.hardware.powershorter import (
    DEFAULT_MAX_PULSE_RAW,
    DURATION_UNIT_NS,
    MockPowerShorter,
    PowerShorterInjector,
    SafetyViolation,
)


def test_pattern_mapping_uses_10ns_unit() -> None:
    """参数映射：pulse=2 → 20ns 毛刺；delay=3160 → 31600ns 等待。"""
    pattern = PowerShorterInjector.build_pattern(3160, 2)
    assert pattern[1] == (0, 2), "毛刺段必须是 level=0（断开供电）+ pulse 单位数"
    assert pattern[0] == (1, 3160), "等待段必须是 level=1（保持供电）"
    assert PowerShorterInjector.to_ns(2) == 2 * DURATION_UNIT_NS == 20
    assert PowerShorterInjector.to_ns(3160) == 31600


def test_injection_receipt_is_complete_and_auditable() -> None:
    """每次注入必须有完整回执（参数、pattern 原样、单位来源）。"""
    dev = MockPowerShorter()
    inj = PowerShorterInjector(dev)
    r = inj.inject(3160, 2)

    assert r.ok is True
    assert r.delay_raw == 3160 and r.pulse_raw == 2
    assert r.delay_ns == 31600 and r.pulse_ns == 20
    assert r.pattern == [(1, 3160), (0, 2), (1, 1)]
    assert "10ns" in r.unit_source, "必须记录单位来源，避免隐式假设"
    assert r.confidence == "observation"


def test_device_call_sequence_is_arm_then_trigger() -> None:
    """设备调用顺序必须是 engine_cfg → arm → soft_trigger。"""
    dev = MockPowerShorter()
    PowerShorterInjector(dev).inject(3000, 2)
    names = [c[0] for c in dev.calls]
    assert names == ["engine_cfg", "arm", "soft_trigger"]


def test_pulse_over_limit_is_rejected() -> None:
    """脉宽超限必须拒绝（防止烧板）。"""
    inj = PowerShorterInjector(MockPowerShorter())
    with pytest.raises(SafetyViolation) as ei:
        inj.inject(3000, DEFAULT_MAX_PULSE_RAW + 1)
    assert "脉宽超限" in str(ei.value)


def test_negative_pulse_is_rejected() -> None:
    inj = PowerShorterInjector(MockPowerShorter())
    with pytest.raises(SafetyViolation):
        inj.inject(3000, -1)


def test_max_injections_limit() -> None:
    """注入次数上限。"""
    inj = PowerShorterInjector(MockPowerShorter(), max_injections=3)
    for _ in range(3):
        assert inj.inject(3000, 2).ok
    with pytest.raises(SafetyViolation) as ei:
        inj.inject(3000, 2)
    assert "次数超限" in str(ei.value)


def test_consecutive_failure_circuit_breaker() -> None:
    """连续失败熔断：设备持续异常时必须停止而不是无限重试。"""
    inj = PowerShorterInjector(MockPowerShorter(fail_times=100),
                               max_consecutive_failures=5)
    fails = 0
    with pytest.raises(SafetyViolation) as ei:
        for _ in range(20):
            if not inj.inject(3000, 2).ok:
                fails += 1
    assert "连续失败熔断" in str(ei.value)
    assert fails == 5, f"应在 5 次连续失败后熔断，实际 {fails}"


def test_emergency_stop_blocks_further_injection() -> None:
    """紧急停止后必须拒绝注入，且需显式解除。"""
    inj = PowerShorterInjector(MockPowerShorter())
    inj.emergency_stop()
    with pytest.raises(SafetyViolation):
        inj.inject(3000, 2)
    inj.reset_safety()
    assert inj.inject(3000, 2).ok is True


def test_device_exception_is_recorded_not_swallowed() -> None:
    """设备异常必须记录到回执里，不得静默吞掉。"""
    inj = PowerShorterInjector(MockPowerShorter(fail_times=1))
    r = inj.inject(3000, 2)
    assert r.ok is False
    assert r.error and "软触发失败" in r.error


def test_history_keeps_every_injection() -> None:
    """历史必须保留每一次注入（审计要求）。"""
    inj = PowerShorterInjector(MockPowerShorter(fail_times=1))
    inj.inject(3000, 2)         # 失败
    inj.inject(3000, 2)         # 成功
    assert len(inj.history) == 2
    assert inj.history[0].ok is False
    assert inj.history[1].ok is True


def test_mock_rejects_invalid_pattern_like_real_device() -> None:
    """mock 应复刻设备的入参校验（level 只能 0/1、pattern ≤8 段）。"""
    dev = MockPowerShorter()
    with pytest.raises(ValueError):
        dev.engine_cfg(0, [(2, 10)])
    with pytest.raises(ValueError):
        dev.engine_cfg(0, [(1, 1)] * 9)
