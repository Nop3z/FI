# -*- coding: utf-8 -*-
"""fi.hardware.powershorter：PowerShorter 毛刺设备接入层。

## 设备语义（来自 power_shorter 库 docstring，属设备事实）

- `engine_cfg(engine, pattern, trigger_mode, pattern_repeat, trigger_edges)`
  - `pattern`: [(level, duration), ...] 最多 8 段
  - **duration 单位 = 10 ns**
  - `level=0` = MOSFET 断开（掉电 = 毛刺）；`level=1` = MOSFET 导通（正常供电）
  - 最后一段 level 保持到下次 arm
- `arm(engine, init_level=0)`：布防（等待触发）
- `soft_trigger(engine)`：软触发
- `state(engine)` → 'armed' | 'glitched'
- `gpio(idx, 0|1)`、`relay(idx, 0|1)`、`PowerShorter(port, timeout)`

## 与实验参数（delay / pulse）的映射

历史 CSV 的 `delay`/`pulse` 就是本设备参数（单位 10ns）：
- `pulse=2` → 毛刺宽度 2 × 10ns = 20 ns
- `delay=3160` → 触发延迟 3160 × 10ns = 31,600 ns

本模块**显式**做这个换算，并把 `unit_scale` 写进每次注入记录，避免隐式假设。

## 安全护栏（实机必须）

- 脉宽上限（默认 100 raw = 1 µs）
- 占空比/次数上限（默认单轮 ≤ 10000 次）
- 连续失败熔断
- 紧急停止（`emergency_stop()`）
- 所有上限可通过构造参数收紧，但**不得**无声放宽

## 纪律

- 实机数据属 Captured State；本模块只负责"打"与"记录参数"，不做解释
- 每次注入都返回完整参数回执（pattern 原样），供审计与复现
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA = "fi.hardware.powershorter-v0"

#: 设备 duration 单位（ns/单位）。来自 engine_cfg docstring：duration is in unit of 10ns
DURATION_UNIT_NS = 10

#: 安全默认上限
DEFAULT_MAX_PULSE_RAW = 100          # 1 µs
DEFAULT_MAX_INJECTIONS = 10_000
DEFAULT_MAX_CONSECUTIVE_FAILURES = 20


@dataclass
class InjectionReceipt:
    """一次注入的完整回执（审计用）。"""
    delay_raw: int
    pulse_raw: int
    delay_ns: int
    pulse_ns: int
    pattern: list[tuple[int, int]]
    engine: int
    trigger_mode: str
    ok: bool
    error: str | None = None
    unit_scale_ns: int = DURATION_UNIT_NS
    unit_source: str = "power_shorter.engine_cfg docstring: duration is in unit of 10ns"
    confidence: str = "observation"        # 参数是实测下发的，属观测
    raw: dict[str, Any] = field(default_factory=dict)


class SafetyViolation(RuntimeError):
    """超出安全边界（脉宽/次数/连续失败）。"""


class PowerShorterInjector:
    """PowerShorter 注入器：把 (delay_raw, pulse_raw) 变成设备 pattern 并执行。

    ``device``：真实的 power_shorter.PowerShorter 实例，或实现了同名方法的 mock。
    """

    def __init__(
        self,
        device,
        *,
        engine: int | None = None,
        trigger_mode: Any = None,
        max_pulse_raw: int = DEFAULT_MAX_PULSE_RAW,
        max_injections: int = DEFAULT_MAX_INJECTIONS,
        max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
        init_level: int = 0,
    ) -> None:
        self.device = device
        self.max_pulse_raw = max_pulse_raw
        self.max_injections = max_injections
        self.max_consecutive_failures = max_consecutive_failures
        self.init_level = init_level

        # 延迟导入设备枚举（无设备环境也能构造本类）
        if engine is None or trigger_mode is None:
            try:
                from power_shorter import Engine, TRIGGER_MODE
                engine = engine if engine is not None else Engine.E1
                trigger_mode = trigger_mode if trigger_mode is not None else TRIGGER_MODE.RISE
            except ImportError:
                engine = engine if engine is not None else 0
                trigger_mode = trigger_mode if trigger_mode is not None else 0
        self.engine = engine
        self.trigger_mode = trigger_mode

        self._n_injections = 0
        self._consecutive_failures = 0
        self._stopped = False
        self.history: list[InjectionReceipt] = []

    # ---------------- 安全 ----------------

    def _check_safety(self, pulse_raw: int) -> None:
        if self._stopped:
            raise SafetyViolation("已紧急停止，拒绝继续注入（需显式 reset_safety()）")
        if pulse_raw < 0:
            raise SafetyViolation(f"pulse_raw 不得为负: {pulse_raw}")
        if pulse_raw > self.max_pulse_raw:
            raise SafetyViolation(
                f"脉宽超限: pulse_raw={pulse_raw} > 上限 {self.max_pulse_raw}"
                f"（= {self.max_pulse_raw * DURATION_UNIT_NS} ns）")
        if self._n_injections >= self.max_injections:
            raise SafetyViolation(
                f"注入次数超限: {self._n_injections} >= {self.max_injections}")
        if self._consecutive_failures >= self.max_consecutive_failures:
            raise SafetyViolation(
                f"连续失败熔断: {self._consecutive_failures} 次连续失败")

    def emergency_stop(self) -> None:
        """紧急停止：拒绝后续注入。"""
        self._stopped = True

    def reset_safety(self) -> None:
        """显式解除紧急停止（需人类确认后调用）。"""
        self._stopped = False
        self._consecutive_failures = 0

    # ---------------- 参数映射 ----------------

    @staticmethod
    def build_pattern(delay_raw: int, pulse_raw: int) -> list[tuple[int, int]]:
        """把 (delay, pulse) 映射为设备 pattern。

        语义：触发后先保持供电 `delay_raw` 个 10ns 单位，然后断开 `pulse_raw` 个
        10ns 单位（毛刺），再恢复供电。

        注意：**delay 的实现在设备侧由触发时机决定**（trigger delay），本 pattern
        用"保持供电 delay → 断开 pulse → 恢复"表达；若设备支持独立的 trigger
        delay 参数，调用方应优先用设备原语，本函数作为纯 pattern 表达。
        """
        return [
            (1, int(delay_raw)),      # 保持导通（等待到切入时刻）
            (0, int(pulse_raw)),      # 断开供电 = 毛刺
            (1, 1),                   # 恢复供电，保持
        ]

    @staticmethod
    def to_ns(value_raw: int) -> int:
        return int(value_raw) * DURATION_UNIT_NS

    # ---------------- 执行 ----------------

    def inject(self, delay_raw: int, pulse_raw: int) -> InjectionReceipt:
        """执行一次注入（布防 → 软触发）。"""
        self._check_safety(int(pulse_raw))
        pattern = self.build_pattern(delay_raw, pulse_raw)
        receipt = InjectionReceipt(
            delay_raw=int(delay_raw),
            pulse_raw=int(pulse_raw),
            delay_ns=self.to_ns(delay_raw),
            pulse_ns=self.to_ns(pulse_raw),
            pattern=pattern,
            engine=int(self.engine) if isinstance(self.engine, int) else repr(self.engine),
            trigger_mode=str(self.trigger_mode),
            ok=False,
        )
        try:
            self.device.engine_cfg(
                self.engine, pattern, trigger_mode=self.trigger_mode,
                pattern_repeat=1, trigger_edges=1,
            )
            self.device.arm(self.engine, init_level=self.init_level)
            self.device.soft_trigger(self.engine)
            receipt.ok = True
            self._consecutive_failures = 0
        except Exception as exc:  # noqa: BLE001 —— 设备异常要记录而非吞掉
            receipt.error = f"{type(exc).__name__}: {exc}"
            self._consecutive_failures += 1
        finally:
            self._n_injections += 1
            self.history.append(receipt)
        return receipt


class MockPowerShorter:
    """假 PowerShorter：用于无设备时跑通全流程与测试。

    行为：记录所有调用；可按 ``fail_times`` 模拟前 N 次失败（验证熔断）。
    """

    def __init__(self, fail_times: int = 0) -> None:
        self.fail_times = fail_times
        self.calls: list[tuple[str, tuple, dict]] = []
        self._armed: dict[int, bool] = {}

    def engine_cfg(self, engine, pattern, trigger_mode=None, pattern_repeat=1,
                   trigger_edges=1):
        self.calls.append(("engine_cfg", (engine, pattern),
                           {"trigger_mode": trigger_mode,
                            "pattern_repeat": pattern_repeat,
                            "trigger_edges": trigger_edges}))
        if len(pattern) > 8:
            raise ValueError("at most 8 pattern can be set")
        for level, dur in pattern:
            if level not in (0, 1):
                raise ValueError(f"level 必须 0/1: {level}")
            if dur < 0:
                raise ValueError(f"duration 不得为负: {dur}")

    def arm(self, engine, init_level=0):
        self.calls.append(("arm", (engine,), {"init_level": init_level}))
        self._armed[engine] = True

    def soft_trigger(self, engine):
        self.calls.append(("soft_trigger", (engine,), {}))
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("mock: 软触发失败（模拟设备异常）")
        self._armed[engine] = False

    def state(self, engine) -> str:
        return "armed" if self._armed.get(engine) else "glitched"

    def gpio(self, idx, value):
        if value not in (0, 1):
            raise ValueError("gpio value must be 0 or 1")
        self.calls.append(("gpio", (idx, value), {}))

    def relay(self, idx, value):
        if value not in (0, 1):
            raise ValueError("relay value must be 0 or 1")
        self.calls.append(("relay", (idx, value), {}))
