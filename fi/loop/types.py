"""闭环值对象：参数窗口 / 参数点 / 注入结果。

单位纪律（对应契约 experiment-scan.schema.json / campaign-record.schema.json）：
- 闭环层参数键名显式携带单位：``delay_ns``、``delay_raw``；
- ``raw`` 是数据源原始刻度（本批 CSV 范围 2640-3190）；
- ``ns`` 是物理单位；raw→ns 的换算（1 raw = 10ns）是未证实工作假设，
  任何换算必须经 ParamMappingSpec / injector 显式配置并标注 hypothesis，
  本模块不做任何隐式换算。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

from fi import UNKNOWN


def param_key(axis: str, unit: str) -> str:
    """参数键名规范：``{axis}_{unit}``，如 delay_ns / pulse_raw。"""
    return f"{axis}_{unit}"


@dataclass(frozen=True)
class ParamAxis:
    """一条参数轴。"""

    name: str                       # 轴名：delay / pulse（泛化允许其他）
    unit: str                       # 单位：ns / raw / unknown
    min_value: float                # 窗口下界（含）
    max_value: float                # 窗口上界（含）
    step_value: float | None = None # 步进；None = 连续窗口（网格策略不可展开）

    @property
    def key(self) -> str:
        return param_key(self.name, self.unit)


@dataclass(frozen=True)
class ParamWindow:
    """参数窗口（闭环输入，如 delay 27000-38000 ns）。

    to_contract_window() 输出符合 experiment-scan.schema.json 的 window 数组。
    """

    axes: tuple[ParamAxis, ...]

    def __post_init__(self) -> None:
        if not self.axes:
            raise ValueError("ParamWindow 至少需要一条参数轴")

    def axis(self, name: str) -> ParamAxis:
        for a in self.axes:
            if a.name == name:
                return a
        raise KeyError(f"窗口中不存在参数轴: {name}")

    def contains(self, point: "ParamPoint") -> bool:
        """点是否落在窗口内（逐轴判断；窗口没有的轴返回 False）。"""
        for a in self.axes:
            v = point.values.get(a.key)
            if v is None or not (a.min_value <= v <= a.max_value):
                return False
        return True

    def grid_points(self) -> Iterator["ParamPoint"]:
        """按步进展开网格点。任一轴缺 step 时抛 ValueError（连续窗口请用策略采样）。"""
        from itertools import product

        ranges = []
        for a in self.axes:
            if a.step_value is None or a.step_value <= 0:
                raise ValueError(f"轴 {a.name} 未定义有效 step，无法展开网格")
            n = int(round((a.max_value - a.min_value) / a.step_value))
            ranges.append([a.min_value + i * a.step_value for i in range(n + 1)])
        for combo in product(*ranges):
            yield ParamPoint(values={a.key: v for a, v in zip(self.axes, combo)})

    def to_contract_window(self) -> list[dict[str, Any]]:
        """导出为 experiment-scan 契约的 window 数组形状。"""
        rows = []
        for a in self.axes:
            rows.append(
                {
                    "axis": a.name,
                    "min_value": a.min_value,
                    "max_value": a.max_value,
                    "step_value": a.step_value if a.step_value is not None else UNKNOWN,
                    "unit": a.unit,
                }
            )
        return rows


@dataclass(frozen=True)
class ParamPoint:
    """一组具体注入参数。键名遵循 ``{axis}_{unit}`` 规范。"""

    values: dict[str, float]

    def get(self, axis: str, unit: str) -> float:
        return self.values[param_key(axis, unit)]

    def try_get(self, axis: str, unit: str) -> float | None:
        return self.values.get(param_key(axis, unit))


@dataclass(frozen=True)
class InjectionOutcome:
    """一次注入的结果（Injector.inject 的返回）。

    evidence_level 纪律：
    - CSVReplay 回放的是历史真实观测 → observation；
    - SimFaultInjector 仿真是重建推断 → hypothesis。
    """

    point: ParamPoint
    """请求注入的参数点。"""

    status: str
    """injected = 成功施加；no_match = 注入器找不到可施加对象（如 CSV 无匹配行）；error = 失败。"""

    evidence_level: str
    """本次结果的证据等级：observation / hypothesis。"""

    response_raw: str | None = None
    """响应原始字面量（CSV response 列等）；无则 None。"""

    state_label: str | None = None
    """原始状态标签（CSV state 列等，语义待确认）；无则 None。"""

    applied_point: dict[str, float] | None = None
    """实际施加的参数（raw 刻度）；无法施加为 None。"""

    raw_data_ref: dict[str, Any] | None = None
    """原始只读数据引用（契约 common.defs#/data_ref 形状）。"""

    source: str = UNKNOWN
    """产出该结果的注入器标识。"""

    detail: dict[str, Any] = field(default_factory=dict)
    """注入器附加信息（fault_event_id / trace_ref / 匹配方式等）。"""
