"""Injector 接口（可插拔注入器，core-contract 维护接口）。

实现方（同一接口两族）：
- 离线（一等公民，一期交付）：CSVReplayInjector（fi.loop.csv_replay）、
  SimFaultInjector（fi.loop.sim_injector）；
- 实机（仅接口预留，不排期）：PowerShorter/SmartHub 等硬件注入器。

实现约定：
- inject() 必须纯"施加 + 报告事实"，不做语义解释（解释归 AnalysisResult）；
- 结果证据等级如实标注：历史回放=observation，仿真=hypothesis；
- 失败用 status=no_match/error 表达，不抛异常打断闭环（编排器按状态计数）。
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from fi.loop.types import InjectionOutcome, ParamPoint


class Injector(ABC):
    """注入器接口。"""

    #: 注入器标识（写进 CampaignRecord.params.injector_id）。
    name: str = "unknown"

    @abstractmethod
    def inject(self, point: ParamPoint) -> InjectionOutcome:
        """在给定参数点上执行一次注入，返回结果。

        实现必须无状态副作用地可重复调用（同一参数点重放得到一致结果，
        仿真注入器由内部重置保证；硬件注入器天然不可重复，如实标注）。
        """
