"""LoopStrategy 接口（调参策略，可插拔，core-contract 维护接口）。

策略只做"看历史 → 提下一批 → 判断收敛"，不接触注入器与观测器实现。
闭环形态：窗口 + 扫描结果 → 下一批参数（提案-评估循环）。

内置基线：fi.loop.strategies.MinimalGridStrategy（朴素网格扫描，
仅用于闭环冒烟与基线对比；智能策略由后续成员实现并实现本接口）。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from fi.loop.types import ParamPoint, ParamWindow

# 符合 campaign-record.schema.json 的实例 dict。
CampaignRecordData = dict[str, Any]


class LoopStrategy(ABC):
    """调参策略接口。"""

    #: 策略标识（写进 LoopResult 与日志）。
    name: str = "unknown"

    @abstractmethod
    def next_batch(
        self,
        window: ParamWindow,
        history: Sequence[CampaignRecordData],
    ) -> list[ParamPoint]:
        """给出下一批要注入的参数点（批大小由策略自定，可为空 = 主动停止）。"""

    @abstractmethod
    def update(self, new_records: Sequence[CampaignRecordData]) -> None:
        """把最新一批实验记录喂给策略（在下一轮 next_batch 前调用）。"""

    @abstractmethod
    def converged(self) -> bool:
        """是否已收敛（稳定命中/批数用尽/无更好提案）。True 时编排器提前结束。"""
