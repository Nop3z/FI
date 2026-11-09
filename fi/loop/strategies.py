"""内置基线策略：朴素网格扫描。

只用于闭环冒烟与基线对比（策略是可插拔点，任何 LoopStrategy 实现都可替换
它）。行为：按窗口网格顺序出批；只要出现一个目标标签命中即收敛；超过
max_points 个提案后停止。
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from fi.loop.strategy import CampaignRecordData, LoopStrategy
from fi.loop.types import ParamPoint, ParamWindow


class MinimalGridStrategy(LoopStrategy):
    """网格扫描基线策略。

    target_state_label 为必填参数：目标标签属于具体实验数据集的实例值，
    禁止在通用代码里给默认值（通用性门禁约束）。
    """

    name = "minimal-grid"

    def __init__(
        self,
        target_state_label: str,
        max_points: int = 64,
    ) -> None:
        self.target_state_label = target_state_label  # 原始标签（语义待确认，仅按字面匹配）
        self.max_points = max_points
        self._proposed = 0
        self._hit = False

    def next_batch(
        self,
        window: ParamWindow,
        history: Sequence[CampaignRecordData],
    ) -> list[ParamPoint]:
        if self._hit or self._proposed >= self.max_points:
            return []
        batch: list[ParamPoint] = []
        for point in window.grid_points():
            batch.append(point)
            self._proposed += 1
            if self._proposed >= self.max_points:
                break
        return batch

    def update(self, new_records: Sequence[CampaignRecordData]) -> None:
        for rec in new_records:
            label = rec.get("response", {}).get("state_label")
            if label == self.target_state_label:
                self._hit = True

    def converged(self) -> bool:
        return self._hit
