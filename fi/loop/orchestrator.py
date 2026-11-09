"""LoopOrchestrator：闭环编排器接口 + 通用实现。

编排时序（一轮）：
    next_batch(window, history) → 逐点 inject(point)
    → 并行 collect observers（detect→capture→normalize→validate）
    → 组装 CampaignRecord → strategy.update → converged?

观测器（observers）是 CaptureProvider 列表：硬件 Provider（uart/trap/...）
仅接口预留，离线阶段传空列表即可——响应事实已由 InjectionOutcome 携带。
Provider.detect() 不可用时跳过并计数，不中断闭环。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from fi.loop.injector import Injector
from fi.loop.providers_shim import collect_contexts
from fi.loop.strategy import CampaignRecordData, LoopStrategy
from fi.loop.types import ParamPoint, ParamWindow
from fi.providers.base import CaptureProvider
from fi.loop.records import build_campaign_record
from fi import UNKNOWN


@dataclass
class LoopResult:
    """一次闭环运行的产物。"""

    records: list[CampaignRecordData] = field(default_factory=list)
    """全部 CampaignRecord（契约实例列表；可直接 dump 成 JSONL 交付）。"""

    rounds: int = 0
    """执行的轮数。"""

    converged: bool = False
    """策略是否报告收敛。"""

    stop_reason: str = UNKNOWN
    """结束原因：converged / empty_batch / max_rounds / injector_exhausted。"""

    context_problems: list[str] = field(default_factory=list)
    """观测上下文校验问题汇总（含 unknown 审计 hint）。"""

    notes: dict[str, Any] = field(default_factory=dict)
    """编排器附加统计（no_match 计数、observer 跳过计数等）。"""


class LoopOrchestrator(ABC):
    """闭环编排器接口。"""

    @abstractmethod
    def run(
        self,
        window: ParamWindow,
        strategy: LoopStrategy,
        injector: Injector,
        observers: list[CaptureProvider],
    ) -> LoopResult:
        """执行闭环：窗口 + 策略 + 注入器 + 观测器 → 实验记录流。"""


class GenericLoopOrchestrator(LoopOrchestrator):
    """通用闭环编排器（默认实现，可整体替换）。

    campaign_id 生成规则：camp-{UTC时间戳}-{序号}，时间由调用方经 clock 注入
    便于测试复现；不传时用 unknown（不谎报时间）。
    """

    def __init__(
        self,
        max_rounds: int = 10,
        batch_size: int | None = None,
        clock: Any = None,
        campaign_id_prefix: str = "camp",
    ) -> None:
        self.max_rounds = max_rounds
        self.batch_size = batch_size  # None = 交由策略决定批大小
        self.clock = clock            # 可选：返回 ISO 字符串的可调用
        self.campaign_id_prefix = campaign_id_prefix

    def run(
        self,
        window: ParamWindow,
        strategy: LoopStrategy,
        injector: Injector,
        observers: list[CaptureProvider],
    ) -> LoopResult:
        result = LoopResult()
        seq = 0
        no_match = 0
        observer_skipped = 0

        for _round in range(1, self.max_rounds + 1):
            batch = strategy.next_batch(window, result.records)
            if self.batch_size is not None:
                batch = batch[: self.batch_size]
            if not batch:
                result.stop_reason = "empty_batch"
                break

            for point in batch:
                seq += 1
                outcome = injector.inject(point)
                if outcome.status == "no_match":
                    no_match += 1

                contexts, problems, skipped = collect_contexts(
                    observers,
                    campaign_id=f"{self.campaign_id_prefix}-{seq:06d}",
                )
                observer_skipped += skipped
                result.context_problems.extend(problems)

                record = build_campaign_record(
                    point=point,
                    outcome=outcome,
                    fault_context_ids=[c["context_id"] for c in contexts],
                    campaign_id=f"{self.campaign_id_prefix}-{seq:06d}",
                    timestamp=self.clock() if self.clock else UNKNOWN,
                )
                result.records.append(record)

            strategy.update(result.records[-len(batch):])
            result.rounds = _round

            if strategy.converged():
                result.converged = True
                result.stop_reason = "converged"
                break
        else:
            result.stop_reason = "max_rounds"

        result.notes["no_match"] = no_match
        result.notes["observer_skipped"] = observer_skipped
        return result
