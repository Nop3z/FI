"""Analyzer 接口契约（core-contract 维护；实现归 exp-analysis 专职）。

调用方（闭环编排器 / CLI）约定：
- analyze() 的输入是 ExperimentScan 契约实例（含 records_ref 明细引用）
  与可选的 FaultContext 列表；
- 输出必须通过 analysis-result.schema.json 校验；
- 候选路径一律 evidence_level=hypothesis 及以下，不得写成已证实轨迹；
- confirmed 与 hypothesized 结论分离。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

# 符合 experiment-scan / analysis-result 契约的实例 dict。
ExperimentScanData = dict[str, Any]
AnalysisResultData = dict[str, Any]


class Analyzer(ABC):
    """实验数据分析器接口。"""

    #: 分析器标识。
    name: str = "unknown"

    @abstractmethod
    def analyze(
        self,
        scan: ExperimentScanData,
        contexts: list[dict[str, Any]] | None = None,
    ) -> AnalysisResultData:
        """对一次参数窗口扫描做分析，产出 AnalysisResult 契约实例。

        scan["records_ref"]["path"] 指向 CampaignRecord JSONL 明细；
        contexts 为可选的三层观测上下文（FaultContext 实例列表）。
        """
