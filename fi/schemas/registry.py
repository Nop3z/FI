"""契约 schema 清单注册表（v0.1）。

新增契约 = 在 ``docs/contracts/schemas/`` 加文件 + 在此登记 + 更新 CHANGELOG。
``common`` 仅为公共 defs，不能直接用于校验实例，因此标记 ``instantiable=False``。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

#: 契约 $id 的 URI 前缀。相对 $ref（如 "common.defs.json"）基于 $id 解析，
#: 加载器会把本地文件注册到这些 URI 上，实例校验不依赖网络。
URI_PREFIX: Final[str] = "https://fi-converters.invalid/contracts/v0.1"


@dataclass(frozen=True)
class SchemaEntry:
    """一条契约的登记项。"""

    name: str                 # CLI/调用方使用的短名
    filename: str             # docs/contracts/schemas/ 下文件名
    title: str                # 人类可读标题
    instantiable: bool = True # False = 仅 defs，不可直接校验实例


SCHEMA_REGISTRY: Final[dict[str, SchemaEntry]] = {
    entry.name: entry
    for entry in (
        SchemaEntry(
            name="common",
            filename="common.defs.json",
            title="公共定义（证据等级/unknown 标记/通用类型）",
            instantiable=False,
        ),
        SchemaEntry(
            name="fault-context",
            filename="fault-context.schema.json",
            title="FaultContext 故障现场统一上下文",
        ),
        SchemaEntry(
            name="campaign-record",
            filename="campaign-record.schema.json",
            title="CampaignRecord 单次注入实验记录",
        ),
        SchemaEntry(
            name="experiment-scan",
            filename="experiment-scan.schema.json",
            title="ExperimentScan 参数窗口扫描汇总",
        ),
        SchemaEntry(
            name="chip-profile-index",
            filename="chip-profile-index.schema.json",
            title="ChipProfile 索引引用约定（格式本身归 chip-profile 专职）",
        ),
        SchemaEntry(
            name="analysis-result",
            filename="analysis-result.schema.json",
            title="AnalysisResult 分析结论",
        ),
        SchemaEntry(
            name="sim-trace",
            filename="sim-trace.schema.json",
            title="SimTrace 仿真轨迹 JSONL（run_meta/trace/fault_event/run_end）",
        ),
        # ---- v0.3（逆向先行 P0 + 自动发现管线 P2）----
        SchemaEntry(
            name="reverse-report",
            filename="reverse-report.schema.json",
            title="ReverseReport 功能级逆向结论（目标功能/调用链/时间估算/注入靶点）",
        ),
        SchemaEntry(
            name="discover-report",
            filename="discover-report.schema.json",
            title="DiscoverReport 自动发现报告（confidence 仅 hypothesis|unknown）",
        ),
        SchemaEntry(
            name="tts-metrics",
            filename="tts-metrics.schema.json",
            title="TTSMetrics 芯片接入耗时与吞吐指标（待定稿）",
        ),
        SchemaEntry(
            name="anomaly-report",
            filename="anomaly-report.schema.json",
            title="AnomalyReport 异常数据综合分析报告（六块骨架 + 统计警示 + 证据链）",
        ),
        # ---- v0.4（故障效果推演：从"打中哪条指令"到"为什么是这个观测"）----
        SchemaEntry(
            name="fault-effect",
            filename="fault-effect.schema.json",
            title="FaultEffect 位翻转效果枚举（confidence 恒 hypothesis）",
        ),
        SchemaEntry(
            name="fault-explanation",
            filename="fault-explanation.schema.json",
            title="FaultExplanation 观测反解（允许多解，confidence 恒 hypothesis）",
        ),
        SchemaEntry(
            name="observation-classification",
            filename="observation-classification.schema.json",
            title="ObservationClassification 观测五色分类（confidence 恒 observation）",
        ),
        SchemaEntry(
            name="bitflip-evidence",
            filename="bitflip-evidence.schema.json",
            title="BitflipEvidence 位翻转关键证据（含寄存器掩码防坑字段 + XOR 不变量）",
        ),
        SchemaEntry(
            name="live-experiment",
            filename="live-experiment.schema.json",
            title="LiveExperiment 实机实验记录（Captured State，与 Simulated 严格分开）",
        ),
    )
}
