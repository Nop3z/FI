# -*- coding: utf-8 -*-
"""常量、假设声明与规范化规则（schema 层）。

本模块是全包「观测 / 假设 / 未知」三级标注的单一来源：
- ``ASSUMPTIONS``：集中声明的全部工作假设（报告头部逐条引用）。
- 状态标签枚举、样例错误码、pulse/基址等**数据集值不在此定义**——
  一律由调用方显式参数传入、从数据观测推导（输出标注 ``*_derived``）、
  或经样例运行配置注入（审计：通用代码零样例默认值）。
- 哨兵 token（如历史样例中的 ``OK`` / ``NONE``）规范化时原样保留为 token，
  不与 0xHHHH 错误码混类；具体集合不硬编码。
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# 单位换算（工作假设，未经用户确认）
# ---------------------------------------------------------------------------
#: delay/pulse 原始步长假设换算：1 raw step ≈ 10 ns。
#: 依据：用户示例窗口 27000–38000 ns 与数据 delay∈[2640,3190] 量级吻合
#: （docs/requirement-baseline.md §4），**未证实**。
NS_PER_STEP_ASSUMED: Final[float] = 10.0

#: 派生文件单位假设标记（由假设常量动态构成，避免重复字面量）
UNIT_ASSUMPTION_TAG: Final[str] = (
    f"{NS_PER_STEP_ASSUMED:g}ns_per_step_unverified"
)

# ---------------------------------------------------------------------------
# 假设集中声明（报告/meta 头部逐条引用；任何 ns 字段均继承第 1 条）
# ---------------------------------------------------------------------------
ASSUMPTIONS: Final[list[dict]] = [
    {
        "id": "A1",
        "claim": "delay/pulse 原始值按 1 step = 10 ns 换算为 ns",
        "basis": "用户示例窗口 27000–38000ns 与数据范围 2640–3190 量级吻合（量级推断）",
        "status": "unverified",  # unknown：待用户实验配置确认
    },
    {
        "id": "A2",
        "claim": "状态标签 FL/HANG/SUCCESS/UNEXPECTED/Fake_Success 按原始标签使用，不解释语义",
        "basis": "用户未确认标签含义（baseline §5.5）",
        "status": "labels_as_written",
    },
    {
        "id": "A3",
        "claim": "同一 (delay,pulse) 的多次重复注入视为独立同分布重复试验",
        "basis": "行序随机化（lag-1 自相关 ≈ 0.0007）且每点重复次数均匀（卡方 p≈0.85）",
        "status": "working_assumption_from_observation",
    },
    {
        "id": "A4",
        "claim": "response 与 unexpected 两列非空时视为同一码的两份拷贝（冗余列）",
        "basis": "观测：两列同时非空的 2,840 行中 100% 逐字符相等",
        "status": "observed_in_this_file",
    },
]

# ---------------------------------------------------------------------------
# 状态标签
# ---------------------------------------------------------------------------
#: 状态标签枚举**不在此定义**（审计：数据集字面量禁止进入通用代码）。
#: 历史样例观测到的标签集合见 docs/analysis 报告与样例运行配置；
#: 枚举校验经 ``parser.clean_typed(known_labels=...)`` 由调用方注入。

#: 历史观测事实（<DATASET> 样例）：主扫描 pulse 原始值为 2。
#: 审计纪律：该样例值不作为任何代码路径的默认值，调用方显式传入或从数据推导。

# ---------------------------------------------------------------------------
# 列名
# ---------------------------------------------------------------------------
COL_STATE = "state"
COL_DELAY = "delay"
COL_PULSE = "pulse"
COL_RESPONSE = "response"
COL_GLITCHED = "glitched"
COL_UNEXPECTED = "unexpected"

#: glitched 列处理规则（观测规则）：非空即标记；历史样例为恒定单值字面量
#: （无对照取值，判定规则 unknown）。具体字面量不硬编码进代码。

#: 哨兵 token 处理规则（观测规则）：非 0x 前缀的非空字面量（如历史样例中的
#: ``OK`` / ``NONE``）规范化时原样保留为 token，不与 0xHHHH 错误码混类。
#: 审计纪律：具体 token 集合不硬编码，由调用方从数据观测推导或配置传入。


def normalize_code(value: str) -> str | None:
    """规范化 response/unexpected 单元格。

    规则（均为观测规则，不做语义解释）：
    - 空串 ``""`` → ``None``（JSON null，表示无值）。
    - ``0xHHHH`` 形式的码 → 保留原字符串（大小写按原文）。
    - 哨兵 token（``OK`` / ``NONE``）→ 原样返回。
    - 其他值 → 原样返回（枚举之外的自见表值不丢弃，报告以 unknown 类别汇总）。
    """
    if value is None:
        return None
    v = value.strip()
    if v == "":
        return None
    return v


def steps_to_ns(steps: float, ns_per_step: float = NS_PER_STEP_ASSUMED) -> float:
    """原始步长 → ns（继承 A1 假设；调用方须在输出中标注该假设）。"""
    return steps * ns_per_step


def code_class_of(response_norm: str | None, unexpected_norm: str | None) -> str:
    """观测分类（code_class），仅依据列值本身，不含语义：

    - response 有值 → 该值（如 ``0x<CODE_A>``、``NONE``）；
    - response 空、unexpected 有值 → unexpected 值（码或哨兵 token 原样）；
    - 两者皆空 → ``"no_response"``（无响应行的观测特征）。
    """
    if response_norm is not None:
        return response_norm
    if unexpected_norm is not None:
        return unexpected_norm
    return "no_response"
