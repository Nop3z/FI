"""InjectionOutcome → CampaignRecord（契约实例）组装。

组装规则（与 campaign-record.schema.json 一一对应）：
- params：优先用注入器实际施加值（applied_point），请求值作 delay_ns/pulse_ns；
  换算假设（如有）从 outcome.detail["unit_assumption"] 透传，evidence=hypothesis；
- response：原始标签按字面量透传 + state_label_semantics 常量 unconfirmed-v0.1；
  response_raw 映射 error_code_raw；responded 仅表示"有无响应字面量"这一
  机械事实；
- evidence_level：如实取自 outcome（CSV 回放=observation，仿真=hypothesis）。
"""

from __future__ import annotations

import re
from typing import Any

from fi import UNKNOWN
from fi.loop.types import InjectionOutcome, ParamPoint

# 符合 campaign-record.schema.json 的实例 dict。
CampaignRecordData = dict[str, Any]

#: responded 机械判定（lead 终审定义，观测级）：零特例。
#: 'NONE' 等占位字面量的语义解释走 evidence 分级，不进布尔字段。
_HEX_CODE_RE = re.compile(r"^0x[0-9a-fA-F]+$")  # 保留：供响应形态分析参考


def has_response(response_raw: str | None, unexpected_raw: str | None) -> bool:
    """responded 机械判定规则（2026-11-09 lead 终审定义，观测级机械事实）。

    定义：**数据源是否记录了响应 token**——response / unexpected 任一列
    非空（且非 unknown）即 True。不是解释级结论（"芯片是否真的发了响应"）：
    'NONE' 等占位字面量的语义解释走 evidence 分级（status-semantics.md §4），
    本函数零特例——特例就是隐藏的语义判断。
    """
    return bool(response_raw and response_raw != UNKNOWN) or bool(
        unexpected_raw and unexpected_raw != UNKNOWN
    )


def build_campaign_record(
    point: ParamPoint,
    outcome: InjectionOutcome,
    fault_context_ids: list[str],
    campaign_id: str,
    timestamp: str = UNKNOWN,
) -> CampaignRecordData:
    """组装一条 CampaignRecord。不做任何字段臆造：没有就 unknown/None。"""
    applied = outcome.applied_point or {}
    unit_assumption = outcome.detail.get("unit_assumption")

    params: dict[str, Any] = {
        "raw_delay": applied.get("delay_raw", UNKNOWN),
        "raw_pulse": applied.get("pulse_raw", UNKNOWN),
        "delay_ns": point.try_get("delay", "ns") if point.try_get("delay", "ns") is not None else UNKNOWN,
        "pulse_ns": point.try_get("pulse", "ns") if point.try_get("pulse", "ns") is not None else UNKNOWN,
    }
    if unit_assumption:
        params["unit_assumption"] = {
            "scale": unit_assumption.get("scale", UNKNOWN),
            "evidence_level": "hypothesis",
        }
    params["injector_id"] = outcome.source

    response_raw = outcome.response_raw
    unexpected_raw = outcome.detail.get("unexpected_raw")
    response: dict[str, Any] = {
        "state_label": outcome.state_label if outcome.state_label else UNKNOWN,
        "state_label_semantics": "unconfirmed-v0.1",
        "error_code_raw": response_raw if response_raw else UNKNOWN,
        "glitched_raw": outcome.detail.get("glitched_raw", UNKNOWN),
        "unexpected_raw": unexpected_raw if unexpected_raw else UNKNOWN,
        "responded": has_response(response_raw, unexpected_raw if unexpected_raw != UNKNOWN else None),
    }

    record: CampaignRecordData = {
        "schema_version": "0.2",
        "campaign_id": campaign_id,
        "params": params,
        "response": response,
        "fault_context_refs": fault_context_ids,
        "evidence_level": outcome.evidence_level,
        "timestamp": timestamp,
    }
    if outcome.raw_data_ref:
        record["raw_data_ref"] = outcome.raw_data_ref
    return record
