# -*- coding: utf-8 -*-
"""契约对接层：把分析层产出对齐 core-contract 的 v0.1 契约实例。

明细转换**复用 core-contract 的单一实现**（lead 2026-11-09 指示）：
``fi.loop.csv_replay.iter_campaign_records`` —— 本模块只做落盘包装与
ExperimentScan 实例组装，不再自行映射字段。

注意（口径备忘，交由 core-contract 裁定）：
- csv_replay 的 ``responded = bool(response_raw)``：SUCCESS 行 response 为空、
  unexpected='OK' 时会记为 responded=False；契约 schema 的示例里 SUCCESS 行
  responded=True。本包 typed JSONL 保留全量列值（response_norm/unexpected_norm），
  分析口径不受影响。
- 契约纪律：``delay_ns``/``pulse_ns`` 在单位假设证实前为 unknown
  （ns 换算只保留在本包自己的派生文件里并标注假设 A1）。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fi.analysis.schema import NS_PER_STEP_ASSUMED

SCHEMA_VERSION = "0.1"
#: 单位假设文本引用 schema 假设常量（审计：样例数值单一来源，不在通用代码重复字面量）
UNIT_ASSUMPTION_CONTRACT = {
    "scale": f"1 raw unit = {NS_PER_STEP_ASSUMED:g} ns",
    "evidence_level": "hypothesis",
}


def _sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_campaign_jsonl(csv_path: str, out_path: str) -> int:
    """CSV → CampaignRecord v0.1 JSONL（复用 fi.loop.csv_replay 单一实现）。

    返回行数。checksum 由调用方对 out_path 另行计算（本函数不写 checksum 字段，
    ExperimentScan.records_ref.checksum 在 build_experiment_scan 里填）。
    """
    from fi.loop.csv_replay import iter_campaign_records

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for rec in iter_campaign_records(csv_path):
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
            n += 1
    return n


def build_experiment_scan(
    *,
    scan_id: str,
    records_path: str,
    records_count: int,
    records_sha256: str,
    state_details: dict,
    delay_min: int,
    delay_max: int,
    pulse_min: int,
    pulse_max: int,
    pulse_step_known: bool,
    timestamp: str = "unknown",
) -> dict:
    """生成 ExperimentScan v0.1 实例（不落盘；调用方写 JSON）。

    ``state_details``: {label: {"count": n, "delay_min": d0, "delay_max": d1}}
    （由调用方从分布事实准备；label 键为原始标签字面量。）
    pulse 窗口由调用方从数据观测推导后显式传入（审计：无样例默认值）。
    """
    by_state = {}
    for label, info in state_details.items():
        by_state[label] = {
            "count": info["count"],
            "delay_min": info.get("delay_min"),
            "delay_max": info.get("delay_max"),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id,
        "window": [
            {"axis": "delay", "min_value": delay_min, "max_value": delay_max,
             "step_value": 1, "unit": "raw"},
            {"axis": "pulse", "min_value": pulse_min, "max_value": pulse_max,
             "step_value": 1 if pulse_step_known else "unknown", "unit": "raw"},
        ],
        "unit_assumption": dict(UNIT_ASSUMPTION_CONTRACT),
        "records_ref": {
            "path": records_path,
            "count": records_count,
            "checksum": records_sha256,
        },
        "summary": {
            "total_records": sum(v["count"] for v in state_details.values()),
            "by_state": by_state,
        },
        "evidence_level": "observation",
        "timestamp": timestamp,
    }
