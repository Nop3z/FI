"""离线注入器 #1：CSVReplayInjector —— 历史实验 CSV 作为注入器输出回放。

语义：CSV 中每一行 (delay,pulse) → response/state 就是一次历史注入的
真实结果。本注入器把"给定参数点"映射到历史行并回放其结果，让闭环的
策略/分析层在无硬件条件下端到端运转。

单位纪律（禁止隐式换算）：
- 参数点是 delay_raw/pulse_raw 时直接精确匹配历史行；
- 参数点是 delay_ns/pulse_ns 时必须显式提供 ns_per_raw（构造参数），
  且换算按工作假设处理（evidence=hypothesis，写进 outcome.detail）；
  ns_per_raw 的数值（如 10）属于数据集假设，禁止写成本模块默认值。
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fi import UNKNOWN
from fi.loop.injector import Injector
from fi.loop.records import has_response as _has_response
from fi.loop.types import InjectionOutcome, ParamPoint

MATCH_MODES = ("exact", "nearest", "sequential")


@dataclass(frozen=True)
class _Row:
    delay_raw: int
    pulse_raw: int
    state: str
    response: str
    glitched: str
    unexpected: str
    row_index: int  # 0 起始数据行号（不含表头）


class CSVReplayInjector(Injector):
    """把历史 CSV 当作注入器输出回放（evidence=observation）。"""

    name = "csv-replay"

    def __init__(
        self,
        csv_path: str | Path,
        ns_per_raw: float | None = None,
        match: str = "nearest",
        unit_assumption_note: str | None = None,
    ) -> None:
        if match not in MATCH_MODES:
            raise ValueError(f"match 必须是 {MATCH_MODES} 之一")
        self.csv_path = Path(csv_path)
        self.ns_per_raw = ns_per_raw  # None = 不支持 ns 参数点（显式配置才启用）
        self.match = match
        self.unit_assumption_note = unit_assumption_note
        self._rows: list[_Row] | None = None
        self._by_params: dict[tuple[int, int], list[int]] | None = None
        self._counts: dict[tuple[int, int], int] = defaultdict(int)
        self._seq_cursor = 0

    # ---------- 数据加载 ----------

    def _load(self) -> None:
        if self._rows is not None:
            return
        rows: list[_Row] = []
        with self.csv_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for idx, rec in enumerate(reader):
                rows.append(
                    _Row(
                        delay_raw=int(rec["delay"]),
                        pulse_raw=int(rec["pulse"]),
                        state=rec["state"],
                        response=rec["response"],
                        glitched=rec["glitched"],
                        unexpected=rec["unexpected"],
                        row_index=idx,
                    )
                )
        self._rows = rows
        by_params: dict[tuple[int, int], list[int]] = defaultdict(list)
        for i, r in enumerate(rows):
            by_params[(r.delay_raw, r.pulse_raw)].append(i)
        self._by_params = dict(by_params)

    # ---------- 参数解析 ----------

    def _resolve_raw(self, point: ParamPoint) -> tuple[int, int] | None:
        """把参数点解析为 raw (delay, pulse)；解析不了返回 None。"""
        d_raw = point.try_get("delay", "raw")
        p_raw = point.try_get("pulse", "raw")
        if d_raw is not None and p_raw is not None:
            return int(d_raw), int(p_raw)

        d_ns = point.try_get("delay", "ns")
        p_ns = point.try_get("pulse", "ns")
        if d_ns is not None and p_ns is not None:
            if self.ns_per_raw is None:
                return None  # 未显式配置换算，拒绝臆测
            return int(round(d_ns / self.ns_per_raw)), int(round(p_ns / self.ns_per_raw))
        return None

    def _unit_assumption_detail(self) -> dict[str, Any] | None:
        if self.ns_per_raw is None:
            return None
        scale = f"1 raw unit = {self.ns_per_raw} ns"
        if self.unit_assumption_note:
            scale = f"{scale}（{self.unit_assumption_note}）"
        return {"scale": scale}

    # ---------- 行匹配 ----------

    def _pick_row(self, raw: tuple[int, int] | None) -> _Row | None:
        self._load()
        rows = self._rows
        assert rows is not None and self._by_params is not None

        if self.match == "sequential":
            if not rows:
                return None
            idx = self._seq_cursor % len(rows)
            self._seq_cursor += 1
            return rows[idx]

        if raw is None:
            return None
        candidates = self._by_params.get(raw)
        if candidates:
            # 同参数多行：第 k 次请求取第 k 行（循环），保证确定性与重放多样性
            k = self._counts[raw]
            self._counts[raw] = k + 1
            return rows[candidates[k % len(candidates)]]

        if self.match == "nearest":
            best = min(
                self._by_params.keys(),
                key=lambda key: (abs(key[0] - raw[0]), abs(key[1] - raw[1])),
            )
            candidates = self._by_params[best]
            k = self._counts[best]
            self._counts[best] = k + 1
            return rows[candidates[k % len(candidates)]]
        return None  # exact 无匹配

    # ---------- Injector 接口 ----------

    def inject(self, point: ParamPoint) -> InjectionOutcome:
        raw = self._resolve_raw(point)
        if self.match != "sequential" and raw is None:
            return InjectionOutcome(
                point=point,
                status="error",
                evidence_level="observation",
                source=self.name,
                detail={
                    "reason": (
                        "参数点缺少 delay_raw/pulse_raw，且未显式配置 ns_per_raw；"
                        "禁止隐式 ns→raw 换算"
                    )
                },
            )

        row = self._pick_row(raw)
        if row is None:
            return InjectionOutcome(
                point=point,
                status="no_match",
                evidence_level="observation",
                source=self.name,
                detail={"reason": f"CSV 中无匹配行 raw={raw}（match={self.match}）"},
            )

        detail: dict[str, Any] = {
            "match_mode": self.match,
            "glitched_raw": row.glitched if row.glitched else UNKNOWN,
            "unexpected_raw": row.unexpected if row.unexpected else UNKNOWN,
        }
        ua = self._unit_assumption_detail()
        if ua:
            detail["unit_assumption"] = ua

        return InjectionOutcome(
            point=point,
            status="injected",
            evidence_level="observation",
            response_raw=row.response if row.response else None,
            state_label=row.state if row.state else None,
            applied_point={"delay_raw": row.delay_raw, "pulse_raw": row.pulse_raw},
            raw_data_ref={
                "kind": "csv",
                "path": str(self.csv_path),
                "row_index": row.row_index,
                "checksum": UNKNOWN,
            },
            source=self.name,
            detail=detail,
        )


# ----------------------------------------------------------------
# CSV → CampaignRecord 契约实例（CLI `fi data convert` 与测试共用）


def iter_campaign_records(
    csv_path: str | Path,
    limit: int | None = None,
    states: list[str] | None = None,
    ns_per_raw: float | None = None,
) -> Iterator[dict[str, Any]]:
    """把历史实验 CSV 逐行转换为 CampaignRecord 契约实例。

    - 原始标签/响应码按字面量透传，语义标记 unconfirmed-v0.1；
    - ns_per_raw 未显式提供时 delay_ns/pulse_ns 保持 unknown（禁止隐式换算）；
    - states 过滤原始标签（字面匹配）；limit 限制输出条数（过滤后计数）；
    - responded 机械判定规则（2026-11-09 裁定，见 status-semantics.md §4）：
      response 列非空，或 unexpected 列为 "OK"/十六进制错误码形态 → True；
      unexpected 列为空串或 "NONE" → False（仅记录"上位机记了 NONE 字面量"，
      不做语义解释）。纯形态匹配，无语义假设。
    """
    wanted = set(states) if states else None
    emitted = 0
    with Path(csv_path).open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for idx, rec in enumerate(reader):
            state = rec["state"]
            if wanted is not None and state not in wanted:
                continue
            if limit is not None and emitted >= limit:
                break

            params: dict[str, Any] = {
                "raw_delay": int(rec["delay"]),
                "raw_pulse": int(rec["pulse"]),
                "delay_ns": UNKNOWN,
                "pulse_ns": UNKNOWN,
                "injector_id": UNKNOWN,  # 历史数据的原始注入器未知
            }
            if ns_per_raw is not None:
                params["delay_ns"] = int(round(int(rec["delay"]) * ns_per_raw))
                params["pulse_ns"] = int(round(int(rec["pulse"]) * ns_per_raw))
                params["unit_assumption"] = {
                    "scale": f"1 raw unit = {ns_per_raw} ns",
                    "evidence_level": "hypothesis",
                }

            response_raw = rec["response"]
            unexpected_raw = rec["unexpected"]
            record: dict[str, Any] = {
                "schema_version": "0.2",
                "campaign_id": f"{Path(csv_path).stem}-{idx:08d}",
                "params": params,
                "response": {
                    "state_label": state if state else UNKNOWN,
                    "state_label_semantics": "unconfirmed-v0.1",
                    "error_code_raw": response_raw if response_raw else UNKNOWN,
                    "glitched_raw": rec["glitched"] if rec["glitched"] else UNKNOWN,
                    "unexpected_raw": unexpected_raw if unexpected_raw else UNKNOWN,
                    "responded": _has_response(response_raw, unexpected_raw),
                },
                "fault_context_refs": [],
                "raw_data_ref": {
                    "kind": "csv",
                    "path": str(csv_path),
                    "row_index": idx,
                    "checksum": UNKNOWN,
                },
                "evidence_level": "observation",
                "timestamp": UNKNOWN,
            }
            emitted += 1
            yield record
