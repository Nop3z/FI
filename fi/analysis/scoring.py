# -*- coding: utf-8 -*-
"""候选参数评分接口（草案 v0.2，离线实现）。

闭环调参层调用方式::

    from fi.analysis.scoring import OfflineScorer, WindowScan

    scorer = OfflineScorer.load(r"data/derived/pointwise-rates.json",
                                target_label="SUCCESS")   # 目标标签显式传入
    report = scorer.score(WindowScan(delay_raw=(3130, 3190), pulse_raw=(2, 2)))
    for cand in report.candidates[:20]:
        print(cand.delay_raw, cand.score, cand.evidence["target_wilson95"])

设计要点：
- ``score(window_scan) -> ScoreReport``：输入参数窗口（或显式点集），输出按分数
  降序的候选点列表，每点附证据字段（密度/率值/错误码类别/与背景分离度）。
- **离线实现**只读 ``data/derived/pointwise-rates.json`` 的历史统计，不触任何实机。
- **增量重评（v0.2）**：``update_stats()`` 接受新观测（仿真注入 / 闭环回放产生的
  单元计数，counts 按数据集标签动态给定）合并进内存统计后直接重评；
  pulse 维天然支持（单元键含 pulse_raw，历史未覆盖的 pulse 值自动进
  ``coverage="unknown"`` 不外推；``covered_pulses()`` 返回有观测的 pulse 集合）。
- **单点判定 = 分布性质，不得过度置信**：同一参数点历史上可出现多种标签
  （finding non_deterministic_response，observation）；因此评分用 Wilson 95%
  **下界**并随观测数收窄，evidence 同时给出点估计/区间/邻居均值。
- 未知区域（窗口超出历史覆盖）**不外推**：score=0、coverage="unknown"、unknowns 标注。
- 评分公式（v0.2，保守可解释）：score = Wilson 95% 下界 of 目标标签率；
  平手按 delay 升序。分离度、邻居一致性、错误码画像只作为 evidence 输出，
  不进入分数（避免未经验证的加权）。
- ``target_label`` 为必填语义参数（哪个标签是"成功"是数据集语义，禁止代码默认）：
  未提供时 ``score()`` 直接抛错；合并后的持久化由调用方负责。

审计纪律（2026-11-09 通用性门禁）：状态标签/目标标签/背景标签不写死字面量——
标签集合从 pointwise 输入键名推导（``{label}_count``），目标标签由调用方显式传入，
背景标签取 overall_rates 中占比最高的标签（观测推导）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from math import log
from typing import Literal

from fi.analysis.schema import NS_PER_STEP_ASSUMED, UNIT_ASSUMPTION_TAG

_COUNT_KEY_RE = re.compile(r"^(\S+)_count$")


# ---------------------------------------------------------------------------
# 输入/输出契约
# ---------------------------------------------------------------------------
@dataclass
class WindowScan:
    """候选参数窗口。坐标默认 raw 步长；unit="ns" 时按 ns_per_step 反换算（A1）。"""

    delay_raw: tuple[int, int] | None = None
    pulse_raw: tuple[int, int] | None = None
    delay_ns: tuple[float, float] | None = None
    pulse_ns: tuple[float, float] | None = None
    step_delay: int = 1
    step_pulse: int = 1
    unit: Literal["raw", "ns"] = "raw"
    ns_per_step: float = NS_PER_STEP_ASSUMED
    max_candidates: int | None = None
    extra: dict = field(default_factory=dict)

    def resolve_raw(self) -> tuple[tuple[int, int], tuple[int, int]]:
        """统一换算为 raw 坐标（ns 输入依赖假设 A1，转换结果标注于报告）。"""
        if self.unit == "raw":
            d = self.delay_raw
            p = self.pulse_raw
        else:
            if self.delay_ns is None or self.pulse_ns is None:
                raise ValueError("unit='ns' 需要 delay_ns/pulse_ns")
            d = (int(self.delay_ns[0] / self.ns_per_step),
                 int(self.delay_ns[1] / self.ns_per_step))
            p = (int(self.pulse_ns[0] / self.ns_per_step),
                 int(self.pulse_ns[1] / self.ns_per_step))
        if d is None or p is None:
            raise ValueError("delay/pulse 范围缺失")
        return d, p


@dataclass
class Candidate:
    delay_raw: int
    pulse_raw: int
    delay_ns_assumed: float
    pulse_ns_assumed: float
    score: float
    coverage: Literal["observed", "unknown"]
    evidence: dict = field(default_factory=dict)
    unknowns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScoreReport:
    scan: dict
    stats_source: str
    target_label: str | None
    candidates: list[Candidate]
    warnings: list[str] = field(default_factory=list)
    unit_assumption: str = UNIT_ASSUMPTION_TAG

    def to_dict(self) -> dict:
        return {
            "scan": self.scan,
            "stats_source": self.stats_source,
            "target_label": self.target_label,
            "unit_assumption": self.unit_assumption,
            "warnings": self.warnings,
            "candidates": [c.to_dict() for c in self.candidates],
        }


# ---------------------------------------------------------------------------
# 离线评分器
# ---------------------------------------------------------------------------
class OfflineScorer:
    """读取 pointwise-rates.json 的离线评分实现（草案 v0.2）。"""

    def __init__(self, pointwise: dict, source: str = "<memory>",
                 target_label: str | None = None):
        self.pw = pointwise
        self.source = source
        self.target_label = target_label
        self.labels: list[str] = []
        self._by_cell: dict[tuple[int, int], dict] = {}
        for p in pointwise.get("points", []):
            self._by_cell[(p["delay_raw"], p["pulse_raw"])] = p
            for k in p:
                m = _COUNT_KEY_RE.match(k)
                if m and m.group(1) not in self.labels:
                    self.labels.append(m.group(1))
        rates = pointwise.get("overall_rates") or {}
        self.overall: dict[str, float] = dict(rates)
        # 背景标签 = overall_rates 中占比最高者（观测推导）
        self.background_label = (
            max(rates, key=lambda k: rates[k]) if rates else None
        )

    @classmethod
    def load(cls, path: str, target_label: str | None = None) -> "OfflineScorer":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f), source=path, target_label=target_label)

    # -- 主入口 ------------------------------------------------------------
    def score(self, scan: WindowScan) -> ScoreReport:
        if self.target_label is None:
            raise ValueError(
                "target_label 必填（评分目标标签是数据集语义，禁止代码默认值；"
                "请由调用方/配置显式传入）"
            )
        (d0, d1), (p0, p1) = scan.resolve_raw()
        warnings: list[str] = []
        if scan.unit == "ns":
            warnings.append(
                f"输入窗口为 ns，已按假设 A1（1 step={scan.ns_per_step:g}ns）反换算为 raw"
            )

        candidates: list[Candidate] = []
        n_unknown = 0
        for pv in range(p0, p1 + 1, scan.step_pulse):
            for dv in range(d0, d1 + 1, scan.step_delay):
                cand = self._score_cell(dv, pv)
                if cand.coverage == "unknown":
                    n_unknown += 1
                candidates.append(cand)
        candidates.sort(key=lambda c: (-c.score, c.delay_raw, c.pulse_raw))
        if scan.max_candidates is not None:
            candidates = candidates[: scan.max_candidates]
        if n_unknown:
            warnings.append(
                f"{n_unknown} 个窗口单元无历史观测（不外推，score=0，coverage=unknown）"
            )
        return ScoreReport(
            scan={
                "delay_raw_resolved": [d0, d1],
                "pulse_raw_resolved": [p0, p1],
                "step_delay": scan.step_delay,
                "step_pulse": scan.step_pulse,
                "requested_unit": scan.unit,
            },
            stats_source=self.source,
            target_label=self.target_label,
            candidates=candidates,
            warnings=warnings,
        )

    # -- 增量重评（v0.2，闭环要点）-----------------------------------------
    def covered_pulses(self) -> list[int]:
        """有历史观测的 pulse 值（闭环选窗口用；本批数据预期只有主 pulse）。"""
        return sorted({int(p) for (_d, p) in self._by_cell})

    def update_stats(self, updates) -> dict:
        """合并新观测单元计数并重算率值（内存内；持久化由调用方负责）。

        ``updates``: iterable of {"delay_raw": int, "pulse_raw": int,
        "counts": {<数据集标签>: int 计数}} —— 标签键必须与 pointwise 统计的
        标签一致（动态传入，不写死）。

        - 新单元（历史未覆盖，例如 pulse 维新扫描）自动建立骨架并转 observed；
        - 合并后重算每单元率值、目标 Wilson 区间与整体率，score() 即刻反映新证据；
        - 纪律：单点判定是分布性质（同点多标签），Wilson 下界随 n 变化，
          合并少量样本可能先降低 score 再回升——这是统计性质不是 bug。
        """
        from fi.analysis.distributions import wilson_interval

        if self.target_label is None:
            raise ValueError("update_stats 需要 target_label（见 score() 说明）")
        updated = 0
        for u in updates:
            key = (int(u["delay_raw"]), int(u["pulse_raw"]))
            cell = self._by_cell.get(key)
            if cell is None:
                cell = {
                    "delay_raw": key[0], "pulse_raw": key[1],
                    "delay_ns_assumed": round(key[0] * NS_PER_STEP_ASSUMED, 6),
                    "n": 0,
                    "non_fl_code_counts": {},
                }
                for s in self.labels:
                    cell[f"{s}_count"] = 0
                self._by_cell[key] = cell
            added = 0
            for label, k in (u.get("counts") or {}).items():
                fld = f"{label}_count"
                if fld not in cell:
                    self.labels.append(label)
                cell[fld] = int(cell.get(fld, 0)) + int(k)
                added += int(k)
            if not added:
                continue
            cell["n"] = int(cell.get("n", 0)) + added
            n = cell["n"]
            for fld in list(cell.keys()):
                if fld.endswith("_count"):
                    base = fld[: -len("_count")]
                    cell[f"{base}_rate"] = round(cell[fld] / n, 8)
            if self.target_label in cell:
                cell["target_wilson95"] = wilson_interval(
                    int(cell[f"{self.target_label}_count"]), n
                )
            updated += 1

        # 重算整体率（合并后）
        total_n = sum(int(c.get("n", 0)) for c in self._by_cell.values())
        if total_n:
            self.overall = {
                fld[: -len("_count")]: round(
                    sum(int(c.get(fld, 0)) for c in self._by_cell.values()) / total_n,
                    8,
                )
                for fld in self._by_cell[next(iter(self._by_cell))]
                if fld.endswith("_count")
            }
            self.background_label = (
                max(self.overall, key=lambda k: self.overall[k])
                if self.overall else None
            )
        return {"cells_updated": updated, "overall_rates": self.overall}

    # -- 单元评分 -----------------------------------------------------------
    def _score_cell(self, delay_raw: int, pulse_raw: int) -> Candidate:
        cell = self._by_cell.get((delay_raw, pulse_raw))
        if cell is None:
            return Candidate(
                delay_raw=delay_raw, pulse_raw=pulse_raw,
                delay_ns_assumed=delay_raw * NS_PER_STEP_ASSUMED,
                pulse_ns_assumed=pulse_raw * NS_PER_STEP_ASSUMED,
                score=0.0, coverage="unknown",
                evidence={},
                unknowns=[
                    "无历史观测：率值/错误码/背景分离度均 unknown",
                    "标签语义未证实（假设 A2）",
                ],
            )
        tl = self.target_label
        n = cell["n"]
        wilson = cell.get("target_wilson95")
        if wilson is None:  # 旧版 pointwise 无 target 字段时现算
            from fi.analysis.distributions import wilson_interval
            wilson = wilson_interval(int(cell.get(f"{tl}_count", 0)), n)
        score = float(wilson[0]) if wilson else 0.0
        target_rate = cell.get(f"{tl}_rate")
        bg = self.background_label
        bg_rate = cell.get(f"{bg}_rate") if bg else None
        neighbors = self._neighbor_mean(delay_raw, pulse_raw)
        codes = cell.get("non_fl_code_counts", {})
        total_codes = sum(codes.values())
        evidence = {
            "observed_n": n,
            "target_rate": target_rate,
            "target_wilson95": wilson,
            "target_z_vs_overall": cell.get(f"{tl}_z_vs_overall"),
            "label_rates": {
                s: cell.get(f"{s}_rate") for s in self.labels
            },
            "background_label": bg,
            "background_rate": bg_rate,
            "target_vs_background_separation": (
                round(target_rate / bg_rate, 8)
                if target_rate is not None and bg_rate
                else None
            ),  # 命中相对背景率的似然比（观测比率，非概率推断）
            "non_background_code_counts": codes,
            "code_diversity": (
                round(-sum((c / total_codes) * _ln(c / total_codes)
                           for c in codes.values() if c > 0), 4)
                if total_codes else 0.0
            ),
            "neighbor_mean_target_rate": neighbors,
            "coverage_note": "率值来自历史 CSV 重复注入（假设 A3：视为独立重复）",
            "single_point_caveat": (
                "同一参数点可出现多种标签（响应含随机成分）：本评分是分布性质"
                "的下界估计，禁止按点估计过度置信"
            ),
        }
        unknowns = ["标签语义未证实（假设 A2）"]
        if n < 1000:
            unknowns.append(f"观测重复数较少（n={n}），Wilson 区间宽")
        return Candidate(
            delay_raw=delay_raw, pulse_raw=pulse_raw,
            delay_ns_assumed=delay_raw * NS_PER_STEP_ASSUMED,
            pulse_ns_assumed=pulse_raw * NS_PER_STEP_ASSUMED,
            score=round(score, 8), coverage="observed",
            evidence=evidence, unknowns=unknowns,
        )

    def _neighbor_mean(self, delay_raw: int, pulse_raw: int) -> float | None:
        """相邻 delay 单元的目标标签平均率（±1、±2 raw）。"""
        tl = self.target_label
        vals = []
        for dd in (-2, -1, 1, 2):
            c = self._by_cell.get((delay_raw + dd, pulse_raw))
            if c is not None:
                v = c.get(f"{tl}_rate")
                if v is not None:
                    vals.append(v)
        if not vals:
            return None
        return round(sum(vals) / len(vals), 8)


def _ln(x: float) -> float:
    return log(x)


def sample_top_candidates(path: str, k: int = 20,
                          target_label: str | None = None) -> dict:
    """默认主扫描窗口示例，供派生 JSON 存档与闭环参考。

    ``target_label`` 透传（审计：无样例默认；未传时 ScoreReport.candidates 为空
    并在 warnings 说明）。
    """
    scorer = OfflineScorer.load(path, target_label=target_label)
    pw = scorer.pw
    mp = pw.get("main_pulse")
    if mp is None:
        raise ValueError("pointwise 缺少 main_pulse（评分窗口需要）")
    report = scorer.score(
        WindowScan(delay_raw=(min(p["delay_raw"] for p in pw["points"]),
                              max(p["delay_raw"] for p in pw["points"])),
                   pulse_raw=(mp, mp))
    )
    d = report.to_dict()
    d["candidates"] = d["candidates"][:k]
    return d
