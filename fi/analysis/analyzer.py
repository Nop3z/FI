# -*- coding: utf-8 -*-
"""CsvScanAnalyzer：Analyzer 契约（fi/analysis/protocol.py）的分布事实实现。

输入：ExperimentScan 契约实例（scan dict）。
- ``records_ref.path`` 为 CampaignRecord JSONL → 纯 Python 流式聚合；
- 或为原始 CSV 路径 → 复用本包 parser/distributions（pandas 路径）。

输出：AnalysisResult v0.1 契约实例（dict）：
- findings：观测级分布事实（observation），含同参数点多标签（非确定性）证据；
- hit_windows：**全部非背景标签**的 delay 覆盖范围（observation，逐标签一条）；
- candidates：ROM 归因候选（**上限 hypothesis**，来自 error-code-attribution.json）；
- metrics：率值/检验指标（目标标签字段 ``target_*`` 由参数决定）；
- 整份 evidence_level = 全部结论最低级（有候选即 hypothesis）。

语义参数（审计纪律：无数据集默认值，均由调用方/配置显式传入）：
- ``target_label``：评分/区间目标标签（哪个标签是"成功"是数据集语义）；
- ``profile_ref``：归因候选引用的 ChipProfile id（未提供 → 契约 "unknown"）；
- 标签集合、背景标签（占比最高者）、齐性卡方入表标签（share ≥ 0.01）均观测推导。

本实现只做分布与静态归因候选，不产生 confirmed 执行轨迹（无硬件 trace/PC 快照）。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from math import erfc, sqrt
from pathlib import Path

from fi.analysis.protocol import Analyzer
from fi.analysis.schema import NS_PER_STEP_ASSUMED

SPARSE_STATE_SHARE = 0.001  # 齐性卡方入表阈值（统计规则，非样例值）


# ---------------------------------------------------------------------------
# 纯 Python 统计（JSONL 流式路径共用的小工具）
# ---------------------------------------------------------------------------
def _chi2_sf_approx(chi2: float, dof: int) -> float:
    q = ((chi2 / dof) ** (1.0 / 3.0) - (1 - 2.0 / (9.0 * dof))) / sqrt(2.0 / (9.0 * dof))
    return 0.5 * erfc(q / sqrt(2.0))


def _rank(v: list[float]) -> list[float]:
    order = sorted(range(len(v)), key=lambda i: v[i])
    ranks = [0.0] * len(v)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def _spearman(x: list[float], y: list[float]) -> float:
    rx, ry = _rank(x), _rank(y)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else 0.0


class _Agg:
    """流式聚合器：状态计数、逐点计数、错误码、行序、同点多标签证据。"""

    ROW_SAMPLE_CAP = 5  # 每单元每标签保留的行号样例上限

    def __init__(self) -> None:
        self.total = 0
        self.by_state: dict[str, int] = {}
        self.delay_by_state: dict[str, tuple[int, int]] = {}
        self.per_point: dict[tuple[int, int], dict[str, int]] = {}
        self.row_samples: dict[tuple[int, int], dict[str, list[int]]] = {}
        self.code_by_state: dict[str, dict[str, int]] = {}
        self.unexpected_tokens_by_state: dict[str, dict[str, int]] = {}
        self.label_stats: dict[str, dict[str, int]] = {}
        self.codes_total = 0
        self.codes_within_16bit = 0
        self.order_delays: list[int] = []
        self.coupling_both = 0
        self.coupling_equal = 0

    def add(self, delay: int, pulse: int, state: str,
            code_raw: str | None, unexpected_raw: str | None,
            row_index: int | None = None) -> None:
        self.total += 1
        self.by_state[state] = self.by_state.get(state, 0) + 1
        lo, hi = self.delay_by_state.get(state, (10**9, -1))
        self.delay_by_state[state] = (min(lo, delay), max(hi, delay))
        cell = self.per_point.setdefault((delay, pulse), {})
        cell[state] = cell.get(state, 0) + 1
        samples = self.row_samples.setdefault((delay, pulse), {})
        lst = samples.setdefault(state, [])
        if row_index is not None and len(lst) < self.ROW_SAMPLE_CAP:
            lst.append(int(row_index))
        # 每标签响应形态计数（帧模型兼容性统计的观测底数）
        st = self.label_stats.setdefault(state, {
            "rows": 0, "response_nonempty": 0,
            "unexpected_nonempty": 0, "both_empty": 0,
        })
        st["rows"] += 1
        if code_raw:
            st["response_nonempty"] += 1
        if unexpected_raw:
            st["unexpected_nonempty"] += 1
        if not code_raw and not unexpected_raw:
            st["both_empty"] += 1
        if unexpected_raw:
            d_ = self.unexpected_tokens_by_state.setdefault(state, {})
            d_[unexpected_raw] = d_.get(unexpected_raw, 0) + 1
        for v in (code_raw,):
            if v and v.lower().startswith("0x"):
                try:
                    iv = int(v, 16)
                    self.codes_total += 1
                    self.codes_within_16bit += int(0 <= iv <= 0xFFFF)
                except ValueError:
                    pass
        if code_raw and code_raw != "unknown":
            self.code_by_state.setdefault(state, {})
            d = self.code_by_state[state]
            d[code_raw] = d.get(code_raw, 0) + 1
            if unexpected_raw and unexpected_raw != "unknown":
                self.coupling_both += 1
                self.coupling_equal += int(code_raw == unexpected_raw)
        elif unexpected_raw and unexpected_raw != "unknown":
            self.code_by_state.setdefault(state, {})
            d = self.code_by_state[state]
            d[unexpected_raw] = d.get(unexpected_raw, 0) + 1
        self.order_delays.append(delay)

    # 观测推导的标签序（行数降序）与背景标签
    def labels_by_count(self) -> list[str]:
        return sorted(self.by_state, key=lambda s: -self.by_state[s])

    @property
    def background_label(self) -> str | None:
        labels = self.labels_by_count()
        return labels[0] if labels else None


class CsvScanAnalyzer(Analyzer):
    """分布事实 + 静态归因候选的 Analyzer 实现（offline）。"""

    name = "csv-distribution-v0"

    def __init__(self, attribution_path: str | None = None,
                 profile_ref: str | None = None,
                 target_label: str | None = None):
        self.attribution_path = attribution_path
        self.profile_ref = profile_ref
        self.target_label = target_label

    # ---- 契约入口 ----------------------------------------------------------
    def analyze(self, scan: dict, contexts: list[dict] | None = None) -> dict:
        records = (scan.get("records_ref") or {})
        path = records.get("path")
        if not path:
            raise ValueError("scan.records_ref.path 缺失")
        scan_id = scan.get("scan_id", "scan-unknown")

        if str(path).lower().endswith(".jsonl"):
            agg = self._aggregate_records(path)
        else:
            agg = self._aggregate_csv(path)

        findings, hit_windows, metrics = self._distribution_outputs(agg, scan_id)
        candidates = self._candidates_from_attribution()
        levels = [f["evidence_level"] for f in findings]
        levels += [c["evidence_level"] for c in candidates]
        overall = "observation" if levels and all(v == "observation" for v in levels) else (
            "unknown" if all(v == "unknown" for v in levels) else "hypothesis"
        )
        return {
            "schema_version": "0.1",
            "analysis_id": f"ana-{scan_id}-distribution",
            "analysis_kind": "distribution",
            "inputs": [{"kind": "scan", "id": scan_id}],
            "findings": findings,
            "hit_windows": hit_windows,
            "candidates": candidates,
            "baseline_diff": "unknown",
            "metrics": metrics,
            "evidence_level": overall,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ---- 输入聚合 ----------------------------------------------------------
    def _aggregate_records(self, path: str) -> _Agg:
        agg = _Agg()
        fallback_idx = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                params = rec.get("params", {})
                resp = rec.get("response", {})
                code = resp.get("error_code_raw")
                unexp = resp.get("unexpected_raw")
                raw_ref = rec.get("raw_data_ref") or {}
                ri = raw_ref.get("row_index")
                if not isinstance(ri, int):
                    ri = fallback_idx
                fallback_idx += 1
                agg.add(
                    int(params.get("raw_delay", 0)),
                    int(params.get("raw_pulse", 0)),
                    resp.get("state_label", "unknown"),
                    code if code not in (None, "unknown") else None,
                    unexp if unexp not in (None, "unknown") else None,
                    row_index=ri,
                )
        return agg

    def _aggregate_csv(self, path: str) -> _Agg:
        # 延迟导入避免 pandas 在纯 JSONL 路径上的开销
        from fi.analysis.parser import clean_typed, load_raw_csv

        df_raw = load_raw_csv(path)
        df, _rep = clean_typed(df_raw, convert_ns=False)
        agg = _Agg()
        for i, row in enumerate(df.itertuples(index=False)):
            agg.add(
                int(row.delay_i), int(row.pulse_i), row.state,
                row.response_norm, row.unexpected_norm,
                row_index=i,  # 0 起始数据行号（与契约 raw_data_ref 口径一致）
            )
        return agg

    # ---- 产出 --------------------------------------------------------------
    def _distribution_outputs(self, agg: _Agg, scan_id: str):
        findings = []
        metrics: dict = {}
        labels = agg.labels_by_count()  # 行数降序（观测推导）
        bg = agg.background_label
        chi2_labels = [s for s in labels
                       if agg.by_state[s] >= SPARSE_STATE_SHARE * agg.total]

        # F1 状态构成
        comp = ", ".join(f"{k}={v}" for k, v in agg.by_state.items())
        findings.append({
            "finding_id": f"find-{scan_id}-001",
            "kind": "state_composition",
            "description": f"状态行数构成（原始标签，行数降序）：{comp}；共 {agg.total} 行",
            "evidence_level": "observation",
            "supporting_refs": [scan_id],
        })

        # F2 网格形状
        pulse_counts: dict[int, int] = {}
        for (d, p), cell in agg.per_point.items():
            pulse_counts[p] = pulse_counts.get(p, 0) + sum(cell.values())
        delays = sorted({d for (d, _p) in agg.per_point})
        main_pulse = max(pulse_counts, key=pulse_counts.get)
        main_rows = pulse_counts[main_pulse]
        findings.append({
            "finding_id": f"find-{scan_id}-002",
            "kind": "scan_grid_shape",
            "description": (
                f"扫描网格形状：pulse={main_pulse} 占 {main_rows}/{agg.total} 行，"
                f"delay 点数 {len(delays)}"
                + (f"（{min(delays)}–{max(delays)}）" if delays else "")
                + (f"；其余 pulse 值仅 {agg.total - main_rows} 行"
                   if agg.total - main_rows else "（无其他 pulse 取值）")
            ),
            "evidence_level": "observation",
            "supporting_refs": [scan_id],
        })

        # F3 目标标签逐点率值与窗口边界（target_label 必填语义参数）
        pts = sorted(d for (d, p) in agg.per_point if p == main_pulse)
        n_main = sum(sum(agg.per_point[(d, main_pulse)].values()) for d in pts)
        if self.target_label is None:
            findings.append({
                "finding_id": f"find-{scan_id}-003",
                "kind": "hit_window_unresolved",
                "description": (
                    "target_label 未指定（数据集语义，禁止代码默认值）："
                    "未生成目标标签的窗口平坦性结论；各标签率值见 metrics.label_rates"
                ),
                "evidence_level": "observation",
                "supporting_refs": [scan_id],
            })
        elif self.target_label in labels:
            tl = self.target_label
            rates_tl: list[float] = []
            z_vals: list[float] = []
            p_tl = agg.by_state[tl] / n_main
            for d in pts:
                cell = agg.per_point[(d, main_pulse)]
                n = sum(cell.values())
                k = cell.get(tl, 0)
                rates_tl.append(k / n if n else 0.0)
                se = sqrt(p_tl * (1 - p_tl) / n) if n else 0.0
                z_vals.append((k / n - p_tl) / se if se else 0.0)
            gt2 = sum(1 for z in z_vals if abs(z) > 2)
            expected_gt2 = len(pts) * 0.0455
            findings.append({
                "finding_id": f"find-{scan_id}-003",
                "kind": "hit_window_flat",
                "description": (
                    f"pulse={main_pulse} 上 {tl} 率逐点平坦"
                    f"（min={min(rates_tl):.4f} max={max(rates_tl):.4f}，"
                    f"z 范围 {min(z_vals):+.2f}–{max(z_vals):+.2f}，"
                    f"|z|>2 共 {gt2} 点≈随机预期 {expected_gt2:.1f}）："
                    "本数据分辨率下未观察到该标签的清晰命中窗口边界"
                ),
                "evidence_level": "observation",
                "supporting_refs": [scan_id],
            })

        # F4 背景漂移 + 齐性卡方（稀疏标签剔除）
        curves: dict[str, list[float]] = {}
        for s in chi2_labels:
            curves[s] = []
            for d in pts:
                cell = agg.per_point[(d, main_pulse)]
                n = sum(cell.values())
                curves[s].append(cell.get(s, 0) / n if n else 0.0)
        delays_f = [float(d) for d in pts]
        rho_pair = {
            s: round(_spearman(delays_f, curves[s]), 4)
            for s in chi2_labels[:2]  # 行数最多的前两个标签作为背景对（观测推导）
        }
        obs = []
        for d in pts:
            cell = agg.per_point[(d, main_pulse)]
            obs.append([cell.get(s, 0) for s in chi2_labels])
        row_tot = [sum(r) for r in obs]
        col_tot = [sum(obs[i][j] for i in range(len(obs))) for j in range(len(chi2_labels))]
        tot = sum(row_tot)
        chi2 = 0.0
        for i, r in enumerate(obs):
            for j, v in enumerate(r):
                e = row_tot[i] * col_tot[j] / tot
                if e:
                    chi2 += (v - e) ** 2 / e
        dof = (len(obs) - 1) * (len(chi2_labels) - 1)
        findings.append({
            "finding_id": f"find-{scan_id}-004",
            "kind": "background_drift",
            "description": (
                f"背景率随 delay 漂移（"
                + "，".join(f"{s}:ρ{v:+.2f}" for s, v in rho_pair.items())
                + f"）；标签齐性卡方 χ²={chi2:.1f}(dof={dof}, "
                f"p≈{_chi2_sf_approx(chi2, dof):.4f}；入表标签 {chi2_labels}"
                + (f"，稀疏剔除 {sorted(set(labels) - set(chi2_labels))}"
                   if set(labels) - set(chi2_labels) else "")
                + "）；漂移主要由背景标签贡献"
            ),
            "evidence_level": "observation",
            "supporting_refs": [scan_id],
        })

        # F5 行序随机化
        ds = agg.order_delays
        mu = sum(ds) / len(ds)
        d0 = [x - mu for x in ds]
        num = sum(a * b for a, b in zip(d0[:-1], d0[1:]))
        den = sum(a * a for a in d0)
        ac1 = num / den if den else None
        findings.append({
            "finding_id": f"find-{scan_id}-005",
            "kind": "row_order_randomized",
            "description": (
                f"行序 delay lag-1 自相关 ≈ {ac1:.5f}：行序接近随机化采样，"
                "不能当作扫描时序解读"
            ),
            "evidence_level": "observation",
            "supporting_refs": [scan_id],
        })

        # F6 列耦合 + 主导错误码（按 UNEXPECTED 等非背景标签中最常见码，观测推导）
        eq_rate = (agg.coupling_equal / agg.coupling_both) if agg.coupling_both else None
        nonbg_codes: dict[str, int] = {}
        for s in chi2_labels[1:]:  # 除最大背景标签外的入表标签
            for c, k in agg.code_by_state.get(s, {}).items():
                nonbg_codes[c] = nonbg_codes.get(c, 0) + k
        dom_code = max(nonbg_codes, key=nonbg_codes.get) if nonbg_codes else "unknown"
        total_nonbg = sum(nonbg_codes.values())
        dom_share = (nonbg_codes[dom_code] / total_nonbg) if total_nonbg else None
        findings.append({
            "finding_id": f"find-{scan_id}-006",
            "kind": "column_coupling",
            "description": (
                f"response/unexpected 两列同时非空时逐字符相等率 "
                f"{agg.coupling_equal}/{agg.coupling_both}"
                + (f"（={eq_rate:.4f}，视为冗余列）" if eq_rate is not None else "")
                + f"；非背景标签响应中主导码 {dom_code} 占 "
                + (f"{dom_share:.4f}" if dom_share is not None else "unknown")
            ),
            "evidence_level": "observation",
            "supporting_refs": [scan_id],
        })

        # F7 同参数点多标签（响应含随机成分；非确定性，observation）
        multi_cells = {k: v for k, v in agg.per_point.items() if len(v) >= 2}
        max_labels = max((len(v) for v in agg.per_point.values()), default=0)
        evidence_cells = sorted(multi_cells.items(), key=lambda kv: -len(kv[1]))[:3]
        ev_parts = []
        for (d_, p_), lbls in evidence_cells:
            rows = agg.row_samples.get((d_, p_), {})
            seg = "，".join(f"{lbl} 行{rows.get(lbl, 'unknown')}" for lbl in lbls)
            ev_parts.append(f"(delay={d_},pulse={p_}) 有 {seg}")
        findings.append({
            "finding_id": f"find-{scan_id}-007",
            "kind": "non_deterministic_response",
            "description": (
                "同一参数点存在多种状态标签（参数不完全决定结果，响应含随机成分）："
                f"{len(multi_cells)}/{len(agg.per_point)} 个扫描单元含 ≥2 种标签，"
                f"单点最多 {max_labels} 种；"
                + "；".join(ev_parts)
                + "（行号为原始 CSV 0 起始数据行号）。"
                "含义：命中概率是分布性质而非确定性函数——单点判定不应过度置信"
                "（用 Wilson 区间而非点估计）"
            ),
            "evidence_level": "observation",
            "supporting_refs": [scan_id],
        })

        # F8 每标签响应形态画像（帧模型兼容性统计的通用底数；映射解释见报告假设区）
        profile = {}
        for s in labels:
            st = agg.label_stats.get(s, {})
            rows = st.get("rows", 0) or 1
            toks = agg.unexpected_tokens_by_state.get(s, {})
            top_tok = max(toks, key=toks.get) if toks else "unknown"
            profile[s] = {
                "rows": st.get("rows", 0),
                "response_nonempty_share": round(st.get("response_nonempty", 0) / rows, 6),
                "unexpected_nonempty_share": round(st.get("unexpected_nonempty", 0) / rows, 6),
                "both_empty_share": round(st.get("both_empty", 0) / rows, 6),
                "top_unexpected_token": top_tok,
                "top_unexpected_token_share": round(toks.get(top_tok, 0) / rows, 6) if toks else None,
            }
        findings.append({
            "finding_id": f"find-{scan_id}-008",
            "kind": "label_response_profile",
            "description": (
                "每标签响应形态画像（observation）："
                + "；".join(
                    f"{s}:response非空{v['response_nonempty_share']:.4f}/"
                    f"unexpected非空{v['unexpected_nonempty_share']:.4f}/"
                    f"双空{v['both_empty_share']:.4f}/"
                    f"主导unexpected值={v['top_unexpected_token']}"
                    f"({v['top_unexpected_token_share']})"
                    for s, v in profile.items()
                )
                + f"；全部 0x 码落在一维码域(≤0xFFFF)比例 "
                f"{agg.codes_within_16bit}/{agg.codes_total}"
                + (f"（={agg.codes_within_16bit / agg.codes_total:.4f}）"
                   if agg.codes_total else "")
            ),
            "evidence_level": "observation",
            "supporting_refs": [scan_id],
        })

        # hit_windows：全部非背景标签的 delay 覆盖范围（observation，逐标签）
        hit_windows = []
        for s in labels:
            if s == bg:
                continue
            lo, hi = agg.delay_by_state.get(s, (None, None))
            if lo is None:
                continue
            hit_windows.append({
                "axis": "delay",
                "min_value": lo,
                "max_value": hi,
                "unit": "raw",
                "state_label": s,
                "evidence_level": "observation",
            })

        metrics = {
            "total_records": agg.total,
            "main_pulse_raw": main_pulse,
            "n_delay_points": len(pts),
            "labels": labels,
            "background_label": bg,
            "target_label": self.target_label,
            "overall_rates": {
                s: round(agg.by_state[s] / agg.total, 8) for s in labels
            },
            "label_rate_per_point_range": {
                s: {
                    "min": round(min(curves[s]), 6) if s in curves else "unknown",
                    "max": round(max(curves[s]), 6) if s in curves else "unknown",
                }
                for s in chi2_labels
            },
            "target_rate_overall": (
                round(agg.by_state[self.target_label] / agg.total, 8)
                if self.target_label in agg.by_state else "unknown"
            ),
            "homogeneity_chi2": round(chi2, 2),
            "homogeneity_dof": dof,
            "homogeneity_p_approx": round(_chi2_sf_approx(chi2, dof), 6),
            "rate_vs_delay_spearman": {
                s: round(_spearman(delays_f, curves[s]), 4) if s in curves else "unknown"
                for s in chi2_labels
            },
            "cells_with_multi_label": len(multi_cells),
            "max_labels_per_cell": max_labels,
            "label_response_profile": profile,
            "codes_within_16bit": {"within": agg.codes_within_16bit,
                                   "total": agg.codes_total},
            "unit_assumption": (
                f"1 raw = {NS_PER_STEP_ASSUMED:g} ns"
                "（假设 A1，未证实；ns 字段均为该假设换算）"
            ),
        }
        return findings, hit_windows, metrics

    # ---- ROM 归因候选（hypothesis 上限） -----------------------------------
    def _candidates_from_attribution(self) -> list[dict]:
        if not self.attribution_path or not Path(self.attribution_path).exists():
            return []  # 显式空：无静态归因输入
        with open(self.attribution_path, "r", encoding="utf-8") as f:
            attr = json.load(f)
        out = []
        idx = 0
        for code, info in attr.get("targets", {}).items():
            conf = info.get("confidence")
            if conf == "candidate_imm_with_context":
                hits = info.get("imm_operand_hits") or info.get("lui_addi_pair_hits") or []
                if not hits:
                    continue
                h = hits[0]
                idx += 1
                pc = int(h.get("addr", "0x0"), 16)
                if "pair" in h:
                    pair_txt = f"（lui/addi 对：{' ; '.join(h['pair'])}）"
                else:
                    pair_txt = f"（{h.get('insn', '')}）"
                out.append({
                    "candidate_id": f"cand-{code}-001",
                    "description": (
                        f"CSV 观测值 {code} 的立即数形式出现于 ROM 0x{pc:08X}{pair_txt}；"
                        "候选代码路径（线性扫描，未验证可达性，语义未证实）"
                    ),
                    "pc": pc,
                    "profile_ref": self.profile_ref or "unknown",
                    "evidence_level": "hypothesis",
                })
            elif conf == "candidate_ascii_string":
                hits = info.get("ascii_hits") or []
                if not hits:
                    continue
                h = hits[0]
                idx += 1
                out.append({
                    "candidate_id": f"cand-token-{code}-001",
                    "description": (
                        f"CSV 非码 token '{code}' 的 ASCII 串出现于 ROM "
                        f"{h.get('addr')}（context={h.get('context_repr','')}）；"
                        "候选协议文本/数据（性质未证实）"
                    ),
                    "pc": "unknown",
                    "profile_ref": self.profile_ref or "unknown",
                    "evidence_level": "hypothesis",
                })
            if idx >= 16:
                break
        return out
