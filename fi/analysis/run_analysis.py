# -*- coding: utf-8 -*-
"""一键重放：CSV → 规范 JSONL + 全部派生 JSON（分布事实/聚类/归因/候选示例）。

重放命令（项目根目录）::

    python -m fi.analysis.run_analysis ^
        --csv <DATASET>.csv ^
        --rom "<ROM_IMAGE>" ^
        --derived data/derived

输出（data/derived/，文件名以 CSV stem 为前缀）：
- ``<stem>.typed.jsonl``                 规范 JSONL（一行一实验）
- ``<stem>.meta.json``                   来源/哈希/假设/版本/重放命令
- ``<stem>.state-counts.json``           状态计数与占比
- ``<stem>.error-codes.json``            错误码频次/耦合/状态交叉
- ``<stem>.delay-pulse-histograms.json`` 边际直方（raw+ns 轴）
- ``<stem>.grid-occupancy.json``         (delay,pulse) 单元占用
- ``<stem>.pointwise-rates.json``        逐点率值+CI+z+齐性检验（核心表）
- ``<stem>.segments.json``               2640–3129 vs 3130–3190 分段对比
- ``<stem>.run-order.json``              行序诊断（随机化证据）
- ``<stem>.clusters.json``               连通域聚类+相对位置+显著点
- ``<stem>.candidates-sample.json``      评分接口默认窗口示例输出
- ``<stem>.error-code-attribution.json`` 错误码 ↔ ROM 搜索结果（与 chip-profile 侧核对）
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fi.analysis import __version__
from fi.analysis.schema import ASSUMPTIONS, COL_STATE, UNIT_ASSUMPTION_TAG
from fi.analysis.parser import clean_typed, load_raw_csv, to_jsonl
from fi.analysis.distributions import (
    delay_pulse_histograms,
    error_code_tables,
    grid_occupancy,
    pointwise_rates,
    run_order_diagnostics,
    segment_compare,
    state_counts,
)
from fi.analysis.clusters import cluster_summary
from fi.analysis.contract_io import build_experiment_scan, write_campaign_jsonl
from fi.analysis.analyzer import CsvScanAnalyzer
from fi.analysis.rom_search import build_attribution
from fi.analysis.scoring import sample_top_candidates


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _dump(obj, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")


def _default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, pd.Timestamp):
        return o.isoformat()
    raise TypeError(f"not serializable: {type(o)}")


def _dump_np(obj, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, default=_default)
        f.write("\n")


def csv_code_side_stats(df) -> dict:
    """CSV 端各码/token 的统计（用于 attribution 表左列）。"""
    out: dict[str, dict] = {}

    def add(key: str, sub) -> None:
        vc = sub["state"].value_counts().to_dict()
        out[key] = {
            "total": int(len(sub)),
            "states": {str(k): int(v) for k, v in vc.items() if v > 0},
            "delay_raw_min": int(sub["delay_i"].min()),
            "delay_raw_max": int(sub["delay_i"].max()),
        }

    # response 列的错误码
    resp = df[df["response_norm"].notna() & df["response_norm"].str.startswith(("0x", "0X"))]
    for code in resp["response_norm"].unique():
        sub = resp[resp["response_norm"] == code]
        add(str(code), sub)
    # 哨兵 token（unexpected 列）：全部非 0x 前缀的非空值按观测推导（审计：无硬编码集合）
    token_mask = (
        df["unexpected_norm"].notna()
        & ~df["unexpected_norm"].astype("string").str.startswith(("0x", "0X"))
    )
    for tok in df.loc[token_mask, "unexpected_norm"].unique():
        sub = df[df["unexpected_norm"] == tok]
        add(str(tok), sub)
    # 无响应
    sub = df[df["code_class"] == "no_response"]
    if len(sub):
        add("no_response", sub)
    return out


def derive_segment_split(df) -> int | None:
    """数据驱动的分段点：取 delay 唯一值序列的最大间隙左侧值。

    观测推导（无样例值）；相邻 delay 无 >1 间隙时返回 None（不分段）。
    """
    ud = sorted(int(v) for v in df["delay_i"].dropna().unique())
    if len(ud) < 2:
        return None
    gaps = [(ud[i + 1] - ud[i], ud[i]) for i in range(len(ud) - 1)]
    max_gap, left = max(gaps)
    return int(left) if max_gap > 1 else None


def load_run_config(path: str | None, args) -> dict:
    """运行配置合并：CLI 显式参数 > --config 样例配置文件（审计：代码零样例默认值）。"""
    cfg: dict = {}
    if path:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    rom_base = args.rom_base if args.rom_base is not None else cfg.get("rom_base")
    if isinstance(rom_base, str):
        rom_base = int(rom_base, 0)
    target_label = (args.target_label if args.target_label is not None
                    else cfg.get("target_label"))
    states_arg = args.states
    if states_arg is None:
        states_arg = cfg.get("states")
    known_labels = None
    if states_arg:
        known_labels = (json.loads(states_arg)
                        if isinstance(states_arg, str) else list(states_arg))
    return {
        "rom_base": rom_base,
        "profile_ref": args.profile_ref if args.profile_ref is not None else cfg.get("profile_ref"),
        "target_label": target_label,
        "known_labels": known_labels,
        "config_file": path,
        "config_keys": sorted(k for k in cfg if k != "comment"),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="FI CSV 全量分布事实与归因重放")
    ap.add_argument("--csv", required=True, help="历史实验 CSV（原始，只读）")
    ap.add_argument("--rom", help="BootROM 二进制（原始，只读）")
    ap.add_argument("--derived", default="data/derived")
    ap.add_argument("--main-pulse", type=int, default=None,
                    help="主扫描 pulse 原始值；缺省=从数据行数最多的 pulse 推导")
    ap.add_argument("--background-code", default=None,
                    help="背景响应码；缺省=主扫描中占比最高的 0x 码（推导并标注）")
    ap.add_argument("--rom-base", default=None,
                    help="ROM 映射基址（用户给定值；缺省=跳过 ROM 归因，无样例默认）")
    ap.add_argument("--profile-ref", default=None,
                    help="ChipProfile id（归因候选引用；缺省=契约 unknown）")
    ap.add_argument("--codes-file", default=None,
                    help="目标码/token JSON（{codes:[],tokens:[]}，如来自 Profile）；"
                         "缺省=从 CSV 观测推导")
    ap.add_argument("--target-label", default=None,
                    help="评分/窗口结论的目标状态标签（数据集语义，必由配置传入；"
                         "缺省=分析结论不含目标标签字段）")
    ap.add_argument("--states", default=None,
                    help="状态标签枚举 JSON 数组字符串（如来自 Profile；"
                         "缺省=跳过枚举校验）")
    ap.add_argument("--config", default=None,
                    help="样例运行配置 JSON（rom_base/profile_ref/target_label 等；"
                         "值随调用显式传入）")
    ap.add_argument("--skip-jsonl", action="store_true", help="跳过 JSONL（调试用）")
    ap.add_argument("--skip-rom", action="store_true", help="跳过 ROM 归因搜索")
    args = ap.parse_args(argv)
    cfg = load_run_config(args.config, args)

    csv_path = Path(args.csv)
    rom_path = Path(args.rom) if args.rom else None
    derived = Path(args.derived)
    derived.mkdir(parents=True, exist_ok=True)
    stem = csv_path.stem
    t0 = datetime.now(timezone.utc)

    print(f"[1/6] 解析 {csv_path}")
    df_raw = load_raw_csv(str(csv_path))
    df, rep = clean_typed(df_raw, convert_ns=True, known_labels=cfg["known_labels"])
    print(f"      rows={rep.rows} parse_errors={rep.parse_errors} "
          f"unknown_labels={rep.unknown_state_labels}")

    if not args.skip_jsonl:
        jsonl_path = derived / f"{stem}.typed.jsonl"
        print(f"[2/6] 写规范 JSONL → {jsonl_path}")
        n = to_jsonl(df, str(jsonl_path))
        print(f"      {n} 行")

    print("[3/6] 分布事实 JSON")
    sc = state_counts(df)
    ec = error_code_tables(df)
    hp = delay_pulse_histograms(df)
    go = grid_occupancy(df)
    pw = pointwise_rates(df, main_pulse=args.main_pulse,
                         background_code=args.background_code,
                         target_label=cfg["target_label"])
    split = derive_segment_split(df)
    if split is not None:
        seg = segment_compare(df, split_low_max=split)
    else:
        seg = {"split_rule": "unknown", "note": "delay 唯一值无 >1 间隙，未分段"}
    ro = run_order_diagnostics(df, main_pulse=args.main_pulse)
    print(f"      main_pulse={'推导' if pw['main_pulse_derived'] else '指定'}={pw['main_pulse']} "
          f"background_code={'推导' if pw['background_code_derived'] else '指定'}"
          f"={pw['background_code']} segment_split={split}")

    print("[4/6] 聚类与相对位置")
    cl = cluster_summary(df, pw)

    print("[5/6] 候选评分示例")
    pw_path = derived / f"{stem}.pointwise-rates.json"
    _dump_np(pw, pw_path)
    cand = sample_top_candidates(str(pw_path), k=20,
                                 target_label=cfg["target_label"])

    rom_base = cfg["rom_base"]
    rom_attr = None
    attribution_path = derived / f"{stem}.error-code-attribution.json"
    if not args.skip_rom and rom_path is not None and rom_path.exists() and rom_base is not None:
        print(f"[5.5] ROM 归因搜索 → {rom_path} (base=0x{rom_base:x})")
        code_stats = csv_code_side_stats(df)
        if args.codes_file:
            with open(args.codes_file, "r", encoding="utf-8") as f:
                spec = json.load(f)
            target_codes = list(spec.get("codes", []))
            target_tokens = list(spec.get("tokens", []))
            codes_source = f"codes-file:{args.codes_file}"
        else:
            # 从 CSV 观测推导目标集（审计：无硬编码码表）
            target_codes = sorted(
                k for k in code_stats if k.lower().startswith("0x")
            )
            target_tokens = sorted(
                k for k in code_stats
                if not k.lower().startswith("0x") and k != "no_response"
            )
            codes_source = "derived-from-csv-observations"
        rom_attr = build_attribution(
            str(rom_path), code_stats,
            rom_base=rom_base,
            target_codes=target_codes,
            target_tokens=target_tokens,
        )
        rom_attr["target_codes_source"] = codes_source
        _dump_np(rom_attr, attribution_path)
    else:
        reason = ("--skip-rom" if args.skip_rom else
                  "rom_base 未提供（审计：无样例默认值）"
                  if rom_base is None else "ROM 文件缺失")
        print(f"[5.5] 跳过 ROM 归因（{reason}）")
        attribution_path.unlink(missing_ok=True)

    print("[5.8] 契约实例（CampaignRecord JSONL / ExperimentScan / AnalysisResult）")
    campaign_path = derived / f"{stem}.campaign-records.jsonl"
    n_rec = write_campaign_jsonl(str(csv_path), str(campaign_path))
    campaign_sha = _sha256(campaign_path)
    state_details = {
        str(label): {
            "count": int(sub.shape[0]),
            "delay_min": int(sub["delay_i"].min()),
            "delay_max": int(sub["delay_i"].max()),
        }
        for label, sub in df.groupby(COL_STATE, observed=True)
    }
    delay_min_all = int(df["delay_i"].min())
    delay_max_all = int(df["delay_i"].max())
    pulse_vals = sorted(int(v) for v in df["pulse_i"].dropna().unique())
    pulse_step_known = (
        len(pulse_vals) >= 2
        and all(b - a == 1 for a, b in zip(pulse_vals, pulse_vals[1:]))
    )
    scan_instance = build_experiment_scan(
        scan_id=f"scan-{stem}",
        records_path=str(campaign_path).replace("\\", "/"),
        records_count=n_rec,
        records_sha256=campaign_sha,
        state_details=state_details,
        delay_min=delay_min_all,
        delay_max=delay_max_all,
        pulse_min=pulse_vals[0] if pulse_vals else 0,
        pulse_max=pulse_vals[-1] if pulse_vals else 0,
        pulse_step_known=pulse_step_known,
        timestamp=t0.isoformat(),
    )
    analyzer = CsvScanAnalyzer(
        attribution_path=str(attribution_path) if attribution_path.exists() else None,
        profile_ref=cfg["profile_ref"],
        target_label=cfg["target_label"],
    )
    analysis_result = analyzer.analyze(scan_instance)
    _dump_np(scan_instance, derived / f"{stem}.experiment-scan.json")
    _dump_np(analysis_result, derived / f"{stem}.analysis-result.sample.json")

    meta = {
        "generated_utc": t0.isoformat(),
        "tool_version": f"fi.analysis {__version__}",
        "env": {"python": sys.version.split()[0], "pandas": pd.__version__,
                "numpy": np.__version__},
        "inputs": {
            "csv": {"path": str(csv_path), "sha256": _sha256(csv_path),
                    "rows": int(rep.rows)},
            "rom": {"path": str(rom_path) if rom_path else None,
                    "sha256": _sha256(rom_path) if rom_path and rom_path.exists() else None},
        },
        "run_config": {
            "rom_base": (f"0x{cfg['rom_base']:x}" if cfg["rom_base"] is not None else None),
            "rom_base_source": "caller/config (audit: no sample defaults)",
            "profile_ref": cfg["profile_ref"],
            "target_label": cfg["target_label"],
            "known_labels": cfg["known_labels"],
            "main_pulse": pw["main_pulse"],
            "main_pulse_derived": pw["main_pulse_derived"],
            "background_code": pw["background_code"],
            "background_code_derived": pw["background_code_derived"],
            "segment_split": split,
            "segment_split_source": "derived-from-data (max delay gap)",
            "config_file": cfg["config_file"],
            "config_keys": cfg["config_keys"],
        },
        "assumptions": ASSUMPTIONS,
        "unit_assumption": UNIT_ASSUMPTION_TAG,
        "parse_report": rep.to_dict(),
        "replay_command": (
            "python -m fi.analysis.run_analysis "
            f"--csv {csv_path} "
            + (f"--rom \"{rom_path}\" " if rom_path else "")
            + f"--derived {derived} "
            + (f"--config {cfg['config_file']} " if cfg["config_file"] else "")
            + (f"--rom-base 0x{cfg['rom_base']:x} " if cfg["rom_base"] is not None else "")
            + (f"--profile-ref {cfg['profile_ref']}" if cfg["profile_ref"] else "")
        ).strip(),
        "outputs": sorted(p.name for p in derived.glob(f"{stem}.*")),
        "discipline": "观测/假设/未知三级标注；原始 CSV/ROM 只读；ns 轴均为假设 A1 换算",
    }
    _dump_np(meta, derived / f"{stem}.meta.json")

    _dump_np(sc, derived / f"{stem}.state-counts.json")
    _dump_np(ec, derived / f"{stem}.error-codes.json")
    _dump_np(hp, derived / f"{stem}.delay-pulse-histograms.json")
    _dump_np(go, derived / f"{stem}.grid-occupancy.json")
    _dump_np(seg, derived / f"{stem}.segments.json")
    _dump_np(ro, derived / f"{stem}.run-order.json")
    _dump_np(cl, derived / f"{stem}.clusters.json")
    _dump_np(cand, derived / f"{stem}.candidates-sample.json")

    print("[6/6] 摘要")
    print(f"  state counts: { {k: v['count'] for k, v in sc['states'].items()} }")
    print(f"  overall rates(pulse={pw['main_pulse']}): {pw['overall_rates']}")
    print(f"  homogeneity chi2: {pw['homogeneity_chi2']}")
    tl = pw["target_label"]
    zkey = "z_extremes_per_label"
    if tl:
        print(f"  {tl} |z|>2: {pw[zkey][tl]['points_abs_z_gt2']} pts"
              f" (null 预期 {pw['expected_abs_z_gt2_under_null']})")
    print(f"  per-label |z|>2: "
          + ", ".join(f"{k}={v['points_abs_z_gt2']}" for k, v in pw[zkey].items()))
    print(f"  rate↔delay spearman: "
          + ", ".join(f"{k}={v:+.4f}" for k, v in pw["rate_vs_delay_spearman"].items()))
    if rom_attr:
        for code, info in rom_attr["targets"].items():
            hc = info["hit_counts"]
            key = next(iter(hc.values()))
            print(f"  ROM {code:>7}: conf={info['confidence']:<28} hits={hc}")
    print(f"  derived → {derived}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
