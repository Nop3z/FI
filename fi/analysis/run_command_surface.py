# -*- coding: utf-8 -*-
"""ISP 命令面分析一键重放（CSV 侧）。

用法（项目根目录）::

    python -m fi.analysis.run_command_surface ^
        --config data/derived/isp-command-surface.config.json ^
        --out data/derived/<DATASET>.isp-command-surface.json

``--config`` 提供全部数据集语义（码族划分/阶段归属/基线状态/主 pulse），
通用代码零样例值。不给 ``--config`` 时只做与数据集无关的纯统计
（码表/漂移/去趋势画像/条件构成），families 与 phase_constraints 输出 unknown。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fi.analysis.command_surface import run_command_surface


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ISP 命令面反推（CSV 侧）")
    ap.add_argument("--typed-jsonl", default=None, help="分析层规范 JSONL（parser.to_jsonl 产出）")
    ap.add_argument("--config", default=None,
                    help="分析入参 JSON（families/code_phase_map/baseline_states/main_pulse）")
    ap.add_argument("--out", default=None, help="输出 JSON 路径")
    ap.add_argument("--n-time-segments", type=int, default=20,
                    help="时间漂移分段数（默认 20）")
    args = ap.parse_args(argv)

    cfg: dict = {}
    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    typed = args.typed_jsonl or cfg.get("typed_jsonl")
    if not typed:
        print("错误: 需要 --typed-jsonl 或 config.typed_jsonl", file=sys.stderr)
        return 2
    if not Path(typed).is_file():
        print(f"错误: typed JSONL 不存在: {typed}", file=sys.stderr)
        return 2

    result = run_command_surface(
        typed,
        families=cfg.get("families"),
        code_phase_map=cfg.get("code_phase_map"),
        baseline_states=cfg.get("baseline_states"),
        n_time_segments=args.n_time_segments,
    )
    result["generated_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["config_file"] = args.config
    result["replay_command"] = (
        "python -m fi.analysis.run_command_surface "
        f"--typed-jsonl {typed} "
        + (f"--config {args.config} " if args.config else "")
        + (f"--out {args.out}" if args.out else "")
    ).strip()

    out_path = args.out or cfg.get("out")
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=1)
            f.write("\n")
        print(f"OK 输出 → {out_path}")

    # 摘要
    tax = result["taxonomy"]
    print(f"  rows={tax['n_rows']} main_pulse={result['inputs']['main_pulse']} "
          f"delay_points={result['inputs']['n_delay_points']} codes={tax['n_codes']}")
    print("  码表（按频次）：")
    for code, d in sorted(tax["codes"].items(), key=lambda kv: -kv[1]["count"])[:15]:
        print(f"    {code:>14} n={d['count']:>7} rate={d['rate']:.6f} states={d['states']}")
    print("  时间漂移（过散比 ≫1 = 非平稳）：")
    for lab, d in result["time_drift"]["per_label"].items():
        print(f"    {lab:>14} first={d['rate_first_segment']:.5f} last={d['rate_last_segment']:.5f} "
              f"Δ={d['segment_slope_total_change']:+.5f} overdisp={d['overdispersion_ratio']}")
    print("  delay 轴去趋势画像：")
    for lab, d in result["delay_axis_profiles"].items():
        print(f"    {lab:>14} raw_ρ={d['raw_spearman']:+.3f} det_ρ={d['detrended_spearman']:+.3f} "
              f"混杂={d['time_confounding']} true_SD={d['true_effect_std']*100:.3f}pp")
    print("  逐点 FDR 显著数：")
    for lab, d in result["pointwise_significance"].items():
        print(f"    {lab:>14} {d['fdr']['n_significant']}/{d['n_points']}")
    if result["families"] != "unknown":
        print("  码族：")
        for fam, d in result["families"]["families"].items():
            print(f"    {fam:>34} n={d['count']:>7} rate={d['rate']:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
