# -*- coding: utf-8 -*-
"""位翻转假设审计一键重放。

用法::

    python -m fi.analysis.run_bitflip ^
        --config data/derived/bitflip.config.json ^
        --out data/derived/<DATASET>.bitflip-hypothesis.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fi.analysis.bitflip import FlipScanConfig, audit_bitflip_hypothesis


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="错误码位翻转假设审计")
    ap.add_argument("--config", required=True, help="配置 JSON（rom/已知码/未归因码/观测计数）")
    ap.add_argument("--out", default=None, help="输出 JSON 路径")
    args = ap.parse_args(argv)

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    rom_base = cfg["rom"]["base"]
    rom_base = int(rom_base, 0) if isinstance(rom_base, str) else rom_base
    scan_cfg = FlipScanConfig(
        rom_path=cfg["rom"]["path"],
        rom_base=rom_base,
        max_flips=int(cfg.get("max_flips", 6)),
        flip_mode=cfg.get("flip_mode", "one_to_zero"),
    )

    result = audit_bitflip_hypothesis(
        scan_cfg,
        known_codes=cfg["known_codes"],
        unattributed_codes=cfg["unattributed_codes"],
        csv_counts=cfg.get("csv_counts", {}),
        code_pairs=cfg.get("code_pairs"),
    )
    result["generated_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["config_file"] = args.config
    result["replay_command"] = (
        f"python -m fi.analysis.run_bitflip --config {args.config}"
        + (f" --out {args.out}" if args.out else "")
    )

    out = args.out or cfg.get("out")
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n",
                             encoding="utf-8")
        print(f"OK 输出 → {out}")

    d = result["distribution"]
    print(f"扫描：{d['n_load_instructions']} 条装载类指令，"
          f"{d['n_total_paths']:,} 条翻转路径，覆盖 {d['n_distinct_values']:,} 种值")
    print(f"  路径数分布：中位 {d['median_paths']}，p90 {d['p90_paths']}，"
          f"最大 {d['max_paths']}（{d['max_paths_value']}）")
    print()
    print(f"{'码':>8} {'CSV':>7} {'addi范围':>9} {'路径数':>9} {'判别力':>10}  裁定")
    for c in result["per_code"]:
        print(f"{c['code']:>8} {c['csv_count']:>7} "
              f"{'是' if c['encoding_boundary']['within_addi_range'] else '否':>9} "
              f"{c['flip_paths_total']:>9,} "
              f"{c['discriminating_power']['discriminating']:>10}  {c['verdict']}")
    if result["frequency_consistency"]:
        print()
        print("频率自洽性：")
        for f in result["frequency_consistency"]:
            print(f"  {f.get('source_code')}→{f.get('target_code')}: "
                  f"隐含翻转率 {f.get('implied_flip_rate')} → {f.get('verdict')}")
    print(f"整体证据级: {result['overall_evidence_level']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
