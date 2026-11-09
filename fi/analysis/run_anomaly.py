# -*- coding: utf-8 -*-
"""统一异常分析一键重放：输入任意观测数据 → 综合报告（JSON + Markdown）。

用法（项目根目录）::

    python -m fi.analysis.run_anomaly ^
        --input data/derived/<DATASET>.typed.jsonl ^
        --config data/derived/anomaly-report.config.json ^
        --out-prefix data/derived/<DATASET>

产出：``<prefix>.anomaly-report.json`` + ``<prefix>.anomaly-report.md``

换数据集只需换 ``--input``/``--config``；列名、标签集、码域、码族划分、
阶段映射全部经 config 传入，通用代码零实例值。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fi.analysis.anomaly_report import (
    AnomalyReportConfig,
    build_anomaly_report,
    render_markdown,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="统一异常分析：任意观测数据 → 综合报告（JSON + Markdown）")
    ap.add_argument("--input", required=True, help="观测数据（CSV/JSONL/trace/bytes，自动识别）")
    ap.add_argument("--config", default=None,
                    help="分析配置 JSON（列映射/码规则/码族/阶段映射/目标标签等）")
    ap.add_argument("--out-prefix", default=None,
                    help="输出前缀（生成 <prefix>.anomaly-report.{json,md}）")
    ap.add_argument("--format", default=None,
                    help="显式指定输入格式（csv|typed_jsonl|trace_jsonl|bytes|text），"
                         "缺省自动识别")
    ap.add_argument("--n-time-segments", type=int, default=None,
                    help="时间漂移分段数（默认取 config 或 20）")
    ap.add_argument("--image", default=None,
                    help="固件镜像路径：提供则追加『指令级归因』section"
                         "（把观测到的码归因到 handler 内的装载指令）")
    ap.add_argument("--image-base", default=None,
                    help="固件镜像基址（十六进制/十进制），与 --image 配套使用")
    args = ap.parse_args(argv)

    src = Path(args.input)
    if not src.exists():
        print(f"错误: 输入不存在: {src}", file=sys.stderr)
        return 2

    cfg_dict: dict = {}
    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.exists():
            print(f"错误: config 不存在: {cfg_path}", file=sys.stderr)
            return 2
        cfg_dict = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg = AnomalyReportConfig.from_dict(cfg_dict)
    if args.format:
        cfg.format = args.format
    if args.n_time_segments is not None:
        cfg.n_time_segments = args.n_time_segments

    report = build_anomaly_report(src, cfg)
    # 内部临时字段不进入输出
    cmd = report["sections"]["command_surface"]
    for k in ("_sig_full", "_delays", "_by_point"):
        cmd.pop(k, None)

    # ---- 指令级归因（可选）：把"码的统计"升级为"码打中了哪条指令" ----
    if args.image or args.image_base:
        from fi.analysis.attribution_section import attach_to_report

        base_val = None
        if args.image_base:
            try:
                base_val = int(args.image_base, 0)
            except ValueError:
                print(f"错误: --image-base 无法解析: {args.image_base}", file=sys.stderr)
                return 2
        report = attach_to_report(report, image_path=args.image, base=base_val)

    report["inputs"]["config_file"] = args.config
    report["inputs"]["replay_command"] = (
        "python -m fi.analysis.run_anomaly "
        f"--input {args.input} "
        + (f"--config {args.config} " if args.config else "")
        + (f"--image {args.image} " if args.image else "")
        + (f"--image-base {args.image_base} " if args.image_base else "")
        + (f"--out-prefix {args.out_prefix}" if args.out_prefix else "")
    ).strip()

    md = render_markdown(report)

    prefix = Path(args.out_prefix) if args.out_prefix else src.with_suffix("")
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = prefix.with_suffix(prefix.suffix + ".anomaly-report.json") \
        if prefix.suffix else Path(f"{prefix}.anomaly-report.json")
    md_path = json_path.with_suffix(".md")

    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n",
                         encoding="utf-8")
    md_path.write_text(md, encoding="utf-8")

    # ---- 终端摘要 ----
    q = report["sections"]["quality_and_stationarity"]
    print(f"OK 报告 → {json_path}")
    print(f"         {md_path}")
    print(f"  输入: {report['inputs']['format']} / {report['inputs']['n_rows']} 行 / "
          f"标签 {q.get('n_labels')} 种 / 字节流={'有' if report['inputs']['has_byte_stream'] else '无'}")
    print(f"  平稳性: {'非平稳(' + str(len(q.get('nonstationary_labels') or [])) + ' 个标签过散超标)' if q.get('nonstationary_labels') else '未检出非平稳'}")
    print(f"  结论 {len(report.get('findings') or [])} 条；"
          f"未决项 {report['sections']['unknowns']['n_items']} 条")
    for f in (report.get("findings") or [])[:6]:
        desc = str(f.get("description", ""))[:100]
        print(f"    [{f.get('evidence_level')}] {f.get('finding_id')}: {desc}")

    # 归因摘要（若已启用）
    att = report["sections"].get("instruction_attribution")
    if att:
        if att.get("available"):
            s = att["summary"]
            print(f"  指令级归因: {s['codes_attributed']}/{s['codes_requested']} 个码"
                  f" → {s['total_sites']} 个站点"
                  f"（命令表 {att['command_table']['entry_count']} 项）")
            for a in att["attributions"]:
                if a["status"] == "attributed_to_handler" and a["sites"]:
                    site0 = a["sites"][0]
                    print(f"    {a['code']} → cmd {site0['command']} @ {site0['insn_addr']}"
                          f" {site0['insn'][:48]}")
        else:
            print(f"  指令级归因: 不可用（{att.get('reason')}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
