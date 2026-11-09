# -*- coding: utf-8 -*-
"""``fi analyze anomaly`` 子命令（import 期自动注册进 fi.cli.COMMANDS）。

两种用法等价::

    fi analyze anomaly --input <数据> --config <配置> --out-prefix <前缀>
    python -m fi.analysis.anomaly_cli --input <数据> --config <配置> --out-prefix <前缀>

**注册方式（需 core-contract 加一行）**：本模块靠 ``fi.cli_plugins`` 的
``OPTIONAL_COMMAND_MODULES`` 在 CLI 启动时被导入；当前该清单只含
``fi.discover.cli``。在清单中加入 ``"fi.analysis.anomaly_cli"`` 即可让
``fi analyze ...`` 可用。在此之前，``python -m fi.analysis.anomaly_cli``
已可独立工作（本模块不依赖注册即可运行主逻辑）。

设计说明：命令名取 ``anomaly`` 而非 ``run``，因为将来 ``fi analyze`` 组可能
容纳多个分析类型（如 ``fi analyze frame``），保持动词-宾语语义清晰。
"""

from __future__ import annotations

import argparse
import sys

_HANDLER_ATTRS = ("configure_args",)


def _run(args: argparse.Namespace) -> int:
    """延迟导入主逻辑（避免 CLI 启动时加载统计/反汇编依赖）。"""
    from fi.analysis.run_anomaly import main as run_main

    argv = ["--input", args.input]
    if args.config:
        argv += ["--config", args.config]
    if args.out_prefix:
        argv += ["--out-prefix", args.out_prefix]
    if args.format:
        argv += ["--format", args.format]
    if args.n_time_segments is not None:
        argv += ["--n-time-segments", str(args.n_time_segments)]
    if getattr(args, "image", None):
        argv += ["--image", args.image]
    if getattr(args, "image_base", None):
        argv += ["--image-base", args.image_base]
    return run_main(argv)


def _configure(p: argparse.ArgumentParser) -> None:
    p.add_argument("--input", required=True,
                   help="观测数据（CSV/JSONL/trace/bytes，格式自动识别）")
    p.add_argument("--config", default=None,
                   help="分析配置 JSON（列映射/码规则/码族/阶段映射/既有结论等）")
    p.add_argument("--out-prefix", default=None,
                   help="输出前缀（生成 <prefix>.anomaly-report.{json,md}）")
    p.add_argument("--format", default=None,
                   help="显式指定输入格式（csv|typed_jsonl|trace_jsonl|bytes|text）")
    p.add_argument("--n-time-segments", type=int, default=None,
                   help="时间漂移分段数（默认 20）")
    p.add_argument("--image", default=None,
                   help="固件镜像路径：提供则追加『指令级归因』section"
                        "（码 → 命令 → handler → 装载指令）")
    p.add_argument("--image-base", default=None,
                   help="固件镜像基址（十六进制/十进制），与 --image 配套")


_run.configure_args = _configure  # type: ignore[attr-defined]


def register() -> bool:
    """尝试注册进 fi.cli；返回是否成功（不抛异常，便于被 plugins 钩子调用）。"""
    try:
        from fi.cli import command
    except Exception:  # noqa: BLE001 —— 宿主不可用时静默降级
        return False
    command("analyze", "anomaly",
            "统一异常分析：任意观测数据 → 综合报告（JSON + Markdown）")(_run)
    return True


def main(argv=None) -> int:
    """独立入口（不依赖 fi.cli 注册）。"""
    ap = argparse.ArgumentParser(
        prog="python -m fi.analysis.anomaly_cli",
        description="统一异常分析：任意观测数据 → 综合报告（JSON + Markdown）")
    _configure(ap)
    return _run(ap.parse_args(argv))


# import 期尽力注册（在 fi.cli 已初始化时生效；否则用上面的独立入口）
_REGISTERED = register()

if __name__ == "__main__":
    raise SystemExit(main())
