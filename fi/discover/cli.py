# -*- coding: utf-8 -*-
"""fi.discover CLI：`fi discover regions|traps|targets|draft|chain|dispatch|attribute`。

两种调用方式等价：
    fi discover targets --bin rom.bin --base 0x<BASE>
    python -m fi.discover targets --bin rom.bin --base 0x<BASE>

注册机制（core-contract 维护的钩子）：本模块被 `fi.cli_plugins` 在
`fi.cli.build_parser()` 中 import，import 期通过 `@command("discover", ...)`
把子命令注册进 `fi.cli.COMMANDS`。**因此本模块顶层不得有重依赖之外的副作用**
（capstone 缺失时只让 discover 组消失，不影响 `fi schema list`）。

输出约定（AI 编程环境调度友好）：
- 默认把报告 JSON 打到 stdout（--out 时写文件并在 stdout 报路径）；
- --summary 只打印人类可读摘要（不输出大 JSON）；
- 退出码：0=成功，2=数据/输入错误，1=参数错误（argparse 自带）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fi.cli import command

DISCOVER_GROUP = "discover"


def _parse_int(text: str) -> int:
    """接受 "0x<BASE>" / "<BASE_DEC>" 两种写法。"""
    return int(text, 0)


def _write_or_print(report: dict, out: str | None, *, summary_only: bool = False) -> int:
    """统一输出：--out 写文件；否则打 stdout。返回退出码。"""
    if out:
        dst = Path(out)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(report, ensure_ascii=False, indent=1, default=str),
                       encoding="utf-8")
        print(f"OK 报告已写出: {dst}")
        if summary_only:
            _print_summary(report)
        return 0
    if summary_only:
        _print_summary(report)
        return 0
    print(json.dumps(report, ensure_ascii=False, indent=1, default=str))
    return 0


def _print_summary(report: dict) -> None:
    """通用人类可读摘要（各子命令共享外壳，字段按存在与否打印）。"""
    img = report.get("image", {})
    print(f"image   : {img.get('path')}  base={img.get('base_address_hex')}  "
          f"size={img.get('size_bytes')} B  sha256={(img.get('sha256') or '')[:16]}…")
    if "method" in report and isinstance(report["method"], dict):
        m = report["method"]
        for key in ("target_value_mode", "min_shared_callers", "call_window"):
            if key in m:
                print(f"method  : {key}={m[key]}")
    summary = report.get("summary") or {}
    print("summary :")
    for k, v in summary.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            print(f"  {k} = {v}")
        elif isinstance(v, list):
            print(f"  {k} = [{len(v)} 项]")
        elif isinstance(v, dict):
            print(f"  {k} = {{{', '.join(f'{kk}:{vv}' for kk, vv in v.items())}}}")
    print(f"confidence = {report.get('confidence', 'hypothesis')}  "
          f"evidence_kind = {report.get('evidence_kind', 'artifact_derived')}")


# ---------------------------------------------------------------- regions
@command(DISCOVER_GROUP, "regions",
         "地址常量扫描 → RAM/MMIO 区域候选（供 fi.sim iterate 消费）")
def discover_regions_cmd(args: argparse.Namespace) -> int:
    from fi.discover.regions import discover_regions

    try:
        report = discover_regions(
            args.bin, _parse_int(args.base),
            xlen=args.xlen, compressed=not args.no_compressed,
            page=_parse_int(args.page), min_addr=_parse_int(args.min_addr),
            min_hits=args.min_hits, top_n=args.top,
        )
    except FileNotFoundError:
        print(f"错误: 镜像不存在: {args.bin}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 —— CLI 层统一转成可读错误
        print(f"错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return _write_or_print(report, args.out, summary_only=args.summary)


def _cfg_regions(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址（十六进制或十进制，未知时可给 0）")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 压缩指令解码")
    p.add_argument("--page", default="0x1000", help="页大小（聚类粒度）")
    p.add_argument("--min-addr", default="0x20000000", help="地址常量最小保留值")
    p.add_argument("--min-hits", type=int, default=2, help="页候选最小命中数")
    p.add_argument("--top", type=int, default=40, help="输出候选上限")
    p.add_argument("--out", default=None, help="报告输出路径（默认打 stdout）")
    p.add_argument("--summary", action="store_true", help="只打印摘要（不输出大 JSON）")


discover_regions_cmd.configure_args = _cfg_regions  # type: ignore[attr-defined]


# ---------------------------------------------------------------- traps
@command(DISCOVER_GROUP, "traps", "trap 机制识别（mtvec 安装点 / mcause / mret / handler 形态）")
def discover_traps_cmd(args: argparse.Namespace) -> int:
    from fi.discover.traps import discover_traps

    try:
        report = discover_traps(
            args.bin, _parse_int(args.base),
            xlen=args.xlen, compressed=not args.no_compressed,
            max_findings_per_kind=args.max_findings,
        )
    except FileNotFoundError:
        print(f"错误: 镜像不存在: {args.bin}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return _write_or_print(report, args.out, summary_only=args.summary)


def _cfg_traps(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 解码")
    p.add_argument("--max-findings", type=int, default=40, help="每类发现上限")
    p.add_argument("--out", default=None, help="报告输出路径")
    p.add_argument("--summary", action="store_true", help="只打印摘要")


discover_traps_cmd.configure_args = _cfg_traps  # type: ignore[attr-defined]


# ---------------------------------------------------------------- targets
@command(DISCOVER_GROUP, "targets",
         "注入靶点枚举（常量装载点/共享函数调用点/比较分支），立即数由参数化输入")
def discover_targets_cmd(args: argparse.Namespace) -> int:
    from fi.discover.targets import discover_targets

    target_values = None
    if args.values:
        target_values = [_parse_int(v) for v in args.values]
    value_range = None
    if args.value_range:
        lo, _, hi = args.value_range.partition("-")
        value_range = (_parse_int(lo), _parse_int(hi))

    try:
        report = discover_targets(
            args.bin, _parse_int(args.base),
            xlen=args.xlen, compressed=not args.no_compressed,
            target_values=target_values, target_value_range=value_range,
            min_shared_callers=args.min_shared_callers,
            call_window=args.call_window,
            max_targets_per_kind=args.max_targets,
            max_shared_functions=args.max_shared,
        )
    except FileNotFoundError:
        print(f"错误: 镜像不存在: {args.bin}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.kind:
        wanted = set(args.kind)
        report = {
            **report,
            "targets": [t for t in report["targets"] if t["kind"] in wanted],
            "summary": {**report["summary"], "filtered_by_kind": sorted(wanted),
                        "target_count_after_filter": len(
                            [t for t in report["targets"] if t["kind"] in wanted])},
        }
    return _write_or_print(report, args.out, summary_only=args.summary)


def _cfg_targets(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 解码")
    p.add_argument("--values", nargs="*", default=None,
                   help="显式关心的常量（错误码/命令号等；不写死芯片值，由调用方给）")
    p.add_argument("--value-range", default=None,
                   help="值域过滤，形如 0x100-0xfff（与 --values 互斥）")
    p.add_argument("--min-shared-callers", type=int, default=3,
                   help="≥该调用点数判定为高频共享函数候选")
    p.add_argument("--call-window", type=int, default=8,
                   help="常量装载后多少条指令内出现调用算'被消费'")
    p.add_argument("--max-targets", type=int, default=400, help="每类靶点上限")
    p.add_argument("--max-shared", type=int, default=60, help="共享函数条目上限")
    p.add_argument("--kind", nargs="*", default=None,
                   choices=("const_load", "compare_branch", "shared_function", "call_site"),
                   help="只保留指定 kind 的靶点")
    p.add_argument("--out", default=None, help="报告输出路径")
    p.add_argument("--summary", action="store_true", help="只打印摘要")


discover_targets_cmd.configure_args = _cfg_targets  # type: ignore[attr-defined]


# ---------------------------------------------------------------- chain
@command(DISCOVER_GROUP, "chain",
         "功能级调用链重建（递归下降 + 函数指针表解析 + gp 相对寻址抬升）")
def discover_chain_cmd(args: argparse.Namespace) -> int:
    from fi.discover.chain import discover_chain

    extra = [_parse_int(a) for a in (args.extra_entries or [])]
    target_const = _parse_int(args.target_const) if args.target_const else None
    try:
        report = discover_chain(
            args.bin, _parse_int(args.base),
            xlen=args.xlen, compressed=not args.no_compressed,
            entry_offset=_parse_int(args.entry_offset),
            extra_entries=extra,
            target_addr=_parse_int(args.target_addr) if args.target_addr else None,
            target_string=args.target_string,
            target_const=target_const,
            max_paths=args.max_paths,
            max_functions=args.max_functions,
            include_function_details=not args.no_details,
        )
    except FileNotFoundError:
        print(f"错误: 镜像不存在: {args.bin}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.paths_only:
        report = {k: report[k] for k in
                  ("schema", "tool", "image", "target", "paths", "summary",
                   "confidence", "evidence_kind")}
    return _write_or_print(report, args.out, summary_only=args.summary)


def _cfg_chain(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 解码")
    p.add_argument("--entry-offset", default="0", help="根入口在镜像内的偏移（复位向量）")
    p.add_argument("--extra-entries", nargs="*", default=None,
                   help="额外根入口地址（如 mtvec 候选、已知 handler 入口）")
    p.add_argument("--target-addr", default=None, help="目标函数地址（或函数体内任一地址）")
    p.add_argument("--target-string", default=None, help="目标行为特征字符串（如 write）")
    p.add_argument("--target-const", default=None, help="目标关键常量（如错误码）")
    p.add_argument("--max-paths", type=int, default=8, help="路径枚举上限")
    p.add_argument("--max-functions", type=int, default=600, help="递归下降函数数上限")
    p.add_argument("--no-details", action="store_true", help="不输出逐函数详情")
    p.add_argument("--paths-only", action="store_true", help="只输出目标与路径（精简）")
    p.add_argument("--out", default=None, help="报告输出路径")
    p.add_argument("--summary", action="store_true", help="只打印摘要")


discover_chain_cmd.configure_args = _cfg_chain  # type: ignore[attr-defined]


# ---------------------------------------------------------------- draft
@command(DISCOVER_GROUP, "draft",
         "合成 regions+traps+targets → profiles/<chip>.draft.yaml（全 hypothesis 草稿）")
def discover_draft_cmd(args: argparse.Namespace) -> int:
    from fi.discover.draft import build_draft

    target_values = None
    if args.values:
        target_values = [_parse_int(v) for v in args.values]
    try:
        result = build_draft(
            args.bin, _parse_int(args.base), args.chip_id,
            xlen=args.xlen, compressed=not args.no_compressed,
            profile_path=args.profile,
            output_dir=args.output_dir,
            target_values=target_values,
            entry_offset=_parse_int(args.entry_offset),
            status_note=args.status_note,
        )
    except FileNotFoundError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"OK 草稿已写出: {result['path']}")
    print(f"   草稿说明: {result['notice']}")
    stats = result["stats"]
    print(f"   claims: fact={stats['fact']} hypothesis={stats['hypothesis']} "
          f"unknown={stats['unknown']} total={stats['total']}")
    if result.get("validation_errors"):
        print(f"   校验: FAIL ({len(result['validation_errors'])} 项)")
        for e in result["validation_errors"][:20]:
            print(f"     - {e}")
        return 1
    print("   校验: PASS")
    if args.summary:
        return 0
    print(json.dumps(result["report_meta"], ensure_ascii=False, indent=1))
    return 0


def _cfg_draft(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址")
    p.add_argument("--chip-id", required=True,
                   help="芯片标识（小写，用作 profile_id 与文件名 <chip_id>.draft.yaml）")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 解码")
    p.add_argument("--values", nargs="*", default=None,
                   help="显式关心的常量（错误码候选）；不给则自动推断")
    p.add_argument("--entry-offset", default="0", help="复位入口偏移")
    p.add_argument("--profile", default=None,
                   help="已有 Profile 路径（只读参考：把草稿与它对照，绝不改写）")
    p.add_argument("--output-dir", default="profiles", help="输出目录（默认 profiles/）")
    p.add_argument("--status-note", default=None, help="附加到草稿 notes 的说明")
    p.add_argument("--summary", action="store_true", help="只打印摘要")


discover_draft_cmd.configure_args = _cfg_draft  # type: ignore[attr-defined]



# ---------------------------------------------------------------- dispatch
@command(DISCOVER_GROUP, "dispatch", "运行期分派表恢复（命令表 → handler 映射）")
def discover_dispatch_cmd(args: argparse.Namespace) -> int:
    from fi.discover.dispatch import discover_dispatch

    try:
        report = discover_dispatch(
            args.bin, _parse_int(args.base),
            xlen=args.xlen, compressed=not args.no_compressed,
            max_entries=args.max_entries,
        )
    except FileNotFoundError:
        print(f"ERROR 镜像不存在: {args.bin}", file=sys.stderr)
        return 2
    return _write_or_print(report, args.out, summary_only=args.summary)


def _cfg_dispatch(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址（十六进制或十进制）")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 压缩指令解码")
    p.add_argument("--max-entries", type=int, default=64, help="单张表最大条目数")
    p.add_argument("--out", default=None, help="报告输出路径（默认打 stdout）")
    p.add_argument("--summary", action="store_true", help="只打印摘要")


discover_dispatch_cmd.configure_args = _cfg_dispatch  # type: ignore[attr-defined]


# ---------------------------------------------------------------- attribute
@command(DISCOVER_GROUP, "attribute", "异常码 → 命令 → handler → 装载指令（归因链路）")
def discover_attribute_cmd(args: argparse.Namespace) -> int:
    from fi.discover.attribution import attribute_codes

    codes = [c.strip() for c in (args.codes or "").split(",") if c.strip()]
    if not codes:
        print("ERROR 需要 --codes（逗号分隔的码值，如 0x<CODE_A>,0x<CODE_B>）", file=sys.stderr)
        return 2
    try:
        report = attribute_codes(
            args.bin, _parse_int(args.base), codes,
            xlen=args.xlen, compressed=not args.no_compressed,
        )
    except FileNotFoundError:
        print(f"ERROR 镜像不存在: {args.bin}", file=sys.stderr)
        return 2
    return _write_or_print(report, args.out, summary_only=args.summary)


def _cfg_attribute(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址（十六进制或十进制）")
    p.add_argument("--codes", required=True,
                   help="要归因的码值，逗号分隔（如 0x<CODE_A>,0x<CODE_B>,0x<CODE_D>）")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 压缩指令解码")
    p.add_argument("--out", default=None, help="报告输出路径（默认打 stdout）")
    p.add_argument("--summary", action="store_true", help="只打印摘要")


discover_attribute_cmd.configure_args = _cfg_attribute  # type: ignore[attr-defined]


# ------------------------------------------- injection-targets / key-evidence
@command(DISCOVER_GROUP, "injection-targets",
         "可注入靶点清单（码装载指令 + 位翻转变体 + 建议动作 + 预期观测）")
def discover_injection_targets_cmd(args: argparse.Namespace) -> int:
    from fi.discover.injection_targets import build_injection_targets, write_injection_targets

    codes = [c.strip() for c in (args.codes or "").split(",") if c.strip()]
    if not codes:
        print("ERROR 需要 --codes（逗号分隔的码值，如 0x<CODE_A>,0x<CODE_B>）", file=sys.stderr)
        return 2
    observed = None
    if args.observed_codes:
        observed = [c.strip() for c in args.observed_codes.split(",") if c.strip()]
        if args.observed_from:
            print("WARN 同时给了 --observed-codes 与 --observed-from，忽略后者",
                  file=sys.stderr)
    elif args.observed_from:
        # 从实验观测统计数据里取码集合（如 isp-command-surface.json 的 taxonomy.codes）
        try:
            data = json.loads(Path(args.observed_from).read_text(encoding="utf-8"))
            keys = ((data.get("taxonomy") or {}).get("codes") or {}).keys()
            observed = [k for k in keys if str(k).lower().startswith("0x")]
            print(f"INFO 从 {args.observed_from} 读到 {len(observed)} 个观测码",
                  file=sys.stderr)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR 读取 --observed-from 失败: {exc}", file=sys.stderr)
            return 1

    try:
        report = build_injection_targets(
            args.bin, _parse_int(args.base), codes,
            xlen=args.xlen, compressed=not args.no_compressed,
            observed_codes=observed, max_flips=args.max_flips,
            include_branch_targets=not args.no_branch_targets,
        )
    except FileNotFoundError:
        print(f"ERROR 镜像不存在: {args.bin}", file=sys.stderr)
        return 2
    return _write_or_print(report, args.out, summary_only=args.summary)


def _cfg_injection_targets(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址（十六进制或十进制）")
    p.add_argument("--codes", required=True,
                   help="要产出靶点的码，逗号分隔（如 0x<CODE_A>,0x<CODE_B>,0x<CODE_D>）")
    p.add_argument("--observed-codes", default=None,
                   help="实验中实际观测到的码（逗号分隔），用于标注'迁移到已观测码'")
    p.add_argument("--observed-from", default=None,
                   help="从实验观测统计 JSON 读取观测码（取 taxonomy.codes 的键）")
    p.add_argument("--max-flips", type=int, default=3, choices=(1, 2, 3, 4),
                   help="位翻转枚举上限（默认 3）")
    p.add_argument("--no-branch-targets", action="store_true",
                   help="不产出 gating_branch 靶点")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 解码")
    p.add_argument("--out", default=None, help="报告输出路径（默认打 stdout）")
    p.add_argument("--summary", action="store_true", help="只打印摘要")


discover_injection_targets_cmd.configure_args = _cfg_injection_targets  # type: ignore[attr-defined]


@command(DISCOVER_GROUP, "key-evidence",
         "核心证据浓缩（1-bit 翻转 ⇒ 实验观测码 A 变实验观测码 B，含可证伪预测）")
def discover_key_evidence_cmd(args: argparse.Namespace) -> int:
    from fi.discover.injection_targets import build_injection_targets, write_injection_targets
    from fi.discover.key_evidence import build_key_evidence

    codes = [c.strip() for c in (args.codes or "").split(",") if c.strip()]
    if not codes:
        print("ERROR 需要 --codes", file=sys.stderr)
        return 2

    counts = None
    observed = None
    if args.observations:
        try:
            data = json.loads(Path(args.observations).read_text(encoding="utf-8"))
            counts = (data.get("taxonomy") or {}).get("codes") or {}
            observed = [k for k in counts if str(k).lower().startswith("0x")]
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR 读取 --observations 失败: {exc}", file=sys.stderr)
            return 1

    try:
        injection = build_injection_targets(
            args.bin, _parse_int(args.base), codes,
            xlen=args.xlen, compressed=not args.no_compressed,
            observed_codes=observed, max_flips=1,
            include_branch_targets=False,
        )
    except FileNotFoundError:
        print(f"ERROR 镜像不存在: {args.bin}", file=sys.stderr)
        return 2

    report = build_key_evidence(injection, observation_counts=counts,
                                max_entries=args.max_entries)
    return _write_or_print(report, args.out, summary_only=args.summary)


def _cfg_key_evidence(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bin", "--image", dest="bin", required=True, help="固件镜像路径（只读）")
    p.add_argument("--base", default="0", help="镜像基址")
    p.add_argument("--codes", required=True, help="码集合，逗号分隔")
    p.add_argument("--observations", default=None,
                   help="实验观测统计 JSON（取 taxonomy.codes 作为观测码集合与计数）")
    p.add_argument("--max-entries", type=int, default=12, help="核心证据条目上限")
    p.add_argument("--xlen", type=int, default=32, choices=(32, 64))
    p.add_argument("--no-compressed", action="store_true", help="禁用 RVC 解码")
    p.add_argument("--out", default=None, help="报告输出路径")
    p.add_argument("--summary", action="store_true", help="只打印摘要")


discover_key_evidence_cmd.configure_args = _cfg_key_evidence  # type: ignore[attr-defined]


# ---------------------------------------------------------------- __main__ 支持
def main(argv: list[str] | None = None) -> int:
    """独立入口：`python -m fi.discover ...`（与 `fi discover ...` 等价）。"""
    from fi.cli import main as fi_main

    argv = list(sys.argv[1:] if argv is None else argv)
    return fi_main([DISCOVER_GROUP, *argv])


if __name__ == "__main__":
    raise SystemExit(main())