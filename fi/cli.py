"""fi 命令行入口（AI 编程环境调度友好：JSON/JSONL 输入输出、稳定退出码）。

子命令注册机制：其他成员往 COMMANDS 注册表注册即可扩展 CLI
（from fi.cli import command；@command("组名", "命令名", "帮助文本")，
专属参数用 handler.configure_args(parser) 钩子），不需要改 main()。

退出码约定：0=成功；1=数据/校验错误；2=用法错误。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from fi import __version__
from fi.cli_registry import COMMANDS, CommandSpec, Handler, command
from fi.schemas import (
    SCHEMA_REGISTRY,
    SchemaNotFoundError,
    list_schemas,
    load_schema,
    load_schema_registry,
    validate_instance,
)
from fi.schemas.invariants import check_semantics

__all__ = [
    "COMMANDS",
    "CommandSpec",
    "Handler",
    "build_parser",
    "command",
    "main",
]


# ---------------------------------------------------------------- schema 组


@command("schema", "list", "列出全部已登记契约 schema")
def schema_list(args: argparse.Namespace) -> int:
    try:
        rows = list_schemas(args.schema_dir)
    except SchemaNotFoundError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    print(f"{'NAME':<20}{'FILE':<36}{'PRESENT':<9}INSTANTIABLE  TITLE")
    for row in rows:
        print(
            f"{row['name']:<20}{row['file']:<36}{row['present']:<9}"
            f"{row['instantiable']:<13}{row['title']}"
        )
    return 0


@command("schema", "validate", "校验 JSON / JSONL 实例是否符合契约（含语义不变量）")
def schema_validate(args: argparse.Namespace) -> int:
    schema_ref: str = args.schema
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"错误: 实例文件不存在: {file_path}", file=sys.stderr)
        return 1

    jsonl = args.jsonl or file_path.suffix.lower() == ".jsonl"
    #: 注册短名 → 用于附加语义不变量；任意 schema 文件路径则不附加。
    semantic_name: str | None = None
    try:
        # common 等仅 defs 契约不可直接校验实例
        if schema_ref in SCHEMA_REGISTRY and not SCHEMA_REGISTRY[schema_ref].instantiable:
            print(
                f"错误: 契约 {schema_ref} 仅含公共定义（defs），不可直接校验实例",
                file=sys.stderr,
            )
            return 1
        # schema 参数 = 注册短名，或任意 schema 文件路径
        candidate = Path(schema_ref)
        if candidate.suffix == ".json" and candidate.is_file():
            with candidate.open("r", encoding="utf-8") as f:
                schema_dict: dict[str, Any] = json.load(f)
        else:
            schema_dict = load_schema(schema_ref, args.schema_dir)
            if schema_ref in SCHEMA_REGISTRY:
                semantic_name = schema_ref
        registry = load_schema_registry(args.schema_dir)
        validator = Draft202012Validator(schema_dict, registry=registry)
        problems = _validate(validator, file_path, jsonl, semantic_name)
    except SchemaNotFoundError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"错误: JSON 解析失败: {exc}", file=sys.stderr)
        return 1

    if problems:
        print(f"FAIL {len(problems)} 个问题（schema={schema_ref}, file={file_path}）:")
        for p in problems[:50]:
            print(f"  - {p}")
        if len(problems) > 50:
            print(f"  ...（其余 {len(problems) - 50} 条略）")
        return 1
    print(f"OK schema={schema_ref} file={file_path}")
    return 0


def _register_schema_validate_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--schema", required=True, help="契约注册短名或 schema 文件路径")
    p.add_argument("--file", required=True, help="待校验实例文件（.json 或 .jsonl）")
    p.add_argument("--jsonl", action="store_true", help="强制按 JSONL 逐行校验")


schema_validate.configure_args = _register_schema_validate_args  # type: ignore[attr-defined]


def _validate(
    validator: Draft202012Validator,
    file_path: Path,
    jsonl: bool,
    semantic_name: str | None = None,
) -> list[str]:
    """校验单 JSON 或 JSONL（逐行，空行跳过）。返回问题列表。"""
    problems: list[str] = []
    if not jsonl:
        with file_path.open("r", encoding="utf-8") as f:
            instance = json.load(f)
        problems.extend(_iter_error_lines(validator, instance, ""))
        if semantic_name:
            problems.extend(check_semantics(semantic_name, instance))
        return problems

    with file_path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                instance = json.loads(line)
            except json.JSONDecodeError as exc:
                problems.append(f"第 {lineno} 行: JSON 解析失败: {exc}")
                continue
            problems.extend(_iter_error_lines(validator, instance, f"第 {lineno} 行 "))
            if semantic_name:
                problems.extend(
                    f"第 {lineno} 行 {p}" for p in check_semantics(semantic_name, instance)
                )
    return problems


def _iter_error_lines(
    validator: Draft202012Validator,
    instance: Any,
    prefix: str,
) -> list[str]:
    out = []
    for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(x) for x in err.absolute_path) or "<root>"
        out.append(f"{prefix}{loc}: {err.message}")
    return out


# ---------------------------------------------------------------- data 组


@command("data", "convert", "历史实验 CSV → CampaignRecord JSONL（原始只读，派生另存）")
def data_convert(args: argparse.Namespace) -> int:
    from fi.loop.csv_replay import iter_campaign_records

    src = Path(args.input)
    if not src.is_file():
        print(f"错误: 输入 CSV 不存在: {src}", file=sys.stderr)
        return 1
    dst = Path(args.output)
    if dst.resolve() == src.resolve():
        print("错误: 输出路径不得与输入相同（原始数据只读）", file=sys.stderr)
        return 1

    ns_per_raw: float | None = args.assume_ns_per_raw
    written = 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8") as out:
        for record in iter_campaign_records(
            src,
            limit=args.limit,
            states=args.state,
            ns_per_raw=ns_per_raw,
        ):
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            written += 1

    print(f"OK 写出 {written} 条 CampaignRecord → {dst}")
    if ns_per_raw is not None:
        print(
            f"注意: 使用了 --assume-ns-per-raw {ns_per_raw} 工作假设，"
            "record.params.unit_assumption.evidence_level=hypothesis"
        )

    # 抽样自检：前 N 条必须通过 campaign-record 契约校验
    sample = min(args.validate_sample, written)
    if sample > 0:
        problems: list[str] = []
        with dst.open("r", encoding="utf-8") as f:
            for lineno, line in zip(range(sample), f):
                for p in validate_instance("campaign-record", json.loads(line)):
                    problems.append(f"第 {lineno + 1} 行 {p}")
        if problems:
            print(f"FAIL 抽样校验发现 {len(problems)} 个问题:")
            for p in problems[:20]:
                print(f"  - {p}")
            return 1
        print(f"OK 抽样自检通过（前 {sample} 条符合 campaign-record v0.1）")
    return 0


def _register_data_convert_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--input", required=True, help="输入 CSV（只读）")
    p.add_argument("--output", required=True, help="输出 JSONL（派生数据另存）")
    p.add_argument("--limit", type=int, default=None, help="只转换前 N 行")
    p.add_argument(
        "--state",
        action="append",
        default=None,
        help="只保留指定原始状态标签（可多次，如 --state SUCCESS）",
    )
    p.add_argument(
        "--assume-ns-per-raw",
        type=float,
        default=None,
        help="显式提供 raw→ns 换算假设（数值须来自已证实的实验协议，不得臆测）；不给则 delay_ns/pulse_ns 保持 unknown",
    )
    p.add_argument(
        "--validate-sample",
        type=int,
        default=100,
        help="抽样校验前 N 条（0=关闭）",
    )


data_convert.configure_args = _register_data_convert_args  # type: ignore[attr-defined]


# ---------------------------------------------------------------- 入口


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fi",
        description="FI 工具集 CLI —— 故障观测/异常捕获/上下文分析/指令级仿真",
    )
    parser.add_argument("--version", action="version", version=f"fi {__version__}")

    # 可选子命令（各专职成员维护的包）：import 期注册进 COMMANDS。
    # 惰性导入避免循环依赖；缺失模块只跳过，不影响主 CLI 可用性。
    from fi.cli_plugins import register_optional_commands

    register_optional_commands()

    groups: dict[str, dict[str, CommandSpec]] = {}
    for (g, n), spec in COMMANDS.items():
        groups.setdefault(g, {})[n] = spec

    sub = parser.add_subparsers(dest="group", metavar="{组}")
    for g, specs in sorted(groups.items()):
        gparser = sub.add_parser(g, help=f"{g} 子命令")
        gsub = gparser.add_subparsers(dest="command", metavar="{命令}", required=True)
        for n, spec in sorted(specs.items()):
            cparser = gsub.add_parser(n, help=spec.help, description=spec.help)
            cparser.add_argument(
                "--schema-dir",
                default=None,
                help="契约目录（默认自动定位仓库 docs/contracts/schemas）",
            )
            configure = getattr(spec.handler, "configure_args", None)
            if configure is not None:
                configure(cparser)
    return parser


def _force_utf8_stdio() -> None:
    """AI 编程环境经管道消费输出：强制 UTF-8，避免 Windows 控制台 GBK 乱码。"""
    import io

    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    group = getattr(args, "group", None)
    name = getattr(args, "command", None)
    if group is None or name is None:
        # 无子命令（裸 `fi`）或只给了组名：打印帮助并按用法错误退出。
        parser.print_help()
        return 2
    spec = COMMANDS.get((group, name))
    if spec is None:
        parser.print_help()
        return 2
    return spec.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
