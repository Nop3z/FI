"""Chip Profile 校验 CLI。

用法::

    python -m fi.profiles.validate profiles/<chip_id>.yaml    # 校验单个文件
    python -m fi.profiles.validate --all                      # 校验 profiles/ 下全部实例
    python -m fi.profiles.validate --all --audit              # 同时做通用性审计
    python -m fi.profiles.validate --all --verbose            # 输出分节统计

退出码：0 = 全部通过；1 = 存在校验/审计错误。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .loader import (
    SCHEMA_PATH,
    ProfileValidationError,
    audit_generality,
    load_raw,
    validate_file,
    validate_profile,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILES_DIR = REPO_ROOT / "profiles"
CODE_ROOTS = [REPO_ROOT / "fi"]


def _fmt_stats(stats: dict) -> str:
    parts = [
        f"fact={stats.get('fact', 0)}",
        f"hypothesis={stats.get('hypothesis', 0)}",
        f"unknown={stats.get('unknown', 0)}",
        f"total_claims={stats.get('total', 0)}",
        f"sources={stats.get('sources', 0)}",
        f"open_questions={stats.get('open_questions', 0)}",
    ]
    return ", ".join(parts)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Chip Profile 校验器")
    ap.add_argument("files", nargs="*", help="要校验的 Profile YAML 文件")
    ap.add_argument("--all", action="store_true", help="校验 profiles/ 下全部实例")
    ap.add_argument("--audit", action="store_true", help="通用性审计（实例值不得出现在通用代码）")
    ap.add_argument("--verbose", action="store_true", help="输出分节统计与警告明细")
    args = ap.parse_args(argv)

    files: list[Path] = [Path(f) for f in args.files]
    if args.all:
        # 草稿（*.draft.yaml）由 fi discover 生成，未经验证，不进 --all 的正式校验集
        files.extend(p for p in sorted(PROFILES_DIR.glob("*.yaml"))
                     if not p.stem.endswith(".draft"))
    if not files:
        ap.error("请给出 Profile 文件或使用 --all")

    failed = False
    for f in files:
        try:
            data = load_raw(f)
        except ProfileValidationError as exc:
            print(f"{f}: FAIL ({exc})")
            failed = True
            continue
        except Exception as exc:  # YAML 语法错误等
            print(f"{f}: FAIL (读取失败: {exc})")
            failed = True
            continue
        rep = validate_profile(data, f)
        print(rep.summary())
        print(f"  stats: {_fmt_stats(rep.stats)}")
        for e in rep.errors:
            print(f"  ERROR  {e}")
        if args.verbose:
            for w in rep.warnings:
                print(f"  WARN   {w}")
            secs = rep.stats.get("sections", {})
            if secs:
                print("  分节统计:")
                for sec, c in sorted(secs.items()):
                    print(f"    {sec:<14} fact={c.get('fact', 0)} "
                          f"hypothesis={c.get('hypothesis', 0)} unknown={c.get('unknown', 0)}")
        if not rep.ok:
            failed = True

    if args.audit:
        print(f"通用性审计: schema={SCHEMA_PATH.name}, 扫描 {', '.join(str(r) for r in CODE_ROOTS)}")
        errs = audit_generality(files, CODE_ROOTS)
        if errs:
            failed = True
            for e in errs:
                print(f"  ERROR  {e}")
        else:
            print("  通过：通用代码/schema 中未发现实例 Profile 的专有值")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
