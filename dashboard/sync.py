"""同步技术团队的契约文档与派生数据，生成 Dashboard 所需的同步状态。

用途：定时任务每 3 小时运行一次，回答三个问题：
1. 技术团队交付的契约文档 / schema / 派生数据有没有变化（按内容指纹比对）；
2. 契约当前版本、状态标签语义、最新 Dashboard 影响条目是什么（从文档解析）；
3. Dashboard 还没消费哪些新的数据产物（需要补展示的地方）。

本脚本只读技术团队的交付物，只写 dashboard/generated/ 与本地同步日志。
它不做解释性推断：解析不到的字段一律写 "unknown"。

用法：
    python dashboard/sync.py            # 生成状态并打印摘要
    python dashboard/sync.py --json     # 打印机器可读摘要
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import os
DATASET_PREFIX = os.environ.get("FI_DATASET_PREFIX", "dataset")

ROOT = Path(__file__).resolve().parents[1]
DASH = Path(__file__).resolve().parent
GENERATED = DASH / "generated"
STATE_FILE = DASH / ".sync-state.json"
LOG_FILE = DASH / "sync-log.jsonl"

CONTRACTS = ROOT / "docs" / "contracts"
DERIVED = ROOT / "data" / "derived"
PROFILES = ROOT / "profiles"

# 超过该大小的文件不做内容哈希，只用 size + mtime 判断变化（避免每次读几百 MB）。
HASH_LIMIT = 8 * 1024 * 1024

# app.py 当前实际消费的数据产物（新增产物若不在其中，会被标记为未消费）。
CONSUMED_ARTIFACTS = {
    f"{DATASET_PREFIX}.meta.json",
    f"{DATASET_PREFIX}.experiment-scan.json",
    f"{DATASET_PREFIX}.analysis-result.sample.json",
    f"{DATASET_PREFIX}.state-counts.json",
    f"{DATASET_PREFIX}.error-codes.json",
    f"{DATASET_PREFIX}.pointwise-rates.json",
    f"{DATASET_PREFIX}.campaign-records.jsonl",
    # v0.3.0 批次新增展示（2026-11-09）：异常分析、命令面、帧终审与覆盖类产物
    f"{DATASET_PREFIX}.anomaly-report.json",
    f"{DATASET_PREFIX}.isp-command-surface.json",
    f"{DATASET_PREFIX}.grid-occupancy.json",
    f"{DATASET_PREFIX}.clusters.json",
    f"{DATASET_PREFIX}.run-order.json",
    f"{DATASET_PREFIX}.segments.json",
    f"{DATASET_PREFIX}.error-code-attribution.json",
    f"{DATASET_PREFIX}.candidates-sample.json",
    # 2026-11-10 批次（位翻转 / 注入靶点 / 实机方案）：各自有专属展示区块
    f"{DATASET_PREFIX}.bitflip-hypothesis.json",
    "bitflip-key-evidence.json",
    "injection-targets.json",
    "live-injection-plan.json",
    "bitflip.config.json",
    "v13c-frame-audit.json",
    # 2026-11-10 实机首批批次：实机 anomaly-report 已有专属区块「实机首批数据」，
    # 与历史批次并列展示（不合并统计口径）。
    "live-20261110.anomaly-report.json",
    # 2026-11-11 看板重写后核对补登：此项本是 /api/histogram 的实际数据源
    # （delay_counts_by_state 摊平为 series），此前被误列为「未展示」。
    # 注：sample-run-<DATASET>.json 属纯运行配置（人读/调用入参），按规则保留在 unconsumed。
    f"{DATASET_PREFIX}.delay-pulse-histograms.json",
}

# 派生目录里不参与「未展示产物」统计的前缀：_probe/_synthetic 为调试与合成数据产物。
ARTIFACT_SKIP_PREFIXES = ("_",)
ARTIFACT_SUFFIXES = (".json", ".jsonl", ".md")

PREFIX = DATASET_PREFIX


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat()


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def fingerprint(path: Path) -> dict[str, Any]:
    stat = path.stat()
    info: dict[str, Any] = {"size": stat.st_size, "mtime": int(stat.st_mtime)}
    if stat.st_size <= HASH_LIMIT:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        info["sha256"] = digest.hexdigest()
    else:
        info["sha256"] = "skipped:large"
    return info


def collect_sources() -> dict[str, dict[str, Any]]:
    """列出需要跟踪的技术团队交付物，按相对路径建索引。"""
    groups: list[tuple[str, Path, str]] = [
        ("contract-doc", CONTRACTS / "CHANGELOG.md", "*.md"),
        ("contract-doc", CONTRACTS / "README.md", "*.md"),
        ("contract-doc", CONTRACTS / "status-semantics.md", "*.md"),
        ("contract-doc", CONTRACTS / "param-mapping.md", "*.md"),
        ("methodology", ROOT / "docs", "*.md"),
        ("schema", CONTRACTS / "schemas", "*.json"),
        ("analysis-doc", ROOT / "docs" / "analysis", "*.md"),
        ("sim-doc", ROOT / "docs" / "sim", "*.md"),
        ("profile", PROFILES, "*.yaml"),
        ("derived-data", DERIVED, "*.json"),
        ("derived-data", DERIVED, "*.jsonl"),
    ]
    sources: dict[str, dict[str, Any]] = {}
    # 指定的单文件条目
    for kind, path, pattern in groups:
        if pattern != "*.md":
            continue
        if path.is_file():
            sources[str(path.relative_to(ROOT)).replace("\\", "/")] = {
                "kind": kind,
                "path": path,
            }
    # 目录条目
    for kind, directory, pattern in groups:
        if pattern == "*.md" and directory == ROOT / "docs":
            continue
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob(pattern)):
            if not path.is_file():
                continue
            key = str(path.relative_to(ROOT)).replace("\\", "/")
            if kind == "methodology" and path.parent != directory:
                continue
            sources.setdefault(key, {"kind": kind, "path": path})
    return sources


def load_previous() -> dict[str, dict[str, Any]]:
    if not STATE_FILE.is_file():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data.get("sources", {})
    except (OSError, json.JSONDecodeError):
        return {}


def parse_changelog(text: str) -> list[dict[str, Any]]:
    """解析 CHANGELOG 的版本小节，保留 Dashboard 影响条目。"""
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    buffer: list[str] = []
    sub = ""

    def flush() -> None:
        if current is None:
            return
        body = "\n".join(buffer).strip()
        if "dashboard" in sub.lower() or "Dashboard" in sub:
            current["dashboard_impact"] = body
        buffer.clear()

    for line in text.splitlines():
        match = re.match(r"^##\s+\[([^\]]+)\](?:\s*-\s*(.+))?\s*$", line)
        if match:
            flush()
            current = {
                "version": match.group(1).strip(),
                "date": (match.group(2) or "").strip() or "unknown",
                "dashboard_impact": "",
            }
            sections.append(current)
            sub = ""
            continue
        if current is None:
            continue
        heading = re.match(r"^###\s+(.+?)\s*$", line)
        if heading:
            flush()
            sub = heading.group(1)
            continue
        buffer.append(line)
    flush()
    return sections


def parse_contract_version(text: str) -> str:
    versions = [s["version"] for s in parse_changelog(text) if re.fullmatch(r"\d+\.\d+(\.\d+)?", s["version"])]
    if not versions:
        return "unknown"
    return sorted(versions, key=lambda v: [int(p) for p in v.split(".")])[-1]


def parse_state_semantics(text: str) -> str:
    match = re.search(r"unconfirmed-v\d+(?:\.\d+)*", text)
    return match.group(0) if match else "unknown"


def schema_version_constant() -> str:
    """契约实例的 schema_version 常量定义在 common.defs.json 的 $defs 中。

    包版本（CHANGELOG 最新小节）与实例常量是两件事：minor 级新增可以不 bump
    常量，因此比对必须以常量为基准，不能拿包版本去判实例是否过期。
    """
    data = load_json(CONTRACTS / "schemas" / "common.defs.json")
    const = ((data.get("$defs") or {}).get("schema_version") or {}).get("const")
    return const if isinstance(const, str) else "unknown"


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def instance_versions(sources: dict[str, dict[str, Any]]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for key, item in sources.items():
        path: Path = item["path"]
        if path.suffix != ".json":
            continue
        data = load_json(path)
        version = data.get("schema_version")
        if isinstance(version, str):
            versions[path.name] = version
    record = DERIVED / f"{PREFIX}.campaign-records.jsonl"
    if record.is_file():
        with record.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    try:
                        versions[record.name] = json.loads(line).get("schema_version", "unknown")
                    except json.JSONDecodeError:
                        versions[record.name] = "unknown"
                    break
    return versions


def schema_inventory(sources: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for key, item in sources.items():
        if item["kind"] != "schema":
            continue
        data = load_json(item["path"])
        items.append(
            {
                "name": item["path"].name,
                "title": str(data.get("title", "unknown")),
                "description": str(data.get("description", "")).split("\n")[0][:160],
            }
        )
    return sorted(items, key=lambda entry: entry["name"])


def diff_sources(
    current: dict[str, dict[str, Any]], previous: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, str]], list[str], list[str]]:
    changed: list[dict[str, str]] = []
    for key, item in current.items():
        before = previous.get(key)
        if before is None:
            changed.append({"path": key, "kind": item["kind"], "change": "新增"})
        elif before.get("sha256") != item.get("sha256") or before.get("size") != item.get("size"):
            changed.append({"path": key, "kind": item["kind"], "change": "修改"})
    removed = [key for key in previous if key not in current]
    for key in removed:
        changed.append({"path": key, "kind": previous[key].get("kind", "unknown"), "change": "移除"})
    return changed, [], removed


def artifacts_inventory() -> list[str]:
    """列出 data/derived/ 下所有交付类产物（json/jsonl/md）。

    早期只统计 `{PREFIX}.*`，导致本批新增的无前缀产物（bitflip-key-evidence /
    injection-targets / live-injection-plan 等）从不进入「未展示」清单。
    调试与合成产物（`_` 前缀）不属于交付物，直接排除。
    """
    names: list[str] = []
    for path in sorted(DERIVED.iterdir()):
        if not path.is_file():
            continue
        if path.suffix not in ARTIFACT_SUFFIXES:
            continue
        if path.name.startswith(ARTIFACT_SKIP_PREFIXES):
            continue
        names.append(path.name)
    return names


def build() -> dict[str, Any]:
    sources = collect_sources()
    previous = load_previous()
    current: dict[str, dict[str, Any]] = {}
    for key, item in sources.items():
        try:
            info = fingerprint(item["path"])
        except OSError:
            continue
        info["kind"] = item["kind"]
        current[key] = info

    changed, _, removed = diff_sources(current, previous)
    changelog_text = read_text(CONTRACTS / "CHANGELOG.md")
    semantics_text = read_text(CONTRACTS / "status-semantics.md")
    sections = parse_changelog(changelog_text)
    versions = instance_versions(sources)
    artifacts = artifacts_inventory()
    unconsumed = sorted(name for name in artifacts if name not in CONSUMED_ARTIFACTS)

    warnings: list[str] = []
    contract_version = parse_contract_version(changelog_text)
    instance_constant = schema_version_constant()
    if contract_version == "unknown":
        warnings.append("未从 CHANGELOG 解析到契约版本")
    if instance_constant == "unknown":
        warnings.append("未从 common.defs.json 解析到 schema_version 常量")
    # 只有实例版本落后于常量才算真问题；包版本高于常量是 CHANGELOG 允许的
    # minor 级新增（v0.3.0 即如此），不构成告警。
    stale = sorted(
        f"{name}={version}"
        for name, version in versions.items()
        if instance_constant != "unknown" and version != instance_constant
    )
    if stale:
        warnings.append(
            f"派生实例的 schema_version 落后于常量 {instance_constant}（历史实例未重生成）：" + ", ".join(stale)
        )
    if unconsumed:
        warnings.append(f"{len(unconsumed)} 个数据产物尚未在 Dashboard 展示")

    # 契约文件已交付但 CHANGELOG/README 均未登记：无法确认归属版本小节，如实提示。
    readme_text = read_text(CONTRACTS / "README.md")
    unregistered = sorted(
        item["name"]
        for item in schema_inventory(sources)
        if item["name"] != "common.defs.json"
        and item["name"] not in changelog_text
        and item["name"] not in readme_text
    )
    if unregistered:
        warnings.append(
            "契约 schema 未在 CHANGELOG/README 登记（版本归属未知）：" + ", ".join(unregistered)
        )

    status = {
        "generated_utc": iso(now_utc()),
        "contract": {
            "version": contract_version,
            "schema_version_constant": instance_constant,
            "state_label_semantics": parse_state_semantics(semantics_text),
            "schemas": schema_inventory(sources),
            "recent_versions": [
                {
                    "version": section["version"],
                    "date": section["date"],
                    "dashboard_impact": section["dashboard_impact"][:1200],
                }
                for section in sections[:3]
            ],
        },
        "instance_versions": versions,
        "artifacts": {"tracked": artifacts, "unconsumed": unconsumed},
        "changes": {
            "changed": changed,
            "removed": removed,
            "tracked_count": len(current),
        },
        "sources": current,
        "warnings": warnings,
    }
    return status


def write_outputs(status: dict[str, Any]) -> None:
    GENERATED.mkdir(parents=True, exist_ok=True)
    (GENERATED / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    STATE_FILE.write_text(
        json.dumps({"updated_utc": status["generated_utc"], "sources": status["sources"]},
                   ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    entry = {
        "generated_utc": status["generated_utc"],
        "contract_version": status["contract"]["version"],
        "changed": len(status["changes"]["changed"]),
        "changed_paths": [item["path"] for item in status["changes"]["changed"]],
        "unconsumed": status["artifacts"]["unconsumed"],
        "warnings": status["warnings"],
    }
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def summarise(status: dict[str, Any]) -> str:
    lines = [
        f"同步时间 (UTC): {status['generated_utc']}",
        f"契约版本: {status['contract']['version']}  ·  状态标签语义: {status['contract']['state_label_semantics']}",
        f"跟踪交付物: {status['changes']['tracked_count']} 个点，本次变更 {len(status['changes']['changed'])} 个",
    ]
    for item in status["changes"]["changed"]:
        lines.append(f"  [{item['change']}] {item['path']}")
    if status["artifacts"]["unconsumed"]:
        lines.append("未展示产物: " + ", ".join(status["artifacts"]["unconsumed"]))
    for warning in status["warnings"]:
        lines.append("注意: " + warning)
    return "\n".join(lines)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="同步技术团队契约与派生数据")
    parser.add_argument("--json", action="store_true", help="输出机器可读摘要")
    args = parser.parse_args()

    status = build()
    write_outputs(status)
    if args.json:
        print(json.dumps(status, ensure_ascii=False, indent=1))
    else:
        print(summarise(status))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())