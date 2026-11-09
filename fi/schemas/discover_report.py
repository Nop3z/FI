"""DiscoverReport 构造与归一（契约层单一实现）。

背景：`fi.discover.*` 各模块（regions/traps/targets）的原始产出形状偏工程化
（如 regions 用 `candidates[]`、traps 用 `findings.{mtvec_writes,mcause_reads,...}` 分组），
而对外交付契约 `discover-report.schema.json` 要求统一形状
`findings.{regions,traps,targets}[]`。若无单一转换实现，各调用方会各自拼装，
形状与证据闸门必然漂移。

本模块提供：

- ``normalize_regions_report(raw)`` / ``normalize_traps_report(raw)`` /
  ``normalize_targets_report(raw)``：把单个模块产出转成"部分报告"；
- ``merge_reports(*partials)``：把多模块部分报告合并为一份完整 discover-report；
- ``DiscoverReportBuilder``：显式构造器（适合新代码直接产出契约形状）。

纪律（与契约层一致）：
- 一切条目 ``confidence`` 恒为 ``hypothesis``/``unknown``，任何外部传入的其他值
  一律降为 ``hypothesis`` 并记录（自动发现不得自称 fact/observation）；
- ``suggested_action`` 必须落在发现层词汇表内，否则降级为最保守动作；
- ``sample_evidence`` 至少 1 条：原始模块没给时由构造器从已有字段合成可回溯文本
  （地址/命中数/访问类型），绝非编造结论。
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from fi import UNKNOWN

#: 自动发现只允许的证据等级（与契约 enum 一致，单一来源见 invariants）。
CONFIDENCE_ALLOWED = ("hypothesis", "unknown")

#: 发现层建议动作词汇表（与 discover-report 契约 enum 一致）。
SUGGESTED_ACTIONS = (
    "skip_insn",
    "flip_reg_bits",
    "reg_write",
    "mem_write",
    "map_region",
    "stub_read",
)

#: 区域类 kind → 保守建议动作（用于原始模块未给动作时兜底）。
_REGION_ACTION = {
    "ram": "map_region",
    "mmio": "stub_read",
    "rom": "map_region",
    "code": "map_region",
    "unknown": "stub_read",
}


def _clamp_confidence(value: Any) -> str:
    return value if value in CONFIDENCE_ALLOWED else "hypothesis"


def _clamp_action(value: Any, fallback: str) -> str:
    return value if value in SUGGESTED_ACTIONS else fallback


def _image_block(raw: dict[str, Any]) -> dict[str, Any]:
    img = raw.get("image") or {}
    return {
        "path": img.get("path", UNKNOWN),
        "sha256": img.get("sha256", UNKNOWN),
        "size_bytes": img.get("size_bytes", 0),
        "base_address": img.get("base_address", 0),
    }


def _method_block(raw: dict[str, Any]) -> dict[str, Any]:
    method = raw.get("method") or {}
    channels = list(method.get("channels") or method.get("patterns") or method.get("approach") or [])
    if isinstance(method.get("approach"), str):
        channels = [method["approach"], *channels] if method["approach"] not in channels else channels
    boundaries = list(method.get("boundaries") or [])
    if not channels:
        channels = ["unknown"]
    if not boundaries:
        boundaries = ["实现未声明边界（视为不可信，需人工复核）"]
    params = method.get("parameters")
    block: dict[str, Any] = {"channels": channels, "boundaries": boundaries}
    if isinstance(params, dict):
        block["parameters"] = params
    return block


# ---------------------------------------------------------------------------
# 各模块原始产出 → findings 条目
# ---------------------------------------------------------------------------


def regions_to_findings(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """`fi.discover.regions` 的 candidates[] → findings.regions[]。"""
    out: list[dict[str, Any]] = []
    for c in raw.get("candidates") or []:
        kind = str(c.get("kind") or "unknown")
        page_base = c.get("page_base")
        addr = page_base if isinstance(page_base, int) else 0
        accesses = c.get("accesses") or []
        evidence = [f"page_base=0x{addr:08x} hit_count={c.get('hit_count', 0)} accesses={accesses}"]
        for sample in (c.get("sample_evidence") or [])[:3]:
            evidence.append(
                f"value={sample.get('value')} at={sample.get('at')} form={sample.get('form')}"
            )
        out.append(
            {
                "kind": kind,
                "addr": addr,
                "offset": UNKNOWN,
                "insn": str((c.get("sample_evidence") or [{}])[0].get("insns", [UNKNOWN])[0])
                if c.get("sample_evidence")
                else UNKNOWN,
                "context": str(c.get("kind_reason") or UNKNOWN),
                "suggested_action": _clamp_action(c.get("suggested_action"), _REGION_ACTION.get(kind, "stub_read")),
                "confidence": _clamp_confidence(c.get("confidence")),
                "evidence_kind": c.get("evidence_kind") if c.get("evidence_kind") in ("artifact", "artifact_derived") else "artifact_derived",
                "sample_evidence": evidence,
                "artifact_derived_from": str(raw.get("method", {}).get("classification") or UNKNOWN),
                "related": [],
            }
        )
    return out


#: traps 模块的 findings 分组名 → 发现层 kind 命名。
_TRAP_GROUP_KIND = {
    "mtvec_writes": "mtvec_write",
    "mcause_reads": "mcause_read",
    "mepc_accesses": "mepc_access",
    "mret_sites": "mret_site",
    "ecall_sites": "ecall_site",
}

#: traps 模块的 findings 分组名 → 建议动作（trap 相关多为"补模型/占位读"）。
_TRAP_GROUP_ACTION = {
    "mtvec_writes": "stub_read",
    "mcause_reads": "stub_read",
    "mepc_accesses": "stub_read",
    "mret_sites": "skip_insn",
    "ecall_sites": "skip_insn",
}


def _addr_of(item: dict[str, Any]) -> int:
    """从 '0x...' 字符串或 int 取地址；不可得返回 0（契约要求 uint）。"""
    value = item.get("addr", item.get("at"))
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return 0
    return 0


def traps_to_findings(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """`fi.discover.traps` 的 findings 分组 → 扁平的 findings.traps[]。"""
    out: list[dict[str, Any]] = []
    findings = raw.get("findings") or {}
    for group, items in findings.items():
        if not isinstance(items, list):
            continue
        kind = _TRAP_GROUP_KIND.get(group, group.rstrip("s"))
        action = _TRAP_GROUP_ACTION.get(group, "stub_read")
        for item in items:
            if not isinstance(item, dict):
                continue
            addr = _addr_of(item)
            context_parts: list[str] = []
            if item.get("insn"):
                context_parts.append(str(item["insn"]))
            if item.get("base_candidate_hex"):
                context_parts.append(f"base_candidate={item['base_candidate_hex']}")
            for ctx in (item.get("context") or [])[:4]:
                context_parts.append(str(ctx))
            evidence: list[str] = []
            if item.get("base_candidate_hex"):
                evidence.append(
                    f"base_candidate={item['base_candidate_hex']} "
                    f"base_in_image={item.get('base_in_image', UNKNOWN)}"
                )
            if item.get("save_frame_evidence"):
                evidence.append(f"save_frame={item['save_frame_evidence']}")
            if not evidence:
                evidence.append(f"{group} at {item.get('at', UNKNOWN)} insn={item.get('insn', UNKNOWN)}")
            out.append(
                {
                    "kind": kind,
                    "addr": addr,
                    "offset": item.get("offset", UNKNOWN),
                    "insn": str(item.get("insn") or UNKNOWN),
                    "context": " / ".join(context_parts) if context_parts else UNKNOWN,
                    "suggested_action": _clamp_action(item.get("suggested_action"), action),
                    "confidence": _clamp_confidence(item.get("confidence")),
                    "evidence_kind": "artifact_derived",
                    "sample_evidence": evidence,
                    "artifact_derived_from": f"trap pattern: {group}",
                    "related": [],
                }
            )
    return out


def targets_to_findings(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """`fi.discover.targets` 的候选 → findings.targets[]（递归兼容常见形状）。"""
    out: list[dict[str, Any]] = []

    def walk(node: Any, group_hint: str) -> None:
        if isinstance(node, list):
            for item in node:
                if isinstance(item, dict):
                    emit(item, group_hint)
            return
        if isinstance(node, dict):
            # 单个候选条目：含地址类字段即视为条目本身
            if any(k in node for k in ("addr", "at", "pc")) and any(
                k in node for k in ("insn", "kind", "description", "context")
            ):
                emit(node, group_hint)
                return
            for key, value in node.items():
                if key in ("image", "tool", "schema", "summary", "method"):
                    continue
                walk(value, key)

    def emit(item: dict[str, Any], group_hint: str) -> None:
        addr = _addr_of(item)
        kind = str(item.get("kind") or group_hint or "target")
        evidence = item.get("sample_evidence")
        if not isinstance(evidence, list) or not evidence:
            evidence = [
                f"{group_hint or kind} addr=0x{addr:08x} "
                f"insn={item.get('insn', UNKNOWN)} site={item.get('call_site', item.get('at', UNKNOWN))}"
            ]
        context = item.get("context")
        if isinstance(context, list):
            context = " / ".join(str(c) for c in context[:4])
        out.append(
            {
                "kind": kind,
                "addr": addr,
                "offset": item.get("offset", UNKNOWN),
                "insn": str(item.get("insn") or UNKNOWN),
                "context": str(context or item.get("description") or UNKNOWN),
                "suggested_action": _clamp_action(
                    item.get("suggested_action"), _TARGET_ACTION.get(kind, "flip_reg_bits")
                ),
                "confidence": _clamp_confidence(item.get("confidence")),
                "evidence_kind": "artifact_derived",
                "sample_evidence": [str(e) for e in evidence][:5],
                "artifact_derived_from": f"target pattern: {group_hint or kind}",
                "related": [str(r) for r in (item.get("related") or [])][:5],
            }
        )

    walk(raw.get("findings") or raw.get("candidates") or raw.get("targets") or {}, "targets")
    return out


#: 靶点 kind → 保守建议动作（未给动作时兜底）。
_TARGET_ACTION = {
    "error_code_store": "flip_reg_bits",
    "error_code_load": "mem_write",
    "branch_compare": "flip_reg_bits",
    "shared_send_call": "skip_insn",
    "call_site": "skip_insn",
}


# ---------------------------------------------------------------------------
# 合并为完整报告
# ---------------------------------------------------------------------------


def _sha256_file(path: str) -> str:
    from pathlib import Path

    p = Path(path)
    if not p.is_file():
        raise ValueError(
            f"镜像文件不存在: {path}（discover-report.image.sha256 必须来自真实镜像，"
            "禁止用占位指纹——要么给出 image_sha256 显式值并说明来源，要么修正路径）"
        )
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_report(
    *,
    schema: str = "fi.discover.report-v0",
    tool_name: str,
    tool_version: str,
    image_path: str,
    base_address: int,
    image_sha256: str | None = None,
    image_size_bytes: int | None = None,
    method: dict[str, Any] | None = None,
    regions: Iterable[dict[str, Any]] = (),
    traps: Iterable[dict[str, Any]] = (),
    targets: Iterable[dict[str, Any]] = (),
    filters: dict[str, Any] | None = None,
    notes: str = UNKNOWN,
    validate: bool = True,
) -> dict[str, Any]:
    """组装完整 discover-report（findings 三分组 + summary + 闸门字段）。"""
    regions_l = list(regions)
    traps_l = list(traps)
    targets_l = list(targets)
    method_block = method or {"channels": ["unknown"], "boundaries": ["未声明边界"]}

    summary: dict[str, Any] = {
        "counts": {
            "regions": len(regions_l),
            "traps": len(traps_l),
            "targets": len(targets_l),
        }
    }
    if filters:
        summary["filters"] = filters
    summary["notes"] = notes

    report: dict[str, Any] = {
        "schema": schema,
        "tool": {"name": tool_name, "version": tool_version},
        "image": {
            "path": image_path,
            "sha256": image_sha256 or _sha256_file(image_path),
            "size_bytes": image_size_bytes if image_size_bytes is not None else 0,
            "base_address": base_address,
        },
        "method": method_block,
        "summary": summary,
        "findings": {"regions": regions_l, "traps": traps_l, "targets": targets_l},
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
    if validate:
        from fi.schemas.loader import validate_instance

        errors = validate_instance("discover-report", report)
        if errors:
            raise ValueError("discover-report 未通过契约校验:\n- " + "\n- ".join(errors))
    return report


def normalize_module_report(raw: dict[str, Any], *, module: str) -> dict[str, Any]:
    """把单个 discover 模块的原始产出转为部分报告（只填一个 findings 分组）。

    ``module`` ∈ {"regions", "traps", "targets"}。
    """
    if module not in ("regions", "traps", "targets"):
        raise ValueError(f"未知 discover 模块: {module!r}（可用 regions/traps/targets）")
    tool = raw.get("tool") or {}
    image = _image_block(raw)
    method = _method_block(raw)
    if module == "regions":
        grouped = {"regions": regions_to_findings(raw), "traps": [], "targets": []}
    elif module == "traps":
        grouped = {"regions": [], "traps": traps_to_findings(raw), "targets": []}
    else:
        grouped = {"regions": [], "traps": [], "targets": targets_to_findings(raw)}

    return build_report(
        schema=str(raw.get("schema") or "fi.discover.report-v0"),
        tool_name=str(tool.get("name") or f"fi.discover.{module}"),
        tool_version=str(tool.get("version") or UNKNOWN),
        image_path=str(image["path"]),
        base_address=int(image["base_address"]),
        image_sha256=str(image["sha256"]),
        image_size_bytes=int(image["size_bytes"]),
        method=method,
        filters=raw.get("summary"),
        notes=str(raw.get("note") if raw.get("note") is not None else UNKNOWN),
        **grouped,
    )


def merge_reports(*reports: dict[str, Any], validate: bool = True) -> dict[str, Any]:
    """把多个部分报告合并成一份（findings 分组并集；method.boundaries 取并集去重）。"""
    if not reports:
        raise ValueError("merge_reports 至少需要一份报告")
    first = reports[0]
    channels: list[str] = []
    boundaries: list[str] = []
    regions: list[dict[str, Any]] = []
    traps: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    for rep in reports:
        for c in rep["method"]["channels"]:
            if c not in channels:
                channels.append(c)
        for b in rep["method"]["boundaries"]:
            if b not in boundaries:
                boundaries.append(b)
        regions.extend(rep["findings"]["regions"])
        traps.extend(rep["findings"]["traps"])
        targets.extend(rep["findings"]["targets"])

    merged = build_report(
        schema=str(first["schema"]),
        tool_name="fi.discover",
        tool_version=str(first["tool"]["version"]),
        image_path=str(first["image"]["path"]),
        base_address=int(first["image"]["base_address"]),
        image_sha256=str(first["image"]["sha256"]),
        image_size_bytes=int(first["image"]["size_bytes"]),
        method={"channels": channels, "boundaries": boundaries},
        regions=regions,
        traps=traps,
        targets=targets,
        notes=UNKNOWN,
        validate=validate,
    )
    merged["summary"]["sources"] = [r["tool"]["name"] for r in reports]
    return merged
