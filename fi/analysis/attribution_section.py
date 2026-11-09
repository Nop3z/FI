# -*- coding: utf-8 -*-
"""fi.analysis.attribution_section：把"码 → 指令"归因并入异常分析报告。

## 解决的问题

`fi analyze anomaly` 目前能回答"数据里有哪些码、分布如何、是否非平稳"，
但**不能回答"这个码打中了哪条指令"**——而后者才是故障注入分析的核心问题。

本模块在报告里新增 `sections.instruction_attribution`：
用 `fi.discover.attribution` 把观测到的码逐条归因到
   码 → 命令号 → handler 地址 → 装载指令地址/文本 → 上下文

## 纪律

- 归因结果恒为 confidence=hypothesis（静态可达性 + 立即数匹配，非运行证明）
- 镜像缺失时 section 标记 available=false 且写明 reason，不得静默省略
- 不修改原报告的既有字段（纯增量 section）
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

SCHEMA_TAG = "fi.analysis.instruction-attribution-v0"


def _extract_codes(sections: dict[str, Any]) -> list[str]:
    """从 command_surface 里取出观测到的、hex 形态的码（排除 no_response/OK 这类非 hex token）。"""
    cs = sections.get("command_surface") or {}
    codes: list[str] = []

    # 主路径：taxonomy.codes（实测结构中码表就在这里）
    tax = cs.get("taxonomy")
    candidates: list[str] = []
    if isinstance(tax, dict):
        codes_dict = tax.get("codes")
        if isinstance(codes_dict, dict):
            candidates.extend(str(k) for k in codes_dict.keys())
        else:
            candidates.extend(str(k) for k in tax.keys())

    for key in ("codes", "label_counts", "code_counts"):
        v = cs.get(key)
        if isinstance(v, dict):
            candidates.extend(str(k) for k in v.keys())

    for c in candidates:
        t = c.strip()
        if t.lower().startswith("0x") and t not in codes:
            codes.append(t)
    return codes


def build_instruction_attribution(
    sections: dict[str, Any],
    *,
    image_path: str | None,
    base: int | None,
) -> dict[str, Any]:
    """构造 instruction_attribution section（不修改入参）。"""
    codes = _extract_codes(sections)

    if not image_path:
        return {
            "schema": SCHEMA_TAG,
            "available": False,
            "reason": "未提供固件镜像（--image），无法做指令级归因",
            "codes_observed": codes,
            "discipline": "归因需要镜像；缺镜像时本 section 明确标记不可用，不推测",
        }
    if base is None:
        return {
            "schema": SCHEMA_TAG,
            "available": False,
            "reason": "未提供镜像基址（--image-base），无法做指令级归因",
            "codes_observed": codes,
            "discipline": "基址是归因的必要输入；缺失时不做猜测",
        }
    if not Path(image_path).is_file():
        return {
            "schema": SCHEMA_TAG,
            "available": False,
            "reason": f"镜像不存在: {image_path}",
            "codes_observed": codes,
        }
    if not codes:
        return {
            "schema": SCHEMA_TAG,
            "available": False,
            "reason": "观测数据中未发现 0x 形态的码，无需归因",
            "codes_observed": [],
        }

    try:
        from fi.discover.attribution import attribute_codes
        report = attribute_codes(image_path, base, codes)
    except Exception as exc:  # noqa: BLE001 —— 归因失败不得让整份报告崩掉
        return {
            "schema": SCHEMA_TAG,
            "available": False,
            "reason": f"归因过程失败: {type(exc).__name__}: {exc}",
            "codes_observed": codes,
        }
    # 精简输出（报告里不需要全部上下文，保留可审计的关键字段）
    attributions = []
    for a in report.get("attributions", []):
        sites = []
        for s in (a.get("sites") or [])[:5]:
            sites.append({
                "insn_addr": s["insn_addr"],
                "insn": s["insn"],
                "command": s["command"],
                "handler": s["handler"],
                "dest_reg": s["dest_reg"],
                "confidence": s["confidence"],
            })
        attributions.append({
            "code": a["code"],
            "status": a["attribution_status"],
            "site_count": a["site_count"],
            "handler_count": a["handler_count"],
            "sites": sites,
            "confidence": a["confidence"],
            "evidence_kind": "artifact_derived",
        })

    cmd_tbl = report.get("command_table") or {}
    return {
        "schema": SCHEMA_TAG,
        "available": True,
        "codes_observed": codes,
        "image": report["image"],
        "command_table": {
            "source_table_addr": cmd_tbl.get("source_table_addr"),
            "entry_count": cmd_tbl.get("entry_count"),
        },
        "summary": report["summary"],
        "attributions": attributions,
        "method_boundaries": report["method"]["boundaries"],
        "discipline": (
            "静态归因 = 该码在某个 handler 体内以立即数装载；"
            "不等于运行时确实执行了该指令（运行期证据需仿真/实测，verified_by 留位）"
        ),
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


def attach_to_report(
    report: dict[str, Any],
    *,
    image_path: str | None,
    base: int | None,
) -> dict[str, Any]:
    """把 instruction_attribution 并入报告（返回新 dict，不改入参）。"""
    sections = dict(report.get("sections") or {})
    section = build_instruction_attribution(sections, image_path=image_path, base=base)
    sections["instruction_attribution"] = section

    out = dict(report)
    out["sections"] = sections

    # 若归因成功，追加 finding（保持"每条结论带 evidence_level"的纪律）
    findings = list(report.get("findings") or [])
    if section.get("available"):
        s = section["summary"]
        findings.append({
            "finding_id": "F-attribution-1",
            "kind": "instruction_attribution",
            "description": (
                f"指令级归因：{s['codes_attributed']}/{s['codes_requested']} 个观测码可归因到"
                f"具体 handler 内的装载指令（共 {s['total_sites']} 个站点，"
                f"命令表 {section['command_table']['entry_count']} 项）"
            ),
            "evidence_level": "hypothesis",
            "supporting_refs": ["sections.instruction_attribution"],
            "source": "this_run",
        })
        unattributed = [a["code"] for a in section["attributions"]
                        if a["status"] != "attributed_to_handler"]
        if unattributed:
            findings.append({
                "finding_id": "F-attribution-2",
                "kind": "attribution_gap",
                "description": (
                    "以下码未在命令表 handler 内以立即数装载，"
                    "可能由运算生成/由调用者传入/经文发送函数统一装载："
                    + ", ".join(unattributed)
                ),
                "evidence_level": "observation",
                "supporting_refs": ["sections.instruction_attribution"],
                "source": "this_run",
            })
    out["findings"] = findings
    return out
