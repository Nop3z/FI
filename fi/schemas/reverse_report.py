"""ReverseReport 构造器（契约层单一实现，避免各产出端各自拼装形状）。

动机（2026-11-09 逆向先行 P0）：`reverse-report.schema.json` 有三条语义不变量
（证据引用完整、未验证不得标 observation、timing 禁裸数字）。若由各工具自行拼 dict，
形状与不变量会漂移。本模块把"怎么正确拼一份报告"固化成单一实现：

- 证据登记由构造器统一编号（`add_evidence` 返回 id，调用方拿 id 去引用），
  杜绝悬空引用；
- `add_call_chain_level` 默认 `hypothesis`；只有显式给 `verified_by` 才允许
  `observation`（否则直接抛错——错在构造期，不留给校验期）；
- `set_timing` 强制要求 ns_per_cycle 假设对象，ns 由 `cycles × ns_per_cycle`
  统一换算（不许各工具自己乘）；
- `build()` 默认跑一次 `validate_instance("reverse-report", ...)`，不合法直接抛错。

用法::

    b = ReverseReportBuilder(report_id="rev-...", target_feature={...})
    ev = b.add_evidence(kind="artifact_derived", locator="fi discover chain ...")
    b.add_entry_point(kind="reset_vector", addr=base, description="复位入口", evidence_ref=ev)
    b.add_call_chain_level(level=1, function_addr=..., call_site_addr=..., evidence_ref=ev)
    b.set_timing(cycles=12000, ns_per_cycle=6.25, ns_per_cycle_confidence="hypothesis",
                 ns_per_cycle_basis="公开文档标称主频折算")
    report = b.build()      # -> dict（已通过契约校验）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fi import UNKNOWN

#: ns 换算公式常量（与 reverse-report 契约的 ns_estimate.formula 一致，单一来源）。
TIMING_FORMULA = "cycles * ns_per_cycle"

#: 允许的注入动作：**与 sim-trace fault_event.action.kind 完全一致**（引擎枚举单一来源）。
#: 注意与 discover-report 的 suggested_action 词汇表差异：发现层用语义名
#: ``skip_insn``，注入层用引擎枚举 ``skip``，映射关系见 docs/contracts/README.md §6。
INJECTION_ACTIONS = ("skip", "flip_reg_bits", "reg_write", "mem_write")

#: 允许的入口类型。
ENTRY_POINT_KINDS = (
    "reset_vector",
    "command_dispatch",
    "interrupt",
    "shared_send_function",
    "table_entry",
    "other",
)

#: 证据种类。
EVIDENCE_KINDS = (
    "artifact",
    "artifact_derived",
    "simulation",
    "measurement",
    "public_doc",
    "public_secondary",
    "inference",
    "unknown",
)

#: 升 observation 的验证手段。
VERIFICATION_METHODS = ("simulation", "measurement", "cross_validation")


class ReverseReportBuildError(ValueError):
    """构造期就违反契约（比事后校验更早暴露，错误信息带字段定位）。"""


@dataclass
class ReverseReportBuilder:
    """ReverseReport 增量构造器。所有"值 + 证据"都必须由调用方给出，不臆造。"""

    report_id: str
    target_feature: dict[str, Any]
    tool: dict[str, str] | None = None
    image: dict[str, Any] | None = None
    schema_version: str = "0.2"
    generated_at: str = UNKNOWN
    notes: str = UNKNOWN

    entry_points: list[dict[str, Any]] = field(default_factory=list)
    call_chain: list[dict[str, Any]] = field(default_factory=list)
    injection_targets: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[dict[str, Any]] = field(default_factory=list)
    _segments: list[dict[str, Any]] = field(default_factory=list)
    _timing: dict[str, Any] | None = None
    _evidence_seq: int = 0

    # ------------------------------------------------------------ 证据

    def add_evidence(
        self,
        *,
        kind: str,
        locator: str,
        confidence: str = "hypothesis",
        detail: str = UNKNOWN,
        sha256: str = UNKNOWN,
        verification: str = UNKNOWN,
    ) -> str:
        """登记一条证据，返回其 id（形如 ev-001）供条目引用。"""
        if kind not in EVIDENCE_KINDS:
            raise ReverseReportBuildError(f"证据 kind={kind!r} 不在契约枚举 {EVIDENCE_KINDS}")
        if confidence not in ("observation", "hypothesis", "unknown"):
            raise ReverseReportBuildError(f"证据 confidence={confidence!r} 非法")
        if confidence == "observation" and kind in ("public_doc", "public_secondary", "inference"):
            raise ReverseReportBuildError(
                f"旁证类证据（kind={kind}）不得标 observation（公开资料仅旁证）"
            )
        self._evidence_seq += 1
        ev_id = f"ev-{self._evidence_seq:03d}"
        self.evidence_refs.append(
            {
                "id": ev_id,
                "kind": kind,
                "locator": locator,
                "confidence": confidence,
                "detail": detail,
                "sha256": sha256,
                "verification": verification,
            }
        )
        return ev_id

    def _require_evidence(self, ev_id: str, where: str) -> None:
        if not any(e["id"] == ev_id for e in self.evidence_refs):
            raise ReverseReportBuildError(
                f"{where}: evidence_ref {ev_id!r} 未登记"
                f"（已登记: {[e['id'] for e in self.evidence_refs] or '空'}）"
            )

    # ------------------------------------------------------------ 结构

    def add_entry_point(
        self,
        *,
        kind: str,
        addr: int | str,
        description: str,
        evidence_ref: str,
        confidence: str = "hypothesis",
        notes: str = UNKNOWN,
    ) -> None:
        if kind not in ENTRY_POINT_KINDS:
            raise ReverseReportBuildError(f"入口 kind={kind!r} 不在枚举 {ENTRY_POINT_KINDS}")
        self._require_evidence(evidence_ref, "entry_point")
        self.entry_points.append(
            {
                "kind": kind,
                "addr": addr,
                "description": description,
                "evidence_ref": evidence_ref,
                "confidence": confidence,
                "notes": notes,
            }
        )

    def add_call_chain_level(
        self,
        *,
        level: int,
        function_addr: int,
        evidence_ref: str,
        confidence: str = "hypothesis",
        function_name: str = UNKNOWN,
        caller_addr: int | str = UNKNOWN,
        call_site_addr: int | str = UNKNOWN,
        call_site_insn: str = UNKNOWN,
        conditions: list[str] | None = None,
        error_exits: list[dict[str, Any]] | None = None,
        verified_by: str | None = None,
        notes: str = UNKNOWN,
    ) -> None:
        """加一层调用链。`confidence="observation"` 必须给 verified_by，否则构造期即报错。"""
        self._require_evidence(evidence_ref, f"call_chain[level={level}]")
        if confidence == "observation":
            if verified_by is None:
                raise ReverseReportBuildError(
                    f"call_chain[level={level}]: 静态推断标 observation 必须给 verified_by"
                    f"（可选 {VERIFICATION_METHODS}；未验证请保持 hypothesis）"
                )
            if verified_by not in VERIFICATION_METHODS:
                raise ReverseReportBuildError(
                    f"call_chain[level={level}]: verified_by={verified_by!r} 不在 {VERIFICATION_METHODS}"
                )
        elif verified_by is not None:
            raise ReverseReportBuildError(
                f"call_chain[level={level}]: 只有 confidence=observation 才可给 verified_by"
            )

        exits: list[dict[str, Any]] = []
        for i, ex in enumerate(error_exits or []):
            ex_ref = ex.get("evidence_ref", evidence_ref)
            self._require_evidence(ex_ref, f"call_chain[level={level}].error_exits[{i}]")
            exits.append(
                {
                    "code_raw": ex.get("code_raw", UNKNOWN),
                    "condition": ex.get("condition", UNKNOWN),
                    "path": ex.get("path", UNKNOWN),
                    "evidence_ref": ex_ref,
                    "confidence": ex.get("confidence", "hypothesis"),
                }
            )

        item: dict[str, Any] = {
            "level": level,
            "function_addr": function_addr,
            "function_name": function_name,
            "caller_addr": caller_addr,
            "call_site_addr": call_site_addr,
            "call_site_insn": call_site_insn,
            "conditions": list(conditions or []),
            "error_exits": exits,
            "evidence_ref": evidence_ref,
            "confidence": confidence,
            "notes": notes,
        }
        if verified_by is not None:
            item["verified_by"] = verified_by
        self.call_chain.append(item)

    def add_injection_target(
        self,
        *,
        addr: int,
        insn: str,
        expected_undesired_effect: str,
        rationale: str,
        evidence_ref: str,
        suggested_action: str,
        confidence: str = "hypothesis",
        trigger_hint: dict[str, Any] | None = None,
    ) -> None:
        self._require_evidence(evidence_ref, "injection_target")
        if suggested_action not in INJECTION_ACTIONS:
            raise ReverseReportBuildError(
                f"injection_target.suggested_action={suggested_action!r} 不在 {INJECTION_ACTIONS}"
                "（map_region/stub_read 属发现层动作，不是注入动作）"
            )
        item: dict[str, Any] = {
            "addr": addr,
            "insn": insn,
            "expected_undesired_effect": expected_undesired_effect,
            "rationale": rationale,
            "evidence_ref": evidence_ref,
            "suggested_action": suggested_action,
            "confidence": confidence,
        }
        if trigger_hint is not None:
            item["trigger_hint"] = trigger_hint
        self.injection_targets.append(item)

    def add_unknown(
        self,
        *,
        topic: str,
        description: str = UNKNOWN,
        needed_material: str = UNKNOWN,
        blocks: list[str] | None = None,
        suggested_probe: str = UNKNOWN,
    ) -> None:
        self.unknowns.append(
            {
                "topic": topic,
                "description": description,
                "needed_material": needed_material,
                "blocks": list(blocks or []),
                "suggested_probe": suggested_probe,
                "confidence": "unknown",
            }
        )

    # ------------------------------------------------------------ 时间估算

    def set_timing(
        self,
        *,
        cycles: int | str,
        ns_per_cycle: float | str,
        ns_per_cycle_confidence: str,
        ns_per_cycle_basis: str = UNKNOWN,
        method: str = UNKNOWN,
        confidence: str = "hypothesis",
        target_window_ns: tuple[int, int] | None = None,
    ) -> None:
        """设置时间估算。ns **由本方法统一换算**（cycles × ns_per_cycle），禁自算。"""
        if ns_per_cycle_confidence not in ("hypothesis", "unknown"):
            raise ReverseReportBuildError(
                f"ns_per_cycle.confidence={ns_per_cycle_confidence!r} 越界"
                "（频率是假设，只能 hypothesis/unknown；证实后应写进 Chip Profile）"
            )
        if isinstance(cycles, int) and isinstance(ns_per_cycle, (int, float)):
            ns_value: int | str = int(round(cycles * float(ns_per_cycle)))
            ns_conf: str = confidence
        else:
            ns_value = UNKNOWN
            ns_conf = "unknown"

        estimate: dict[str, Any] = {
            "cycles": cycles,
            "ns_per_cycle": {
                "value": ns_per_cycle,
                "confidence": ns_per_cycle_confidence,
                "basis": ns_per_cycle_basis,
            },
            "ns_estimate": {
                "value": ns_value,
                "formula": TIMING_FORMULA,
                "confidence": ns_conf,
            },
            "method": method,
            "confidence": confidence,
        }
        if target_window_ns is not None:
            lo, hi = target_window_ns
            estimate["target_window_ns"] = {"min_ns": lo, "max_ns": hi}
        self._timing = estimate

    def add_timing_segment(
        self,
        *,
        name: str,
        cycles: int | str,
        evidence_ref: str,
        ns_estimate: int | str = UNKNOWN,
        confidence: str = "hypothesis",
    ) -> None:
        self._require_evidence(evidence_ref, f"timing_segment[{name}]")
        self._segments.append(
            {
                "name": name,
                "cycles": cycles,
                "ns_estimate": ns_estimate,
                "evidence_ref": evidence_ref,
                "confidence": confidence,
            }
        )

    # ------------------------------------------------------------ 输出

    def build(self, *, validate: bool = True) -> dict[str, Any]:
        """组装报告 dict；validate=True 时立即按契约校验，不合法抛 ReverseReportBuildError。"""
        if self._timing is None:
            raise ReverseReportBuildError("缺 timing_estimate：必须先调 set_timing()")
        timing = dict(self._timing)
        if self._segments:
            timing["segments"] = list(self._segments)

        report: dict[str, Any] = {
            "schema_version": self.schema_version,
            "report_id": self.report_id,
            "target_feature": dict(self.target_feature),
            "entry_points": list(self.entry_points),
            "call_chain": list(self.call_chain),
            "timing_estimate": timing,
            "injection_targets": list(self.injection_targets),
            "evidence_refs": list(self.evidence_refs),
            "unknowns": list(self.unknowns),
            "confidence": self._overall_confidence(),
            "notes": self.notes,
            "generated_at": self.generated_at,
        }
        if self.tool is not None:
            report["tool"] = dict(self.tool)
        if self.image is not None:
            report["image"] = dict(self.image)

        if validate:
            from fi.schemas.loader import validate_instance

            errors = validate_instance("reverse-report", report)
            if errors:
                raise ReverseReportBuildError(
                    "构造的 reverse-report 未通过契约校验:\n- " + "\n- ".join(errors)
                )
        return report

    def _overall_confidence(self) -> str:
        """报告整体等级 = 各断言最弱级（有 unknown → unknown；全部 observation → observation）。"""
        levels: list[str] = [self._timing.get("confidence", "unknown") if self._timing else "unknown"]
        for item in (*self.entry_points, *self.call_chain, *self.injection_targets):
            levels.append(str(item.get("confidence", "unknown")))
        for ev in self.evidence_refs:
            levels.append(str(ev.get("confidence", "unknown")))
        if not self.call_chain and not self.entry_points and not self.injection_targets:
            return "unknown"
        if "unknown" in levels:
            return "unknown"
        if "hypothesis" in levels:
            return "hypothesis"
        return "observation"
