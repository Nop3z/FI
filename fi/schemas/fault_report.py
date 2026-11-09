"""Fault 明细契约的构造/归一（契约层单一实现）。

背景（方法论 docs/methodology-fault-effect-reasoning.md）：`fi.fault` 三个模块
（effects / reasoning / simulate）解决"指令被打坏后变成什么、为什么产生这个观测"。
它们的原始产出是工程形状（`Variant` dataclass、`matches_observed` 等），而对外交付
契约是 `fault-effect` / `fault-explanation` / `observation-classification` 三份
标准 JSON Schema。

本模块把"怎么正确拼一份契约实例"固化下来（与 `fi.schemas.discover_report` 同思路）：

- `build_fault_effect`      : 位翻转枚举 → fault-effect 契约实例
- `build_fault_explanation` : 观测反解 → fault-explanation 契约实例
- `build_observation_classification` : 五色分类 → observation-classification 实例

纪律（硬编码在构造器里，不靠调用方自觉）：

1. 三份产出的 confidence **恒定**（枚举/反解=hypothesis，分类=observation），
   构造器不接受外部传入的 confidence —— 想抬等级必须先改契约。
2. `fault-explanation` 的**多解**：候选全部保留，`summary.multiple_solutions`
   与 `n_candidates` 自动计算，杜绝"摘要说单解、明细有多条"。
3. `candidates` 为空时构造器自动填 `reason`（禁止静默空结果）。
4. `observation-classification` 的 `label`/`is_interesting` 由 `kind` 推导，
   调用方只能给证据（pc_ok/target_reg_ok/...），不能自己写标签。
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Iterable

from fi import UNKNOWN

#: 契约常量：kind → 五色 label（与 observation-classification 契约一致）。
KIND_TO_LABEL = {
    "normal": "绿",
    "restart": "品红",
    "pc_wrong": "黄",
    "missed_target": "青",
    "target_hit": "红",
}

#: kind → 建议下一步动作。
KIND_TO_ACTION = {
    "normal": "none",
    "restart": "reduce_glitch_width",
    "pc_wrong": "adjust_delay_window",
    "missed_target": "enumerate_bitflips",
    "target_hit": "enumerate_bitflips",
}

#: change_kind 枚举（与 fault-effect 契约一致）。
CHANGE_KINDS = (
    "same",
    "rd_changed",
    "rs_changed",
    "imm_changed",
    "opcode_changed",
    "undecodable",
    "nop_like",
)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _hex_or_unknown(value: Any) -> str:
    return value if isinstance(value, str) and value else UNKNOWN


def _variant_to_contract(v: Any) -> dict[str, Any]:
    """把 effects.Variant（dataclass）转成契约 variant 形状。

    兼容 dict 输入，便于上层从 JSON 复算/回放。
    """
    if isinstance(v, dict):
        positions = list(v.get("flipped_bit_positions") or [])
        mutated_code = v.get("mutated_code_hex") or v.get("mutated_code") or ""
        mutated_insn = v.get("mutated_insn")
        kind = v.get("change_kind") or "undefined"
        changed = v.get("semantics_changed")
        raw_diff = v.get("raw_diff_hex")
        if isinstance(mutated_code, (bytes, bytearray)):
            mutated_code = bytes(mutated_code).hex()
    else:  # effects.Variant dataclass
        positions = list(getattr(v, "flipped_bit_positions", []) or [])
        mutated_code = getattr(v, "mutated_code", b"")
        if isinstance(mutated_code, (bytes, bytearray)):
            mutated_code = bytes(mutated_code).hex()
        mutated_insn = getattr(v, "mutated_insn", None)
        kind = getattr(v, "change_kind", "undefined")
        changed = getattr(v, "semantics_changed", None)
        raw_diff = getattr(v, "raw_diff_hex", None)

    if kind not in CHANGE_KINDS:
        kind = "undecodable" if mutated_insn is None else "opcode_changed"
    if changed is None:
        changed = kind != "same"
    item: dict[str, Any] = {
        "flipped_bit_positions": positions,
        "mutated_code_hex": _hex_or_unknown(mutated_code),
        "mutated_insn": mutated_insn if mutated_insn else UNKNOWN,
        "change_kind": kind,
        "semantics_changed": bool(changed),
        "raw_diff_hex": raw_diff if isinstance(raw_diff, str) and raw_diff else UNKNOWN,
        "confidence": "hypothesis",
    }
    return item


def build_fault_effect(
    *,
    insn_hex: str,
    addr: int,
    variants: Iterable[Any],
    flip_mode: str = "one_to_zero",
    max_flips: int = 4,
    fault_level: str = UNKNOWN,
    disasm: str = UNKNOWN,
    enumeration_complete: bool | str = UNKNOWN,
    reason: str = UNKNOWN,
    report_id: str | None = None,
    validate: bool = True,
) -> dict[str, Any]:
    """组装 fault-effect 契约实例（位翻转枚举产出）。

    ``confidence`` 恒为 hypothesis：变体是候选解释，不是已证实的物理过程。
    """
    items = [_variant_to_contract(v) for v in variants]
    by_kind: dict[str, int] = {}
    for it in items:
        by_kind[it["change_kind"]] = by_kind.get(it["change_kind"], 0) + 1

    if not items and reason == UNKNOWN:
        # 空枚举必须解释（契约不变量）：默认给最诚实的原因，调用方可覆盖。
        reason = "当前 flip_mode/max_flips 下无可枚举变体（或全部语义未变且已过滤）"

    report: dict[str, Any] = {
        "schema_version": "0.2",
        "report_id": report_id or f"fe-{addr:08x}-{len(items)}",
        "original_insn": {
            "bytes_hex": insn_hex,
            "addr": addr,
            "disasm": disasm if disasm else UNKNOWN,
        },
        "physical_assumption": {
            "flip_mode": flip_mode,
            "max_flips": max_flips,
            "fault_level": fault_level,
            "confidence": "hypothesis",
            "note": (
                "假设毛刺把若干位翻转（one_to_zero ≈ crowbar-to-ground 常见效果）；"
                "不同技术（EMFI/时钟毛刺）效果可能不同，此为 hypothesis"
            ),
        },
        "variants": items,
        "summary": {
            "by_change_kind": by_kind,
            "n_variants_total": len(items),
            "n_variants_semantically_changed": sum(
                1 for it in items if it["change_kind"] != "same"
            ),
            "enumeration_complete": enumeration_complete,
            "reason": reason,
        },
        "confidence": "hypothesis",
        "discipline": "变体是候选解释，不是已证实的物理过程；真实毛刺可能同时影响多条指令",
        "generated_at": _now(),
    }
    if validate:
        from fi.schemas.loader import validate_instance

        errors = validate_instance("fault-effect", report)
        if errors:
            raise ValueError("fault-effect 未通过契约校验:\n- " + "\n- ".join(errors))
    return report


def build_fault_explanation(
    *,
    observation: dict[str, Any],
    pre_state: dict[str, Any],
    candidates: Iterable[dict[str, Any]],
    flip_mode: str = "one_to_zero",
    max_flips: int = 4,
    target_insn: dict[str, Any] | None = None,
    simulation_verification: dict[str, Any] | None = None,
    n_variants_considered: int | str = UNKNOWN,
    n_variants_unsupported: int | str = UNKNOWN,
    reason: str = UNKNOWN,
    report_id: str | None = None,
    evidence_kind: str = "artifact_derived",
    validate: bool = True,
) -> dict[str, Any]:
    """组装 fault-explanation 契约实例（观测反解产出）。

    **多解自动表达**：`summary.multiple_solutions` 与 `n_candidates` 由候选数决定，
    调用方无法伪造"单解"。
    """
    cand_list = [dict(c) for c in candidates]
    for c in cand_list:
        c.setdefault("confidence", "hypothesis")
        c.setdefault("match_detail", UNKNOWN)
        c.setdefault("eval_status", "ok")
        c.setdefault("simulation", UNKNOWN)
        c.setdefault("mutated_insn", UNKNOWN)
        c.setdefault("mutated_code_hex", UNKNOWN)
        c.setdefault("change_kind", UNKNOWN)

    n = len(cand_list)
    multiple = n > 1
    if n == 0 and reason == UNKNOWN:
        reason = "无候选能解释观测（求值层覆盖不足时应做仿真验证）"

    best = max((c.get("match_score", 0) for c in cand_list), default=UNKNOWN)

    sim = simulation_verification
    if sim is None:
        sim = {
            "executed": False,
            "matches_observation": UNKNOWN,
            "exception": UNKNOWN,
            "n_variants_tested": UNKNOWN,
            "n_matched": UNKNOWN,
            "engine": UNKNOWN,
            "discipline": "未做仿真验证；候选仅由轻量求值筛选",
        }
    else:
        sim = dict(sim)
        sim.setdefault("discipline", "仿真复现只说明在该模型下成立，不等于硬件机理已证实")

    report: dict[str, Any] = {
        "schema_version": "0.2",
        "report_id": report_id or f"fx-{n:03d}",
        "observation": {
            "regs": dict(observation.get("regs") or {}),
            "pc": observation.get("pc", UNKNOWN),
            "source": observation.get("source", UNKNOWN),
            "confidence": observation.get("confidence", "observation"),
        },
        "pre_state": {
            "regs": dict(pre_state.get("regs") or {}),
            "origin": pre_state.get("origin", "reconstructed"),
            "confidence": pre_state.get("confidence", "hypothesis"),
        },
        "physical_assumption": {
            "flip_mode": flip_mode,
            "max_flips": max_flips,
            "confidence": "hypothesis",
            "note": "假设毛刺把若干位翻转；具体物理机理未证实",
        },
        "candidates": cand_list,
        "reason": reason,
        "simulation_verification": sim,
        "summary": {
            "multiple_solutions": multiple,
            "n_candidates": n,
            "n_variants_considered": n_variants_considered,
            "n_variants_unsupported": n_variants_unsupported,
            "best_match_score": best,
        },
        "discipline": (
            "多解时全部列出，不得只报一个；候选是 hypothesis 级解释，"
            "需仿真/实测验证；仿真≠实测"
        ),
        "confidence": "hypothesis",
        "evidence_kind": evidence_kind,
        "generated_at": _now(),
    }
    if target_insn is not None:
        report["target_insn"] = dict(target_insn)
    if validate:
        from fi.schemas.loader import validate_instance

        errors = validate_instance("fault-explanation", report)
        if errors:
            raise ValueError("fault-explanation 未通过契约校验:\n- " + "\n- ".join(errors))
    return report


def build_observation_classification(
    *,
    pc_ok: bool | str = UNKNOWN,
    target_reg_ok: bool | str = UNKNOWN,
    other_regs_changed: bool | str = UNKNOWN,
    restarted: bool | str = UNKNOWN,
    evidence: dict[str, Any] | None = None,
    kind: str | None = None,
    classification_id: str | None = None,
    experiment_ref: str = UNKNOWN,
    target_feature_ref: str = UNKNOWN,
    validate: bool = True,
) -> dict[str, Any]:
    """组装 observation-classification 契约实例（五色分类）。

    `kind` 默认由证据推导（与 `fi.fault.effects.classify_observation` 同规则）；
    `label` / `is_interesting` **只能由 kind 推导**，调用方无权重写。
    证据不足时优先用 restart（重启会掩盖 PC/寄存器判定）。
    """
    if kind is None:
        if restarted is True:
            kind = "restart"
        elif pc_ok is False:
            kind = "pc_wrong"
        elif pc_ok is True and target_reg_ok is True and other_regs_changed is not True:
            kind = "normal"
        elif pc_ok is True and target_reg_ok is True and other_regs_changed is True:
            kind = "missed_target"
        elif pc_ok is True and target_reg_ok is False:
            kind = "target_hit"
        else:
            raise ValueError(
                "证据不足，无法推导五色分类：需要 restarted / pc_ok / target_reg_ok"
                f"（收到 pc_ok={pc_ok!r}, target_reg_ok={target_reg_ok!r}, "
                f"other_regs_changed={other_regs_changed!r}, restarted={restarted!r}）"
            )

    if kind not in KIND_TO_LABEL:
        raise ValueError(f"非法 kind: {kind!r}（可用: {sorted(KIND_TO_LABEL)}）")

    ev = dict(evidence or {})
    # 证据字段只在已知时写入（契约里 pc_ok/target_reg_ok 必填，故这里保证有值：
    # 未判定的轴按该 kind 的语义补全，并保留 original 值供复核）
    if "pc_ok" not in ev:
        ev["pc_ok"] = bool(pc_ok) if isinstance(pc_ok, bool) else (kind != "pc_wrong")
    if "target_reg_ok" not in ev:
        ev["target_reg_ok"] = (
            bool(target_reg_ok) if isinstance(target_reg_ok, bool) else (kind != "target_hit")
        )
    if "other_regs_changed" not in ev:
        ev["other_regs_changed"] = other_regs_changed
    if "restarted" not in ev:
        ev["restarted"] = restarted

    report: dict[str, Any] = {
        "schema_version": "0.2",
        "classification_id": classification_id or f"oc-{kind}",
        "kind": kind,
        "label": KIND_TO_LABEL[kind],
        "is_interesting": kind == "target_hit",
        "confidence": "observation",
        "evidence": ev,
        "note": _kind_note(kind),
        "next_action": KIND_TO_ACTION[kind],
        "experiment_ref": experiment_ref,
        "target_feature_ref": target_feature_ref,
    }
    if validate:
        from fi.schemas.loader import validate_instance

        errors = validate_instance("observation-classification", report)
        if errors:
            raise ValueError(
                "observation-classification 未通过契约校验:\n- " + "\n- ".join(errors)
            )
    return report


def _kind_note(kind: str) -> str:
    return {
        "normal": "正常：PC 与寄存器均符合预期（未命中目标指令）",
        "restart": "CPU 重启：通常毛刺过长/电压跌落过深，需缩短脉冲宽度",
        "pc_wrong": "PC 错误：未走到目标代码，毛刺影响了更早的执行路径，需调整 delay 窗口",
        "missed_target": "命中了某处但非目标指令：目标寄存器未变、其他寄存器变了",
        "target_hit": "命中目标指令：PC 正确但目标寄存器值不符预期（唯一值得深挖的类）",
    }[kind]


def normalize_effect_report(raw: dict[str, Any]) -> dict[str, Any]:
    """把 effects 模块的原始报告（summarize_variants 等）归一为 fault-effect 契约。"""
    orig = raw.get("original_insn") or {}
    if isinstance(orig, str):
        orig = {"disasm": orig}
    return build_fault_effect(
        insn_hex=str(raw.get("insn_bytes") or raw.get("bytes_hex") or ""),
        addr=int(raw.get("insn_addr") or raw.get("addr") or 0),
        variants=raw.get("variants") or [],
        flip_mode=(raw.get("physical_assumption") or {}).get("flip_mode", "one_to_zero"),
        max_flips=int((raw.get("physical_assumption") or {}).get("max_flips", 4)),
        disasm=str(orig.get("disasm") or UNKNOWN),
        reason=UNKNOWN,
    )


def normalize_reasoning_report(raw: dict[str, Any]) -> dict[str, Any]:
    """把 reasoning.explain_observation() 的原始产出归一为 fault-explanation 契约。"""
    observation = {
        "regs": raw.get("observation") or {},
        "pc": raw.get("insn_addr", UNKNOWN),
        "source": raw.get("source", UNKNOWN),
    }
    pre_state = {
        "regs": raw.get("pre_state") or {},
        "origin": raw.get("pre_state_origin", "reconstructed"),
    }
    summary = raw.get("summary") or {}
    candidates = []
    for c in raw.get("candidates") or []:
        candidates.append(
            {
                "flipped_bit_positions": c.get("flipped_bit_positions") or [],
                "mutated_insn": c.get("mutated_insn", UNKNOWN),
                "mutated_code_hex": c.get("mutated_code_hex", UNKNOWN),
                "change_kind": c.get("change_kind", UNKNOWN),
                "predicted_regs": c.get("predicted") or c.get("predicted_regs") or {},
                "match_score": 1.0 if c.get("matches_observed") is not False else 0.5,
                "match_detail": c.get("match_detail", UNKNOWN),
                "eval_status": c.get("eval_status", "ok"),
                "simulation": c.get("simulation", UNKNOWN),
                "confidence": "hypothesis",
            }
        )
    return build_fault_explanation(
        observation=observation,
        pre_state=pre_state,
        candidates=candidates,
        flip_mode=(raw.get("physical_assumption") or {}).get("flip_mode", "one_to_zero"),
        max_flips=int((raw.get("physical_assumption") or {}).get("max_flips", 4)),
        n_variants_considered=summary.get("variants_considered", UNKNOWN),
        n_variants_unsupported=summary.get("variants_unsupported", UNKNOWN),
        reason=UNKNOWN,
    )
