"""契约语义不变量（JSON Schema 表达不了的跨字段约束）。

JSON Schema（Draft 2020-12）只能表达结构约束；契约里另有一批**语义不变量**，
例如"引用必须存在""某字段出现必须伴随另一字段"。这些规则放在本模块，
由 ``fi.schemas.loader.validate_instance`` 统一附加执行（CLI ``fi schema validate``
同样生效），避免只靠评审纪律。

设计原则：
- 每个不变量返回**人类可读错误列表**，空列表=通过；
- 全部为**跨字段一致性**检查，不复述 schema 已表达的类型/枚举约束；
- 芯片无关：不含任何具体芯片地址/错误码/ID（通用性门禁强制）。

已实现：
- ``reverse-report``：evidence_ref 引用完整性（调用链/入口/靶点 → evidence_refs）；
  未验证不得标 observation；timing 禁裸数字。
- ``discover-report``：自动发现证据闸门（confidence 只能是 hypothesis|unknown）；
  suggested_action 词汇表；sample_evidence 必带（findings 非空时）。
"""

from __future__ import annotations

from typing import Any, Callable

from fi import UNKNOWN

#: 自动发现产出的证据闸门：只允许这两级（禁 fact/observation）。
DISCOVER_CONFIDENCE_ALLOWED = ("hypothesis", "unknown")

#: 自动发现建议动作词汇表（与 sim-trace fault_event.action.kind 及 fi.sim 能力对齐）。
DISCOVER_SUGGESTED_ACTIONS = (
    "skip_insn",
    "flip_reg_bits",
    "reg_write",
    "mem_write",
    "map_region",
    "stub_read",
)

#: 功能级逆向的注入靶点允许的动作：**与 sim-trace fault_event.action.kind 一致**
#: （引擎枚举）。注意发现层词汇表用语义名 skip_insn，映射见 README §6。
REVERSE_SUGGESTED_ACTIONS = ("skip", "flip_reg_bits", "reg_write", "mem_write")


def _evidence_ids(instance: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for item in instance.get("evidence_refs") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            ids.add(item["id"])
    return ids


def _check_ref_exists(ref: Any, ids: set[str], where: str) -> list[str]:
    if not isinstance(ref, str):
        return [f"{where}: evidence_ref 必须是字符串（实际 {type(ref).__name__}）"]
    if ref not in ids:
        return [
            f"{where}: evidence_ref {ref!r} 未在 evidence_refs 登记"
            f"（已登记: {', '.join(sorted(ids)) or '空'}）"
        ]
    return []


def check_reverse_report(instance: Any) -> list[str]:
    """reverse-report 语义不变量。

    1) call_chain / entry_points / injection_targets / error_exits / timing segments
       的每一处 evidence_ref 都必须指向 evidence_refs 中已登记的 id；
    2) call_chain 条目 confidence=observation 时必须给 verified_by
       （未经仿真/实测验证的静态推断不得写成事实）；
    3) timing_estimate 必须是对象且带 ns_per_cycle 假设对象 + formula 常量
       （禁止裸数字：ns 是假设推导值）。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []
    ids = _evidence_ids(instance)

    entries = instance.get("call_chain") or []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        where = f"call_chain[{i}]"
        errors.extend(_check_ref_exists(entry.get("evidence_ref"), ids, where))
        if entry.get("confidence") == "observation" and not entry.get("verified_by"):
            errors.append(
                f"{where}: confidence=observation 但缺 verified_by"
                "（调用链条目须经 simulation/measurement/cross_validation 验证才能升为观测）"
            )
        for j, ex in enumerate(entry.get("error_exits") or []):
            if isinstance(ex, dict):
                errors.extend(
                    _check_ref_exists(ex.get("evidence_ref"), ids, f"{where}.error_exits[{j}]")
                )

    for i, ep in enumerate(instance.get("entry_points") or []):
        if isinstance(ep, dict):
            errors.extend(_check_ref_exists(ep.get("evidence_ref"), ids, f"entry_points[{i}]"))

    for i, tgt in enumerate(instance.get("injection_targets") or []):
        if not isinstance(tgt, dict):
            continue
        where = f"injection_targets[{i}]"
        errors.extend(_check_ref_exists(tgt.get("evidence_ref"), ids, where))
        action = tgt.get("suggested_action")
        if action not in REVERSE_SUGGESTED_ACTIONS:
            errors.append(
                f"{where}: suggested_action={action!r} 不在允许集合 "
                f"{list(REVERSE_SUGGESTED_ACTIONS)}"
            )

    timing = instance.get("timing_estimate")
    if isinstance(timing, dict):
        nspc = timing.get("ns_per_cycle")
        if not isinstance(nspc, dict):
            errors.append(
                "timing_estimate.ns_per_cycle: 必须是对象 "
                "{value, confidence[, basis]}（禁止裸数字表达频率假设）"
            )
        elif "value" not in nspc or "confidence" not in nspc:
            errors.append("timing_estimate.ns_per_cycle: 必须含 value 与 confidence")
        ns_est = timing.get("ns_estimate")
        if not isinstance(ns_est, dict):
            errors.append("timing_estimate.ns_estimate: 必须是对象（禁止裸数字）")
        elif ns_est.get("formula") != "cycles * ns_per_cycle":
            errors.append(
                "timing_estimate.ns_estimate.formula: 必须为常量 'cycles * ns_per_cycle'"
            )
        for i, seg in enumerate(timing.get("segments") or []):
            if isinstance(seg, dict):
                errors.extend(
                    _check_ref_exists(
                        seg.get("evidence_ref"), ids, f"timing_estimate.segments[{i}]"
                    )
                )
    return errors


def check_discover_report(instance: Any) -> list[str]:
    """discover-report 语义不变量（自动发现证据闸门，schema 层强制的补充）。

    schema 已用 enum 限制各 confidence 只能 hypothesis|unknown；本函数复查
    findings 三层（regions/traps/targets）+ 顶层 confidence，并检查：
    - findings 非空 ⇒ 每条必须有 sample_evidence（可回溯的原始证据样例）；
    - suggested_action 必须在发现层动作词汇表内。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []

    top = instance.get("confidence")
    if top not in DISCOVER_CONFIDENCE_ALLOWED:
        errors.append(
            f"confidence: {top!r} 越界（自动发现只允许 {list(DISCOVER_CONFIDENCE_ALLOWED)}）"
        )

    findings = instance.get("findings") or {}
    if not isinstance(findings, dict):
        return errors + ["findings: 必须是对象 {regions[], traps[], targets[]}"]
    for group in ("regions", "traps", "targets"):
        items = findings.get(group) or []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            where = f"findings.{group}[{i}]"
            conf = item.get("confidence")
            if conf not in DISCOVER_CONFIDENCE_ALLOWED:
                errors.append(
                    f"{where}.confidence: {conf!r} 越界（自动发现只允许 "
                    f"{list(DISCOVER_CONFIDENCE_ALLOWED)}；fact 需人工/交叉验证升级）"
                )
            action = item.get("suggested_action")
            if action is not None and action not in DISCOVER_SUGGESTED_ACTIONS:
                errors.append(
                    f"{where}.suggested_action: {action!r} 不在允许集合 "
                    f"{list(DISCOVER_SUGGESTED_ACTIONS)}"
                )
            if not item.get("sample_evidence"):
                errors.append(f"{where}.sample_evidence: 自动发现条目必须附原始证据样例")
    return errors



def check_chip_profile_index(instance: Any) -> list[str]:
    """chip-profile-index 草稿语义不变量（v0.3，lead 裁定）。

    规则：条目带具体 ``generated_by``（非 unknown）⇒ 必为草稿——即
    ``status == "draft"`` 且 ``source == "artifact_derived"``。
    动机：自动生成草稿必须可追溯来源，且**不得被当成已验证数据**：
    一旦通过验证，要么改 status，要么清空 generated_by（二者只能选一，
    不能既标 validated 又留着"自动生成"的身份）。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []
    for i, entry in enumerate(instance.get("profiles") or []):
        if not isinstance(entry, dict):
            continue
        gen = entry.get("generated_by")
        if not gen or gen == UNKNOWN:
            continue
        where = f"profiles[{i}]"
        if entry.get("status") != "draft":
            errors.append(
                f"{where}: generated_by={gen!r}（自动生成）但 status="
                f"{entry.get('status')!r}；自动生成草稿的 status 必须为 draft"
                "（通过验证后应改 status 或清空 generated_by）"
            )
        if entry.get("source") != "artifact_derived":
            errors.append(
                f"{where}: generated_by={gen!r}（自动生成）但 source="
                f"{entry.get('source')!r}；草稿来源恒为 artifact_derived"
            )
    return errors


def check_anomaly_report(instance: Any) -> list[str]:
    """anomaly-report 语义不变量（Phase 1『分析异常数据』的契约护栏）。

    三条，与 reverse-report 同思路（证据可回溯 / 未验证不得当事实 / 假设与结论自洽）：

    1. **证据可回溯**：findings / contradictions（含各方）/ unknowns 以及各 section
       与各嵌套条目的 evidence_refs，都必须指向 sections.evidence_chain.links[].id。
    2. **未验证不得标 observation**：证据链里 kind=computation（纯计算推导）或
       prior_report（既有报告转述）不得自称 observation——推导/转述不是直接观测。
    3. **统计警示与结论自洽**：statistical_caveats 四项齐备；数据非平稳
       （nonstationarity_detected=true）或时间混杂为 material 时，报告整体
       confidence 不得为 observation（非平稳数据不得带病出高等级总评）。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []

    sections = instance.get("sections") if isinstance(instance.get("sections"), dict) else {}
    chain = sections.get("evidence_chain") if isinstance(sections.get("evidence_chain"), dict) else {}
    links = chain.get("links") or []

    ids: set[str] = set()
    for i, ev in enumerate(links):
        if not isinstance(ev, dict):
            continue
        ev_id = ev.get("id")
        if isinstance(ev_id, str):
            ids.add(ev_id)
        if ev.get("kind") in ("computation", "prior_report") and ev.get("confidence") == "observation":
            errors.append(
                f"sections.evidence_chain.links[{i}] ({ev.get('id')}): "
                f"kind={ev['kind']} 不得标 observation"
                "（推导/转述不是直接观测；请降为 hypothesis，或改用 data_rows/rom_range 类证据）"
            )

    def refs_ok(refs: Any, where: str) -> None:
        if refs is None:
            return
        if not isinstance(refs, list):
            errors.append(f"{where}.evidence_refs: 必须是数组")
            return
        for r in refs:
            if r not in ids:
                errors.append(
                    f"{where}.evidence_refs: {r!r} 未在 evidence_chain 登记"
                    f"（已登记: {', '.join(sorted(ids)) or '空'}）"
                )

    for i, f in enumerate(instance.get("findings") or []):
        if isinstance(f, dict):
            refs_ok(f.get("evidence_refs"), f"findings[{i}]")
    for i, u in enumerate(instance.get("unknowns") or []):
        if not isinstance(u, dict):
            continue
        refs_ok(u.get("evidence_refs"), f"unknowns[{i}]")
        if u.get("confidence") != "unknown":
            errors.append(
                f"unknowns[{i}]: confidence={u.get('confidence')!r} 必须为 unknown"
                "（未知项不得包装成 hypothesis/observation）"
            )
    for i, c in enumerate(instance.get("contradictions") or []):
        if not isinstance(c, dict):
            continue
        where = f"contradictions[{i}]"
        refs_ok(c.get("evidence_refs"), where)
        for j, side in enumerate(c.get("sides") or []):
            if not isinstance(side, dict):
                continue
            ref = side.get("evidence_ref")
            if ref is not None and ref not in ids:
                errors.append(
                    f"{where}.sides[{j}].evidence_ref: {ref!r} 未在 evidence_chain 登记"
                )
        resolved_by = c.get("resolved_by_evidence_ref")
        if isinstance(resolved_by, str) and resolved_by != UNKNOWN and resolved_by not in ids:
            errors.append(
                f"{where}.resolved_by_evidence_ref: {resolved_by!r} 未在 evidence_chain 登记"
            )

    # 各 section 及其嵌套条目的 evidence_refs
    sections = instance.get("sections") or {}
    for section_key in (
        "quality_and_stationarity",
        "command_surface",
        "frame_format",
        "statistical_power",
        "unknowns",
        "evidence_chain",
    ):
        section = sections.get(section_key)
        if not isinstance(section, dict):
            continue
        refs_ok(section.get("evidence_refs"), f"sections.{section_key}")
        for field_name in (
            "nonstationary_labels",
            "code_taxonomy",
            "code_families",
            "code_phase_map",
            "detrended_axis_profiles",
            "pointwise_significance",
            "field_layout",
            "rom_three_way_comparison",
            "per_label",
            "items",
        ):
            for k, item in enumerate(section.get(field_name) or []):
                if isinstance(item, dict):
                    refs_ok(item.get("evidence_refs"), f"sections.{section_key}.{field_name}[{k}]")
    axis = (sections.get("command_surface") or {}).get("axis_structure")
    if isinstance(axis, dict):
        refs_ok(axis.get("evidence_refs"), "sections.command_surface.axis_structure")

    # 统计警示与结论自洽
    caveats = instance.get("statistical_caveats")
    if isinstance(caveats, dict):
        for key in (
            "overdispersion_ratio",
            "mde_abs",
            "low_count_warning",
            "time_confounding",
        ):
            if key not in caveats:
                errors.append(f"statistical_caveats: 缺必填项 {key}（统计警示四项必须齐备）")
        quality = (sections.get("quality_and_stationarity") or {})
        nonstationary = bool(quality.get("nonstationarity_detected"))
        confounded = caveats.get("time_confounding") == "material"
        if (nonstationary or confounded) and instance.get("confidence") == "observation":
            errors.append(
                "confidence: 数据非平稳或时间混杂 material 时，报告整体不得为 observation"
                "（跨行比较结论受污染；请降为 hypothesis 并在 caveat_notes 说明）"
            )
    return errors


#: bitflip-evidence 的掩码作用对象唯一合法常量。
MASK_APPLIES_TO = "post_insn_reg_value"


def _parse_hex_int(value: Any) -> int | None:
    """解析 "0x..." / int / 十进制字符串为 int；失败返回 None。"""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            try:
                return int(value, 16)
            except ValueError:
                return None
    return None


def _bits_of(value: int) -> set[int]:
    """返回值为 1 的位位置集合。"""
    return {i for i in range(max(1, value.bit_length())) if (value >> i) & 1}


def check_bitflip_evidence(instance: Any) -> list[str]:
    """bitflip-evidence 语义不变量（**两个防坑字段的核心校验**）。

    背景（真实 bug）：`fi.fault.effects` 枚举的是**指令机器码位**，而注入翻转的是
    **寄存器值位**（I-type 装载指令中机器码位 b ↔ 立即数位 b-20）。历史上拿机器码位
    当注入掩码（如 0x40000000）会翻到无关高位：码值不变、注入静默失效且不报错。

    本函数强制：
    1. ``claim.bit_mask_on_reg_value`` 必须等于 ``bits(source XOR target)`` 的掩码
       ——掩码写错（常见：用了机器码位）立即拒；
    2. ``claim.mask_applies_to`` 必须为 ``post_insn_reg_value``（schema const 已拦，
       此处复查嵌套的 injection spec）；
    3. ``flipped_reg_value_bits`` 必须与 mask 的位集合一致（两处表达同一个事实，
       不许一处对一处错）；
    4. 报告级/条目级/claim 级 confidence 恒 hypothesis（观测计数在
       experimental_context，属 observation，两者分字段）；
    5. ``falsifiable_prediction.injection`` 里的 bit_mask/mask_applies_to 也必须一致
       （这是真正喂给注入器的字段，最容易被手工改错）。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []

    if instance.get("confidence") != "hypothesis":
        errors.append(
            f"confidence: {instance.get('confidence')!r} 非法——位翻转证据是候选解释，恒 hypothesis"
        )

    for i, entry in enumerate(instance.get("entries") or []):
        if not isinstance(entry, dict):
            continue
        where = f"entries[{i}]"
        if entry.get("confidence") != "hypothesis":
            errors.append(f"{where}.confidence: {entry.get('confidence')!r} 非法（恒 hypothesis）")

        claim = entry.get("claim")
        if not isinstance(claim, dict):
            errors.append(f"{where}.claim: 缺失或非对象")
            continue

        if claim.get("confidence") != "hypothesis":
            errors.append(
                f"{where}.claim.confidence: {claim.get('confidence')!r} 非法（预测恒 hypothesis；"
                "观测计数在 experimental_context，不得混进 claim）"
            )

        # --- 防坑 1：mask_applies_to 常量 ---
        if claim.get("mask_applies_to") != MASK_APPLIES_TO:
            errors.append(
                f"{where}.claim.mask_applies_to: {claim.get('mask_applies_to')!r} 非法，"
                f"必须是 {MASK_APPLIES_TO!r}（掩码作用于指令执行后的寄存器值，不是机器码）"
            )

        # --- 防坑 2：mask == source XOR target ---
        src = _parse_hex_int(claim.get("source_code"))
        tgt = _parse_hex_int(claim.get("target_code"))
        mask = _parse_hex_int(claim.get("bit_mask_on_reg_value"))
        if src is None or tgt is None:
            errors.append(
                f"{where}.claim: source_code/target_code 无法解析为整数"
                f"（{claim.get('source_code')!r} / {claim.get('target_code')!r}）"
            )
        elif mask is None:
            errors.append(f"{where}.claim.bit_mask_on_reg_value: 无法解析为整数")
        else:
            expected_mask = src ^ tgt
            if mask != expected_mask:
                hint = (
                    "；提示：若你用机器码位算掩码就会得这个错——I-type 装载指令中"
                    "机器码位 b 对应立即数位 b-20，注入必须用寄存器值掩码"
                )
                errors.append(
                    f"{where}.claim.bit_mask_on_reg_value: {hex(mask)} != "
                    f"source({hex(src)}) XOR target({hex(tgt)}) = {hex(expected_mask)}{hint}"
                )

            # --- flipped_reg_value_bits 必须与 mask 位集合一致 ---
            bits = claim.get("flipped_reg_value_bits")
            if isinstance(bits, list):
                mask_bits = _bits_of(expected_mask)
                declared = {b for b in bits if isinstance(b, int)}
                if declared != mask_bits:
                    errors.append(
                        f"{where}.claim.flipped_reg_value_bits: {sorted(declared)} 与 "
                        f"source XOR target 的位集合 {sorted(mask_bits)} 不一致"
                    )

            # --- 机器码位不得等于寄存器位（同号必然是把两者搞混） ---
            mc_bits = claim.get("flipped_machine_code_bits")
            reg_bits = claim.get("flipped_reg_value_bits")
            if isinstance(mc_bits, list) and isinstance(reg_bits, list):
                if set(mc_bits) == set(reg_bits) and mc_bits:
                    errors.append(
                        f"{where}.claim: flipped_machine_code_bits 与 flipped_reg_value_bits "
                        f"完全相同 {mc_bits}——两者通常不同（I-type 差 20），疑似把两套位搞混"
                    )

        # --- 防坑 3：falsifiable_prediction.injection 一致性（真正喂给注入器的字段）---
        pred = entry.get("falsifiable_prediction")
        if isinstance(pred, dict):
            inj = pred.get("injection")
            if isinstance(inj, dict) and inj.get("action") == "flip_reg_bits":
                inj_mask = _parse_hex_int(inj.get("bit_mask"))
                claim_mask = _parse_hex_int(claim.get("bit_mask_on_reg_value"))
                if inj_mask is not None and claim_mask is not None and inj_mask != claim_mask:
                    errors.append(
                        f"{where}.falsifiable_prediction.injection.bit_mask: {hex(inj_mask)} "
                        f"与 claim.bit_mask_on_reg_value {hex(claim_mask)} 不一致"
                        "（注入规格与断言必须同一套掩码）"
                    )
                if inj.get("mask_applies_to") != MASK_APPLIES_TO:
                    errors.append(
                        f"{where}.falsifiable_prediction.injection.mask_applies_to: "
                        f"{inj.get('mask_applies_to')!r} 必须是 {MASK_APPLIES_TO!r}"
                    )

        # --- 观测与预测必须分字段（experimental_context 才能有 count）---
        ctx = entry.get("experimental_context")
        if isinstance(ctx, dict):
            for key in ("source_code_observations", "target_code_observations"):
                obs = ctx.get(key)
                if isinstance(obs, dict):
                    cnt = obs.get("count")
                    if not isinstance(cnt, int):
                        errors.append(
                            f"{where}.experimental_context.{key}.count: 观测计数必须是整数"
                        )
    return errors


def check_live_experiment(instance: Any) -> list[str]:
    """live-experiment 语义不变量（实机记录，Captured 与 Simulated 严格分开）。

    1. **state_origin 恒 captured**，captured_state.origin 亦然；实机记录不得标 simulated；
    2. **Simulated 不得混入观测**：observation 块里不得出现 simulated 语义字段；
       simulated_comparison.origin 必须为 simulated（不能拿仿真冒充捕获）；
    3. **单位显式**：params.unit_scale 与 pattern 必须存在；delay_ns/pulse_ns 若给出
       必须等于 raw × unit_scale（换算必须对得上，防手工算错）；
    4. **pattern 段数 ≤ 8**（设备硬限制，超了会静默失效）；
    5. **安全状态自洽**：safety.stopped=true ⇒ stop_reason 不得为 unknown。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []

    if instance.get("state_origin") != "captured":
        errors.append(
            f"state_origin: {instance.get('state_origin')!r} 非法——实机实验记录恒为 'captured'"
            "（仿真推断请放 simulated_comparison）"
        )
    cs = instance.get("captured_state")
    if isinstance(cs, dict):
        if cs.get("origin") != "captured":
            errors.append(
                f"captured_state.origin: {cs.get('origin')!r} 非法（Captured State 恒为 captured）"
            )

    sim = instance.get("simulated_comparison")
    if isinstance(sim, dict):
        if sim.get("origin") != "simulated":
            errors.append(
                f"simulated_comparison.origin: {sim.get('origin')!r} 非法（仿真块恒为 simulated）"
            )
    obs = instance.get("observation")
    if isinstance(obs, dict):
        leaked = [k for k in obs if k in ("predicted_code", "simulated", "simulated_code")]
        if leaked:
            errors.append(
                f"observation: 含仿真语义字段 {leaked}——实机观测不得混入仿真推断"
            )

    params = instance.get("params")
    if isinstance(params, dict):
        scale = params.get("unit_scale")
        pattern = params.get("pattern")
        if not isinstance(scale, int) or scale <= 0:
            errors.append("params.unit_scale: 必须是正整数（raw→ns 换算比例，禁止隐式假设）")
            scale = None
        if not isinstance(pattern, list):
            errors.append("params.pattern: 必须给出设备 pattern 原样回执")
        elif len(pattern) > 8:
            errors.append(
                f"params.pattern: {len(pattern)} 段超过设备上限 8（超限会静默失效）"
            )
        if scale is not None:
            for raw_key, ns_key in (("delay_raw", "delay_ns"), ("pulse_raw", "pulse_ns")):
                raw = params.get(raw_key)
                ns = params.get(ns_key)
                if isinstance(raw, int) and isinstance(ns, int) and ns != raw * scale:
                    errors.append(
                        f"params.{ns_key}: {ns} != {raw_key}({raw}) × unit_scale({scale})"
                        f" = {raw * scale}（换算对不上，疑似手工算错）"
                    )

    safety = instance.get("safety")
    if isinstance(safety, dict):
        if safety.get("stopped") is True and safety.get("stop_reason") in (None, "", UNKNOWN):
            errors.append(
                "safety.stop_reason: stopped=true 时必须给出停止原因（安全事件须可追因）"
            )
        limits = safety.get("limits")
        if isinstance(limits, dict):
            max_pulse = limits.get("max_pulse_raw")
            pulse = (params or {}).get("pulse_raw") if isinstance(params, dict) else None
            if isinstance(max_pulse, int) and isinstance(pulse, int) and pulse > max_pulse:
                errors.append(
                    f"params.pulse_raw({pulse}) 超过 safety.limits.max_pulse_raw({max_pulse})"
                    "——该注入不应被记录为成功实验"
                )
    return errors


#: fault-effect 允许的语义变化类别（与契约 enum 一致）。
CHANGE_KINDS = (
    "same",
    "rd_changed",
    "rs_changed",
    "imm_changed",
    "opcode_changed",
    "undecodable",
    "nop_like",
)

#: 观测五色分类的 kind → label 规范配对（契约常量，UI 与校验器共用）。
KIND_LABEL_PAIRS = {
    "normal": "绿",
    "restart": "品红",
    "pc_wrong": "黄",
    "missed_target": "青",
    "target_hit": "红",
}


def check_fault_effect(instance: Any) -> list[str]:
    """fault-effect 语义不变量（『指令被打坏后变成什么』的护栏）。

    1. **confidence 闸门**：报告级与变体级 confidence 恒为 hypothesis，禁 fact/observation；
    2. **位位置自洽**：flipped_bit_positions 必须落在指令位宽内（越界=算错，不是数据问题）；
    3. **变化类别自洽**：change_kind=undecodable ⇔ mutated_insn=unknown；
       semantics_changed 必须与 change_kind 一致（same ⇔ False）；
    4. **机器码长度自洽**：mutated_code_hex 必须与 original_insn.bytes_hex 等长。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []

    confidence = instance.get("confidence")
    if confidence != "hypothesis":
        errors.append(
            f"confidence: {confidence!r} 非法——位翻转枚举是候选解释，恒 hypothesis（禁 fact/observation）"
        )

    orig = instance.get("original_insn") or {}
    orig_hex = orig.get("bytes_hex") if isinstance(orig, dict) else None
    n_bits = len(orig_hex) * 4 if isinstance(orig_hex, str) and len(orig_hex) % 2 == 0 else None

    variants = instance.get("variants") or []
    for i, v in enumerate(variants):
        if not isinstance(v, dict):
            continue
        where = f"variants[{i}]"
        if v.get("confidence") != "hypothesis":
            errors.append(
                f"{where}.confidence: {v.get('confidence')!r} 非法（变体恒 hypothesis）"
            )
        positions = v.get("flipped_bit_positions")
        if isinstance(positions, list) and n_bits is not None:
            for pos in positions:
                if isinstance(pos, int) and (pos < 0 or pos >= n_bits):
                    errors.append(
                        f"{where}.flipped_bit_positions: {pos} 越界（指令仅 {n_bits} 位，0..{n_bits - 1}）"
                    )
        kind = v.get("change_kind")
        mutated_insn = v.get("mutated_insn")
        if kind == "undecodable" and mutated_insn not in (None, "unknown"):
            errors.append(
                f"{where}: change_kind=undecodable 但 mutated_insn={mutated_insn!r}"
                "（无法解码必须写 unknown）"
            )
        if kind not in (None, "undecodable") and mutated_insn == "unknown":
            errors.append(
                f"{where}: change_kind={kind!r} 但 mutated_insn=unknown"
                "（可解码的变体必须给反汇编）"
            )
        if kind == "same" and v.get("semantics_changed") is not False:
            errors.append(f"{where}: change_kind=same ⇒ semantics_changed 必须为 false")
        if kind in CHANGE_KINDS and kind != "same" and v.get("semantics_changed") is not True:
            errors.append(
                f"{where}: change_kind={kind!r} ⇒ semantics_changed 必须为 true"
            )
        mutated_hex = v.get("mutated_code_hex")
        if isinstance(mutated_hex, str) and isinstance(orig_hex, str) and len(mutated_hex) != len(orig_hex):
            errors.append(
                f"{where}.mutated_code_hex: 长度 {len(mutated_hex)} 与原始指令 {len(orig_hex)} 不等"
            )
    return errors


def check_fault_explanation(instance: Any) -> list[str]:
    """fault-explanation 语义不变量（观测反解的护栏）。

    1. **confidence 闸门**：报告级与候选级恒 hypothesis，禁 fact/observation；
    2. **多解必须真列出**：summary.multiple_solutions=true ⇒ candidates ≥ 2
       （schema 已强制长度，此处复查并与 n_candidates 对齐）；
    3. **计数自洽**：summary.n_candidates == len(candidates)（防止摘要与明细打架）；
    4. **空解必须有 reason**：candidates 为空 ⇒ reason 不得为 unknown/空；
    5. **仿真布尔自洽**：simulation_verification.executed=false ⇒ matches_observation 不得为 true。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []

    if instance.get("confidence") != "hypothesis":
        errors.append(
            f"confidence: {instance.get('confidence')!r} 非法——观测反解是候选解释，恒 hypothesis"
        )

    candidates = instance.get("candidates") or []
    summary = instance.get("summary") or {}
    n_cand = len(candidates)

    for i, c in enumerate(candidates):
        if isinstance(c, dict) and c.get("confidence") != "hypothesis":
            errors.append(f"candidates[{i}].confidence: {c.get('confidence')!r} 非法（候选恒 hypothesis）")
        if isinstance(c, dict):
            score = c.get("match_score")
            if isinstance(score, (int, float)) and not (0 <= score <= 1):
                errors.append(f"candidates[{i}].match_score: {score} 越界（必须在 0..1）")

    if isinstance(summary, dict):
        if summary.get("multiple_solutions") is True and n_cand < 2:
            errors.append(
                f"summary.multiple_solutions=true 但仅 {n_cand} 条候选"
                "（多解必须全部列出，不得只报一个）"
            )
        if summary.get("multiple_solutions") is False and n_cand > 1:
            errors.append(
                f"summary.multiple_solutions=false 但有 {n_cand} 条候选（标志与明细不一致）"
            )
        declared = summary.get("n_candidates")
        if isinstance(declared, int) and declared != n_cand:
            errors.append(
                f"summary.n_candidates={declared} 与实际 candidates 条数 {n_cand} 不一致"
            )

    if n_cand == 0:
        reason = instance.get("reason")
        if reason in (None, "", UNKNOWN):
            errors.append(
                "reason: candidates 为空时必须给出原因（如『无变体能复现观测』『求值层不支持』）"
            )

    sim = instance.get("simulation_verification")
    if isinstance(sim, dict):
        if sim.get("executed") is False and sim.get("matches_observation") is True:
            errors.append(
                "simulation_verification: executed=false 但 matches_observation=true（自相矛盾）"
            )
    return errors


def check_observation_classification(instance: Any) -> list[str]:
    """observation-classification 语义不变量（五色分类的护栏）。

    1. **confidence 闸门**：恒为 observation（机械比对；禁 hypothesis/unknown/fact）；
    2. **kind ↔ label 配对**：五类与五色一一固定（normal=绿 / restart=品红 /
       pc_wrong=黄 / missed_target=青 / target_hit=红），错配直接拒；
    3. **is_interesting 与 kind 一致**：只有 target_hit 为 true；
    4. **判定条件与 kind 自洽**：evidence 里的 pc_ok/restarted/target_reg_ok
       必须能推出该 kind（防止『标签与证据打架』）。
    """
    if not isinstance(instance, dict):
        return ["<root>: 实例必须是 JSON object"]
    errors: list[str] = []

    if instance.get("confidence") != "observation":
        errors.append(
            f"confidence: {instance.get('confidence')!r} 非法——五色分类是对已捕获观测的机械判定，恒 observation"
        )

    kind = instance.get("kind")
    label = instance.get("label")
    expected_label = KIND_LABEL_PAIRS.get(kind) if isinstance(kind, str) else None
    if expected_label is not None and label != expected_label:
        errors.append(
            f"label: kind={kind!r} 必须配『{expected_label}』，实际 {label!r}"
        )

    interesting = instance.get("is_interesting")
    if kind == "target_hit" and interesting is not True:
        errors.append("is_interesting: kind=target_hit 必须为 true（唯一值得深挖的类）")
    if kind != "target_hit" and interesting is True:
        errors.append(f"is_interesting: kind={kind!r} 不得为 true（只有 target_hit 有价值）")

    # 判定条件推导
    ev = instance.get("evidence")
    if isinstance(ev, dict):
        pc_ok = ev.get("pc_ok")
        target_ok = ev.get("target_reg_ok")
        restarted = ev.get("restarted")
        other_changed = ev.get("other_regs_changed")
        derived: str | None = None
        if restarted is True:
            derived = "restart"
        elif pc_ok is False:
            derived = "pc_wrong"
        elif pc_ok is True and target_ok is True and other_changed is not True:
            derived = "normal"
        elif pc_ok is True and target_ok is True and other_changed is True:
            derived = "missed_target"
        elif pc_ok is True and target_ok is False:
            derived = "target_hit"
        if derived is not None and kind is not None and derived != kind:
            errors.append(
                f"kind: 证据推出 {derived!r}，但声明 {kind!r}"
                "（分类标签必须与 pc_ok/target_reg_ok/restarted/other_regs_changed 一致）"
            )
    return errors


#: 契约名 → 语义不变量检查函数。
SEMANTIC_CHECKS: dict[str, Callable[[Any], list[str]]] = {
    "reverse-report": check_reverse_report,
    "discover-report": check_discover_report,
    "chip-profile-index": check_chip_profile_index,
    "anomaly-report": check_anomaly_report,
    "fault-effect": check_fault_effect,
    "fault-explanation": check_fault_explanation,
    "observation-classification": check_observation_classification,
    "bitflip-evidence": check_bitflip_evidence,
    "live-experiment": check_live_experiment,
}


def check_semantics(schema_name: str, instance: Any) -> list[str]:
    """按契约名执行语义不变量；未登记语义规则的契约返回空列表。"""
    checker = SEMANTIC_CHECKS.get(schema_name)
    if checker is None:
        return []
    try:
        return checker(instance)
    except Exception as exc:  # noqa: BLE001 —— 语义检查自身异常必须显性报出，不静默通过
        return [f"<semantics>: 语义不变量检查异常: {exc!r}"]
