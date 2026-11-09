# -*- coding: utf-8 -*-
"""fi.discover.injection_targets：把"静态归因"升级为**可注入靶点清单**。

## 定位（docs/methodology-fault-effect-reasoning.md）

`fi.discover.attribution` 回答"这个码由哪条指令装载"；
`fi.fault.effects` 回答"这条指令被打坏后变成什么"；
**本模块把两者接起来**，产出"精确故障注入"的直接输入：

    给每个靶点：命令号 / handler / 装载指令地址+机器码+反汇编
              / 位翻转变体（1–3 bit，1→0）会把码变成什么
              / 建议注入动作 / 预期观测变化

这样闭环不必"盲试"，而是带着预期去试（文章箴言：**don't glitch and pray**）。

## 关键机制（本模块存在的理由）

错误码装载指令通常是 `addi rd, zero, imm`。它在**立即数位**上被打坏时，
码值本身会变成另一个码——而那个码**可能正是实验里真实观测到的另一个状态**。

实测样例（target-chip，验证用；代码里不写死）：
    0x<CODE_D> 的 `addi a0,zero,0x504` 翻 1 bit（bit30）→ `addi a0,zero,0x104`
    ⇒ 一次位翻转把"0x504 路径"变成"0x104 路径"，直接解释两个码的频次结构。

所以本模块的核心产出是**码间迁移矩阵**：哪些 1–3 bit 翻转会让码 A 变成码 B
（B 若在观测集里 → 高价值靶点，因为它把两条观测链连起来）。

## 纪律

- 芯片无关：码值/命令号/观测集全部由参数传入，代码中无实例字面量
- 全部 `confidence=hypothesis`（物理过程是候选解释，不是已证实）
- 变体**允许多解**：同一码可能由多个翻转组合得到，全部列出
- 明确区分"语义改变"与"变成不可解码"（后者通常 → 非法指令 trap）
"""
from __future__ import annotations

import re
from collections import defaultdict, Counter
from pathlib import Path

import capstone

from .common import Insn, linear_disasm, load_image, sha256_hex

SCHEMA = "fi.discover.injection-targets-v1"

#: 建议注入动作枚举（与 sim-trace / discover-report 契约对齐）
ACTIONS = ("skip_insn", "flip_reg_bits", "reg_write", "mem_write")

_RE_LI = re.compile(r"^(?:c\.li|li|addi)\s+(\w+),\s*(?:zero,\s*)?(-?(?:0x[0-9a-fA-F]+|\d+))$")


def _sext(v: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (v & (sign - 1)) - (v & sign)


def _insn_code_at(image: bytes, base: int, addr: int) -> bytes | None:
    """取该地址的指令机器码（按 RVC 长度：低 2 位 != 0b11 则是 2 字节）。"""
    off = addr - base
    if not (0 <= off < len(image)):
        return None
    lo = image[off]
    size = 2 if (lo & 0x3) != 0b11 else 4
    if off + size > len(image):
        return None
    return image[off:off + size]


def _disasm_one(code: bytes, addr: int, xlen: int, compressed: bool) -> str | None:
    md = capstone.Cs(
        capstone.CS_ARCH_RISCV,
        (capstone.CS_MODE_RISCV32 if xlen == 32 else capstone.CS_MODE_RISCV64)
        | (capstone.CS_MODE_RISCVC if compressed else 0),
    )
    try:
        insn = next(md.disasm(code, addr))
    except StopIteration:
        return None
    return f"{insn.mnemonic} {insn.op_str}".strip()


def _code_from_insn_text(text: str | None) -> int | None:
    """从（变体）指令文本里解析出"该指令会装载进 rd 的常量值"。

    只接受单条立即数装载形态（li / c.li / addi rd,zero,imm）；其它形态返回 None
    （语义已不是"装载一个码"，不能当作码值解释）。
    """
    if not text:
        return None
    m = _RE_LI.match(text.strip())
    if not m:
        return None
    try:
        return int(m.group(2), 0) & 0xFFFFFFFF
    except ValueError:
        return None


def _classify_variant(orig_text: str, mutated: str | None) -> str:
    """把变体归到对注入有意义的小类里。"""
    if mutated is None:
        return "undecodable"          # 通常 → 非法指令异常（trap）
    if mutated.strip() == orig_text.strip():
        return "semantics_unchanged"
    m = _RE_LI.match(mutated.strip())
    if m:
        return "loads_other_constant"   # ★ 最有价值：码值改变
    if mutated.split()[0] in ("nop", "c.nop"):
        return "becomes_nop"            # 等价于跳过
    return "other_semantic_change"


def _discriminating_predictions(
    *,
    orig_code_val: int,
    target_code: str | None,
    target_observed: bool,
    addr: int,
    dest_reg: str,
    all_codes_here: list[int],
) -> list[dict]:
    """列出"如何区分本靶点与其它可能机制"的具体判据。

    动机（docs/methodology-fault-effect-reasoning.md：多解必须能分辨）：
    同一个观测（例如上位机看到 0x<CODE_B>）可能有多种成因：
      a) 本靶点的装载指令被 1-bit 翻坏 → 码字段变、帧其余不变；
      b) 打中了发送函数（帧构造/魔术字/长度）→ 帧结构整体可能异常；
      c) 打中了决定走哪条分支的指令 → 走的是另一个 handler 的 0x<CODE_B> 出口；
      d) 打中了更早的指令导致路径完全不同 → PC/时序侧证据会不同。
    只列"能实际执行/观测的判据"，不写无法验证的猜测。
    """
    out: list[dict] = []
    if target_code:
        out.append({
            "hypothesis": "本靶点命中：装载指令的立即数位被翻转",
            "prediction": (
                f"响应帧中码字段由 0x{orig_code_val:04x} 变为 {target_code}；"
                f"帧的 magic/长度/其余字段与未注入时逐字节相同"),
            "supporting_evidence": (
                f"码字段变化且帧结构不变；PC 轨迹仍经过 0x{addr:08x}；"
                f"寄存器 {dest_reg} 在 0x{addr:08x} 之后的值等于 {target_code}"),
            "rules_out": "排除'打中发送函数'（那会改变帧结构/长度）",
        })
        out.append({
            "hypothesis": "打中了共享发送函数（而非本装载指令）",
            "prediction": "响应帧结构异常：magic 字节错误、长度字段错误、或帧被截断/重复",
            "supporting_evidence": (
                "magic/长度与基线不同；或观测到 0 字节/部分帧；"
                "码字段即便恰好等于目标码，帧其余部分也应与基线不同"),
            "rules_out": "排除本靶点（本靶点只改码字段，不改帧结构）",
        })
        out.append({
            "hypothesis": "打中了决定路径的条件分支（走了另一个 handler 的出口）",
            "prediction": (
                "时序侧可见：PC 轨迹进入的是另一个 handler 地址；"
                f"且 0x{addr:08x} 之前的条件分支结果与基线相反"),
            "supporting_evidence": (
                f"才需要'另一个码装载点'也存在该码；本镜像中 "
                f"{target_code} 的装载点集合若与本点地址不同即可区分"),
            "rules_out": "若 trace 显示未经过本装载点，则本靶点不成立",
        })
    if len(all_codes_here) > 1:
        out.append({
            "hypothesis": "同一 handler 内有多个码装载点，观测无法区分是哪一处",
            "prediction": (
                "需看注入时刻（delay/seq）是否落在该装载点执行窗口内；"
                "或看寄存器差异出现于哪条指令之后"),
            "supporting_evidence": (
                f"本 handler 内的码装载点："
                f"{', '.join(f'0x{c:04x}' for c in sorted(set(all_codes_here)))}；"
                "需用 seq/pc 精确触发而非模糊时间窗"),
            "rules_out": "时间定位不足时不得断言具体装载点",
        })
    out.append({
        "hypothesis": "毛刺影响了多条指令（非单位翻转）",
        "prediction": "出现无法由单条指令解释的多寄存器差异，或 PC 跳飞/异常",
        "supporting_evidence": (
            "trap 现场（mcause/mepc/寄存器帧）显示异常；或轨迹在多处偏离基线"),
        "rules_out": "单点解释不成立时必须按多故障模型重估",
    })
    if not target_observed:
        out.append({
            "hypothesis": "目标码在实验中从未被观测到",
            "prediction": f"若本靶点成立，应首次观测到 {target_code}（可作为独立验证）",
            "supporting_evidence": (
                "该码在历史 CSV/日志中零命中，出现即为新证据；"
                "但需排除'上位机把它归到其它标签'的可能"),
            "rules_out": "若该码从未出现且其它预测也不符，则靶点假设需修正",
        })
    return out


def _target_from_code_site(
    *,
    image: bytes,
    base: int,
    site: dict,
    entry: dict,
    code_str: str,
    observed_codes: set[int],
    max_flips: int,
    xlen: int,
    compressed: bool,
    max_variants_listed: int,
    sibling_codes: list[int] | None = None,
) -> dict | None:
    """把一个归因站点（码装载指令）转成注入靶点条目。"""
    addr = int(site["insn_addr"], 16)
    code_bytes = _insn_code_at(image, base, addr)
    if code_bytes is None:
        return None

    from fi.fault.effects import enumerate_bitflips

    orig_code_val = int(code_str, 16)
    variants = enumerate_bitflips(
        code_bytes, addr, max_flips=max_flips, flip_mode="one_to_zero", xlen=xlen,
    )

    # 按"翻转位数"分组统计，并抽取"改变码值"的关键条目
    by_kind: Counter = Counter()
    by_nbits: Counter = Counter()
    code_migrations: dict[int, list[dict]] = defaultdict(list)   # new_code -> variants
    rd_only_changes: list[dict] = []      # rd 变了但码值不变（不是码迁移）
    undecodable_examples: list[dict] = []
    listed: list[dict] = []

    for v in variants:
        n = len(v.flipped_bit_positions)
        by_nbits[n] += 1
        kind = _classify_variant(site["insn"], v.mutated_insn)
        by_kind[kind] += 1
        item = {
            "flipped_bits": v.flipped_bit_positions,
            "n_bits": n,
            "mutated_code_hex": v.mutated_code.hex(),
            "mutated_insn": v.mutated_insn,
            "change_kind": kind,
        }
        if kind == "loads_other_constant":
            new_code = _code_from_insn_text(v.mutated_insn)
            if new_code is not None:
                if new_code == orig_code_val:
                    # 只改了目标寄存器（rd），码值不变 —— **不是码迁移**，单独归类
                    item["rd_changed_only"] = True
                    if len(rd_only_changes) < 4:
                        rd_only_changes.append(item)
                    continue
                item["resulting_code"] = f"0x{new_code:04x}"
                item["resulting_code_observed"] = new_code in observed_codes
                # ---- 关键：区分两类位位置（语义完全不同，混用会让注入完全失效） ----
                #   machine_code_bits : 指令**机器码**里的位（effects 枚举用的就是这个）
                #   reg_value_bits    : 装载后**寄存器值**里的位 = 源码 XOR 结果码
                # 二者关系（RISC-V I-type）：机器码位 b（20≤b≤31）↔ 立即数位 b-20。
                # 寄存器 mask 一律由 XOR 推导，不依赖编码布局知识，天然正确。
                reg_xor = orig_code_val ^ new_code
                item["machine_code_bits"] = list(v.flipped_bit_positions)
                item["reg_value_bits"] = [b for b in range(len(code_bytes) * 8)
                                          if (reg_xor >> b) & 1]
                item["reg_value_mask"] = f"0x{reg_xor:x}"
                code_migrations[new_code].append(item)
        elif kind == "undecodable" and len(undecodable_examples) < 4:
            undecodable_examples.append(item)
        if len(listed) < max_variants_listed and kind in (
                "loads_other_constant", "becomes_nop", "undecodable"):
            listed.append(item)

    # 码间迁移摘要（按"变成的码"聚合，优先列出观测集中出现过的目标码）
    migration_summary = []
    for new_code, items in sorted(
        code_migrations.items(),
        key=lambda kv: (kv[0] not in observed_codes, min(i["n_bits"] for i in kv[1]), kv[0]),
    ):
        bits_min = min(i["n_bits"] for i in items)
        cheapest = [i for i in items if i["n_bits"] == bits_min][0]
        migration_summary.append({
            "resulting_code": f"0x{new_code:04x}",
            "resulting_code_observed_in_experiments": new_code in observed_codes,
            "min_flips_needed": bits_min,
            # 两套位置必须都给出：machine_code_bits 指"翻指令里的哪些位"，
            # reg_value_bits 指"翻寄存器值的哪些位"（注入动作实际用后者）。
            "example_machine_code_bits": cheapest["machine_code_bits"],
            "example_reg_value_bits": cheapest["reg_value_bits"],
            "example_reg_value_mask": cheapest["reg_value_mask"],
            "example_mutated_insn": cheapest["mutated_insn"],
            "n_variants": len(items),
        })

    # 高价值判定：存在"1 bit 翻转 → 另一个被观测到的码"
    one_bit_migrations = [m for m in migration_summary
                          if m["min_flips_needed"] == 1
                          and m["resulting_code_observed_in_experiments"]]

    # ---- 建议动作 + 预期观测 ----
    # 逻辑一：要复现"码 A 被改成码 B"，最小扰动 = 翻转那 1 bit（flip_reg_bits），
    #         或直接 reg_write 把 rd 写成 B（更可控但更"人工"）。
    # 逻辑二：要让"该错误码不再上报"= skip 装载指令（rd 保留旧值）。
    if one_bit_migrations:
        best = one_bit_migrations[0]
        suggested = {
            "primary": {
                "action": "flip_reg_bits",
                "reg": site.get("dest_reg", "unknown"),
                "bit_width": len(code_bytes) * 8,
                "bit_mask": best["example_reg_value_mask"],
                # 语义显式声明（lead 裁定）：mask 针对**装载指令执行后**寄存器值的位，
                # 不是在指令执行前翻转、也不是针对指令机器码位。
                "mask_applies_to": "post_insn_reg_value",
                "note": (f"装载指令执行完、下一条指令执行前，翻转寄存器 "
                         f"{site.get('dest_reg', 'unknown')} 的位 "
                         f"{best['example_reg_value_bits']}"
                         f"（对应机器码位 {best['example_machine_code_bits']}）⇒ 码 "
                         f"0x{orig_code_val:04x} 变为 {best['resulting_code']}"),
            },
            "alternative": {
                "action": "reg_write",
                "reg": site.get("dest_reg", "unknown"),
                "value": best["resulting_code"],
                "mask_applies_to": "post_insn_reg_value",
                "note": "直接写入目标码（可控性更高，但物理真实性更低：不模拟位翻转过程）",
            },
            "negative_control": {
                "action": "skip_insn",
                "note": "跳过装载指令 ⇒ rd 保持旧值，该码不上报（用于对照）",
                "expected_if_not_hit": (
                    f"未注入/注入未命中时：应观测到基线行为 —— 码 0x{orig_code_val:04x} "
                    f"正常上报，帧结构与基线逐字节一致；"
                    "若连基线都观测不到该码，说明该路径在本次运行时未被走到（与靶点无关）"),
            },
        }
        expected = {
            "primary_effect": f"响应帧中的码字段由 0x{orig_code_val:04x} 变为 {best['resulting_code']}",
            "observable_change": (
                f"若上位机按码分类：观测状态从该码对应的标签迁移到 "
                f"{best['resulting_code']} 对应的标签（后者是否被实验观测到："
                f"{'是' if best['resulting_code_observed_in_experiments'] else '否'}）"),
            "secondary_effect": "帧其余字节（magic/长度）预期不变——本靶点只改码字段",
            "negative_control_effect": "该码消失；若发送路径仍执行，可能观测到旧码或 0",
            "discriminating_predictions": _discriminating_predictions(
                orig_code_val=orig_code_val,
                target_code=best["resulting_code"],
                target_observed=best["resulting_code_observed_in_experiments"],
                addr=addr, dest_reg=site.get("dest_reg", "unknown"),
                all_codes_here=sibling_codes or [orig_code_val],
            ),
        }
    else:
        suggested = {
            "primary": {
                "action": "skip_insn",
                "note": "无可用的 1-bit 码迁移；跳过装载指令使该码不上报（对照用）",
                "expected_if_not_hit": (
                    f"未命中时：码 0x{orig_code_val:04x} 正常上报（与基线一致）"),
            },
            "alternative": {
                "action": "flip_reg_bits",
                "reg": site.get("dest_reg", "unknown"),
                "bit_width": len(code_bytes) * 8,
                "bit_mask": "unknown",
                "mask_applies_to": "post_insn_reg_value",
                "note": "码迁移需 ≥2 bit，物理上不确定；可先试 imm 高位单 bit",
            },
            "negative_control": {
                "action": "skip_insn",
                "note": "同上（本情形主/对照同一动作）",
                "expected_if_not_hit": f"未命中时：码 0x{orig_code_val:04x} 正常上报",
            },
        }
        expected = {
            "primary_effect": "该码不再上报（rd 保持旧值）",
            "observable_change": "该码对应的观测标签消失，或落到 HANG/其它状态",
            "secondary_effect": "unknown（无 1-bit 码迁移，帧内容不确定性更高）",
            "negative_control_effect": "同上",
            "discriminating_predictions": _discriminating_predictions(
                orig_code_val=orig_code_val, target_code=None, target_observed=False,
                addr=addr, dest_reg=site.get("dest_reg", "unknown"),
                all_codes_here=sibling_codes or [orig_code_val],
            ),
        }

    return {
        "target_id": f"tgt-{orig_code_val:04x}-at-{addr:08x}",
        "kind": "error_code_load",
        "code": f"0x{orig_code_val:04x}",
        "command": entry.get("command"),
        "command_hex": (f"0x{entry['command']:02x}"
                        if isinstance(entry.get("command"), int) else None),
        "handler": entry.get("handler"),
        "handler_entry_addr": site.get("handler"),
        "addr": site["insn_addr"],
        "offset": addr - base,
        "insn_bytes_hex": code_bytes.hex(),
        "insn_width_bits": len(code_bytes) * 8,
        "insn": site["insn"],
        "dest_reg": site.get("dest_reg"),
        "context": site.get("context", []),
        "bitflip_variants": {
            "physical_assumption": (
                "假设毛刺把若干位 1→0（crowbar-to-ground 常见效果）；"
                "1–3 bit 同时翻转，笛卡尔枚举。这是候选解释，不是已证实物理过程"
            ),
            "flip_mode": "one_to_zero",
            "max_flips": max_flips,
            "n_variants_total": len(variants),
            "n_variants_by_nbits": {str(k): v for k, v in sorted(by_nbits.items())},
            "n_variants_by_kind": dict(by_kind),
            "code_migrations": migration_summary[:24],
            "rd_changed_only_examples": rd_only_changes,
            "undecodable_examples": undecodable_examples,
            "sample_variants": listed[:max_variants_listed],
        },
        "suggested_action": suggested,
        "expected_observation": expected,
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
        "hardware_verification": "unknown（本项目纯离线，无实机；结论仅静态+仿真级）",
    }


def _mask_hex(bits: list[int], n_bytes: int) -> str:
    """把"从 LSB 起算的位位置"渲染为位掩码（供 flip_reg_bits 的 bit_mask 直接用）。"""
    v = 0
    for b in bits:
        v |= 1 << b
    return f"0x{v:x}"


def _branches_near_code_site(
    disasm: list[Insn], addr: int, window: int = 12
) -> list[dict]:
    """找码装载指令附近的"决定该码是否被执行"的条件分支（第二类靶点）。"""
    idx = next((i for i, x in enumerate(disasm) if x.addr == addr), None)
    if idx is None:
        return []
    out = []
    for j in range(max(0, idx - window), min(len(disasm), idx + 2)):
        insn = disasm[j]
        if insn.mnemonic not in ("beq", "bne", "c.beqz", "c.bnez", "blt", "bge",
                                 "bltu", "bgeu", "bgez", "bltz", "blem", "bgtz"):
            continue
        out.append({
            "addr": f"0x{insn.addr:08x}",
            "offset": insn.offset,
            "insn": insn.text,
            "relation": ("after_code_load" if insn.addr > addr else "before_code_load"),
        })
    return out


def build_injection_targets(
    image_path: str,
    base: int,
    codes: list[int | str],
    *,
    xlen: int = 32,
    compressed: bool = True,
    observed_codes: list[int | str] | None = None,
    max_flips: int = 3,
    max_variants_listed: int = 12,
    include_branch_targets: bool = True,
    dispatch_report: dict | None = None,
    attribution_report: dict | None = None,
) -> dict:
    """主入口：镜像 + 码集合 → 注入靶点清单（机器可读）。

    参数
    ----
    codes             : 要产出靶点的码（错误码/命令号等）；芯片无关，由调用方给。
    observed_codes    : 实验里**实际观测到**的码集合（用于标注"某翻转会变成观测集里的码"）
                        —— 这是本清单最高价值信号；不给则退化为一律 False。
    max_flips         : 位翻转枚举上限（1–3 足够覆盖多数物理情形，且保持组合数可控）
    dispatch_report   : 可传入已算好的 discover_dispatch() 结果（省一次解码）
    attribution_report: 可传入已算好的 attribute_codes() 结果
    """
    image = load_image(image_path)
    observed: set[int] = set()
    for c in (observed_codes or []):
        try:
            observed.add(int(c, 16) if isinstance(c, str) and str(c).lower().startswith("0x")
                         else int(c))
        except (TypeError, ValueError):
            continue

    if attribution_report is None:
        from .attribution import attribute_codes

        attribution_report = attribute_codes(
            image_path, base, codes, xlen=xlen, compressed=compressed,
            dispatch_report=dispatch_report,
        )
    if dispatch_report is None:
        dispatch_report = None  # attribute_codes 内部已缓存，不必重复

    disasm = linear_disasm(image, base, xlen=xlen, compressed=compressed)
    by_addr = {i.addr: i for i in disasm}

    command_table = attribution_report.get("command_table") or {}
    cmd_entries = command_table.get("entries") or []

    # 码 → 命令表项（用 handler 地址反查；一个 handler 可对应多个码）
    handler_to_entry = {}
    for e in cmd_entries:
        try:
            handler_to_entry[int(e["handler"], 16)] = e
        except (KeyError, TypeError, ValueError):
            continue

    targets: list[dict] = []
    skipped: list[dict] = []
    # 每个 handler 内出现的所有码（供 discriminating_predictions 判断同函数多解）
    codes_by_handler: dict[str, set[int]] = defaultdict(set)
    for attr in attribution_report.get("attributions", []):
        try:
            cv = int(attr.get("code"), 16)
        except (TypeError, ValueError):
            continue
        for s in (attr.get("sites") or []):
            codes_by_handler[str(s.get("handler"))].add(cv)

    for attr in attribution_report.get("attributions", []):
        code_str = attr.get("code")
        sites = attr.get("sites") or []
        if not sites:
            skipped.append({"code": code_str, "reason": "该码未归因到任何分派 handler 内的装载点"})
            continue
        for site in sites:
            try:
                handler_addr = int(site["handler"], 16)
            except (KeyError, TypeError, ValueError):
                handler_addr = 0
            entry = handler_to_entry.get(handler_addr) or {
                "command": None, "handler": site.get("handler"),
            }
            t = _target_from_code_site(
                image=image, base=base, site=site, entry=entry, code_str=code_str,
                observed_codes=observed, max_flips=max_flips,
                xlen=xlen, compressed=compressed,
                max_variants_listed=max_variants_listed,
                sibling_codes=sorted(codes_by_handler.get(str(site.get("handler")), set())),
            )
            if t is None:
                skipped.append({"code": code_str, "reason": "指令机器码取不到（越界）",
                                "site": site.get("insn_addr")})
                continue
            targets.append(t)

    # ---- 第二类：分支靶点（决定"码是否被走到"）----
    branch_targets: list[dict] = []
    if include_branch_targets:
        seen_branch: set[str] = set()
        for t in list(targets):
            for br in _branches_near_code_site(disasm, int(t["addr"], 16)):
                if br["addr"] in seen_branch:
                    continue
                seen_branch.add(br["addr"])
                node = by_addr.get(int(br["addr"], 16))
                branch_targets.append({
                    "target_id": f"tgt-branch-{int(br['addr'], 16):08x}",
                    "kind": "gating_branch",
                    "code": t["code"],
                    "command": t["command"],
                    "command_hex": t["command_hex"],
                    "handler": t["handler"],
                    "addr": br["addr"],
                    "offset": br["offset"],
                    "insn": br["insn"],
                    "insn_bytes_hex": (node.raw_hex if node is not None else "unknown"),
                    "guards_code_load_at": t["addr"],
                    "relation": br["relation"],
                    "suggested_action": {
                        "primary": {
                            "action": "flip_reg_bits",
                            "reg": "unknown",
                            "note": "翻转被比较寄存器可改变该码路径是否被走到（需先确定比较寄存器）",
                        },
                        "alternative": {
                            "action": "skip_insn",
                            "note": "跳过分支 ⇒ 落到 fallthrough，等价于强制走另一条路",
                        },
                    },
                    "expected_observation": {
                        "primary_effect": f"码 {t['code']} 是否上报取决于本分支走向",
                        "observable_change": "该码出现/消失（二值变化，比码迁移更强）",
                        "caveat": "分支方向改变会让整条路径变化，可能连带影响多个码与帧格式",
                    },
                    "confidence": "hypothesis",
                    "evidence_kind": "artifact_derived",
                })

    # ---- 汇总：码间迁移矩阵（全清单级）----
    migration_index: dict[tuple[str, str], dict] = {}
    for t in targets:
        for m in t["bitflip_variants"]["code_migrations"]:
            key = (t["code"], m["resulting_code"])
            cur = migration_index.get(key)
            cand = {
                "from_code": t["code"],
                "to_code": m["resulting_code"],
                "to_code_observed": m["resulting_code_observed_in_experiments"],
                "min_flips": m["min_flips_needed"],
                "at": t["addr"],
                "command": t["command_hex"],
                # 注入动作要用寄存器位；两者都保留便于人工核对
                "reg_value_mask": m["example_reg_value_mask"],
                "reg_value_bits": m["example_reg_value_bits"],
                "machine_code_bits": m["example_machine_code_bits"],
            }
            if cur is None or cand["min_flips"] < cur["min_flips"]:
                migration_index[key] = cand
    migrations = sorted(
        migration_index.values(),
        key=lambda m: (not m["to_code_observed"], m["min_flips"], m["from_code"]),
    )

    high_value = [t for t in targets
                  if any(m["min_flips_needed"] == 1
                         and m["resulting_code_observed_in_experiments"]
                         for m in t["bitflip_variants"]["code_migrations"])]

    by_kind = Counter(t["kind"] for t in targets + branch_targets)
    return {
        "schema": SCHEMA,
        "tool": {"name": "fi.discover.injection_targets", "version": "0.1.0"},
        "image": {
            "path": str(image_path), "sha256": sha256_hex(image),
            "size_bytes": len(image), "base_address": base,
            "base_address_hex": f"0x{base:08x}",
        },
        "method": {
            "pipeline": [
                "码集合 → fi.discover.attribution（码 → 命令 → handler → 装载指令）",
                "装载指令机器码 → fi.fault.effects.enumerate_bitflips（1–3 bit，1→0）",
                "变体反汇编 → 解析'结果码'（仍是立即数装载形态才计入）",
                "结果码 ∈ 实验观测集 → 标记为高价值靶点（码间迁移）",
                "装载点附近的条件分支 → gating_branch 靶点（决定码是否被走到）",
            ],
            "physical_assumption": {
                "flip_mode": "one_to_zero",
                "max_flips": max_flips,
                "note": "crowbar-to-ground 类毛刺常把 1 变 0；EMFI/时钟毛刺效果可能不同。"
                        "这是 hypothesis，不是已证实的物理过程",
            },
            "boundaries": [
                "位翻转枚举是**独立位**假设：真实毛刺可能影响相邻位或跨指令",
                "只对'仍是立即数装载'的变体解析结果码；变成其它指令形态的变体只归类不解析",
                "码装载点由静态归因给出：运行时是否真走到该点仍未知（需仿真轨迹佐证）",
                "观测集（observed_codes）由调用方提供；未提供的码不会标注'观测到'",
                "本清单不含时序：注入时刻（delay）需另由调用链+周期估算确定",
                "全部 hypothesis：候选解释，需仿真复现或实机验证",
            ],
        },
        "inputs": {
            "codes_requested": [
                f"0x{int(c, 16) if isinstance(c, str) and str(c).lower().startswith('0x') else int(c):04x}"
                for c in codes
            ],
            "observed_codes": sorted(f"0x{c:04x}" for c in observed),
            "max_flips": max_flips,
        },
        "command_table": {
            "source_table_addr": command_table.get("source_table_addr"),
            "entry_count": len(cmd_entries),
            "entries": cmd_entries,
        },
        "summary": {
            "n_targets": len(targets),
            "n_branch_targets": len(branch_targets),
            "n_targets_total": len(targets) + len(branch_targets),
            "by_kind": dict(by_kind),
            "n_code_migrations": len(migrations),
            "n_one_bit_migrations": sum(1 for m in migrations if m["min_flips"] == 1),
            "n_one_bit_migrations_to_observed_code": sum(
                1 for m in migrations if m["min_flips"] == 1 and m["to_code_observed"]),
            "n_high_value_targets": len(high_value),
            "high_value_target_ids": [t["target_id"] for t in high_value],
            "skipped_codes": skipped,
            "codes_with_targets": sorted({t["code"] for t in targets}),
        },
        "code_migration_matrix": migrations,
        "targets": targets,
        "branch_targets": branch_targets,
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
        "discipline": (
            "全部靶点 hypothesis；建议动作与预期观测是**静态推演**，"
            "必须经 fi.sim 仿真复现或实机验证后才可升级；"
            "不得把本清单当作已验证的注入效果"
        ),
    }


def write_injection_targets(report: dict, path: str | Path) -> Path:
    """把靶点清单写成 JSON 文件（原子写：先写临时文件再替换）。"""
    import json

    dst = Path(path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    tmp.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(dst)
    return dst
