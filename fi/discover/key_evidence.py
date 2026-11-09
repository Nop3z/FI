# -*- coding: utf-8 -*-
"""fi.discover.key_evidence：从完整靶点清单抽出**核心可展示证据**（浓缩版）。

## 用途

`data/derived/injection-targets.json` 是给闭环用的完整清单（39 靶点、62 条迁移）；
本模块抽出的 `bitflip-key-evidence.json` 是**给人看**的：
只保留"**1 bit 翻转 ⇒ 得到一个在实验中真实观测到的码**"这类最强结论，
每条附完整证据链 + 可证伪预测 + 如何区分多解。

## 为什么这是"最强"

按 hn security 方法论（docs/methodology-fault-effect-reasoning.md），
"don't glitch and pray" 的前提是：先知道**打坏后应该看到什么**。

1-bit 迁移的强度在于：
  - **物理最小**：单 bit 翻转是毛刺的最基本效果，不需要假设多 bit 同时命中；
  - **可证伪**：预测"帧码字段由 A 变 B、帧其余不变"，仿真/实机一跑即知；
  - **跨观测链**：A 与 B 都是实验里真实出现过的码 ⇒ 把两条观测链用单一机制连起来。

## 纪律

- 芯片无关：所有值来自靶点清单参数，代码中无实例字面量
- 全部 hypothesis；观测计数（若提供）为 observation 级，两者分开标注
"""
from __future__ import annotations

from collections import Counter

SCHEMA = "fi.discover.bitflip-key-evidence-v1"


def build_key_evidence(
    injection_report: dict,
    *,
    observation_counts: dict[str, dict] | None = None,
    max_entries: int = 12,
) -> dict:
    """从 injection-targets 报告抽出"1-bit → 已观测码"的核心证据。

    ``observation_counts``：码 → {count, states, ...}（来自实验数据的观测统计）。
    给出时用于标注"源码/目标码在实验中的实际出现次数"，让证据可被人直接核对。
    """
    counts = observation_counts or {}
    entries: list[dict] = []

    for t in injection_report.get("targets", []):
        variants = t.get("bitflip_variants") or {}
        # 只取"1 bit 翻转且结果码被实验观测到"的迁移（最强证据）
        for m in variants.get("code_migrations", []):
            if m.get("min_flips_needed") != 1:
                continue
            if not m.get("resulting_code_observed_in_experiments"):
                continue
            src = t["code"]
            dst = m["resulting_code"]
            src_cnt = counts.get(src) or counts.get(_norm(src))
            dst_cnt = counts.get(dst) or counts.get(_norm(dst))
            entries.append({
                "evidence_id": f"bf-{src.replace('0x', '')}-to-{dst.replace('0x', '')}"
                               f"-at-{t['addr'].replace('0x', '')}",
                "summary": (
                    f"在 {t['addr']}（{t['insn']}）翻转 1 个 bit，"
                    f"错误码 {src} → {dst}；"
                    f"其中 {src} 在实验中观测 "
                    f"{src_cnt['count'] if src_cnt else 'unknown'} 次，"
                    f"{dst} 观测 {dst_cnt['count'] if dst_cnt else 'unknown'} 次"
                ),
                "claim": {
                    "source_code": src,
                    "target_code": dst,
                    "flip_count_required": 1,
                    # 机器码位（"指令里哪一位"）与寄存器值位（"注入时翻哪一位"）不同，
                    # 二者都给出避免误用：I-type 下机器码位 b ↔ 立即数位 b-20。
                    "flipped_machine_code_bits": m["example_machine_code_bits"],
                    "flipped_reg_value_bits": m["example_reg_value_bits"],
                    "bit_mask_on_reg_value": m["example_reg_value_mask"],
                    "mask_applies_to": "post_insn_reg_value",
                    "physically_explains": (
                        "单 bit 1→0 翻转即可把一个实验观测码变成另一个实验观测码；"
                        "无需假设多 bit 同时命中，也不需要路径改变"
                    ),
                },
                "technical_chain": {
                    "command": t.get("command_hex"),
                    "command_dec": t.get("command"),
                    "handler": t.get("handler"),
                    "target_addr": t["addr"],
                    "target_offset_in_image": t.get("offset"),
                    "insn": t["insn"],
                    "insn_bytes_hex": t.get("insn_bytes_hex"),
                    "dest_reg": t.get("dest_reg"),
                    "original_insn_after_flip": m.get("example_mutated_insn"),
                    "instruction_decodable_after_flip": True,
                    "why_decodable": (
                        "翻转发生在 12 位立即数的有效位内，opcode/rd/rs1 均未变，"
                        "因此指令仍被正常译码并执行（对应方法论文章 'Level 1："
                        "指令被打成本质无效但仍执行'）"),
                    "static_evidence": [
                        f"机器码 {t.get('insn_bytes_hex')} 反汇编 = {t['insn']}",
                        f"该地址由 fi.discover.attribution 归因到命令 "
                        f"{t.get('command_hex')} / handler {t.get('handler')}",
                        f"位翻转枚举由 fi.fault.effects.enumerate_bitflips 产出并反汇编核对",
                    ],
                },
                "experimental_context": {
                    "source_code_observations": _obs_summary(src_cnt),
                    "target_code_observations": _obs_summary(dst_cnt),
                    "note": (
                        "两个码都在同一实验数据集内出现 ⇒ 该迁移是可被数据检验的，"
                        "不是纯理论构造"),
                },
                "falsifiable_prediction": {
                    "injection": {
                        "action": "flip_reg_bits",
                        "where": t["addr"],
                        "reg": t.get("dest_reg"),
                        "bit_mask": m["example_reg_value_mask"],
                        "mask_applies_to": "post_insn_reg_value",
                        "note": (
                            f"翻寄存器值的位 {m['example_reg_value_bits']}"
                            f"（= 机器码位 {m['example_machine_code_bits']}；"
                            "I-type 装载指令中机器码位 b 对应立即数位 b-20，"
                            "注入时请用寄存器位掩码，不要用机器码位）"),
                    },
                    "expected": (
                        f"响应帧中码字段由 {src} 变为 {dst}；"
                        "帧 magic 与长度字段与基线逐字节一致"),
                    "verification_rule": {
                        "supports_hypothesis_if": [
                            f"观测到 {dst} 且帧结构（magic/长度）与基线相同",
                            f"PC 轨迹仍经过 {t['addr']}",
                        ],
                        "refutes_hypothesis_if": [
                            "帧 magic/长度也发生变化（更可能打中了发送函数）",
                            f"码既非 {src} 也非 {dst}（更可能打中了其它装载点或分支）",
                            "trap 被触发（该翻转若落在非法编码区会变成非法指令）",
                        ],
                    },
                    "negative_control": {
                        "action": "skip_insn",
                        "expected_if_not_hit": (
                            f"未命中时 {src} 正常上报，与基线一致；"
                            f"若连 {src} 都未出现，说明该命令路径本次未被走到"),
                    },
                },
                "confidence": "hypothesis",
                "evidence_kind": "artifact_derived",
                "observation_level_of_counts": (
                    "observation" if (src_cnt or dst_cnt) else "unknown"),
            })

    # 按"源码观测次数多的在前"排序（越常见越重要），再按目标码是否常见
    def _sort_key(e: dict) -> tuple:
        src_n = (counts.get(e["claim"]["source_code"]) or {}).get("count", 0)
        dst_n = (counts.get(e["claim"]["target_code"]) or {}).get("count", 0)
        return (-src_n, -dst_n, e["evidence_id"])

    entries.sort(key=_sort_key)
    entries = entries[:max_entries]

    # 去重（同一 src→dst 可能有多个装载点）：保留全部（它们是不同物理落点，都有价值），
    # 但额外给一个"按码对聚合"的索引，便于人先看结论再看落点。
    by_pair: dict[tuple[str, str], list[str]] = {}
    for e in entries:
        key = (e["claim"]["source_code"], e["claim"]["target_code"])
        by_pair.setdefault(key, []).append(e["evidence_id"])

    pairs = []
    for (src, dst), ids in sorted(
            by_pair.items(),
            key=lambda kv: -(counts.get(kv[0][0]) or {}).get("count", 0)):
        pairs.append({
            "source_code": src,
            "target_code": dst,
            "n_sites": len(ids),
            "sites": ids,
            "source_observed": _obs_summary(counts.get(src)),
            "target_observed": _obs_summary(counts.get(dst)),
        })

    return {
        "schema": SCHEMA,
        "tool": {"name": "fi.discover.key_evidence", "version": "0.1.0"},
        "title": "核心证据：单 bit 翻转即可把实验观测码 A 变成实验观测码 B",
        "image": injection_report.get("image"),
        "one_sentence": (
            "在下列地址各翻转 1 个 bit，错误码就从 A 变成 B；A 与 B 都是实验中真实"
            "出现过的码 —— 这是目前对『故障如何改变观测』最强、最可证伪的机制解释之一"
        ),
        "counts": {
            "n_entries": len(entries),
            "n_distinct_code_pairs": len(by_pair),
        },
        "code_pair_index": pairs,
        "entries": entries,
        "how_to_read": [
            "claim：这一条到底断言了什么（源码、目标码、翻转几位、翻哪一位）",
            "technical_chain：静态证据链（命令 → handler → 装载指令 → 机器码）",
            "experimental_context：两个码在实验数据里各出现过多少次（观测级）",
            "falsifiable_prediction：怎么注入、应该看到什么、什么情况算被推翻",
            "confidence=hypothesis：这是候选解释，尚未经仿真复现或实机验证",
        ],
        "discipline": (
            "全部 hypothesis 级；观测计数为 observation 级，两者严格分开。"
            "本文件不构成已验证结论，须经 fi.sim 仿真复现或实机实验后方可升级"
        ),
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


def _norm(code: str) -> str:
    """统一码的渲染形式 0x0abc（小写、4 位）。"""
    try:
        return f"0x{int(code, 16):04x}"
    except (TypeError, ValueError):
        return code


def _obs_summary(item: dict | None) -> dict:
    if not item:
        return {"observed": False, "count": 0, "note": "该码未出现在提供的观测统计中"}
    return {
        "observed": True,
        "count": item.get("count"),
        "rate": item.get("rate"),
        "states": item.get("states"),
        "delay_raw_range": [item.get("delay_raw_min"), item.get("delay_raw_max")]
        if item.get("delay_raw_min") is not None else None,
    }
