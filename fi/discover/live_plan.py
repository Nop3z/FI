# -*- coding: utf-8 -*-
"""fi.discover.live_plan：把静态靶点 + 位翻转证据转成**实机可执行的注入方案**。

## 为什么需要单独一层（而不是直接把 JSON 交给实机）

实机（PowerShorter）**只能控制"何时打、打多宽"，不能指定翻转哪一位**。
所以"静态上存在 1-bit 码迁移"≠"实机能验证它"。必须显式区分：

  - **live_verifiable**：实机能验证（靠时间窗口 + 观测率变化）；
  - **sim_only**：只能仿真验证（需要精确位翻转，实机做不到）。

判据（本模块的核心逻辑，全部可计算、不靠主观）：

1. **悬空条件（dangling）**：若"源码"在历史实验中从未出现（背景率 ≈ 0），
   则"它被翻转成目标码"这件事在实机上**不可观测**——你必须先能让源码出现，
   否则没有可被翻转的对象。→ sim_only。

2. **信号淹没（swamped）**：若转换产生的事件数（源码背景率 × 采样量）
   远小于目标码自身的统计涨落（3σ 噪声底），则"目标码上升"不可检测。
   例：把 ~1 个事件/点 的码转成一个 ~44 事件/点 的码，信号完全淹没。→ sim_only
   （但**反向可检测**：目标码的**下降**、或源码的**消失**仍可能有信号，见 3）。

3. **消失可检测（disappearance）**：源码本身有可观测背景率时，
   "源码计数降到 0"是强信号（泊松下尾），几个采样点即可判定。→ live_verifiable
   （判据形态为"源码消失"，不是"目标码上升"）。

每个 live 方案给出：
  - 目标靶点的**时间窗口**（由调用链 + 周期估算给出，缺失时显式 unknown 并说明如何补）；
  - delay/pulse 扫描网格（PowerShorter 单位 = 10 ns，原样使用 raw 单位）；
  - **期望观测**与**判据**（含接受/拒绝阈值、样本量需求）；
  - 基线对照方案（pulse=0 / 不打 / 打偏窗口）。

## 纪律

- 全部 confidence=hypothesis；实机尚未运行，方案是**计划**不是结果
- 明确标 `feasibility` 与 `feasibility_reason`，不得把 sim_only 的靶点包装成"实机可验证"
- 缺失信息（时间窗口、主频）一律显式 `unknown`，不猜
"""
from __future__ import annotations

import math

SCHEMA = "fi.discover.live-injection-plan-v1"

#: 设备单位（来自 power_shorter.engine_cfg docstring：duration 单位为 10 ns）
DURATION_UNIT_NS = 10

#: 统计判据的显著性水平（双侧/单侧近似用 3σ）
SIGMA = 3.0

#: 默认每点采样量（历史 CSV 每 delay 点约 1.2 万行）
DEFAULT_SAMPLES_PER_POINT = 12100


def _poisson_zero_threshold(lam: float, alpha: float = 0.05) -> int | None:
    """在背景率 lam 下，需要多少个采样单元"连续为 0"才能以 alpha 拒绝背景。

    P(0 events | lam) = exp(-lam) → 连续 k 个单元全 0 的概率 exp(-lam*k)。
    """
    if lam <= 0:
        return None
    k = 1
    while k <= 10_000:
        if math.exp(-lam * k) < alpha:
            return k
        k += 1
    return None


def _detect_rise_threshold(lam_target: float) -> float:
    """检测目标码"上升"所需的额外事件数（3σ 近似，泊松→正态）。"""
    return SIGMA * math.sqrt(max(lam_target, 0.25))


def classify_feasibility(
    *,
    source_count: int,
    target_count: int,
    samples_per_point: int,
    has_timing_window: bool,
) -> dict:
    """判定某条码迁移"实机可验证 / 只能仿真"，并给出理由与可用的判据形态。

    返回 {feasibility, reason, detectable_signal, required_samples, ...}
    """
    total = max(1, samples_per_point)
    lam_src = source_count / max(1, 1) / 61.0 if source_count else 0.0
    # 用"每 delay 点"的背景率：历史数据共 61 个 delay 点
    lam_src = source_count / 61.0
    lam_dst = target_count / 61.0

    if source_count == 0:
        return {
            "feasibility": "sim_only",
            "reason": (
                "悬空条件：源码在历史实验中从未出现（背景率 0），"
                "实机上没有'可被翻转的对象'——必须先让源码出现才谈得上翻转它。"
                "实机无法验证；需仿真注入（reg_write 制造源码 / flip_reg_bits 翻转）"
            ),
            "blocking_factor": "source_code_never_observed",
        }
    if not has_timing_window:
        # 时间窗口缺失仍可做"广扫"，但效率低、且无法定向
        pass

    rise_threshold = _detect_rise_threshold(lam_dst)
    max_possible_rise = lam_src          # 100% 转换时的最大额外事件数
    rise_detectable = max_possible_rise >= rise_threshold

    # 消失判据：源码计数降到 0
    k_zero = _poisson_zero_threshold(lam_src)
    drop_detectable = k_zero is not None and k_zero <= 10

    if rise_detectable:
        return {
            "feasibility": "live_verifiable",
            "reason": (
                f"目标码背景率低（≈{lam_dst:.2f} 事件/点），"
                f"而源码可提供最多 ≈{lam_src:.2f} 事件/点的转换信号，"
                f"超过 3σ 检测底({rise_threshold:.2f})——'目标码上升'可检测"
            ),
            "primary_test": "target_code_rise",
            "detectable_signal": {
                "max_extra_events_per_point": round(max_possible_rise, 3),
                "detection_floor_3sigma": round(rise_threshold, 3),
                "margin_ratio": round(max_possible_rise / rise_threshold, 2)
                if rise_threshold > 0 else None,
            },
            "drop_test": {
                "applicable": drop_detectable,
                "consecutive_zero_points_required": k_zero,
                "note": "同时可用'源码计数归零'作为独立佐证（更强）",
            } if drop_detectable else {"applicable": False},
        }

    if drop_detectable:
        return {
            "feasibility": "live_verifiable",
            "reason": (
                f"目标码上升被淹没：源码最多提供 ≈{lam_src:.2f} 事件/点，"
                f"而目标码自身涨落需 ≥{rise_threshold:.2f} 才可分辨。"
                f"但'源码计数归零'可检测：连续 {k_zero} 个采样点全 0 即可以 "
                f"95% 置信拒绝背景（P(0|λ)^k = exp(-{lam_src:.2f}×{k_zero})）"
            ),
            "primary_test": "source_code_disappearance",
            "detectable_signal": {
                "source_lambda_per_point": round(lam_src, 3),
                "consecutive_zero_points_required": k_zero,
                "total_samples_needed": k_zero * total,
            },
            "rise_test": {
                "applicable": False,
                "note": (
                    f"目标码上升不可检测（需 ≥{rise_threshold:.2f} 事件/点，"
                    f"最多只有 {max_possible_rise:.2f}）——不要用上升率作为判据"
                ),
            },
        }

    return {
        "feasibility": "sim_only",
        "reason": (
            f"信号太弱：源码背景率 ≈{lam_src:.2f} 事件/点、目标码 ≈{lam_dst:.2f}，"
            f"既不足以检测上升（需 ≥{rise_threshold:.2f}），"
            f"也不足以检测消失（需连续 {k_zero} 点全 0，超出可承受采样量）"
        ),
        "blocking_factor": "signal_below_noise_floor",
        "detectable_signal": {
            "source_lambda_per_point": round(lam_src, 3),
            "target_lambda_per_point": round(lam_dst, 3),
            "rise_floor_3sigma": round(rise_threshold, 3),
        },
    }


def build_live_plan(
    key_evidence: dict,
    *,
    observation_counts: dict[str, dict] | None = None,
    total_rows: int | None = None,
    n_delay_points: int = 61,
    samples_per_point: int = DEFAULT_SAMPLES_PER_POINT,
    timing_windows: dict[str, dict] | None = None,
    max_pulse_raw: int = 100,
) -> dict:
    """把核心证据转成实机注入方案。

    ``timing_windows``：靶点地址 → {delay_raw_range: [lo, hi], source: "..."}。
    缺失时方案仍产出，但 `timing` 段显式 unknown 并给出补充方法。
    """
    counts = observation_counts or {}
    timing = timing_windows or {}
    total = total_rows or sum(v.get("count", 0) for v in counts.values())

    # ---- 按码对聚合（同一码对的多个站点合并成一个实验方案） ----
    pairs: dict[tuple[str, str], list[dict]] = {}
    for e in key_evidence.get("entries", []):
        c = e["claim"]
        pairs.setdefault((c["source_code"], c["target_code"]), []).append(e)

    plans: list[dict] = []
    for (src, dst), entries in sorted(pairs.items()):
        src_cnt = (counts.get(src) or {}).get("count", 0)
        dst_cnt = (counts.get(dst) or {}).get("count", 0)
        has_timing = any(e["technical_chain"]["target_addr"] in timing for e in entries)
        feas = classify_feasibility(
            source_count=src_cnt, target_count=dst_cnt,
            samples_per_point=samples_per_point, has_timing_window=has_timing,
        )

        sites = []
        for e in entries:
            ch = e["technical_chain"]
            addr = ch["target_addr"]
            tw = timing.get(addr)
            sites.append({
                "target_id": e["evidence_id"],
                "addr": addr,
                "command": ch.get("command"),
                "insn": ch.get("insn"),
                "dest_reg": ch.get("dest_reg"),
                "flip_for_simulation": {
                    "action": "flip_reg_bits",
                    "reg": ch.get("dest_reg"),
                    "bit_mask": e["claim"]["bit_mask_on_reg_value"],
                    "mask_applies_to": "post_insn_reg_value",
                    "note": "仿真用；实机无法指定翻转位",
                },
                "timing_window": tw or {
                    "delay_raw_range": None,
                    "source": "unknown",
                    "note": ("未提供该靶点的时间窗口。补法：fi discover chain 定调用链 → "
                             "fi.sim timing 估周期 → 主频反推折算 delay；"
                             "或先用宽网格扫描定位"),
                },
            })

        # ---- 判据（区分"上升"与"消失"两种可检测形态） ----
        if feas.get("primary_test") == "target_code_rise":
            criteria = {
                "primary": {
                    "observable": f"错误码 {dst} 的出现率上升（{src} 下降，转移而非新增）",
                    "accept_if": (
                        f"在靶点窗口内出现 {dst}，且出现率相对基线提升超过 "
                        f"{feas['detectable_signal']['detection_floor_3sigma']} 事件/点"),
                    "reject_if": (
                        f"窗口内 {dst} 计数与基线无显著差异，或 {src} 计数未下降"
                        "（说明未命中该装载指令）"),
                },
                "transfer_check": (
                    f"强判据：{src} 的计数下降量 ≈ {dst} 的上升量（同一批事件被改码，"
                    "不是新增路径）。若二者不互补，可能是打中了别的指令"),
            }
        elif feas.get("primary_test") == "source_code_disappearance":
            k = feas["detectable_signal"]["consecutive_zero_points_required"]
            criteria = {
                "primary": {
                    "observable": f"错误码 {src} 在该窗口内**消失**（计数归零）",
                    "accept_if": (
                        f"连续 {k} 个采样点（共 ≥{k * samples_per_point} 次注入）"
                        f"均未观测到 {src}；此时拒绝背景假设的显著性 < 5%"),
                    "reject_if": (
                        f"{src} 仍以与基线相当的频率出现（说明未命中，或翻转后码值未变）"),
                },
                "secondary": {
                    "observable": f"{dst} 是否上升",
                    "verdict": (
                        "**不作为判据**——上升被统计噪声淹没（见 feasibility 说明）。"
                        f"若观测到 {dst} 上升，只作旁证；观测不到不能否定假设"),
                },
            }
        else:
            criteria = {
                "primary": {
                    "observable": "无实机可检测信号",
                    "verdict": (
                        f"本码对**只能仿真验证**：{feas['reason']}。"
                        "实机上可用作探索性扫描，但无法据此判定假设成立/不成立"),
                },
            }

        # ---- delay/pulse 扫描网格 ----
        win = next((s["timing_window"]["delay_raw_range"] for s in sites
                    if s["timing_window"]["delay_raw_range"]), None)
        if win:
            lo, hi = win
            grid = {"delay_raw": list(range(int(lo), int(hi) + 1)),
                    "note": "窄扫：窗口来自调用链+周期估算"}
        else:
            grid = {
                "delay_raw": {"mode": "wide_sweep",
                              "suggested_range": [3130, 3190],
                              "note": ("宽扫：窗口 unknown。范围取历史实验已覆盖的 delay 区间"
                                       "（该区间应据实机复跑确认）；每点建议 ≥"
                                       f"{samples_per_point} 次注入以获得统计功效")},
            }

        plans.append({
            "plan_id": f"live-{src}-to-{dst}".replace("0x", ""),
            "code_pair": {"source": src, "target": dst},
            "feasibility": feas["feasibility"],
            "feasibility_reason": feas["reason"],
            "blocking_factor": feas.get("blocking_factor"),
            "detectable_signal": feas.get("detectable_signal"),
            "rise_test": feas.get("rise_test"),
            "drop_test": feas.get("drop_test"),
            "background_rates": {
                "source": {"count": src_cnt,
                           "lambda_per_delay_point": round(src_cnt / n_delay_points, 3),
                           "states": (counts.get(src) or {}).get("states")},
                "target": {"count": dst_cnt,
                           "lambda_per_delay_point": round(dst_cnt / n_delay_points, 3),
                           "states": (counts.get(dst) or {}).get("states")},
                "note": ("背景率来自历史 CSV 观测（observation 级）；"
                         "实机需先复跑基线确认这些率是否可重现"),
            },
            "sites": sites,
            "sweep_plan": {
                "device": "PowerShorter",
                "unit": {"duration_raw": "10 ns（设备 docstring 事实）",
                         "delay_raw_to_ns": f"×{DURATION_UNIT_NS}",
                         "pulse_raw_to_ns": f"×{DURATION_UNIT_NS}"},
                "pattern_semantics": (
                    "pattern = [(level=1, delay_raw), (level=0, pulse_raw), (level=1, 1)]："
                    "触发后先保持供电 delay_raw×10ns，再断电 pulse_raw×10ns（毛刺），再恢复"),
                "grid": grid,
                "pulse_raw": {
                    "default": 2,
                    "note": ("历史实验 740,207/740,209 行用 pulse=2（=20 ns）。"
                             "先从 2 开始；若 20 ns 打不出效果，再试 4/6/8"
                             "（pulse=6 在历史中仅 2 行，说明该宽度基本未探索）"),
                    "safety_cap": max_pulse_raw,
                },
                "samples_per_point": samples_per_point,
                "randomization": (
                    "建议 delay 点随机化顺序（非单调扫描），以抵消数据侧已观测到的"
                    "行序漂移（历史 CSV 的 FL 率随运行单调下降 ~10pp）——"
                    "否则时间漂移会被误读为 delay 效应"),
            },
            "acceptance_criteria": criteria,
            "baseline_control": {
                "why": "必须能区分'毛刺效应'与'运行漂移/环境变化'",
                "runs": [
                    {"name": "no_glitch", "delay_raw": None, "pulse_raw": 0,
                     "note": "不打毛刺（pulse=0），完整跑同样样本量 → 得到本机基线率"},
                    {"name": "glitch_off_window", "delay_raw": "窗外的随机点",
                     "pulse_raw": 2,
                     "note": "打毛刺但打偏时间窗 → 应与 no_glitch 无显著差异"},
                    {"name": "glitch_off_cmd", "delay_raw": "窗口内",
                     "pulse_raw": 2,
                     "note": ("若能让目标命令不执行（如发其它命令），"
                              "则窗口内打毛刺也不应产生码迁移 → 排除'毛刺导致全局行为变化'")},
                ],
                "expected_if_no_effect": (
                    f"{src} 与 {dst} 的计数与 no_glitch 基线在统计上无差异"),
                "drift_guard": (
                    "在整轮扫描开始与结束各插一次 no_glitch 基线（各占 5% 样本），"
                    "若首尾基线本身有显著漂移，则本轮数据不可用于判据（需重跑）"),
            },
            "confidence": "hypothesis",
            "evidence_kind": "artifact_derived",
            "status": "planned_not_executed",
        })

    live = [p for p in plans if p["feasibility"] == "live_verifiable"]
    sim_only = [p for p in plans if p["feasibility"] != "live_verifiable"]

    return {
        "schema": SCHEMA,
        "tool": {"name": "fi.discover.live_plan", "version": "0.1.0"},
        "title": "实机注入方案（PowerShorter）：把静态码迁移转成可执行实验",
        "inputs": {
            "n_delay_points": n_delay_points,
            "samples_per_point": samples_per_point,
            "total_rows_reference": total,
            "observation_counts_provided": bool(counts),
            "timing_windows_provided": bool(timing),
            "device_unit_ns": DURATION_UNIT_NS,
        },
        "summary": {
            "n_code_pairs": len(plans),
            "n_live_verifiable": len(live),
            "n_sim_only": len(sim_only),
            "live_plan_ids": [p["plan_id"] for p in live],
            "sim_only_plan_ids": [p["plan_id"] for p in sim_only],
            "headline": (
                f"{len(live)}/{len(plans)} 条码对实机可验证，"
                f"{len(sim_only)}/{len(plans)} 只能仿真验证"),
        },
        "key_finding": {
            "statement": (
                "**实机（PowerShorter）不能指定翻转哪一位**——它只控制'何时打、打多宽'。"
                "因此'静态上存在 1-bit 码迁移'不等于'实机可验证'。"
                "判据必须按背景率与统计功效设计：有的码对只能验证'源码消失'，"
                "有的连消失都测不到，只能仿真"),
            "implication": (
                "实机实验应以'**源码消失**'为主要判据，而非'目标码上升'——"
                "因为目标码的历史背景率普遍高于可转移的事件数（见各 plan 的 feasibility_reason）"),
        },
        "plans": plans,
        "discipline": (
            "全部 hypothesis；实机尚未运行（status=planned_not_executed）。"
            "判据中的阈值基于历史 CSV 的背景率，实机复跑基线后应据实测重算。"
            "不得把 sim_only 的方案当作实机可验证"),
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
