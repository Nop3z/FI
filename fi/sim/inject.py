"""仿真故障注入钩子（M3 闭环的离线注入器接口 v0，与 sim-trace 契约对齐）。

动作语义（契约引擎动作 skip / flip_reg_bits；reg_write / mem_write 为扩展预留）：
- skip           命中时跳过该条指令（仿真器从 next_pc 重启）
- flip_reg_bits  命中时位翻转寄存器：new = old XOR bit_mask（或直接 new_value），
                 引擎把 old/new_value 回填进 fault_event.action
- reg_write      命中时在该条指令执行前写通用寄存器
- mem_write      命中时在该条指令执行前写内存

## 动作时机（when，重要）

`before`（默认）：动作在目标指令**执行前**生效。`skip` 恒为此语义。
`after`：动作在目标指令**执行完毕、下一条指令执行前**生效。

**为什么必须有 after**：把"码装载指令的结果改成另一个码"这类注入（
`addi a0, zero, 0x504` → 期望 a0 变 0x104）在 `before` 下完全无效——
装载指令会把 a0 覆盖回 0x504。正确做法是在它写完之后翻 bit。
`fi.fault` 产出的 injection-targets 全部按此语义设计（bit_mask 针对装载后的寄存器值），
所以靶点接入时必须用 `when=after`。

## 触发定位

trigger.mode：pc | seq | cycle_estimate | every。
- pc / seq / every 都是确定性定位（地址 / 指令序号 / 每 N 条）；
- cycle_estimate 按 fi.sim.timing 的**估算累计周期**解释：累计周期首次跨过目标
  值时触发（"在估算时刻 T 注入"）。timing 未启用时不命中，并由 run_end 显式报告
  unapplied 原因——绝不静默退化成按指令序号。
times=0 不限次。每次触发都由 machine 层写 fault_event 行进事实日志。
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import InjectSpec, _parse_inject


class InjectionEngine:
    def __init__(self, specs: list[InjectSpec]):
        self.specs = specs
        self.fired: list[int] = [0] * len(specs)  # 每条 spec 已触发次数
        #: cycle_estimate 触发：记录"是否已跨过该周期点"（首次达到即触发，只触发一次）
        self._cycle_passed: list[bool] = [False] * len(specs)
        #: 待在下一条指令执行前应用的 after 动作（必须等目标指令执行完才能拿到新寄存器值）
        self._pending_after: list[int] = []

    # ---- after 时机 ----

    def schedule_pending(self, idx: int) -> None:
        """登记一个"等目标指令执行完再应用"的动作。"""
        if idx not in self._pending_after:
            self._pending_after.append(idx)

    @property
    def has_pending_after(self) -> bool:
        """是否有等待应用的 after 动作（machine 每条指令前检查，需 O(1)）。"""
        return bool(self._pending_after)

    def take_pending_after(self) -> list[int]:
        """取出并清空待应用的 after 动作列表。"""
        out = self._pending_after
        self._pending_after = []
        return out

    def fire_after(self, idx: int, sim) -> dict:
        """执行 after 时机动作（此时目标指令已执行完，寄存器已是写回后的新值）。"""
        return self.fire(idx, sim, pc=0, size=0)

    def match(self, pc: int, seq: int, cycle: float | None = None) -> list[int]:
        """返回本次命中的 spec 索引列表。

        cycle_estimate 语义（真正按估算周期，不是按指令序号）：
        - 需要 timing 模型提供的累计周期 `cycle`；
        - 当累计周期**首次跨过** spec.cycle_estimate 时触发（即该指令的执行时刻
          已到达/越过目标周期）—— 语义为"在估算时刻 T 注入"；
        - 同一 spec 最多触发一次（除非 times>1，此时跨过后按 times 记录次数上限）；
        - timing 未启用（cycle=None）时不匹配，并在 run_end 报告里说明原因。
        """
        hits: list[int] = []
        for idx, spec in enumerate(self.specs):
            if spec.times and self.fired[idx] >= spec.times:
                continue
            hit = False
            if spec.pc is not None and spec.pc == pc:
                hit = True
            if spec.seq is not None and spec.seq == seq:
                hit = True
            if spec.cycle_estimate is not None:
                if cycle is None:
                    # 无周期模型：不静默退化，也不命中（run_end 会报 unapplied 原因）
                    continue
                if not self._cycle_passed[idx] and cycle >= spec.cycle_estimate:
                    self._cycle_passed[idx] = True
                    hit = True
            if spec.every and spec.every > 0 and seq > 0 and seq % spec.every == 0:
                hit = True
            if hit:
                hits.append(idx)
        return hits

    def unmatched_cycle_specs(self, *, timing_enabled: bool = True) -> list[dict]:
        """未生效的 cycle_estimate 触发（显式报告原因，不静默跳过）。"""
        out = []
        for idx, spec in enumerate(self.specs):
            if spec.cycle_estimate is not None and not self._cycle_passed[idx]:
                out.append(
                    {
                        "spec_index": idx,
                        "cycle_estimate": spec.cycle_estimate,
                        "reason": (
                            "timing 模型未启用（timing.enabled=false）：周期触发不生效，未静默退化为指令序号"
                            if not timing_enabled
                            else "运行在达到该估算周期之前已结束（目标周期晚于本次停机时刻）"
                        ),
                    }
                )
        return out

    def fire(self, idx: int, sim, pc: int, size: int) -> dict:
        """执行动作；返回动作应用详情（action 渲染 + applied_result 素材）。"""
        spec = self.specs[idx]
        self.fired[idx] += 1
        if spec.type == "skip":
            return {"kind": "skip", "applied": True, "next_pc": pc + size}
        if spec.type == "flip_reg_bits":
            reg_id = sim.reg_id(spec.reg)
            if reg_id is None:
                return {"kind": "flip_reg_bits", "applied": False, "error": f"未知寄存器 {spec.reg!r}"}
            width = spec.bit_width if spec.bit_width > 0 else 32
            mask = spec.bit_mask & ((1 << width) - 1)
            old = sim.uc.reg_read(reg_id)
            new = (spec.new_value if spec.new_value is not None else old ^ mask) & ((1 << width) - 1)
            sim.uc.reg_write(reg_id, new)
            return {
                "kind": "flip_reg_bits",
                "applied": True,
                "reg": spec.reg,
                "bit_width": width,
                "bit_mask": mask,
                "old_value": old,
                "new_value": new,
            }
        if spec.type == "reg_write":
            reg_id = sim.reg_id(spec.reg)
            if reg_id is None:
                return {"kind": "reg_write", "applied": False, "error": f"未知寄存器 {spec.reg!r}"}
            if spec.value is None:
                return {"kind": "reg_write", "applied": False, "error": "缺少 value"}
            sim.uc.reg_write(reg_id, spec.value & 0xFFFFFFFF)
            return {"kind": "reg_write", "applied": True, "reg": spec.reg, "value": spec.value & 0xFFFFFFFF}
        if spec.type == "mem_write":
            if spec.addr is None or not spec.data_hex:
                return {"kind": "mem_write", "applied": False, "error": "缺少 addr/data_hex"}
            data = bytes.fromhex(spec.data_hex)
            sim.uc.mem_write(spec.addr, data)
            return {"kind": "mem_write", "applied": True, "addr": spec.addr, "bytes_hex": spec.data_hex}
        return {"kind": spec.type, "applied": False, "error": "未知注入类型"}


# ---- 契约渲染（trigger / action；fault_event 行与 run_meta 预注册共用） ----

def render_trigger(spec: InjectSpec) -> dict:
    if spec.pc is not None:
        return {"mode": "pc", "value": spec.pc}
    if spec.seq is not None:
        return {"mode": "seq", "value": spec.seq}
    if spec.cycle_estimate is not None:
        return {"mode": "cycle_estimate", "value": spec.cycle_estimate}
    if spec.every:
        return {"mode": "every", "value": spec.every}
    return {"mode": "unknown", "value": "unknown"}


def render_action(spec: InjectSpec, detail: dict | None = None) -> dict:
    """契约 fault_event.action 渲染（各变体 additionalProperties=false，严格对齐 schema）。"""
    detail = detail or {}
    kind = spec.type
    if kind == "skip":
        return {"kind": "skip"}
    if kind == "flip_reg_bits":
        return {
            "kind": "flip_reg_bits",
            "reg": spec.reg or "unknown",
            "bit_width": spec.bit_width,
            "bit_mask": f"0x{spec.bit_mask:x}" if spec.bit_mask else "unknown",
            "new_value": detail.get("new_value", "unknown"),
        }
    if kind == "reg_write":
        return {"kind": "reg_write", "reg": spec.reg or "unknown", "value": detail.get("value", "unknown")}
    if kind == "mem_write":
        try:
            size = len(bytes.fromhex(spec.data_hex)) if spec.data_hex else "unknown"
            value = int(spec.data_hex, 16) if spec.data_hex else "unknown"
        except ValueError:
            size, value = "unknown", "unknown"
        return {
            "kind": "mem_write",
            "addr": spec.addr if spec.addr is not None else "unknown",
            "size": size,
            "value": value,
        }
    return {"kind": kind}


def render_applied_result(
    spec: InjectSpec,
    detail: dict,
    seq: int,
    *,
    cycle: float | None = None,
    timing=None,
    at_pc: int | None = None,
    when: str | None = None,
) -> dict | str:
    """契约 fault_event.applied_result（自由对象）：生效细节回填。

    除契约原有内容外，本实现额外回填（均为自由对象内的新增键，不破坏契约）：
    - cycle_estimate 触发的时序：trigger_cycle_target / applied_at_cycle_estimate /
      applied_at_ns_estimate（估算值，hypothesis 级）；
    - 动作时机：when（before|after）与 applied_at_pc（注入归属的目标指令地址）——
      after 语义下这是"哪条指令的结果被改了"的唯一凭证，必须记录。
    """
    if not detail.get("applied"):
        result = {"error": detail.get("error", "unknown")}
    elif spec.type == "skip":
        result = {"skipped_at_seq": seq, "next_pc": detail.get("next_pc", "unknown")}
    elif spec.type == "flip_reg_bits":
        result = {"old_value": detail.get("old_value", "unknown"), "new_value": detail.get("new_value", "unknown")}
    else:
        result = {"applied": True}
    if spec.cycle_estimate is not None:
        result["trigger_cycle_target"] = spec.cycle_estimate
        if cycle is not None:
            result["applied_at_cycle_estimate"] = round(float(cycle), 3)
            if timing is not None:
                result["applied_at_ns_estimate"] = _round_or_unknown(timing.cycles_to_ns(cycle))
            result["note_timing"] = "周期/时间为 fi.sim.timing 估算值（hypothesis），非实测"
    # 动作时机（before/after）与归属指令：after 语义必须留痕，否则无法解释"改的是哪条指令的结果"
    result["when"] = when or spec.when
    if at_pc is not None:
        result["applied_at_pc"] = at_pc
    if spec.note:
        result["note"] = spec.note
    return result


def _round_or_unknown(value):
    return value if isinstance(value, str) else round(float(value), 3)


def render_preregistered(spec: InjectSpec, run_id: str, seq_index: int) -> dict:
    """run_meta.fault_events 预注册清单元素（形状=fault_event 行，applied=unknown）。

    spec.note 不进预注册行（契约行无 note 字段）；它保留在 run_meta.memory_map.config_raw。"""
    return {
        "type": "fault_event",
        "event_id": f"{run_id}-f{seq_index + 1:03d}",
        "run_id": run_id,
        "campaign_id": spec.campaign_id or "unknown",
        "trigger": render_trigger(spec),
        "action": render_action(spec),
        "pulse": "unknown",
        "applied": "unknown",
        "applied_at_seq": "unknown",
        "evidence_level": "unknown",
    }


def load_inject_file(path: str) -> list[InjectSpec]:
    """从 JSON 文件读注入清单：接受列表或 {"injects": [...]}。"""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw["injects"] if isinstance(raw, dict) and "injects" in raw else raw
    return [_parse_inject(item) for item in items]
