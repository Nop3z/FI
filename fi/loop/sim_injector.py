"""离线注入器 #2：SimFaultInjector —— 参数窗口到仿真故障事件的映射注入。

对接 fi.sim.SimBackend（实现归 sim-engine 专职）。本模块只做三件事：
1. delay_ns/pulse_ns → FaultEventSpec（触发位置/作用宽度/动作）的显式映射；
2. 驱动仿真 backend：reset → apply_fault → run；
3. 把仿真产出包装成 InjectionOutcome（evidence=hypothesis，仿真=重建推断）。

映射关系（详见 docs/contracts/param-mapping.md，契约文档为准）：
- trigger（delay_ns → 何时打，引擎 trigger.mode 枚举 {pc, seq, cycle_estimate, every}）：
    seq             : 触发值 = int(delay_ns)，即"第 N 条指令前触发"（默认，
                      确定性 1:1 声明映射）
    cycle_estimate  : 触发值 = int(delay_ns / ns_per_cycle)，依赖
                      ns_per_cycle 假设，证据等级降为 hypothesis
- width（pulse_ns → 打多宽）：
    instruction_count : 受影响指令条数 = int(pulse_ns)（默认）
    single_event      : 单事件，pulse 忽略
- action（映射目标动作，引擎实现 {skip, flip_reg_bits}；reg_write/mem_write
  为扩展预留）：
    skip             / flip_reg_bits（位宽取 int(pulse_ns)）/
    reg_write / mem_write（探索模式预留）
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from fi import UNKNOWN
from fi.loop.injector import Injector
from fi.loop.types import InjectionOutcome, ParamPoint
from fi.sim.protocol import SimBackend

TRIGGER_MODES = ("seq", "cycle_estimate")
WIDTH_MODES = ("instruction_count", "single_event")
ACTION_KINDS = ("skip", "flip_reg_bits", "reg_write", "mem_write")


@dataclass(frozen=True)
class ParamMappingSpec:
    """delay_ns/pulse_ns → 仿真事件的显式映射配置。

    全部字段显式传入，禁止模块级默认值携带任何数据集假设；
    本 dataclass 的默认值只是"行为模式名"，不是数值假设。
    """

    trigger_mode: str = "instruction_index"
    width_mode: str = "instruction_count"
    action_kind: str = "skip"
    flip_target_reg: str = "a0"        # flip_reg_bits 的目标寄存器
    ns_per_cycle: float | None = None  # cycle_estimate 模式必需
    profile_ref: str = UNKNOWN         # 归因引用的 ChipProfile ID

    def __post_init__(self) -> None:
        if self.trigger_mode not in TRIGGER_MODES:
            raise ValueError(f"trigger_mode 必须是 {TRIGGER_MODES} 之一")
        if self.width_mode not in WIDTH_MODES:
            raise ValueError(f"width_mode 必须是 {WIDTH_MODES} 之一")
        if self.trigger_mode == "cycle_estimate" and not self.ns_per_cycle:
            raise ValueError("cycle_estimate 模式必须显式提供 ns_per_cycle")

    def map_trigger(self, delay_ns: float) -> dict[str, Any]:
        """delay_ns → trigger 对象（sim-trace 契约 fault_event.trigger 形状）。"""
        if self.trigger_mode == "seq":
            return {"mode": "seq", "value": int(delay_ns), "ns_per_cycle": UNKNOWN}
        assert self.ns_per_cycle is not None
        return {
            "mode": "cycle_estimate",
            "value": int(delay_ns / self.ns_per_cycle),
            "ns_per_cycle": self.ns_per_cycle,
        }

    def map_width(self, pulse_ns: float | None) -> dict[str, Any] | None:
        """pulse_ns → pulse 对象；single_event 模式返回 None（契约里写 unknown）。"""
        if self.width_mode == "single_event" or pulse_ns is None:
            return None
        return {"mode": "instruction_count", "value": int(pulse_ns)}

    def map_action(self, pulse_ns: float | None) -> dict[str, Any]:
        """动作对象：flip_reg_bits 的位宽取 pulse 值（脉冲越宽翻越多位）。"""
        if self.action_kind == "flip_reg_bits":
            width = int(pulse_ns) if pulse_ns is not None else 1
            return {
                "kind": "flip_reg_bits",
                "reg": self.flip_target_reg,
                "bit_width": width,
                "bit_mask": UNKNOWN,
                "new_value": UNKNOWN,
            }
        if self.action_kind == "reg_write":
            return {"kind": "reg_write", "reg": UNKNOWN, "value": UNKNOWN}
        if self.action_kind == "mem_write":
            return {
                "kind": "mem_write",
                "addr": UNKNOWN,
                "size": UNKNOWN,
                "value": UNKNOWN,
            }
        return {"kind": "skip"}


class SimFaultInjector(Injector):
    """仿真故障注入器（evidence=hypothesis）。"""

    name = "sim-fault"

    def __init__(
        self,
        backend: SimBackend,
        mapping: ParamMappingSpec,
        max_instructions: int = 100000,
    ) -> None:
        self.backend = backend
        self.mapping = mapping
        self.max_instructions = max_instructions
        self._run_seq = 0

    def inject(self, point: ParamPoint) -> InjectionOutcome:
        delay_ns = point.try_get("delay", "ns")
        pulse_ns = point.try_get("pulse", "ns")
        if delay_ns is None:
            # raw 参数点在仿真侧无时间语义：仿真域只接受 ns（映射为指令序号）
            return InjectionOutcome(
                point=point,
                status="error",
                evidence_level="hypothesis",
                source=self.name,
                detail={"reason": "仿真注入器参数点必须携带 delay_ns（映射为触发事件）"},
            )

        event: dict[str, Any] = {
            "type": "fault_event",
            "event_id": f"fev-{uuid.uuid4().hex[:12]}",
            "run_id": UNKNOWN,  # 运行尚未发生；契约要求字段存在，缺失语义用 unknown
            "campaign_id": UNKNOWN,
            "trigger": self.mapping.map_trigger(delay_ns),
            "action": self.mapping.map_action(pulse_ns),
            "pulse": self.mapping.map_width(pulse_ns) if self.mapping.map_width(pulse_ns) else UNKNOWN,
            "applied": UNKNOWN,
            "applied_at_seq": UNKNOWN,
            "applied_result": UNKNOWN,
            "evidence_level": "hypothesis",
        }
        if self.mapping.profile_ref != UNKNOWN:
            event["profile_ref"] = self.mapping.profile_ref

        self.backend.reset()
        self.backend.apply_fault(event)
        run = self.backend.run(self.max_instructions)

        self._run_seq += 1
        metrics = run.outcome_metrics or {}
        response_signal = metrics.get("observable_output")

        return InjectionOutcome(
            point=point,
            status="injected",
            evidence_level="hypothesis",
            response_raw=str(response_signal) if response_signal is not None else None,
            state_label=None,  # 仿真没有 CSV 原始标签，交给契约的 unknown
            applied_point={
                "delay_raw": UNKNOWN,
                "pulse_raw": UNKNOWN,
            },
            raw_data_ref=None,
            source=self.name,
            detail={
                "fault_event": event,
                "run_id": run.run_id,
                "trace_ref": run.trace_ref if run.trace_ref else UNKNOWN,
                "exit_reason": run.exit_reason,
                "final_pc": run.final_pc,
                "instruction_count": run.instruction_count,
                "outcome_metrics": metrics,
            },
        )
