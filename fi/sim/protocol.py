"""SimBackend 接口契约（core-contract 维护；实现归 sim-engine 专职）。

对接方式（SimFaultInjector 的调用时序）：
    backend.load_image(rom_path, base_address=0x<BASE>, profile_ref="target-chip")
    backend.reset()
    backend.apply_fault(event)      # fault_event：sim-trace 契约行形状
    result = backend.run(max_instructions)

SimRunResult.trace_ref 指向的 JSONL 必须符合 sim-trace.schema.json；
final_context 必须符合 fault-context.schema.json。
base_address=0x<BASE> 是用户给定的唯一事实，仅作为调用方参数出现，
不写进本协议的任何默认值。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fi import UNKNOWN

#: fault-event 行形状（sim-trace.schema.json）的 type 常量。
FAULT_EVENT_TYPE = "fault_event"


@dataclass(frozen=True)
class SimRunResult:
    """一次仿真运行的产出。"""

    run_id: str
    """本次运行唯一 ID（trace JSONL 每行的 run_id 与此一致）。"""

    exit_reason: str
    """结束原因：normal / exception / max_instructions / timeout / hang / unknown。"""

    final_pc: int | str
    """结束 PC；不可得时为 "unknown"。"""

    instruction_count: int
    """已执行指令条数。"""

    trace_ref: str | None
    """轨迹 JSONL 路径；未落盘为 None。"""

    final_context: dict[str, Any] = field(default_factory=dict)
    """结束现场（fault-context 契约形状，processor_context 层）。"""

    outcome_metrics: dict[str, Any] = field(default_factory=dict)
    """可观测输出信号（如关键寄存器值、UART 缓冲内容）；键由实现自定并自释。"""


class SimBackend(ABC):
    """指令级仿真后端接口（可插拔：Unicorn / 其他后端均可实现）。"""

    #: 后端标识（如 unicorn-rv32）。
    name: str = "unknown"

    @abstractmethod
    def load_image(
        self,
        image_path: Path,
        base_address: int,
        profile_ref: str = UNKNOWN,
    ) -> None:
        """加载固件镜像到 base_address；profile_ref 引用 ChipProfile ID
        （内存布局/CSR 配置以其为准）。"""

    @abstractmethod
    def reset(self) -> None:
        """复位到入口状态。复位入口由 ChipProfile 提供；Profile 未定稿时
        实现自行记录假设并标注 hypothesis。"""

    @abstractmethod
    def apply_fault(self, event: dict[str, Any]) -> str:
        """挂起一个故障事件（在下一次 run 中生效），返回 event_id。

        event 必须符合 sim-trace.schema.json 的 fault_event 行形状：
        trigger{mode,value}（instruction_index / cycle_estimate）+
        action{kind,...}（skip_instruction / flip_reg_bits / corrupt_mem_value）+
        pulse{mode,value}（instruction_count / single_event）。
        """

    @abstractmethod
    def run(self, max_instructions: int) -> SimRunResult:
        """从当前状态执行至多 max_instructions 条指令。"""
