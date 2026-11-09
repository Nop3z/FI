"""Trap 捕获 Provider（占位）。

蓝图定位：Level 2 处理器上下文。获取：异常 PC、mcause/mepc/mtval、
部分寄存器（覆盖范围取决于固件的 Trap Handler 保存了什么）；
局限：只覆盖真正进入 Trap 的情况——PC 被改到合法地址时不触发 Trap。

对应契约 observation_level="processor_context"。硬件/固件侧接线在 M4；
仿真侧的 trap 等价物由 sim-engine 的 SimBackend 产出 FaultContext，
不经过本类。
"""

from __future__ import annotations

from fi.providers.base import (
    CaptureProvider,
    CaptureRequest,
    DetectResult,
    RawCapture,
)


class TrapCaptureProvider(CaptureProvider):
    """CPU 异常处理程序现场采集。占位实现，detect 恒为不可用。"""

    name = "trap"

    def detect(self) -> DetectResult:
        return DetectResult(
            provider_name=self.name,
            available=False,
            reason="占位实现：需要目标固件植入/实机调试通道（M4）",
            observation_level="processor_context",
        )

    def capture(self, request: CaptureRequest) -> RawCapture:
        raise RuntimeError("trap Provider 未实现")

    def normalize(self, raw: RawCapture) -> dict:
        raise RuntimeError("trap Provider 未实现")
