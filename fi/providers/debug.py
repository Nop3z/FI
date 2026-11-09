"""Debug 捕获 Provider（占位）。

蓝图定位：Level 2 处理器上下文（最高质量来源）。获取：经 JTAG/Debug
Module 读取 PC、通用寄存器、CSR；局限：取决于芯片调试权限。

对应契约 observation_level="processor_context"。实机调试器上架前不可用。
"""

from __future__ import annotations

from fi.providers.base import (
    CaptureProvider,
    CaptureRequest,
    DetectResult,
    RawCapture,
)


class DebugCaptureProvider(CaptureProvider):
    """JTAG/Debug Module 现场采集。占位实现，detect 恒为不可用。"""

    name = "debug"

    def detect(self) -> DetectResult:
        return DetectResult(
            provider_name=self.name,
            available=False,
            reason="占位实现：调试器硬件未上架（M4）",
            observation_level="processor_context",
        )

    def capture(self, request: CaptureRequest) -> RawCapture:
        raise RuntimeError("debug Provider 未实现")

    def normalize(self, raw: RawCapture) -> dict:
        raise RuntimeError("debug Provider 未实现")
