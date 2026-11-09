"""Crash Dump 捕获 Provider（占位）。

蓝图定位：Level 2 处理器上下文。获取：固件崩溃记录中保存的上下文；
局限：依赖固件实现（是否有 dump 逻辑、保存哪些寄存器）。

对应契约 observation_level="processor_context"。
"""

from __future__ import annotations

from fi.providers.base import (
    CaptureProvider,
    CaptureRequest,
    DetectResult,
    RawCapture,
)


class CrashDumpCaptureProvider(CaptureProvider):
    """固件 Crash Dump 采集。占位实现，detect 恒为不可用。"""

    name = "crash_dump"

    def detect(self) -> DetectResult:
        return DetectResult(
            provider_name=self.name,
            available=False,
            reason="占位实现：需确认目标固件是否含 Crash Dump 逻辑（待用户资料）",
            observation_level="processor_context",
        )

    def capture(self, request: CaptureRequest) -> RawCapture:
        raise RuntimeError("crash_dump Provider 未实现")

    def normalize(self, raw: RawCapture) -> dict:
        raise RuntimeError("crash_dump Provider 未实现")
