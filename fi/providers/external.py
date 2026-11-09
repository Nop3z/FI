"""外部观测 Provider（占位）。

蓝图定位：Level 1 行为观测的泛化容器：GPIO、示波器、外部逻辑分析、
复位原因监测等。获取：外部事件与时间关系；局限：不能直接还原 CPU 状态。

对应契约 observation_level="behavior"。示波器/分路电源等设备按
bench_list 确认当前不在架子上（M4 接入）。
"""

from __future__ import annotations

from fi.providers.base import (
    CaptureProvider,
    CaptureRequest,
    DetectResult,
    RawCapture,
)


class ExternalCaptureProvider(CaptureProvider):
    """GPIO/示波器等外部设备采集。占位实现，detect 恒为不可用。"""

    name = "external"

    def detect(self) -> DetectResult:
        return DetectResult(
            provider_name=self.name,
            available=False,
            reason="占位实现：示波器/GPIO 设备未上架（M4）",
            observation_level="behavior",
        )

    def capture(self, request: CaptureRequest) -> RawCapture:
        raise RuntimeError("external Provider 未实现")

    def normalize(self, raw: RawCapture) -> dict:
        raise RuntimeError("external Provider 未实现")
