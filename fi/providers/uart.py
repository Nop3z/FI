"""UART 行为观测 Provider（占位，M4 实机接入时实现）。

蓝图定位：Level 1 行为观测。获取：错误码、响应内容、通信中断；
局限：无法直接定位 PC。对应契约 observation_level="behavior"。

当前状态：接口占位。离线阶段的 UART 等价物是 csv_replay（从历史 CSV
重放响应），在 loop/analysis 侧实现，不伪装成实机 UART。
"""

from __future__ import annotations

from fi.providers.base import (
    CaptureProvider,
    CaptureRequest,
    DetectResult,
    RawCapture,
)


class UartCaptureProvider(CaptureProvider):
    """UART 串口响应采集。detect 恒为不可用，直到实机接入。"""

    name = "uart"

    def detect(self) -> DetectResult:
        return DetectResult(
            provider_name=self.name,
            available=False,
            reason="占位实现：实机串口未接入（M4）；离线请走 csv_replay",
            observation_level="behavior",
        )

    def capture(self, request: CaptureRequest) -> RawCapture:
        raise RuntimeError("uart Provider 未实现：实机接入前请使用 csv_replay 来源")

    def normalize(self, raw: RawCapture) -> dict:
        raise RuntimeError("uart Provider 未实现：实机接入前请使用 csv_replay 来源")
