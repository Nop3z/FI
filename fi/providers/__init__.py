"""CaptureProvider 抽象与占位实现。

设计蓝图（总结故障注入文章 §5/§6）：
- 统一抽象 detect / capture / normalize / validate 四步；
- 不把异常捕获限制为 Trap Handler：UART、Crash Dump、Debug、外部观测都是
  平等的 Provider；
- 每个 Provider 只填自己能确认的数据，未采集字段显式 "unknown"；
- normalize 的输出必须通过 fault-context.schema.json 校验。

纪律：本目录的 5 个占位类只约定接口形状，不做任何硬件假设；
硬件接入（PowerShorter/SmartHub/示波器）在 M4 里程碑，当前离线实现走
simulation / csv_replay 来源。
"""

from fi.providers.base import (
    CaptureProvider,
    CaptureRequest,
    DetectResult,
    RawCapture,
)
from fi.providers.crash_dump import CrashDumpCaptureProvider
from fi.providers.debug import DebugCaptureProvider
from fi.providers.external import ExternalCaptureProvider
from fi.providers.trap import TrapCaptureProvider
from fi.providers.uart import UartCaptureProvider

__all__ = [
    "CaptureProvider",
    "CaptureRequest",
    "DetectResult",
    "RawCapture",
    "UartCaptureProvider",
    "TrapCaptureProvider",
    "CrashDumpCaptureProvider",
    "DebugCaptureProvider",
    "ExternalCaptureProvider",
]
