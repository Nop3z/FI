"""CaptureProvider 抽象基类（接口契约，core-contract 维护）。

所有观测来源（uart/trap/crash_dump/debug/trace/external/simulation/csv_replay）
实现同一四步协议：

    detect()                    检测本 Provider 当前是否可用（不产生副作用）
    capture(request)            采集一次原始现场
    normalize(raw)              原始数据 → 统一 FaultContext（契约校验通过）
    validate(context)           上下文完整性复核（字段级 unknown 审计）

实现约定：
- normalize 产出的 dict 必须符合 docs/contracts/schemas/fault-context.schema.json；
- 未采集到的字段写 fi.UNKNOWN（"unknown"），禁止 null/0/""；
- Provider 自己的配置（串口参数、地址映射等）由实现类构造函数携带，
  本基类不假设任何芯片/硬件细节。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from fi import UNKNOWN

# 符合 fault-context.schema.json 的实例（结构校验由 fi.schemas 负责）。
FaultContextData = dict[str, Any]


@dataclass(frozen=True)
class CaptureRequest:
    """一次采集请求。Provider 按自身能力取用字段，取不到的忽略。"""

    campaign_id: str = "unknown"
    """关联的注入实验 ID（CampaignRecord.campaign_id）。"""

    timeout_s: float = 10.0
    """采集超时（秒）。"""

    options: dict[str, Any] = field(default_factory=dict)
    """Provider 专属选项（自由键值，实现自行解释）。"""


@dataclass(frozen=True)
class DetectResult:
    """detect() 的返回：可用性及原因。"""

    provider_name: str
    """Provider 标识（对应契约 provider_name 枚举）。"""

    available: bool
    """当前是否可用于采集。"""

    reason: str = "unknown"
    """不可用原因/能力描述；available=True 时可写能力摘要。"""

    observation_level: str = "unknown"
    """本 Provider 提供的观测层：behavior / processor_context / execution_trace。"""


@dataclass(frozen=True)
class RawCapture:
    """capture() 的返回：未归一化的原始采集数据。"""

    provider_name: str
    """采集来源标识。"""

    payload: bytes | str
    """原始载荷（字节流或文本），实现自行定义编码。"""

    timestamp: str = UNKNOWN
    """采集时刻（ISO 8601 带时区；拿不到写 unknown）。"""

    metadata: dict[str, Any] = field(default_factory=dict)
    """随载荷的元信息（端口、采样率、触发条件等）。"""


class CaptureProvider(ABC):
    """统一捕获 Provider 接口（ABC，便于框架强约束子类）。"""

    #: Provider 标识，子类覆写；应取 fi.schemas 契约 provider_name 枚举值。
    name: str = "unknown"

    @abstractmethod
    def detect(self) -> DetectResult:
        """检测本 Provider 当前可用的捕获机制（无副作用、可重复调用）。"""

    @abstractmethod
    def capture(self, request: CaptureRequest) -> RawCapture:
        """采集一次异常现场原始数据。不可用时抛 RuntimeError，由编排器决定降级。"""

    @abstractmethod
    def normalize(self, raw: RawCapture) -> FaultContextData:
        """原始数据 → 统一 FaultContext。

        返回 dict 必须通过 fault-context.schema.json 校验；
        本 Provider 采集不到的字段显式写 "unknown"。
        """

    def validate(self, context: FaultContextData) -> list[str]:
        """上下文完整性复核：返回问题列表，空列表 = 通过。

        默认实现 = 契约 schema 校验 + unknown 审计（哪些关键字段仍是 unknown，
        便于编排器决定是否需要更高观测层的 Provider 补采）。子类可扩展。
        """
        from fi.schemas import validate_instance

        problems = validate_instance("fault-context", context)
        problems.extend(_audit_unknowns(context))
        return problems


def _audit_unknowns(context: FaultContextData) -> list[str]:
    """unknown 审计：提示哪些高价值字段缺失，帮助选择补采 Provider。

    注意：unknown 本身是合法值（纪律允许且要求显式缺失），
    这里只产生提示性条目，不算校验失败。
    """
    hints: list[str] = []
    if context.get("pc") == UNKNOWN:
        hints.append("hint: pc=unknown —— 行为观测拿不到 PC，可尝试 debug/trap 层补采")
    if context.get("registers") == UNKNOWN:
        hints.append("hint: registers=unknown —— 处理器上下文缺失，可尝试 debug/trap 层补采")
    if context.get("execution_trace") == UNKNOWN:
        hints.append("hint: execution_trace=unknown —— 无执行轨迹，归因只能到候选级别")
    return hints
