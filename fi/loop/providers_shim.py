"""观测器采集 shim：编排器与 CaptureProvider 之间的采集循环。

独立成模块便于单测与被其他编排器复用。规则：
- detect() 不可用的 Provider 跳过并计数（不中断闭环）；
- capture/normalize 抛异常时记为该 Provider 的错误，继续其余观测器；
- validate() 的输出中，"hint:" 开头是提示不算失败，其余计入 problems。
"""

from __future__ import annotations

from fi.providers.base import CaptureProvider, CaptureRequest

# 符合 fault-context.schema.json 的实例 dict。
FaultContextData = dict


def collect_contexts(
    observers: list[CaptureProvider],
    campaign_id: str,
) -> tuple[list[FaultContextData], list[str], int]:
    """执行一轮观测采集。

    返回 (上下文列表, 校验问题列表, 跳过的观测器数)。
    """
    contexts: list[FaultContextData] = []
    problems: list[str] = []
    skipped = 0

    for provider in observers:
        try:
            detect = provider.detect()
            if not detect.available:
                skipped += 1
                continue
            raw = provider.capture(CaptureRequest(campaign_id=campaign_id))
            context = provider.normalize(raw)
            ctx_problems = provider.validate(context)
            hard = [p for p in ctx_problems if not p.startswith("hint:")]
            problems.extend(f"{provider.name}/{p}" for p in hard)
            contexts.append(context)
        except Exception as exc:  # noqa: BLE001 —— 单个观测器故障不拖垮闭环
            problems.append(f"{provider.name}/采集异常: {exc}")
            skipped += 1
    return contexts, problems, skipped
