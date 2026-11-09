"""闭环编排（项目心脏）：参数窗口 → 注入 → 捕获 → 分析 → 调参收敛。

可插拔点（全部面向接口，不锁定具体实现）：
- Injector（fi.loop.injector）      : 注入器。内置离线实现：CSVReplayInjector / SimFaultInjector。
- CaptureProvider（fi.providers）   : 观测器。硬件 Provider 仅接口预留，离线阶段可为空。
- LoopStrategy（fi.loop.strategy）  : 调参策略。内置基线：MinimalGridStrategy。
- LoopOrchestrator（fi.loop.orchestrator）: 编排器，通用实现 run_closed_loop。

模块清单：
- types        : ParamPoint / ParamWindow / InjectionOutcome 等值对象
- injector     : Injector 接口
- strategy     : LoopStrategy 接口
- orchestrator : 编排器接口 + 通用实现
- csv_replay   : 离线注入器 #1（历史 CSV 回放）
- sim_injector : 离线注入器 #2（仿真故障注入，对接 fi.sim.SimBackend）
- strategies   : 内置基线策略
- records      : InjectionOutcome → CampaignRecord（契约实例）组装
"""

from fi.loop.types import InjectionOutcome, ParamAxis, ParamPoint, ParamWindow
from fi.loop.injector import Injector
from fi.loop.strategy import LoopStrategy
from fi.loop.orchestrator import GenericLoopOrchestrator, LoopOrchestrator, LoopResult

__all__ = [
    "InjectionOutcome",
    "ParamAxis",
    "ParamPoint",
    "ParamWindow",
    "Injector",
    "LoopStrategy",
    "LoopOrchestrator",
    "GenericLoopOrchestrator",
    "LoopResult",
]
