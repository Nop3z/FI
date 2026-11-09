"""FI —— 通用 RISC-V 故障观测/异常捕获/上下文分析/指令级仿真工具集。

包结构（core-contract 维护骨架与契约；各专职成员负责实现）：

- ``fi.schemas``   : 数据契约（JSON Schema + 语义不变量）加载与校验辅助。
- ``fi.providers`` : CaptureProvider 抽象（uart/trap/crash_dump/debug/external 占位）。
- ``fi.loop``      : 闭环编排接口（参数窗口 → 注入 → 捕获 → 分析 → 调参收敛）。
- ``fi.discover``  : 芯片接入自动发现管线（regions/traps/functions/chain，TTS 核心）。
- ``fi.sim``       : 指令级仿真后端接口（实现归 sim-engine 专职）。
- ``fi.analysis``  : 实验数据分析接口（实现归 exp-analysis 专职）。
- ``fi.profiles``  : 芯片画像存取接口（实现归 chip-profile 专职）。

纪律：泛化优先；target-chip 只能以样例配置出现，禁止进通用代码；
缺失字段显式 ``unknown``；证据分级 observation|hypothesis|unknown 必填。
"""

__version__ = "0.3.0"

#: 数据契约版本（与 docs/contracts/schemas/*.json 内 schema_version 常量一致）。
CONTRACT_VERSION = "0.2"

#: 证据等级三值枚举：观测事实 / 假设 / 未知。所有契约实例必填。
EVIDENCE_LEVELS = ("observation", "hypothesis", "unknown")

#: 显式缺失标记：未采集到的信息一律用该字符串，禁止用 null/0/"" 猜测。
UNKNOWN = "unknown"
