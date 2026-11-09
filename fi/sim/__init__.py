"""fi.sim：通用 RISC-V 指令级仿真骨架（Unicorn 后端）。

组成：
- config：声明式仿真配置（内存区域/入口/策略/注入清单）
- machine：Simulator 引擎（内存映射、钩子、WARL/探索策略、停止分类）
- tracer：JSONL 轨迹落盘（行类型与 docs/contracts 的 sim-trace 契约草案对齐）
- devices：可插拔设备模型 + 探索占位设备（所有占位访问强制记录）
- decode：capstone 反汇编与 CSR 解码辅助
- inject：仿真故障注入钩子（M3 闭环的离线注入器接口 v0）
- timing：周期估算与时间映射（指令 → 估算周期 → ns；delay 调参前提）
- stopreasons：停止原因分类
- loopdetect：疑似死循环启发式检测
- cli：命令行入口（python -m fi.sim run / time-report ...）

纪律：本包不写任何芯片专有默认值；占位访问必带 stub 标记进事实日志；
候选解释一律标注 hypothesis，不写成事实。
"""

__all__ = [
    "config",
    "devices",
    "decode",
    "tracer",
    "loopdetect",
    "stopreasons",
    "inject",
    "machine",
    "timing",
    "cli",
]
