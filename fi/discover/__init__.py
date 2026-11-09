# -*- coding: utf-8 -*-
"""fi.discover：芯片接入自动发现管线（TTS 核心）。

目标（docs/tts-baseline.md）：把"新芯片从只有固件 bin 到仿真跑起来"的人工分析
步骤产品化为芯片无关的自动管线。发现能力：

    regions   地址常量扫描 → RAM/MMIO 区域候选（供 sim 的 iterate 消费）
    traps     trap 机制识别 → mtvec 安装点 / mcause 读取 / mret / handler 形态
    targets   注入靶点枚举 → 错误码装载点 / 发送函数调用点 / 比较分支
    draft     Profile 草稿生成 → profiles/<chip>.draft.yaml（全 hypothesis）
    chain     功能级调用链重建（递归下降 + 函数指针表 + gp 相对寻址抬升）
    dispatch  运行期分派表恢复（ROM 源表 → 命令号 ↔ handler）
    attribute 异常码归因（码 → 命令 → handler → 装载指令）
    injection_targets
              注入靶点清单（码装载指令 + 位翻转变体 + 建议动作 + 预期观测）
    key_evidence
              核心证据浓缩（1-bit 翻转 ⇒ 实验观测码 A 变实验观测码 B）

纪律：
- 本包**不含任何具体芯片的地址、错误码、ID**（通用性门禁强制）。
- 全部产出 confidence 恒为 hypothesis（自动发现的证据闸门，core-contract 契约层强制）。
- 只产出候选与草稿；不得自动改写已有 fact 级 claim。
- 位翻转类产出必须区分「机器码位」与「寄存器值位」——
  注入用后者，混用会静默失效（见 docs/discover/injection-targets-guide.md）。
"""

from __future__ import annotations

__all__ = [
    "regions", "traps", "targets", "draft", "common",
    "chain", "dispatch", "attribution", "injection_targets", "key_evidence", "cli",
]

DISCOVER_VERSION = "0.1.0"
SCHEMA_NAME = "fi.discover.report-v0"
