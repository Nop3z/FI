# -*- coding: utf-8 -*-
"""fi.hardware：实机接入层（毛刺设备、目标通信、安全护栏）。

设计原则：
- 无设备也能构造与测试（mock 实现与真实设备同接口）
- 所有单位换算显式（delays/pulses 的 10ns 单位来自设备文档）
- 安全护栏强制（脉宽/次数/连续失败/紧急停止）
- 实机数据一律标 Captured State，与仿真（Simulated State）严格分开
"""

from __future__ import annotations

__all__ = ["powershorter"]

SCHEMA_PREFIX = "fi.hardware"
