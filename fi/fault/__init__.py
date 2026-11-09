# -*- coding: utf-8 -*-
"""fi.fault：故障效果推演（bit-flip → 语义变化 → 执行结果反解）。

对应方法论 `docs/methodology-fault-effect-reasoning.md`：
从"打中了哪条指令"进到"这条指令被打坏后变成了什么、为什么产生这个观测"。
"""

from __future__ import annotations

__all__ = ["effects"]

SCHEMA_PREFIX = "fi.fault"
