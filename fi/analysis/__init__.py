# -*- coding: utf-8 -*-
"""FI 实验数据分析包（M2 分析层）。

职责边界（baseline v2 §7）
--------------------------
- 本包**实现**归 exp-analysis 专职（CSV 解析/分布事实/聚类/评分/ROM 归因搜索）。
- 接口契约 ``fi/analysis/protocol.py``（Analyzer）由 core-contract 维护，
  分析产出需对齐 AnalysisResult 契约（docs/contracts/schemas/）。

主要模块
--------
- ``parser``         CSV 解析/清洗/类型化/规范 JSONL
- ``schema``         常量与假设声明（观测/假设/未知三级标注的单一来源）
- ``distributions``  状态计数、错误码、直方、逐点率值、分段对比、行序诊断
- ``clusters``       网格密度、连通域聚类、状态间相对位置
- ``scoring``        候选参数评分接口（OfflineScorer，草案 v0.1）
- ``rom_search``     错误码 ↔ ROM 静态归因搜索（capstone RV32IMC）
- ``run_analysis``   一键重放入口

纪律
----
- 观测 / 假设 / 未知三级标注；缺失显式 ``unknown`` / ``null``。
- 原始 CSV / ROM 只读；派生数据写 ``data/derived/``。
- delay/pulse 单位按 **10 ns/步** 换算只是工作假设（``schema.ASSUMPTIONS`` A1），
  所有 ns 字段均继承该假设，未经证实。
- 状态标签（FL/HANG/SUCCESS/UNEXPECTED/Fake_Success）语义未经用户确认且用户不提供
  协议资料（baseline v2），一律按原始标签处理，自主逆向归因（``rom_search``）。
"""

__version__ = "0.1.0"

from fi.analysis.schema import ASSUMPTIONS, NS_PER_STEP_ASSUMED
from fi.analysis.parser import clean_typed, load_raw_csv, to_jsonl
from fi.analysis.protocol import Analyzer  # core-contract 接口契约（re-export）

__all__ = [
    "Analyzer",
    "ASSUMPTIONS",
    "NS_PER_STEP_ASSUMED",
    "clean_typed",
    "load_raw_csv",
    "to_jsonl",
    "__version__",
]
