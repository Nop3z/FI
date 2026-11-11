# -*- coding: utf-8 -*-
"""CSV 解析与清洗：类型化、空值、标签枚举、单位换算开关、规范 JSONL 输出。

用法（项目根目录）::

    from fi.analysis.parser import load_raw_csv, clean_typed, to_jsonl

    df_raw = load_raw_csv(r"<PROJECT_ROOT>\\<DATASET>.csv")
    df = clean_typed(df_raw, convert_ns=True)   # convert_ns=False 关闭换算
    to_jsonl(df, "data/derived/<DATASET>.typed.jsonl")

清洗规则（全部为观测规则，无数据集字面量）：
- ``delay`` / ``pulse``：强制 int，解析失败记入 ``_parse_errors``。
- ``state``：保留原字符串；调用方传入 ``known_labels`` 枚举时，不在枚举内的值
  计入 ``unknown_state_labels``（审计：枚举由调用方/Profile 提供，不硬编码）。
- ``response`` / ``unexpected``：空串 → ``None``（JSON null）；其余按 ``normalize_code``。
- ``glitched``：非空 → True（观测规则：该列任何字面量均表示"已注入"标记；
  本历史样例中该字面量为恒定单值，无对照取值）。
- ns 字段仅在 ``convert_ns=True`` 时生成，且继承假设 A1（常数见 schema，
  未证实）。
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from typing import Sequence

import pandas as pd

from fi.analysis.schema import (
    COL_DELAY,
    COL_GLITCHED,
    COL_PULSE,
    COL_RESPONSE,
    COL_STATE,
    COL_UNEXPECTED,
    NS_PER_STEP_ASSUMED,
    UNIT_ASSUMPTION_TAG,
    code_class_of,
    normalize_code,
    steps_to_ns,
)


@dataclass
class ParseReport:
    """解析/清洗过程报告（可审计）。"""

    rows: int = 0
    parse_errors: dict = field(default_factory=dict)
    unknown_state_labels: dict = field(default_factory=dict)
    response_tokens: dict = field(default_factory=dict)   # 含哨兵 token 计数
    unexpected_tokens: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rows": self.rows,
            "parse_errors": self.parse_errors,
            "unknown_state_labels": self.unknown_state_labels,
            "response_tokens": self.response_tokens,
            "unexpected_tokens": self.unexpected_tokens,
            "notes": self.notes,
        }


def load_raw_csv(path: str) -> pd.DataFrame:
    """原始读取：全列 str、空串不转 NA（保持观测原样，只读不写）。"""
    return pd.read_csv(path, dtype=str, keep_default_na=False)


def clean_typed(
    df_raw: pd.DataFrame,
    convert_ns: bool = True,
    ns_per_step: float = NS_PER_STEP_ASSUMED,
    known_labels: Sequence[str] | None = None,
) -> tuple[pd.DataFrame, ParseReport]:
    """类型化 + 规范化，返回 (typed_df, report)。

    ``known_labels``：调用方提供的状态标签枚举（如来自 Profile/配置）；
    提供时才做枚举外标签检查。其余输出列见 docstring。
    """
    rep = ParseReport()
    df = df_raw.copy()

    rep.rows = len(df)

    # delay / pulse 类型化
    for col, out in ((COL_DELAY, "delay_i"), (COL_PULSE, "pulse_i")):
        vals = pd.to_numeric(df[col], errors="coerce")
        bad = df[vals.isna()]
        if len(bad):
            rep.parse_errors[col] = sorted(set(bad[col]))[:20]
        df[out] = vals.astype("Int64")

    # 状态标签枚举（仅当调用方提供枚举时检查）
    if known_labels:
        unknown_states = df.loc[~df[COL_STATE].isin(set(known_labels)), COL_STATE]
        if len(unknown_states):
            rep.unknown_state_labels = unknown_states.value_counts().to_dict()

    # response / unexpected 规范化
    for col in (COL_RESPONSE, COL_UNEXPECTED):
        norm = df[col].map(normalize_code)
        tokens = {}
        for v in norm.dropna().unique():
            if not v.lower().startswith("0x"):
                tokens[v] = int((norm == v).sum())
        if col == COL_RESPONSE:
            rep.response_tokens = tokens
        else:
            rep.unexpected_tokens = tokens
        df[f"{col}_norm"] = norm.astype(object).where(norm.notna(), None)

    # glitched 布尔化（观测规则：非空即标记；历史样例为恒定单值字面量）
    df["glitched_b"] = df[COL_GLITCHED].astype("string").fillna("").ne("")

    # code_class 观测分类
    df["code_class"] = [
        code_class_of(r, u) for r, u in zip(df["response_norm"], df["unexpected_norm"])
    ]

    # 单位换算开关（假设 A1）
    if convert_ns:
        df["delay_ns"] = df["delay_i"].astype("Float64") * ns_per_step
        df["pulse_ns"] = df["pulse_i"].astype("Float64") * ns_per_step
        df.attrs["unit_assumption"] = UNIT_ASSUMPTION_TAG

    df.attrs["parse_report"] = rep.to_dict()
    return df, rep


# ---------------------------------------------------------------------------
# 规范 JSONL（流式逐行写出，避免 74 万行 records 驻留内存）
# ---------------------------------------------------------------------------
def _jsonl_record(row_idx: int, row) -> dict:
    rec = {
        "row": row_idx,
        "state": row[COL_STATE],
        "delay_raw": int(row["delay_i"]),
        "pulse_raw": int(row["pulse_i"]),
        "response_norm": row["response_norm"],
        "unexpected_norm": row["unexpected_norm"],
        "glitched": bool(row["glitched_b"]),
        "code_class": row["code_class"],
    }
    if "delay_ns" in row.index:
        rec["delay_ns"] = float(row["delay_ns"])
        rec["pulse_ns"] = float(row["pulse_ns"])
    return rec


def to_jsonl(df: pd.DataFrame, out_path: str) -> int:
    """写规范 JSONL（UTF-8，一行一实验）。返回行数。"""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    n = 0
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for i, row in enumerate(df.itertuples(index=False), start=1):
            # itertuples 字段访问按列名
            rec = {
                "row": i,
                "state": getattr(row, COL_STATE),
                "delay_raw": int(getattr(row, "delay_i")),
                "pulse_raw": int(getattr(row, "pulse_i")),
                "response_norm": getattr(row, "response_norm"),
                "unexpected_norm": getattr(row, "unexpected_norm"),
                "glitched": bool(getattr(row, "glitched_b")),
                "code_class": getattr(row, "code_class"),
            }
            if hasattr(row, "delay_ns"):
                rec["delay_ns"] = float(getattr(row, "delay_ns"))
                rec["pulse_ns"] = float(getattr(row, "pulse_ns"))
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
            n += 1
    return n


def iter_raw_rows(path: str):
    """流式读取原始 CSV 行（jsonl 写出备选路径；当前未用，保留为轻量接口）。"""
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row
