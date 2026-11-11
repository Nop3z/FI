# -*- coding: utf-8 -*-
"""数据集适配层：把任意来源的异常观测数据规范化为统一记录流。

**为什么需要这一层（能力 vs 一次性分析的分界线）**
历史分析的每个脚本都默认了 19991231 这批数据的形态：列名固定（state/delay/
pulse/response/unexpected/glitched）、状态标签集固定、码域固定为 0x 前缀。
换一份数据（不同列名、不同标签、错误码用十进制或纯数字、多了几列元信息）
就会全线崩掉。本层把"数据形态"与"分析逻辑"彻底解耦：

- **格式自动识别**：CSV / 规范 JSONL（本包 typed 格式）/ 仿真 trace JSONL /
  原始字节流 / 纯文本日志；也可用 config 显式指定，避免猜错。
- **列名全参数化**：``ColumnMapping`` 的每个字段都是"源数据里的列名"，
  由调用方/config 给出；本模块不含任何具体列名以外的假设。
- **标签集/码域从数据推导**：不预设标签字面量，不预设"码必须是 0x 前缀"——
  码分类规则可配（见 ``CodeRule``），缺省按"能解析成整数即视为码"处理。
- **缺失字段显式 unknown**：数据源没有的列一律记 ``None``，由上层标注 unknown，
  不用 0/空串填充。

纪律：本模块不含任何芯片实例值；一切数据集语义经 ``ColumnMapping`` 传入。
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

__all__ = [
    "ColumnMapping",
    "CodeRule",
    "LoadReport",
    "Dataset",
    "detect_format",
    "load_dataset",
    "iter_records",
    "FORMATS",
]

#: 支持的输入格式
FORMATS = ("csv", "typed_jsonl", "trace_jsonl", "bytes", "text")


# ---------------------------------------------------------------------------
# 配置对象
# ---------------------------------------------------------------------------
@dataclass
class CodeRule:
    """响应值 → 错误码 的解析规则（不预设码域）。

    ``hex_prefixes``：视为十六进制码的字符串前缀（如 ``"0x"``）。
    ``allow_decimal``：无法按前缀解析时，是否接受纯十进制整数为码。
    ``tokens``：显式声明为"非码 token"的字面量集合（如哨兵占位）；
    未列出的非数值字面量仍会保留为 token，但会被标记 ``is_token=True``。
    ``empty_markers``：视为"无响应"的字面量（如空串、``"-"``、``"NONE"`` 之外
    由调用方指定的占位符）。缺省只把空串当无响应。
    """

    hex_prefixes: tuple[str, ...] = ("0x", "0X")
    allow_decimal: bool = False
    tokens: tuple[str, ...] = ()
    empty_markers: tuple[str, ...] = ()

    def parse(self, raw: Any) -> dict:
        """返回 ``{"key": str|None, "numeric": int|None, "is_token": bool}``。"""
        if raw is None:
            return {"key": None, "numeric": None, "is_token": False, "raw": None}
        s = str(raw).strip()
        if s == "" or s in self.empty_markers:
            return {"key": None, "numeric": None, "is_token": False, "raw": None}
        for p in self.hex_prefixes:
            if s.lower().startswith(p.lower()):
                try:
                    return {"key": s, "numeric": int(s, 16), "is_token": False, "raw": s}
                except ValueError:
                    break
        if s in self.tokens:
            return {"key": s, "numeric": None, "is_token": True, "raw": s}
        if self.allow_decimal:
            try:
                return {"key": s, "numeric": int(s, 10), "is_token": False, "raw": s}
            except ValueError:
                pass
        # 其它非数值字面量：保留为 token（不丢弃，不猜语义）
        return {"key": s, "numeric": None, "is_token": True, "raw": s}


@dataclass
class ColumnMapping:
    """源数据列名映射。每一项都是"源数据里的列名"，可经 config 覆盖。

    值为 ``None`` 表示该字段在数据源中不存在（显式 unknown）。
    """

    state: str | None = "state"
    delay: str | None = "delay"
    pulse: str | None = "pulse"
    response: str | None = "response"
    unexpected: str | None = "unexpected"
    glitched: str | None = "glitched"
    #: 可选：已存在的"码分类"列（有此列时优先直接使用，不再自行解析）
    code_class: str | None = None
    #: 可选：行号/时间戳列（用于建立时间轴；没有则用行序）
    row_index: str | None = None
    timestamp: str | None = None

    @classmethod
    def from_dict(cls, d: dict | None) -> "ColumnMapping":
        if not d:
            return cls()
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class LoadReport:
    """加载过程报告（可审计：哪些字段缺失、哪些行被跳过）。"""

    source: str = ""
    format: str = ""
    n_rows_raw: int = 0
    n_rows_loaded: int = 0
    skipped: int = 0
    skip_reasons: dict = field(default_factory=dict)
    missing_fields: list = field(default_factory=list)
    detected_columns: list = field(default_factory=list)
    code_parse: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Dataset:
    """规范化数据集：records 为逐行 dict，字段固定（见 ``RECORD_FIELDS``）。"""

    records: list[dict]
    report: LoadReport
    byte_stream: bytes | None = None
    byte_stream_meta: dict = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.records)

    @property
    def states(self) -> list[str]:
        return [r["state"] for r in self.records]


#: 规范化记录的固定字段
RECORD_FIELDS = ("row", "state", "delay_raw", "pulse_raw", "code_key",
                 "code_numeric", "code_is_token", "glitched", "timestamp")


# ---------------------------------------------------------------------------
# 格式识别
# ---------------------------------------------------------------------------
def detect_format(path: str | Path, hint: str | None = None) -> str:
    """识别输入格式。``hint`` 由调用方/config 给出时优先采用（不做猜测）。

    返回值 ∈ ``FORMATS``。识别依据：
    - 二进制且不可解码为文本 → ``bytes``（原始字节流）；
    - 扩展名 ``.jsonl`` → 读首行判断：有 ``type: trace/run_meta/run_end`` →
      ``trace_jsonl``；有 ``delay_raw``/``pulse_raw`` → ``typed_jsonl``；
    - 扩展名 ``.csv`` 或首行含逗号分隔表头 → ``csv``；
    - 其它 → ``text``。
    """
    if hint:
        if hint not in FORMATS:
            raise ValueError(f"未知格式 hint={hint!r}，可选 {FORMATS}")
        return hint

    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".jsonl":
        first = _first_nonempty_line(p)
        try:
            obj = json.loads(first) if first else {}
        except json.JSONDecodeError:
            return "text"
        if isinstance(obj, dict):
            if obj.get("type") in ("trace", "run_meta", "run_end", "fault_event"):
                return "trace_jsonl"
            if "delay_raw" in obj or "pulse_raw" in obj:
                return "typed_jsonl"
        return "typed_jsonl"
    if suffix in (".csv", ".tsv"):
        return "csv"

    raw = p.read_bytes()
    if b"\x00" in raw[:4096]:
        return "bytes"
    try:
        head = raw[:4096].decode("utf-8")
    except UnicodeDecodeError:
        return "bytes"
    if "\n" in head and "," in head.split("\n", 1)[0]:
        return "csv"
    return "text"


def _first_nonempty_line(path: Path) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                return line.strip()
    return ""


# ---------------------------------------------------------------------------
# 加载
# ---------------------------------------------------------------------------
def load_dataset(path: str | Path,
                 mapping: ColumnMapping | None = None,
                 code_rule: CodeRule | None = None,
                 fmt: str | None = None,
                 byte_data_addr: tuple[int, int] | None = None,
                 byte_region: str | None = None,
                 preamble_len: int = 0,
                 max_rows: int | None = None) -> Dataset:
    """加载任意支持格式为规范化数据集。

    ``byte_data_addr``/``byte_region``：当格式为 ``trace_jsonl`` 时，用它们从
    trace 的写事件重建字节流（见 ``fi.analysis.trace_bytes``）；格式为 ``bytes``
    时直接用文件内容。
    """
    mapping = mapping or ColumnMapping()
    code_rule = code_rule or CodeRule()
    p = Path(path)
    fmt = detect_format(p, fmt)
    rep = LoadReport(source=str(p), format=fmt)

    if fmt == "csv":
        records = _load_csv(p, mapping, code_rule, rep, max_rows)
        stream, smeta = None, {}
    elif fmt == "typed_jsonl":
        records = _load_typed_jsonl(p, mapping, code_rule, rep, max_rows)
        stream, smeta = None, {}
    elif fmt == "trace_jsonl":
        records = []
        rep.notes.append("trace 格式不含实验参数行；records 为空，仅提供字节流")
        stream, smeta = _load_trace_bytes(p, byte_data_addr, byte_region, rep)
        stream = stream[preamble_len:] if stream else stream
        if smeta:
            smeta["preamble_len"] = preamble_len
    elif fmt == "bytes":
        raw = p.read_bytes()
        stream = raw[preamble_len:]
        smeta = {"source": str(p), "total_bytes": len(raw), "preamble_len": preamble_len}
        records = []
        rep.notes.append("bytes 格式不含结构化行；records 为空，仅提供字节流")
    else:  # text
        raw = p.read_bytes()
        stream = raw
        smeta = {"source": str(p), "total_bytes": len(raw), "preamble_len": 0}
        records = []
        rep.notes.append("text 格式无结构化字段；仅作为原始证据引用")

    rep.n_rows_loaded = len(records)
    if max_rows is not None and len(records) >= max_rows:
        rep.notes.append(f"已按 max_rows={max_rows} 截断")
    return Dataset(records=records, report=rep, byte_stream=stream,
                   byte_stream_meta=smeta)


# ---- CSV --------------------------------------------------------------
def _load_csv(path: Path, m: ColumnMapping, cr: CodeRule,
              rep: LoadReport, max_rows: int | None) -> list[dict]:
    # 全列按字符串读，空串不转 NA（保持观测原样）
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        cols = list(reader.fieldnames or [])
        rep.detected_columns = cols
        _check_mapping(m, cols, rep)
        out = []
        for i, row in enumerate(reader):
            if max_rows is not None and len(out) >= max_rows:
                break
            rec = _row_to_record(row, i, m, cr, rep, is_mapping_source=True)
            if rec is not None:
                out.append(rec)
            rep.n_rows_raw += 1
    return out


# ---- 规范 JSONL -------------------------------------------------------
def _load_typed_jsonl(path: Path, m: ColumnMapping, cr: CodeRule,
                      rep: LoadReport, max_rows: int | None) -> list[dict]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            if max_rows is not None and len(out) >= max_rows:
                break
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                _skip(rep, "json_decode_error")
                continue
            rep.n_rows_raw += 1
            rec = _json_to_record(obj, i, cr, rep)
            if rec is not None:
                out.append(rec)
    if not rep.detected_columns:
        rep.detected_columns = sorted({k for obj in out[:1] for k in obj})
    return out


# ---- trace → 字节流 ---------------------------------------------------
def _load_trace_bytes(path: Path, addr: tuple[int, int] | None,
                      region: str | None, rep: LoadReport):
    if addr is None:
        rep.notes.append("trace 格式未提供 byte_data_addr：跳过字节流重建")
        return None, {}
    from fi.analysis.trace_bytes import reconstruct_uart_stream_from_trace

    rec = reconstruct_uart_stream_from_trace(path, addr[0], addr[1], region_name=region)
    rep.notes.append(f"从 trace 重建字节流 {len(rec.data)} 字节（{len(rec.writes)} 次写事件）")
    meta = rec.to_dict()
    meta.pop("writes", None)  # 报告里不塞全部写事件（体积）
    return rec.data, meta


# ---- 行 → 记录 --------------------------------------------------------
_INT_RE = re.compile(r"^-?\d+$")


def _row_to_record(row: dict, i: int, m: ColumnMapping, cr: CodeRule,
                   rep: LoadReport, is_mapping_source: bool) -> dict | None:
    def get(col: str | None):
        if col is None:
            return None
        v = row.get(col)
        if v is None:
            return None
        s = str(v).strip()
        return s if s != "" else None

    state = get(m.state)
    if state is None:
        _skip(rep, "missing_state")
        return None

    delay = _to_int(get(m.delay), rep, "delay")
    pulse = _to_int(get(m.pulse), rep, "pulse")

    # 码：优先用现成的 code_class 列；否则按 response → unexpected 的顺序解析
    code_info = {"key": None, "numeric": None, "is_token": False, "raw": None}
    if m.code_class:
        raw = get(m.code_class)
        code_info = cr.parse(raw)
    if code_info["key"] is None:
        for col in (m.response, m.unexpected):
            raw = get(col)
            if raw is not None:
                code_info = cr.parse(raw)
                if code_info["key"] is not None:
                    break
    if code_info["key"] is None and (m.response or m.unexpected):
        # response 与 unexpected 都空 → 无响应（不是缺失，是观测）
        code_info = {"key": None, "numeric": None, "is_token": False, "raw": None}

    glitched_raw = get(m.glitched)
    ts = get(m.timestamp)
    return {
        "row": i,
        "state": state,
        "delay_raw": delay,
        "pulse_raw": pulse,
        "code_key": code_info["key"],
        "code_numeric": code_info["numeric"],
        "code_is_token": code_info["is_token"],
        "glitched": (None if glitched_raw is None else True),
        "timestamp": ts,
    }


def _json_to_record(obj: dict, i: int, cr: CodeRule, rep: LoadReport) -> dict | None:
    """规范 JSONL（本包 typed 格式）→ 记录。字段名固定，不需列映射。"""
    state = obj.get("state")
    if state is None:
        _skip(rep, "missing_state")
        return None
    code_key = obj.get("code_class")
    info = cr.parse(code_key) if code_key is not None else {
        "key": None, "numeric": None, "is_token": False}
    # typed 格式的 code_class 已是"分类后"的值（含 no_response 这类哨兵）
    if info["key"] is None and code_key is not None:
        info = {"key": str(code_key), "numeric": None, "is_token": False}
    return {
        "row": obj.get("row", i),
        "state": str(state),
        "delay_raw": _to_int(obj.get("delay_raw"), rep, "delay_raw"),
        "pulse_raw": _to_int(obj.get("pulse_raw"), rep, "pulse_raw"),
        "code_key": info["key"],
        "code_numeric": info["numeric"],
        "code_is_token": info["is_token"],
        "glitched": obj.get("glitched"),
        "timestamp": obj.get("timestamp"),
    }


def _to_int(v, rep: LoadReport, field_name: str) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        _skip(rep, f"bad_{field_name}")
        return None


def _skip(rep: LoadReport, reason: str) -> None:
    rep.skipped += 1
    rep.skip_reasons[reason] = rep.skip_reasons.get(reason, 0) + 1


def _check_mapping(m: ColumnMapping, cols: Sequence[str], rep: LoadReport) -> None:
    """检查映射指向的列是否存在；缺失的记入 missing_fields（显式 unknown）。"""
    for fname in ColumnMapping.__dataclass_fields__:  # type: ignore[attr-defined]
        col = getattr(m, fname)
        if col is not None and col not in cols:
            rep.missing_fields.append(f"{fname}={col!r}（数据无此列）")


def iter_records(ds: Dataset) -> Iterator[dict]:
    return iter(ds.records)
