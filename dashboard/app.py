"""FI Dashboard 后端 API（重写版）。

单一职责的只读 HTTP 服务：
- 转发技术团队已算好的派生数据（data/derived/*.json）
- 流式分页读取实验 CSV（data/derived/<dataset>.csv；数据集前缀支持
  FI_DATASET_PREFIX 环境变量与 ?dataset= 查询参数动态选择，见 /api/datasets）
- 转发 AI 活动流（dashboard/activity.py）
- 暴露契约版本信息（docs/contracts/）
- 静态文件服务（dashboard/static/index.html）

展示纪律（与技术团队契约对齐，不得违反）：
- 状态标签按原始字面量展示（FL/HANG/SUCCESS/UNEXPECTED/Fake_Success），
  语义标注为 unconfirmed-v0.1；
- 单位换算 ns = raw * 10 是未证实假设 A1，任何 ns 数值必须带此标注；
- 证据等级 observation/hypothesis/unknown/fact 原样透传，不改写；
- 缺数据写 unknown 或给出 missing_reason，不用 0/空串冒充；
- 只读服务：不写任何数据文件，不提供实验控制接口。

纯标准库实现（http.server + csv + json），不依赖 pandas。

CSV 尾窗读取复用 dashboard/vendor/viewviewview/ 的 _TailReader（O(limit) 内存）；
vendor 缺失或深分页时回退到内置标准库流式扫描，行为一致。
"""

# 基于 ViewViewView (https://github.com/Nop3z/ViewViewView) 的代码修改/复制而来。
# 原项目以 MulanPSL-2.0 (http://license.coscl.org.cn/MulanPSL2) 许可。
# 本文件按 MulanPSL-2.0 第 4 条保留原版权与许可声明。

from __future__ import annotations

import csv
import json
import os
import re
import sys
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

# 让 `python dashboard/app2.py` 与模块导入两种方式都能找到 activity.py
_APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_APP_DIR))
import activity  # noqa: E402  (本目录现成模块，直接复用)

# 复用 vendor 的 _TailReader（纯标准库尾窗读取）；目录缺失时回退内置实现。
_VENDOR_SRC = _APP_DIR / "vendor" / "viewviewview" / "src"
if _VENDOR_SRC.is_dir():
    sys.path.insert(0, str(_VENDOR_SRC))
try:
    from viewviewview.core import _TailReader  # type: ignore  # noqa: E402

    TAIL_READER_SOURCE = "viewviewview._TailReader (MulanPSL-2.0, vendor/viewviewview)"
except ImportError:  # pragma: no cover - vendor 未就位时的兼容路径
    _TailReader = None
    TAIL_READER_SOURCE = "stdlib-csv-stream"

BASE_DIR = Path(__file__).resolve().parent.parent
DERIVED_DIR = BASE_DIR / "data" / "derived"
CONTRACTS_DIR = BASE_DIR / "docs" / "contracts"
SCHEMAS_DIR = CONTRACTS_DIR / "schemas"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# ---------------------------------------------------------------------------
# 数据集参数化：所有派生数据文件都按「数据集前缀」定位（<prefix>.csv、
# <prefix>.state-counts.json 等）。代码不写死任何具体数据集名；换数据集
# 不改代码、不重启服务：AI 直接用 ?dataset= 查询参数（见 /api/datasets）。
# ---------------------------------------------------------------------------

DATASET_ENV_VAR = "FI_DATASET_PREFIX"
DATASET_FALLBACK_PREFIX = "dataset"
# 白名单：字母数字开头，仅含 [A-Za-z0-9._-]，长度 ≤ 64；额外禁止 ".."（防路径穿越）。
_DATASET_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_STATE_COUNTS_TAIL = ".state-counts.json"


def _validate_dataset(prefix):
    """数据集前缀白名单校验；不合法（含 ".." 路径穿越尝试）返回 None。"""
    if not isinstance(prefix, str) or not prefix or ".." in prefix:
        return None
    if not _DATASET_PREFIX_RE.fullmatch(prefix):
        return None
    return prefix


def _scan_dataset_prefixes() -> list[str]:
    """扫描现存数据集前缀，取词干并集，返回排序列表。

    来源：data/derived/*.state-counts.json、data/derived/*.csv、项目根目录 *.csv。
    候补词干需通过 _validate_dataset 白名单（顺带排除 `_` 开头的调试/合成
    产物，与 sync.py 的 skip 约定一致），无效词干不进入数据集清单。
    """
    prefixes: set[str] = set()
    for path in DERIVED_DIR.glob(f"*{_STATE_COUNTS_TAIL}"):
        prefixes.add(_validate_dataset(path.name[: -len(_STATE_COUNTS_TAIL)]) or "")
    for path in DERIVED_DIR.glob("*.csv"):
        prefixes.add(_validate_dataset(path.stem) or "")
    for path in BASE_DIR.glob("*.csv"):
        prefixes.add(_validate_dataset(path.stem) or "")
    prefixes.discard("")
    return sorted(prefixes)


def _resolve_active_prefix() -> str:
    """活跃前缀三级优先级：FI_DATASET_PREFIX → 扫描结果恰有一个数据集 → 兜底。

    每次请求时重新解析（开销仅为两次目录 glob）：环境变量在进程内不变，
    但新数据集文件落盘后无需重启即可被扫描到并通过 ?dataset= 选用；
    恰有一个数据集时自动选中，保证主仓开箱即用。
    """
    env_value = os.environ.get(DATASET_ENV_VAR, "").strip()
    if env_value and _validate_dataset(env_value):
        return env_value
    scanned = _scan_dataset_prefixes()
    if len(scanned) == 1:
        return scanned[0]
    return DATASET_FALLBACK_PREFIX


def _resolve_dataset_paths(prefix: str) -> dict:
    """某前缀的数据文件路径组。

    实验记录 CSV：契约描述在 data/derived/ 下，实际批次文件可能也在项目根目录，
    两处都作为候选，以实际存在者为准（meta.json inputs.csv.path 指向根目录文件）。
    """
    return {
        "csv_candidates": [
            DERIVED_DIR / f"{prefix}.csv",
            BASE_DIR / f"{prefix}.csv",
        ],
        "state_counts": DERIVED_DIR / f"{prefix}.state-counts.json",
        "histograms": DERIVED_DIR / f"{prefix}.delay-pulse-histograms.json",
        "meta": DERIVED_DIR / f"{prefix}.meta.json",
    }


def _pick_csv_path(paths: dict) -> Path:
    """从 csv 候选中取第一个实际存在者；都不存在时返回首个候选（供 404 报因）。"""
    candidates = paths["csv_candidates"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def _dataset_param(query: dict):
    """解析 ?dataset=：缺省=活跃前缀。

    返回 (prefix, None)；显式给出但不合法时返回 (None, (body, 400))，
    body 结构与既有错误惯例一致（generated_utc / data_source / error / missing_reason）。
    """
    raw = query.get("dataset", [None])[0]
    if raw is None or raw == "":
        return _resolve_active_prefix(), None
    prefix = _validate_dataset(raw)
    if prefix is None:
        body = base_envelope("none")
        body.update({"error": "invalid_dataset", "missing_reason": "dataset 参数不合法"})
        return None, (body, 400)
    return prefix, None


def _dataset_missing(missing_reason: str):
    """数据集所需文件缺失的结构化 404（不裸 500）。"""
    body = base_envelope("none")
    body.update({"error": "dataset_missing", "missing_reason": missing_reason})
    return body, 404
CHANGELOG_PATH = CONTRACTS_DIR / "CHANGELOG.md"
STATUS_SEMANTICS_PATH = CONTRACTS_DIR / "status-semantics.md"
COMMON_DEFS_PATH = SCHEMAS_DIR / "common.defs.json"
# sync.py 的产物：交付物指纹台账 / 变更 / 未展示清单 / 实例版本告警。
# 只读转发，供 /api/contracts 如实呈现「历史实例未重生成」等告警。
SYNC_STATUS_PATH = _APP_DIR / "generated" / "status.json"

HOST = "127.0.0.1"
PORT = 8765

# 单位假设 A1：ns = raw * 10，未证实。任何 ns 数值都必须带此标注。
UNIT_ASSUMPTION_NOTE = (
    "ns = raw * 10 为未证实假设 A1（meta.json assumptions[A1].status=unverified），"
    "所有 ns 数值仅按此假设换算展示，不代表实测确认。"
)

STATE_LABEL_SEMANTICS = "unconfirmed-v0.1"

DEFAULT_LIMIT = 50
MAX_LIMIT = 500

SESSION_ID_RE = re.compile(r"[0-9a-f-]+")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".map": "application/json; charset=utf-8",
}


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class JsonCache:
    """小 JSON 文件的 mtime 缓存，避免每个请求重复读盘/解析。"""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, object]] = {}

    def load(self, path: Path):
        key = str(path)
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        hit = self._cache.get(key)
        if hit is not None and hit[0] == mtime:
            return hit[1]
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return None
        self._cache[key] = (mtime, data)
        return data


_JSON_CACHE = JsonCache()


def load_json(path: Path):
    return _JSON_CACHE.load(path)


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def base_envelope(data_source) -> dict:
    return {"generated_utc": now_utc_iso(), "data_source": data_source}


# ---------------------------------------------------------------------------
# /api/records：CSV 分页（按数据行号倒序，最新在上）
#
# 读取策略：
# - 无 state 过滤且窗口完全落在文件尾部：用 _TailReader（O(limit) 内存，最快）；
# - 有 state 过滤或深分页：流式扫描一遍，只保留匹配窗口（内存仍恒定）；
# - 总数一律来自 state-counts.json（技术团队已算好），不扫 CSV 计数。
# ---------------------------------------------------------------------------

def csv_scan_count(csv_path: Path, state_filter: str | None) -> int:
    """统计匹配行数（仅当 state-counts.json 缺失时兜底使用）。"""
    total = 0
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        next(reader, None)  # header
        if state_filter is None:
            total = sum(1 for _ in reader)
        else:
            for row in reader:
                if row and row[0] == state_filter:
                    total += 1
    return total


def _tail_records(csv_path: Path, limit: int, total_matched: int) -> list[dict] | None:
    """取最新 limit 条（尾窗），返回按行号倒序的记录；失败返回 None。

    _TailReader 返回文件尾部 limit 条（文件顺序），行号需加上
    「数据总行数 - 窗口条数」偏移才是全文件 1 起始行号。
    """
    if _TailReader is None:
        return None
    try:
        _header, rows = _TailReader(str(csv_path)).read(limit)
    except (OSError, ValueError):
        return None  # 坏行等异常走内置流式路径，不让单请求 500
    first_row_index = total_matched - len(rows) + 1
    records = [
        _row_to_record(first_row_index + i, row)
        for i, row in enumerate(rows)
    ]
    records.reverse()
    return records


def _stream_window(csv_path: Path, total_matched: int, offset: int, limit: int, state_filter: str | None):
    """流式扫描取「匹配行中倒数第 offset+1 .. offset+limit 条」，倒序输出。"""
    skip = max(0, total_matched - offset - limit)
    records: list[dict] = []
    seen_matched = 0
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        next(reader, None)  # header
        for row_index, row in enumerate(reader, start=1):
            if not row:
                continue
            if state_filter is not None and row[0] != state_filter:
                continue
            if seen_matched >= skip:
                records.append(_row_to_record(row_index, row))
                if len(records) >= limit:
                    break
            seen_matched += 1
    records.reverse()
    return records


def _row_to_record(row_index: int, row: list[str]) -> dict:
    """CSV 行 → API 记录。row_index 为 1 起始数据行号（不含表头）。"""
    return {
        "row_index": row_index,
        "state": row[0] if len(row) > 0 else "",
        "delay": _to_int_or_raw(row[1] if len(row) > 1 else ""),
        "pulse": _to_int_or_raw(row[2] if len(row) > 2 else ""),
        "response": row[3] if len(row) > 3 else "",
        "glitched": row[4] if len(row) > 4 else "",
        "unexpected": row[5] if len(row) > 5 else "",
    }


def _to_int_or_raw(value: str):
    """delay/pulse 原始值为整数则转 int，否则保留原始字符串（不做猜测）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def api_records(query: dict) -> tuple[dict, int]:
    limit = _parse_int_param(query, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT)
    if limit is None:
        return _bad_request("limit 必须是 1..500 的整数")
    offset = _parse_int_param(query, "offset", 0, 0, None)
    if offset is None:
        return _bad_request("offset 必须是非负整数")
    state_filter = query.get("state", [None])[0]
    prefix, err = _dataset_param(query)
    if err is not None:
        return err

    paths = _resolve_dataset_paths(prefix)
    csv_path = _pick_csv_path(paths)
    if not csv_path.is_file():
        return _dataset_missing(f"{prefix}.csv（data/derived/ 与项目根目录均未找到）")

    # 总数来自 state-counts.json（技术团队已算好），缺失时才兜底流式计数。
    state_counts_doc = load_json(paths["state_counts"])
    if state_filter:
        known = None
        if isinstance(state_counts_doc, dict):
            known = (state_counts_doc.get("states") or {}).get(state_filter)
        if isinstance(known, dict) and isinstance(known.get("count"), int):
            total_matched = known["count"]
        else:
            total_matched = csv_scan_count(csv_path, state_filter)
    else:
        total_matched = None
        if isinstance(state_counts_doc, dict):
            total_matched = state_counts_doc.get("total_rows")
        if not isinstance(total_matched, int):
            total_matched = csv_scan_count(csv_path, None)

    read_mode = "stream-scan"
    if offset >= total_matched:
        records: list[dict] = []
    elif not state_filter and offset == 0:
        # 首屏最新窗口：_TailReader 尾窗读取，O(limit) 内存，不全扫文件
        tail = _tail_records(csv_path, limit, total_matched)
        if tail is not None:
            records = tail
            read_mode = TAIL_READER_SOURCE
        else:
            records = _stream_window(csv_path, total_matched, offset, limit, state_filter)
    else:
        records = _stream_window(csv_path, total_matched, offset, limit, state_filter)

    body = base_envelope(str(csv_path.relative_to(BASE_DIR)))
    body.update({
        "dataset": prefix,
        "total_matched": total_matched,
        "offset": offset,
        "limit": limit,
        "state_filter": state_filter,
        "read_mode": read_mode,
        "row_index_meaning": "1 起始的数据行号（不含表头），按行号倒序即最新在上",
        "records": records,
    })
    # 兼容别名：前端早期按 rows/total 读取。语义与 records/total_matched 完全一致，
    # 保留两个名字只为避免旧页面静默空白；新代码请用 records/total_matched。
    body["rows"] = records
    body["total"] = total_matched
    return body, 200


def _parse_int_param(query: dict, name: str, default: int, minimum: int, maximum):
    raw = query.get(name, [None])[0]
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return None
    if value < minimum:
        return None
    if maximum is not None and value > maximum:
        return None
    return value


def _bad_request(reason: str):
    body = base_envelope("none")
    body.update({"error": "bad_request", "reason": reason})
    return body, 400


def _contract_version() -> dict:
    """契约包版本与 schema_version 常量（同步判断，供 summary/contracts 共用）。"""
    changelog_text = read_text(CHANGELOG_PATH)
    version = None
    if changelog_text:
        entries = _parse_changelog(changelog_text)
        if entries:
            version = entries[0]["version"]
    defs_doc = load_json(COMMON_DEFS_PATH)
    const = None
    if isinstance(defs_doc, dict):
        const = (((defs_doc.get("$defs") or {}).get("schema_version") or {}).get("const"))
    return {
        "version": version,
        "schema_version_constant": const,
        "state_label_semantics": STATE_LABEL_SEMANTICS,
        # minor 新增允许不 bump 常量：包版本高于常量属正常，不作为告警
        "note": "包版本=CHANGELOG 最新小节；常量为 schemas/common.defs.json 的 $defs.schema_version.const。"
                "minor 新增不 bump 常量，故包版本高于常量是正常的。",
    }


# ---------------------------------------------------------------------------
# /api/datasets：数据集清单与当前活跃前缀（不依赖任何数据集文件本身）
#
# 无数据时返回空 datasets 列表，不报错；has_* 以文件存在性实时判定，
# 故新数据集落盘后无需重启即出现在清单中。
# ---------------------------------------------------------------------------

def api_datasets() -> tuple[dict, int]:
    body = base_envelope("service")
    prefixes = _scan_dataset_prefixes()
    # 环境变量固定的前缀即使扫描不到（如该数据集尚无 csv/state-counts 产物）
    # 也列入清单，避免出现 active 不在 datasets 里的费解状态。
    env_value = os.environ.get(DATASET_ENV_VAR, "").strip()
    env_prefix = _validate_dataset(env_value)
    if env_prefix and env_prefix not in prefixes:
        prefixes = sorted([env_prefix, *prefixes])
    entries = []
    for prefix in prefixes:
        paths = _resolve_dataset_paths(prefix)
        entries.append({
            "prefix": prefix,
            "has_csv": any(candidate.is_file() for candidate in paths["csv_candidates"]),
            "has_state_counts": paths["state_counts"].is_file(),
            "has_histograms": paths["histograms"].is_file(),
            "has_meta": paths["meta"].is_file(),
        })
    body.update({
        "readonly": True,
        "active": _resolve_active_prefix(),
        "datasets": entries,
    })
    return body, 200


# ---------------------------------------------------------------------------
# /api/summary 与 /api/histogram：转发派生 JSON，不重算
# ---------------------------------------------------------------------------

def api_summary(query: dict) -> tuple[dict, int]:
    prefix, err = _dataset_param(query)
    if err is not None:
        return err
    paths = _resolve_dataset_paths(prefix)
    if not paths["state_counts"].is_file():
        return _dataset_missing(f"{prefix}.state-counts.json（data/derived/ 下未找到）")
    state_counts = load_json(paths["state_counts"])
    meta = load_json(paths["meta"])
    histograms = load_json(paths["histograms"])
    contract = _contract_version()

    if state_counts is None:
        body = base_envelope(str(paths["state_counts"].relative_to(BASE_DIR)))
        body.update({"error": "data_missing", "missing_reason": f"无法读取 {paths['state_counts'].name}"})
        return body, 500

    body = base_envelope({
        "state_counts": str(paths["state_counts"].relative_to(BASE_DIR)),
        "meta": str(paths["meta"].relative_to(BASE_DIR)),
        "histograms": str(paths["histograms"].relative_to(BASE_DIR)),
    })
    body["dataset"] = prefix
    body.update({
        "total_rows": state_counts.get("total_rows") if isinstance(state_counts, dict) else None,
        # 状态标签为原始字面量，语义未证实（unconfirmed-v0.1），不做业务化改写
        "state_label_semantics": STATE_LABEL_SEMANTICS,
        "states": state_counts.get("states") if isinstance(state_counts, dict) else None,
        "meta": meta,
        "histograms": histograms,
        "unit_assumption": UNIT_ASSUMPTION_NOTE,
        # 包版本 = CHANGELOG 最新小节；常量 = common.defs.json 的 $defs.schema_version.const。
        # 两者不等是允许的（minor 新增不 bump 常量），页面据此区分「正常」与「实例落后」。
        "contract": contract,
    })
    # 兼容别名：页面按 total 读取行数（与 total_rows 同值，不是另算）
    body["total"] = body["total_rows"]
    return body, 200


def api_histogram(query: dict) -> tuple[dict, int]:
    prefix, err = _dataset_param(query)
    if err is not None:
        return err
    paths = _resolve_dataset_paths(prefix)
    histograms_path = paths["histograms"]
    if not histograms_path.is_file():
        return _dataset_missing(f"{prefix}.delay-pulse-histograms.json（data/derived/ 下未找到）")
    histograms = load_json(histograms_path)
    body = base_envelope(str(histograms_path.relative_to(BASE_DIR)))
    body["dataset"] = prefix
    if histograms is None:
        body.update({"error": "data_missing", "missing_reason": f"无法读取 {histograms_path.name}"})
        return body, 500
    body.update({
        "histograms": histograms,
        "unit_assumption": UNIT_ASSUMPTION_NOTE,
    })
    # 图表消费用的规范视图：按状态聚合 {raw: count} → [{state,total,points[]}]，
    # 点数不设上限、不做重采样；缺某状态就不出现在 series 里（页面显示 unknown，不画 0 柱）。
    series = _histogram_series(histograms)
    body["series"] = series
    # 兼容别名：页面按 histogram.series / axis 读取，与顶层结构同源同值。
    body["histogram"] = {"series": series, "axis": {"unit": "delay_raw"}}
    body["axis"] = {
        "unit": "delay_raw",
        "ns_note": "ns = raw × 10（假设 A1，未证实）",
    }
    return body, 200


def _histogram_series(histograms) -> list[dict]:
    """把 delay_counts_by_state 摊平成图表点序列，保持原始桶值不改写单位。"""
    if not isinstance(histograms, dict):
        return []
    counts = histograms.get("delay_counts_by_state")
    if not isinstance(counts, dict):
        return []
    series: list[dict] = []
    for state, buckets in counts.items():
        if not isinstance(buckets, dict):
            continue
        points = []
        for raw, count in buckets.items():
            try:
                raw_int = int(raw)
            except (TypeError, ValueError):
                continue
            if isinstance(count, int) and count > 0:
                points.append({"delay_raw": raw_int, "count": count})
        points.sort(key=lambda p: p["delay_raw"])
        series.append({
            "state": state,
            "total": sum(p["count"] for p in points),
            "bucket_count": len(points),
            "delay_raw_range": [points[0]["delay_raw"], points[-1]["delay_raw"]] if points else None,
            "points": points,
        })
    series.sort(key=lambda s: s["total"], reverse=True)
    return series


# ---------------------------------------------------------------------------
# /api/activity：转发 dashboard/activity.py，session 参数白名单过滤
# ---------------------------------------------------------------------------

def api_activity(query: dict) -> tuple[dict, int]:
    session = query.get("session", [None])[0]
    if session is not None:
        if not SESSION_ID_RE.fullmatch(session):
            return _bad_request("session 仅允许字符 [0-9a-f-]")
    try:
        data = activity.read_activity(session)
    except Exception as exc:  # 活动流是辅助数据，读失败不拖垮整个接口
        body = base_envelope("~/.workbuddy-ai/projects/d-project-FI/*.jsonl")
        body.update({
            "available": False,
            "missing_reason": f"unknown：读取活动流失败（{type(exc).__name__}）",
        })
        return body, 200
    body = base_envelope("~/.workbuddy-ai/projects/d-project-FI/*.jsonl（本机会话日志，经 dashboard/activity.py 读取）")
    body.update(data)
    return body, 200


# ---------------------------------------------------------------------------
# /api/contracts：契约版本、schema 常量、状态语义、未登记告警
# ---------------------------------------------------------------------------

_VERSION_HEAD = re.compile(r"^## \[([^\]]+)\]\s*-\s*(\S+)\s*(.*)$", re.M)
_DASHBOARD_IMPACT = re.compile(r"^###\s+Dashboard 影响\s*$", re.M)


def _parse_changelog(text: str) -> list[dict]:
    """按 `## [version] - date (title)` 切分版本小节。"""
    heads = list(_VERSION_HEAD.finditer(text))
    entries: list[dict] = []
    for i, match in enumerate(heads):
        start = match.end()
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        entries.append({
            "version": match.group(1),
            "date": match.group(2),
            "title": match.group(3).strip().strip("（）。()"),
            "body": text[start:end].strip(),
        })
    return entries


def _dashboard_impact_section(body: str) -> str | None:
    match = _DASHBOARD_IMPACT.search(body)
    if match is None:
        return None
    rest = body[match.end():]
    nxt = re.search(r"^###\s+", rest, re.M)
    section = rest[: nxt.start()] if nxt else rest
    return section.strip()


def api_contracts() -> tuple[dict, int]:
    changelog_text = read_text(CHANGELOG_PATH)
    defs_doc = load_json(COMMON_DEFS_PATH)
    status_text = read_text(STATUS_SEMANTICS_PATH)
    # 与数据集无参数关联（不接受 ?dataset=），沿用当前活跃前缀的批次 meta。
    active_paths = _resolve_dataset_paths(_resolve_active_prefix())
    meta = load_json(active_paths["meta"])

    body = base_envelope({
        "changelog": "docs/contracts/CHANGELOG.md",
        "schema_version_const": "docs/contracts/schemas/common.defs.json",
        "status_semantics": "docs/contracts/status-semantics.md",
        "schemas_dir": "docs/contracts/schemas/",
    })

    schema_version_const = None
    if isinstance(defs_doc, dict):
        node = ((defs_doc.get("$defs") or {}).get("schema_version") or {})
        schema_version_const = node.get("const")

    versions: list[dict] = []
    if changelog_text:
        for entry in _parse_changelog(changelog_text):
            impact = _dashboard_impact_section(entry["body"])
            versions.append({
                "version": entry["version"],
                "date": entry["date"],
                "title": entry["title"],
                "dashboard_impact_md": impact,
                "dashboard_impact_available": impact is not None,
            })
    body["schema_version_const"] = schema_version_const
    body["changelog_latest"] = versions[0] if versions else None
    body["recent_dashboard_impacts"] = [
        {"version": v["version"], "date": v["date"], "dashboard_impact_md": v["dashboard_impact_md"]}
        for v in versions[:3]
        if v["dashboard_impact_md"] is not None
    ]

    # 状态语义：标签待确认（unconfirmed-v0.1），字面量列表来自批次 meta 的 known_labels
    known_labels = None
    if isinstance(meta, dict):
        known_labels = (meta.get("run_config") or {}).get("known_labels")
    body["status_semantics"] = {
        "label_semantics": STATE_LABEL_SEMANTICS,
        "state_labels_raw": known_labels,
        "note": "状态标签按原始字面量展示，语义标注为候选/待确认，不得改写为业务语义",
        "doc_title": status_text.splitlines()[0].lstrip("# ").strip() if status_text else None,
    }

    # schema 文件清单 + 未登记告警（在 schemas/ 但 CHANGELOG 未提及）
    schema_files: list[str] = []
    unregistered: list[str] = []
    if SCHEMAS_DIR.is_dir():
        schema_files = sorted(p.name for p in SCHEMAS_DIR.glob("*.json"))
        if changelog_text:
            unregistered = [name for name in schema_files if name not in changelog_text]
    body["schema_files"] = schema_files
    body["unregistered_schemas"] = unregistered
    if unregistered:
        body["unregistered_warning"] = (
            "以下 schema 文件存在于 schemas/ 但 CHANGELOG.md 未提及，"
            "可能未完成登记流程，引用前请与契约维护方确认：" + "、".join(unregistered)
        )
    else:
        body["unregistered_warning"] = None

    # ---- sync.py 台账：实例版本 / 未展示产物（只读转发，不改判定） ----
    sync_doc = load_json(SYNC_STATUS_PATH)
    sync_block = None
    instance_versions: dict[str, str] = {}
    drift: dict[str, str] = {}
    if isinstance(sync_doc, dict):
        changes = sync_doc.get("changes") or {}
        artifacts = sync_doc.get("artifacts") or {}
        instance_versions = sync_doc.get("instance_versions") or {}
        sync_block = {
            "generated_utc": sync_doc.get("generated_utc"),
            "tracked_count": changes.get("tracked_count"),
            "changed": changes.get("changed") or [],
            "removed": changes.get("removed") or [],
            "unconsumed": artifacts.get("unconsumed") or [],
            "warnings": sync_doc.get("warnings") or [],
        }
        # 版本判断规则：包版本（CHANGELOG 最新小节）可以高于常量（minor 新增允许不 bump）；
        # 只有「派生实例 schema_version < 常量」才代表历史实例未重生成，需如实标出。
        if schema_version_const:
            drift = {
                name: ver for name, ver in instance_versions.items()
                if str(ver) != str(schema_version_const)
            }

    # 页面消费的扁平字段（与 /api/contracts 既有字段并存，不删旧键）
    warnings: list[str] = []
    if body["unregistered_warning"]:
        warnings.append(body["unregistered_warning"])
    if drift:
        warnings.append(
            "派生实例 schema_version 落后于常量 " + str(schema_version_const) +
            "（历史实例未重生成）：" +
            "、".join(f"{name}={ver}" for name, ver in sorted(drift.items()))
        )
    body["contract_version"] = versions[0]["version"] if versions else None
    body["schema_version_constant"] = schema_version_const
    body["state_label_semantics"] = STATE_LABEL_SEMANTICS
    body["schemas"] = schema_files
    body["recent_versions"] = [
        {"version": v["version"], "date": v["date"], "note": v["title"]}
        for v in versions[:5]
    ]
    body["warnings"] = warnings
    body["instance_versions"] = instance_versions
    body["instance_version_drift"] = drift
    body["sync"] = sync_block
    return body, 200


# ---------------------------------------------------------------------------
# 静态文件
# ---------------------------------------------------------------------------

def serve_static(rel_path: str):
    if not STATIC_DIR.is_dir():
        return None, 404
    rel_path = rel_path.lstrip("/")
    if not rel_path:
        rel_path = "index.html"
    base = STATIC_DIR.resolve()
    target = (base / rel_path).resolve()
    if not target.is_relative_to(base):
        return None, 403
    if not target.is_file():
        index = base / "index.html"
        if rel_path == "" or not index.is_file():
            return None, 404
        target = index
    content_type = CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream")
    try:
        data = target.read_bytes()
    except OSError:
        return None, 404
    return (data, content_type), 200


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "FI-Dashboard/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 日志静默
        pass

    # -- 输出辅助 -----------------------------------------------------------

    def _send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self._common_headers()
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, data: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self._common_headers()
        self.end_headers()
        self.wfile.write(data)

    def _common_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")

    def _send_error_json(self, status: int, reason: str) -> None:
        body = base_envelope("none")
        body.update({"error": f"http_{status}", "reason": reason})
        self._send_json(body, status)

    # -- 路由 ---------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (http.server 命名约定)
        try:
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            query = parse_qs(parsed.query)

            if path == "/api/health":
                body = base_envelope("service")
                body.update({"status": "ok", "service": "fi-dashboard", "readonly": True})
                self._send_json(body)
            elif path == "/api/datasets":
                payload, status = api_datasets()
                self._send_json(payload, status)
            elif path == "/api/summary":
                payload, status = api_summary(query)
                self._send_json(payload, status)
            elif path == "/api/records":
                payload, status = api_records(query)
                self._send_json(payload, status)
            elif path == "/api/histogram":
                payload, status = api_histogram(query)
                self._send_json(payload, status)
            elif path == "/api/activity":
                payload, status = api_activity(query)
                self._send_json(payload, status)
            elif path == "/api/contracts":
                payload, status = api_contracts()
                self._send_json(payload, status)
            elif path == "/" or path.startswith("/static/"):
                rel = path[len("/static/"):] if path.startswith("/static/") else ""
                result = serve_static(rel)
                if result[1] != 200:
                    self._send_error_json(result[1], f"静态文件不存在：{path}")
                    return
                (data, content_type), status = result
                self._send_bytes(data, content_type, status)
            else:
                self._send_error_json(404, f"未知路径：{path}（可用：/api/health, /api/datasets, /api/summary, "
                                           "/api/records, /api/histogram, /api/activity, /api/contracts, /）")
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001 单请求异常不拖垮服务
            try:
                self._send_error_json(500, f"{type(exc).__name__}: {exc}")
            except Exception:
                pass


def main(argv: list[str]) -> int:
    port = PORT
    if len(argv) > 1:
        try:
            port = int(argv[1])
        except ValueError:
            print(f"无效端口：{argv[1]}", file=sys.stderr)
            return 2
    server = ThreadingHTTPServer((HOST, port), DashboardHandler)
    print(f"FI Dashboard API listening on http://{HOST}:{port} (readonly)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main(sys.argv))
