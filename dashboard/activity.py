"""AI 活动流：读取本机 agent 会话记录，供看板展示「AI 正在做什么」。

数据来源是 agent 自己的会话日志（JSONL，逐条追加），每条 `function_call`
记录一次工具调用（工具名 + 完整参数），对应的 `function_call_result`
给出状态与结束时间。这不是我们推测的行为，是运行时真实落盘的记录。

只读：本模块绝不写入会话日志所在目录。

边界说明（页面需一并展示）：
- 只能看到本机、本项目目录下产生的会话；跨机器或未落盘的部分为 unknown。
- 记录里的 `status` 是 agent 侧的完成状态，不代表命令在业务上成功。
- 参数可能包含路径、URL 等；默认原样展示，不做语义推断。
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SESSIONS_DIR = Path.home() / ".workbuddy-ai" / "projects" / "d-project-FI"
UNKNOWN = "unknown"

# 单次读取的最大行数上限，避免大会话文件拖慢页面（超出部分只统计不解析）。
MAX_LINES = 20000
# 明细返回条数
DETAIL_LIMIT = 60


def _parse_ts(value) -> float | None:
    """记录里 timestamp 是毫秒整数。"""
    if isinstance(value, (int, float)) and value > 1e11:
        return value / 1000.0
    return None


def _iso(epoch: float | None) -> str:
    if epoch is None:
        return UNKNOWN
    return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0).isoformat()


def _short(value, limit: int = 220) -> str:
    """参数摘要：单行、截断，保留原始文本不做解释。"""
    if value is None:
        return UNKNOWN
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            value = str(value)
    text = " ".join(value.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _args_of(record: dict) -> dict:
    raw = record.get("arguments")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"_raw": raw}
        except json.JSONDecodeError:
            return {"_raw": raw}
    return {}


def _sessions() -> list[Path]:
    if not SESSIONS_DIR.is_dir():
        return []
    files = [p for p in SESSIONS_DIR.glob("*.jsonl") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def session_summary(path: Path) -> dict:
    stat = path.stat()
    return {
        "session": path.stem,
        "modified_utc": _iso(stat.st_mtime),
        "size_bytes": stat.st_size,
        "age_seconds": max(0, int(datetime.now(timezone.utc).timestamp() - stat.st_mtime)),
    }


def read_activity(session: str | None = None) -> dict:
    """解析指定会话（默认取最近修改的），返回调用时间线与统计。"""
    files = _sessions()
    if not files:
        return {
            "available": False,
            "missing_reason": f"未找到会话记录目录 {SESSIONS_DIR}（仅本机、本项目可用）",
            "sessions": [],
        }

    listed = [session_summary(p) for p in files[:20]]
    target = files[0]
    if session:
        for candidate in files:
            if candidate.stem == session:
                target = candidate
                break

    calls: dict[str, dict] = {}
    order: list[str] = []
    pending_results: dict[str, dict] = {}
    messages: list[dict] = []
    truncated = False
    line_count = 0

    with target.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line_count += 1
            if line_count > MAX_LINES:
                truncated = True
                break
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = rec.get("type")

            if kind == "function_call":
                key = rec.get("callId") or rec.get("id") or f"anon-{line_count}"
                calls[key] = {
                    "call_id": key,
                    "tool": rec.get("name", UNKNOWN),
                    "args": _args_of(rec),
                    "started": _parse_ts(rec.get("timestamp")),
                    "model": ((rec.get("providerData") or {}).get("requestModelName") or UNKNOWN),
                    "status": "running",
                    "finished": None,
                }
                order.append(key)
                if key in pending_results:
                    _apply_result(calls[key], pending_results.pop(key))

            elif kind == "function_call_result":
                key = rec.get("callId") or rec.get("id")
                status = rec.get("status", UNKNOWN)
                done = _parse_ts(rec.get("timestamp"))
                if key and key in calls:
                    _apply_result(calls[key], {"status": status, "finished": done})
                elif key:
                    pending_results[key] = {"status": status, "finished": done}

            elif kind == "message" and rec.get("role") in {"user", "assistant"}:
                text = ""
                for part in rec.get("content") or []:
                    if isinstance(part, dict) and part.get("type") in {"input_text", "output_text", "text"}:
                        text += part.get("text", "")
                if text.strip():
                    messages.append({
                        "role": rec.get("role"),
                        "ts": _parse_ts(rec.get("timestamp")),
                        "text": _short(text, 240),
                    })

    timeline = [calls[key] for key in order if key in calls]
    for item in timeline:
        item["started_iso"] = _iso(item["started"])
        if isinstance(item["finished"], (int, float)) and isinstance(item["started"], (int, float)):
            item["duration_s"] = round(item["finished"] - item["started"], 3)
        else:
            item["duration_s"] = UNKNOWN
        item["args_preview"] = _short(
            item["args"].get("command")
            or item["args"].get("file_path")
            or item["args"].get("url")
            or item["args"].get("description")
            or json.dumps(item["args"], ensure_ascii=False)
        )

    tool_counts = Counter(item["tool"] for item in timeline)
    running = [item for item in timeline if item["status"] == "running"]
    finished = [item for item in timeline if item["status"] != "running"]
    durations = [item["duration_s"] for item in finished if isinstance(item["duration_s"], (int, float))]

    return {
        "available": True,
        "session": target.stem,
        "session_modified_utc": _iso(target.stat().st_mtime),
        "sessions": listed,
        "n_calls": len(timeline),
        "n_running": len(running),
        "n_failed": sum(1 for item in finished if item["status"] not in {"completed", "success"}),
        "tool_counts": [{"tool": name, "count": count} for name, count in tool_counts.most_common()],
        "duration": {
            "n": len(durations),
            "median_s": round(sorted(durations)[len(durations) // 2], 3) if durations else UNKNOWN,
            "max_s": round(max(durations), 3) if durations else UNKNOWN,
        },
        "running": [
            {"tool": item["tool"], "args_preview": item["args_preview"], "started_iso": item["started_iso"]}
            for item in running
        ],
        "recent": [
            {
                "tool": item["tool"],
                "status": item["status"],
                "args_preview": item["args_preview"],
                "started_iso": item["started_iso"],
                "duration_s": item["duration_s"],
                "model": item["model"],
            }
            for item in reversed(timeline[-DETAIL_LIMIT:])
        ],
        "args_by_tool": {
            name: [item["args_preview"] for item in reversed(timeline) if item["tool"] == name][:6]
            for name, _ in tool_counts.most_common(6)
        },
        "messages": messages[-6:],
        "truncated": truncated,
        "line_count": line_count,
        "discipline": (
            "来自本机会话日志的落盘记录，非推测；status 是 agent 侧完成状态，"
            "不代表命令业务成功。只覆盖本机本项目，其他来源为 unknown。"
        ),
    }


def _apply_result(call: dict, result: dict) -> None:
    call["status"] = result.get("status", UNKNOWN)
    call["finished"] = result.get("finished")


if __name__ == "__main__":
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    data = read_activity()
    print(json.dumps({k: v for k, v in data.items() if k != "sessions"}, ensure_ascii=False, indent=1)[:3000])
