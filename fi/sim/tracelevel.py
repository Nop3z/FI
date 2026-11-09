"""轨迹分级策略：off / binary / sampled / full。

## 四个级别

| 级别 | 产物 | 体积（实测 target-chip 40 万指令） | 用途 |
| --- | --- | --- | --- |
| `off` | 只有 summary.json | 0（无轨迹文件） | 批量扫描、只关心结果 |
| `binary`（默认） | trace.fitb | ≈4.5 B/指令（目标 ≤8） | 日常：完整逐指令信息 + 可读回 |
| `sampled` | trace.jsonl（每 N 条抽样） | 随 N 线性下降 | 长时间运行的粗粒度观察 |
| `full` | trace.jsonl（逐条全字段） | ≈262 B/指令 | 调试、契约比对基准 |

## sampled 的语义（重要，避免误读）

抽样的规则是"每 N 条指令落 1 条"，但**事件不被抽样丢弃**：
- 有 `mem_access.stub=true` 的指令（占位访问）——纪律要求必须记录，抽样保留；
- 所有 `fault_event` / `run_end` 行——全保留；
- 被抽样跳过的指令条数在 `run_end.detail.trace_sampling` 里显式记账
  （`skipped_by_sampling`），避免"轨迹看起来只有 4000 条"被误读成"只执行了 4000 条"。

## 为什么 binary 不是"丢信息的压缩"

`binary` 与 `full` 的**语义内容相同**（每条指令的 pc/原始字节/内存事件/CSR 事件/
证据级），只是换了表示：pc 增量 + 指令字典 + 事件位图。`fi/sim/tracebin.py` 的
`TraceReader` 能把 `.fitb` 读回成与 full 模式逐字段一致的契约行，`fi schema validate`
应能校验读回产物（见 examples 自测）。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

TRACE_LEVELS = ("off", "binary", "sampled", "full")
DEFAULT_TRACE_LEVEL = "binary"


def normalize_trace_level(level: str | None) -> str:
    """校验并归一化轨迹级别（None → 默认 binary）。"""
    if level is None:
        return DEFAULT_TRACE_LEVEL
    level = str(level).strip().lower()
    if level not in TRACE_LEVELS:
        raise ValueError(f"trace_level 必须是 {TRACE_LEVELS} 之一，收到 {level!r}")
    return level


def trace_filename(level: str) -> str | None:
    """各级别对应的轨迹文件名（off 无文件）。"""
    level = normalize_trace_level(level)
    if level == "off":
        return None
    if level == "binary":
        return "trace.fitb"
    return "trace.jsonl"


class SampledTracer:
    """抽样 JSONL 轨迹写入器（每 N 条指令 1 条，事件行全保留）。

    实现与 `fi.sim.tracer.Tracer` 相同的接口，可直接交给 Simulator。
    抽样决策在 `flush_insn` 时做（此时该指令的 mem/csr 事件已到齐），
    因此"有事件的指令"可以优先保留。
    """

    def __init__(
        self,
        path: str | Path,
        run_id: str,
        meta: dict[str, Any],
        *,
        every: int = 100,
        keep_event_insns: bool = True,
        keep_stub_insns: bool = True,
    ):
        if every <= 0:
            raise ValueError("采样间隔 every 必须 > 0")
        from .tracer import Tracer

        self._inner = Tracer(path, run_id, meta)
        self.run_id = run_id
        self.path = self._inner.path
        self.every = every
        self.keep_event_insns = keep_event_insns
        self.keep_stub_insns = keep_stub_insns
        self.stats = {
            "trace_level": "sampled",
            "sample_every": every,
            "instructions_executed": 0,
            "instructions_written": 0,
            "skipped_by_sampling": 0,
            "kept_due_to_event": 0,
            "kept_due_to_stub": 0,
        }

    # ---- Tracer 接口 ----

    def begin_insn(self, seq: int, pc: int, instruction_raw: str, disasm: str) -> None:
        self._inner.begin_insn(seq, pc, instruction_raw, disasm)

    def attach_mem(self, *args, **kwargs) -> None:
        self._inner.attach_mem(*args, **kwargs)

    def attach_csr(self, entry: dict) -> None:
        self._inner.attach_csr(entry)

    def mark_hypothesis(self) -> None:
        self._inner.mark_hypothesis()

    def flush_insn(self) -> None:
        cur = self._inner.current
        if cur is None:
            return
        self.stats["instructions_executed"] += 1
        seq = int(cur.get("seq") or 0)
        mem = cur.get("mem_access")
        has_stub = isinstance(mem, dict) and bool(mem.get("stub"))
        has_event = isinstance(mem, dict) or bool(cur.get("csrs_changed"))

        keep = (seq % self.every == 0)
        if not keep and self.keep_stub_insns and has_stub:
            keep = True
            self.stats["kept_due_to_stub"] += 1
        elif not keep and self.keep_event_insns and has_event:
            keep = True
            self.stats["kept_due_to_event"] += 1

        if keep:
            self._inner.flush_insn()
            self.stats["instructions_written"] += 1
        else:
            self._inner._cur = None  # 丢弃该行（事件已计入 kept_due_to_* 统计）
            self.stats["skipped_by_sampling"] += 1

    def fault_event(self, **kwargs) -> None:
        self._inner.flush_insn()
        self._inner.fault_event(**kwargs)

    def run_end(self, *args, **kwargs) -> None:
        self._inner.flush_insn()
        self._inner.run_end(*args, **kwargs)

    def close(self) -> None:
        self._inner.close()

    @property
    def current(self) -> dict | None:
        return self._inner.current
