"""轨迹分级策略：off / binary / sampled / full。

## 四个级别

| 级别 | 产物 | 体积（实测 target-chip 40 万指令） | 用途 |
| --- | --- | --- | --- |
| `off` | 只有 summary.json | 0（无轨迹文件） | 批量扫描、只关心结果 |
| `binary`（默认） | trace.fitb | **5.57 B/指令**（目标 ≤8，相对 full 缩 44.5×） | 日常：完整逐指令信息 + 可读回 |
| `sampled` | trace.jsonl（每 N 条抽样 + 特殊行全留） | 随 N 线性下降 | 长时间运行的粗粒度观察 |
| `full` | trace.jsonl（逐条全字段） | 247.8 B/指令 | 调试、契约比对基准 |

## sampled 的语义（重要，避免误读）

采样规则严格对齐 `docs/contracts/trace-levels.md` §5 keep_special：
- `evidence_level=hypothesis` 的行——保留（含仿真器猜测效果，不可丢）；
- `mem_access.stub=true` 的行——保留（占位值纪律）；
- `csrs_changed` 非空的行——保留（CSR 语义是逆向关键证据）；
- 停机前最后 N 条——保留（`keep_tail`，保证现场可见）；
- `fault_event` / `run_meta` / `run_end`——全保留。

**普通内存访问行（stub=false 且非 CSR、非 hypothesis）允许被抽样丢弃**，这是
sampled 相对 full 省体积的主要来源。被丢弃的条数记在 `trace_stats.skipped_by_sampling`，
采样策略登记进 `run_meta.memory_map.trace_policy`，避免"轨迹看起来只有 4000 条"
被误读成"只执行了 4000 条"。

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
    """抽样 JSONL 轨迹写入器（每 N 条指令 1 条，特殊行全保留）。

    实现与 `fi.sim.tracer.Tracer` 相同的接口，可直接交给 Simulator。
    抽样决策在 `flush_insn` 时做（此时该指令的 mem/csr 事件已到齐）。

    **特殊行定义严格对齐 `docs/contracts/trace-levels.md` §5 keep_special**：
      - `evidence_level=hypothesis` 的行（含仿真器猜测效果，不可丢）
      - `mem_access.stub=true` 的行（占位值纪律：必须记录）
      - `csrs_changed` 非空的行（CSR 语义是逆向关键证据）
      - 最后 N 条（`keep_tail`，保证停机现场可见）
    普通内存访问行（stub=false 且非 CSR、非 hypothesis）**允许被抽样丢弃**——
    这正是 sampled 相对 full 能省体积的地方；契约并未要求保留全部 mem 事件。
    """

    def __init__(
        self,
        path: str | Path,
        run_id: str,
        meta: dict[str, Any],
        *,
        every: int = 100,
        keep_tail: int = 200,
        trace_policy_sink: dict | None = None,
    ):
        if every <= 0:
            raise ValueError("采样间隔 every 必须 > 0")
        from .tracer import Tracer

        # 把采样策略登记进 run_meta（契约 §5 要求消费方知道"缺的指令是没记，不是没跑"）
        meta = dict(meta)
        memory_map = meta.get("memory_map")
        if isinstance(memory_map, dict):
            memory_map = dict(memory_map)
            policy = dict(memory_map.get("policy") or {})
            policy["trace_level"] = "sampled"
            memory_map["policy"] = policy
            memory_map["trace_policy"] = {
                "level": "sampled",
                "rule": "every_n",
                "params": {"every": every, "keep_special": True, "keep_tail": keep_tail},
                "note": "未记录的指令是'未采样'，不等于'未执行'；指令总数见 run_end.instruction_count",
            }
            meta["memory_map"] = memory_map

        self._inner = Tracer(path, run_id, meta)
        self.run_id = run_id
        self.path = self._inner.path
        self.every = every
        self.keep_tail = max(0, int(keep_tail))
        #: 最近 keep_tail 行指令（停下时补写，保证停机现场完整）
        self._tail: list[dict] = []
        self.stats = {
            "trace_level": "sampled",
            "sample_every": every,
            "keep_tail": self.keep_tail,
            "instructions_executed": 0,
            "instructions_written": 0,
            "skipped_by_sampling": 0,
            "kept_due_to_stub": 0,
            "kept_due_to_csr": 0,
            "kept_due_to_hypothesis": 0,
            "kept_due_to_interval": 0,
            "kept_from_tail": 0,
        }
        if trace_policy_sink is not None:
            trace_policy_sink.update(meta.get("memory_map", {}).get("trace_policy") or {})

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
        has_csr = bool(cur.get("csrs_changed"))
        is_hyp = cur.get("evidence_level") == "hypothesis"

        # 契约 §5 keep_special：以下行永不因抽样丢弃
        keep_reason = None
        if has_stub:
            keep_reason = "kept_due_to_stub"
        elif has_csr:
            keep_reason = "kept_due_to_csr"
        elif is_hyp:
            keep_reason = "kept_due_to_hypothesis"
        elif seq % self.every == 0:
            keep_reason = "kept_due_to_interval"

        if keep_reason:
            self._inner.flush_insn()
            self.stats["instructions_written"] += 1
            self.stats[keep_reason] += 1
            if self.keep_tail:
                self._tail.append(cur)
                if len(self._tail) > self.keep_tail:
                    self._tail.pop(0)
        else:
            self._inner._cur = None  # 丢弃该行（不是"未执行"）
            self.stats["skipped_by_sampling"] += 1
            if self.keep_tail:
                self._tail.append(cur)
                if len(self._tail) > self.keep_tail:
                    self._tail.pop(0)

    def _flush_tail(self) -> None:
        """停机时补写最后 N 条指令行（保证停机现场可见；可能重复已写行，去重）。"""
        if not self.keep_tail or not self._tail:
            return
        written_seqs = getattr(self, "_written_seqs", None)
        if written_seqs is None:
            written_seqs = set()
            self._written_seqs = written_seqs
        for row in self._tail:
            seq = int(row.get("seq") or 0)
            if seq in written_seqs:
                continue
            written_seqs.add(seq)
            self._inner._cur = row
            self._inner.flush_insn()
            self.stats["instructions_written"] += 1
            self.stats["kept_from_tail"] += 1
        self._tail = []

    def fault_event(self, **kwargs) -> None:
        self._inner.flush_insn()
        self._inner.fault_event(**kwargs)

    def run_end(self, *args, **kwargs) -> None:
        self._flush_tail()   # 停机现场补写（契约 §5：exit 前最后 N 条必留）
        self._inner.flush_insn()
        self._inner.run_end(*args, **kwargs)

    def close(self) -> None:
        self._inner.close()

    @property
    def current(self) -> dict | None:
        return self._inner.current
