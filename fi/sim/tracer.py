"""JSONL 轨迹落盘。

行类型与 docs/contracts/schemas/sim-trace.schema.json（core-contract 起草中）对齐：
- run_meta   首行，run 元数据（配置回显/引擎版本/映射/补丁），重放所需
- trace      每条指令一行：seq/pc/instruction_raw/disasm/mem_access/csrs_changed/
             writeback/evidence_level
- fault_event 每次注入触发一行：trigger/action/applied/applied_at_seq
- run_end    末行：exit_reason/final_pc/instruction_count/detail

证据纪律：
- evidence_level ∈ {observation, hypothesis}（行级，取该行最弱级）；
- WARL 处理（写忽略/读占位0）、占位设备访问（stub=true）→ hypothesis；
- 值缺失/未知一律字符串 "unknown"，禁止 null 或 0 冒充。

字段注记：disasm / mem_access.stub / mem_access.region / csrs_changed[].warl /
fault_event.applied_at_seq 为 sim-engine 向 core-contract 提议的新增字段，
契约定稿后以 schema 为准（见 docs/sim/trace-format-v0.md）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA = "fi.sim.trace-v0"
UNKNOWN = "unknown"


class Tracer:
    def __init__(self, path: str | Path, run_id: str, meta: dict[str, Any]):
        self.path = Path(path)
        self.run_id = run_id
        self._f = self.path.open("w", encoding="utf-8", newline="\n")
        # meta 必须已符合 sim-trace.schema.json 的 run_meta 形状（本类不再附加字段）
        self._emit(meta)

    def _emit(self, obj: dict) -> None:
        self._f.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")

    # ---- trace 行（缓冲：指令的 mem/csr 事件在其执行过程中陆续到达，末尾统一落盘） ----

    def begin_insn(self, seq: int, pc: int, instruction_raw: str, disasm: str) -> None:
        self.flush_insn()
        self._cur = {
            "type": "trace",
            "run_id": self.run_id,
            "seq": seq,
            "pc": pc,
            "instruction_raw": instruction_raw,
            "disasm": disasm,
            "mem_access": UNKNOWN,
            "csrs_changed": [],
            "writeback": UNKNOWN,
            "evidence_level": "observation",
        }

    def attach_mem(
        self,
        kind: str,
        addr: int,
        size: int,
        value: int | str,
        region: str,
        stub: bool,
        unmapped: bool = False,
    ) -> None:
        if self._cur is None:
            return
        note = (
            "占位访问：值由仿真器 stub 产生，非硬件观测" if stub and not unmapped else
            "unmapped 动态占位页：仿真器零页占位，非硬件观测" if unmapped else
            "unknown"
        )
        self._cur["mem_access"] = {
            "kind": kind,
            "addr": addr,
            "size": size,
            "value": value,
            "stub": stub,
            "region": region,
            "note": note,
            **({"unmapped": True} if unmapped else {}),
        }
        if stub:
            self._cur["evidence_level"] = "hypothesis"

    def attach_csr(self, entry: dict) -> None:
        if self._cur is None:
            return
        self._cur["csrs_changed"].append(entry)

    def mark_hypothesis(self) -> None:
        """行级证据降级为 hypothesis（说明文字放事件对象内，契约行无 note 字段）。"""
        if self._cur is None:
            return
        self._cur["evidence_level"] = "hypothesis"

    def flush_insn(self) -> None:
        if getattr(self, "_cur", None) is not None:
            self._emit(self._cur)
            self._cur = None

    # ---- fault_event 行 ----

    def fault_event(
        self,
        event_id: str,
        campaign_id: str,
        trigger: dict,
        action: dict,
        applied: bool,
        applied_at_seq: int,
        applied_result: dict | str = "unknown",
    ) -> None:
        self._emit(
            {
                "type": "fault_event",
                "event_id": event_id,
                "run_id": self.run_id,
                "campaign_id": campaign_id,
                "trigger": trigger,
                "action": action,
                "pulse": UNKNOWN,
                "applied": applied,
                "applied_at_seq": applied_at_seq,
                "applied_result": applied_result,
                "evidence_level": "hypothesis",  # 注入效果是仿真器制造的 → hypothesis（契约规则）
            }
        )

    # ---- run_end 行 ----

    def run_end(self, exit_reason: str, final_pc: int, instruction_count: int, detail: dict, evidence_level: str) -> None:
        self.flush_insn()
        self._emit(
            {
                "type": "run_end",
                "run_id": self.run_id,
                "exit_reason": exit_reason,
                "final_pc": final_pc,
                "instruction_count": instruction_count,
                "detail": detail,
                "evidence_level": evidence_level,
            }
        )
        self._f.flush()

    def close(self) -> None:
        self.flush_insn()
        self._f.close()

    @property
    def current(self) -> dict | None:
        return getattr(self, "_cur", None)


class NullTracer:
    """不落盘轨迹的 Tracer 替身（时间评估/周期扫描用）。

    为什么需要：算"运行到地址 X 的周期数"必须跑完整段执行，但**不需要**逐条
    指令的 JSONL（40 万指令 = 约 100MB）。本类保留 Tracer 的全部接口与计数语义
    （instruction_count / fault_events / exit_reason 仍完整产出），只丢弃逐指令行，
    并在 run_end 里写入一条显式说明——避免"没有轨迹"被误读成"没有观测"。
    """

    def __init__(self, run_id: str, meta: dict[str, Any] | None = None):
        self.run_id = run_id
        self.meta = meta or {}
        self.path: Path | None = None
        self._cur: dict | None = None
        self.trace_rows_dropped = 0
        self.fault_events: list[dict] = []
        self.run_end_row: dict | None = None
        self._mem_events = 0
        self._csr_events = 0
        self._stub_rows = 0

    def begin_insn(self, seq: int, pc: int, instruction_raw: str, disasm: str) -> None:
        self._cur = None  # 不保留行对象；机器层的 attach_* 调用会走空实现
        self.trace_rows_dropped += 1

    def attach_mem(self, *args, **kwargs) -> None:
        self._mem_events += 1
        stub = kwargs.get("stub")
        if stub is None and len(args) >= 6:
            stub = args[5]
        if stub:
            self._stub_rows += 1

    def attach_csr(self, entry: dict) -> None:
        self._csr_events += 1

    def mark_hypothesis(self) -> None:
        return None

    def flush_insn(self) -> None:
        self._cur = None

    def fault_event(self, **kwargs) -> None:
        self.fault_events.append(dict(kwargs))

    def run_end(
        self,
        exit_reason: str,
        final_pc: int,
        instruction_count: int,
        detail: dict,
        evidence_level: str,
    ) -> None:
        self.flush_insn()
        self.run_end_row = {
            "type": "run_end",
            "run_id": self.run_id,
            "exit_reason": exit_reason,
            "final_pc": final_pc,
            "instruction_count": instruction_count,
            "detail": detail,
            "evidence_level": evidence_level,
        }

    def close(self) -> None:
        self.flush_insn()

    @property
    def current(self) -> dict | None:
        return self._cur

    def stats(self) -> dict:
        return {
            "mode": "null",
            "trace_rows_dropped": self.trace_rows_dropped,
            "mem_events_observed": self._mem_events,
            "mem_stub_events_observed": self._stub_rows,
            "csr_events_observed": self._csr_events,
            "fault_events": len(self.fault_events),
            "note": (
                "本次运行不落盘逐指令轨迹（--no-trace / NullTracer）；"
                "事件计数仍为观测事实，但无逐条轨迹可供回放"
            ),
        }
