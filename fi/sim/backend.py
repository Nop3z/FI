"""SimBackend 协议的 Unicorn 实现（fi.sim.simulation 后端）。

对接 SimFaultInjector 调用时序（见 protocol.py）：
    backend = UnicornBackend(trace_dir=..., extra_regions=[...])
    backend.load_image(rom_path, base_address=0x<BASE>)
    backend.reset()
    backend.apply_fault(event_dict)   # fault_event 行形状（sim-trace.schema.json）
    result = backend.run(max_instructions)

实现说明：
- 内存/入口/策略：load_image 用骨架默认假设构建 SimConfig（ROM 区 + 入口 offset 0
  hypothesis + csr_policy=warl-log + unmapped_policy=stub-page）；
- apply_fault 接收 sim-trace 契约 fault_event 形状 dict（trigger{mode,value}/
  action{kind,...}），兼容 protocol.py docstring 的旧动作名
  （skip_instruction→skip、corrupt_mem_value→mem_write）；
- run() 产出的 trace JSONL 通过 sim-trace.schema.json 校验；campaign-records.jsonl
  通过 campaign-record.schema.json（v0.2.0 sim_trigger）校验；
- final_context 为 fault-context.schema.json 的 processor_context 层形状
  （仿真重放重建 → evidence_level=hypothesis）。

纪律：本模块不携带任何芯片专有字面量（帧格式/错误码候选由 ChipProfile 与分析层处理）。
仿真侧只原样记录 UART 字节流（uart-bytes.bin + 文本原样），帧格式匹配判断留给分析层
对照 profile 候选——避免"用候选假设验证候选假设"的循环论证（core-contract 门禁 2026-11-09）。
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fi import CONTRACT_VERSION, UNKNOWN
from fi.sim.protocol import SimBackend, SimRunResult
from fi.sim.config import EntrySpec, InjectSpec, RegionSpec, SimConfig, parse_int
from fi.sim.machine import Simulator
from fi.sim.tracebin import is_binary_trace, iter_json_rows
from fi.sim.tracer import Tracer

# protocol.py docstring 旧动作名 → schema/sim-trace 定稿动作名
_ACTION_ALIASES = {"skip_instruction": "skip", "corrupt_mem_value": "mem_write"}

_UART_TEXT_MAX = 4000  # CampaignRecord.response.unexpected_raw 文本截断上限（防 trap 风暴污染）


class UnicornBackend(SimBackend):
    name = "unicorn-rv32"

    def __init__(
        self,
        trace_dir: str | Path = "runs/sim-backend",
        extra_regions: list[RegionSpec] | None = None,
    ):
        """extra_regions：调用方按 ChipProfile/样例配置传入的附加内存区域
        （RAM/MMIO/设备模型）。backend 保持通用，不携带芯片专有字面量。"""
        self.trace_dir = Path(trace_dir)
        self.extra_regions = list(extra_regions or [])
        self._image_path: Path | None = None
        self._base_address: int | None = None
        self._profile_ref: str = UNKNOWN
        self._fault_specs: list[InjectSpec] = []
        self._fault_campaigns: list[str] = []
        self._event_seq = 0
        self._sim: Simulator | None = None

    # ---- SimBackend 协议 ----

    def load_image(self, image_path: Path, base_address: int, profile_ref: str = UNKNOWN) -> None:
        self._image_path = Path(image_path)
        self._base_address = base_address
        self._profile_ref = profile_ref or UNKNOWN
        self._fault_specs = []
        self._fault_campaigns = []
        self._event_seq = 0

    def reset(self) -> None:
        """复位到入口状态：丢弃旧 Simulator，保留已注册的故障清单（重新生效）。"""
        self._sim = None

    def apply_fault(self, event: dict[str, Any]) -> str:
        if self._image_path is None:
            raise RuntimeError("先 load_image 再 apply_fault")
        spec = self._event_to_spec(event)
        self._fault_specs.append(spec)
        self._fault_campaigns.append(spec.campaign_id)
        self._event_seq += 1
        return spec.event_id or f"fev-{self._event_seq:04d}"

    def run(self, max_instructions: int) -> SimRunResult:
        if self._image_path is None or self._base_address is None:
            raise RuntimeError("先 load_image 再 run")
        config = self._build_config(max_instructions)
        sim = Simulator(config)
        run_id = f"r-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
        out_dir = self.trace_dir / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        trace_path = out_dir / "trace.jsonl"
        meta = self._build_meta(config, sim, run_id)
        tracer = Tracer(trace_path, run_id, meta)
        sim.bind_tracer(tracer)
        result = sim.run()
        tracer.close()

        uart_bytes = self._uart_bytes(sim)
        if uart_bytes:
            (out_dir / "uart-bytes.bin").write_bytes(bytes(uart_bytes))
        write_campaign_records(out_dir / "campaign-records.jsonl", run_id, trace_path, self._uart_text(sim))

        campaign = next((c for c in reversed(self._fault_campaigns) if c != UNKNOWN), UNKNOWN)
        final_context = {
            "schema_version": CONTRACT_VERSION,
            "context_id": f"ctx-{run_id}",
            "campaign_id": campaign,
            "source_provider": "simulation",
            "observation_level": "processor_context",
            "evidence_level": "hypothesis",  # 仿真重放重建 → hypothesis（契约规则）
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "pc": result.final_pc,
            "registers": {k: v for k, v in result.regs.items() if k != "pc"},
            "csrs": UNKNOWN,  # 未实现 CSR 快照（unicorn CSR 层受限），显式 unknown
            "memory_snapshot": [],
            "execution_trace": {"trace_ref": str(trace_path)},
            "raw_data_ref": UNKNOWN,
            "notes": "仿真器最终现场；WARL/占位语义与全部占位访问见 trace JSONL（stub=true 行）",
        }
        outcome_metrics = {
            "detail_kind": result.detail_kind,
            "entry_addr": result.entry,
            "stub_accesses": result.stub_accesses,
            "warl_events": result.warl_events,
            "fault_events_fired": result.fault_events_fired,
            "uart_response_raw": self._uart_text(sim),
            "uart_log_observation": "仿真观测：设备模型假设下的输出，非真实串口时序",
        }
        self._sim = sim
        return SimRunResult(
            run_id=run_id,
            exit_reason=result.exit_reason,
            final_pc=result.final_pc,
            instruction_count=result.instructions,
            trace_ref=str(trace_path),
            final_context=final_context,
            outcome_metrics=outcome_metrics,
        )

    # ---- 内部 ----

    def _build_config(self, max_instructions: int) -> SimConfig:
        rom_size = (self._image_path.stat().st_size + 0xFFF) & ~0xFFF
        regions = [
            RegionSpec(
                name="bootrom",
                kind="rom",
                base=self._base_address,
                size=rom_size,
                file=self._image_path,
                file_sha256=hashlib.sha256(self._image_path.read_bytes()).hexdigest(),
            ),
            *self.extra_regions,
        ]
        return SimConfig(
            regions=regions,
            entry=EntrySpec(region="bootrom", offset=0),
            max_instructions=max_instructions,
            unmapped_policy="stub-page",
            csr_policy="warl-log",
            injects=list(self._fault_specs),
        )

    def _event_to_spec(self, event: dict[str, Any]) -> InjectSpec:
        trigger = event.get("trigger", {}) or {}
        action = event.get("action", {}) or {}
        mode = trigger.get("mode")
        value = trigger.get("value")
        common = dict(campaign_id=event.get("campaign_id") or UNKNOWN)
        if mode == "pc":
            spec = InjectSpec(type="skip", pc=parse_int(value, "trigger.value"), **common)
        elif mode == "seq":
            spec = InjectSpec(type="skip", seq=parse_int(value, "trigger.value"), **common)
        elif mode == "cycle_estimate":
            spec = InjectSpec(type="skip", cycle_estimate=parse_int(value, "trigger.value"), **common)
        elif mode == "every":
            spec = InjectSpec(type="skip", every=parse_int(value, "trigger.value"), **common)
        else:
            raise ValueError(f"不支持的 trigger.mode: {mode!r}")

        # pulse：single_event/未知 → 单次生效；instruction_count → times=value
        pulse = event.get("pulse")
        if isinstance(pulse, dict) and pulse.get("mode") == "instruction_count" and pulse.get("value") not in (None, UNKNOWN):
            spec.times = parse_int(pulse["value"], "pulse.value")
        else:
            spec.times = 1  # 单事件（最小意外原则）

        kind = _ACTION_ALIASES.get(action.get("kind"), action.get("kind"))
        if kind == "skip":
            spec.type = "skip"
        elif kind == "flip_reg_bits":
            spec.type = "flip_reg_bits"
            spec.reg = action.get("reg")
            spec.bit_width = parse_int(action.get("bit_width", 32), "action.bit_width")
            mask = action.get("bit_mask")
            spec.bit_mask = parse_int(mask, "action.bit_mask") if isinstance(mask, str) and mask != UNKNOWN else (mask if isinstance(mask, int) else 0)
            nv = action.get("new_value")
            spec.new_value = parse_int(nv, "action.new_value") if isinstance(nv, (int, str)) and nv != UNKNOWN else None
        elif kind == "reg_write":
            spec.type = "reg_write"
            spec.reg = action.get("reg")
            nv = action.get("value")
            spec.value = parse_int(nv, "action.value") if nv is not None else None
        elif kind == "mem_write":
            spec.type = "mem_write"
            spec.addr = parse_int(action["addr"], "action.addr") if action.get("addr") not in (None, UNKNOWN) else None
            size = action.get("size")
            value = action.get("value")
            if isinstance(value, int) and value is not UNKNOWN and size not in (None, UNKNOWN):
                spec.data_hex = (value if isinstance(value, int) else parse_int(value, "action.value")).to_bytes(
                    parse_int(size, "action.size"), "little"
                ).hex()
        else:
            raise ValueError(f"不支持的 action.kind: {action.get('kind')!r}")
        spec.event_id = event.get("event_id")
        note = event.get("applied_result")
        if isinstance(note, dict):
            spec.note = str(note.get("note", ""))
        return spec

    def _uart_text(self, sim: Simulator) -> str:
        for dev in sim.devices.values():
            if getattr(dev, "log", None):
                return dev.text  # type: ignore[return-value]
        return UNKNOWN

    def _uart_bytes(self, sim: Simulator) -> bytearray:
        for dev in sim.devices.values():
            if getattr(dev, "log", None):
                return dev.log  # type: ignore[return-value]
        return bytearray()

    def _build_meta(self, config: SimConfig, sim: Simulator, run_id: str) -> dict:
        image_region = next((r for r in sim.regions if r.file), None)
        image_meta: dict | str = "unknown"
        if image_region is not None and image_region.file_sha256:
            image_meta = {
                "path": str(image_region.file),
                "sha256": image_region.file_sha256,
                "base_address": image_region.base,
                "size_bytes": len(sim.images.get(image_region.name, b"")),
            }
        return {
            "type": "run_meta",
            "run_id": run_id,
            "image": image_meta,
            "engine": {"name": self.name, "version": __import__("unicorn").__version__},
            "profile_ref": self._profile_ref,
            "memory_map": {
                "regions": sim.mapping_info,
                "entry_addr": sim.resolve_entry(),
                "entry_evidence": "hypothesis: 复位入口未确认，backend 默认 offset 0",
                "policy": {"csr": config.csr_policy, "unmapped": config.unmapped_policy, "mem_trace": config.mem_trace},
            },
            "patches": sim.patches,
            "fault_events": [render_preregistered_backend(spec, run_id, i) for i, spec in enumerate(config.injects)],
            "evidence_level": "observation",
        }


def render_preregistered_backend(spec: InjectSpec, run_id: str, seq_index: int) -> dict:
    """backend 的预注册 fault_event 渲染（从 fi.sim.inject.render_trigger/render_action 取件）。"""
    from fi.sim.inject import render_action, render_trigger

    return {
        "type": "fault_event",
        "event_id": f"{run_id}-f{seq_index + 1:03d}",
        "run_id": run_id,
        "campaign_id": spec.campaign_id,
        "trigger": render_trigger(spec),
        "action": render_action(spec),
        "pulse": UNKNOWN,
        "applied": UNKNOWN,
        "applied_at_seq": UNKNOWN,
        "evidence_level": UNKNOWN,
    }


def iter_contract_rows(trace_path: Path):
    """统一读取轨迹的契约行：自动识别紧凑二进制（trace.fitb）与 JSONL。

    二进制轨迹只解码非 trace 行（run_meta/fault_event/run_end），避免为拿几条
    fault_event 而解码 40 万条指令行。
    """
    trace_path = Path(trace_path)
    if is_binary_trace(trace_path):
        yield from iter_json_rows(trace_path)
        return
    for line in trace_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def write_campaign_records(path: Path, run_id: str, trace_path: Path, uart_text: str) -> None:
    """从 trace 回读 fault_event 行，按 CampaignRecord 契约产出注入记录。

    供 backend.run() 与 CLI（python -m fi.sim run）共用。
    轨迹既可能是 JSONL（full/sampled）也可能是紧凑二进制（binary，trace.fitb），
    本函数统一经 `iter_contract_rows` 读取，两种格式行为一致。
    映射（campaign-record v0.2.0 sim_trigger，core-contract 2026-11-09）：
    raw_delay/raw_pulse 写 unknown（仿真域没有 CSV 原始刻度，臆造数值违反
    缺失显式 unknown 纪律）；仿真触发信息放 params.sim_trigger（聚合切度=
    applied_at_seq）；响应=UART 仿真观测文本原样（不做帧格式判断——匹配留给
    分析层对照 ChipProfile 候选）。
    TODO（已向 core-contract 登记）：按触发点分段响应文本，每个注入点独立
    CampaignRecord + 注入点级 fault_context_refs（当前 run 级粒度多注入会互相污染归因）。"""
    events = []
    for obj in iter_contract_rows(trace_path):
        if obj.get("type") == "fault_event" and obj.get("applied") is True:
            events.append(obj)
    if not events:
        return
    if uart_text == UNKNOWN:
        responded: bool | str = False
        response_raw: str = UNKNOWN
    else:
        responded = True
        response_raw = uart_text
        if len(response_raw) > _UART_TEXT_MAX:
            response_raw = response_raw[:_UART_TEXT_MAX] + f"...[截断，全文见 {trace_path.name} 行级事件与 uart-bytes.bin]"
    try:
        rel = str(trace_path.relative_to(Path.cwd()))
    except ValueError:
        rel = str(trace_path)

    lines = []
    for e in events:
        applied_at = e.get("applied_at_seq")
        action_kind = (e.get("action") or {}).get("kind") or UNKNOWN
        sim_trigger = {
            "trigger_mode": "seq",
            "trigger_value": applied_at if isinstance(applied_at, int) else UNKNOWN,
            "width_mode": "single_event",
            "width_value": UNKNOWN,
            "action_kind": action_kind,
        }
        lines.append(
            json.dumps(
                {
                    "schema_version": CONTRACT_VERSION,
                    "campaign_id": e.get("campaign_id") or UNKNOWN,
                    "params": {
                        "raw_delay": UNKNOWN,
                        "raw_pulse": UNKNOWN,
                        "delay_ns": UNKNOWN,
                        "pulse_ns": UNKNOWN,
                        "unit_assumption": {
                            "scale": "simulation trigger scale = instruction sequence index (not comparable to CSV ns scale)",
                            "evidence_level": "hypothesis",
                        },
                        "injector_id": "sim-injector",
                        "sim_trigger": sim_trigger,
                    },
                    "response": {
                        "state_label": UNKNOWN,
                        "state_label_semantics": "unconfirmed-v0.1",
                        "error_code_raw": UNKNOWN,
                        "glitched_raw": UNKNOWN,
                        "unexpected_raw": response_raw,
                        "responded": responded,
                    },
                    "fault_context_refs": [f"ctx-{run_id}"],
                    "raw_data_ref": {
                        "kind": "trace",
                        "path": rel,
                        "checksum": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
                    },
                    "evidence_level": "hypothesis",
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
