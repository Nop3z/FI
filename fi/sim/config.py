"""声明式仿真配置。

所有地址/入口/ISA 在配置里都是【假设】级输入：本模块只负责结构与校验，
不承载任何芯片事实。target-chip 等样例配置放 examples/，本包不写芯片专有默认。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .timing import TimingPolicy, timing_policy_from_raw

PAGE_SIZE = 0x1000

REGION_KINDS = ("rom", "ram", "mmio")
UNMAPPED_POLICIES = ("stub-page", "stop")
CSR_POLICIES = ("warl-log", "strict-stop")
MEM_TRACE_MODES = ("all", "stub", "off")
# skip/flip_reg_bits 为契约引擎动作；reg_write/mem_write 为扩展预留（探索用）
INJECT_TYPES = ("skip", "flip_reg_bits", "reg_write", "mem_write")
#: 注入动作时机：before=目标指令执行前；after=目标指令执行后、下一条指令前
INJECT_WHENS = ("before", "after")
# 触发定位模式：pc=地址命中；seq=指令序号；cycle_estimate=估算周期（timing 模型累计）；
# every=每 N 条指令。cycle_estimate 需要 timing 模型启用（默认启用）。
TRIGGER_MODES = ("pc", "seq", "cycle_estimate", "every")


def parse_int(value: Any, name: str = "value") -> int:
    """接受 int 或 "0x..." / 十进制字符串。"""
    if isinstance(value, bool):
        raise ValueError(f"{name}: bool 不是合法整数")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.strip(), 0)
    raise ValueError(f"{name}: 无法解析为整数: {value!r}")


@dataclass
class RegionSpec:
    name: str
    kind: str  # rom | ram | mmio
    base: int
    size: int
    file: Path | None = None      # 预加载镜像（绝对路径，只读引用）
    file_sha256: str | None = None
    device: str | None = None     # 设备注册名；kind=mmio 且缺省 → null-stub
    stub_value: int = 0           # null-stub 的占位返回值
    exec_: bool | None = None     # None → 按 kind 默认（rom=X, ram=X, mmio=无X）
    device_params: dict = field(default_factory=dict)  # 设备构造参数（如 uart-log 的 ready_value）


@dataclass
class EntrySpec:
    region: str | None = None     # 相对某 region 的 offset
    offset: int = 0
    addr: int | None = None       # 或绝对地址


@dataclass
class LoopPolicy:
    # 疑似死循环判定是启发式（hypothesis 级），阈值全部可配置
    pc_count_threshold: int = 20000   # 单条 PC 执行次数阈值
    cycle_window: int = 1024          # 循环模式扫描窗口（条）
    max_cycle_len: int = 64           # 识别的最大循环长度（条指令）
    min_cycle_streak: int = 8         # 连续重复最少次数
    check_interval: int = 2048        # 每 N 条指令扫描一次循环模式


@dataclass
class InjectSpec:
    """仿真故障注入动作（M3 离线注入器接口 v0，与 sim-trace 契约对齐）。

    type=skip          命中时跳过该条指令（仿真器从 next_pc 继续）
    type=flip_reg_bits 命中时位翻转寄存器：new = old XOR bit_mask（或直接 new_value），
                       bit_width 为寄存器位宽（RV32=32）
    type=reg_write     命中时写通用寄存器
    type=mem_write     命中时写内存
    触发定位 trigger.mode：pc | seq | cycle_estimate | every
    seq 按指令序号（0 起，全 run 计数）解释；
    cycle_estimate 按 fi.sim.timing 的**估算周期累计值**解释（首次达到即触发，
                     见 machine._injections_cycle_hit；为估算值，证据级 hypothesis）；
    every 按每 N 条指令；times=0 不限次。
    when（动作时机）：
      - before（默认）：在目标指令**执行前**生效（skip 恒为此语义）
      - after：在目标指令**执行完毕后、下一条指令执行前**生效。
        **这是"改寄存器结果"类注入的正确语义**：例如把码装载指令
        `addi a0, zero, 0x504` 的结果改成 0x104，必须在 a0 被写好之后再翻 bit30；
        若在装载前翻转，指令会把 a0 覆盖回去，注入完全无效。
    每次触发都写 fault_event 行进事实日志。
    """
    type: str
    pc: int | None = None
    seq: int | None = None
    cycle_estimate: int | None = None
    every: int | None = None
    times: int = 0
    reg: str | None = None        # flip_reg_bits / reg_write 用
    bit_width: int = 32           # flip_reg_bits 用
    bit_mask: int = 0             # flip_reg_bits 用
    new_value: int | None = None  # flip_reg_bits 可直接指定新值
    value: int | None = None      # reg_write / mem_write 配合 addr 用
    addr: int | None = None       # mem_write 用
    data_hex: str | None = None   # mem_write 用（小端 hex）
    when: str = "before"          # before=目标指令执行前（默认）| after=执行后、下一条前
    campaign_id: str = "unknown"
    event_id: str | None = None   # 契约 fault_event 的 event_id（backend 注入用）
    note: str = ""


@dataclass
class SimConfig:
    isa: str = "rv32imac"          # 假设级；evidence 由调用方在 raw/config 里给
    xlen: int = 32
    regions: list[RegionSpec] = field(default_factory=list)
    entry: EntrySpec = field(default_factory=EntrySpec)
    max_instructions: int = 200000
    unmapped_policy: str = "stub-page"   # stub-page=记录+动态占位页继续；stop=停机
    csr_policy: str = "warl-log"         # warl-log=未知CSR记录后继续；strict-stop=停机
    trap_dispatch: bool = True           # 未映射访问落入 trap_addrs 时按 mtvec 分发（固件自测路径依赖）
    trap_addrs: list[list[int]] = field(default_factory=list)  # [[start,end],...]：视为"故意异常"的地址区间；空=不启用
    trap_dispatch: bool = True           # mtvec 已安装时未映射访问按 trap 分发（自测路径依赖）
    mem_trace: str = "all"               # all|stub|off（stub 访问无论如何都记录）
    loop: LoopPolicy = field(default_factory=LoopPolicy)
    injects: list[InjectSpec] = field(default_factory=list)
    skip_csr: list[int] = field(default_factory=list)       # 线性扫描补丁（对照工具）
    patch_offsets: list[int] = field(default_factory=list)  # 精确偏移补丁（观察到的卡点）
    timing: "TimingPolicy" = field(default_factory=lambda: TimingPolicy())  # 周期估算策略
    report_time_at: list[int] = field(default_factory=list)  # 输出这些地址的首达周期
    window_ns: tuple[float, float] | None = None             # delay 窗口 → 指令区间反查
    initial_regs: dict[str, int] = field(default_factory=dict)  # 入口前预置寄存器（GPR 名→值）
    raw: dict[str, Any] = field(default_factory=dict)       # 原始 JSON 回显进 run_meta


def parse_bool(value: Any, name: str = "value") -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes"):
            return True
        if value.lower() in ("false", "0", "no"):
            return False
    raise ValueError(f"{name}: 无法解析为布尔: {value!r}")


def _parse_region(raw_region: dict, config_dir: Path) -> RegionSpec:
    name = raw_region.get("name")
    kind = raw_region.get("kind")
    if not name or kind not in REGION_KINDS:
        raise ValueError(f"region 需要 name 与 kind({REGION_KINDS}): {raw_region!r}")
    base = parse_int(raw_region["base"], f"region {name} base")
    size = parse_int(raw_region["size"], f"region {name} size")
    if base % PAGE_SIZE:
        raise ValueError(f"region {name}: base 0x{base:x} 未按 4KB 对齐")
    if size <= 0:
        raise ValueError(f"region {name}: size 必须 > 0")
    file_path = None
    if raw_region.get("file"):
        file_path = Path(raw_region["file"])
        if not file_path.is_absolute():
            file_path = config_dir / file_path
        file_path = file_path.resolve()
        if not file_path.is_file():
            raise FileNotFoundError(f"region {name}: 镜像不存在: {file_path}")
    sha = None
    if file_path is not None:
        sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
    return RegionSpec(
        name=name,
        kind=kind,
        base=base,
        size=size,
        file=file_path,
        file_sha256=sha,
        device=raw_region.get("device"),
        stub_value=parse_int(raw_region.get("stub_value", 0), f"region {name} stub_value"),
        exec_=raw_region.get("exec"),
        device_params=dict(raw_region.get("device_params", {})),
    )


def _parse_inject(raw_inject: dict) -> InjectSpec:
    itype = raw_inject.get("type")
    if itype not in INJECT_TYPES:
        raise ValueError(f"inject.type 必须是 {INJECT_TYPES}: {raw_inject!r}")
    when = raw_inject.get("when", "before")
    if when not in INJECT_WHENS:
        raise ValueError(f"inject.when 必须是 {INJECT_WHENS}: {raw_inject!r}")
    return InjectSpec(
        type=itype,
        pc=parse_int(raw_inject["pc"], "inject.pc") if raw_inject.get("pc") is not None else None,
        seq=parse_int(raw_inject["seq"], "inject.seq") if raw_inject.get("seq") is not None else None,
        cycle_estimate=parse_int(raw_inject["cycle_estimate"], "inject.cycle_estimate") if raw_inject.get("cycle_estimate") is not None else None,
        every=parse_int(raw_inject["every"], "inject.every") if raw_inject.get("every") is not None else None,
        times=parse_int(raw_inject.get("times", 0), "inject.times"),
        reg=raw_inject.get("reg"),
        bit_width=parse_int(raw_inject.get("bit_width", 32), "inject.bit_width"),
        bit_mask=parse_int(raw_inject.get("bit_mask", 0), "inject.bit_mask"),
        new_value=parse_int(raw_inject["new_value"], "inject.new_value") if raw_inject.get("new_value") is not None else None,
        value=parse_int(raw_inject["value"], "inject.value") if raw_inject.get("value") is not None else None,
        addr=parse_int(raw_inject["addr"], "inject.addr") if raw_inject.get("addr") is not None else None,
        data_hex=raw_inject.get("data_hex"),
        when=raw_inject.get("when", "before"),
        campaign_id=raw_inject.get("campaign_id", "unknown"),
        event_id=raw_inject.get("event_id"),
        note=raw_inject.get("note", ""),
    )


def load_config(path: str | Path) -> SimConfig:
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    config_dir = path.resolve().parent

    regions = [_parse_region(r, config_dir) for r in raw.get("regions", [])]
    if not regions:
        raise ValueError("config.regions 至少需要一个内存区域")
    names = [r.name for r in regions]
    if len(set(names)) != len(names):
        raise ValueError(f"region 名重复: {names}")
    ordered = sorted(regions, key=lambda r: r.base)
    for a, b in zip(ordered, ordered[1:]):
        if a.base + a.size > b.base:
            raise ValueError(f"region 重叠: {a.name} 与 {b.name}")

    entry_raw = raw.get("entry", {})
    entry = EntrySpec(
        region=entry_raw.get("region"),
        offset=parse_int(entry_raw.get("offset", 0), "entry.offset"),
        addr=parse_int(entry_raw["addr"], "entry.addr") if entry_raw.get("addr") is not None else None,
    )
    if entry.addr is None and entry.region is None:
        entry.region = regions[0].name  # 缺省入口 = 第一个 region 的 offset 0
    if entry.region and entry.region not in names:
        raise ValueError(f"entry.region 不存在: {entry.region}")

    loop_raw = raw.get("loop", {})
    loop = LoopPolicy(
        pc_count_threshold=parse_int(loop_raw.get("pc_count_threshold", LoopPolicy.pc_count_threshold), "loop.pc_count_threshold"),
        cycle_window=parse_int(loop_raw.get("cycle_window", LoopPolicy.cycle_window), "loop.cycle_window"),
        max_cycle_len=parse_int(loop_raw.get("max_cycle_len", LoopPolicy.max_cycle_len), "loop.max_cycle_len"),
        min_cycle_streak=parse_int(loop_raw.get("min_cycle_streak", LoopPolicy.min_cycle_streak), "loop.min_cycle_streak"),
        check_interval=parse_int(loop_raw.get("check_interval", LoopPolicy.check_interval), "loop.check_interval"),
    )

    unmapped_policy = raw.get("unmapped_policy", SimConfig.unmapped_policy)
    csr_policy = raw.get("csr_policy", SimConfig.csr_policy)
    mem_trace = raw.get("mem_trace", SimConfig.mem_trace)
    if unmapped_policy not in UNMAPPED_POLICIES:
        raise ValueError(f"unmapped_policy 必须是 {UNMAPPED_POLICIES}")
    if csr_policy not in CSR_POLICIES:
        raise ValueError(f"csr_policy 必须是 {CSR_POLICIES}")
    if mem_trace not in MEM_TRACE_MODES:
        raise ValueError(f"mem_trace 必须是 {MEM_TRACE_MODES}")

    config = SimConfig(
        isa=raw.get("arch", {}).get("isa", SimConfig.isa),
        xlen=parse_int(raw.get("arch", {}).get("xlen", 32), "arch.xlen"),
        regions=regions,
        entry=entry,
        max_instructions=parse_int(raw.get("limits", {}).get("max_instructions", SimConfig.max_instructions), "limits.max_instructions"),
        unmapped_policy=unmapped_policy,
        csr_policy=csr_policy,
        trap_dispatch=parse_bool(raw.get("trap_dispatch", True), "trap_dispatch"),
        trap_addrs=[[parse_int(a, "trap_addrs"), parse_int(b, "trap_addrs")] for a, b in raw.get("trap_addrs", [])],
        mem_trace=mem_trace,
        loop=loop,
        injects=[_parse_inject(i) for i in raw.get("injects", [])],
        skip_csr=[parse_int(x, "skip_csr") for x in raw.get("skip_csr", [])],
        patch_offsets=[parse_int(x, "patch_offsets") for x in raw.get("patch_offsets", [])],
        timing=timing_policy_from_raw(raw.get("timing")),
        report_time_at=[
            parse_int(x, "report_time_at") for x in raw.get("report_time_at", [])
        ],
        window_ns=_parse_window_ns(raw.get("window_ns")),
        initial_regs=_parse_initial_regs(raw.get("initial_regs")),
        raw=raw,
    )
    return config


def _parse_initial_regs(value: Any) -> dict[str, int]:
    """配置 `initial_regs: {"sp": "0x42044000", ...}` → 入口前预置寄存器。

    用途：跳过复位前段直接进入某个函数（如 ISP handler 试运行）时，
    该函数期望的寄存器/栈上下文必须显式给出——这是 hypothesis 级输入，
    不是"复原了真实复位状态"。未给出的寄存器保持 unicorn 初值 0。
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"initial_regs 需要对象（寄存器名→值）: {value!r}")
    out: dict[str, int] = {}
    for name, raw_val in value.items():
        out[str(name)] = parse_int(raw_val, f"initial_regs.{name}")
    return out


def _parse_window_ns(value: Any) -> tuple[float, float] | None:
    """配置 `window_ns: [lo, hi]` → ns 窗口（delay 调参窗口反查用）；缺省 None。"""
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ValueError(f"window_ns 需要 [lo_ns, hi_ns] 两项: {value!r}")
    lo, hi = float(value[0]), float(value[1])
    if lo > hi:
        raise ValueError(f"window_ns 需 lo<=hi: {value!r}")
    return (lo, hi)


def apply_cli_overrides(
    config: SimConfig,
    base: int | None = None,
    entry_offset: int | None = None,
    entry_addr: int | None = None,
    count: int | None = None,
    csr_policy: str | None = None,
    unmapped_policy: str | None = None,
    stub_value: int | None = None,
    mem_trace: str | None = None,
    skip_csr: list[int] | None = None,
    patch_offsets: list[int] | None = None,
    injects: list[InjectSpec] | None = None,
    label: str | None = None,
    ns_per_cycle: float | None = None,
    report_time_at: list[int] | None = None,
    window_ns: tuple[float, float] | None = None,
    timing_enabled: bool | None = None,
    initial_regs: dict[str, int] | None = None,
) -> None:
    """CLI 覆盖项原地生效。--base 覆盖第一个 region 的 base（入口随动）。"""
    if base is not None:
        if base % PAGE_SIZE:
            raise ValueError(f"--base 0x{base:x} 未按 4KB 对齐")
        first = sorted(config.regions, key=lambda r: r.base)[0]
        # 平移该 region 后检查与其他 region 的重叠
        others = [r for r in config.regions if r is not first]
        for other in others:
            if base < other.base + other.size and other.base < base + first.size:
                raise ValueError(f"--base 0x{base:x} 与 region {other.name} 重叠")
        first.base = base
    if entry_addr is not None:
        config.entry.addr = entry_addr
    if entry_offset is not None:
        config.entry.offset = entry_offset
        config.entry.addr = None
    if count is not None:
        if count <= 0:
            raise ValueError("--count 必须 > 0")
        config.max_instructions = count
    if csr_policy is not None:
        config.csr_policy = csr_policy
    if unmapped_policy is not None:
        config.unmapped_policy = unmapped_policy
    if stub_value is not None:
        for region in config.regions:
            if region.kind == "mmio":
                region.stub_value = stub_value
    if mem_trace is not None:
        config.mem_trace = mem_trace
    if skip_csr:
        config.skip_csr.extend(skip_csr)
    if patch_offsets:
        config.patch_offsets.extend(patch_offsets)
    if injects:
        config.injects.extend(injects)
    if ns_per_cycle is not None:
        if ns_per_cycle <= 0:
            raise ValueError("--ns-per-cycle 必须 > 0")
        config.timing.ns_per_cycle = ns_per_cycle
    if timing_enabled is not None:
        config.timing.enabled = timing_enabled
    if report_time_at:
        config.report_time_at.extend(report_time_at)
    if window_ns is not None:
        if window_ns[0] > window_ns[1]:
            raise ValueError("--window-ns 需 lo<=hi")
        config.window_ns = window_ns
    if initial_regs:
        config.initial_regs.update(initial_regs)
    if label is not None:
        config.raw = {**config.raw, "label": label}


def config_to_dict(config: SimConfig) -> dict:
    """run_meta 回显用。"""
    return {
        "arch": {"isa": config.isa, "xlen": config.xlen},
        "regions": [
            {
                "name": r.name,
                "kind": r.kind,
                "base": r.base,
                "size": r.size,
                "file": str(r.file) if r.file else None,
                "file_sha256": r.file_sha256,
                "device": r.device,
                "stub_value": r.stub_value,
                "exec": r.exec_,
            }
            for r in config.regions
        ],
        "entry": {
            "region": config.entry.region,
            "offset": config.entry.offset,
            "addr": config.entry.addr,
            "evidence": (config.raw.get("entry", {}) or {}).get("evidence"),
        },
        "limits": {"max_instructions": config.max_instructions},
        "policy": {
            "csr": config.csr_policy,
            "unmapped": config.unmapped_policy,
            "mem_trace": config.mem_trace,
            "trap_dispatch": config.trap_dispatch,
            "trap_addrs": [[hex(a), hex(b)] for a, b in config.trap_addrs],
        },
        "loop": vars(config.loop),
        "injects": [vars(i) for i in config.injects],
        "skip_csr": [hex(x) for x in config.skip_csr],
        "patch_offsets": [hex(x) for x in config.patch_offsets],
        "timing": {
            "enabled": config.timing.enabled,
            "base_cpi": config.timing.base_cpi,
            "class_weights": dict(config.timing.class_weights),
            "taken_control_penalty": config.timing.taken_control_penalty,
            "ns_per_cycle": (
                config.timing.ns_per_cycle
                if config.timing.ns_per_cycle is not None
                else "unknown"
            ),
            "evidence_level": config.timing.evidence_level,
        },
        "report_time_at": [hex(x) for x in config.report_time_at],
        "window_ns": list(config.window_ns) if config.window_ns else None,
        "initial_regs": {k: hex(v) for k, v in config.initial_regs.items()},
    }
