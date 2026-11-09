"""Unicorn RV32IMAC 仿真引擎核心。

职责：声明式内存映射装载、指令/内存钩子、WARL 与探索策略、停止原因分类、
注入触发、寄存器快照。不承载任何芯片专有事实；所有占位访问强制记录。

策略（默认值即当前工作假设，均可在 config 覆盖）：
- csr_policy=warl-log：unicorn 未实现的 CSR 访问 → 记录事实（CSR 号/op/attempted
  值/PC/指令字节）后按 WARL 继续（写忽略、读占位 0），该行 evidence_level=hypothesis。
- unmapped_policy=stub-page：未映射 read/write → 零页占位并记录（stub=true）继续；
  fetch 未映射一律停机（控制流离开已映射空间是重要边界，不静默续跑）。
- 停止分类：normal / exception(细分) / max_instructions / hang_suspected(启发式)。
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

import unicorn
import unicorn.riscv_const as rc
from unicorn import (
    UC_ARCH_RISCV,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MODE_RISCV32,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
    UcError,
)

from .config import PAGE_SIZE, SimConfig
from .decode import InsnInfo, disasm_one, make_disassembler, sweep_csr_write_offsets
from .devices import DEVICE_REGISTRY, NullStubDevice, UartLogDevice
from .inject import InjectionEngine, render_action, render_applied_result, render_trigger
from .loopdetect import LoopDetector
from .timing import TimingModel
from .stopreasons import (
    EXIT_EXCEPTION,
    EXIT_HANG_SUSPECTED,
    EXIT_MAX_INSTRUCTIONS,
    EXIT_NORMAL,
    classify_uc_error,
)

UNTIL_MARKER = 1 << 62  # 永不命中的 until 标记

# 影子 CSR（仿真器自维护，unicorn 无语义）：trap 闭环所需最小集
SHADOW_MTVEC = 0x305
SHADOW_MEPC = 0x341
SHADOW_MCAUSE = 0x342
SHADOW_MTVAL = 0x343
SHADOW_CSR_NAMES = {SHADOW_MTVEC: "mtvec", SHADOW_MEPC: "mepc", SHADOW_MCAUSE: "mcause", SHADOW_MTVAL: "mtval"}

# unmapped 访问 → mcause 候选映射（RISC-V 标准 access fault 编码；芯片实际编码可能不同，
# 已知差异例：mtvec MODE 观测 0b11 非标准。此映射整体为 hypothesis。）
_MCAUSE_CANDIDATE = {"read": 5, "write": 7, "fetch": 1}

_GPR_NAMES = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6",
]
_REG_IDS: dict[str, int] = {
    name: getattr(rc, f"UC_RISCV_REG_{name.upper()}")
    for name in _GPR_NAMES
    if hasattr(rc, f"UC_RISCV_REG_{name.upper()}")
}
_REG_IDS["pc"] = rc.UC_RISCV_REG_PC
_INDEX_TO_NAME = {i: name for i, name in enumerate(_GPR_NAMES) if name in _REG_IDS}

_ACCESS_KIND: dict[int, str] = {}
for _attr, _kind in [
    ("UC_MEM_READ", "read"), ("UC_MEM_WRITE", "write"), ("UC_MEM_FETCH", "fetch"),
    ("UC_MEM_READ_UNMAPPED", "read"), ("UC_MEM_WRITE_UNMAPPED", "write"), ("UC_MEM_FETCH_UNMAPPED", "fetch"),
    ("UC_MEM_READ_PROT", "read"), ("UC_MEM_WRITE_PROT", "write"), ("UC_MEM_FETCH_PROT", "fetch"),
]:
    if hasattr(unicorn, _attr):
        _ACCESS_KIND[getattr(unicorn, _attr)] = _kind

# valid 钩子只处理真正有效的访问（unicorn 会对未映射访问先调 valid 钩子，access 带 UNMAPPED 类型）
_ACCESS_VALID_READ = getattr(unicorn, "UC_MEM_READ", -1)
_ACCESS_VALID_WRITE = getattr(unicorn, "UC_MEM_WRITE", -2)


@dataclass
class RunResult:
    exit_reason: str
    detail_kind: str
    entry: int
    final_pc: int
    instructions: int
    stub_accesses: int
    warl_events: int
    fault_events_fired: int
    regs: dict
    cycles: float | str = "unknown"   # 估算周期（timing 模型；未启用时 unknown）
    ns: float | str = "unknown"       # 估算时间（需显式 ns_per_cycle 假设）


class Simulator:
    def __init__(self, config: SimConfig):
        self.config = config
        self.uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
        self.dis = make_disassembler()
        self.tracer = None  # 运行前由 CLI/selftest 绑定
        self.regions = sorted(config.regions, key=lambda r: r.base)
        self.devices: dict[str, object] = {}
        self.images: dict[str, bytes] = {}
        self.mapping_info: list[dict] = []
        self.patches: list[dict] = []
        self.executed = 0
        self.stub_accesses = 0
        self.stub_by_region: Counter[str] = Counter()
        self.warl_count = 0
        self.fault_events_fired = 0
        self.dynamic_pages: set[int] = set()
        self._unmapped_events: list[dict] = []
        self._last_insn: InsnInfo | None = None
        self._pending_skip: int | None = None
        self._cycle_now: float | None = None
        self._after_pc: int | None = None  # after 注入归属的目标指令 PC
        self._unmapped_event: dict | None = None
        self._loop_report: dict | None = None
        self.loop = LoopDetector(config.loop)
        self._dyn_retried: tuple[int, str] | None = None
        self.shadow_csrs: dict[int, int] = {}  # mtvec/mepc/mcause/mtval（trap 闭环 v1）
        self.traps: list[dict] = []  # trap 分发历史（run_end.detail.traps）
        self._pending_trap_target: int | None = None
        self._injections = InjectionEngine(config.injects)
        # 周期估算模型（timing.enabled=False 时不登记，保持零开销）
        self.timing: TimingModel | None = (
            TimingModel(config.timing) if config.timing.enabled else None
        )
        self._load_and_map()

    # ---------- 构建 ----------

    def _load_and_map(self) -> None:
        for region in self.regions:
            img = region.file.read_bytes() if region.file else b""
            if len(img) > region.size:
                raise ValueError(
                    f"region {region.name}: 镜像 {len(img)} 字节超过声明 size {region.size}"
                )
            if img:
                self.patches.extend(self._patch_image(region, img))
            self.images[region.name] = bytes(img)
            mapped_size = (region.size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
            perms = self._perms_of(region)
            self.uc.mem_map(region.base, mapped_size, perms)
            if img:
                self.uc.mem_write(region.base, img)
            device_desc = None
            if region.kind == "mmio":
                if region.device and region.device in DEVICE_REGISTRY:
                    dev = DEVICE_REGISTRY[region.device](region.name, region.stub_value, **region.device_params)
                else:
                    # MMIO 未声明设备 → 默认 null-stub（全部访问记入事实日志）
                    dev = NullStubDevice(region.name, region.stub_value)
                self.devices[region.name] = dev
                device_desc = dev.describe()
            self.mapping_info.append(
                {
                    "name": region.name,
                    "kind": region.kind,
                    "base": region.base,
                    "size": region.size,
                    "mapped_size": mapped_size,
                    "perms": perms,
                    "image_bytes": len(img),
                    "file": str(region.file) if region.file else None,
                    "file_sha256": region.file_sha256,
                    "device": device_desc,
                }
            )

    def _perms_of(self, region) -> int:
        if region.kind == "rom":
            return UC_PROT_READ | UC_PROT_EXEC
        if region.kind == "ram":
            return UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC
        perms = UC_PROT_READ | UC_PROT_WRITE
        if region.exec_:
            perms |= UC_PROT_EXEC
        return perms

    def _patch_image(self, region, img: bytearray) -> list[dict]:
        """启动前补丁（对照/探索工具，默认不用）。offsets 相对 region 起始。"""
        out: list[dict] = []
        targets: dict[int, str] = {}
        if self.config.patch_offsets:
            for off in self.config.patch_offsets:
                targets[off] = "manual"
        if self.config.skip_csr and img:
            sweep = sweep_csr_write_offsets(self.dis, bytes(img), region.base)
            for found in sweep:
                info = disasm_one(self.dis, img[found["offset"]: found["offset"] + 4], found["addr"])
                if info.csr is not None and info.csr in self.config.skip_csr:
                    targets[found["offset"]] = f"skip-csr-0x{info.csr:x}"
        ba = img if isinstance(img, bytearray) else bytearray(img)
        for off in sorted(targets):
            if off + 2 > len(ba):
                out.append({"offset": off, "reason": targets[off], "error": "offset 越界", "evidence_level": "unknown"})
                continue
            info = disasm_one(self.dis, bytes(ba[off: off + 4]), region.base + off)
            size = 2 if (info.undecoded or info.size == 2) else info.size
            if off + size > len(ba):
                size = 2
            nop = b"\x01\x00" if size == 2 else b"\x13\x00\x00\x00"  # c.nop / nop
            old = bytes(ba[off: off + size])
            ba[off: off + size] = nop
            out.append(
                {
                    "region": region.name,
                    "offset": off,
                    "addr": region.base + off,
                    "old_hex": old.hex(),
                    "new_hex": nop.hex(),
                    "insn": f"{info.mnemonic} {info.op_str}".strip(),
                    "reason": targets[off],
                    "evidence_level": "hypothesis",
                    "note": "启动前补丁：镜像改动会让该运行的执行路径偏离原始固件（探索性）",
                }
            )
        return out

    # ---------- 查询 ----------

    def region_of(self, addr: int):
        for r in self.regions:
            if r.base <= addr < r.base + r.size:
                return r
        return None

    def reg_id(self, name: str | None) -> int | None:
        if not name:
            return None
        return _REG_IDS.get(name.lower())

    def resolve_entry(self) -> int:
        e = self.config.entry
        if e.addr is not None:
            addr = e.addr
        else:
            region = next((r for r in self.regions if r.name == e.region), None)
            if region is None:
                raise ValueError(f"entry.region 不存在: {e.region}")
            addr = region.base + e.offset
        if self.region_of(addr) is None:
            raise ValueError(f"入口 0x{addr:x} 不在任何已声明 region 内")
        return addr

    def _gpr_read(self, index: int | None) -> int | None:
        if index is None:
            return None
        name = _INDEX_TO_NAME.get(index)
        rid = _REG_IDS.get(name) if name else None
        if rid is None:
            return None
        try:
            return self.uc.reg_read(rid)
        except UcError:
            return None

    def _gpr_write_index(self, index: int | None, value: int) -> bool:
        if index in (None, 0):
            return False
        name = _INDEX_TO_NAME.get(index)
        rid = _REG_IDS.get(name) if name else None
        if rid is None:
            return False
        self.uc.reg_write(rid, value & 0xFFFFFFFF)
        return True

    def _csr_src_value(self, insn: InsnInfo) -> int | None:
        """CSR 写形态的源寄存器当前值（attempted value）。"""
        if insn.rs1_index is not None:
            return self._gpr_read(insn.rs1_index)
        # 压缩指令：op_str 里最后一个寄存器 token
        for token in reversed(insn.op_str.replace(",", " ").split()):
            rid = _REG_IDS.get(token.lower())
            if rid is not None:
                try:
                    return self.uc.reg_read(rid)
                except UcError:
                    return None
        return None

    # ---------- 钩子 ----------

    def _flush(self) -> None:
        if self.tracer is not None:
            self.tracer.flush_insn()

    def _hook_code(self, uc, address, size, ud):
        # 上一条指令挂起的 after 注入：此刻应用（目标指令已执行完，寄存器是新值）
        if self._injections.has_pending_after:
            self._apply_pending_after()
        self._flush()
        self._dyn_retried = None  # 动态页重试标记只对单条指令有效
        self.executed += 1
        try:
            data = bytes(uc.mem_read(address, size))
        except UcError:
            data = b""
        if data:
            info = disasm_one(self.dis, data, address)
        else:
            info = InsnInfo(addr=address, size=size or 4, data_hex="", mnemonic="<undecoded>", op_str="", undecoded=True)
        self._last_insn = info
        # 周期估算：登记本条指令，得到其**起始**累计周期（上一条 taken 惩罚已计入）
        if self.timing is not None:
            self._cycle_now = self.timing.on_insn(address, info.size, info.mnemonic)
        self.tracer.begin_insn(
            self.executed - 1,
            address,
            info.data_hex,
            f"{info.mnemonic} {info.op_str}".strip(),
        )
        if info.csr is not None:
            # CSR 指令执行前先记录 attempted 值（异常发生时这条记录被 WARL 条目替换）
            entry = {
                "csr": info.csr,
                "op": info.csr_op or "read",
                "value": "unknown",
                "warl": False,
                "placeholder": False,
                "action_detail": "unicorn_executed",
            }
            if info.csr_op in ("write", "set", "clear"):
                v = self._csr_src_value(info)
                if v is not None:
                    entry["value"] = v
            self.tracer.attach_csr(entry)
            # 影子 CSR：trap 闭环寄存器由仿真器自维护（unicorn 无 mepc/mcause/mret 语义）
            if info.csr in SHADOW_CSR_NAMES:
                handled = self._handle_shadow_csr(info, entry)
                if handled is not None:
                    cur = self.tracer.current
                    if cur is not None:
                        cur["evidence_level"] = "hypothesis"
                    self._flush()
                    self._pending_skip = handled  # mtvec→继续下条；mret→跳到 mepc
                    uc.emu_stop()
                    return
        # mret：按影子 mepc 返回（unicorn 无该语义）
        if info.mnemonic == "mret":
            target = self.shadow_csrs.get(SHADOW_MEPC, 0)
            self.traps.append(
                {
                    "kind": "mret",
                    "at_pc": address,
                    "target": target,
                    "evidence_level": "hypothesis",
                    "note": "mret 语义由仿真器按影子 mepc 实现（标准 RISC-V 语义假设）",
                }
            )
            cur = self.tracer.current
            if cur is not None:
                cur["evidence_level"] = "hypothesis"
            self._flush()
            self._pending_skip = target
            uc.emu_stop()
            return

        report = self.loop.on_insn(address)
        if report is not None and self._loop_report is None:
            self._loop_report = report
            self._flush()
            uc.emu_stop()
            return

        hits = self._injections.match(address, self.executed - 1, cycle=self._cycle_now)
        self._after_pc = address
        for idx in hits:
            spec = self._injections.specs[idx]
            if spec.when == "after":
                # 延迟到本指令执行完再应用（否则装载指令会把寄存器写回，注入失效）
                self._injections.schedule_pending(idx)
                continue
            detail = self._injections.fire(idx, self, address, size)
            self._emit_fault_event(spec, detail, self.executed - 1, at_pc=address)
            if detail.get("kind") == "skip" and detail.get("applied"):
                self._pending_skip = detail["next_pc"]
                self._flush()
                uc.emu_stop()
                return

    def _apply_pending_after(self) -> None:
        """在下一条指令开始前，应用上一指令的 after 时机注入。

        语义：目标指令已执行完毕（寄存器写回已发生），此处翻转/写入其**结果值**。
        典型用法：`addi a0, zero, 0x504` 执行后翻 a0 的 bit30 → a0 = 0x104。
        """
        pending = self._injections.take_pending_after()
        if not pending:
            return
        # 先把上一条指令的 trace 行落盘，保证 fault_event 行排在被注入指令之后
        self._flush()
        for idx in pending:
            spec = self._injections.specs[idx]
            detail = self._injections.fire_after(idx, self)
            # applied_at_seq 用"上一条已执行指令"的序号（注入效果归属该指令）
            self._emit_fault_event(spec, detail, max(self.executed - 1, 0), at_pc=self._after_pc)

    def _emit_fault_event(self, spec, detail: dict, seq: int, at_pc: int | None = None) -> None:
        self.fault_events_fired += 1
        event_id = f"{self.run_id}-f{self.fault_events_fired:03d}"
        self.tracer.fault_event(
            event_id=event_id,
            campaign_id=spec.campaign_id or "unknown",
            trigger=render_trigger(spec),
            action=render_action(spec, detail),
            applied=bool(detail.get("applied", False)),
            applied_at_seq=seq,
            applied_result=render_applied_result(
                spec, detail, seq, cycle=self._cycle_now, timing=self.timing,
                at_pc=at_pc, when=spec.when,
            ),
        )

    def _should_log_mem(self, stub: bool) -> bool:
        if stub:
            return True  # 占位访问无论如何都记录（纪律）
        return self.config.mem_trace == "all"

    def _hook_mem_read(self, uc, access, address, size, value, ud):
        if access != _ACCESS_VALID_READ:  # 未映射/保护错类型由 unmapped 钩子负责
            return
        try:
            data = bytes(uc.mem_read(address, size))
        except UcError:
            return  # 地址尚不可翻译（unmapped 钩子会记录本次访问）
        region = self.region_of(address)
        dynamic = address & ~(PAGE_SIZE - 1) in self.dynamic_pages
        region_name = region.name if region else ("__dynamic__" if dynamic else "unknown")
        dev = self.devices.get(region_name) if region_name else None
        stub = False
        if dev is not None:
            placeholder = dev.on_read(self, address, size)
            try:
                uc.mem_write(address, int(placeholder).to_bytes(size, "little"))
            except UcError:
                pass
            stub = getattr(dev, "placeholder_reads", False)
        if region_name == "__dynamic__":
            stub = True
            # unmapped 钩子已记录并计数过的重试：只刷新事件值，不重复计数
            if getattr(self, "_dyn_retried", None) == (address, "read"):
                self._dyn_retried = None
                self.tracer.attach_mem("read", address, size, 0, region_name, True)
                return
        if stub:
            self.stub_accesses += 1
            self.stub_by_region[region_name] += 1
        v = int.from_bytes(data, "little") if size <= 8 else data.hex()
        if self._should_log_mem(stub):
            self.tracer.attach_mem("read", address, size, v, region_name, stub)

    def _hook_mem_write(self, uc, access, address, size, value, ud):
        if access != _ACCESS_VALID_WRITE:  # 未映射/保护错类型由 unmapped 钩子负责
            return
        try:
            uc.mem_read(address, size)  # 探测可翻译性；失败→unmapped 钩子记录
        except UcError:
            return
        region = self.region_of(address)
        dynamic = address & ~(PAGE_SIZE - 1) in self.dynamic_pages
        region_name = region.name if region else ("__dynamic__" if dynamic else "unknown")
        dev = self.devices.get(region_name) if region_name else None
        stub = False
        if dev is not None:
            dev.on_write(self, address, size, value)
            # 写方向：只有 null-stub 视为"写被忽略"的占位效果；设备模型收集写（如 uart-log）不标 stub
            stub = isinstance(dev, NullStubDevice)
        if region_name == "__dynamic__":
            stub = True
            if getattr(self, "_dyn_retried", None) == (address, "write"):
                self._dyn_retried = None
        if stub:
            self.stub_accesses += 1
            self.stub_by_region[region_name] += 1
        try:
            v = int(value).to_bytes(size, "little").hex()
        except (UcError, ValueError, OverflowError):
            v = "unknown"
        if self._should_log_mem(stub):
            self.tracer.attach_mem("write", address, size, v, region_name, stub)

    def _hook_mem_unmapped(self, uc, access, address, size, value, ud):
        kind = _ACCESS_KIND.get(access, "unknown")
        try:
            pc_now = self.uc.reg_read(rc.UC_RISCV_REG_PC)
        except UcError:
            pc_now = "unknown"
        event = {"kind": kind, "addr": address, "size": size, "pc": pc_now}
        # mtvec 已安装 → trap 分发（固件故意 lw(zero) 自测路径依赖此行为）
        if self.config.trap_dispatch and kind in ("read", "write") and self._try_trap_dispatch(kind, address, pc_now):
            self._unmapped_event = event
            self._unmapped_events.append({**event, "action": "trap_dispatched"})
            return False  # 抛 UcError，主循环按 _pending_trap_target 跳 handler
        # fetch 未映射一律停机：控制流离开已映射空间不静默续跑
        if self.config.unmapped_policy == "stub-page" and kind in ("read", "write"):
            page = address & ~(PAGE_SIZE - 1)
            if page in self.dynamic_pages:
                self._unmapped_event = event
                self._unmapped_events.append({**event, "action": "reuse_dynamic_page"})
                return True
            try:
                self.uc.mem_map(page, PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE)
                # 显式清零：不信任底层未初始化内存（占位页内容必须可复现，不许脏数据冒充观测）
                self.uc.mem_write(page, b"\x00" * PAGE_SIZE)
                self.dynamic_pages.add(page)
            except UcError as exc:
                event["action"] = f"map_failed:{exc}"
                self._unmapped_event = event
                self._unmapped_events.append(event)
                return False
            event["action"] = "mapped_zero_page"
            self._unmapped_event = event
            self._unmapped_events.append(event)
            # 记录本次访问（写值=钩子参数；读值=清零页必为 0，均为事实），计数一次。
            # unicorn 重试可能不再触发 valid 钩子，这里是该次访问唯一的行级记录点。
            if self.tracer.current is not None:
                try:
                    if kind == "write":
                        v = int(value).to_bytes(size, "little").hex()
                    else:
                        v = 0
                except (UcError, ValueError, OverflowError):
                    v = "unknown"
                self.tracer.attach_mem(kind, address, size, v, "__dynamic__", True, unmapped=True)
            self.stub_accesses += 1
            self.stub_by_region["__dynamic__"] += 1
            self._dyn_retried = (address, kind)
            return True
        self._unmapped_event = event
        self._unmapped_events.append(event)
        return False

    # ---------- 影子 CSR / trap 分发 ----------

    def _handle_shadow_csr(self, info: InsnInfo, entry: dict) -> int | None:
        """影子 CSR（mtvec/mepc/mcause/mtval）由仿真器按标准 RISC-V 语义维护。

        返回 pending_skip 目标（跳过 unicorn 对该指令的执行），None=不接管。
        语义是假设级：mtvec MODE=0b11 已证明芯片 CSR 行为存在非标差异。"""
        csr = info.csr
        name = SHADOW_CSR_NAMES[csr]
        op = info.csr_op or "read"
        old = self.shadow_csrs.get(csr, 0)
        rd_index = info.rd_index
        if op == "read":
            entry.update(value=old, placeholder=True, action_detail=f"sim_shadow_csr({name})")
            if rd_index not in (None, 0):
                self._gpr_write_index(rd_index, old)
        elif op in ("write", "set", "clear"):
            src = self._csr_src_value(info) or 0
            new = src if op == "write" else (old | src if op == "set" else old & ~src)
            new &= 0xFFFFFFFF
            self.shadow_csrs[csr] = new
            entry.update(
                value=src,
                placeholder=True,
                action_detail=f"sim_shadow_csr({name}: 0x{old:x}->0x{new:x})",
            )
            if rd_index not in (None, 0):
                self._gpr_write_index(rd_index, old)  # csrrw/csrrs/csrrc 读回旧值（标准语义假设）
        else:
            return None
        return info.addr + info.size

    def _try_trap_dispatch(self, kind: str, address: int, pc_now) -> bool:
        """未映射访问落在 trap_addrs 区间 → 按 mtvec 分发 trap（仿真器假设实现，v0）。

        trap_addrs 用于区分"固件故意触发的异常访问"（如自测路径 lw 0(zero)）与
        "尚未建模的内存/外设"（栈、RAM 走 stub-page 探索兜底）。
        假设标注：mcause 编码按 RISC-V 标准 access fault（read=5/write=7/fetch=1）；
        mtvec MODE 观测为非标准 0b11，BASE 提取假设为低 2 位清零；芯片实际语义未知。"""
        if not any(start <= address <= end for start, end in self.config.trap_addrs):
            return False
        mtvec = self.shadow_csrs.get(SHADOW_MTVEC, 0)
        if mtvec == 0:
            return False
        handler_base = mtvec & ~0x3
        insn_pc = self._last_insn.addr if self._last_insn is not None else pc_now
        mcause = _MCAUSE_CANDIDATE.get(kind, 1)
        self.shadow_csrs[SHADOW_MEPC] = insn_pc & 0xFFFFFFFF
        self.shadow_csrs[SHADOW_MCAUSE] = mcause
        self.shadow_csrs[SHADOW_MTVAL] = address & 0xFFFFFFFF
        self.traps.append(
            {
                "kind": "access_fault_dispatch",
                "access": kind,
                "addr": address,
                "pc_of_fault_insn": insn_pc,
                "mcause_candidate": mcause,
                "mtvec_raw": mtvec,
                "handler_base": handler_base,
                "evidence_level": "hypothesis",
                "note": "trap 分发=仿真器假设实现（mcause 标准编码；mtvec MODE 非标，BASE 提取假设低 2 位清零）",
            }
        )
        self._pending_trap_target = handler_base
        self._flush()
        return True

    def _warl_handle(self) -> int | None:
        """WARL 处理未知 CSR 异常：记录事实后继续。返回 next_pc 或 None。"""
        insn = self._last_insn
        if insn is None or insn.csr is None:
            return None
        next_pc = insn.addr + insn.size
        op = insn.csr_op or "read"
        if op in ("write", "set", "clear"):
            entry = {
                "csr": insn.csr,
                "op": op,
                "value": "unknown",
                "warl": True,
                "placeholder": True,
                "action_detail": "write_ignored_warl(unicorn未实现该CSR,真实硬件语义未知,WARL处理为假设)",
            }
            v = self._csr_src_value(insn)
            if v is not None:
                entry["value"] = v
        else:
            entry = {
                "csr": insn.csr,
                "op": "read",
                "value": 0,
                "warl": True,
                "placeholder": True,
                "action_detail": "read_placeholder_zero(unicorn未实现该CSR,真实硬件语义未知,WARL处理为假设)",
            }
            rd_index = insn.rd_index
            if rd_index is None and self._last_insn.op_str:
                for token in self._last_insn.op_str.replace(",", " ").split():
                    if token.lower() in _REG_IDS:
                        idx = _GPR_NAMES.index(token.lower())
                        rd_index = idx if idx in _INDEX_TO_NAME else None
                        break
            if rd_index is not None and self._gpr_write_index(rd_index, 0):
                entry["action_detail"] += f"(rd={_INDEX_TO_NAME.get(rd_index, f'x{rd_index}')}=0)"
        cur = self.tracer.current
        if cur is not None:
            cur["csrs_changed"] = [entry]  # 替换 code hook 时的 unicorn_executed 条目
            cur["evidence_level"] = "hypothesis"
        self.warl_count += 1
        self._flush()
        return next_pc

    # ---------- 运行 ----------

    def bind_tracer(self, tracer) -> None:
        self.tracer = tracer
        self.run_id = tracer.run_id

    def _apply_initial_regs(self) -> None:
        """入口前预置寄存器（config.initial_regs）。

        纪律：预置值是**调用方提供的假设**（例如"从某函数入口试运行、假定栈已建好"），
        不是复原了真实复位状态。预置结果写入 run_meta.memory_map.initial_regs_applied
        与 run_end.detail，并在证据说明里标 hypothesis。
        """
        self.initial_regs_applied: list[dict] = []
        for name, value in (self.config.initial_regs or {}).items():
            reg_id = self.reg_id(name)
            if reg_id is None:
                self.initial_regs_applied.append(
                    {"reg": name, "value": value, "applied": False, "error": "未知寄存器名"}
                )
                continue
            self.uc.reg_write(reg_id, int(value) & 0xFFFFFFFF)
            self.initial_regs_applied.append({"reg": name, "value": value, "applied": True})

    def _snapshot(self) -> dict:
        out = {}
        for name, rid in _REG_IDS.items():
            try:
                out[name] = self.uc.reg_read(rid)
            except UcError:
                out[name] = "unknown"
        return out

    def run(self) -> RunResult:
        if self.tracer is None:
            raise RuntimeError("先 bind_tracer 再 run")
        entry = self.resolve_entry()
        pc = entry
        self._apply_initial_regs()
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_mem_unmapped)

        stop: tuple[str, str, dict] | None = None
        while stop is None:
            remaining = self.config.max_instructions - self.executed
            if remaining <= 0:
                stop = (EXIT_MAX_INSTRUCTIONS, "instruction_limit", {"note": "达到指令数上限；不代表程序语义完成"})
                break
            try:
                self.uc.emu_start(pc, UNTIL_MARKER, 0, remaining)
            except UcError as exc:
                if self._pending_trap_target is not None:
                    # trap 分发：跳到 mtvec handler（unmapped hook 已记录事件）
                    pc = self._pending_trap_target
                    self._pending_trap_target = None
                    self._unmapped_event = None
                    continue
                reason, kind, extra = classify_uc_error(exc, self._last_insn, self._unmapped_event)
                if self.config.csr_policy == "warl-log" and kind == "unsupported_csr":
                    next_pc = self._warl_handle()
                    if next_pc is not None:
                        pc = next_pc
                        self._unmapped_event = None
                        continue
                stop = (reason, kind, extra)
                break
            if self._pending_skip is not None:
                pc = self._pending_skip
                self._pending_skip = None
                continue
            if self._loop_report is not None:
                rep = self._loop_report
                stop = (
                    EXIT_HANG_SUSPECTED,
                    f"loop_{rep['kind']}",
                    {"loop_report": rep, "note": "启发式判定：疑似死循环（hypothesis 级，非证实）"},
                )
                break
            if self.executed >= self.config.max_instructions:
                stop = (EXIT_MAX_INSTRUCTIONS, "instruction_limit", {"note": "达到指令数上限；不代表程序语义完成"})
                break
            stop = (EXIT_NORMAL, "emu_returned", {"note": "emu_start 正常返回（until 标记/hook emu_stop）"})

        self._flush()
        reason, kind, extra = stop
        regs = self._snapshot()
        try:
            final_pc = self.uc.reg_read(rc.UC_RISCV_REG_PC)
        except UcError:
            final_pc = "unknown"
        detail = {
            "detail_kind": kind,
            "entry_addr": entry,
            "regs": regs,
            "stub_accesses": self.stub_accesses,
            "stub_by_region": dict(self.stub_by_region),
            "warl_events": self.warl_count,
            "fault_events_fired": self.fault_events_fired,
            "dynamic_pages": [hex(p) for p in sorted(self.dynamic_pages)],
            "unmapped_accesses": self._unmapped_events[-20:],
            "unmapped_access_total": len(self._unmapped_events),
            "patches_applied": self.patches,
            "initial_regs_applied": getattr(self, "initial_regs_applied", []),
            "traps": self.traps,
            "shadow_csrs": {f"0x{csr:x}({SHADOW_CSR_NAMES[csr]})": f"0x{val:x}" for csr, val in sorted(self.shadow_csrs.items())},
            "uart_logs": {
                name: {"text": dev.text, "write_count": dev.write_count}
                for name, dev in self.devices.items()
                if isinstance(dev, UartLogDevice)
            },
            "timing": self.timing_report(),
            "unapplied_cycle_injections": self._injections.unmatched_cycle_specs(
                timing_enabled=self.timing is not None
            ),
            **extra,
        }
        evidence = "hypothesis" if reason == EXIT_HANG_SUSPECTED else "observation"
        self.tracer.run_end(reason, final_pc, self.executed, detail, evidence)
        timing = self.timing
        return RunResult(
            exit_reason=reason,
            detail_kind=kind,
            entry=entry,
            final_pc=final_pc,
            instructions=self.executed,
            stub_accesses=self.stub_accesses,
            warl_events=self.warl_count,
            fault_events_fired=self.fault_events_fired,
            regs=regs,
            cycles=round(timing.cycles, 3) if timing is not None else "unknown",
            ns=(
                timing.cycles_to_ns(timing.cycles)
                if timing is not None
                else "unknown"
            ),
        )

    def timing_report(self) -> dict:
        """周期/时间估算报告（供 run_end.detail 与 summary 使用）。"""
        if self.timing is None:
            return {
                "enabled": False,
                "note": "timing 模型未启用（config.timing.enabled=false）；cycles/ns 全部 unknown",
                "evidence_level": "unknown",
                "unapplied": self._injections.unmatched_cycle_specs(timing_enabled=False),
            }
        report = self.timing.report(
            run_id=getattr(self, "run_id", "unknown"),
            report_at=self.config.report_time_at,
            window_ns=self.config.window_ns,
        )
        report["enabled"] = True
        report["unapplied"] = self._injections.unmatched_cycle_specs(timing_enabled=True)
        return report
