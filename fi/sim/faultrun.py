"""在**真实镜像上下文**里做指令级故障注入并跑一段（fi/fault ↔ fi/sim 的桥）。

## 与 fi.fault.simulate 的分工

`fi.fault.simulate.step_one_instruction` 把一条指令放进**scratch 页**单步执行，
回答"这条（损坏）指令执行后寄存器会变成什么"——快、够用，但**没有真实上下文**：
gp 指向的全局区、栈帧、外设寄存器、ROM 里的数据表全都不存在，所以任何
依赖上下文的行为（`lw a4,-0x3c(gp)`、`c.swsp`、间接跳转）都跑不出真实结果。

本模块补的是另一半：**保留完整镜像与内存映射、只把目标地址上的指令字节换成
变体，然后从某个入口跑一段**。这样 gp/栈/外设/数据表都是真实的（在仿真模型假设内），
能观察到"这条指令坏掉之后，固件继续跑会发生什么"——正是 hn security 文章
第 7 步（把枚举出的损坏指令放进仿真复现解释）在 RISC-V 上的落地方式。

## 两种注入模型的区别（**极其重要，容易混淆**）

| 模型 | 做法 | 语义 | 本模块 |
| --- | --- | --- | --- |
| **指令损坏** | 替换目标地址的**指令机器码** | 模拟毛刺把指令编码的某些位翻掉（如 `addi a0,zero,0x504` 的 imm bit10 位于机器码 bit30，翻它 → `addi a0,zero,0x104`） | ✅ `patch_instruction` |
| **寄存器损坏** | 在某条指令**执行后**翻转寄存器位 | 模拟毛刺直接打坏寄存器结果（`a0=0x504` 翻 bit10 → 0x104） | ✅ 用 fi.sim 的 `flip_reg_bits` + `when=after` |

两者的 **bit 位置不一样**：指令编码里 imm bit10 在机器码 bit30，而寄存器值是
bit10 本身。把"指令 bit30"误当成"寄存器 bit30"会得到完全错误（且无效）的注入。
本模块的 `variant_to_patch()` 与 `variant_to_reg_flip()` 把这两种换算显式做出来。

## 纪律

- 结论是 Simulated State（仿真状态），与 Captured State（硬件实测）严格分开；
- 全部 `confidence=hypothesis`；
- 变体指令无法解码、或执行触发异常，都是**有效结论**，不当作错误；
- 不含任何芯片专有常量（地址/寄存器/掩码全部由调用方传入）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .config import EntrySpec, InjectSpec, LoopPolicy, RegionSpec, SimConfig, TimingPolicy
from .machine import Simulator
from .tracer import NullTracer

SCHEMA = "fi.sim.faultrun-v0"
UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# 指令替换
# ---------------------------------------------------------------------------


@dataclass
class InstructionPatch:
    """把某个地址上的指令字节换成变体字节。"""

    addr: int
    original_bytes: bytes
    mutated_bytes: bytes
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "addr": self.addr,
            "addr_hex": f"0x{self.addr:08x}",
            "original_hex": self.original_bytes.hex(),
            "mutated_hex": self.mutated_bytes.hex(),
            "note": self.note,
            "evidence_level": "hypothesis",
        }


def apply_instruction_patches(
    image: bytes,
    base: int,
    patches: Iterable[InstructionPatch],
) -> tuple[bytes, list[dict]]:
    """返回打过指令补丁的新镜像 + 补丁清单（原镜像不被修改）。"""
    buf = bytearray(image)
    applied: list[dict] = []
    for p in patches:
        off = p.addr - base
        if off < 0 or off + len(p.original_bytes) > len(buf):
            applied.append({**p.as_dict(), "applied": False, "error": "地址越界（不在镜像内）"})
            continue
        current = bytes(buf[off:off + len(p.original_bytes)])
        if current != p.original_bytes:
            applied.append(
                {
                    **p.as_dict(),
                    "applied": False,
                    "error": "镜像内容与声明的 original_bytes 不符（拒绝盲改）",
                    "image_bytes_at_addr_hex": current.hex(),
                }
            )
            continue
        buf[off:off + len(p.mutated_bytes)] = p.mutated_bytes
        applied.append({**p.as_dict(), "applied": True})
    return bytes(buf), applied


# ---------------------------------------------------------------------------
# 从 fi.fault 的变体换算到两种注入模型
# ---------------------------------------------------------------------------


def variant_to_patch(addr: int, original_bytes: bytes, mutated_bytes: bytes, note: str = "") -> InstructionPatch:
    """fi.fault 的位翻转变体 → **指令损坏**补丁（直接替换机器码）。"""
    return InstructionPatch(addr=addr, original_bytes=original_bytes,
                            mutated_bytes=mutated_bytes, note=note)


def variant_to_reg_flip(
    original_bytes: bytes,
    mutated_bytes: bytes,
    reg: str,
) -> dict:
    """fi.fault 的位翻转变体 → **寄存器损坏**参数（after 时机）。

    用途：当"翻指令编码的某一位"恰好等价于"翻寄存器结果的某一位"时
    （典型：立即数装载指令），可以用寄存器翻转更快地复现同一观测，
    不需要改镜像。本函数把指令位差换算成寄存器掩码：

      - 只支持 12 位立即数装载形态（addi rd, x0, imm）；其他形态返回 unsupported；
      - 返回的 mask 是**寄存器值**的掩码（不是指令编码的位位置）。
    """
    from .decode import disasm_one, make_disassembler

    dis = make_disassembler()
    before = disasm_one(dis, original_bytes, 0)
    after = disasm_one(dis, mutated_bytes, 0)
    info: dict[str, Any] = {
        "schema": "fi.sim.variant-reg-flip-v0",
        "reg": reg,
        "before_insn": f"{before.mnemonic} {before.op_str}".strip(),
        "after_insn": f"{after.mnemonic} {after.op_str}".strip(),
        "supported": False,
        "note": "",
        "evidence_level": "hypothesis",
    }
    if before.mnemonic != "addi" or not before.op_str.startswith(f"{reg}, zero,"):
        info["note"] = "仅支持 `addi <reg>, zero, <imm12>` 形态的立即数装载指令"
        return info
    if after.mnemonic != "addi" or not after.op_str.startswith(f"{reg}, zero,"):
        info["note"] = "变体已不是立即数装载形态（语义类别变了），不能用寄存器位翻转等价表达"
        return info
    try:
        imm_before = int(before.op_str.rsplit(",", 1)[1].strip(), 0)
        imm_after = int(after.op_str.rsplit(",", 1)[1].strip(), 0)
    except (IndexError, ValueError):
        info["note"] = "立即数解析失败"
        return info
    mask = imm_before ^ imm_after
    info.update(
        {
            "supported": True,
            "imm_before": f"0x{imm_before:x}",
            "imm_after": f"0x{imm_after:x}",
            "reg_mask": f"0x{mask:x}",
            "reg_mask_int": mask,
            "note": (
                "指令编码位 → 寄存器位换算完成：等价于在装载后翻转寄存器 mask。"
                "注意 mask 是**寄存器值**的掩码，不等于指令编码里的位位置"
            ),
        }
    )
    return info


# ---------------------------------------------------------------------------
# 运行
# ---------------------------------------------------------------------------


@dataclass
class FaultRunResult:
    exit_reason: str
    detail_kind: str
    instructions: int
    cycles: Any
    ns: Any
    final_pc: Any
    regs_before: dict = field(default_factory=dict)
    regs_after: dict = field(default_factory=dict)
    reg_diff: dict = field(default_factory=dict)
    mem_writes: list = field(default_factory=list)
    uart_text: str = UNKNOWN
    uart_bytes_hex: str = UNKNOWN
    stop_detail: dict = field(default_factory=dict)
    patches: list = field(default_factory=list)
    fault_events: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            'exit_reason': self.exit_reason,
            'detail_kind': self.detail_kind,
            'instructions': self.instructions,
            'cycles_estimate': self.cycles,
            'ns_estimate': self.ns,
            'final_pc': self.final_pc,
            'reg_diff': self.reg_diff,
            'mem_writes': self.mem_writes,
            'uart_text': self.uart_text,
            'uart_bytes_hex': self.uart_bytes_hex,
            'patches': self.patches,
            'fault_events': self.fault_events,
        }


def run_with_variant(
    image_path: str | Path,
    base: int,
    *,
    entry_addr: int | None = None,
    entry_region: str | None = None,
    entry_offset: int = 0,
    patches: Iterable[InstructionPatch] = (),
    injects: Iterable[Any] = (),
    initial_regs: dict[str, int] | None = None,
    extra_regions: Iterable[RegionSpec] = (),
    image_region_name: str = "image",
    image_region_kind: str = "rom",
    image_region_size: int | None = None,
    max_instructions: int = 20000,
    ns_per_cycle: float | None = None,
    report_time_at: Iterable[int] = (),
    snapshot_regs: Iterable[str] = (),
    unmapped_policy: str = "stub-page",
    csr_policy: str = "warl-log",
    loop: LoopPolicy | None = None,
    write_patched_image: str | Path | None = None,
) -> FaultRunResult:
    """在真实镜像上下文里跑一次"坏掉的固件"，输出差异与停止原因。

    与普通 `fi.sim run` 的区别：
    - 指令补丁在内存镜像里生效（可选择把打补丁后的镜像落盘供复核）；
    - 自动对比 snapshot_regs 的前后值（默认全 GPR）；
    - 收集 UART 输出字节（若配置了 uart-log 设备）；
    - 返回结构化结果，便于 fi.fault 的批量候选验证直接消费。
    """
    image_path = Path(image_path)
    image = image_path.read_bytes()
    size = image_region_size or ((len(image) + 0xFFF) & ~0xFFF)

    patched_image, patch_log = apply_instruction_patches(image, base, patches)
    applied_any = any(p.get("applied") for p in patch_log)

    # 有补丁时用临时镜像文件承载"坏掉的固件"（Simulator 从 file 装载）
    image_file: Path | None = image_path
    tmp_path: Path | None = None
    if applied_any or write_patched_image is not None:
        import tempfile

        if write_patched_image is not None:
            tmp_path = Path(write_patched_image)
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            tmp_path = Path(tempfile.mkdtemp()) / "patched-image.bin"
        tmp_path.write_bytes(patched_image)
        image_file = tmp_path

    regions = [
        RegionSpec(
            name=image_region_name,
            kind=image_region_kind,
            base=base,
            size=size,
            file=image_file,
        ),
        *extra_regions,
    ]
    if entry_addr is not None:
        entry = EntrySpec(addr=entry_addr)
    else:
        entry = EntrySpec(region=entry_region or image_region_name, offset=entry_offset)

    cfg = SimConfig(
        regions=regions,
        entry=entry,
        max_instructions=max_instructions,
        unmapped_policy=unmapped_policy,
        csr_policy=csr_policy,
        timing=TimingPolicy(ns_per_cycle=ns_per_cycle),
        report_time_at=list(report_time_at),
        initial_regs=dict(initial_regs or {}),
        injects=list(injects),
        loop=loop or LoopPolicy(),
    )
    sim = Simulator(cfg)
    sim.bind_tracer(NullTracer("faultrun"))
    result = sim.run()

    before = {k: 0 for k in _GPR_NAMES_DEFAULT}
    after = dict(result.regs)
    watch = list(snapshot_regs) or [k for k in after if k != "pc"]
    diff = {}
    for name in watch:
        if name in after:
            old = before.get(name, 0)
            if after[name] != old:
                diff[name] = {
                    "before": f"0x{old:x}" if isinstance(old, int) else old,
                    "after": f"0x{after[name]:x}" if isinstance(after[name], int) else after[name],
                }

    uart_text = UNKNOWN
    uart_hex = UNKNOWN
    for dev in sim.devices.values():
        if hasattr(dev, "log") and hasattr(dev, "text"):
            uart_text = dev.text
            uart_hex = bytes(dev.log).hex()
            break

    fault_events = []
    tracer = sim.tracer
    for ev in getattr(tracer, "fault_events", []) or []:
        fault_events.append(
            {
                "event_id": ev.get("event_id"),
                "trigger": ev.get("trigger"),
                "action": ev.get("action"),
                "applied": ev.get("applied"),
                "applied_at_seq": ev.get("applied_at_seq"),
                "applied_result": ev.get("applied_result"),
            }
        )

    run_end = getattr(tracer, "run_end_row", None) or {}
    stop_detail = (run_end.get("detail") or {})

    return FaultRunResult(
        exit_reason=result.exit_reason,
        detail_kind=result.detail_kind,
        instructions=result.instructions,
        cycles=result.cycles,
        ns=result.ns,
        final_pc=result.final_pc,
        regs_before=before,
        regs_after=after,
        reg_diff=diff,
        mem_writes=stop_detail.get("patches_applied") or [],
        uart_text=uart_text,
        uart_bytes_hex=uart_hex,
        stop_detail=stop_detail,
        patches=patch_log,
        fault_events=fault_events,
    )


_GPR_NAMES_DEFAULT = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6",
]


# ---------------------------------------------------------------------------
# 批量验证（给 fi.fault 的候选集直接用）
# ---------------------------------------------------------------------------


def verify_variants_in_context(
    image_path: str | Path,
    base: int,
    variants: Iterable[dict],
    *,
    exec_addr: int,
    baseline_builder=None,
    **run_kwargs,
) -> dict:
    """把一批位翻转变体逐个放进真实上下文跑，与基线对照，列出**能复现观测**的候选。

    ``variants``：形如 `{"mutated_code_hex": ..., "flipped_bit_positions": [...], ...}`；
    需含 `mutated_code_hex`（变体机器码）与（可选）`original_code_hex`。

    ``baseline_builder``：可选，`fn(result) -> dict`，用于把一次运行归一成
    "可观测量"（如 UART 字节/关键寄存器），便于基线-变体对比。默认用
    `{"uart_bytes_hex", "reg_diff", "exit_reason"}`。
    """
    baseline = run_with_variant(image_path, base, **run_kwargs)
    normalize = baseline_builder or _default_normalize
    base_obs = normalize(baseline)

    rows = []
    reproduced = []
    for v in variants:
        mutated_hex = v.get("mutated_code_hex") or v.get("insn_bytes_hex")
        original_hex = v.get("original_code_hex")
        if not mutated_hex:
            rows.append({**v, "faultrun": {"applied": False, "note": "缺变体机器码"}})
            continue
        try:
            mutated = bytes.fromhex(mutated_hex)
        except ValueError:
            rows.append({**v, "faultrun": {"applied": False, "note": "变体机器码非法 hex"}})
            continue
        if original_hex:
            original = bytes.fromhex(original_hex)
        else:
            original = _read_image_bytes(image_path, base, exec_addr, len(mutated))

        patch = InstructionPatch(addr=exec_addr, original_bytes=original,
                                 mutated_bytes=mutated, note="variant")
        try:
            res = run_with_variant(image_path, base, patches=[patch], **run_kwargs)
        except Exception as exc:  # noqa: BLE001 —— 单个变体失败不影响整批
            rows.append({**v, "faultrun": {"applied": False, "error": str(exc)}})
            continue
        obs = normalize(res)
        same_as_baseline = obs == base_obs
        item = {
            **v,
            "faultrun": {
                "applied": patch.as_dict(),
                "exit_reason": res.exit_reason,
                "detail_kind": res.detail_kind,
                "instructions": res.instructions,
                "reg_diff": res.reg_diff,
                "uart_bytes_hex": res.uart_bytes_hex,
                "observation": obs,
                "same_as_baseline": same_as_baseline,
            },
        }
        rows.append(item)
        if not same_as_baseline:
            reproduced.append(item)

    return {
        "schema": SCHEMA,
        "image": str(image_path),
        "base_address": base,
        "exec_addr": f"0x{exec_addr:08x}",
        "baseline": {
            "exit_reason": baseline.exit_reason,
            "detail_kind": baseline.detail_kind,
            "instructions": baseline.instructions,
            "observation": base_obs,
        },
        "summary": {
            "variants_tested": len(rows),
            "variants_changed_observation": len(reproduced),
        },
        "results": rows,
        "discipline": (
            "Simulated State：仿真里复现只说明'在该模型下成立'，不等于硬件机理已证实；"
            "指令损坏模型（改镜像）与寄存器损坏模型（改寄存器）的 bit 位置不同，不可混用"
        ),
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


def _default_normalize(result: FaultRunResult) -> dict:
    return {
        "exit_reason": result.exit_reason,
        "detail_kind": result.detail_kind,
        "uart_bytes_hex": result.uart_bytes_hex,
        "reg_diff": result.reg_diff,
    }


def _read_image_bytes(image_path: str | Path, base: int, addr: int, length: int) -> bytes:
    image = Path(image_path).read_bytes()
    off = addr - base
    if off < 0 or off + length > len(image):
        raise ValueError(f"地址 0x{addr:08x} 不在镜像范围内（base=0x{base:08x}）")
    return image[off:off + length]


def dump_report(report: dict, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
