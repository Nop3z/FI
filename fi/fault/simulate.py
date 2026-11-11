# -*- coding: utf-8 -*-
"""fi.fault.simulate：把位翻转变体放进 Unicorn 仿真精算效果。

## 分层设计（性能与精度）

`fi.fault.reasoning` 用**轻量表达式求值**快速筛选（覆盖常见 ALU 指令，毫秒级）；
本模块对**少量候选**做**真实指令执行**验证（覆盖访存/分支/CSR 等全部形态）。

## 用法

给定一条指令的机器码与执行前寄存器状态，直接在 Unicorn 里单步执行该指令，
读回寄存器/内存变化——这是"这条损坏指令执行后到底会怎样"的权威答案
（在仿真模型的假设范围内）。

## 纪律

- 仿真结果 = Simulated State，与硬件实测（Captured State）必须分开标注
- 单步执行可能触发异常（如损坏成非法指令/非法访存），异常也是有效结论
- 全部 confidence=hypothesis（仿真≠硬件）
"""
from __future__ import annotations

from dataclasses import dataclass

SCHEMA = "fi.fault.simulate-v0"

# 单步执行用的临时映射（不依赖具体芯片布局，只为让指令能跑）
_SCRATCH_BASE = 0x10000000
_SCRATCH_SIZE = 0x1000


@dataclass
class StepResult:
    executed: bool
    insn_text: str | None
    regs_after: dict[str, int]
    mem_writes: dict[int, bytes]
    exception: str | None


def _uc_reg_consts():
    """Unicorn 的 RISC-V 寄存器常量（延迟导入，缺依赖时不影响纯静态能力）。"""
    from unicorn.riscv_const import (
        UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_A2, UC_RISCV_REG_A3,
        UC_RISCV_REG_A4, UC_RISCV_REG_A5, UC_RISCV_REG_A6, UC_RISCV_REG_A7,
        UC_RISCV_REG_GP, UC_RISCV_REG_RA, UC_RISCV_REG_S0, UC_RISCV_REG_S1,
        UC_RISCV_REG_SP, UC_RISCV_REG_T0, UC_RISCV_REG_T1, UC_RISCV_REG_T2,
        UC_RISCV_REG_TP,
    )
    return {
        "ra": UC_RISCV_REG_RA, "sp": UC_RISCV_REG_SP, "gp": UC_RISCV_REG_GP,
        "tp": UC_RISCV_REG_TP, "t0": UC_RISCV_REG_T0, "t1": UC_RISCV_REG_T1,
        "t2": UC_RISCV_REG_T2, "s0": UC_RISCV_REG_S0, "s1": UC_RISCV_REG_S1,
        "a0": UC_RISCV_REG_A0, "a1": UC_RISCV_REG_A1, "a2": UC_RISCV_REG_A2,
        "a3": UC_RISCV_REG_A3, "a4": UC_RISCV_REG_A4, "a5": UC_RISCV_REG_A5,
        "a6": UC_RISCV_REG_A6, "a7": UC_RISCV_REG_A7,
    }


def step_one_instruction(
    insn_bytes: bytes,
    exec_addr: int,
    pre_regs: dict[str, int],
    *,
    xlen: int = 32,
    scratch_base: int = _SCRATCH_BASE,
) -> StepResult:
    """在 Unicorn 里单步执行一条指令，返回执行后的寄存器与内存变化。

    ``pre_regs``：ABI 名的初始寄存器值（未知的保持 0）。
    执行地址与映射都在临时 scratch 区，不影响真实镜像语义。
    """
    try:
        from unicorn import Uc, UcError, UC_ARCH_RISCV, UC_HOOK_MEM_WRITE
        from unicorn import UC_MODE_RISCV32, UC_MODE_RISCV64
    except ImportError as exc:  # pragma: no cover
        return StepResult(False, None, dict(pre_regs), {},
                          f"unicorn 不可用: {exc}")

    import capstone

    md = capstone.Cs(capstone.CS_ARCH_RISCV,
                     (capstone.CS_MODE_RISCV32 if xlen == 32 else capstone.CS_MODE_RISCV64)
                     | capstone.CS_MODE_RISCVC)
    try:
        insn = next(md.disasm(insn_bytes, exec_addr))
        insn_text = f"{insn.mnemonic} {insn.op_str}".strip()
    except StopIteration:
        return StepResult(False, None, dict(pre_regs), {}, "无法反汇编")

    mode = UC_MODE_RISCV32 if xlen == 32 else UC_MODE_RISCV64
    uc = Uc(UC_ARCH_RISCV, mode)
    uc.mem_map(scratch_base, _SCRATCH_SIZE)
    uc.mem_write(exec_addr, insn_bytes)

    reg_map = _uc_reg_consts()
    for name, val in pre_regs.items():
        rid = reg_map.get(name)
        if rid is not None:
            uc.reg_write(rid, val & ((1 << xlen) - 1))

    writes: dict[int, bytes] = {}

    def _on_write(uc_, access, address, size, value, _ud):
        try:
            writes[address] = bytes(uc_.mem_read(address, size))
        except Exception:  # noqa: BLE001
            pass

    uc.hook_add(UC_HOOK_MEM_WRITE, _on_write)

    exc_msg: str | None = None
    executed = False
    try:
        uc.emu_start(exec_addr, exec_addr + len(insn_bytes), count=1)
        executed = True
    except UcError as exc:
        exc_msg = str(exc)

    regs_after: dict[str, int] = {}
    for name, rid in reg_map.items():
        try:
            regs_after[name] = uc.reg_read(rid)
        except Exception:  # noqa: BLE001
            pass

    return StepResult(executed, insn_text, regs_after, writes, exc_msg)


def verify_variants_by_simulation(
    variants: list[dict],
    *,
    exec_addr: int,
    pre_regs: dict[str, int],
    observed_regs: dict[str, int],
    xlen: int = 32,
) -> dict:
    """对候选变体逐个仿真执行，验证哪个能真正复现观测。

    ``variants``：来自 reasoning 的候选（需含 ``mutated_insn`` 与位信息），
    但本函数需要**机器码**——由调用方保证传入 ``insn_bytes_hex`` 字段。
    """
    results = []
    matched = []
    for v in variants:
        hexs = v.get("insn_bytes_hex") or v.get("mutated_code_hex")
        if not hexs:
            results.append({**v, "simulation": {"executed": False,
                                                "note": "缺机器码，无法仿真验证"}})
            continue
        sr = step_one_instruction(bytes.fromhex(hexs), exec_addr, pre_regs, xlen=xlen)
        mismatch = {}
        if sr.executed:
            for r, exp in observed_regs.items():
                got = sr.regs_after.get(r)
                if got is not None and got != exp:
                    mismatch[r] = {"observed": f"0x{exp:08x}",
                                   "simulated": f"0x{got:08x}"}
        item = {
            **v,
            "simulation": {
                "executed": sr.executed,
                "insn_text": sr.insn_text,
                "exception": sr.exception,
                "regs_after": {k: f"0x{val:08x}" for k, val in sr.regs_after.items()},
                "mem_writes": {f"0x{a:08x}": b.hex() for a, b in sr.mem_writes.items()},
                "matches_observation": sr.executed and not mismatch,
                "mismatch": mismatch,
            },
        }
        results.append(item)
        if sr.executed and not mismatch:
            matched.append(item)

    return {
        "schema": SCHEMA,
        "exec_addr": f"0x{exec_addr:08x}",
        "pre_state": {k: f"0x{val:08x}" for k, val in pre_regs.items()},
        "observation": {k: f"0x{val:08x}" for k, val in observed_regs.items()},
        "summary": {
            "variants_tested": len(variants),
            "executed_ok": sum(1 for r in results if r["simulation"]["executed"]),
            "matched_by_simulation": len(matched),
        },
        "results": results,
        "discipline": (
            "仿真结果属 Simulated State，与硬件实测（Captured State）必须分开；"
            "仿真能复现观测只说明'在该模型下成立'，不等于硬件机理已证实"
        ),
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
