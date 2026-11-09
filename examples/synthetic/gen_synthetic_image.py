# -*- coding: utf-8 -*-
"""生成一颗"陌生芯片"的合成 RV32 镜像，用于验证发现能力不依赖具体芯片。

设计：完全自造地址空间与命令集（与任何真实芯片无关），但保留 RISC-V 通用结构：
  - 复位入口：安装 mtvec、调用主流程
  - 命令分派：RAM 分派表 + 从 ROM 源表 memcpy（与真实固件同构，但地址/命令号全新）
  - 每个 handler 体内以立即数装载各自的"错误码"（值由脚本随机选取，不取真实码）
  - 一段 trap handler（保存寄存器 + csrr mcause + mret）

验证目标：fi discover regions/traps/dispatch/attribute 在**零改动**下能恢复：
  命令表条目数、每个命令号、每个 handler 地址、每个错误码的归因。

用法：
    python examples/synthetic/gen_synthetic_image.py --out examples/synthetic/synthetic-a.bin
产出同时打印"真值表"（ground truth），供测试断言。
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

# ---- RISC-V 编码小工具（RV32I + C 子集，够用即可） ----

def r_type(funct7: int, rs2: int, rs1: int, funct3: int, rd: int, opcode: int) -> int:
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def i_type(imm: int, rs1: int, funct3: int, rd: int, opcode: int) -> int:
    imm &= 0xFFF
    return (imm << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def s_type(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    imm &= 0xFFF
    return ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((imm & 0x1F) << 7) | opcode


def b_type(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    imm &= 0x1FFF
    return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3F) << 25) | (rs2 << 20) | (rs1 << 15) \
        | (funct3 << 12) | (((imm >> 1) & 0xF) << 8) | (((imm >> 11) & 1) << 7) | opcode


def j_type(imm: int, rd: int, opcode: int) -> int:
    imm &= 0x1FFFFF
    return (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3FF) << 21) | (((imm >> 11) & 1) << 20) \
        | (((imm >> 12) & 0xFF) << 12) | (rd << 7) | opcode


def u_type(imm20: int, rd: int, opcode: int) -> int:
    return ((imm20 & 0xFFFFF) << 12) | (rd << 7) | opcode


ADDI, JAL, LUI, SW, LW, BNE, CSRW, CSRR, MRET, AUIPC, ADDI_SP = 0x13, 0x6F, 0x37, 0x23, 0x03, 0x63, 0x73, 0x73, 0x73, 0x17, 0x13


def build(commands: list[tuple[int, int]], codes: dict[int, int], base: int) -> tuple[bytes, dict]:
    """构造镜像：ROM 表 + 分派器 + 各 handler。

    commands: [(cmd_byte, flag_byte)]；codes: {cmd_byte: code_value}
    返回 (image, ground_truth)
    """
    # 布局规划
    RESET_OFF = 0x0000
    TRAP_OFF = 0x0200
    TABLE_OFF = 0x1000          # ROM 源表（8 字节/项）
    DISPATCH_OFF = 0x2000       # 分派器
    HANDLER_BASE = 0x3000       # 各 handler 起点，间隔 0x100
    PAD = 0x100

    # 镜像总长需覆盖 handler 区（HANDLER_BASE + 命令数*0x100）
    total = HANDLER_BASE + len(commands) * 0x100 + PAD
    img = bytearray(total)

    def put(off: int, word: int) -> None:
        struct.pack_into("<I", img, off, word & 0xFFFFFFFF)

    # --- 复位入口：装 mtvec，跳到分派器 ---
    put(RESET_OFF + 0x00, u_type((base + TRAP_OFF) >> 12, 5, LUI))       # lui t0, trap>>12
    put(RESET_OFF + 0x04, i_type((base + TRAP_OFF) & 0xFFF, 5, 0, 5, ADDI))  # addi t0,t0,low
    put(RESET_OFF + 0x08, i_type(0x305, 5, 1, 0, CSRW))                  # csrw mtvec, t0
    put(RESET_OFF + 0x0C, j_type(DISPATCH_OFF - (RESET_OFF + 0x0C), 0, JAL))

    # --- trap handler：保存 ra 到栈、读 mcause、mret ---
    put(TRAP_OFF + 0x00, i_type(-16, 2, 0, 2, ADDI))                     # addi sp,sp,-16
    put(TRAP_OFF + 0x04, s_type(12, 1, 2, 2, SW))                        # sw ra,12(sp)
    put(TRAP_OFF + 0x08, i_type(0x342, 0, 2, 12, CSRR))                  # csrr a2, mcause
    put(TRAP_OFF + 0x0C, i_type(12, 2, 0, 1, LW))                        # lw ra,12(sp)
    put(TRAP_OFF + 0x10, i_type(16, 2, 0, 2, ADDI))                      # addi sp,sp,16
    put(TRAP_OFF + 0x14, 0x30200073)                                     # mret

    # --- ROM 源表：每项 8 字节 [cmd u8][flag u8][pad u16][ptr u32] ---
    handler_addrs = {}
    for i, (cmd, flag) in enumerate(commands):
        h_off = HANDLER_BASE + i * 0x100
        handler_addrs[cmd] = base + h_off
        entry_off = TABLE_OFF + i * 8
        img[entry_off + 0] = cmd & 0xFF
        img[entry_off + 1] = flag & 0xFF
        struct.pack_into("<H", img, entry_off + 2, 0)
        struct.pack_into("<I", img, entry_off + 4, base + h_off)

    # --- 分派器：从 RAM 表取项 → 间接跳转（用真实的 c.jr t1 形态）---
    # 简化：lw t1, 0(t0) —— 真实固件是表基址 + cmd*8；这里保留"间接跳转"结构
    put(DISPATCH_OFF + 0x00, u_type((base + TABLE_OFF) >> 12, 6, LUI))   # lui t1, table>>12
    put(DISPATCH_OFF + 0x04, i_type((base + TABLE_OFF) & 0xFFF, 6, 0, 6, ADDI))
    put(DISPATCH_OFF + 0x08, i_type(4, 6, 2, 7, LW))                     # lw t2, 4(t1)  取 handler 指针
    put(DISPATCH_OFF + 0x0C, 0x00030067)                                 # jalr x0, 0(t2) 跳到 handler

    # --- 各 handler：装载自己的错误码（addi a0,zero,code）然后返回 ---
    for i, (cmd, flag) in enumerate(commands):
        h_off = HANDLER_BASE + i * 0x100
        code = codes.get(cmd, 0)
        put(h_off + 0x00, i_type(-16, 2, 0, 2, ADDI))                    # addi sp,sp,-16
        put(h_off + 0x04, s_type(12, 1, 2, 2, SW))                       # sw ra,12(sp)
        # 码装载：大于 12 位的用 lui+addi 两段构造
        if code <= 0x7FF:
            put(h_off + 0x08, i_type(code, 0, 0, 10, ADDI))              # addi a0,zero,code
            nxt = 0x0C
        else:
            put(h_off + 0x08, u_type((code + 0x800) >> 12, 10, LUI))     # lui a0, hi
            put(h_off + 0x0C, i_type(code & 0xFFF, 10, 0, 10, ADDI))     # addi a0,a0,lo
            nxt = 0x10
        put(h_off + nxt + 0x00, i_type(12, 2, 0, 1, LW))                 # lw ra,12(sp)
        put(h_off + nxt + 0x04, i_type(16, 2, 0, 2, ADDI))               # addi sp,sp,16
        put(h_off + nxt + 0x08, 0x00008067)                              # ret (jalr x0,0(ra))

    gt = {
        "base": f"0x{base:08x}",
        "size_bytes": len(img),
        "reset_vector": f"0x{base + RESET_OFF:08x}",
        "trap_handler": f"0x{base + TRAP_OFF:08x}",
        "table_addr": f"0x{base + TABLE_OFF:08x}",
        "dispatcher": f"0x{base + DISPATCH_OFF:08x}",
        "command_count": len(commands),
        "commands": [
            {"cmd": f"0x{c:02x}", "flag": f, "handler": f"0x{handler_addrs[c]:08x}",
             "code": f"0x{codes.get(c, 0):04x}"}
            for c, f in commands
        ],
    }
    return bytes(img), gt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="输出 .bin 路径")
    ap.add_argument("--base", default="0x80000000", help="合成镜像基址（故意不同于任何真实芯片）")
    ap.add_argument("--gt", default=None, help="真值表 JSON 输出路径（默认与 bin 同名）")
    args = ap.parse_args()

    base = int(args.base, 0)
    # 完全自造的命令集与码值（与真实芯片无关）
    commands = [(0x01, 1), (0x02, 1), (0x07, 1), (0x0B, 1), (0x15, 1), (0x2A, 0), (0x7E, 1)]
    codes = {0x01: 0x0A01, 0x02: 0x0B02, 0x07: 0x0C03, 0x0B: 0x0D04,
             0x15: 0x0E05, 0x2A: 0x0F06, 0x7E: 0x1007}

    img, gt = build(commands, codes, base)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(img)
    gt_path = Path(args.gt) if args.gt else out.with_suffix(".truth.json")
    gt_path.write_text(json.dumps(gt, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"OK 写出镜像 {out}（{len(img)} 字节，base={gt['base']}）")
    print(f"OK 真值表 {gt_path}")
    print(json.dumps(gt, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
