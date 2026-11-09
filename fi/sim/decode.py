"""capstone 反汇编与 CSR 解码辅助。

CSR 号/读写形态提取：
- 32-bit SYSTEM 指令（opcode==0x73）直接按位域解出 csr/funct3/rd/rs1。
- 压缩 CSR 指令（c.csrr*）用 capstone 反汇编文本里第一个数字 token 提取
  （best-effort；解析失败置 None，不猜）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC, Cs

_NUM_TOKEN = re.compile(r"^(?:0x[0-9a-fA-F]+|[0-9]+)$")

# funct3 → 助记符族（Zicsr）
_FUNCT3_NAMES = {1: "csrrw", 2: "csrrs", 3: "csrrc", 5: "csrrwi", 6: "csrrsi", 7: "csrrci"}


@dataclass
class InsnInfo:
    addr: int
    size: int
    data_hex: str                 # 指令原始字节 hex（契约 instruction_raw）
    mnemonic: str
    op_str: str
    csr: int | None = None        # CSR 编号（best-effort）
    csr_op: str | None = None     # write | write-imm | rw | read | None
    rd_index: int | None = None   # 32-bit CSR 指令的 rd 编号
    rs1_index: int | None = None  # 32-bit CSR 指令的 rs1 编号
    undecoded: bool = False


def make_disassembler() -> Cs:
    return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


def _first_number(text: str) -> int | None:
    for token in text.replace(",", " ").split():
        if _NUM_TOKEN.match(token):
            return int(token, 0)
    return None


def disasm_one(dis: Cs, data: bytes, addr: int) -> InsnInfo:
    ins = next(dis.disasm(data, addr), None)
    if ins is None:
        return InsnInfo(
            addr=addr,
            size=len(data) or 4,
            data_hex=data.hex(),
            mnemonic="<undecoded>",
            op_str="",
            undecoded=True,
        )
    info = InsnInfo(
        addr=addr,
        size=ins.size,
        data_hex=data[: ins.size].hex(),
        mnemonic=ins.mnemonic,
        op_str=ins.op_str,
    )

    # 压缩 CSR 指令（c.csrr*）：从反汇编文本提取
    # op 枚举对齐 sim-trace 契约：write | read | set | clear
    if ins.mnemonic.startswith("c.csr"):
        info.csr = _first_number(ins.op_str)
        info.csr_op = {
            "c.csrw": "write",
            "c.csrrw": "write",
            "c.csrrwi": "write",
            "c.csrrs": "set",
            "c.csrrsi": "set",
            "c.csrrc": "clear",
            "c.csrrci": "clear",
        }.get(ins.mnemonic, "read")
        return info

    # 32-bit SYSTEM：opcode==0x73
    # csrw/csrrw→write；csrrs/csrrsi→set；csrrc/csrrci→clear；rd==x0 的 set/clear 实为纯读→read
    if len(data) >= 4:
        word = int.from_bytes(data[:4], "little")
        if word & 0x7F == 0x73:
            funct3 = (word >> 12) & 0x7
            if funct3 in _FUNCT3_NAMES:
                info.csr = (word >> 20) & 0xFFF
                info.rd_index = (word >> 7) & 0x1F
                info.rs1_index = (word >> 15) & 0x1F
                rd0 = info.rd_index == 0
                info.csr_op = {
                    1: "write",
                    2: "read" if rd0 else "set",
                    3: "read" if rd0 else "clear",
                    5: "write",
                    6: "read" if rd0 else "set",
                    7: "read" if rd0 else "clear",
                }[funct3]
    return info


def sweep_csr_write_offsets(dis: Cs, img: bytes, base: int) -> list[dict]:
    """线性扫描整镜像收集 CSR 写形态指令（--skip-csr 补丁的对照工具）。

    注意：线性扫描在数据区会反汇编出垃圾并可能误报，产物仅供人工核对，
    默认路径不用它（默认用观察到的精确 --patch-offset）。"""
    found: list[dict] = []
    off = 0
    while off < len(img):
        chunk = img[off : off + 4]
        ins = next(dis.disasm(chunk, base + off), None)
        if ins is None:
            off += 2
            continue
        mnem = ins.mnemonic
        if mnem in ("csrw", "csrwi", "csrrw", "csrrwi", "c.csrw", "c.csrrwi"):
            found.append(
                {
                    "offset": off,
                    "addr": base + off,
                    "size": ins.size,
                    "mnemonic": f"{mnem} {ins.op_str}",
                }
            )
        off += ins.size
    return found
