# -*- coding: utf-8 -*-
"""fi.discover.functions：函数抽取与调用链数据库（可达性驱动版）。

用户要求（2026-11-09）："先分析出来运行执行了什么函数，然后将这些函数都抽出来，
组成数据库或其他形式。"

## 为什么必须可达性驱动（实测教训）

线性扫描（linear sweep）把数据段也当指令解码，在 128KB 的样例镜像上产生
22 万条伪调用边、把所有函数体切成碎片——得到的"调用图"是垃圾。

正确做法是**递归下降（recursive descent）+ 控制流遍历**：从入口开始，
逐条解码，遇到分支则把两个目标都加入待办，遇到调用则记录边并把被调函数
加入待办，遇到返回/尾部跳转则本路径结束。只有被真正走到的字节才被认定为代码。

## 产物

  1) 函数清单：入口、边界、栈帧、保存寄存器、直接调用、间接调用点、返回点、
     引用的绝对地址（外设/内存线索）
  2) 调用图：caller → callee 边（含调用点）
  3) SQLite 数据库（可 SQL 查询）+ JSON 导出
  4) 调用链回溯查询：给定目标函数，向上回溯到根的所有路径

## 纪律

  - 芯片无关（通用性门禁）
  - 全部 hypothesis：无符号表，边界是结构推断
  - 函数名占位 func_<addr>，语义命名归分析层
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import capstone

from .common import make_disassembler, load_image, sha256_hex

SCHEMA = "fi.discover.functions-v1"
DB_VERSION = 2

# 控制流分类
_TERMINATORS = {"ret", "mret", "c.jr", "jr", "sret", "uret", "ebreak"}
_UNCOND_JUMPS = {"j", "c.j", "jal"}          # jal rd=x0 是无条件跳转（尾调用）
_BRANCHES = {
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
    "c.beqz", "c.bnez",
}


@dataclass
class Function:
    addr: int
    entry_insn: str = ""
    insn_addrs: set[int] = field(default_factory=set)
    size: int = 0
    stack_frame: int | None = None
    saved_regs: list[str] = field(default_factory=list)
    direct_calls: dict[int, list[int]] = field(default_factory=dict)   # callee -> [call_site]
    indirect_call_sites: list[int] = field(default_factory=list)
    tail_calls: list[int] = field(default_factory=list)
    return_sites: list[int] = field(default_factory=list)
    abs_consts: list[int] = field(default_factory=list)
    mem_refs: list[tuple[int, str]] = field(default_factory=list)
    has_csr_access: bool = False


def _resolve_target(insn: "capstone.CsInsn", text: str, base: int, size: int) -> int | None:
    """把跳转/分支指令的目标解析为绝对地址。

    **关键事实（已用真实仿真轨迹校准）**：capstone 对 RISC-V 的 jal/branch
    输出的是**相对当前指令地址的偏移**，不是绝对地址、也不是镜像内偏移。

    证据（trace 逐字节验证）：
      0x<ADDR> `jal 0x3bf4` → 实际执行 0x<ADDR>
      而 0x<ADDR> + 0x3bf4 = 0x<ADDR> ✓

    因此解析规则：target = insn.address + displayed_value。
    极少数情况下 capstone 可能直接给出绝对地址（落在镜像区间），此时原样采用。
    """
    m = re.search(r"(?:^|,\s*)(0x[0-9a-fA-F]+|-?\d+)$", text.strip())
    if not m:
        m = re.search(r"(0x[0-9a-fA-F]+|-?\d+)$", text.strip())
        if not m:
            return None
    try:
        val = int(m.group(1), 0)
    except ValueError:
        return None

    # 情形 A：已落在镜像区间（绝对地址形态）
    if base <= val < base + size:
        return val

    # 情形 B：相对当前指令地址的偏移（capstone RISC-V 的默认输出）
    relative = insn.address + val
    if base <= relative < base + size:
        return relative

    # 情形 C：镜像内偏移形态（部分反汇编器/某些指令）
    if 0 <= val < size:
        absolute = base + val
        if base <= absolute < base + size:
            return absolute

    return None


def discover_functions(
    image_path: str,
    base: int,
    *,
    xlen: int = 32,
    compressed: bool = True,
    entry_offsets: list[int] | None = None,
    max_functions: int = 4096,
    max_insns: int = 2_000_000,
) -> dict:
    """可达性驱动的函数发现主入口。"""
    image = load_image(image_path)
    size = len(image)
    md = make_disassembler(xlen, compressed)

    def decode_one(addr: int):
        off = addr - base
        if not (0 <= off < size):
            return None
        chunk = image[off:off + 4]
        try:
            insn = next(md.disasm(chunk, addr))
        except StopIteration:
            return None
        if not (0 <= off + insn.size <= size):
            return None
        return insn

    # ---- 待办入口队列：默认从镜像起点开始 ----
    pending: deque[int] = deque()
    seeds = [base + o for o in (entry_offsets or [0])]
    for s in seeds:
        if base <= s < base + size:
            pending.append(s)

    visited_code: set[int] = set()
    funcs: dict[int, Function] = {}
    insn_cache: dict[int, "capstone.CsInsn"] = {}

    def analyze_function(entry: int) -> None:
        nonlocal pending
        f = Function(addr=entry)
        work: deque[int] = deque([entry])
        seen: set[int] = set()
        first = True
        while work:
            addr = work.popleft()
            if addr in seen:
                continue
            seen.add(addr)
            insn = insn_cache.get(addr) or decode_one(addr)
            if insn is None:
                continue
            insn_cache[addr] = insn
            visited_code.add(addr)
            f.insn_addrs.add(addr)
            mnem = insn.mnemonic
            text = f"{insn.mnemonic} {insn.op_str}".strip()
            if first:
                f.entry_insn = text
                first = False
            # 栈帧
            if f.stack_frame is None and mnem in ("addi", "c.addi16sp") and "sp" in text:
                m = re.match(r"^addi\s+sp,\s*sp,\s*(-?(?:0x[0-9a-fA-F]+|\d+))$", text)
                if m:
                    v = int(m.group(1), 0)
                    if v < 0:
                        f.stack_frame = -v
            # 保存寄存器
            m = re.match(r"^(?:c\.)?sw\s+(\w+),\s*[^,]*\(sp\)$", text)
            if m and m.group(1) not in f.saved_regs:
                f.saved_regs.append(m.group(1))
            if mnem.startswith("csr") or mnem in ("csrr", "csrw", "csrrs", "csrrc"):
                f.has_csr_access = True
            # 绝对地址常量（外设/内存线索）
            mel = re.match(r"^(?:c\.)?lui\s+\w+,\s*(-?(?:0x[0-9a-fA-F]+|\d+))$", text)
            if mel:
                v = int(mel.group(1), 0) << 12
                if not (base <= v < base + size) and v >= 0x1000:
                    if v not in f.abs_consts:
                        f.abs_consts.append(v)
            # 控制流
            if mnem in _TERMINATORS:
                f.return_sites.append(addr)
                continue
            if mnem in ("jal", "c.jal"):
                rd = text.split()[1].split(",")[0] if "," in text else ""
                target = _resolve_target(insn, text, base, size)
                if target is None:
                    continue
                if rd in ("ra", "x1"):
                    # 调用：记录边，被调函数加入待办；**本函数继续走 fall-through**
                    # （call-return 语义：调用返回后继续执行下一条）
                    f.direct_calls.setdefault(target, []).append(addr)
                    if target not in funcs and target not in pending:
                        pending.append(target)
                    nxt = addr + insn.size
                    if base <= nxt < base + size:
                        work.append(nxt)
                else:
                    # rd=x0 等：无条件跳转/尾调用，本路径转移目标
                    work.append(target)
                continue
            if mnem in ("c.j", "j"):
                target = _resolve_target(insn, text, base, size)
                if target is not None:
                    work.append(target)
                continue
            if mnem in _BRANCHES:
                target = _resolve_target(insn, text, base, size)
                if target is not None:
                    work.append(target)
                # fall-through
                nxt = addr + insn.size
                if base <= nxt < base + size:
                    work.append(nxt)
                continue
            if mnem in ("jalr", "c.jalr"):
                # 间接调用或返回：ra 作基址且无偏移 → 视为返回
                if re.search(r"\bra\b", insn.op_str) and mnem == "c.jalr":
                    f.return_sites.append(addr)
                    continue
                f.indirect_call_sites.append(addr)
                continue
            # 普通指令：顺序执行
            nxt = addr + insn.size
            if base <= nxt < base + size:
                work.append(nxt)

        if f.insn_addrs:
            lo, hi = min(f.insn_addrs), max(f.insn_addrs)
            insn_hi = insn_cache.get(hi)
            f.size = (hi - lo) + (insn_hi.size if insn_hi is not None else 4)
        funcs[entry] = f

    # ---- 主循环：不断处理待办入口，直到收敛 ----
    processed: set[int] = set()
    while pending and len(funcs) < max_functions and len(visited_code) < max_insns:
        entry = pending.popleft()
        if entry in processed or entry in funcs:
            continue
        processed.add(entry)
        analyze_function(entry)
        # 新发现的入口可能已经在本轮被记录，重新入队处理其函数体
        for callee in list(funcs[entry].direct_calls):
            if callee not in funcs and callee not in processed:
                pending.append(callee)

    # ---- 调用图反查 ----
    callers: dict[int, list[tuple[int, int]]] = {}
    for f in funcs.values():
        for callee, sites in f.direct_calls.items():
            for s in sites:
                callers.setdefault(callee, []).append((f.addr, s))

    roots = [a for a in funcs if a not in callers]
    leaves = [a for a, fn in funcs.items()
              if not fn.direct_calls and not fn.indirect_call_sites]

    return {
        "schema": SCHEMA,
        "tool": {"name": "fi.discover.functions", "version": "0.2.0", "db_version": DB_VERSION},
        "image": {
            "path": str(image_path), "sha256": sha256_hex(image),
            "size_bytes": size, "base_address": base,
            "base_address_hex": f"0x{base:08x}",
        },
        "method": {
            "algorithm": "递归下降 + 控制流遍历（可达性驱动，非线性扫描）",
            "why": [
                "线性扫描会把数据段当指令解码：实测在 128KB 镜像上产生 22 万条伪调用边、"
                "函数体碎裂，调用图不可用",
                "递归下降只把真正可达的字节认定为代码，调用图边的可信度显著提高",
            ],
            "entry_detection": [
                "显式种子入口（默认镜像起点 offset 0）",
                "调用目标（jal rd=ra 的解析目标）递归加入待办",
            ],
            "boundaries": [
                "无符号表：函数边界为可达指令集合的包络，可能包含共享尾部",
                "间接调用（jalr/c.jalr 非 ra）目标未解析，调用图存在缺失边",
                "函数指针表调用的函数（如经表 dispatch 的公共发送函数）不会被静态发现——"
                "需动态轨迹或指针表分析补充",
                "数据段中未被可达性触达的函数不会被发现（可能是死代码或经表调用）",
                "函数名占位 func_<addr>，语义命名需人工/分析层归因",
            ],
            "coverage": {
                "code_bytes_reached": len(visited_code),
                "image_bytes": size,
                "coverage_ratio": round(len(visited_code) / max(1, size), 4),
            },
        },
        "summary": {
            "function_count": len(funcs),
            "direct_call_edges": sum(len(s) for f in funcs.values() for s in f.direct_calls.values()),
            "indirect_call_sites": sum(len(f.indirect_call_sites) for f in funcs.values()),
            "tail_calls": sum(len(f.tail_calls) for f in funcs.values()),
            "root_candidates": len(roots),
            "leaf_functions": len(leaves),
            "funcs_with_csr_access": sum(1 for f in funcs.values() if f.has_csr_access),
        },
        "functions": [
            {
                "func_id": f"func-{f.addr:08x}",
                "addr": f"0x{f.addr:08x}",
                "size": f.size,
                "insn_count": len(f.insn_addrs),
                "entry_insn": f.entry_insn,
                "stack_frame": f.stack_frame,
                "saved_regs": f.saved_regs,
                "direct_calls": [
                    {"callee": f"0x{c:08x}", "call_sites": [f"0x{s:08x}" for s in sites]}
                    for c, sites in sorted(f.direct_calls.items())
                ],
                "callers": [
                    {"caller": f"0x{c:08x}", "call_sites": [f"0x{s:08x}" for s in sites]}
                    for c, sites in sorted(
                        ((c, [s for cc, s in callers.get(f.addr, []) if cc == c])
                         for c in {cc for cc, _ in callers.get(f.addr, [])}), key=lambda x: x[0])
                ],
                "indirect_call_sites": [f"0x{a:08x}" for a in f.indirect_call_sites],
                "return_sites": [f"0x{a:08x}" for a in f.return_sites],
                "abs_consts": [f"0x{a:08x}" for a in f.abs_consts[:20]],
                "has_csr_access": f.has_csr_access,
                "confidence": "hypothesis",
                "evidence_kind": "artifact_derived",
            }
            for f in sorted(funcs.values(), key=lambda x: x.addr)
        ],
        "call_graph": {
            "edges": [
                {"caller": f"0x{f.addr:08x}", "callee": f"0x{c:08x}",
                 "call_sites": [f"0x{s:08x}" for s in sites]}
                for f in funcs.values() for c, sites in f.direct_calls.items()
            ],
            "root_candidates": [f"0x{a:08x}" for a in roots],
        },
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


# ---------------------------------------------------------------------------
# SQLite 导出与查询
# ---------------------------------------------------------------------------

def export_sqlite(report: dict, db_path: str | Path) -> Path:
    """把函数清单 + 调用图导出为可 SQL 查询的 SQLite 库。"""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    cur.executescript(
        """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE image (path TEXT, sha256 TEXT, size_bytes INT, base_address INT);
        CREATE TABLE functions (
            func_id TEXT PRIMARY KEY, addr INT, size INT, insn_count INT,
            entry_insn TEXT, stack_frame INT, has_csr_access INT,
            confidence TEXT, evidence_kind TEXT
        );
        CREATE TABLE call_edges (
            caller INT, callee INT, call_site INT, edge_kind TEXT
        );
        CREATE TABLE saved_regs (func_id TEXT, reg TEXT);
        CREATE TABLE abs_consts (func_id TEXT, addr INT);
        CREATE INDEX idx_func_addr ON functions(addr);
        CREATE INDEX idx_edge_caller ON call_edges(caller);
        CREATE INDEX idx_edge_callee ON call_edges(callee);
        CREATE INDEX idx_const_addr ON abs_consts(addr);
        """
    )
    cur.executemany("INSERT INTO meta VALUES (?,?)", [
        ("schema", report["schema"]),
        ("tool", json.dumps(report["tool"], ensure_ascii=False)),
        ("confidence", report["confidence"]),
        ("evidence_kind", report["evidence_kind"]),
    ])
    img = report["image"]
    cur.execute("INSERT INTO image VALUES (?,?,?,?)",
                (img["path"], img["sha256"], img["size_bytes"], img["base_address"]))
    for fn in report["functions"]:
        cur.execute("INSERT INTO functions VALUES (?,?,?,?,?,?,?,?,?)", (
            fn["func_id"], int(fn["addr"], 16), fn["size"], fn["insn_count"],
            fn["entry_insn"], fn["stack_frame"], int(fn["has_csr_access"]),
            fn["confidence"], fn["evidence_kind"]))
        cur.executemany("INSERT INTO saved_regs VALUES (?,?)",
                        [(fn["func_id"], r) for r in fn["saved_regs"]])
        cur.executemany("INSERT INTO abs_consts VALUES (?,?)",
                        [(fn["func_id"], int(a, 16)) for a in fn["abs_consts"]])
    for fn in report["functions"]:
        caller = int(fn["addr"], 16)
        for c in fn["direct_calls"]:
            for site in c["call_sites"]:
                cur.execute("INSERT INTO call_edges VALUES (?,?,?,?)",
                            (caller, int(c["callee"], 16), int(site, 16), "direct"))
        for s in fn["indirect_call_sites"]:
            cur.execute("INSERT INTO call_edges VALUES (?,?,?,?)",
                        (caller, -1, int(s, 16), "indirect_unknown"))
    con.commit()
    con.close()
    return db_path


def trace_call_chain(db_path: str | Path, function_addr: int, max_depth: int = 64,
                     max_paths: int = 200) -> dict:
    """向上回溯调用链：给定目标函数，返回所有到达根的路径。

    这是"构造完整调用链"的查询入口：要打某功能时，先问"谁调用它、一路到入口"。
    """
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    paths: list[list[dict]] = []
    visited: set[int] = set()

    def walk(node: int, path: list[dict]) -> None:
        if len(paths) >= max_paths or len(path) > max_depth:
            return
        if node in visited:
            paths.append({"path": path, "note": "cycle detected"})
            return
        rows = con.execute(
            "SELECT caller, call_site FROM call_edges WHERE callee=? AND edge_kind='direct'",
            (node,)).fetchall()
        if not rows:
            paths.append({"path": list(reversed(path)), "reaches_entry": True})
            return
        visited.add(node)
        for r in rows:
            fn = con.execute("SELECT entry_insn FROM functions WHERE addr=?",
                             (r["caller"],)).fetchone()
            step = {
                "caller": f"0x{r['caller']:08x}",
                "call_site": f"0x{r['call_site']:08x}",
                "callee": f"0x{node:08x}",
                "caller_entry": fn["entry_insn"] if fn else "unknown",
            }
            walk(r["caller"], path + [step])
        visited.discard(node)

    walk(function_addr, [])
    con.close()
    return {
        "target": f"0x{function_addr:08x}",
        "paths": paths,
        "path_count": len(paths),
        "confidence": "hypothesis",
        "note": "间接调用/函数指针表调用的边不在图中，回溯结果可能不完整",
    }
