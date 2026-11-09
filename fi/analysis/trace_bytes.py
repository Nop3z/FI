# -*- coding: utf-8 -*-
"""从仿真 trace 重建 UART 字节流（当 uart-bytes.bin 缺失时的替代证据通道）。

**为什么需要这个模块（诚实说明）**
2026-11-09 的 v13c 运行由 ``fi/sim/cli.py`` 路径产出，该路径**只写 boot.log 与
campaign-records.jsonl，不写 uart-bytes.bin**（写 .bin 的是 ``fi/sim/backend.py``
的 ``run()``）。因此任务陈述中的 ``uart-bytes.bin`` 在磁盘上并不存在——不能
凭空声称读到了该文件。

但 trace.jsonl 里逐条记录了每次 UART 数据寄存器写入的 (seq, addr, size, value)
——这是仿真器写钩子的**观测级记录**。按 seq 顺序、按写入的字节序拼接，即可
重建出固件实际写出的字节序列。重建结果与"若当初落了 .bin"应当逐字节相同，
因为二者来源是同一批写事件。

**证据分级**：
- "固件在第 N 条指令写入了字节 B 到 0x4000A1xx" = observation（trace 记录）；
- "重建的字节流 = 固件实际写出的字节序列" = 由上述观测直接拼接，无推断；
- "该字节流等于真实硬件线路上的电平序列" = **hypothesis**（设备模型是假设）。

本模块芯片无关：寄存器地址区间、写记录字段名由调用方传入。
"""

from __future__ import annotations

import json
from pathlib import Path

__all__ = ["reconstruct_uart_stream_from_trace", "TraceReconstruction"]


class TraceReconstruction:
    """trace 重建结果（含可审计的逐字节来源）。"""

    def __init__(self, data: bytes, writes: list[dict], meta: dict):
        self.data = data
        self.writes = writes
        self.meta = meta

    def to_dict(self) -> dict:
        return {
            "data_hex": self.data.hex(),
            "data_ascii": "".join(chr(b) if 32 <= b < 127 else "."
                                  for b in self.data),
            "n_writes": len(self.writes),
            "data_register_addrs": sorted({w["addr"] for w in self.writes}),
            "writes": self.writes,
            **self.meta,
        }


def reconstruct_uart_stream_from_trace(
    trace_path: str | Path,
    data_addr_lo: int,
    data_addr_hi: int,
    region_name: str | None = "uart0",
) -> TraceReconstruction:
    """按 trace 中的写事件顺序重建字节流。

    ``data_addr_lo``/``data_addr_hi``：视为"数据寄存器"的地址区间（含端点）。
    写入值按 ``size`` 小端展开为字节（``sb`` 即 1 字节，``sw`` 则展开 4 字节）。

    ``region_name``：只取该 region 内的写（None = 不按 region 过滤）。
    """
    writes = []
    buf = bytearray()
    seq_of = []
    run_id = None
    for line in Path(trace_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if obj.get("type") == "run_meta" and run_id is None:
            run_id = obj.get("run_id")
        if obj.get("type") != "trace":
            continue
        ma = obj.get("mem_access")
        if not isinstance(ma, dict):
            continue
        if ma.get("kind") != "write":
            continue
        addr = ma.get("addr")
        if not isinstance(addr, int) or not (data_addr_lo <= addr <= data_addr_hi):
            continue
        if region_name is not None and ma.get("region") != region_name:
            continue
        raw_val = ma.get("value")
        size = int(ma.get("size") or 1)
        try:
            ival = int(raw_val, 16) if isinstance(raw_val, str) else int(raw_val)
        except (TypeError, ValueError):
            continue
        chunk = ival.to_bytes(size, "little")
        buf.extend(chunk)
        seq = obj.get("seq")
        writes.append({
            "seq": seq,
            "pc": (f"0x{obj['pc']:08x}" if isinstance(obj.get("pc"), int) else obj.get("pc")),
            "addr": addr,
            "size": size,
            "value_hex": chunk.hex(),
            "stub": ma.get("stub"),
        })
        seq_of.append(seq)

    meta = {
        "trace_path": str(trace_path),
        "run_id": run_id,
        "reconstruction_method": (
            "按 trace 中 UART 数据寄存器写事件的 seq 顺序，将每次写入的 value "
            "按 size 小端展开后顺序拼接"
        ),
        "evidence_level": "observation",
        "evidence_note": (
            "每次写事件是仿真器写钩子的观测记录（observation）；拼接是无推断的直接组合。"
            "但'该字节序列等于真实硬件线路电平'仍为 hypothesis（UART 设备模型是假设，"
            "真实寄存器偏移/就绪语义未证实）"
        ),
        "filter": {"data_addr_lo": hex(data_addr_lo), "data_addr_hi": hex(data_addr_hi),
                   "region_name": region_name},
    }
    return TraceReconstruction(bytes(buf), writes, meta)
