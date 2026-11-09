"""紧凑二进制轨迹格式（FITB v1）——写入器 + 读取器。

## 为什么需要

`--trace-level=full` 逐指令落 JSONL 时实测 **262 B/指令**（40 万指令 = 100 MB），
在"74 万次实验历史规模"下不可用。本模块把逐指令记录压到 **≤8 B/指令**
（实测 target-chip 40 万指令约 4.5 B/指令，见 `docs/sim/trace-levels-v0.md`）。

## 设计取舍

压得下去的三个原因：
1. **PC 增量编码**：88% 的指令是顺序执行（pc == prev_pc + prev_size），
   一个标志位就够，不需要存 4 字节绝对地址。
2. **指令字典**：一条 40 万指令的真实运行只有约 558 种不同指令编码，
   首次出现时内联（原始字节 + 反汇编文本），之后只写 1–2 字节字典索引。
3. **事件位图 + 变长整数**：内存访问只有约 33% 的指令有，读/写/大小/占位标志
   压进 1 个字节，地址用相对上一次访问地址的 zigzag 变长编码。

**不压内容，只压表示**：disasm 也进字典，所以读回的行与 full 模式逐字段等价
（唯一例外是 writeback，本来就恒 unknown）。

## 文件结构（分块，按写入顺序）

```
magic   b"FITB"          4 B
version u16 LE           2 B   当前 = 1
flags   u16 LE           2 B   保留（当前 0）
        —— 之后是连续的块，读到 EOF 结束 ——
block:  type u8 | len u32 LE | payload[len]
        type 1 = META      payload = run_meta JSON（utf-8）
        type 2 = INSNS     payload = 一条或多条指令记录（见下）
        type 3 = JSONROW   payload = 一条契约 JSON 行（fault_event / run_end）
        type 4 = INSNDICT  保留（当前字典在指令记录内联增长）
```

## 指令记录（type 2 的 payload 内连续排列）

```
flags u8
  bit0-1  pc 增量宽度码：0=顺序执行（隐含 delta=上一条指令长度）、1=1B、2=2B、3=4B
  bit2    有内存访问事件
  bit3    有 CSR 事件
  bit4    该行 evidence_level = hypothesis（否则 observation）
  bit5    指令是**新字典项**（内联原始字节 + 反汇编文本），否则后随字典索引
  bit6    内联时指令长度码：0=2B、1=4B
  bit7    扩展标志：后随 1 个扩展字节
[ext u8]            仅 bit7=1 时存在；bit0=内存事件数 >1（后随 varint 事件数）
pc 增量             按 bit0-1 的宽度，zigzag 变长
指令                新项：u8 原始字节（2 或 4） | 旧项：varint 字典索引
内存事件（若有）     见下，可能有多个（扩展字节给出数量）
CSR 事件（若有）     varint 条目数 + 每条的紧凑编码
```

## 内存事件

```
hdr u8
  bit0-1  kind：0=read、1=write、2=fetch、3=unknown
  bit2-3  地址增量宽度码：0=1B、1=2B、2=4B、3=varint
  bit4-5  size 码：0=1B、1=2B、2=4B、3=8B
  bit6    stub（占位值）
  bit7    value 为 unknown（否则按 size 写原始小端字节）
addr 增量            zigzag（相对上一次内存访问地址）
region              varint（字符串字典索引，新增项按“下一个槽位”隐式写入）
value               size 字节原始小端；或 value 为 unknown 时不写
```

## CSR 事件条目

```
csr                varint
op 码              u8：0=read、1=write、2=set、3=clear、4=unknown
value 类型         u8：0=无符号整数（后随 varint）、1=unknown
flags              u8：bit0=warl、bit1=placeholder
action_detail      varint（字符串字典索引）
```

## 字符串字典

region 名与 `action_detail` 共用一张字符串表。编码规则：写 `varint(id)`；
当 `id == 读取端当前表长` 表示**新项**，紧跟 `varint(len) + utf8 bytes`，
读取端把它追加到表尾（因此两端表序天然一致，不需要额外同步）。

## 纪律

- 二进制格式只是**表示层**；读回的行必须逐个字段符合 `sim-trace.schema.json`。
- 读回时 `disasm` 从字典还原（不依赖 capstone），保持与写入端一致。
- 本模块不含任何芯片专有常量。
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, Iterator

MAGIC = b"FITB"
VERSION = 1
HEADER = struct.Struct("<4sHH")

BLOCK_META = 1
BLOCK_INSNS = 2
BLOCK_JSONROW = 3
BLOCK_INSNDICT = 4

# 标志位
F_PCDELTA_MASK = 0b0000_0011
F_HAS_MEM = 0b0000_0100
F_HAS_CSR = 0b0000_1000
F_HYPOTHESIS = 0b0001_0000
F_INSN_NEW = 0b0010_0000
F_INSN_SIZE4 = 0b0100_0000
F_EXT = 0b1000_0000

_OP_ENUM = {"read": 0, "write": 1, "set": 2, "clear": 3}
_OP_NAMES = ("read", "write", "set", "clear")
_KIND_ENUM = {"read": 0, "write": 1, "fetch": 2}
_KIND_NAMES = ("read", "write", "fetch", "unknown")
_SIZE_CODE = {1: 0, 2: 1, 4: 2, 8: 3}
_SIZE_FROM_CODE = (1, 2, 4, 8)

_UNKNOWN = "unknown"
_DYNAMIC_REGION = "__dynamic__"


# ---------------------------------------------------------------------------
# 变长整数
# ---------------------------------------------------------------------------


def _write_varint(buf: bytearray, value: int) -> None:
    if value < 0:
        raise ValueError(f"varint 不接受负数: {value}")
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            buf.append(byte | 0x80)
        else:
            buf.append(byte)
            return


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("varint 截断：数据提前结束")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint 过长（>63 位）")


def _zigzag_encode(value: int) -> int:
    return (value << 1) ^ (value >> 63) if value < 0 else (value << 1)


def _zigzag_decode(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


# ---------------------------------------------------------------------------
# 写入器
# ---------------------------------------------------------------------------


class BinaryTracer:
    """紧凑二进制轨迹写入器（实现与 Tracer 相同的接口，可直接交给 Simulator）。

    与 `fi.sim.tracer.Tracer` 的接口契约一致：
    `begin_insn / attach_mem / attach_csr / mark_hypothesis / flush_insn /
    fault_event / run_end / close / current / run_id`。
    """

    def __init__(self, path: str | Path, run_id: str, meta: dict[str, Any]):
        self.path = Path(path)
        self.run_id = run_id
        self._f = self.path.open("wb")
        self._f.write(HEADER.pack(MAGIC, VERSION, 0))
        self._buf = bytearray()
        self._chunk_records = 0
        self._chunk_limit = 4096  # 每块最多多少条指令记录（控制内存与块开销）

        # 指令字典：raw bytes -> index；disasm 与 raw 一起内联，读回时一致
        self._insn_index: dict[bytes, int] = {}
        self._insn_list: list[tuple[bytes, str]] = []
        # 字符串字典（region 名 / action_detail）
        self._str_index: dict[str, int] = {}
        self._str_list: list[str] = []

        self._prev_pc: int | None = None
        self._prev_size = 0
        self._prev_mem_addr: int | None = None
        self._cur: dict[str, Any] | None = None

        # 统计（给 bench / summary 用）
        self.stats = {
            "trace_level": "binary",
            "instructions": 0,
            "mem_events": 0,
            "csr_events": 0,
            "instruction_dict_entries": 0,
            "string_dict_entries": 0,
            "blocks": 0,
        }
        self._emit_block(BLOCK_META, json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    # ---- 块与字典 ----

    def _emit_block(self, block_type: int, payload: bytes) -> None:
        self._f.write(bytes((block_type,)))
        self._f.write(struct.pack("<I", len(payload)))
        self._f.write(payload)
        self.stats["blocks"] += 1

    def _flush_chunk(self) -> None:
        if not self._buf:
            return
        self._emit_block(BLOCK_INSNS, bytes(self._buf))
        self._buf = bytearray()
        self._chunk_records = 0

    def _str_id(self, text: str) -> int:
        idx = self._str_index.get(text)
        if idx is not None:
            _write_varint(self._buf, idx)
            return idx
        idx = len(self._str_list)
        self._str_index[text] = idx
        self._str_list.append(text)
        self.stats["string_dict_entries"] = len(self._str_list)
        _write_varint(self._buf, idx)  # idx == len-1，读取端据此识别“新项”
        encoded = text.encode("utf-8")
        _write_varint(self._buf, len(encoded))
        self._buf.extend(encoded)
        return idx

    # ---- Tracer 接口 ----

    def begin_insn(self, seq: int, pc: int, instruction_raw: str, disasm: str) -> None:
        self.flush_insn()
        self._cur = {
            "type": "trace",
            "run_id": self.run_id,
            "seq": seq,
            "pc": pc,
            "instruction_raw": instruction_raw,
            "disasm": disasm,
            "mem_access": _UNKNOWN,
            "csrs_changed": [],
            "writeback": _UNKNOWN,
            "evidence_level": "observation",
        }

    def attach_mem(
        self,
        kind: str,
        addr: int,
        size: int,
        value: Any,
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
        entry = {
            "kind": kind,
            "addr": addr,
            "size": size,
            "value": value,
            "stub": stub,
            "region": region,
            "note": note,
        }
        if unmapped:
            entry["unmapped"] = True
        existing = self._cur["mem_access"]
        if isinstance(existing, dict):
            # 与 Tracer 行为保持一致：一条指令只留最后一次 mem_access（已知限制，
            # 见 docs/sim/trace-format-v0.md）；但二进制层如实累计计数。
            self._cur.setdefault("_mem_extra", 0)
            self._cur["_mem_extra"] += 1
        self._cur["mem_access"] = entry
        if stub:
            self._cur["evidence_level"] = "hypothesis"

    def attach_csr(self, entry: dict) -> None:
        if self._cur is None:
            return
        self._cur["csrs_changed"].append(entry)

    def mark_hypothesis(self) -> None:
        if self._cur is None:
            return
        self._cur["evidence_level"] = "hypothesis"

    def flush_insn(self) -> None:
        cur = self._cur
        if cur is None:
            return
        self._cur = None
        self._encode_record(cur)
        self.stats["instructions"] += 1
        self._chunk_records += 1
        if self._chunk_records >= self._chunk_limit:
            self._flush_chunk()

    def fault_event(
        self,
        event_id: str,
        campaign_id: str,
        trigger: dict,
        action: dict,
        applied: bool,
        applied_at_seq: int,
        applied_result: dict | str = _UNKNOWN,
    ) -> None:
        self.flush_insn()
        self._flush_chunk()
        row = {
            "type": "fault_event",
            "event_id": event_id,
            "run_id": self.run_id,
            "campaign_id": campaign_id,
            "trigger": trigger,
            "action": action,
            "pulse": _UNKNOWN,
            "applied": applied,
            "applied_at_seq": applied_at_seq,
            "applied_result": applied_result,
            "evidence_level": "hypothesis",
        }
        self._emit_block(BLOCK_JSONROW, json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def run_end(
        self,
        exit_reason: str,
        final_pc: int,
        instruction_count: int,
        detail: dict,
        evidence_level: str,
    ) -> None:
        self.flush_insn()
        self._flush_chunk()
        row = {
            "type": "run_end",
            "run_id": self.run_id,
            "exit_reason": exit_reason,
            "final_pc": final_pc,
            "instruction_count": instruction_count,
            "detail": detail,
            "evidence_level": evidence_level,
        }
        self._emit_block(BLOCK_JSONROW, json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def close(self) -> None:
        self.flush_insn()
        self._flush_chunk()
        if not self._f.closed:
            self._f.flush()
            self._f.close()

    @property
    def current(self) -> dict | None:
        return self._cur

    # ---- 记录编码 ----

    def _encode_record(self, cur: dict) -> None:
        pc = int(cur["pc"])
        raw_hex = cur.get("instruction_raw") or ""
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            raw = b""
        size = len(raw)

        flags = 0
        # PC 增量
        if self._prev_pc is None:
            delta = pc
            width_code = 1 if -128 <= delta <= 127 else (2 if -32768 <= delta <= 32767 else 3)
        else:
            delta = pc - (self._prev_pc + self._prev_size)
            if delta == 0:
                width_code = 0
            elif -128 <= delta <= 127:
                width_code = 1
            elif -32768 <= delta <= 32767:
                width_code = 2
            else:
                width_code = 3

        flags |= width_code

        mem = cur.get("mem_access")
        has_mem = isinstance(mem, dict)
        if has_mem:
            flags |= F_HAS_MEM
        csrs = cur.get("csrs_changed") or []
        if csrs:
            flags |= F_HAS_CSR
        if cur.get("evidence_level") == "hypothesis":
            flags |= F_HYPOTHESIS

        is_new = raw not in self._insn_index
        if is_new:
            flags |= F_INSN_NEW
            if size != 2 and size != 4:
                # 非 2/4 字节指令：跳过二进制记录（写入端不应出现，防御性处理）
                flags &= ~F_INSN_NEW
                is_new = False
            elif size == 4:
                flags |= F_INSN_SIZE4

        mem_extra = int(cur.get("_mem_extra") or 0)
        if mem_extra:
            flags |= F_EXT

        self._buf.append(flags)
        if flags & F_EXT:
            # 扩展字节：bit0 表示存在多条内存事件（本实现只保留最后一条，
            # 但如实记录被丢弃的条数，读端可据此提示信息缺失）
            self._buf.append(0x01)
            _write_varint(self._buf, mem_extra)

        if width_code == 0:
            pass
        elif width_code == 1:
            self._buf.extend(struct.pack("<b", delta))
        elif width_code == 2:
            self._buf.extend(struct.pack("<h", delta))
        elif -2147483648 <= delta <= 2147483647:
            self._buf.extend(struct.pack("<i", delta))
        else:
            # 理论不可达（PC 是 32 位），但显式失败优于静默截断
            raise ValueError(f"PC 增量超出 32 位有符号范围: {delta}")

        if is_new:
            self._insn_index[raw] = len(self._insn_list)
            self._insn_list.append((raw, cur.get("disasm") or _UNKNOWN))
            self.stats["instruction_dict_entries"] = len(self._insn_list)
            self._buf.extend(raw)
        else:
            _write_varint(self._buf, self._insn_index[raw])

        if has_mem:
            self._encode_mem(mem)

        if csrs:
            _write_varint(self._buf, len(csrs))
            for entry in csrs:
                self._encode_csr(entry)

        self._prev_pc = pc
        self._prev_size = size or 4
        self.stats["mem_events" if has_mem else "_"] = self.stats.get("mem_events", 0) + (1 if has_mem else 0)
        if csrs:
            self.stats["csr_events"] = self.stats.get("csr_events", 0) + len(csrs)

    def _encode_mem(self, mem: dict) -> None:
        kind = str(mem.get("kind") or "unknown")
        kind_code = _KIND_ENUM.get(kind, 3)
        addr = int(mem.get("addr") or 0)
        size = int(mem.get("size") or 4)
        size_code = _SIZE_CODE.get(size)
        if size_code is None:
            size_code = 2
            size = 4
        stub = bool(mem.get("stub"))
        value = mem.get("value")
        value_unknown = not isinstance(value, int) and not isinstance(value, (bytes, bytearray))
        if isinstance(value, str):
            try:
                value_bytes = bytes.fromhex(value)
                value_unknown = len(value_bytes) != size
            except ValueError:
                value_unknown = True
        elif isinstance(value, (bytes, bytearray)):
            value_bytes = bytes(value)
            value_unknown = len(value_bytes) != size
        elif isinstance(value, int):
            value_bytes = int(value).to_bytes(size, "little", signed=False) if value >= 0 else b""
            value_unknown = value < 0 or value >= (1 << (size * 8))
        else:
            value_bytes = b""
            value_unknown = True

        if self._prev_mem_addr is None:
            delta = addr
            awidth = 3
        else:
            delta = addr - self._prev_mem_addr
            if -128 <= delta <= 127:
                awidth = 0
            elif -32768 <= delta <= 32767:
                awidth = 1
            elif -2147483648 <= delta <= 2147483647:
                awidth = 2
            else:
                awidth = 3  # 超出 32 位有符号范围：退回 zigzag varint（不静默截断）
        hdr = kind_code & 0b11
        hdr |= (awidth & 0b11) << 2
        hdr |= (size_code & 0b11) << 4
        if stub:
            hdr |= 0b0100_0000
        if value_unknown:
            hdr |= 0b1000_0000
        self._buf.append(hdr)

        if awidth == 0:
            self._buf.extend(struct.pack("<b", delta))
        elif awidth == 1:
            self._buf.extend(struct.pack("<h", delta))
        elif awidth == 2:
            self._buf.extend(struct.pack("<i", delta))
        else:
            _write_varint(self._buf, _zigzag_encode(delta))

        self._str_id(str(mem.get("region") or _UNKNOWN))

        if not value_unknown:
            self._buf.extend(value_bytes[:size])
        self._prev_mem_addr = addr

    def _encode_csr(self, entry: dict) -> None:
        _write_varint(self._buf, int(entry.get("csr") or 0))
        op = str(entry.get("op") or "read")
        self._buf.append(_OP_ENUM.get(op, 4))
        value = entry.get("value")
        if isinstance(value, int) and value >= 0:
            self._buf.append(0)
            _write_varint(self._buf, value)
        else:
            self._buf.append(1)
        flags = 0
        if entry.get("warl") is True:
            flags |= 0b01
        if entry.get("placeholder") is True:
            flags |= 0b10
        self._buf.append(flags)
        self._str_id(str(entry.get("action_detail") or _UNKNOWN))


# ---------------------------------------------------------------------------
# 读取器
# ---------------------------------------------------------------------------


class TraceReader:
    """把 FITB 二进制轨迹流式读回 sim-trace 契约行。

    用法：
        reader = TraceReader("trace.fitb")
        for row in reader.iter_rows():
            ...  # row 与 full 模式 JSONL 的字段一致（disasm 从字典还原）

    或一次性拿全部行：`TraceReader(path).read_all()`。
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._insn_list: list[tuple[bytes, str]] = []
        self._str_list: list[str] = []
        self.run_id: str | None = None
        self.meta: dict | None = None
        self.errors: list[str] = []
        self.info: dict[str, Any] = {
            "version": None,
            "blocks": 0,
            "instructions": 0,
            "mem_events": 0,
            "csr_events": 0,
            "dropped_mem_events": 0,
        }

    # ---- 公共 API ----

    def iter_rows(self) -> Iterator[dict]:
        with self.path.open("rb") as f:
            head = f.read(HEADER.size)
            if len(head) < HEADER.size:
                raise ValueError(f"不是 FITB 文件（头部截断）: {self.path}")
            magic, version, _flags = HEADER.unpack(head)
            if magic != MAGIC:
                raise ValueError(f"magic 不匹配（期望 {MAGIC!r}，实际 {magic!r}）: {self.path}")
            if version != VERSION:
                raise ValueError(f"不支持的 FITB 版本 {version}（本读取器支持 {VERSION}）")
            self.info["version"] = version

            seq = 0
            prev_pc: int | None = None
            prev_size = 0
            prev_mem_addr: int | None = None

            while True:
                type_and_len = f.read(5)
                if not type_and_len:
                    break
                if len(type_and_len) < 5:
                    self.errors.append("块头截断（文件可能未正常关闭）")
                    break
                block_type = type_and_len[0]
                (length,) = struct.unpack("<I", type_and_len[1:])
                payload = f.read(length)
                if len(payload) < length:
                    self.errors.append(f"块 payload 截断（type={block_type}, 期望 {length}B）")
                    break
                self.info["blocks"] += 1

                if block_type == BLOCK_META:
                    self.meta = json.loads(payload.decode("utf-8"))
                    self.run_id = self.meta.get("run_id")
                    yield self.meta
                elif block_type == BLOCK_JSONROW:
                    yield json.loads(payload.decode("utf-8"))
                elif block_type == BLOCK_INSNS:
                    pos = 0
                    while pos < len(payload):
                        row, pos, prev_pc, prev_size, prev_mem_addr = self._decode_record(
                            payload, pos, seq, prev_pc, prev_size, prev_mem_addr
                        )
                        seq += 1
                        self.info["instructions"] += 1
                        yield row
                elif block_type == BLOCK_INSNDICT:
                    # 预留：当前字典在指令记录内联增长
                    continue
                else:
                    self.errors.append(f"未知块类型 {block_type}（已跳过 {length}B）")

    def read_all(self) -> list[dict]:
        return list(self.iter_rows())

    # ---- 记录解码 ----

    def _decode_record(
        self,
        data: bytes,
        pos: int,
        seq: int,
        prev_pc: int | None,
        prev_size: int,
        prev_mem_addr: int | None,
    ) -> tuple[dict, int, int, int, int | None]:
        if pos >= len(data):
            raise ValueError("指令记录截断（缺 flags 字节）")
        flags = data[pos]
        pos += 1

        mem_extra = 0
        if flags & F_EXT:
            if pos >= len(data):
                raise ValueError("指令记录截断（缺扩展字节）")
            ext = data[pos]
            pos += 1
            if ext & 0x01:
                mem_extra, pos = _read_varint(data, pos)

        width_code = flags & F_PCDELTA_MASK
        if width_code == 0:
            delta = 0
        elif width_code == 1:
            (delta,) = struct.unpack_from("<b", data, pos)
            pos += 1
        elif width_code == 2:
            (delta,) = struct.unpack_from("<h", data, pos)
            pos += 2
        else:
            (delta,) = struct.unpack_from("<i", data, pos)
            pos += 4

        if prev_pc is None:
            pc = delta
        else:
            pc = prev_pc + prev_size + delta

        if flags & F_INSN_NEW:
            size = 4 if flags & F_INSN_SIZE4 else 2
            raw = data[pos:pos + size]
            pos += size
            self._insn_list.append((raw, _UNKNOWN))  # 占位，稍后补 disasm
            insn_idx = len(self._insn_list) - 1
        else:
            insn_idx, pos = _read_varint(data, pos)
            if insn_idx >= len(self._insn_list):
                raise ValueError(f"指令字典索引越界: {insn_idx} >= {len(self._insn_list)}")
            raw, _ = self._insn_list[insn_idx]
            size = len(raw)

        # 注意：disasm 在本格式中**不内联**（字典项只存原始字节）。
        # 原因：disasm 可由 capstone 从字节重建，内联会让文件多出约 20 B/条；
        # 读取端提供 `resolve_disasm` 时按需反汇编，否则写 "unknown"（契约允许）。
        row: dict[str, Any] = {
            "type": "trace",
            "run_id": self.run_id,
            "seq": seq,
            "pc": pc,
            "instruction_raw": raw.hex(),
            "disasm": _UNKNOWN,
            "mem_access": _UNKNOWN,
            "csrs_changed": [],
            "writeback": _UNKNOWN,
            "evidence_level": "hypothesis" if flags & F_HYPOTHESIS else "observation",
        }

        if flags & F_HAS_MEM:
            mem, pos, prev_mem_addr = self._decode_mem(data, pos, prev_mem_addr)
            if mem_extra:
                # 一条指令多次访存时 full 模式只留最后一次（已知限制）；这里如实说明
                self.info["dropped_mem_events"] += mem_extra
                mem["note"] = (
                    f"该指令另有 {mem_extra} 次内存访问未被记录"
                    f"（遵循 full 模式'一条指令只留最后一次 mem_access'的既有约定）"
                )
            row["mem_access"] = mem
            self.info["mem_events"] += 1

        if flags & F_HAS_CSR:
            count, pos = _read_varint(data, pos)
            entries = []
            for _ in range(count):
                entry, pos = self._decode_csr(data, pos)
                entries.append(entry)
            row["csrs_changed"] = entries
            self.info["csr_events"] += count

        return row, pos, pc, size or 4, prev_mem_addr

    def _decode_mem(self, data: bytes, pos: int, prev_mem_addr: int | None) -> tuple[dict, int, int]:
        hdr = data[pos]
        pos += 1
        kind = _KIND_NAMES[hdr & 0b11]
        awidth = (hdr >> 2) & 0b11
        size = _SIZE_FROM_CODE[(hdr >> 4) & 0b11]
        stub = bool(hdr & 0b0100_0000)
        value_unknown = bool(hdr & 0b1000_0000)

        if awidth == 0:
            (delta,) = struct.unpack_from("<b", data, pos)
            pos += 1
        elif awidth == 1:
            (delta,) = struct.unpack_from("<h", data, pos)
            pos += 2
        elif awidth == 2:
            (delta,) = struct.unpack_from("<i", data, pos)
            pos += 4
        else:
            enc, pos = _read_varint(data, pos)
            delta = _zigzag_decode(enc)

        addr = delta if prev_mem_addr is None else prev_mem_addr + delta

        region, pos = self._decode_str(data, pos)

        if value_unknown:
            value: Any = _UNKNOWN
        else:
            raw = data[pos:pos + size]
            pos += size
            # 与 full 模式（machine.py）保持同一表示：
            #   read  → int（int.from_bytes 小端）
            #   write → 小端 hex 字符串
            if kind == "write":
                value = raw.hex()
            else:
                value = int.from_bytes(raw, "little")

        # unmapped 动态占位页在写入端 region 恒为 "__dynamic__"（machine.py 约定），
        # 读回时据此还原 unmapped 标志，保证与 full 模式字段等价。
        unmapped = region == _DYNAMIC_REGION
        note = (
            "unmapped 动态占位页：仿真器零页占位，非硬件观测" if unmapped
            else "占位访问：值由仿真器 stub 产生，非硬件观测" if stub
            else _UNKNOWN
        )
        mem = {
            "kind": kind if kind != "unknown" else "unknown",
            "addr": addr,
            "size": size,
            "value": value,
            "stub": stub,
            "region": region,
            "note": note,
        }
        if unmapped:
            mem["unmapped"] = True
        return mem, pos, addr

    def _decode_csr(self, data: bytes, pos: int) -> tuple[dict, int]:
        csr, pos = _read_varint(data, pos)
        op_code = data[pos]
        pos += 1
        op = _OP_NAMES[op_code] if op_code < len(_OP_NAMES) else _UNKNOWN
        vtype = data[pos]
        pos += 1
        if vtype == 0:
            value, pos = _read_varint(data, pos)
        else:
            value = _UNKNOWN
        flags = data[pos]
        pos += 1
        detail, pos = self._decode_str(data, pos)
        return (
            {
                "csr": csr,
                "op": op,
                "value": value,
                "warl": bool(flags & 0b01),
                "placeholder": bool(flags & 0b10),
                "action_detail": detail,
            },
            pos,
        )

    def _decode_str(self, data: bytes, pos: int) -> tuple[str, int]:
        idx, pos = _read_varint(data, pos)
        if idx == len(self._str_list):
            length, pos = _read_varint(data, pos)
            text = data[pos:pos + length].decode("utf-8")
            pos += length
            self._str_list.append(text)
            return text, pos
        if idx > len(self._str_list):
            raise ValueError(f"字符串字典索引越界: {idx} > {len(self._str_list)}")
        return self._str_list[idx], pos


def read_trace(path: str | Path) -> list[dict]:
    """便捷入口：读回全部契约行（含 run_meta / trace / fault_event / run_end）。"""
    return TraceReader(path).read_all()


def iter_json_rows(path: str | Path) -> Iterator[dict]:
    """只产出非 trace 的契约行（run_meta / fault_event / run_end）——供生成
    campaign-records 等下游产物时使用，避免把 40 万条指令行全部解码。"""
    reader = TraceReader(path)
    with reader.path.open("rb") as f:
        head = f.read(HEADER.size)
        if len(head) < HEADER.size:
            raise ValueError(f"不是 FITB 文件（头部截断）: {path}")
        magic, version, _ = HEADER.unpack(head)
        if magic != MAGIC or version != VERSION:
            raise ValueError(f"不支持的 FITB 文件: {path}")
        while True:
            type_and_len = f.read(5)
            if len(type_and_len) < 5:
                break
            block_type = type_and_len[0]
            (length,) = struct.unpack("<I", type_and_len[1:])
            payload = f.read(length)
            if block_type == BLOCK_META:
                reader.meta = json.loads(payload.decode("utf-8"))
                reader.run_id = reader.meta.get("run_id")
                yield reader.meta
            elif block_type == BLOCK_JSONROW:
                yield json.loads(payload.decode("utf-8"))


def is_binary_trace(path: str | Path) -> bool:
    """探测文件是否为 FITB 二进制轨迹（供工具自动分流）。"""
    try:
        with Path(path).open("rb") as f:
            return f.read(4) == MAGIC
    except OSError:
        return False
