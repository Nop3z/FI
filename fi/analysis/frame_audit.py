# -*- coding: utf-8 -*-
"""响应帧格式终审：从真实字节流**逐字段独立验算**（不做候选格式反向匹配）。

背景（lead 2026-11-09 P0）：sim-engine 的 v13c 运行产出了真实 UART 字节流，
这是「ROM 静态构造 ↔ 仿真动态产出 ↔ CSV 观测形态」三方对齐的最后一票。

**方法纪律（本模块的核心）**：不采用"拿候选格式去套字节流看是否吻合"的做法
（那样任何足够宽的候选都能"匹配"上）。而是：

1. 从字节流**独立地**做结构性推断——帧边界如何确定、各字段在哪、字节序是什么；
2. 从 ROM 的**指令序列独立地**推导构造式（slli/or/lui+addi 的算术结果），
   不引用任何"预期码值"；
3. 两边独立得出的结论再**比对**；同时把 CSV 侧观测形态作为第三方约束。
4. 每个字段给出独立的判定依据与 evidence_level，无法判定的一律 unknown。

本模块**芯片无关**：magic 值、码值、帧长、观测字节流路径全部由调用方传入。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Sequence

__all__ = [
    "ByteStream",
    "extract_frame_candidates",
    "derive_frame_layout",
    "derive_rom_frame_construction",
    "audit_frame_claims",
]

EVIDENCE_ORDER = {"fact": 3, "hypothesis": 2, "unknown": 1}


# ---------------------------------------------------------------------------
# 字节流
# ---------------------------------------------------------------------------
@dataclass
class ByteStream:
    """一段真实/仿真产出的字节流及其来源标注。"""

    data: bytes
    source: str
    preamble_len: int = 0          # 已知的文本前缀长度（如启动日志），由调用方量出
    evidence_level: str = "observation"
    notes: list[str] = field(default_factory=list)

    @property
    def framed(self) -> bytes:
        """去掉已知文本前缀后的部分（帧候选区）。"""
        return self.data[self.preamble_len:]

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "total_bytes": len(self.data),
            "preamble_len": self.preamble_len,
            "preamble_hex": self.data[:self.preamble_len].hex(),
            "framed_bytes": len(self.framed),
            "framed_hex": self.framed.hex(),
            "framed_ascii": "".join(chr(b) if 32 <= b < 127 else "."
                                    for b in self.framed),
            "evidence_level": self.evidence_level,
            "notes": self.notes,
        }


def extract_frame_candidates(stream: ByteStream, min_len: int = 2,
                            max_len: int = 8) -> dict:
    """在帧候选区上做**边界分析**：帧长候选、尾随填充、可切分性。

    独立判据（都不依赖 magic 假设）：
    - 候选区总长与 max_len 的整除关系（定长帧 ⇒ 应整除）；
    - 尾随零字节数（长度参数缺失/过大时会多发 0——见下方 ``trailing_zeros``）；
    - 若总长不能被任何 min_len..max_len 整除，则帧长不是定长或边界错误。

    返回的 ``plausible_frame_lengths`` 只是**候选**，本函数不下结论。
    """
    payload = stream.framed
    n = len(payload)
    trailing_zeros = 0
    for b in reversed(payload):
        if b == 0:
            trailing_zeros += 1
        else:
            break
    stripped = payload[: n - trailing_zeros] if trailing_zeros else payload
    divisors = [L for L in range(max_len, min_len - 1, -1)
                if n and n % L == 0]
    divisors_stripped = [L for L in range(max_len, min_len - 1, -1)
                         if len(stripped) and len(stripped) % L == 0]
    return {
        "payload_len": n,
        "payload_hex": payload.hex(),
        "trailing_zeros": trailing_zeros,
        "len_without_trailing_zeros": len(stripped),
        "plausible_frame_lengths": divisors,
        "plausible_frame_lengths_after_zero_strip": divisors_stripped,
        "interpretation": (
            "定长帧应在 plausible_frame_lengths 中出现；若只有剥掉尾随零后才整除，"
            "说明帧后有多发的填充字节（长度参数问题），帧长应按剥零后判定"
        ),
    }


# ---------------------------------------------------------------------------
# 字节序 / 字段布局：穷举窗口 + 位域分解
# ---------------------------------------------------------------------------
def derive_frame_layout(stream: ByteStream, frame_len: int,
                        observed_code: int | None = None) -> dict:
    """在**不假设 magic 值**的前提下，枚举所有 window×字节序 的取值分解。

    对帧候选区的每个 ``frame_len`` 窗口、每个起点，按两种字节序解出 16 位
    半字，列出全部取值。调用方随后用**独立来源**（ROM 构造式 / CSV 观测值）
    去比对——这是"先描述、后比对"，而非"先假设、后匹配"。

    若 ``observed_code`` 由调用方从 **CSV 侧**（与字节流无关的独立通道）给出，
    则额外标出"该码值在哪些 (offset, endian) 组合下出现"——这是码字段字节序
    判定的独立证据，因为码值本身来自另一条证据链。
    """
    payload = stream.framed
    windows = []
    for start in range(0, max(0, len(payload) - frame_len + 1)):
        w = payload[start:start + frame_len]
        le16 = [struct.unpack_from("<H", w, i)[0] for i in range(0, frame_len - 1, 2)]
        be16 = [struct.unpack_from(">H", w, i)[0] for i in range(0, frame_len - 1, 2)]
        u32_le = struct.unpack("<I", w)[0] if frame_len == 4 else None
        windows.append({
            "start": start,
            "bytes_hex": w.hex(),
            "u16_le_by_offset": [f"0x{v:04X}" for v in le16],
            "u16_be_by_offset": [f"0x{v:04X}" for v in be16],
            "u32_le": (f"0x{u32_le:08X}" if u32_le is not None else None),
        })
    result = {
        "frame_len": frame_len,
        "payload_len": len(payload),
        "n_windows": len(windows),
        "windows": windows,
    }
    if observed_code is not None:
        code_le = observed_code & 0xFFFF
        code_be = ((observed_code & 0xFF) << 8) | ((observed_code >> 8) & 0xFF)
        hits = []
        for w in windows:
            for i, hx in enumerate(w["u16_le_by_offset"]):
                v = int(hx, 16)
                if v == code_le:
                    hits.append({"start": w["start"], "offset": i * 2,
                                 "endianness": "little",
                                 "value": hx})
                elif v == code_be:
                    hits.append({"start": w["start"], "offset": i * 2,
                                 "endianness": "big",
                                 "value": hx})
        result["observed_code"] = f"0x{observed_code:04X}"
        result["observed_code_hits"] = hits
        result["note"] = (
            "observed_code 来自**与字节流无关的独立通道**（如 CSV 观测列）；"
            "它在某 (offset, endian) 出现，独立地指示码字段位置与字节序"
        )
    return result


# ---------------------------------------------------------------------------
# ROM 侧：从指令序列独立推导构造式
# ---------------------------------------------------------------------------
def derive_rom_frame_construction(ops: Sequence[dict],
                                  var_code: str = "a0",
                                  var_target: str = "a5") -> dict:
    """从**指令序列**独立推导帧构造式（不引用任何预期码值）。

    ``ops``：按执行顺序的指令列表，每项 ``{"mnem": str, "args": [str,...]}``，
    例如 ``{"mnem": "slli", "args": ["a5", "a0", "0x10"]}``。
    支持的最小集合（够覆盖典型的"移位+或掩码"组帧）::

        lui  rd, imm          → rd = imm << 12
        addi rd, rs, imm      → rd = rs + imm（符号扩展到 32 位）
        slli rd, rs, imm      → rd = rs << imm
        or   rd, rs1, rs2     → rd = rs1 | rs2
        c.li rd, imm          → rd = imm          （仅用于长度字段）
        sw   rs, off(rd)      → 记录写入（不参与值推导）

    返回值包含：每个目标变量的符号表达式（含常量项的数值）、最终帧值、
    以及"哪些位来自码、哪些位来自常量"的位域分解。

    纪律：本函数只做算术推导，**不说**这就是芯片的帧格式——那是比对结论。

    **符号形式（关键）**：组帧表达式的典型形态是 ``(code << shift) | mask``，
    其中 ``mask`` 是常量、``code`` 是运行时变量。因此本函数不用"整值常量"
    表示，而用二元形式::

        {"known_mask": int,            # 由常量位确定的部分
         "unknown": [(varname, shift)],# 变量占用的位（左移位数）
         "expr": str}                  # 人类可读表达式

    这样即使 code 值未知，仍可写出「帧值 = (a0 << 16) | 0x4C46」；
    随后用字节流的实际帧值反解 ``a0``——这就是码字段位置/字节序的独立验证。
    """
    env: dict[str, dict] = {}
    stores: list[dict] = []
    exprs: list[str] = []

    def _lit(v: int) -> dict:
        return {"known_mask": v & 0xFFFFFFFF, "unknown": [], "expr": f"0x{v & 0xFFFFFFFF:08X}"}

    def _get(v: str) -> dict:
        return env.get(v, {"known_mask": 0, "unknown": [(v, 0)], "expr": v})

    def _num(s: str):
        try:
            return int(s, 0)
        except (TypeError, ValueError):
            return None

    def _shift(ent: dict, sh: int) -> dict:
        return {
            "known_mask": (ent["known_mask"] << sh) & 0xFFFFFFFF,
            "unknown": [(name, s + sh) for name, s in ent["unknown"]],
            "expr": f"({ent['expr']} << {sh})",
        }

    for op in ops:
        mn = op["mnem"].lower()
        a = [str(x).strip() for x in op.get("args", [])]

        if mn in ("lui", "c.lui") and len(a) >= 2:
            rd, imm = a[0], _num(a[-1])
            if imm is not None:
                env[rd] = _lit((imm << 12) & 0xFFFFFFFF)
                exprs.append(f"{rd} = 0x{(imm << 12) & 0xFFFFFFFF:08X}")
        elif mn in ("addi", "c.addi") and len(a) >= 3:
            rd, rs, imm = a[0], a[1], _num(a[2])
            if imm is None:
                continue
            if rd != rs:
                # 非同寄存器加法：只在源已知且为纯常量时可求值，否则记符号和
                src = _get(rs)
                if not src["unknown"]:
                    env[rd] = _lit((src["known_mask"] + imm) & 0xFFFFFFFF)
                    exprs.append(f"{rd} = 0x{env[rd]['known_mask']:08X}")
                continue
            base = _get(rs)
            if not base["unknown"]:
                env[rd] = _lit((base["known_mask"] + imm) & 0xFFFFFFFF)
                exprs.append(f"{rd} = 0x{env[rd]['known_mask']:08X}")
            else:
                # 变量 + 常量：不能与移位变量合并（会破坏位域），显式标注不可分解
                env[rd] = {"known_mask": 0,
                           "unknown": base["unknown"],
                           "expr": f"({base['expr']} + {imm})",
                           "note": "变量加常量：位域不可分离"}
                exprs.append(f"{rd} = {base['expr']} + {imm}")
        elif mn == "slli" and len(a) >= 3:
            rd, rs, sh = a[0], a[1], _num(a[2])
            if sh is not None:
                env[rd] = _shift(_get(rs), sh)
                exprs.append(f"{rd} = {env[rd]['expr']} = "
                             + _fmt(env[rd]))
        elif mn in ("or", "c.or"):
            if len(a) >= 3:
                rd, r1, r2 = a[0], a[1], a[2]
            elif len(a) == 2:
                rd, r1, r2 = a[0], a[0], a[1]
            else:
                continue
            e1, e2 = _get(r1), _get(r2)
            merged = {
                "known_mask": (e1["known_mask"] | e2["known_mask"]) & 0xFFFFFFFF,
                "unknown": list(e1["unknown"]) + list(e2["unknown"]),
                "expr": f"({e1['expr']} | {e2['expr']})",
            }
            # 若两侧都含变量且位域重叠，标注不可分解
            sh1 = {s for _, s in e1["unknown"]}
            sh2 = {s for _, s in e2["unknown"]}
            if sh1 and sh2 and (e1["known_mask"] & e2["known_mask"]) and sh1 == sh2:
                merged["note"] = "两个变量位域叠加：不可分离"
            env[rd] = merged
            exprs.append(f"{rd} = {merged['expr']} = " + _fmt(merged))
        elif mn in ("c.mv", "mv") and len(a) >= 2:
            env[a[0]] = dict(_get(a[1]))
            exprs.append(f"{a[0]} = {env[a[0]]['expr']}")
        elif mn in ("sw", "c.sw") and len(a) >= 2:
            stores.append({"args": a, "value_var": a[0],
                           "value_expr": env.get(a[0], {}).get("expr"),
                           "value_known_mask": env.get(a[0], {}).get("known_mask")})
        elif mn in ("li", "c.li") and len(a) >= 2:
            rd, imm = a[0], _num(a[-1])
            if imm is not None:
                env[rd] = _lit(imm & 0xFFFFFFFF)
                exprs.append(f"{rd} = {imm}")

    target = env.get(var_target)
    result = {
        "derivation_steps": exprs,
        "final_env": {k: {"expr": v["expr"],
                          "known_mask": f"0x{v['known_mask']:08X}",
                          "unknown_vars": [{"name": n, "shift": s} for n, s in v["unknown"]],
                          "note": v.get("note")}
                      for k, v in env.items()},
        "frame_value_var": var_target,
        "frame_expr": target["expr"] if target else None,
        "stores": stores,
    }
    if target is not None:
        result["symbolic_frame"] = {
            "expr": target["expr"],
            "known_mask": f"0x{target['known_mask']:08X}",
            "unknown_vars": [{"name": n, "shift": s} for n, s in target["unknown"]],
            "decomposable": len(target["unknown"]) == 1 and not target.get("note"),
            "note": ("单一变量 + 常量掩码，可用字节流实际值反解该变量"
                     if len(target["unknown"]) == 1 and not target.get("note")
                     else "变量多于一个或位域重叠：无法由帧值唯一反解"),
        }
        # 位域分解（常量部分的可读解释）
        c = target["known_mask"]
        result["bitfield_decomposition"] = {
            "known_mask": f"0x{c:08X}",
            "low16": f"0x{c & 0xFFFF:04X}",
            "high16": f"0x{(c >> 16) & 0xFFFF:04X}",
            "low16_ascii_le": _ascii_le(c & 0xFFFF),
            "note": "known_mask 是常量位；变量占用的位移见 symbolic_frame.unknown_vars",
        }
    return result


def _fmt(ent: dict) -> str:
    if not ent["unknown"]:
        return f"0x{ent['known_mask']:08X}"
    parts = [f"({n} << {s})" if s else n for n, s in ent["unknown"]]
    if ent["known_mask"]:
        parts.append(f"0x{ent['known_mask']:08X}")
    return " | ".join(parts)


def _ascii_le(v: int) -> str:
    """把 16 位值按小端字节序解释成 ASCII（不可打印用 . 表示）。"""
    lo, hi = v & 0xFF, (v >> 8) & 0xFF
    return "".join(chr(b) if 32 <= b < 127 else "." for b in (lo, hi))


# ---------------------------------------------------------------------------
# claim 判定
# ---------------------------------------------------------------------------
def audit_frame_claims(claims: Sequence[dict]) -> dict:
    """汇总逐字段 claim 的判定结果并给出整体证据等级。

    ``claims``：每项 ``{"id","claim","value","evidence_level","basis",...}``。
    ``evidence_level`` 由调用方根据"独立验证是否成立"给定，本函数只做：
    - 一致性检查（不许出现 fact 但 basis 为空）；
    - 整体等级 = 全部 claim 的最低等级；
    - 生成"可升级/须保持 hypothesis"分组。
    """
    problems = []
    for c in claims:
        lv = c.get("evidence_level")
        if lv not in EVIDENCE_ORDER:
            problems.append(f"{c.get('id')}: 非法 evidence_level {lv!r}")
        if lv == "fact" and not c.get("basis"):
            problems.append(f"{c.get('id')}: fact 必须给出 basis（独立判定依据）")
        if lv == "fact" and not c.get("verified_by"):
            problems.append(f"{c.get('id')}: fact 必须标出独立验证来源（verified_by）")
    lowest = "fact"
    for c in claims:
        lv = c.get("evidence_level", "unknown")
        if EVIDENCE_ORDER.get(lv, 0) < EVIDENCE_ORDER.get(lowest, 0):
            lowest = lv
    return {
        "n_claims": len(claims),
        "claims": list(claims),
        "consistent": not problems,
        "problems": problems,
        "overall_evidence_level": lowest,
        "upgradable_to_fact": [c["id"] for c in claims
                               if c.get("evidence_level") == "fact"],
        "must_stay_hypothesis": [c["id"] for c in claims
                                 if c.get("evidence_level") == "hypothesis"],
        "unknown": [c["id"] for c in claims if c.get("evidence_level") == "unknown"],
    }
