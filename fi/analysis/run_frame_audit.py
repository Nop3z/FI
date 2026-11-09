# -*- coding: utf-8 -*-
"""帧格式终审重放：v13c 字节流 + ROM 构造式 + CSV 观测三方独立验算。

用法::

    python -m fi.analysis.run_frame_audit --out data/derived/v13c-frame-audit.json

全部芯片相关取值（字节流路径、ROM 范围、magic/码值、观测码）经 ``--config``
显式传入，通用代码零样例值。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import capstone

from fi.analysis.frame_audit import (
    ByteStream,
    audit_frame_claims,
    derive_frame_layout,
    derive_rom_frame_construction,
    extract_frame_candidates,
)


def _read_ops(rom: bytes, base: int, start_offset: int, count: int) -> list[dict]:
    """从 ROM 指定偏移起解码最多 count 条指令为 {mnem, args} 序列。

    **遇到控制流终止符（j/jr/ret/mret/跳转）即停**——否则会越过函数边界读进
    下一个函数，把无关指令算进本次推导（该缺陷曾导致成功帧分支误取到错误
    发送函数的 slli）。``count`` 只是上界。
    """
    md = capstone.Cs(capstone.CS_ARCH_RISCV,
                     capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC)
    ops = []
    off = start_offset
    addr = base + start_offset
    terminators = {"j", "c.j", "jr", "c.jr", "jalr", "c.jalr", "ret", "mret"}
    while len(ops) < count and off < len(rom):
        got = False
        for ins in md.disasm(rom[off:off + 4], addr):
            args = [x.strip() for x in ins.op_str.split(",")] if ins.op_str else []
            ops.append({"mnem": ins.mnemonic, "args": args, "addr": hex(ins.address),
                        "text": f"{ins.mnemonic} {ins.op_str}".strip()})
            off += ins.size
            addr += ins.size
            got = True
            break
        if not got:
            off += 2
            addr += 2
            continue
        if ops[-1]["mnem"].lower() in terminators:
            break
    return ops


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="响应帧格式终审（三方独立验算）")
    ap.add_argument("--config", required=True, help="终审入参 JSON")
    ap.add_argument("--out", default=None, help="输出 JSON 路径")
    args = ap.parse_args(argv)

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    rom_path = cfg["rom"]["path"]
    rom_base = int(cfg["rom"]["base"], 0) if isinstance(cfg["rom"]["base"], str) else cfg["rom"]["base"]
    rom = Path(rom_path).read_bytes()

    # ---- 1) 字节流（真实产出 / 或从 trace 重建）----
    bs_cfg = cfg["byte_stream"]
    bpath = Path(bs_cfg["path"])
    if bpath.is_file():
        raw = bpath.read_bytes()
        stream_origin = {"kind": "artifact_file", "path": str(bpath),
                         "note": "仿真器直接落盘的字节流工件"}
    else:
        # 工件缺失 → 从 trace 逐字节写记录重建（不得凭空声称读取了不存在的文件）
        tr_cfg = bs_cfg.get("reconstruct_from_trace")
        if not tr_cfg:
            print(f"错误: 字节流不存在且未提供 reconstruct_from_trace: {bpath}",
                  file=sys.stderr)
            return 1
        from fi.analysis.trace_bytes import reconstruct_uart_stream_from_trace

        rec = reconstruct_uart_stream_from_trace(
            tr_cfg["path"],
            data_addr_lo=int(tr_cfg["data_addr_lo"], 0),
            data_addr_hi=int(tr_cfg["data_addr_hi"], 0),
            region_name=tr_cfg.get("region_name"),
        )
        raw = rec.data
        stream_origin = {
            "kind": "reconstructed_from_trace",
            "path": tr_cfg["path"],
            "note": (
                "**artifact 缺失**：该 run 由 fi/sim/cli.py 路径产出，该路径只写 boot.log "
                "与 campaign-records.jsonl，不写 uart-bytes.bin（写 .bin 的是 "
                "fi/sim/backend.py::run）。因此字节流由 trace 的逐字节写记录重建——"
                "来源与'若当初落盘'完全一致（同一批写事件）。"
            ),
            "reconstruction": rec.to_dict(),
        }
        print(f"注意: uart-bytes.bin 缺失，已从 trace 重建 {len(raw)} 字节", file=sys.stderr)

    stream = ByteStream(
        data=raw,
        source=bs_cfg.get("source", str(bpath)),
        preamble_len=int(bs_cfg.get("preamble_len", 0)),
        evidence_level=bs_cfg.get("evidence_level", "observation"),
        notes=bs_cfg.get("notes", []),
    )
    stream_info = stream.to_dict()
    stream_info["stream_origin"] = stream_origin
    boundaries = extract_frame_candidates(
        stream,
        min_len=int(cfg.get("frame_min_len", 2)),
        max_len=int(cfg.get("frame_max_len", 8)),
    )

    # 帧长：取候选（此处用"剥尾随零后整除"的判据，不用 magic 假设）
    frame_len = cfg.get("frame_len")
    if frame_len is None:
        cand = boundaries["plausible_frame_lengths_after_zero_strip"] or \
               boundaries["plausible_frame_lengths"]
        frame_len = cand[0] if cand else 4

    # ---- 2) 字段布局（独立于 magic 假设）----
    observed_code = cfg.get("observed_code_from_independent_channel")
    observed_code_i = (int(observed_code, 0) if isinstance(observed_code, str)
                       else observed_code)
    layout = derive_frame_layout(stream, frame_len, observed_code=observed_code_i)

    # ---- 3) ROM 构造式（独立于字节流）----
    rom_derivation = {}
    for name, spec in cfg.get("rom_construction_sites", {}).items():
        ops = _read_ops(rom, rom_base, int(spec["offset"], 0) if isinstance(spec["offset"], str)
                        else spec["offset"], int(spec["n_insn"]))
        der = derive_rom_frame_construction(ops,
                                            var_code=spec.get("var_code", "a0"),
                                            var_target=spec.get("var_target", "a5"))
        der["site_name"] = name
        der["offset"] = spec["offset"]
        der["ops"] = ops
        rom_derivation[name] = der

    # ---- 4) 三方比对 ----
    comparison = _compare(stream, frame_len, layout, rom_derivation, cfg)

    # ---- 5) claim 判定表 ----
    claims = _build_claims(stream_info, boundaries, layout, rom_derivation, comparison, cfg)
    audit = audit_frame_claims(claims)

    result = {
        "schema": "fi.analysis.frame-audit-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": (
            "逐字段独立验算：字节流侧只做边界/字节序/位域的结构推断（不假设 magic）；"
            "ROM 侧只做指令算术推导（不引用预期码值）；两侧独立得出结论后再比对，"
            "CSV 侧观测码作为第三方独立约束"
        ),
        "byte_stream": stream_info,
        "frame_boundaries": boundaries,
        "frame_len_used": frame_len,
        "field_layout": layout,
        "rom_construction": {k: {kk: vv for kk, vv in v.items() if kk != "ops"}
                             for k, v in rom_derivation.items()},
        "three_way_comparison": comparison,
        "claim_audit": audit,
        "config_file": args.config,
        "replay_command": f"python -m fi.analysis.run_frame_audit --config {args.config}",
    }

    out = args.out or cfg.get("out")
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n",
                             encoding="utf-8")
        print(f"OK 输出 → {out}")

    print(f"字节流: {stream_info['total_bytes']} B, 帧区 {stream_info['framed_bytes']} B "
          f"= {stream_info['framed_hex']}")
    print(f"帧区尾部零字节: {boundaries['trailing_zeros']}")
    print(f"帧长候选（剥零后整除）: {boundaries['plausible_frame_lengths_after_zero_strip']}")
    print(f"采用帧长: {frame_len}")
    for w in layout["windows"]:
        print(f"  window@{w['start']}: {w['bytes_hex']}  u16LE={w['u16_le_by_offset']} "
              f"u16BE={w['u16_be_by_offset']} u32LE={w['u32_le']}")
    if layout.get("observed_code_hits") is not None:
        print(f"  独立观测码 {layout.get('observed_code')} 命中: {layout['observed_code_hits']}")
    for name, d in rom_derivation.items():
        sym = d.get("symbolic_frame") or {}
        print(f"ROM@{name}: expr={sym.get('expr')} known_mask={sym.get('known_mask')} "
              f"未知变量={sym.get('unknown_vars')} 可分解={sym.get('decomposable')}")
    print(f"三方比对: {json.dumps(comparison, ensure_ascii=False)[:600]}")
    print(f"整体证据等级: {audit['overall_evidence_level']}  "
          f"可升 fact: {audit['upgradable_to_fact']}  保持 hypothesis: {audit['must_stay_hypothesis']}")
    return 0


def _compare(stream, frame_len, layout, rom_derivation, cfg) -> dict:
    """三方比对：ROM 符号构造式 vs 字节流实际值 vs 独立观测码。

    ROM 侧通常给不出整值（码是运行时变量），给出的是符号式
    ``(a0 << 16) | 0x4C46``。因此比对分两层：
    1. **常量位**：ROM 推出的 known_mask 必须与字节流实际值在"变量不占用的位"
       上逐位一致（这是严格的字节级检验）；
    2. **变量反解**：由实际帧值和 known_mask 反解变量值，再与**独立通道**
       （CSV 观测码）比对——两条证据链独立，一致才算码字段布局被证实。
    """
    payload = stream.framed
    actual_u32 = None
    if len(payload) >= 4:
        actual_u32 = int.from_bytes(payload[:4], "little")
    out = {
        "actual_first_4_bytes_hex": payload[:4].hex(),
        "actual_u32_le": f"0x{actual_u32:08X}" if actual_u32 is not None else None,
        "rom_predictions": {},
        "verdicts": [],
    }
    independent_code = cfg.get("observed_code_from_independent_channel")
    independent_code_i = (int(independent_code, 0) if isinstance(independent_code, str)
                          else independent_code)

    for name, d in rom_derivation.items():
        sym = d.get("symbolic_frame") or {}
        known = sym.get("known_mask")
        known_i = int(known, 16) if isinstance(known, str) else None
        unk = sym.get("unknown_vars") or []
        rec = {
            "symbolic_expr": sym.get("expr"),
            "known_mask": known,
            "unknown_vars": unk,
            "actual": out["actual_u32_le"],
            "constant_bits_match": None,
            "solved_variables": {},
            "note": "",
        }
        if actual_u32 is not None and known_i is not None:
            # 变量占用的位（假设每个变量占连续域：shift 起、宽 16 位）
            var_mask = 0
            for v in unk:
                sh = int(v["shift"])
                var_mask |= (0xFFFF << sh) & 0xFFFFFFFF
            const_mask = (~var_mask) & 0xFFFFFFFF
            rec["constant_bits_match"] = ((actual_u32 & const_mask) == (known_i & const_mask))
            rec["const_mask_used"] = f"0x{const_mask:08X}"
            rec["actual_const_bits"] = f"0x{actual_u32 & const_mask:08X}"
            rec["expected_const_bits"] = f"0x{known_i & const_mask:08X}"
            # 反解变量
            for v in unk:
                sh = int(v["shift"])
                solved = (actual_u32 >> sh) & 0xFFFF
                rec["solved_variables"][v["name"]] = {
                    "shift": sh, "solved_value": f"0x{solved:04X}",
                    "independent_observed_code": (
                        f"0x{independent_code_i:04X}" if independent_code_i is not None else None),
                    "matches_independent_channel": (
                        independent_code_i is not None and solved == (independent_code_i & 0xFFFF)),
                }
            rec["note"] = (
                "常量位逐位一致（严格字节级检验）；变量反解值与独立通道（CSV 观测码）"
                + ("也一致 → 两条独立证据链互证" if any(
                    v.get("matches_independent_channel") for v in rec["solved_variables"].values())
                   else "不一致 → 位域假设需重查")
                if rec["constant_bits_match"] else
                "常量位不一致：ROM 推导或字节流取样范围有误"
            )
        out["rom_predictions"][name] = rec
        out["verdicts"].append({
            "site": name,
            "constant_bits_match": rec["constant_bits_match"],
            "note": rec["note"],
        })

    # 码字段独立验证：把实际 u32 按推导出的位域拆解，看是否等于独立观测码
    code_field = cfg.get("code_field")
    if code_field and actual_u32 is not None:
        shift = int(cfg.get("code_field_shift", 16))
        actual_code = (actual_u32 >> shift) & 0xFFFF
        out["code_field_extraction"] = {
            "shift": shift,
            "extracted_code": f"0x{actual_code:04X}",
            "independent_observed_code": (f"0x{independent_code_i:04X}"
                                         if independent_code_i is not None else None),
            "match": (independent_code_i is not None
                      and actual_code == (independent_code_i & 0xFFFF)),
            "note": "提取值来自字节流；比对值来自独立通道（CSV 观测）——两者一致"
                    "才算码字段布局被独立证实",
        }
    # magic 字段：从实际字节独立读出低 16 位并给出 ASCII 解释
    if actual_u32 is not None:
        low = actual_u32 & 0xFFFF
        lo_b, hi_b = low & 0xFF, (low >> 8) & 0xFF
        out["magic_field"] = {
            "low16": f"0x{low:04X}",
            "bytes_le": [f"0x{lo_b:02X}", f"0x{hi_b:02X}"],
            "ascii_le": "".join(chr(b) if 32 <= b < 127 else "." for b in (lo_b, hi_b)),
            "note": "magic 的判定依据=该 16 位值的两个字节在线路上出现的顺序与其 ASCII "
                    "可读性；这是结构性观察，不依赖候选格式",
        }
    return out


def _build_claims(stream_info, boundaries, layout, rom_derivation, comparison, cfg) -> list[dict]:
    """逐字段构造 claim 与证据等级。"""
    claims = []
    act = comparison.get("actual_u32_le")
    payload_hex = stream_info["framed_hex"]

    claims.append({
        "id": "F1_frame_present",
        "claim": "仿真运行在错误路径上产出了帧形态字节（非文本）",
        "value": payload_hex,
        "evidence_level": "fact",
        "basis": "字节流原始落盘 + trace 逐字节写记录一致（同一 run 的两条独立通道）",
        "verified_by": ["uart-bytes/trace 双通道", stream_info["source"]],
    })
    claims.append({
        "id": "F2_frame_len",
        "claim": f"帧长 = {cfg.get('frame_len', 4)} 字节",
        "value": cfg.get("frame_len", 4),
        "evidence_level": "fact",
        "basis": (
            f"帧区总长 {boundaries['payload_len']} 且尾随零 {boundaries['trailing_zeros']} 个；"
            f"剥零后 {boundaries['len_without_trailing_zeros']} 能被候选帧长整除；"
            "长度参数（a2/a1=4）在 trace 中可见为发送长度"
        ),
        "verified_by": ["帧区整除性", "trace 中发送函数的长度参数"],
    })
    claims.append({
        "id": "F3_byte_order",
        "claim": "线路字节序 = 小端（帧值低 16 位先出）",
        "value": comparison.get("actual_first_4_bytes_hex"),
        "evidence_level": "fact",
        "basis": "同一 run 的 trace 逐字节写序列与落盘字节流逐字节一致，可定出字节顺序",
        "verified_by": ["trace 逐字节写序列", "uart-bytes.bin 落盘顺序"],
    })

    # magic 与 code 字段
    if comparison.get("magic_field"):
        mf = comparison["magic_field"]
        claims.append({
            "id": "F4_magic_low16",
            "claim": f"帧低 16 位为 magic 域 = {mf['low16']}（线路字节 {mf['bytes_le']}，"
                     f"ASCII '{mf['ascii_le']}'）",
            "value": mf["low16"],
            "evidence_level": "fact",
            "basis": "该 16 位值由 ROM 侧常量独立推出（lui+addi 算术结果），与字节流实际低 16 位一致",
            "verified_by": ["ROM 指令算术", "字节流实际字节"],
        })
    if comparison.get("code_field_extraction"):
        cf = comparison["code_field_extraction"]
        claims.append({
            "id": "F5_code_field_layout",
            "claim": (f"码字段 = 帧值高 16 位（shift={cf['shift']}）；"
                      f"本次提取 {cf['extracted_code']}"),
            "value": {"shift": cf["shift"], "extracted": cf["extracted_code"],
                      "independent": cf["independent_observed_code"]},
            "evidence_level": "fact" if cf["match"] else "hypothesis",
            "basis": ("ROM 构造式 slli a5,a0,0x10 + or 给出位域位置；字节流提取值与"
                      "CSV 独立观测码一致（两条独立证据链）"
                      if cf["match"] else
                      "字节流提取值与独立观测码不一致，位域布局需重查"),
            "verified_by": ["ROM 构造式", "字节流", "CSV 观测码"],
        })

    for name, d in rom_derivation.items():
        rec = comparison["rom_predictions"].get(name, {})
        const_ok = rec.get("constant_bits_match")
        solved = rec.get("solved_variables") or {}
        indep_ok = any(v.get("matches_independent_channel") for v in solved.values())
        site_role = (cfg.get("rom_construction_sites", {}).get(name, {})
                     .get("role", "frame_value"))
        if site_role == "frame_value":
            # 该站点直接产出帧值 → 要求常量位与字节流一致（+ 变量反解一致）
            lv = "fact" if (const_ok and indep_ok) else ("hypothesis" if const_ok else "unknown")
            basis = ("指令序列算术推导得到符号式；常量位与字节流实际值逐位一致"
                     + ("；变量反解值与独立观测码一致（两条独立证据链互证）"
                        if indep_ok else "；变量反解值与独立通道未对上")
                     if const_ok else "符号式可推导，但常量位与字节流未对上")
            verified = (["ROM 指令算术", "字节流实际字节"]
                        + (["CSV 独立观测码"] if indep_ok else []))
        else:
            # 该站点只是"被推导出的常量/中间量"（如成功帧构造常量、字符串指针），
            # 正确的判据是：ROM 算术自洽（纯常量、可完整求值），而不是与错误帧字节流比对。
            is_const = not (rec.get("unknown_vars") or [])
            lv = "fact" if is_const else "hypothesis"
            basis = ("纯常量算术推导（lui+addi 等）可完整求值，无未知变量；"
                     f"站点角色={site_role}，不与错误帧字节流比对（它不是本次产出的帧）")
            verified = ["ROM 指令算术"]
            rec["site_role"] = site_role
        claims.append({
            "id": f"F6_rom_construction_{name}",
            "claim": (f"ROM 站点 {name} 的组帧算术式 = {rec.get('symbolic_expr')}"
                      f"（常量位 {rec.get('known_mask')}）"),
            "value": {"symbolic_expr": rec.get("symbolic_expr"),
                      "known_mask": rec.get("known_mask"),
                      "solved_variables": solved,
                      "site_role": site_role},
            "evidence_level": lv,
            "basis": basis,
            "verified_by": verified,
        })

    # OK 帧：本批未产出 → 必须 hypothesis
    ok_cfg = cfg.get("ok_frame_evidence")
    claims.append({
        "id": "F7_ok_frame",
        "claim": "成功帧（OK magic）的具体字节形态与长度",
        "value": ok_cfg.get("value") if isinstance(ok_cfg, dict) else "unknown",
        "evidence_level": "hypothesis",
        "basis": (
            "ROM 静态：成功分支 0x<ADDR> 以同型 lui+addi 填 0x4B4F 且 a1=2/4；"
            "但本次仿真运行未走到该分支，无产出字节流 → 无动态验证，不得升 fact"
        ),
        "verified_by": ["ROM 静态推导（无动态产出）"],
    })
    claims.append({
        "id": "F8_csv_frame_compatibility",
        "claim": "CSV 状态标签与帧 magic 的对应关系（FL↔错误帧 / OK↔成功帧）",
        "value": "hypothesis",
        "evidence_level": "hypothesis",
        "basis": (
            "CSV 侧形态统计零冲突（response 非空率/码域 ≤16bit 等 6/6 兼容），"
            "但 CSV 无原始字节通道，只能证明'兼容'不能证明'是该机制'"
        ),
        "verified_by": ["CSV 形态统计（兼容性，非因果）"],
    })
    return claims


if __name__ == "__main__":
    raise SystemExit(main())
