# -*- coding: utf-8 -*-
"""fi.discover.draft：自动发现产出 → Profile 草稿 `profiles/<chip_id>.draft.yaml`。

定位（docs/tts-baseline.md 产品化清单第 7 项）：把"手工写 Profile"变成一条命令。
但**草稿不是 Profile 事实**，纪律在代码层强制：

  1) **全部 claim = hypothesis**，`evidence.source` 指向 `artifact_derived` 来源；
     fact 只能由人工/三方对齐后升级——本模块**没有任何写 fact 的代码路径**；
  2) 显式标注「自动生成草稿，禁止当已验证数据」：`status: draft` +
     `generated_by` / `generated_at` / `tool_version` + `notes` 首行警示；
  3) **绝不改写已有 Profile**：`--profile` 只读参考；输出恒为 `*.draft.yaml`；
     输出路径与参考路径相同则直接报错退出（防误覆盖）；
  4) 代码零实例值：芯片标识、基址、错误码全部来自调用参数或从镜像推导。

草稿内容（尽量"有内容但不臆断"）：
  - sources：`artifact`（镜像本体，SHA-256 绑定）+ `artifact_derived`（本次 discover 扫描）
  - chip.id：调用方给的 chip_id（fact 形状？**不**——草稿统一 hypothesis，
    因为 chip_id 是"调用方声明"，尚未经用户/资料确认；note 写明来源）
  - architecture.isa_family / xlen / extensions：从解码结果推断（hypothesis）
  - boot.reset_vector：入口偏移候选（hypothesis）
  - memory_map.regions：regions 候选（前 N 项，hypothesis）
  - exception.entry / mechanism：traps 的 mtvec 候选（hypothesis）
  - error_codes.entries：targets 的常量装载候选 + 发送函数谱（hypothesis）
  - capture/peripherals/csr_table 等：显式 unknown（value=null）
  - open_questions：由 unknown 字段与"待人工验证"项自动生成
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import yaml

from . import DISCOVER_VERSION
from .common import load_image, sha256_hex
from .regions import discover_regions
from .targets import discover_targets
from .traps import discover_traps

#: 草稿固定的警示文案（Dashboard 与消费方据此拒绝把草稿当已验证数据）
DRAFT_NOTICE = "自动生成草稿，禁止当已验证数据（all claims hypothesis）"

#: 本工具可写出的 claim 置信度上限（代码层硬约束，不提供写 fact 的路径）
DRAFT_MAX_CONFIDENCE = "hypothesis"

_HEX = lambda v: f"0x{v:08x}"  # noqa: E731 —— 统一十六进制渲染


def _claim(value, *, source: str, note: str | None = None) -> dict:
    """构造一个 hypothesis 级 claim（草稿中唯一允许的 confidence）。"""
    ev: dict = {"source": source, "confidence": DRAFT_MAX_CONFIDENCE,
                "note": note or "自动发现产出；需人工/仿真交叉验证后按 profile-guide §5 升级"}
    return {"value": value, "evidence": ev}


def _unknown(note: str | None = None) -> dict:
    """构造显式未知 claim（value 必须 null）。"""
    ev: dict = {"confidence": "unknown"}
    if note:
        ev["note"] = note
    return {"value": None, "evidence": ev}


def _infer_isa(image: bytes, base: int, xlen: int, compressed: bool) -> dict:
    """从解码结果推断 ISA 特性（结构证据，非规范断言）。

    判别：压缩指令出现 ⇒ c 扩展；见到 mul/div/rem ⇒ m；见到 flw/fsw/fld/fsw 类 ⇒ f/d。
    这些都只是"该镜像确实用了这些编码"，是否硬件支持仍需行为验证。
    """
    from .common import linear_disasm

    disasm = linear_disasm(image, base, xlen=xlen, compressed=compressed)
    mnems = {i.mnemonic for i in disasm}
    exts = ["i"]
    if any(m.startswith("c.") for m in mnems):
        exts.append("c")
    if any(m in ("mul", "mulh", "div", "divu", "rem", "remu") for m in mnems):
        exts.append("m")
    fp_insns = {m for m in mnems if m.startswith(("flw", "fsw", "fld", "fsd", "fadd", "fsub"))}
    if fp_insns:
        exts.append("f")
        if any(m.startswith(("fld", "fsd")) for m in mnems):
            exts.append("d")
    return {
        "extensions": exts,
        "evidence_insns": sorted(fp_insns)[:6],
        "compressed_insn_seen": any(m.startswith("c.") for m in mnems),
        "decoded_insns": len(disasm),
    }


def build_draft(
    image_path: str,
    base: int,
    chip_id: str,
    *,
    xlen: int = 32,
    compressed: bool = True,
    profile_path: str | None = None,
    output_dir: str = "profiles",
    target_values: list[int] | None = None,
    entry_offset: int = 0,
    status_note: str | None = None,
) -> dict:
    """主入口：镜像 → 草稿 YAML 文件 + 结果元信息（dict）。

    返回 {path, notice, stats, validation_errors, report_meta}。
    `validation_errors` 非空表示草稿未通过 `fi.profiles.loader.validate_profile`
    （正常情况应为空；draft 文件名规则由 loader 显式豁免）。
    """
    img_path = Path(image_path)
    if not img_path.is_file():
        raise FileNotFoundError(f"镜像不存在: {img_path}")
    image = load_image(img_path)

    out_dir = Path(output_dir)
    draft_path = out_dir / f"{chip_id}.draft.yaml"

    # 防误覆盖：绝不写到已有 Profile 上
    if profile_path:
        ref = Path(profile_path)
        if ref.resolve() == draft_path.resolve():
            raise ValueError(
                "输出路径与参考 Profile 相同（禁止覆盖已有 Profile）："
                f"{ref} —— 草稿必须写到 *.draft.yaml")
        if not ref.is_file():
            raise FileNotFoundError(f"参考 Profile 不存在: {ref}")

    # ---- 三类 discover 产出（同一次运行内复用镜像，全部 hypothesis） ----
    regions = discover_regions(str(img_path), base, xlen=xlen, compressed=compressed)
    traps = discover_traps(str(img_path), base, xlen=xlen, compressed=compressed)
    targets = discover_targets(str(img_path), base, xlen=xlen, compressed=compressed,
                               target_values=target_values)
    isa = _infer_isa(image, base, xlen, compressed)

    now = _dt.datetime.now(_dt.timezone.utc).astimezone()
    sha = sha256_hex(image)
    tool_version = f"fi.discover.draft {DISCOVER_VERSION}"

    # ---- sources（草稿自证的来源登记） ----
    # 注意：S1（镜像本体）必须被至少一个 claim 引用，否则校验器报"登记未引用"警告。
    # 由 memory_map.regions 的容器级 evidence 引用 S1（容器说明这批条目来自镜像本体分析）。
    sources = [
        {
            "id": "S1",
            "kind": "artifact",
            "title": f"固件镜像（{img_path.name}，{len(image)} 字节，只读）",
            "locator": f"{img_path}；SHA-256 {sha}",
            "date": now.strftime("%Y-%m-%d"),
        },
        {
            "id": "S2",
            "kind": "artifact_derived",
            "title": "fi discover 自动扫描产出（regions + traps + targets，线性/递归下降反汇编）",
            "locator": (f"{tool_version}；扫描时间 {now.isoformat(timespec='seconds')}；"
                        f"镜像 SHA-256 {sha}"),
            "date": now.strftime("%Y-%m-%d"),
        },
    ]

    # ---- memory_map.regions：取 regions 候选（页级，hypothesis） ----
    region_entries = []
    for cand in (regions.get("candidates") or [])[:24]:
        page_base = cand["page_base"]
        region_entries.append({
            "id": f"auto-{page_base:08x}",
            "name": _claim(f"自动发现页候选 {cand['page_base_hex']}", source="S2",
                           note=f"证据：{cand['hit_count']} 次地址常量命中，"
                                f"访问类型 {cand['accesses']}，形态 {cand['forms']}；"
                                f"页级近似，边界未独立确认"),
            "type": _claim(cand["kind"], source="S2",
                           note=f"分类依据：{cand['kind_reason']}；通用地址惯例启发式"),
            "base": _claim(cand["page_base_hex"], source="S2",
                           note="页对齐基址（页大小 0x1000），实际区域边界未知"),
            "size_bytes": _claim(0x1000, source="S2", note="页级下界，实际大小未知"),
            "access": _claim("rw" if "write" in cand["accesses"] else "r", source="S2",
                             note=f"观测到的访问形态：{cand['accesses']}"),
            "aliases": _unknown("未见别名映射证据"),
            "description": _claim(cand["stub_suggestion"]["note"], source="S2",
                                  note="仿真建模建议（stub 策略），非芯片事实"),
        })

    # ---- exception：mtvec 安装点（hypothesis） ----
    mtvec_writes = (traps.get("findings") or {}).get("mtvec_writes") or []
    best_mtvec = next((w for w in mtvec_writes if w.get("base_candidate") is not None), None)
    exception_entry_base = _unknown("未在 csrw mtvec 前窗口内识别出地址构造")
    exception_mode = _unknown()
    if best_mtvec is not None:
        exception_entry_base = _claim(
            _HEX(best_mtvec["base_candidate"]), source="S2",
            note=f"由 {best_mtvec['at']} 的 {best_mtvec['insn']} 前窗口常量构造推断；"
                 f"raw 写入值 {best_mtvec.get('base_candidate_hex')}，"
                 f"剥离的低位 {best_mtvec.get('mode_bits_observed')}")
        exception_mode = _claim(
            f"low_bits={best_mtvec.get('mode_bits_observed')}", source="S2",
            note="mtvec 低位 MODE 字段的观测值；标准仅 0/1，实现可能自定义")

    mrets = (traps.get("findings") or {}).get("mret_sites") or []
    mcause_reads = (traps.get("findings") or {}).get("mcause_reads") or []

    # ---- error_codes：targets 的常量装载候选（值 + 装载点 + 是否被共享函数消费） ----
    error_entries = []
    seen_codes: dict[int, dict] = {}
    for t in targets.get("targets", []):
        if t["kind"] != "const_load":
            continue
        d = t.get("detail") or {}
        raw_value = int(d.get("value", "0x0"), 16)
        if raw_value == 0 or raw_value > 0xFFFF:
            continue
        if not d.get("followed_by_call"):
            continue
        rec = seen_codes.setdefault(raw_value, {"sites": [], "shared": False, "callers": []})
        rec["sites"].append(t["addr"])
        if d.get("callee_is_shared_function"):
            rec["shared"] = True
        if d.get("call_target"):
            rec["callers"].append(d["call_target"])
    for code in sorted(seen_codes):
        rec = seen_codes[code]
        error_entries.append({
            "id": f"auto-code-{code:04x}",
            "code": _claim(f"0x{code:04x}", source="S2",
                           note=f"装载点 {len(rec['sites'])} 处：{', '.join(rec['sites'][:6])}"),
            "meaning": _unknown("自动发现只能定位装载点，无法推断语义；需人工逆向/仿真/CSV 三方对齐"),
            "observed": _unknown("本次运行未接入实验数据；observed 需 exp-analysis 产出"),
            "context": _claim({
                "loaded_at": rec["sites"][:8],
                "consumed_by_call_targets": sorted(set(rec["callers"]))[:8],
                "callee_is_shared_function": rec["shared"],
            }, source="S2",
                note="结构上下文：常量装载后短窗口内的直接调用（疑似发送/处理函数消费）"),
        })
    if not error_entries:
        error_entries = [{
            "id": "auto-code-none",
            "code": _unknown("未发现'装载即被调用消费'的小整数常量候选"),
            "meaning": _unknown(),
        }]

    # ---- capture：trap 通道（hypothesis）+ 其余 unknown ----
    trap_capture = _unknown("未识别到 trap 机制")
    if mtvec_writes or (mcause_reads and mrets):
        trap_capture = _claim({
            "available": True,
            "mtvec_write_sites": [w["at"] for w in mtvec_writes[:8]],
            "mtvec_base_candidate": (_HEX(best_mtvec["base_candidate"])
                                     if best_mtvec else None),
            "mcause_read_sites": [r["at"] for r in mcause_reads[:8]],
            "mret_sites": [m["at"] for m in mrets[:8]],
        }, source="S2",
            note="trap 机制结构识别（安装点/读取点/返回点）；handler 内容与语义未验证")

    # ---- 共享函数（发送/公共函数候选）作为 observations 登记 ----
    shared_obs = []
    for i, fn in enumerate((targets.get("summary") or {}).get("shared_functions", [])[:12]):
        # 注意：statement 不得以 "0x" 开头——Profile 校验器会把整个 value 当十六进制字面量
        # 校验格式（"非法十六进制字面量"），这是 Profile 格式的既有约定。
        shared_obs.append({
            "id": f"auto-shared-{i:02d}",
            "statement": _claim(
                f"函数 {fn['callee']} 被 {fn['caller_count']} 个直接调用点调用"
                f"（调用者示例 {', '.join(fn['callers'][:4])}）", source="S2",
                note="高频共享函数候选（发送/日志/公共子程序）；语义未验证"),
            "conditions": _claim(
                "基于线性反汇编的直接调用（jal/c.jal）统计；间接调用未计入",
                source="S2",
                note="若该函数主要经函数指针被调用，真实调用次数会更高"),
        })

    # ---- open_questions：自动生成 ----
    open_questions = [
        {
            "id": "auto-verify-claims",
            "question": "草稿中全部 hypothesis 级 claim 是否成立？",
            "target_field": "*",
            "needed_material": ("人工复核 + 仿真复现 + 实验数据三方对齐"
                                "（requirement-baseline §8 升级规则）"),
            "status": "open",
        },
        {
            "id": "auto-reset-vector",
            "question": "复位向量是否为镜像基址 + 入口偏移？",
            "target_field": "boot.reset_vector",
            "needed_material": "仿真从基址起跑并观察首条有效指令序列 + 用户确认",
            "status": "open",
        },
        {
            "id": "auto-exception-handler",
            "question": "trap handler 的完整指令序列与上下文保存布局未知",
            "target_field": "exception.context",
            "needed_material": "从 mtvec 候选地址重同步反汇编 + 仿真进入 handler",
            "status": "open",
        },
        {
            "id": "auto-error-semantics",
            "question": "错误码的语义（meaning）全部未知，仅有装载点定位",
            "target_field": "error_codes.entries[].meaning",
            "needed_material": "人工逆向控制流 + 仿真复现 + CSV 观测三方对齐",
            "status": "open",
        },
        {
            "id": "auto-isa-extensions",
            "question": f"ISA 扩展推断为 {isa['extensions']}，但硬件实际支持集未验证",
            "target_field": "architecture.extensions",
            "needed_material": "仿真逐扩展试跑（非法指令异常判定）+ 用户/资料确认",
            "status": "open",
        },
    ]
    if target_values:
        open_questions.append({
            "id": "auto-target-values",
            "question": f"调用方给出的 target_values={[hex(v) for v in target_values]} 语义未知",
            "target_field": "error_codes.entries[].meaning",
            "needed_material": "这些值的来源说明（Profile/资料/实测）与语义确认",
            "status": "open",
        })

    # ---- 组装草稿 ----
    notes_lines = [
        f"【{DRAFT_NOTICE}】",
        f"由 {tool_version} 于 {now.isoformat(timespec='seconds')} 自动生成。",
        "用法：本文件是**候选清单**，供人工复核与仿真验证；确认后可把相应 claim"
        "（保留 evidence 推理链）迁入 profiles/<chip_id>.yaml 并升级 confidence。",
        "本工具不写 fact 级 claim，也不会改写任何已有 Profile。",
    ]
    if status_note:
        notes_lines.append(f"调用方补充：{status_note}")

    draft = {
        "schema_version": "0.1",
        "profile_id": chip_id,
        "title": f"{chip_id} Chip Profile（自动生成草稿）",
        "status": "draft",
        "revision": "0.0.1-draft",
        "updated": now.strftime("%Y-%m-%d"),
        "maintainer": "chip-profile",
        # ---- 草稿溯源元数据（额外字段：由 loader 允许，属元数据结构键） ----
        "generated_by": tool_version,
        "generated_at": now.isoformat(timespec="seconds"),
        "generated_from": {
            "image_path": str(img_path),
            "image_sha256": sha,
            "image_size_bytes": len(image),
            "base_address": _HEX(base),
            "entry_offset": _HEX(entry_offset),
            "tool_version": tool_version,
            "notice": DRAFT_NOTICE,
        },
        "sources": sources,
        "chip": {
            "id": _claim(chip_id, source="S2",
                         note="芯片标识由调用方指定（未在本草稿内被证据确认）；"
                              "profile-guide 要求与文件名一致，草稿文件名规则由 loader 豁免"),
            "vendor": _unknown("自动发现无法推断厂商"),
            "family": _unknown(),
            "part_number": _unknown(),
            "package": _unknown(),
        },
        "architecture": {
            "isa_family": _claim("riscv", source="S2",
                                 note=f"推理链：镜像可按 RISC-V xlen={xlen} 连续解码 "
                                      f"{isa['decoded_insns']} 条指令（含 RVC={compressed}）"),
            "xlen": _claim(xlen, source="S2",
                           note="解码成功的一致性推断；RV64/RV32 判别未做负向验证"),
            "extensions": _claim(isa["extensions"], source="S2",
                                 note="指令编码出现即计入（结构证据）；硬件支持集未验证；"
                                      f"FP 相关指令样例 {isa['evidence_insns']}"),
            "privilege_modes": _unknown("未做 CSR 特权级访问分析"),
            "core": _unknown(),
            "bus": _unknown(),
            "notes": _unknown(),
        },
        "exception": {
            "mechanism": _unknown("trap 机制结构已识别，但 handler 流程/分类表未解析"),
            "entry": {
                "csr": _claim("mtvec", source="S2",
                              note="由 csrw 目标 CSR 号识别（RISC-V 规范 CSR 0x305）"
                              if mtvec_writes else "未识别到 mtvec 写入"),
                "mode": exception_mode,
                "base": exception_entry_base,
            },
            "delegation": _unknown(),
            "context": {
                "source": _unknown("handler 上下文保存来源未分析"),
                "stack": _unknown(),
                "layout": _unknown("寄存器保存帧布局需从 handler 入口重同步反汇编"),
                "registers_saved": _unknown(),
                "csrs_read": _claim(
                    [r["at"] for r in mcause_reads[:8]] or None, source="S2",
                    note="mcause 读取点（RISC-V 规范 CSR 0x342）"
                    if mcause_reads else "未识别到 mcause 读取")
                if mcause_reads else _unknown("未识别到 mcause 读取"),
            },
            "interrupt_sources": _unknown(),
        },
        "boot": {
            "reset_vector": _claim(_HEX(base + entry_offset), source="S2",
                                   note="候选：镜像基址 + 入口偏移（偏移由调用方指定，"
                                        "缺省 0）；复位向量是硬件行为，可执行性≠复位向量"),
            "boot_modes": _unknown(),
            "watchdog": _unknown(),
        },
        "memory_map": {
            "regions": {
                "value": region_entries,
                "evidence": {
                    "source": "S1",
                    "confidence": DRAFT_MAX_CONFIDENCE,
                    "note": (f"来源合流：镜像本体（S1，SHA-256 绑定）+ 本次扫描（S2）。"
                             f"地址常量扫描产出 {regions['summary']['page_candidates']} 个页候选，"
                             f"按命中数取前 {len(region_entries)} 项登记；"
                             "页级近似，区域边界与类型未独立确认"),
                },
            },
        },
        "csr_table": {
            "entries": {
                "value": [],
                "evidence": {
                    "source": "S2",
                    "confidence": DRAFT_MAX_CONFIDENCE,
                    "note": "本次 discover 未做 CSR 普查（仅识别 mtvec/mcause/mepc 的访问点，"
                            "已在 exception 节登记）；完整 CSR 表需后续扫描",
                },
            },
        },
        "error_codes": {
            "channel": _claim(
                (targets.get("summary") or {}).get("shared_functions", [{}])[0].get("callee")
                and {
                    "candidate_shared_senders": [
                        f["callee"] for f in
                        (targets.get("summary") or {}).get("shared_functions", [])[:6]
                    ],
                    "note": "高频共享函数候选（发送通道 hypothesis）；未验证哪一个是响应通道",
                } or None,
                source="S2",
                note="错误码通道候选：常量装载后被高频共享函数消费的形态"
                if error_entries and error_entries[0]["id"] != "auto-code-none"
                else "未发现可信的错误码发送通道候选"),
            "entries": {
                "value": error_entries,
                "evidence": {
                    "source": "S2",
                    "confidence": DRAFT_MAX_CONFIDENCE,
                    "note": (f"由 targets 扫描产出：候选码 {len(error_entries)} 个"
                             f"（模式 {targets['method']['target_value_mode']}）；"
                             "全部只有'装载点'证据，语义（meaning）一律 unknown"),
                },
            },
        },
        "capture": {
            "trap": trap_capture,
            "crash_dump": _unknown("未发现崩溃转储通道证据"),
            "debug": _unknown(),
            "trace": _unknown(),
            "external": _unknown(),
            "reset": _unknown(),
        },
        "peripherals": {
            "entries": {
                "value": [],
                "evidence": {
                    "source": "S2",
                    "confidence": DRAFT_MAX_CONFIDENCE,
                    "note": "外设归属需 MMIO 访问点 + 语义分析；本次未产出可信外设条目",
                },
            },
        },
        "observations": {
            "entries": {
                "value": shared_obs,
                "evidence": {
                    "source": "S2",
                    "confidence": DRAFT_MAX_CONFIDENCE,
                    "note": "共享函数观测（结构统计），非行为观测",
                },
            },
        },
        "open_questions": open_questions,
        "notes": "\n".join(notes_lines),
    }

    # ---- 写出 + 自校验（draft 文件名规则由 loader 显式豁免） ----
    out_dir.mkdir(parents=True, exist_ok=True)
    _dump_yaml(draft, draft_path)

    from fi.profiles.loader import validate_file

    rep = validate_file(draft_path)
    report_meta = {
        "generated_by": tool_version,
        "generated_at": draft["generated_at"],
        "image": {"path": str(img_path), "sha256": sha, "size_bytes": len(image),
                  "base_address": _HEX(base)},
        "sources": [s["id"] for s in sources],
        "discover_summary": {
            "regions": regions["summary"],
            "traps": traps["summary"],
            "targets": {k: v for k, v in targets["summary"].items()
                        if k != "shared_functions"},
        },
        "reference_profile": str(profile_path) if profile_path else None,
    }
    return {
        "path": str(draft_path),
        "notice": DRAFT_NOTICE,
        "stats": rep.stats,
        "validation_errors": rep.errors,
        "validation_warnings": rep.warnings,
        "report_meta": report_meta,
    }


def _dump_yaml(data: dict, path: Path) -> None:
    """写出 YAML：保留中文、不折行（便于 diff 与人工复核）、固定键序。"""
    text = yaml.safe_dump(
        data, allow_unicode=True, sort_keys=False,
        default_flow_style=False, width=4096,
    )
    header = (
        "# " + "=" * 76 + "\n"
        f"# 【{DRAFT_NOTICE}】\n"
        f"# 本文件由 fi discover draft 自动生成，请勿手工当作已验证数据使用。\n"
        "# 复核通过后，把相应 claim（含 evidence 推理链）迁入 profiles/<chip_id>.yaml。\n"
        "# " + "=" * 76 + "\n"
    )
    path.write_text(header + text, encoding="utf-8")
