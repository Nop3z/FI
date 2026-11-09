"""fi.sim CLI：python -m fi.sim run --config <json> [...overrides]

run_meta 严格按 docs/contracts/schemas/sim-trace.schema.json 渲染：
run_id / image{path,sha256,base_address,size_bytes} / engine{name,version} /
profile_ref / memory_map / patches / fault_events(预注册) / evidence_level。
"""
from __future__ import annotations

import argparse
import json
import platform
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

import unicorn

from .devices import UartLogDevice
from .config import (
    CSR_POLICIES,
    MEM_TRACE_MODES,
    UNMAPPED_POLICIES,
    SimConfig,
    apply_cli_overrides,
    config_to_dict,
    load_config,
    parse_int,
)
from .inject import load_inject_file, render_preregistered
from .machine import Simulator
from .stopreasons import EXIT_REASONS
from .tracebin import BinaryTracer, TraceReader, is_binary_trace
from .tracer import SCHEMA, NullTracer, Tracer
from .tracelevel import (
    DEFAULT_TRACE_LEVEL,
    TRACE_LEVELS,
    SampledTracer,
    normalize_trace_level,
    trace_filename,
)


def _gen_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"r-{ts}-{secrets.token_hex(3)}"


def _capstone_version() -> str:
    try:
        from importlib.metadata import version

        return version("capstone")
    except Exception:
        import capstone

        return getattr(capstone, "__version__", "unknown")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m fi.sim", description="通用 RISC-V 指令级仿真骨架")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="运行一次仿真")
    run.add_argument("--config", required=True, help="仿真配置 JSON（声明式内存映射/入口/策略）")
    run.add_argument("--base", type=parse_int, help="覆盖第一个 region 的 base（入口随动）")
    run.add_argument("--entry-offset", type=parse_int, help="覆盖入口 offset（相对 entry.region）")
    run.add_argument("--entry-addr", type=parse_int, help="覆盖入口绝对地址")
    run.add_argument("--count", type=int, help="覆盖指令数上限")
    run.add_argument("--csr-policy", choices=CSR_POLICIES, help="未知 CSR 策略（默认 warl-log）")
    run.add_argument("--unmapped-policy", choices=UNMAPPED_POLICIES, help="未映射访问策略（默认 stub-page）")
    run.add_argument("--stub-value", type=parse_int, help="null-stub 占位返回值（覆盖 mmio region）")
    run.add_argument("--mem-trace", choices=MEM_TRACE_MODES, help="普通内存访问记录级别（stub 访问恒记录）")
    run.add_argument("--skip-csr", action="append", type=parse_int, help="线性扫描补丁：跳过对该 CSR 的写（对照工具，可多次）")
    run.add_argument("--patch-offset", action="append", type=parse_int, help="精确补丁：按镜像 offset 补 nop（可多次）")
    run.add_argument("--inject", action="append", help="注入清单 JSON 文件（列表或 {injects:[...]}，可多次）")
    run.add_argument("--campaign-id", default="unknown", help="注入 campaign 标识（缺省 unknown）")
    run.add_argument("--out", default=None, help="输出目录（默认 runs/<时间戳>-<label>）")
    run.add_argument("--label", default="run", help="运行标签")
    run.add_argument("--run-id", default=None, help="指定 run_id（默认自动生成）")

    # ---- 周期/时间估算（docs/methodology-reverse-first.md 第 4 步）----
    run.add_argument(
        "--ns-per-cycle",
        type=float,
        default=None,
        help="每周期纳秒数（主频倒数），用于估算 ns；不给则 ns 全部 unknown（禁止隐式换算）",
    )
    run.add_argument(
        "--report-time-at",
        action="append",
        type=parse_int,
        default=None,
        help="输出运行到该地址的估算周期/时间（可多次，地址或 0x 十六进制）",
    )
    run.add_argument(
        "--window-ns",
        nargs=2,
        type=float,
        default=None,
        metavar=("LO", "HI"),
        help="delay 调参窗口（ns）：反查该窗口对应的指令序号区间与热点 PC",
    )
    run.add_argument(
        "--no-timing",
        action="store_true",
        help="关闭周期估算模型（默认启用；关闭后 cycles/ns=unknown，cycle_estimate 触发不生效）",
    )
    run.add_argument(
        "--no-trace",
        action="store_true",
        help="不落盘逐指令轨迹（等价于 --trace-level=off；保留以兼容旧脚本）",
    )
    run.add_argument(
        "--trace-level",
        choices=TRACE_LEVELS,
        default=DEFAULT_TRACE_LEVEL,
        help=(
            "轨迹级别（默认 binary）：off=只出 summary；binary=紧凑二进制 trace.fitb"
            "（≈4.5 B/指令，可读回契约行）；sampled=每 N 条抽样 JSONL（事件行不丢）；"
            "full=逐条全字段 JSONL（≈262 B/指令，调试用）"
        ),
    )
    run.add_argument(
        "--trace-sample-every",
        type=int,
        default=100,
        help="--trace-level=sampled 时的采样间隔（每 N 条指令落 1 条，默认 100）",
    )
    run.add_argument(
        "--set-reg",
        action="append",
        metavar="NAME=VALUE",
        default=None,
        help="入口前预置通用寄存器（如 sp=0x42048000；跳过复位前段直接进函数时必需，hypothesis 级假设）",
    )

    tp = sub.add_parser(
        "time-report",
        help="运行时间评估：跑到地址 X 的估算周期/时间 + ns 窗口反查（可批量地址）",
    )
    tp.add_argument("--config", required=True, help="仿真配置 JSON")
    tp.add_argument("--base", type=parse_int, help="覆盖第一个 region 的 base")
    tp.add_argument("--entry-addr", type=parse_int, help="覆盖入口绝对地址（可直接跳进目标函数）")
    tp.add_argument("--entry-offset", type=parse_int, help="覆盖入口 offset")
    tp.add_argument("--count", type=int, help="指令数上限")
    tp.add_argument("--ns-per-cycle", type=float, default=None, help="每周期纳秒数（必须显式给出才输出 ns）")
    tp.add_argument("--at", action="append", type=parse_int, default=None,
                    help="目标地址（可多次）：报告运行到该地址的估算周期/时间")
    tp.add_argument("--window-ns", nargs=2, type=float, default=None, metavar=("LO", "HI"),
                    help="delay 窗口（ns）→ 指令区间反查")
    tp.add_argument("--out", default=None, help="时间报告输出路径（JSON；默认不落盘只打印）")
    tp.add_argument("--label", default="time-report", help="标签")
    tp.add_argument(
        "--set-reg",
        action="append",
        metavar="NAME=VALUE",
        default=None,
        help="入口前预置通用寄存器（如 sp=0x42048000；直接跳进函数时必需，hypothesis 级假设）",
    )

    # ---- 轨迹读回：binary → 契约 JSONL ----
    dump = sub.add_parser(
        "dump-trace",
        help="把紧凑二进制轨迹（trace.fitb）读回为 sim-trace 契约 JSONL",
    )
    dump.add_argument("--trace", required=True, help="trace.fitb（或 JSONL，直接原样校验）")
    dump.add_argument("--out", default=None, help="输出 JSONL 路径（默认打印到 stdout）")
    dump.add_argument("--limit", type=int, default=None, help="只输出前 N 行（调试用）")
    dump.add_argument("--stats", action="store_true", help="只打印统计信息，不输出行")

    # ---- 吞吐/体积基准 ----
    bench = sub.add_parser(
        "bench",
        help="轨迹基准：测 instr/s 与 bytes/instr（四种 trace-level 对比）",
    )
    bench.add_argument("--config", required=True, help="仿真配置 JSON")
    bench.add_argument("--count", type=int, default=None, help="覆盖指令数上限")
    bench.add_argument("--levels", default="off,binary,sampled,full",
                       help="要对比的级别（逗号分隔，默认全四个）")
    bench.add_argument("--trace-sample-every", type=int, default=100,
                       help="sampled 级别的采样间隔（默认 100）")
    bench.add_argument("--entry-addr", type=parse_int, help="覆盖入口绝对地址")
    bench.add_argument("--out", default=None, help="基准报告 JSON 输出路径")
    bench.add_argument("--no-timing", action="store_true", help="关闭周期估算（对比纯轨迹开销）")
    return p


def _default_out_dir(label: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("runs") / f"{ts}-{label}"


def _parse_set_reg(items: list[str] | None) -> dict[str, int]:
    """--set-reg NAME=VALUE 列表 → {寄存器名: 值}。值支持 0x 十六进制。"""
    out: dict[str, int] = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"--set-reg 需要 NAME=VALUE 形式: {item!r}")
        name, raw = item.split("=", 1)
        out[name.strip()] = parse_int(raw.strip(), f"--set-reg {name}")
    return out


def _collect_trace_stats(tracer, trace_level: str, trace_path) -> dict:
    """汇总轨迹体积指标（bytes/instr 是项目验收硬指标之一）。"""
    stats: dict = {"level": trace_level}
    inner = getattr(tracer, "stats", None)
    if isinstance(inner, dict):
        stats.update(inner)
    if trace_path is not None and Path(trace_path).exists():
        size = Path(trace_path).stat().st_size
        n = int(stats.get("instructions") or stats.get("instructions_written") or 0)
        stats["file"] = str(trace_path)
        stats["file_bytes"] = size
        stats["bytes_per_instruction"] = round(size / n, 3) if n else "unknown"
        if trace_level == "binary":
            stats["note"] = (
                "binary 为紧凑表示：pc 增量 + 指令字典 + 事件位图；"
                "可用 fi.sim.tracebin.TraceReader 读回契约行"
            )
        elif trace_level == "sampled":
            stats["note"] = (
                "sampled 只落 1/N 指令行，但事件行（stub 访问/fault_event/run_end）全保留；"
                "bytes_per_instruction 按**写入行数**计的参考值，不代表单条真实开销"
            )
    elif trace_level == "off":
        stats["file_bytes"] = 0
        stats["bytes_per_instruction"] = 0.0
    return stats


def cmd_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    injects = []
    for path in args.inject or []:
        injects.extend(load_inject_file(path))
    if injects and args.campaign_id != "unknown":
        for spec in injects:
            if spec.campaign_id == "unknown":
                spec.campaign_id = args.campaign_id

    apply_cli_overrides(
        config,
        base=args.base,
        entry_offset=args.entry_offset,
        entry_addr=args.entry_addr,
        count=args.count,
        csr_policy=args.csr_policy,
        unmapped_policy=args.unmapped_policy,
        stub_value=args.stub_value,
        mem_trace=args.mem_trace,
        skip_csr=args.skip_csr,
        patch_offsets=args.patch_offset,
        injects=injects,
        label=args.label,
        ns_per_cycle=args.ns_per_cycle,
        report_time_at=args.report_time_at,
        window_ns=tuple(args.window_ns) if args.window_ns else None,
        timing_enabled=False if args.no_timing else None,
        initial_regs=_parse_set_reg(args.set_reg),
    )

    run_id = args.run_id or _gen_run_id()
    out_dir = Path(args.out) if args.out else _default_out_dir(args.label)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 轨迹级别：--no-trace 等价于 off（兼容旧脚本）；否则取 --trace-level
    trace_level = "off" if args.no_trace else normalize_trace_level(args.trace_level)
    fname = trace_filename(trace_level)
    trace_path = (out_dir / fname) if fname else None
    summary_path = out_dir / "summary.json"

    sim = Simulator(config)  # 映射 + 补丁在构造期完成
    entry = sim.resolve_entry()

    # ---- run_meta（契约形状：engine 只含 name/version；其余引擎信息进 memory_map.engine_detail）----
    entry_region = sim.region_of(entry)
    image_region = next((r for r in sim.regions if r.file), None)
    image_meta: dict | str
    if image_region is not None and image_region.file_sha256:
        try:
            img_path = str(image_region.file.relative_to(Path.cwd()))
        except ValueError:
            img_path = str(image_region.file)
        image_meta = {
            "path": img_path,
            "sha256": image_region.file_sha256,
            "base_address": image_region.base,
            "size_bytes": len(sim.images.get(image_region.name, b"")),
        }
    else:
        image_meta = "unknown"

    meta = {
        "type": "run_meta",
        "run_id": run_id,
        "image": image_meta,
        "engine": {
            "name": "fi.sim/unicorn",
            "version": unicorn.__version__,
        },
        "profile_ref": "unknown",
        "memory_map": {
            "regions": sim.mapping_info,
            "entry_addr": entry,
            "entry_evidence": (config.raw.get("entry", {}) or {}).get("evidence", "unknown"),
            "isa": config.isa,
            "isa_evidence": (config.raw.get("arch", {}) or {}).get("evidence", "unknown"),
            "policy": {"csr": config.csr_policy, "unmapped": config.unmapped_policy, "mem_trace": config.mem_trace},
            "limits": {"max_instructions": config.max_instructions},
            "loop_policy": vars(config.loop),
            "initial_regs": config.initial_regs,
            "initial_regs_evidence": (
                "hypothesis: 入口前预置寄存器（跳过复位前段时的显式假设，非复原真实复位状态）"
                if config.initial_regs
                else "none"
            ),
            "engine_detail": {
                "trace_schema": SCHEMA,
                "capstone": _capstone_version(),
                "python": platform.python_version(),
            },
            "cmd": " ".join(sys.argv),
            "config_raw": config.raw,
        },
        "patches": sim.patches,
        "fault_events": [render_preregistered(spec, run_id, i) for i, spec in enumerate(config.injects)],
        "evidence_level": "observation",
    }

    if trace_level == "off":
        tracer = NullTracer(run_id, meta)
    elif trace_level == "binary":
        tracer = BinaryTracer(trace_path, run_id, meta)
    elif trace_level == "sampled":
        tracer = SampledTracer(
            trace_path, run_id, meta,
            every=max(1, int(args.trace_sample_every)),
        )
    else:  # full
        tracer = Tracer(trace_path, run_id, meta)
    sim.bind_tracer(tracer)
    result = sim.run()
    tracer.close()

    trace_stats = _collect_trace_stats(tracer, trace_level, trace_path)

    summary_uart_logs = {
        name: {"text": dev.text, "write_count": dev.write_count}
        for name, dev in sim.devices.items()
        if isinstance(dev, UartLogDevice)
    }
    timing_report = sim.timing_report()

    summary = {
        "schema": "fi.sim.summary-v0",
        "run_id": run_id,
        "label": args.label,
        "exit_reason": result.exit_reason,
        "detail_kind": result.detail_kind,
        "entry_addr": result.entry,
        "final_pc": result.final_pc,
        "instructions": result.instructions,
        "cycles_estimate": result.cycles,
        "ns_estimate": result.ns,
        "stub_accesses": result.stub_accesses,
        "stub_by_region": dict(sim.stub_by_region),
        "warl_events": result.warl_events,
        "fault_events_fired": result.fault_events_fired,
        "regs": result.regs,
        "uart_logs": summary_uart_logs,
        "trace_level": trace_level,
        "trace_path": str(trace_path) if trace_path else "unknown",
        "trace_mode": "null" if trace_level == "off" else (
            "binary" if trace_level == "binary" else "jsonl"
        ),
        "trace_stats": trace_stats,
        "patches": sim.patches,
        "timing": timing_report,
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---- 时间报告单独落盘（人读 + 下游调参直接消费）----
    if timing_report.get("schema"):
        (out_dir / "time-report.json").write_text(
            json.dumps(timing_report, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # ---- boot log 落盘（仿真观测：设备模型让固件走到输出路径后收集的字符）----
    if summary_uart_logs:
        boot_log_path = out_dir / "boot.log"
        boot_log_path.write_text(
            "\n".join(f"[{name}] {info['text']}" for name, info in summary_uart_logs.items()),
            encoding="utf-8",
        )

    # ---- CampaignRecord 注入记录（契约 v0.2.0 sim_trigger 形状，backend 共用实现）----
    from .backend import write_campaign_records

    uart_text = next((info["text"] for info in summary_uart_logs.values() if info["text"]), "unknown")
    campaign_path = out_dir / "campaign-records.jsonl"
    if trace_path is not None:
        write_campaign_records(campaign_path, run_id, trace_path, uart_text)

    # ---- UART 原始字节落盘（CLI 路径此前只写 boot.log，缺 .bin；exp-analysis 已提出）----
    uart_bin_written = None
    for name, dev in sim.devices.items():
        log = getattr(dev, "log", None)
        if log:
            uart_bin_written = out_dir / "uart-bytes.bin"
            uart_bin_written.write_bytes(bytes(log))
            break

    # ---- 人读摘要 ----
    print(f"[fi.sim] run_id={run_id} label={args.label}")
    for m in sim.mapping_info:
        print(
            f"  region {m['name']:<14} {m['kind']:<4} 0x{m['base']:08x}+0x{m['size']:x}"
            f" (mapped 0x{m['mapped_size']:x}, {m['perms']}, image={m['image_bytes']}B)"
        )
    print(f"  entry 0x{entry:08x}  policy csr={config.csr_policy} unmapped={config.unmapped_policy} mem_trace={config.mem_trace}")
    print(f"  patches={len(sim.patches)} injects={len(config.injects)}")
    print(
        f"STOP exit_reason={result.exit_reason} detail_kind={result.detail_kind}"
        f" instructions={result.instructions} final_pc=0x{result.final_pc:x}"
        if isinstance(result.final_pc, int)
        else f"STOP exit_reason={result.exit_reason} detail_kind={result.detail_kind} instructions={result.instructions}"
    )
    if sim._last_insn is not None:
        print(f"  last_insn @0x{sim._last_insn.addr:08x}: {sim._last_insn.mnemonic} {sim._last_insn.op_str}")
    print(
        f"  warl_events={result.warl_events} stub_accesses={result.stub_accesses}"
        f" fault_events_fired={result.fault_events_fired} dynamic_pages={len(sim.dynamic_pages)}"
    )
    # ---- 时间估算人读摘要 ----
    if timing_report.get("schema"):
        tot = timing_report["totals"]
        tb = timing_report["time_base"]
        print(
            f"  timing: instructions={tot['instructions']} cycles≈{tot['cycles']}"
            f" cycles/insn≈{tot['cycles_per_insn']} ns≈{tot['ns']}"
            f" (ns_per_cycle={tb['ns_per_cycle']}) evidence={tot['evidence_level']}"
        )
        for cp in timing_report.get("checkpoints") or []:
            if cp.get("reached"):
                print(
                    f"    @{cp['addr_hex']}: first_seq={cp['first_seq']}"
                    f" first_cycle≈{cp['first_cycle']} first_ns≈{cp['first_ns']} hits={cp['hits']}"
                )
            else:
                print(f"    @{cp['addr_hex']}: 未到达（该运行未执行此地址）")
        wm = timing_report.get("window_map")
        if isinstance(wm, dict) and wm.get("status") == "ok":
            rng = wm["insn_range"]
            print(
                f"    window {wm['window_ns'][0]}–{wm['window_ns'][1]}ns"
                f" → cycles≈{wm['window_cycles'][0]}–{wm['window_cycles'][1]}"
                f" → seq≈{rng['seq_first']}–{rng['seq_last']}（hypothesis）"
            )
    unapplied = [u for u in (timing_report.get("unapplied") or [])]
    if unapplied:
        print(f"    WARN 未生效的周期触发 {len(unapplied)} 条")
    if summary_uart_logs:
        for name, info in summary_uart_logs.items():
            print(f"  boot_log[{name}] ({info['write_count']} 次写，仿真观测): {info['text']}")
    # ---- 轨迹体积指标（验收硬指标：≤8 B/指令）----
    print(f"  trace-level={trace_level}", end="")
    if trace_stats.get("file_bytes") is not None:
        print(
            f"  file={trace_stats.get('file_bytes')} B"
            f"  bytes/instr={trace_stats.get('bytes_per_instruction')}"
            f"  (instructions={result.instructions})"
        )
    else:
        print("  (无轨迹文件)")
    if trace_level == "binary":
        print("  hint: 读回契约行 → python -m fi.sim dump-trace --trace <fitb> --out <jsonl>")
    if uart_bin_written is not None:
        print(f"  uart-bytes: {uart_bin_written}")
    print(f"  trace: {trace_path if trace_path else '(未落盘)'}")
    print(f"  summary: {summary_path}")
    return 0


def cmd_dump_trace(args: argparse.Namespace) -> int:
    """把二进制轨迹读回为契约 JSONL（验证 binary 级别不丢信息）。"""
    src = Path(args.trace)
    if not src.is_file():
        print(f"错误: 轨迹文件不存在: {src}", file=sys.stderr)
        return 1

    if not is_binary_trace(src):
        # 已是 JSONL：原样透传（方便"两种轨迹同一条命令处理"）
        rows = [json.loads(x) for x in src.read_text(encoding="utf-8").splitlines() if x.strip()]
        stats = {"format": "jsonl", "rows": len(rows),
                 "file_bytes": src.stat().st_size}
    else:
        reader = TraceReader(src)
        rows = reader.read_all()
        stats = {
            "format": "fitb",
            "version": reader.info.get("version"),
            "blocks": reader.info.get("blocks"),
            "instructions": reader.info.get("instructions"),
            "mem_events": reader.info.get("mem_events"),
            "csr_events": reader.info.get("csr_events"),
            "dropped_mem_events": reader.info.get("dropped_mem_events"),
            "rows": len(rows),
            "file_bytes": src.stat().st_size,
            "errors": reader.errors,
        }

    if args.stats:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return 0

    limit = args.limit
    lines = []
    for i, row in enumerate(rows):
        if limit is not None and i >= limit:
            break
        lines.append(json.dumps(row, ensure_ascii=False, separators=(",", ":")))

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        print(f"OK 写出 {len(lines)} 行 → {out}")
        if stats.get("errors"):
            print(f"警告: 解码期间有 {len(stats['errors'])} 个问题: {stats['errors'][:3]}")
    else:
        for line in lines:
            print(line)
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """轨迹级别基准：同一配置下逐级别跑，报告 instr/s 与 bytes/instr。"""
    import tempfile
    import time

    levels = [x.strip() for x in args.levels.split(",") if x.strip()]
    for lv in levels:
        normalize_trace_level(lv)

    results = []
    print(f"[fi.sim bench] config={args.config}")
    print(f"{'level':<9}{'instr':>9}{'sec':>9}{'instr/s':>13}{'file_B':>12}{'B/instr':>10}")
    print("-" * 62)
    for lv in levels:
        config = load_config(args.config)
        apply_cli_overrides(
            config,
            count=args.count,
            entry_addr=args.entry_addr,
            timing_enabled=False if args.no_timing else None,
        )
        tmpdir = Path(tempfile.mkdtemp(prefix=f"fi-bench-{lv}-"))
        fname = trace_filename(lv)
        path = (tmpdir / fname) if fname else None
        meta = {
            "type": "run_meta", "run_id": f"bench-{lv}", "image": "unknown",
            "engine": {"name": "fi.sim/bench"}, "evidence_level": "observation",
        }
        sim = Simulator(config)
        if lv == "off":
            tracer = NullTracer(f"bench-{lv}", meta)
        elif lv == "binary":
            tracer = BinaryTracer(path, f"bench-{lv}", meta)
        elif lv == "sampled":
            tracer = SampledTracer(path, f"bench-{lv}", meta,
                                   every=max(1, args.trace_sample_every))
        else:
            tracer = Tracer(path, f"bench-{lv}", meta)
        sim.bind_tracer(tracer)

        t0 = time.perf_counter()
        result = sim.run()
        tracer.close()
        elapsed = time.perf_counter() - t0

        size = path.stat().st_size if path is not None and path.exists() else 0
        n = result.instructions
        rate = n / elapsed if elapsed > 0 else 0.0
        bpi = size / n if n else 0.0
        row = {
            "level": lv,
            "instructions": n,
            "seconds": round(elapsed, 4),
            "instr_per_second": round(rate, 1),
            "file_bytes": size,
            "bytes_per_instruction": round(bpi, 3),
            "exit_reason": result.exit_reason,
            "detail_kind": result.detail_kind,
        }
        if isinstance(getattr(tracer, "stats", None), dict):
            row["tracer_stats"] = {k: v for k, v in tracer.stats.items() if k != "file"}
        results.append(row)
        print(f"{lv:<9}{n:>9}{elapsed:>9.3f}{rate:>13,.0f}{size:>12,}{bpi:>10.2f}")

    # 校验验收指标：binary 是否 ≤ 8 B/指令
    binary = next((r for r in results if r["level"] == "binary"), None)
    verdict = {}
    if binary:
        verdict["binary_bytes_per_instruction"] = binary["bytes_per_instruction"]
        verdict["binary_within_8B_target"] = binary["bytes_per_instruction"] <= 8.0
        verdict["target_bytes_per_instruction"] = 8.0
        full = next((r for r in results if r["level"] == "full"), None)
        if full and full["file_bytes"]:
            verdict["reduction_vs_full"] = round(
                full["file_bytes"] / max(binary["file_bytes"], 1), 1
            )

    report = {
        "schema": "fi.sim.bench-v0",
        "config": str(args.config),
        "count": args.count,
        "timing_enabled": not args.no_timing,
        "results": results,
        "verdict": verdict,
        "evidence_level": "observation",
    }
    print()
    if verdict:
        print(f"验收: binary {verdict['binary_bytes_per_instruction']} B/指令"
              f"（目标 ≤{verdict['target_bytes_per_instruction']}）→ "
              f"{'达标' if verdict['binary_within_8B_target'] else '未达标'}")
        if "reduction_vs_full" in verdict:
            print(f"相对 full 体积缩减 {verdict['reduction_vs_full']}×")
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"报告: {out}")
    return 0 if verdict.get("binary_within_8B_target", True) else 1


def cmd_time_report(args: argparse.Namespace) -> int:
    """运行时间评估：跑到地址 X 的估算周期/时间 + ns 窗口反查。

    与 `run` 的区别：默认不落盘逐指令轨迹（40 万指令约 100MB，时间评估不需要），
    专注输出"目标地址首次达到的周期/时间"与"delay 窗口对应的指令序号区间"。
    """
    config = load_config(args.config)
    apply_cli_overrides(
        config,
        base=args.base,
        entry_offset=args.entry_offset,
        entry_addr=args.entry_addr,
        count=args.count,
        label=args.label,
        ns_per_cycle=args.ns_per_cycle,
        report_time_at=args.at,
        window_ns=tuple(args.window_ns) if args.window_ns else None,
        initial_regs=_parse_set_reg(args.set_reg),
    )
    sim = Simulator(config)
    run_id = _gen_run_id()
    tracer = NullTracer(run_id, {})
    sim.bind_tracer(tracer)
    result = sim.run()
    report = sim.timing_report()

    print(f"[fi.sim time-report] run_id={run_id} entry=0x{result.entry:08x}")
    print(
        f"STOP exit_reason={result.exit_reason} detail_kind={result.detail_kind}"
        f" instructions={result.instructions}"
    )
    tot = report.get("totals") or {}
    print(
        f"totals: instructions={tot.get('instructions')} cycles≈{tot.get('cycles')}"
        f" cycles/insn≈{tot.get('cycles_per_insn')} ns≈{tot.get('ns')}"
    )
    tb = report.get("time_base") or {}
    if tb.get("ns_per_cycle") in (None, "unknown"):
        print("注意: 未提供 --ns-per-cycle，ns 全部 unknown（需要芯片主频假设才能折算时间）")
    for cp in report.get("checkpoints") or []:
        if cp.get("reached"):
            print(
                f"  @{cp['addr_hex']}: first_seq={cp['first_seq']}"
                f" first_cycle≈{cp['first_cycle']} first_ns≈{cp['first_ns']}"
                f" hits={cp['hits']} last_cycle≈{cp['last_cycle']}"
            )
        else:
            print(f"  @{cp['addr_hex']}: 未到达")
    wm = report.get("window_map")
    if isinstance(wm, dict):
        if wm.get("status") == "ok":
            print(
                f"window {wm['window_ns'][0]}–{wm['window_ns'][1]}ns"
                f" → cycles≈{wm['window_cycles'][0]}–{wm['window_cycles'][1]}"
                f" → seq≈{wm['insn_range']['seq_first']}–{wm['insn_range']['seq_last']}"
                f"（hypothesis；窗口内热点 PC {wm['hot_pc_count']} 个）"
            )
            for hp in (wm.get("hot_pcs") or [])[:10]:
                print(f"    hot @{hp['pc_hex']} first_ns≈{hp['first_ns']} hits={hp['hits']}")
        else:
            print(f"window: {wm.get('note')}")
    top = report.get("top_pc_buckets") or []
    if top:
        print("top PC 区间（占用周期最多）:")
        for row in top[:8]:
            print(
                f"  {row['pc_range']}  insns={row['instructions']}"
                f" cycles≈{row['cycles']} share={row['share_of_total_cycles']:.3%}"
            )
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"time-report: {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "time-report":
        return cmd_time_report(args)
    if args.cmd == "dump-trace":
        return cmd_dump_trace(args)
    if args.cmd == "bench":
        return cmd_bench(args)
    parser.error(f"未知子命令: {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
