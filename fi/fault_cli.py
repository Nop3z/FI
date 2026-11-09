# -*- coding: utf-8 -*-
"""``fi fault`` 子命令组（import 期自动注册进 fi.cli.COMMANDS）。

三个命令对应"为什么是这个观测"的三步（方法论
docs/methodology-fault-effect-reasoning.md 步骤 6-7）：

    fi fault enumerate  --insn-bytes <hex> --addr <addr> [--max-flips N] [--flip-mode ...]
    fi fault explain    --insn-bytes <hex> --addr <addr> --pre-regs '<json>' --observed-regs '<json>'
    fi fault classify   --pc-ok/--pc-wrong --target-reg-ok/--target-reg-wrong [--others-changed] [--restarted]

设计约束（与 fi.discover.cli / fi.analysis.anomaly_cli 一致）：
- 本模块只做**参数解析 + 契约组装 + 落盘**，算法在 `fi.fault.*`（lead 维护）；
- 重依赖（capstone / unicorn）延迟导入：`fi schema list` 等基础命令不受影响；
- 每个命令产出的 JSON 都**过契约校验**（fault-effect / fault-explanation /
  observation-classification），不合法直接非零退出；
- 纯静态能力（enumerate）在缺 unicorn 时仍可用。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DISCOVER_GROUP = "fault"

#: 退出码：0 成功；1 数据/校验错误；2 用法错误。


def _load_json_arg(text: str | None, *, arg_name: str) -> dict:
    """解析 JSON 字符串或 @文件 路径。

    文件按 ``utf-8-sig`` 读取以容忍 BOM（Windows 下 PowerShell/记事本等工具
    默认会写 BOM，把它当解析错误拒掉是没必要的摩擦）。
    """
    if not text:
        return {}
    raw = text
    if text.startswith("@"):
        path = Path(text[1:])
        if not path.is_file():
            raise SystemExit(f"错误: {arg_name} 指向的文件不存在: {path}")
        raw = path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"错误: {arg_name} 不是合法 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"错误: {arg_name} 必须是 JSON object")
    return data


def _regs_to_int(mapping: dict) -> dict[str, int]:
    """把 {reg: "0x.."|int} 统一成 int（字符串按 0 进制解析）。"""
    out: dict[str, int] = {}
    for k, v in mapping.items():
        if isinstance(v, int):
            out[k] = v
        elif isinstance(v, str):
            try:
                out[k] = int(v, 0)
            except ValueError as exc:
                raise SystemExit(f"错误: 寄存器 {k} 的值不是合法整数: {v!r}") from exc
        else:
            raise SystemExit(f"错误: 寄存器 {k} 的值类型非法: {type(v).__name__}")
    return out


def _write_json(path: str | None, data: dict, *, label: str) -> None:
    if path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"OK {label} → {p}")
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------- enumerate


def _cmd_enumerate(args: argparse.Namespace) -> int:
    from fi.fault.effects import enumerate_bitflips
    from fi.schemas.fault_report import build_fault_effect

    insn_hex: str = args.insn_bytes
    try:
        insn = bytes.fromhex(insn_hex)
    except ValueError:
        print(f"错误: --insn-bytes 不是合法 hex: {insn_hex!r}", file=sys.stderr)
        return 1
    if not insn:
        print("错误: --insn-bytes 不能为空", file=sys.stderr)
        return 1

    try:
        variants = enumerate_bitflips(
            insn,
            args.addr,
            max_flips=args.max_flips,
            flip_mode=args.flip_mode,
            include_semantics_unchanged=args.include_unchanged,
        )
    except ValueError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2

    disasm = "unknown"
    try:
        from fi.fault.effects import _disasm_one

        disasm = _disasm_one(insn, args.addr) or "unknown"
    except Exception:  # noqa: BLE001 —— 反汇编失败不影响枚举
        pass

    try:
        report = build_fault_effect(
            insn_hex=insn_hex,
            addr=args.addr,
            variants=variants,
            flip_mode=args.flip_mode,
            max_flips=args.max_flips,
            disasm=disasm,
            enumeration_complete=True,
        )
    except ValueError as exc:
        print(f"错误: 产物不合 fault-effect 契约:\n{exc}", file=sys.stderr)
        return 1

    print(
        f"[fault enumerate] insn={insn_hex} addr=0x{args.addr:08x} "
        f"flip_mode={args.flip_mode} max_flips={args.max_flips} "
        f"variants={report['summary']['n_variants_total']} "
        f"(语义改变 {report['summary']['n_variants_semantically_changed']})",
        file=sys.stderr,
    )
    _write_json(args.out, report, label="fault-effect 报告")
    return 0


def _configure_enumerate(p: argparse.ArgumentParser) -> None:
    p.add_argument("--insn-bytes", required=True, help="指令机器码 hex（如 13051700 或 0040）")
    p.add_argument("--addr", required=True, type=lambda s: int(s, 0), help="指令执行地址（如 0x<BASE>）")
    p.add_argument("--max-flips", type=int, default=4, help="最大同时翻转位数（默认 4）")
    p.add_argument(
        "--flip-mode",
        choices=("one_to_zero", "zero_to_one", "both"),
        default="one_to_zero",
        help="翻转方向假设（默认 one_to_zero：crowbar-to-ground 常见效果）",
    )
    p.add_argument(
        "--include-unchanged",
        action="store_true",
        help="保留语义未变的变体（默认过滤，只看真正的『打坏』）",
    )
    p.add_argument("--out", default=None, help="输出 JSON 路径（默认 stdout）")


# ---------------------------------------------------------------- explain


def _cmd_explain(args: argparse.Namespace) -> int:
    from fi.fault.reasoning import explain_observation
    from fi.schemas.fault_report import build_fault_explanation

    try:
        insn = bytes.fromhex(args.insn_bytes)
    except ValueError:
        print(f"错误: --insn-bytes 不是合法 hex: {args.insn_bytes!r}", file=sys.stderr)
        return 1

    pre_regs = _regs_to_int(_load_json_arg(args.pre_regs, arg_name="--pre-regs"))
    observed = _regs_to_int(_load_json_arg(args.observed_regs, arg_name="--observed-regs"))
    if not observed:
        print("错误: --observed-regs 不能为空（至少要有一个观测寄存器）", file=sys.stderr)
        return 1

    try:
        raw = explain_observation(
            insn_bytes=insn,
            insn_addr=args.addr,
            pre_regs=pre_regs,
            observed_regs=observed,
            max_flips=args.max_flips,
            flip_mode=args.flip_mode,
        )
    except ValueError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2

    # 仿真精算（可选；缺 unicorn 时降级为未验证，不失败）
    sim_block: dict | None = None
    if not args.no_simulate and raw.get("candidates"):
        try:
            from fi.fault.simulate import verify_variants_by_simulation

            to_test = [
                {**c, "insn_bytes_hex": c.get("mutated_code_hex")}
                for c in raw["candidates"]
                if c.get("mutated_code_hex")
            ]
            if to_test:
                sim_raw = verify_variants_by_simulation(
                    to_test,
                    exec_addr=args.addr,
                    pre_regs=pre_regs,
                    observed_regs=observed,
                )
                matched = sim_raw["summary"]["matched_by_simulation"]
                sim_block = {
                    "executed": True,
                    "matches_observation": matched > 0,
                    "exception": "unknown",
                    "n_variants_tested": sim_raw["summary"]["variants_tested"],
                    "n_matched": matched,
                    "engine": "unicorn",
                    "discipline": sim_raw["discipline"],
                }
        except ImportError as exc:  # unicorn 缺失：保留未验证状态
            print(f"注意: 未做仿真精算（{exc}）", file=sys.stderr)

    candidates = []
    for c in raw.get("candidates") or []:
        candidates.append(
            {
                "flipped_bit_positions": c.get("flipped_bit_positions") or [],
                "mutated_insn": c.get("mutated_insn") or "unknown",
                "mutated_code_hex": c.get("raw_diff_hex") and c.get("mutated_code_hex") or c.get("mutated_code_hex", "unknown"),
                "change_kind": c.get("change_kind") or "unknown",
                "predicted_regs": {
                    k: int(v, 0) if isinstance(v, str) else v
                    for k, v in (c.get("predicted") or {}).items()
                },
                "match_score": 1.0,
                "match_detail": "unknown",
                "eval_status": "ok",
                "simulation": "unknown",
            }
        )

    try:
        report = build_fault_explanation(
            observation={
                "regs": {k: v for k, v in observed.items()},
                "pc": args.addr,
                "source": args.source or "unknown",
            },
            pre_state={
                "regs": {k: v for k, v in pre_regs.items()},
                "origin": args.pre_origin,
            },
            candidates=candidates,
            flip_mode=args.flip_mode,
            max_flips=args.max_flips,
            n_variants_considered=(raw.get("summary") or {}).get("variants_considered", "unknown"),
            n_variants_unsupported=(raw.get("summary") or {}).get("variants_unsupported", "unknown"),
            simulation_verification=sim_block,
            reason="无候选能解释观测" if not candidates else "unknown",
        )
    except ValueError as exc:
        print(f"错误: 产物不合 fault-explanation 契约:\n{exc}", file=sys.stderr)
        return 1

    print(
        f"[fault explain] addr=0x{args.addr:08x} candidates={report['summary']['n_candidates']} "
        f"multiple_solutions={report['summary']['multiple_solutions']} "
        f"(变体 {report['summary']['n_variants_considered']}，不支持求值 "
        f"{report['summary']['n_variants_unsupported']})",
        file=sys.stderr,
    )
    if report["summary"]["multiple_solutions"]:
        print("注意: 存在多解——已全部列出，禁止只取第一条作为结论", file=sys.stderr)
    _write_json(args.out, report, label="fault-explanation 报告")
    return 0


def _configure_explain(p: argparse.ArgumentParser) -> None:
    p.add_argument("--insn-bytes", required=True, help="原始指令机器码 hex")
    p.add_argument("--addr", required=True, type=lambda s: int(s, 0), help="指令执行地址")
    p.add_argument("--pre-regs", default=None, help="执行前寄存器 JSON 或 @文件（如 '{\"a0\":\"0x1000\"}'）")
    p.add_argument("--observed-regs", required=True, help="观测到的寄存器 JSON 或 @文件（如 '{\"a6\":119}'）")
    p.add_argument("--pre-origin", default="reconstructed",
                   choices=("captured", "reconstructed", "simulated", "assumed", "unknown"),
                   help="执行前状态来源（默认 reconstructed）")
    p.add_argument("--source", default=None, help="观测数据来源（CSV 行/捕获文件）")
    p.add_argument("--max-flips", type=int, default=4, help="最大同时翻转位数（默认 4）")
    p.add_argument("--flip-mode", choices=("one_to_zero", "zero_to_one", "both"),
                   default="one_to_zero", help="翻转方向假设")
    p.add_argument("--no-simulate", action="store_true", help="跳过仿真精算（只用轻量求值筛选）")
    p.add_argument("--out", default=None, help="输出 JSON 路径（默认 stdout）")


# ---------------------------------------------------------------- classify


def _cmd_classify(args: argparse.Namespace) -> int:
    from fi.schemas.fault_report import build_observation_classification

    pc_ok = args.pc_ok
    target_ok = args.target_reg_ok
    evidence: dict = {}
    if args.expected_regs:
        evidence["expected_regs"] = _regs_to_int(
            _load_json_arg(args.expected_regs, arg_name="--expected-regs")
        )
    if args.observed_regs:
        evidence["observed_regs"] = _regs_to_int(
            _load_json_arg(args.observed_regs, arg_name="--observed-regs")
        )
    if args.target_reg:
        evidence["target_reg"] = args.target_reg
    if args.source:
        evidence["source"] = args.source

    try:
        report = build_observation_classification(
            pc_ok=pc_ok,
            target_reg_ok=target_ok,
            other_regs_changed=args.others_changed,
            restarted=args.restarted,
            evidence=evidence,
            experiment_ref=args.experiment_ref or "unknown",
            target_feature_ref=args.target_feature or "unknown",
        )
    except ValueError as exc:
        print(f"错误: 产物不合 observation-classification 契约:\n{exc}", file=sys.stderr)
        return 1

    print(
        f"[fault classify] kind={report['kind']} label={report['label']} "
        f"is_interesting={report['is_interesting']}",
        file=sys.stderr,
    )
    _write_json(args.out, report, label="五色分类")
    return 0


def _configure_classify(p: argparse.ArgumentParser) -> None:
    pc = p.add_mutually_exclusive_group(required=True)
    pc.add_argument("--pc-ok", dest="pc_ok", action="store_true", help="PC 符合预期（走到目标代码）")
    pc.add_argument("--pc-wrong", dest="pc_ok", action="store_false", help="PC 不符预期")
    p.set_defaults(pc_ok=None)

    reg = p.add_mutually_exclusive_group(required=True)
    reg.add_argument("--target-reg-ok", dest="target_reg_ok", action="store_true",
                     help="目标寄存器值符合预期")
    reg.add_argument("--target-reg-wrong", dest="target_reg_ok", action="store_false",
                     help="目标寄存器值不符预期")
    p.set_defaults(target_reg_ok=None)

    p.add_argument("--others-changed", action="store_true",
                   help="目标寄存器之外还有其他寄存器变化（区分『打到别处』）")
    p.add_argument("--restarted", action="store_true", help="观测到 CPU 重启")
    p.add_argument("--target-reg", default=None, help="目标寄存器名（如 a6）")
    p.add_argument("--expected-regs", default=None, help="期望寄存器 JSON 或 @文件")
    p.add_argument("--observed-regs", default=None, help="观测寄存器 JSON 或 @文件")
    p.add_argument("--source", default=None, help="观测数据来源")
    p.add_argument("--experiment-ref", default=None, help="关联实验/记录 ID")
    p.add_argument("--target-feature", default=None, help="关联目标功能 ID")
    p.add_argument("--out", default=None, help="输出 JSON 路径（默认 stdout）")


# ---------------------------------------------------------------- 注册


def register() -> bool:
    """尝试注册进 fi.cli；返回是否成功（不抛异常，便于被 plugins 钩子调用）。"""
    try:
        from fi.cli import command
    except Exception:  # noqa: BLE001 —— 宿主不可用时静默降级
        return False

    for name, help_text, handler, configure in (
        ("enumerate", "位翻转枚举：一条指令 → 全部损坏变体（confidence 恒 hypothesis）",
         _cmd_enumerate, _configure_enumerate),
        ("explain", "观测反解：寄存器差异 → 能解释它的损坏指令候选（允许多解）",
         _cmd_explain, _configure_explain),
        ("classify", "五色分类：观测结果 → 绿/品红/黄/青/红（confidence 恒 observation）",
         _cmd_classify, _configure_classify),
    ):
        handler.configure_args = configure  # type: ignore[attr-defined]
        command(DISCOVER_GROUP, name, help_text)(handler)
    return True


def main(argv: list[str] | None = None) -> int:
    """独立入口（不依赖 fi.cli 注册）。"""
    ap = argparse.ArgumentParser(
        prog="python -m fi.fault_cli",
        description="故障效果推演：位翻转枚举 / 观测反解 / 五色分类",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, help_text, handler, configure in (
        ("enumerate", "位翻转枚举", _cmd_enumerate, _configure_enumerate),
        ("explain", "观测反解", _cmd_explain, _configure_explain),
        ("classify", "五色分类", _cmd_classify, _configure_classify),
    ):
        sp = sub.add_parser(name, help=help_text)
        configure(sp)
        sp.set_defaults(_handler=handler)
    args = ap.parse_args(argv)
    return args._handler(args)


# import 期尽力注册
_REGISTERED = register()

if __name__ == "__main__":
    raise SystemExit(main())
