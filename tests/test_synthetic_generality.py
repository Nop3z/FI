# -*- coding: utf-8 -*-
"""合成镜像自检：证明 discover 能力**不依赖任何具体芯片**。

方法：用 examples/synthetic/gen_synthetic_image.py 现场生成一颗"陌生芯片"
（全新基址/命令集/错误码），零改动跑 discover，与它生成的**真值表**逐项对比。

这是项目"不是 lab toy"的机器可验证证明：
  - 基址故意用 0x80000000（不是任何真实样例的基址）
  - 命令号与错误码全部自造
  - 断言对象是真值表，不是我的记忆
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "examples" / "synthetic" / "gen_synthetic_image.py"


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory) -> tuple[Path, dict]:
    """生成合成镜像并读回真值表。"""
    if not GEN.is_file():
        pytest.skip("合成镜像生成器不存在")
    out_dir = tmp_path_factory.mktemp("synthetic")
    img = out_dir / "synth.bin"
    gt = out_dir / "synth.truth.json"
    proc = subprocess.run(
        [sys.executable, str(GEN), "--out", str(img), "--base", "0x80000000",
         "--gt", str(gt)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        pytest.skip(f"合成镜像生成失败: {proc.stdout[-500:]} {proc.stderr[-500:]}")
    return img, json.loads(gt.read_text(encoding="utf-8"))


def test_synthetic_dispatch_matches_ground_truth(synthetic) -> None:
    """分派表恢复：命令数 / 命令号 / flag / handler 地址全部与真值一致。"""
    from fi.discover.dispatch import discover_dispatch

    img, gt = synthetic
    base = int(gt["base"], 16)
    report = discover_dispatch(str(img), base)

    tables = [t for t in report["recovered_tables"] if t["table"]["entry_count"] > 0]
    assert tables, "未恢复出任何分派表（通用性缺陷）"

    # 找与真值命令数最接近、且 cmd 集合匹配度最高的表
    truth = {int(c["cmd"], 16): c for c in gt["commands"]}
    best, best_hit = None, -1
    for t in tables:
        cmds = {e["fields"].get("byte0") for e in t["table"]["entries"]
                if isinstance(e["fields"].get("byte0"), int)}
        hit = len(cmds & set(truth))
        if hit > best_hit:
            best, best_hit = t, hit
    assert best is not None
    assert best_hit == len(truth), (
        f"命令号恢复不全：真值 {len(truth)} 条，命中 {best_hit} 条")

    by_cmd = {}
    for e in best["table"]["entries"]:
        c = e["fields"].get("byte0")
        if isinstance(c, int):
            by_cmd[c] = e

    for cmd, t in truth.items():
        e = by_cmd[cmd]
        assert e["handler"].lower() == t["handler"].lower(), (
            f"cmd 0x{cmd:02x} 的 handler 不符：{e['handler']} vs 真值 {t['handler']}")
        assert e["fields"].get("byte1") == t["flag"], (
            f"cmd 0x{cmd:02x} 的 flag 不符")


def test_synthetic_attribution_matches_ground_truth(synthetic) -> None:
    """归因链路：每个自造错误码都应归因到真值表指定的命令与 handler。"""
    from fi.discover.attribution import attribute_codes
    from fi.discover.dispatch import discover_dispatch

    img, gt = synthetic
    base = int(gt["base"], 16)
    truth = {int(c["code"], 16): c for c in gt["commands"]}

    disp = discover_dispatch(str(img), base)
    report = attribute_codes(str(img), base,
                             [f"0x{c:04x}" for c in truth],
                             dispatch_report=disp)

    assert report["summary"]["codes_attributed"] == len(truth), (
        f"应归因 {len(truth)} 个码，实际 {report['summary']['codes_attributed']}")

    for a in report["attributions"]:
        code = int(a["code"], 16)
        t = truth[code]
        assert a["sites"], f"码 0x{code:04x} 无归因站点"
        s = a["sites"][0]
        assert s["handler"].lower() == t["handler"].lower(), (
            f"码 0x{code:04x} 归因 handler 不符：{s['handler']} vs 真值 {t['handler']}")
        assert s["command"] and int(s["command"], 16) == int(t["cmd"], 16), (
            f"码 0x{code:04x} 归因命令不符：{s['command']} vs 真值 {t['cmd']}")


def test_synthetic_traps_matches_ground_truth(synthetic) -> None:
    """trap 识别：mtvec 安装点与 mret 位置应与真值一致。"""
    from fi.discover.traps import discover_traps

    img, gt = synthetic
    base = int(gt["base"], 16)
    report = discover_traps(str(img), base)

    assert report["summary"]["trap_mechanism_present"], "未识别出 trap 机制"
    writes = report["findings"]["mtvec_writes"]
    assert writes, "未找到 mtvec 写入点"

    trap = int(gt["trap_handler"], 16)
    # 至少有一个 mtvec 写入点的候选基址（剥离低位 MODE）指向真值 trap handler
    cands = {int(w["base_candidate_hex"], 16) & ~0x3
             for w in writes if w.get("base_candidate_hex")}
    assert trap in cands or any(abs(c - trap) <= 4 for c in cands), (
        f"mtvec 候选 {[hex(c) for c in cands]} 未命中真值 {gt['trap_handler']}")
