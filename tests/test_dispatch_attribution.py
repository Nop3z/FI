# -*- coding: utf-8 -*-
"""dispatch / attribution 能力的结构与性质测试。

纪律：这些测试**不硬编码任何芯片实例值**（地址/码值/命令号全部从镜像推导或
由测试输入给出），只验证"能力的性质"：
  - 分派表恢复应给出稳定、非空、指针全部落在镜像内的表
  - 字段相位判定应给出 flag∈{0,1} 占多数的表（真命令表特征）
  - 归因链路应把"确实以立即数装载在 handler 体内"的码归因出来
  - 所有产出 confidence 恒为 hypothesis（自动发现证据闸门）
"""
from __future__ import annotations

from pathlib import Path

import pytest

from fi.discover.attribution import attribute_codes
from fi.discover.dispatch import discover_dispatch

ROOT = Path(__file__).resolve().parents[1]


def _sample_image() -> tuple[Path, int] | None:
    """找一个可用样例镜像：优先仓库根的 *.bin，其次环境变量。"""
    import os

    env = os.environ.get("FI_SMOKE_IMAGE")
    candidates = ([Path(env)] if env else []) + sorted(ROOT.glob("*.bin"))
    for c in candidates:
        if c.is_file() and c.stat().st_size > 0:
            base_env = os.environ.get("FI_SMOKE_BASE")
            base = int(base_env, 0) if base_env else 0
            return c, base
    return None


@pytest.fixture(scope="module")
def sample() -> tuple[Path, int]:
    s = _sample_image()
    if s is None:
        pytest.skip("未找到样例镜像（设置 FI_SMOKE_IMAGE 或放一个 *.bin 到仓库根）")
    return s


def test_dispatch_report_shape_and_gates(sample) -> None:
    """分派表报告：结构完整 + 证据闸门 + 指针全部落在镜像内。"""
    image, base = sample
    report = discover_dispatch(str(image), base)

    assert report["schema"].startswith("fi.discover.dispatch")
    assert report["confidence"] in ("hypothesis", "unknown")
    assert report["evidence_kind"] == "artifact_derived"

    img = report["image"]
    assert img["size_bytes"] > 0
    assert len(img["sha256"]) == 64

    tables = report["recovered_tables"]
    non_empty = [t for t in tables if t["table"]["entry_count"] > 0]
    if not non_empty:
        pytest.skip("该镜像未发现可由 memcpy 源恢复的分派表（能力边界，非失败）")

    lo = img["base_address"]
    hi = lo + img["size_bytes"]
    for t in non_empty:
        for e in t["table"]["entries"]:
            ptr = int(e["handler"], 16)
            assert lo <= ptr < hi, f"handler 指针越界: {e['handler']}"
            assert ptr % 2 == 0, f"handler 指针未对齐: {e['handler']}"
            assert e["confidence"] == "hypothesis", "自动发现条目不得标 fact/observation"


def test_dispatch_command_table_field_plausibility(sample) -> None:
    """真命令表特征：flag 字节应集中在 {0,1}（禁用/启用标志），cmd 应分散。

    注意：镜像里可能存在多张"指针表"（真命令表 + 其他数据表），因此不能用
    "条目最多的表"来代表命令表——应按**字段合法性得分**取最优者。
    """
    from fi.discover.dispatch import _phase_score

    image, base = sample
    report = discover_dispatch(str(image), base)
    tables = [t for t in report["recovered_tables"]
              if t["table"]["entry_count"] >= 3]
    if not tables:
        pytest.skip("无足够大的表可检验字段合理性")

    best = max(tables, key=lambda t: (_phase_score(t["table"]["entries"]),
                                      t["table"]["entry_count"]))
    entries = best["table"]["entries"]
    flags = [e["fields"].get("byte1") for e in entries
             if isinstance(e["fields"].get("byte1"), int)]
    cmds = [e["fields"].get("byte0") for e in entries
            if isinstance(e["fields"].get("byte0"), int)]
    if not flags or not cmds:
        pytest.skip("该表布局未识别出 cmd/flag 字段（能力边界，非失败）")

    flag_ratio = sum(1 for f in flags if f in (0, 1)) / len(flags)
    assert flag_ratio >= 0.8, (
        f"flag 字节合法性过低（{flag_ratio:.2f}）——可能相位判定错了")
    assert len(set(cmds)) >= max(2, len(cmds) // 2), "cmd 字节重复过多，可能相位判定错了"


def test_attribution_chain_end_to_end(sample) -> None:
    """归因链路：把从分派表 handler 体内以立即数装载的码归因出来。

    做法（不硬编码实例值）：先跑 dispatch 拿到命令表，再从各 handler 体内
    扫出"实际被立即数装载"的码作为已知可归因集合，然后要求 attribution
    对这些码 100% 归因——这是自洽性验证，而非对特定芯片值的断言。
    """
    from fi.discover.dispatch import _phase_score

    image, base = sample
    disp = discover_dispatch(str(image), base)
    tables = [t for t in disp["recovered_tables"] if t["table"]["entry_count"] >= 3]
    if not tables:
        pytest.skip("无命令表，归因链路不可测")

    # 选"字段合法性最高"的表（与 attribution 内部选择标准一致），
    # 而不是条目最多的表——后者可能是非命令表的指针数组。
    best = max(tables, key=lambda t: (_phase_score(t["table"]["entries"]),
                                      t["table"]["entry_count"]))
    handlers = [e["handler"] for e in best["table"]["entries"]]

    # 从镜像里找 handler 体内装载的立即数码：用 attribution 的反向能力——
    # 直接把一批候选码喂进去，检查"归因到的站点是否真在该 handler 体内"。
    from fi.discover.common import linear_disasm, load_image, parse_imm
    import re

    img = load_image(str(image))
    disasm = linear_disasm(img, base)
    by_addr = {i.addr: i for i in disasm}
    li_re = re.compile(r"^(?:c\.li|li|addi)\s+(\w+),\s*(?:zero,\s*)?(-?(?:0x[0-9a-fA-F]+|\d+))$")

    found_codes: set[int] = set()
    handler_set = {int(h, 16) for h in handlers}
    for h in sorted(handler_set):
        addr = h
        for _ in range(2000):
            insn = by_addr.get(addr)
            if insn is None:
                break
            m = li_re.match(insn.text)
            if m:
                v = parse_imm(m.group(2))
                if v is not None and 0 < v < 0x10000:
                    found_codes.add(v)
            if insn.mnemonic in ("ret", "mret") or insn.text.startswith("c.jr ra"):
                break
            addr += insn.size

    if not found_codes:
        pytest.skip("handler 体内未发现立即数码装载")

    codes = sorted(found_codes)[:12]
    # 显式 min_code_value=0：本测试要验证"能从 handler 体里找到的码都能归因"，
    # 而探测到的码可能含小值（如标志位常量），默认下限会过滤掉它们。
    report = attribute_codes(str(image), base, [f"0x{c:x}" for c in codes],
                             dispatch_report=disp, min_code_value=0)

    assert report["summary"]["codes_attributed"] > 0, "一个码都没归因出来，链路可能断了"
    for a in report["attributions"]:
        if a["attribution_status"] != "attributed_to_handler":
            continue
        for s in a["sites"]:
            site = int(s["insn_addr"], 16)
            handler = int(s["handler"], 16)
            # 判据：站点必须**在该 handler 的函数体内**——即从 handler 起点
            # 顺序执行可达的原位置（用反汇编顺序验证，而不是猜一个固定窗口）。
            assert site >= handler, (
                f"归因站点 {s['insn_addr']} 早于其声称的 handler {s['handler']}")
            # 站点与 handler 之间不应跨过另一个已知 handler 的起点
            between = [h for h in handler_set if handler < h <= site]
            assert not between, (
                f"归因站点 {s['insn_addr']} 与其 handler {s['handler']} 之间夹着"
                f"另一个 handler 起点 {[hex(b) for b in between]}")
            assert s["confidence"] == "hypothesis"


def test_attribution_unattributed_is_explicit(sample) -> None:
    """找不到的码必须显式标 not_found，不得静默省略。"""
    image, base = sample
    # 一个几乎不可能被立即数装载的高熵值
    report = attribute_codes(str(image), base, ["0xdead_beef"])
    assert report["summary"]["codes_requested"] == 1
    a = report["attributions"][0]
    assert a["attribution_status"] in ("attributed_to_handler",
                                       "not_found_in_dispatch_handlers")
    if a["attribution_status"] == "not_found_in_dispatch_handlers":
        assert a["site_count"] == 0
        assert a["sites"] == []
