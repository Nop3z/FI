# -*- coding: utf-8 -*-
"""fi.discover.regions：地址常量扫描 → 内存区域候选（芯片无关）。

产出供仿真配置（fi.sim）与迭代补模型（fi discover iterate）消费的区域候选：
  - RAM 候选：读写混合、地址位于数据/内存空间惯例区间
  - MMIO 候选：以读为主或读改写、地址位于外设惯例区间
  - 只读区：只有 read 访问

判定全部基于结构启发式 + 通用地址惯例，不含任何具体芯片常量；
confidence 恒为 hypothesis（自动发现证据闸门）。
"""
from __future__ import annotations

from dataclasses import dataclass

from .common import (
    ConstHit,
    cluster_values,
    linear_disasm,
    load_image,
    scan_address_constants,
    sha256_hex,
)

# 地址区间提示（mmio_ranges / ram_ranges）**不设代码内置默认值**：
# 某段地址是 MMIO 还是内存，属于具体芯片/厂商地址映射知识，必须由调用方
# （Profile memory_map、样例配置或命令行参数）显式提供。无提示时，本模块
# 仅依据**观测到的访问形态**分类，边界写在 method.boundaries 里。
#
# 设计理由（通用性纪律）：把某个具体地址区间写进通用代码，等价于把某颗芯片
# 的地址映射当作通用假设；这正是通用性门禁禁止的模式。


@dataclass
class RegionCandidate:
    page_base: int
    hit_count: int
    accesses: list[str]
    kinds_observed: list[str]

    @property
    def kind_guess(self) -> str:
        """ram / mmio / rom-like（只读）"""
        readonly = self.accesses == ["read"]
        if readonly:
            return "rom-like"
        return "ram" if any(self.accesses) else "unknown"


def _in_ranges(value: int, ranges) -> bool:
    if not ranges:
        return False
    return any(lo <= value < hi for lo, hi in ranges)


def classify(cand: dict, *, mmio_ranges=None, ram_ranges=None,
             image_range: tuple[int, int] | None = None,
             readonly_as_mmio: bool = True) -> dict:
    """给单个页候选定 kind 与建议 stub 策略（纯启发式，hypothesis）。

    判定顺序：镜像自身范围 → 调用方给出的 ram/mmio 提示区间 → 观测访问形态。
    无提示区间时只靠形态，并在输出中标注 classified_by="access_pattern"。
    """
    base = cand["page_base"]
    accesses = cand["accesses"]

    if image_range and image_range[0] <= base < image_range[1]:
        kind, reason, basis = "rom", "地址落于镜像自身映射范围", "image_range"
    elif _in_ranges(base, ram_ranges):
        kind, reason, basis = "ram", "地址落于调用方提供的内存提示区间", "caller_hint"
    elif _in_ranges(base, mmio_ranges):
        kind, reason, basis = "mmio", "地址落于调用方提供的 MMIO 提示区间", "caller_hint"
    elif accesses == ["exec"]:
        kind, reason, basis = "code", "仅见跳转目标（代码地址）", "access_pattern"
    elif accesses == ["read"] and readonly_as_mmio:
        kind, reason, basis = "mmio", "仅见读访问（外设/状态寄存器形态）", "access_pattern"
    elif "write" in accesses and "read" in accesses:
        kind, reason, basis = "ram", "读写混合（内存形态）", "access_pattern"
    elif accesses == ["write"]:
        kind, reason, basis = "ram", "仅见写访问（内存形态）", "access_pattern"
    else:
        kind, reason, basis = "unknown", "访问形态不足，无法分类", "insufficient"

    suggestion = {
        "ram": {"stub_value": None, "note": "映射为可读写内存（初始零填充）"},
        "mmio": {"stub_value": 0, "note": "映射为 MMIO stub；读返回 0，写忽略并记录"},
        "rom": {"stub_value": None, "note": "镜像自身范围，已由加载镜像覆盖"},
        "code": {"stub_value": None, "note": "代码地址，非区域"},
        "unknown": {"stub_value": 0, "note": "先按 MMIO stub 处理，等迭代观测修正"},
    }[kind]

    return {
        **cand,
        "kind": kind,
        "kind_reason": reason,
        "classified_by": basis,
        "stub_suggestion": suggestion,
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }


def discover_regions(
    image_path: str,
    base: int,
    *,
    xlen: int = 32,
    compressed: bool = True,
    page: int = 0x1000,
    min_addr: int = 0x20000000,
    min_hits: int = 2,
    mmio_ranges=None,
    ram_ranges=None,
    top_n: int = 40,
) -> dict:
    """主入口：镜像 → 区域候选报告（dict，可直接序列化为 discover-report）。"""
    image = load_image(image_path)
    disasm = linear_disasm(image, base, xlen=xlen, compressed=compressed)
    hits: list[ConstHit] = scan_address_constants(disasm, image, base, min_addr=min_addr)
    clusters = cluster_values(hits, page=page)
    image_range = (base, base + len(image))
    candidates = [classify(c, mmio_ranges=mmio_ranges, ram_ranges=ram_ranges,
                           image_range=image_range)
                  for c in clusters if c["hit_count"] >= min_hits]
    candidates.sort(key=lambda c: -c["hit_count"])

    by_kind: dict[str, int] = {}
    for c in candidates:
        by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1

    return {
        "schema": "fi.discover.region-report-v0",
        "tool": {"name": "fi.discover.regions", "version": "0.1.0"},
        "image": {
            "path": str(image_path),
            "sha256": sha256_hex(image),
            "size_bytes": len(image),
            "base_address": base,
            "base_address_hex": f"0x{base:08x}",
        },
        "method": {
            "decoder": f"capstone linear sweep xlen={xlen} compressed={compressed}",
            "channels": [
                "lui+addi 常量对（窗口 6 条）",
                "基址寄存器绝对 lw/sw（同一 lui 窗口约束）",
                "jal 直接目标（高地址区间）",
                "数据段 32 位地址字（仅作佐证，不单独立项）",
            ],
            "classification": "访问形态启发式（调用方可提供 ram/mmio 提示区间提升准确度）",
            "hint_ranges_provided": {
                "mmio": bool(mmio_ranges),
                "ram": bool(ram_ranges),
            },
            "boundaries": [
                "线性扫描含数据段，伪指令可能产生噪声；已用基址窗口与最小命中数抑制",
                "未做控制流可达性分析（复位入口 unknown），命中 ≠ 执行路径",
                "区域边界为页级近似，未独立确认",
                "kind 分类在无调用方区间提示时仅依据访问形态（classified_by=access_pattern），"
                "只读访问按 MMIO 形态假定，可能把只读内存误判为外设",
            ],
        },
        "summary": {
            "instruction_side_hits": len([h for h in hits if h.form != "word"]),
            "page_candidates": len(candidates),
            "by_kind": by_kind,
            "min_hits_filter": min_hits,
        },
        "candidates": candidates[:top_n],
        "confidence": "hypothesis",
        "evidence_kind": "artifact_derived",
    }
