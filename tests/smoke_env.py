# -*- coding: utf-8 -*-
"""冒烟样例（镜像 + 基址）解析的**单一实现**（tests/ 共同资产）。

## 为什么需要这个模块（2026-11-10 缺陷复盘）

各测试各自写了一份 ``FI_SMOKE_BASE`` 解析，且都写成
``base = int(os.environ.get("FI_SMOKE_BASE") or 0)`` —— **默认 0**。
后果：仓库根有真实 ROM 时，测试会用 base=0 去跑真正依赖地址语义的能力
（分派表恢复、码→指令归因），于是所有绝对地址都错、产出垃圾，
既可能是**假绿**（断言恰好宽松）也可能是**假红**（断言命中垃圾数据）。

**基址是芯片语义参数，不是可以默认的常量**：0 对任何真实 ROM 都不是有效
加载基址。因此本模块的规则是：

1. 显式给了 ``FI_SMOKE_BASE`` → 用它；
2. 没给且**断言依赖地址语义** → ``pytest.skip`` 并提示设置环境变量
   （绝不默认 0，也绝不内置某颗芯片的基址）；
3. 没给且**断言只依赖形状/证据闸门**（如"产出是否符合契约"）→ 允许用
   ``base=0``，但调用方必须显式传 ``require_base=False`` 并在测试里说明
   为什么地址无关，避免默认值悄悄扩散。

芯片实例值（某颗芯片的真实基址）**不得**出现在本文件或任何通用测试里。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

#: 显式指定冒烟镜像的路径（优先于仓库根 *.bin 自动发现）。
IMAGE_ENV = "FI_SMOKE_IMAGE"
#: 显式指定加载基址（必需：地址语义类测试缺它会 skip 而不是用 0）。
BASE_ENV = "FI_SMOKE_BASE"

_SKIP_NO_IMAGE = (
    f"未找到冒烟样例镜像（设置 {IMAGE_ENV}，或在仓库根放一个 *.bin）"
)
_SKIP_NO_BASE = (
    f"该测试断言依赖地址语义，但未设置 {BASE_ENV}——"
    "基址是芯片语义参数，不能默认 0（0 对任何真实 ROM 都不是有效加载基址）。"
    f"请设置例如 {BASE_ENV}=0x<该镜像的真实加载基址> 后重跑；"
    "若只想验形状/契约，请改用 require_base=False 并说明地址无关的理由"
)


def find_sample_image() -> Path | None:
    """定位冒烟镜像：``FI_SMOKE_IMAGE`` 优先，其次仓库根首个非空 ``*.bin``。"""
    env = os.environ.get(IMAGE_ENV)
    if env:
        p = Path(env)
        return p if p.is_file() else None
    for cand in sorted(REPO_ROOT.glob("*.bin")):
        if cand.is_file() and cand.stat().st_size > 0:
            return cand
    return None


def read_base() -> int | None:
    """读取 ``FI_SMOKE_BASE``（支持 0x 前缀）；未设置返回 None（**不默认 0**）。"""
    raw = os.environ.get(BASE_ENV)
    if not raw:
        return None
    return int(raw, 0)


def resolve_sample(*, require_base: bool) -> tuple[Path, int]:
    """解析 (镜像, 基址)，缺前提直接 skip。

    ``require_base=True``：断言依赖地址语义，缺 ``FI_SMOKE_BASE`` 即 skip。
    ``require_base=False``：断言只依赖形状/闸门，允许 ``base=0``（仅作地址标签）。
    """
    image = find_sample_image()
    if image is None:
        pytest.skip(_SKIP_NO_IMAGE)
    base = read_base()
    if base is None:
        if require_base:
            pytest.skip(_SKIP_NO_BASE)
        base = 0
    return image, base


def sample_or_none(*, require_base: bool) -> tuple[Path, int] | None:
    """非 pytest 上下文（脚本/夹具内部）用：缺前提返回 None 而不抛。"""
    image = find_sample_image()
    if image is None:
        return None
    base = read_base()
    if base is None:
        if require_base:
            return None
        base = 0
    return image, base
