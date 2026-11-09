"""宿主包子命令自动注册钩子（core-contract 维护）。

fi.cli 的命令注册表是 **import 期副作用**：子命令模块在导入时调用
``@command("组名", "命令名", ...)`` 把自己的 handler 登记进 ``COMMANDS``。
本模块负责把各专职成员提供的可选子命令模块集中导入，避免主入口硬编码每个成员的
模块路径（新增子命令包时只改这里一行）。

设计约束：
- **可选依赖**：模块不存在、或其所依赖的第三方库缺失（如 capstone）时，
  只记录原因并跳过，绝不让 fi 主 CLI 因此不可用（`fi schema list` 必须永远能跑）。
- **幂等**：重复调用不会重复注册（COMMANDS 是 dict，同名覆盖同一 handler）。
- **可见性**：跳过的模块可用 ``registration_report()`` 查询，便于排障与测试。
"""

from __future__ import annotations

import importlib
from typing import Final

#: 可选子命令模块清单（点分路径）。导入即注册。
OPTIONAL_COMMAND_MODULES: Final[tuple[str, ...]] = (
    "fi.discover.cli",           # fi discover ...（chip-profile 维护）
    "fi.analysis.anomaly_cli",   # fi analyze anomaly ...（exp-analysis 维护）
    "fi.fault_cli",              # fi fault enumerate|explain|classify（core-contract 维护）
)

#: 已尝试导入的结果：模块 → None（成功）或异常描述（跳过原因）。
_REGISTRATION_RESULT: dict[str, str | None] = {}


def register_optional_commands() -> dict[str, str | None]:
    """导入全部可选子命令模块；返回 {模块: None|跳过原因}。幂等。"""
    for module_name in OPTIONAL_COMMAND_MODULES:
        if module_name in _REGISTRATION_RESULT:
            continue
        try:
            importlib.import_module(module_name)
            _REGISTRATION_RESULT[module_name] = None
        except ImportError as exc:  # 模块或其后端依赖缺失：不影响主 CLI
            _REGISTRATION_RESULT[module_name] = f"ImportError: {exc}"
        except Exception as exc:  # noqa: BLE001 —— 子命令模块自身错误必须可见但不致命
            _REGISTRATION_RESULT[module_name] = f"{type(exc).__name__}: {exc}"
    return dict(_REGISTRATION_RESULT)


def registration_report() -> dict[str, str | None]:
    """当前已知的注册结果（未尝试的模块不在结果里）。"""
    return dict(_REGISTRATION_RESULT)


def reset_registration_cache() -> None:
    """清空尝试缓存（测试用：模拟模块后到/修复后重试）。"""
    _REGISTRATION_RESULT.clear()
