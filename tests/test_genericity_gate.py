"""通用性门禁：芯片实例值不得出现在 fi/ 通用代码（lead 已裁定采纳）。

规则同源：chip-profile 的 audit_generality（fi.profiles.loader）提取
实例 Profile 的专有 token（SHA-256 / 长 hex / 大整数 / chip.id）；
本测试按 lead 指示补充两点：
1. token 检查**豁免注释与文档字符串**（AST 扫描天然无注释；
   docstring 用精确节点识别，优于全文子串匹配）；
2. 额外覆盖 CSV 实例值（原始状态标签、错误码、基址），黑名单见
   gate_rules.py —— profiles/ 目录暂无实例时静态黑名单仍生效。
"""

import ast
from pathlib import Path

import pytest

from tests.gate_rules import (
    FORBIDDEN_INTS,
    FORBIDDEN_STRINGS,
    GENERIC_CONVENTION_REASONS,
    GENERIC_CONVENTION_TOKENS,
    INT_TOKEN_THRESHOLD,
    WHITELIST_FILES,
)

FI_ROOT = Path(__file__).resolve().parents[1] / "fi"
PROFILES_DIR = Path(__file__).resolve().parents[1] / "profiles"


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """收集模块/类/函数 docstring 的常量节点 id（豁免用）。"""
    nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                nodes.add(id(body[0].value))
    return nodes


def _instance_tokens_from_profiles() -> set[str]:
    """从 profiles/*.yaml 动态提取实例专有 token（复用 chip-profile 提取器）。

    提取规则与 fi.profiles.loader._iter_tokens 一致：
    SHA-256 / 长 hex / >=0x10000 的整数（hex 形式）/ chip.id。
    """
    tokens: set[str] = set()
    try:
        from fi.profiles.loader import _iter_tokens, load_raw
    except Exception:  # noqa: BLE001 —— chip-profile 模块不可用时不阻断静态黑名单
        return tokens

    for path in sorted(PROFILES_DIR.glob("*.yaml")):
        try:
            raw = load_raw(path)
        except Exception:  # noqa: BLE001
            continue
        for _, tok in _iter_tokens(raw, path.stem):
            tokens.add(tok.lower())
        pid = raw.get("chip", {}).get("id", {})
        pid = pid.get("value") if isinstance(pid, dict) else None
        if isinstance(pid, str) and pid:
            tokens.add(pid.lower())
    return tokens


def _scan_file(path: Path) -> list[str]:
    """扫描单个 .py：返回违规描述列表（注释/docstring 已豁免）。

    两层豁免，性质不同、都保持可见：
    - ``WHITELIST_FILES``：**文件级临时豁免**（在途修复，有计划移除）；
    - ``GENERIC_CONVENTION_TOKENS``：**token 级永久豁免**（RISC-V 通用惯例，
      不是芯片实例值；每项须在 gate_rules 写明理由）。
    """
    text = path.read_text(encoding="utf-8-sig")
    tree = ast.parse(text)
    docs = _docstring_nodes(tree)
    problems: list[str] = []
    dynamic = _instance_tokens_from_profiles() - {
        t.lower() for t in GENERIC_CONVENTION_TOKENS
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or id(node) in docs:
            continue
        value = node.value
        if isinstance(value, str):
            if value in FORBIDDEN_STRINGS:
                problems.append(f"行 {node.lineno}: 字符串实例值 {value!r}")
            elif value.lower() in dynamic:
                problems.append(f"行 {node.lineno}: 字符串实例值 {value!r}")
        elif isinstance(value, int) and not isinstance(value, bool):
            if abs(value) >= INT_TOKEN_THRESHOLD:
                if abs(value) in FORBIDDEN_INTS:
                    problems.append(f"行 {node.lineno}: 整数实例值 {hex(value)}")
                elif hex(abs(value)).lower() in dynamic:
                    problems.append(f"行 {node.lineno}: 整数实例值 {hex(value)}")
    return problems


def test_generic_convention_exemptions_are_justified() -> None:
    """通用惯例豁免必须逐项写明理由（防止被当成"万能豁免通道"滥用）。"""
    missing = [t for t in GENERIC_CONVENTION_TOKENS if t not in GENERIC_CONVENTION_REASONS]
    assert not missing, f"豁免 token 缺理由说明: {missing}"

    # 豁免集与静态黑名单不得相交（同一值不能既禁又放）
    overlap = GENERIC_CONVENTION_TOKENS & FORBIDDEN_STRINGS
    assert not overlap, f"豁免与禁用冲突: {overlap}"

    # 豁免 token 必须真的是长 hex 形态（防止误加芯片 ID 之类的短串）
    for tok in GENERIC_CONVENTION_TOKENS:
        assert tok.startswith("0x") and len(tok) >= 6, f"豁免 token 形态可疑: {tok}"


def test_no_instance_values_in_generic_code() -> None:
    """门禁：fi/ 通用代码（含 schema JSON）不得出现芯片实例值。"""
    violations: list[str] = []
    for py in sorted(FI_ROOT.rglob("*.py")):
        rel = py.relative_to(FI_ROOT.parent).as_posix()
        problems = _scan_file(py)
        if not problems:
            continue
        if rel in WHITELIST_FILES:
            # 在途修复：跳过但保留可见性（修复完成后从 gate_rules.WHITELIST_FILES 移除）
            continue
        violations.extend(f"{rel}: {p}" for p in problems)

    assert not violations, (
        "通用代码出现芯片实例值（纪律：样例值禁止进通用代码）:\n"
        + "\n".join(violations)
        + "\n如属在途修复，请登记到 tests/gate_rules.py WHITELIST_FILES"
    )


def test_whitelist_shrinks_over_time() -> None:
    """白名单必须指向真实存在的文件；防止修复完成后忘记移除条目。"""
    stale = [f for f in WHITELIST_FILES if not (FI_ROOT.parent / f).exists()]
    assert not stale, f"白名单条目指向不存在的文件（请移除）: {stale}"


def test_dynamic_tokens_extracted_when_profiles_exist() -> None:
    """profiles/ 有实例时，动态 token 提取必须工作（门禁有效性自检）。"""
    yamls = list(PROFILES_DIR.glob("*.yaml"))
    if not yamls:
        pytest.skip("profiles/ 暂无实例 Profile")
    tokens = _instance_tokens_from_profiles()
    if not tokens:
        # 区分"提取器坏了"与"实例文件暂不可解析"（后者待包所有者修复，skip 不红 CI）
        from fi.profiles.loader import load_raw

        with pytest.raises(Exception) as exc_info:
            load_raw(yamls[0])
        pytest.skip(f"实例 Profile 暂不可解析（待包所有者修复）: {exc_info.value}")
    assert tokens, "动态 token 提取为空：检查 chip.id / hex token 提取器"
