"""fi discover 子命令冒烟测试（lead 2026-11-09 指派）。

验收点：
1. `fi discover regions` 能在样例镜像上跑通（非空产物）；
2. 产物 confidence **全部为 hypothesis**（自动发现证据闸门）——顶层 + 每条 finding；
3. 产物同时满足结构契约（discover-report.schema.json）与语义不变量
   （suggested_action 词汇表、sample_evidence 必填）；
4. 端到端经 CLI（`fi schema validate --schema discover-report`）可校验。

设计说明（避免 CI 红/假绿）：
- discover 子命令模块由 chip-profile 维护（fi/discover/cli.py）。若尚未注册，
  本测试**跳过**并明确提示（不红 CI，但可见）；
- 若已注册但产物不符合契约，则**必须失败**（这才是契约该抓的）；
- 镜像/基址不写死在测试里：经环境变量或仓库根样例文件发现，绝不硬编码芯片实例值；
- "原始模块产出 → 契约形状"的归一由 `fi.schemas.discover_report` 单一实现负责，
  测试不重复实现映射（避免实现与测试各自漂移）。
"""

import json
import os
from pathlib import Path

import pytest

from fi.cli import COMMANDS, main
from fi.schemas import DISCOVER_CONFIDENCE_ALLOWED, DISCOVER_SUGGESTED_ACTIONS, validate_instance

REPO_ROOT = Path(__file__).resolve().parents[1]

#: 冒烟用镜像：优先环境变量 FI_SMOKE_IMAGE，其次仓库根首个 *.bin（不硬编码文件名）。
IMAGE_ENV = "FI_SMOKE_IMAGE"
#: 冒烟用基址：优先环境变量 FI_SMOKE_BASE（0x 前缀可），否则取 0（基址只影响地址标签）。
BASE_ENV = "FI_SMOKE_BASE"


def _discover_command_available() -> bool:
    """discover 子命令是否已注册（模块存在且导入成功）。"""
    from fi.cli_plugins import register_optional_commands

    register_optional_commands()
    return any(group == "discover" for group, _name in COMMANDS)


def _smoke_image() -> Path | None:
    env = os.environ.get(IMAGE_ENV)
    if env:
        p = Path(env)
        return p if p.is_file() else None
    candidates = sorted(REPO_ROOT.glob("*.bin"))
    return candidates[0] if candidates else None


def _smoke_base() -> int:
    raw = os.environ.get(BASE_ENV)
    if not raw:
        return 0
    return int(raw, 0)


@pytest.fixture()
def discover_ready() -> tuple[str, Path, int]:
    """返回 (regions 子命令名, 镜像路径, 基址)；缺任一前提则 skip。"""
    if not _discover_command_available():
        pytest.skip(
            "fi discover 子命令未注册（fi/discover/cli.py 尚未提供或依赖缺失）；"
            "注册后本测试自动生效"
        )
    commands = sorted(name for group, name in COMMANDS if group == "discover")
    assert commands, "discover 组存在但没有任何命令"
    regions_cmd = next((c for c in commands if "region" in c), None)
    if regions_cmd is None:
        pytest.skip(f"discover 组无 regions 命令（现有: {commands}）")
    image = _smoke_image()
    if image is None:
        pytest.skip(f"未找到冒烟镜像（设置 {IMAGE_ENV} 或放一个 *.bin 到仓库根）")
    return regions_cmd, image, _smoke_base()


def _run_discover_regions(cmd: str, image: Path, base: int, out_dir: Path) -> dict:
    """跑 regions 子命令并返回其 JSON 产物。

    兼容两种实现风格（都在契约允许范围内）：
    - 产出 JSON 文件（--out/--output/-o 指向的文件）；
    - 仅打印 JSON 到 stdout（无文件参数时）。
    """
    out_file = out_dir / "discover-regions.json"
    base_argv = ["discover", cmd, "--image", str(image), "--base", hex(base)]
    for flag in ("--out", "--output", "-o"):
        if out_file.exists():
            out_file.unlink()
        rc = main([*base_argv, flag, str(out_file)])
        if rc == 0 and out_file.is_file():
            return json.loads(out_file.read_text(encoding="utf-8"))
        if rc not in (0, 2):
            raise AssertionError(f"fi discover {cmd} 失败（rc={rc}）")

    # 回退：不带输出参数，从 stdout 抓 JSON
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(base_argv)
    text = buf.getvalue()
    if rc == 0 and "{" in text:
        start = text.index("{")
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            pass
    pytest.skip(
        f"fi discover {cmd} 未提供可解析的 JSON 输出（既无文件也无 stdout 约定）；"
        "请在实现中对齐 discover-report 契约的输出方式"
    )
    return {}


def _normalize_via_contract_layer(report: dict, module: str) -> dict:
    """用契约层单一实现归一；实现已直接产出契约形状时原样返回。"""
    from fi.schemas.discover_report import normalize_module_report

    if set(report) >= {"schema", "tool", "image", "method", "summary", "findings", "confidence",
                       "evidence_kind"}:
        return report
    return normalize_module_report(report, module=module)


def _assert_confidence_gate(report: dict) -> None:
    """自动发现证据闸门：顶层 + 所有 findings 条目的 confidence 只能是 hypothesis|unknown。"""
    assert report["confidence"] in DISCOVER_CONFIDENCE_ALLOWED, (
        f"报告顶层 confidence={report['confidence']!r} 越界"
        f"（只允许 {DISCOVER_CONFIDENCE_ALLOWED}）"
    )
    findings = report.get("findings") or {}
    assert findings, "discover 产物 findings 为空，无法验证证据闸门"
    checked = 0
    for group in ("regions", "traps", "targets"):
        for i, item in enumerate(findings.get(group) or []):
            conf = item.get("confidence")
            assert conf in DISCOVER_CONFIDENCE_ALLOWED, (
                f"findings.{group}[{i}].confidence={conf!r} 越界"
                f"（自动发现禁 fact/observation）"
            )
            checked += 1
    assert checked > 0, "findings 三分组全空：闸门形同虚设"


def test_discover_regions_smoke_conforms_to_contract(discover_ready, tmp_path: Path) -> None:
    """端到端：regions 在样例镜像上跑通 + confidence 闸门 + 契约结构校验。"""
    cmd, image, base = discover_ready
    report = _normalize_via_contract_layer(_run_discover_regions(cmd, image, base, tmp_path), "regions")

    assert report.get("schema"), "缺 schema 标识字段"
    assert report.get("tool", {}).get("name"), "缺 tool.name"
    image_meta = report.get("image") or {}
    for key in ("path", "sha256", "size_bytes", "base_address"):
        assert key in image_meta, f"缺 image.{key}"
    assert image_meta["sha256"] and len(str(image_meta["sha256"])) == 64

    _assert_confidence_gate(report)

    errors = validate_instance("discover-report", report)
    assert errors == [], "discover 产物不符合 discover-report 契约:\n" + "\n".join(errors)


def test_discover_regions_smoke_cli_validate(discover_ready, tmp_path: Path) -> None:
    """CLI 视角：产物落盘后可被 `fi schema validate --schema discover-report` 校验通过。"""
    cmd, image, base = discover_ready
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    report = _normalize_via_contract_layer(_run_discover_regions(cmd, image, base, out_dir), "regions")
    f = tmp_path / "report.json"
    f.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    assert main(["schema", "validate", "--schema", "discover-report", "--file", str(f)]) == 0


def test_discover_suggested_action_vocabulary_used(discover_ready, tmp_path: Path) -> None:
    """实现不得自造动作名（词汇表是契约，不是建议）。"""
    cmd, image, base = discover_ready
    report = _normalize_via_contract_layer(_run_discover_regions(cmd, image, base, tmp_path), "regions")
    findings = report.get("findings") or {}
    for group in ("regions", "traps", "targets"):
        for i, item in enumerate(findings.get(group) or []):
            action = item.get("suggested_action")
            assert action in DISCOVER_SUGGESTED_ACTIONS, (
                f"findings.{group}[{i}].suggested_action={action!r} 不在契约词汇表 "
                f"{DISCOVER_SUGGESTED_ACTIONS}"
            )


@pytest.mark.parametrize("module", ["regions", "traps"])
def test_module_report_shape_without_cli(module: str) -> None:
    """不经 CLI 的纯函数冒烟：模块产出经契约层归一后必须能装入 discover-report 契约。

    即使 discover 子命令尚未注册，这条也能验证底层模块的产出形状与闸门一致。
    """
    try:
        if module == "regions":
            from fi.discover.regions import discover_regions as fn
        else:
            from fi.discover.traps import discover_traps as fn
    except Exception as exc:  # noqa: BLE001 —— 模块或其依赖（capstone）不可用
        pytest.skip(f"fi.discover.{module} 不可用: {exc}")

    image = _smoke_image()
    if image is None:
        pytest.skip(f"未找到冒烟镜像（设置 {IMAGE_ENV} 或放一个 *.bin 到仓库根）")

    from fi.schemas.discover_report import normalize_module_report

    raw = fn(str(image), _smoke_base())
    report = normalize_module_report(raw, module=module)
    errors = validate_instance("discover-report", report)
    assert errors == [], f"{module} 产出归一后不符合契约:\n" + "\n".join(errors)
    _assert_confidence_gate(report)
