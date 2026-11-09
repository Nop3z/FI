"""CLI 测试：注册机制、schema list/validate、data convert 端到端。"""

import json
from pathlib import Path

import pytest

from fi import __version__
from fi.cli import COMMANDS, build_parser, command, main


# ---------------------------------------------------------------- 注册机制


def test_builtin_commands_registered() -> None:
    assert ("schema", "list") in COMMANDS
    assert ("schema", "validate") in COMMANDS
    assert ("data", "convert") in COMMANDS


def test_optional_command_registration_is_non_fatal() -> None:
    """可选子命令（fi.discover.cli）缺失时只跳过，绝不让主 CLI 不可用。

    这是核心稳定性约束：`fi schema list` 必须永远能跑，即使某成员的子命令包
    尚未提交或其第三方依赖（capstone）缺失。
    """
    from fi.cli_plugins import OPTIONAL_COMMAND_MODULES, register_optional_commands

    report = register_optional_commands()
    assert set(report) == set(OPTIONAL_COMMAND_MODULES)
    # 无论成功或跳过，都必须给出明确结果（None=成功；字符串=跳过原因）
    for module, result in report.items():
        assert result is None or isinstance(result, str), module
    # 主 CLI 仍然可用
    assert main(["schema", "list"]) == 0


def test_discover_group_registered_when_module_present() -> None:
    """fi/discover/cli.py 存在且可用时，discover 组必须自动出现在 CLI 里。

    模块缺失时 skip（由 chip-profile 维护，不阻塞其余契约测试）。
    """
    from fi.cli_plugins import register_optional_commands, registration_report

    register_optional_commands()
    result = registration_report().get("fi.discover.cli", "not-attempted")
    if result is not None:
        pytest.skip(f"fi.discover.cli 未可用（{result}）；注册后本测试自动生效")
    assert any(group == "discover" for group, _ in COMMANDS), "模块已导入但未注册 discover 命令"
    # 子命令须能被 parser 构造出来（否则 --help 会炸）
    parser = build_parser()
    assert parser is not None


def test_registration_hook_picks_up_late_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """自动注册钩子必须在模块"后到"时也能注册（不依赖 import 顺序）。

    用假模块验证：真实 fi.discover.cli 由 chip-profile 提供，本测试只验证 hook 机制。
    """
    import sys
    import types

    from fi import cli_plugins

    fake = types.ModuleType("fi.discover.cli")

    @command("discover", "demo", "假 discover 命令（hook 机制验证用）")
    def _demo(args) -> int:  # noqa: ANN001
        return 0

    fake._demo = _demo
    monkeypatch.setitem(sys.modules, "fi.discover.cli", fake)
    monkeypatch.setattr(cli_plugins, "register_optional_commands", cli_plugins.register_optional_commands)
    cli_plugins.reset_registration_cache()
    try:
        report = cli_plugins.register_optional_commands()
        assert report["fi.discover.cli"] is None, report
        assert ("discover", "demo") in COMMANDS
    finally:
        COMMANDS.pop(("discover", "demo"), None)
        cli_plugins.reset_registration_cache()


def test_registration_hook_records_failure_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    """导入失败必须记录原因（可见），且不抛出（不致命）。"""
    import sys
    import types

    from fi import cli_plugins

    broken = types.ModuleType("fi.discover.cli")
    # 模拟模块内部依赖缺失：模块体抛 ImportError 难以模拟，用 import 失败更直接
    broken.__spec__ = None
    monkeypatch.setitem(sys.modules, "fi.discover.cli", broken)
    real_import = cli_plugins.importlib.import_module

    def _raise(name: str):
        if name == "fi.discover.cli":
            raise ImportError("simulated missing capstone")
        return real_import(name)

    monkeypatch.setattr(cli_plugins.importlib, "import_module", _raise)
    cli_plugins.reset_registration_cache()
    try:
        report = cli_plugins.register_optional_commands()
        assert report["fi.discover.cli"] is not None
        assert "simulated missing capstone" in report["fi.discover.cli"]
        # 主 CLI 仍可用
        assert main(["schema", "list"]) == 0
    finally:
        cli_plugins.reset_registration_cache()


def test_custom_command_registration() -> None:
    """其他成员可经装饰器扩展 CLI，不改 main()。"""

    @command("demo", "ping", "测试命令")
    def _ping(args) -> int:
        return 7

    try:
        assert main(["demo", "ping"]) == 7
        assert ("demo", "ping") in COMMANDS
    finally:
        COMMANDS.pop(("demo", "ping"), None)


def test_registry_is_single_object_across_entry_points() -> None:
    """注册表必须是**单一对象**，与入口方式无关（历史坑：注册进影子副本）。

    背景：`python -m fi.cli` 把 fi/cli.py 当 __main__ 执行；若 COMMANDS 定义在
    fi.cli 内，成员包 `from fi.cli import command` 会再导入一份 fi.cli，
    结果命令注册进另一份 dict，主入口看不到。注册表已移到 fi.cli_registry。
    """
    import subprocess
    import sys

    from fi.cli import COMMANDS as cli_commands
    from fi.cli_registry import COMMANDS as registry_commands

    assert cli_commands is registry_commands, "COMMANDS 必须来自 fi.cli_registry（同一对象）"

    # 子进程验证 `python -m fi.cli` 也能看到成员子命令（这是影子副本的判别式）
    code = (
        "import sys;"
        "from fi.cli import build_parser, COMMANDS;"
        "build_parser();"
        "groups=sorted({g for g,_ in COMMANDS});"
        "print(','.join(groups))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr[-2000:]
    groups = out.stdout.strip().split(",")
    assert "schema" in groups
    # 成员子命令模块存在时，其组必须出现在注册表里
    from fi.cli_plugins import register_optional_commands, registration_report

    report = register_optional_commands()
    if report.get("fi.discover.cli") is None:
        assert "discover" in groups, f"discover 组未注册（groups={groups}）"
    if report.get("fi.analysis.anomaly_cli") is None:
        assert "analyze" in groups, f"analyze 组未注册（groups={groups}）"


def test_analyze_group_registered_when_module_present() -> None:
    """fi/analysis/anomaly_cli.py 存在时，analyze 组必须出现在 CLI 里。"""
    from fi.cli_plugins import register_optional_commands, registration_report

    register_optional_commands()
    result = registration_report().get("fi.analysis.anomaly_cli", "not-attempted")
    if result is not None:
        pytest.skip(f"fi.analysis.anomaly_cli 未可用（{result}）；注册后本测试自动生效")
    assert ("analyze", "anomaly") in COMMANDS
    parser = build_parser()
    assert parser is not None


def test_version_flag(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_bare_invocation_prints_help_not_crash(capsys: pytest.CaptureFixture) -> None:
    """裸 `fi`（无子命令）必须打印帮助并返回 2，不得抛 AttributeError。

    历史缺陷：main() 直接读 args.command，无子命令时 argparse 不给该属性。
    """
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 2
    assert "usage:" in out.lower()
    assert "schema" in out


# ---------------------------------------------------------------- schema 子命令


def test_schema_list_ok(capsys: pytest.CaptureFixture) -> None:
    assert main(["schema", "list"]) == 0
    out = capsys.readouterr().out
    for name in ("fault-context", "campaign-record", "experiment-scan",
                 "chip-profile-index", "analysis-result", "sim-trace",
                 "reverse-report", "discover-report", "tts-metrics"):
        assert name in out


def test_schema_validate_campaign_record(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    record = {
        "schema_version": "0.2",
        "campaign_id": "camp-cli-000001",
        "params": {"raw_delay": 3145, "raw_pulse": 2},
        "response": {"state_label": "SUCCESS", "state_label_semantics": "unconfirmed-v0.1"},
        "evidence_level": "observation",
    }
    f = tmp_path / "record.json"
    f.write_text(json.dumps(record), encoding="utf-8")
    assert main(["schema", "validate", "--schema", "campaign-record", "--file", str(f)]) == 0

    record["evidence_level"] = "not-a-level"
    f.write_text(json.dumps(record), encoding="utf-8")
    assert main(["schema", "validate", "--schema", "campaign-record", "--file", str(f)]) == 1


def test_schema_validate_jsonl_sim_trace(tmp_path: Path) -> None:
    run_id = "run-cli-1"
    lines = [
        {"type": "run_meta", "run_id": run_id,
         "image": {"path": "<ROM_IMAGE>", "sha256": "a" * 64, "base_address": <BASE_DEC>},
         "engine": {"name": "stub"}, "evidence_level": "observation"},
        {"type": "trace", "run_id": run_id, "seq": 0, "pc": <BASE_DEC>,
         "instruction_raw": "73100730", "evidence_level": "observation"},
        {"type": "run_end", "run_id": run_id, "exit_reason": "normal",
         "final_pc": <BASE_DEC>, "instruction_count": 1, "evidence_level": "observation"},
    ]
    f = tmp_path / "trace.jsonl"
    f.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    assert main(["schema", "validate", "--schema", "sim-trace", "--file", str(f)]) == 0


def test_schema_validate_common_rejected(tmp_path: Path) -> None:
    f = tmp_path / "x.json"
    f.write_text("{}", encoding="utf-8")
    assert main(["schema", "validate", "--schema", "common", "--file", str(f)]) == 1


# ---------------------------------------------------------------- data 子命令


def test_data_convert_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    csv_src = tmp_path / "sample.csv"
    csv_src.write_text(
        "state,delay,pulse,response,glitched,unexpected\n"
        "SUCCESS,3130,2,,glitched,OK\n"
        "FL,2640,6,0x<CODE_A>,glitched,\n",
        encoding="utf-8",
    )
    out = tmp_path / "derived" / "out.jsonl"

    rc = main([
        "data", "convert",
        "--input", str(csv_src),
        "--output", str(out),
        "--validate-sample", "10",
    ])
    assert rc == 0
    records = [json.loads(line) for line in out.open(encoding="utf-8")]
    assert len(records) == 2
    assert records[0]["response"]["state_label"] == "SUCCESS"
    assert records[0]["params"]["delay_ns"] == "unknown"
    assert records[0]["raw_data_ref"]["row_index"] == 0

    # --state 过滤 + ns 假设
    rc = main([
        "data", "convert",
        "--input", str(csv_src),
        "--output", str(tmp_path / "filtered.jsonl"),
        "--state", "FL",
        "--assume-ns-per-raw", "10",
    ])
    assert rc == 0
    rows = [json.loads(line) for line in (tmp_path / "filtered.jsonl").open(encoding="utf-8")]
    assert len(rows) == 1
    assert rows[0]["response"]["state_label"] == "FL"
    assert rows[0]["params"]["delay_ns"] == 26400
    assert rows[0]["params"]["unit_assumption"]["evidence_level"] == "hypothesis"


def test_data_convert_refuses_overwrite_source(tmp_path: Path) -> None:
    csv_src = tmp_path / "sample.csv"
    csv_src.write_text(
        "state,delay,pulse,response,glitched,unexpected\nSUCCESS,3130,2,,glitched,OK\n",
        encoding="utf-8",
    )
    assert main(["data", "convert", "--input", str(csv_src), "--output", str(csv_src)]) == 1
