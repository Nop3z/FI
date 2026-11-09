"""冒烟测试：包可导入、版本/契约版本一致、包结构完整。"""

import importlib


def test_package_imports() -> None:
    import fi

    assert fi.__version__ == "0.3.0"
    assert fi.CONTRACT_VERSION == "0.2"
    assert fi.EVIDENCE_LEVELS == ("observation", "hypothesis", "unknown")
    assert fi.UNKNOWN == "unknown"


def test_subpackage_imports() -> None:
    for mod in (
        "fi.schemas",
        "fi.providers",
        "fi.loop",
        "fi.sim",
        "fi.analysis",
        "fi.profiles",
        "fi.cli",
    ):
        importlib.import_module(mod)


def test_contract_version_consistency() -> None:
    """包内 CONTRACT_VERSION 必须与公共定义的 schema_version 常量一致；
    各契约的 schema_version 字段统一 $ref 到该定义（单一事实来源）。"""
    import fi
    from fi.schemas import load_schema

    common = load_schema("common")
    assert common["$defs"]["schema_version"]["const"] == fi.CONTRACT_VERSION

    for name in (
        "fault-context",
        "campaign-record",
        "experiment-scan",
        "chip-profile-index",
        "analysis-result",
        "reverse-report",
        "tts-metrics",
    ):
        schema = load_schema(name)
        ref = schema["properties"]["schema_version"].get("$ref", "")
        assert ref.endswith("common.defs.json#/$defs/schema_version"), name


def test_package_version_matches_pyproject() -> None:
    """fi.__version__ 必须与 pyproject.toml 的 project.version 一致（避免版本漂移）。"""
    import re
    from pathlib import Path

    import fi

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "pyproject.toml 缺 project.version"
    assert m.group(1) == fi.__version__
