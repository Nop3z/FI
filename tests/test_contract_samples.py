"""契约样例产物一致性测试：`data/derived/contract-samples/*.sample.json` 必须始终合法。

动机：样例是交付给 Web 团队照抄的模板。契约改了而样例没重生成，是最常见的
"文档对、数据错"事故。本测试把样例纳入门禁：

- 三个新契约的样例必须存在、通过结构 + 语义校验；
- reverse-report 样例的每条断言必须是 hypothesis/unknown（样例不得冒充事实）；
- discover-report 样例的 confidence 闸门同样强制；
- 样例与契约字段集合不漂移（顶层 required 全出现）。

重生成命令（源码变更后）：
    python data/derived/_gen_contract_samples.py --image <bin> --base <addr>
"""

import json
from pathlib import Path

import pytest

from fi.schemas import validate_instance

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "derived" / "contract-samples"

CASES = ("discover-report", "reverse-report", "tts-metrics")


def _load(name: str) -> dict:
    path = SAMPLES / f"{name}.sample.json"
    if not path.is_file():
        pytest.skip(f"样例未生成：{path.relative_to(REPO_ROOT)}（运行 _gen_contract_samples.py）")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", CASES)
def test_sample_exists_and_validates(name: str) -> None:
    data = _load(name)
    errors = validate_instance(name, data)
    assert errors == [], f"{name} 样例不合契约（需重生成）:\n" + "\n".join(errors)


@pytest.mark.parametrize("name", CASES)
def test_sample_covers_required_fields(name: str) -> None:
    from fi.schemas import load_schema

    schema = load_schema(name)
    data = _load(name)
    missing = [k for k in schema["required"] if k not in data]
    assert not missing, f"{name} 样例缺必填字段: {missing}"


def test_reverse_sample_assertions_not_overclaimed() -> None:
    """样例是模板：任何断言都不得标 observation（否则可能被照抄成"已验证"）。"""
    data = _load("reverse-report")
    allowed = {"hypothesis", "unknown"}
    levels = {data["confidence"]}
    for item in data.get("call_chain") or []:
        levels.add(item["confidence"])
    for item in data.get("entry_points") or []:
        levels.add(item["confidence"])
    for item in data.get("injection_targets") or []:
        levels.add(item["confidence"])
    assert levels <= allowed, f"样例出现越界等级: {levels - allowed}"


def test_reverse_sample_timing_has_assumption_object() -> None:
    """时间估算样例必须示范"带假设对象"，不能只给 ns 数字。"""
    data = _load("reverse-report")
    timing = data["timing_estimate"]
    assert isinstance(timing["ns_per_cycle"], dict)
    assert "confidence" in timing["ns_per_cycle"]
    assert timing["ns_estimate"]["formula"] == "cycles * ns_per_cycle"


def test_discover_sample_confidence_gate() -> None:
    from fi.schemas import DISCOVER_CONFIDENCE_ALLOWED

    data = _load("discover-report")
    assert data["confidence"] in DISCOVER_CONFIDENCE_ALLOWED
    for group in ("regions", "traps", "targets"):
        for item in data["findings"][group]:
            assert item["confidence"] in DISCOVER_CONFIDENCE_ALLOWED
            assert item["sample_evidence"], "样例条目必须示范 sample_evidence"


def test_tts_sample_demonstrates_unknown_not_zero() -> None:
    """样例必须示范"未知写 unknown"，而不是填 0 冒充实测值。"""
    data = _load("tts-metrics")
    assert data["instr_per_sec"] == "unknown"
    assert data["bytes_per_instr"] == "unknown"
    assert data["tts_a_minutes"] == "unknown"


def test_generator_script_is_replayable() -> None:
    """生成脚本必须存在且声明默认镜像发现策略（不硬编码芯片文件名）。"""
    script = REPO_ROOT / "data" / "derived" / "_gen_contract_samples.py"
    assert script.is_file()
    text = script.read_text(encoding="utf-8")
    assert "glob(\"*.bin\")" in text or "glob('*.bin')" in text, "应自动发现样例镜像"
    assert "validate_instance" in text, "生成后必须自校验"
