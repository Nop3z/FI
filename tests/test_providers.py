"""Provider 接口测试：占位实现 detect 不可用、capture 报错、unknown 审计。"""

import pytest

from fi import UNKNOWN
from fi.providers import (
    CrashDumpCaptureProvider,
    DebugCaptureProvider,
    ExternalCaptureProvider,
    TrapCaptureProvider,
    UartCaptureProvider,
)
from fi.providers.base import _audit_unknowns

ALL_PLACEHOLDERS = [
    UartCaptureProvider,
    TrapCaptureProvider,
    CrashDumpCaptureProvider,
    DebugCaptureProvider,
    ExternalCaptureProvider,
]


@pytest.mark.parametrize("cls", ALL_PLACEHOLDERS)
def test_placeholder_detects_unavailable(cls) -> None:
    """纯离线约束：实机 Provider 只做接口预留，detect 必须报告不可用。"""
    provider = cls()
    result = provider.detect()
    assert result.available is False
    assert result.provider_name == provider.name
    assert result.reason  # 必须说明不可用原因
    assert result.observation_level in ("behavior", "processor_context", "execution_trace")


@pytest.mark.parametrize("cls", ALL_PLACEHOLDERS)
def test_placeholder_capture_raises(cls) -> None:
    from fi.providers.base import CaptureRequest

    provider = cls()
    with pytest.raises(RuntimeError):
        provider.capture(CaptureRequest(campaign_id="c1"))


def test_provider_names_in_contract_vocabulary() -> None:
    """占位 Provider 名必须在契约 provider_name 枚举词汇表内。"""
    from fi.schemas import load_schema

    common = load_schema("common")
    allowed = set(common["$defs"]["provider_name"]["enum"])
    for cls in ALL_PLACEHOLDERS:
        assert cls.name in allowed, f"{cls.__name__}: {cls.name} 不在契约枚举内"


def test_unknown_audit_hints() -> None:
    context = {
        "schema_version": "0.2",
        "context_id": "ctx-x",
        "source_provider": "uart",
        "observation_level": "behavior",
        "evidence_level": "observation",
        "pc": UNKNOWN,
        "registers": UNKNOWN,
        "execution_trace": UNKNOWN,
    }
    hints = _audit_unknowns(context)
    assert len(hints) == 3
    assert all(h.startswith("hint:") for h in hints)
