"""Panel trait and asset tests (ARCHITECTURE §4.2/§4.3)."""

from __future__ import annotations

import pytest

pytest.importorskip("anywidget")

from viewviewview.panel import VvvPanel  # noqa: E402

PAYLOAD = {
    "columns": [
        {"name": "delay", "type": "int"},
        {"name": "reply", "type": "str"},
    ],
    "state_key": "state",
    "counts": {"PASS": 3, "FAIL": 1},
    "rows": [[10, "ok"], [20, "no-reply"]],
    "total": 4,
    "window": 2,
    "version": 42,
}


def test_panel_traits_round_trip():
    panel = VvvPanel(
        payload=PAYLOAD,
        colors={"count": "#19ff25"},
        number_columns=["delay"],
    )
    assert panel.payload == PAYLOAD
    assert panel.theme == "dark"
    assert panel.colors == {"count": "#19ff25"}
    assert panel.number_columns == ["delay"]


def test_panel_bundles_esm_and_css():
    panel = VvvPanel(payload=PAYLOAD)
    assert "renderPayload" in panel._esm
    assert "export default { render }" in panel._esm
    assert "vvv-resize" in panel._esm
    assert "vvv-num" in panel._esm
    assert "number_columns" in panel._esm
    assert "--vvv-count" in panel._esm
    assert "--vvv-number" in panel._esm
    assert "--vvv-bg" in panel._css
    assert "--vvv-panel" in panel._css
    assert "--vvv-count: #19ff25" in panel._css
    assert "--vvv-number: #19ff25" in panel._css
    assert "vvv-table--fixed" in panel._css


def test_panel_default_payload_is_empty():
    panel = VvvPanel()
    assert panel.payload == {}
