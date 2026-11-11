"""Delay-statistics pane: core accumulation + payload attach.

The stats block is additive to the frozen §4.3 payload: since v0.4.0 the
pane is on by default (bucket width 100), and **``stats_bucket=0`` must
leave every payload exactly as before** (the pre-0.4.0 default), while an
enabled pane aggregates every accepted CSV record (not the display window).
"""

from __future__ import annotations

import time

import pytest

from viewviewview import ViewWidget


def snapshot(widget: ViewWidget, include_stats: bool = False, depth: int = 5):
    """Latest §4.3 payload through the locked builder (Syncer's own path)."""
    with widget._lock:  # noqa: SLF001 - mirrors _build_live_snapshot
        return widget._build_payload_locked(
            "state", depth, include_stats=include_stats
        )


def test_stats_enabled_by_default(tmp_path, monkeypatch):
    import viewviewview.core as core

    captured = {}
    monkeypatch.setattr(
        core,
        "render_payload",
        lambda payload, colors=None, number_columns=None, on_created=None: captured.update(
            {"payload": payload}
        ),
    )
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    for index in range(4):
        widget.update(state="PASS" if index % 2 else "FAIL", delay=index)
    widget.show()
    stats = captured["payload"]["stats"]
    assert stats["bucket"] == 100
    assert stats["rows"] == 4
    widget.close()


def test_stats_bucket_zero_keeps_payload_without_stats(tmp_path, monkeypatch):
    import viewviewview.core as core

    captured = {}
    monkeypatch.setattr(
        core,
        "render_payload",
        lambda payload, colors=None, number_columns=None, on_created=None: captured.update(
            {"payload": payload}
        ),
    )
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"), stats_bucket=0)
    for index in range(4):
        widget.update(state="PASS" if index % 2 else "FAIL", delay=index)
    widget.show()
    assert "stats" not in captured["payload"]
    widget.close()


def test_show_includes_stats_when_enabled(tmp_path, monkeypatch):
    import viewviewview.core as core

    captured = {}
    monkeypatch.setattr(
        core,
        "render_payload",
        lambda payload, colors=None, number_columns=None, on_created=None: captured.update(
            {"payload": payload}
        ),
    )
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"), stats_bucket=100, live_rows=200
    )
    widget.update(state="PASS", delay=2700)
    widget.update(state="HANG", delay=2750)
    widget.show()
    stats = captured["payload"]["stats"]
    assert stats["bucket"] == 100
    assert stats["bars"] == 30
    assert stats["success"] == "PASS"
    assert stats["hang"] == "HANG"
    assert stats["buckets"] == [[2700, 2800, 2, 1, 1]]
    widget.close()


def test_stats_bucketing_counters_and_negative_floors(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"), stats_bucket=100)
    widget.update(state="PASS", delay=2700)
    widget.update(state="FAIL", delay=2705)
    widget.update(state="HANG", delay=2799)
    widget.update(state="PASS", delay=110)
    widget.update(state="HANG", delay=-3)
    payload = snapshot(widget, include_stats=True)
    stats = payload["stats"]
    assert stats["rows"] == 5
    assert stats["buckets"] == [
        [-100, 0, 1, 0, 1],
        [100, 200, 1, 1, 0],
        [2700, 2800, 3, 1, 1],
    ]
    widget.close()


def test_stats_float_delay_uses_floor(tmp_path):
    """A float-type delay column still folds (floats floor toward -inf)."""
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        columns={"state": str, "delay": float},
        stats_bucket=100,
    )
    widget.update(state="PASS", delay=149.9)
    widget.update(state="PASS", delay=-0.5)
    payload = snapshot(widget, include_stats=True)
    assert payload["stats"]["buckets"] == [
        [-100, 0, 1, 1, 0],
        [100, 200, 1, 1, 0],
    ]
    widget.close()


def test_stats_skips_rows_without_usable_delay(tmp_path):
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        columns={"pulse": int},
        stats_bucket=100,
    )
    widget.update(pulse=1)
    widget.update(pulse=2)
    payload = snapshot(widget, include_stats=True)
    stats = payload["stats"]
    assert stats["buckets"] == []
    assert stats["rows"] == 0
    widget.close()


def test_stats_requires_state_and_delay_columns(tmp_path):
    """No usable pair of state+delay columns: skip accumulation entirely."""
    delay_only = ViewWidget(
        csv_path=str(tmp_path / "d.csv"),
        columns={"delay": int},
        stats_bucket=100,
    )
    delay_only.update(delay=50)
    delay_only.update(delay=150)
    assert snapshot(delay_only, include_stats=True)["stats"]["buckets"] == []
    delay_only.close()

    state_only = ViewWidget(
        csv_path=str(tmp_path / "s.csv"),
        columns={"state": str},
        stats_bucket=100,
    )
    state_only.update(state="PASS")
    assert snapshot(state_only, include_stats=True)["stats"]["buckets"] == []
    state_only.close()


def test_stats_time_gap_gating(tmp_path):
    """stats refresh is gated by time since the last attach, not build count."""
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        stats_bucket=100,
        stats_interval=5,  # 5 x frame_delay(0.05) = 0.25 s minimum gap
    )
    widget.update(state="PASS", delay=10)

    with widget._lock:  # noqa: SLF001
        widget._stats_last_attach = time.monotonic()
    assert "stats" not in snapshot(widget)  # gap far below the minimum
    with widget._lock:  # noqa: SLF001
        widget._stats_last_attach = time.monotonic() - 1.0
    assert "stats" in snapshot(widget)  # due again
    assert "stats" in snapshot(widget, include_stats=True)  # show() always does
    widget.close()


def test_stats_settle_timer_pushes_after_burst(tmp_path):
    """A fast burst compressed into one Syncer frame still ends with stats."""

    class StubPanel:
        payload = None

    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        stats_bucket=100,
        stats_interval=5,
        live_rows=200,
    )
    panel = StubPanel()
    widget.syncer.attach(panel)
    with widget._lock:  # noqa: SLF001
        widget._selected_depth = 5  # as show() would set for live frames
    for index in range(150):
        widget.update(state="PASS" if index % 2 else "HANG", delay=1500 + index)
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if panel.payload is not None and "stats" in panel.payload:
            break
        time.sleep(0.05)
    assert panel.payload is not None and "stats" in panel.payload
    stats = panel.payload["stats"]
    assert stats["rows"] == 150
    assert len(stats["buckets"]) == 2  # delays 1500..1649 → two 100-wide buckets
    widget.close()


def test_stats_force_flag_is_consumed_once(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"), stats_bucket=100)
    widget.update(state="PASS", delay=10)
    widget.syncer.attach(type("Stub", (), {})())  # panels present: flush works
    with widget._lock:  # noqa: SLF001
        widget._selected_depth = 5

    with widget._lock:  # noqa: SLF001
        widget._stats_force = True
        first = widget._build_live_snapshot()
        second = widget._build_live_snapshot()
    assert "stats" in first
    assert "stats" not in second  # consumed on the first build
    widget.close()


def test_stats_custom_column_names(tmp_path):
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        columns={"result": str, "ms": int},
        stats_bucket=100,
        stats_state="result",
        stats_delay="ms",
        stats_success="OK",
        stats_hang="STUCK",
    )
    widget.update(result="OK", ms=123)
    widget.update(result="STUCK", ms=124)
    widget.update(result="MAYBE", ms=125)
    payload = snapshot(widget, include_stats=True)
    stats = payload["stats"]
    assert stats["success"] == "OK"
    assert stats["hang"] == "STUCK"
    assert stats["buckets"] == [[100, 200, 3, 1, 1]]
    widget.close()


def test_stats_bucket_count_is_capped_by_coarsening(tmp_path):
    """Sparse delay ranges merge into wider buckets instead of growing. """
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        stats_bucket=1,
        stats_state="state",
        stats_delay="delay",
        live_rows=10,
        flush_every=1000,
    )
    for delay in range(600):
        widget.update(state="PASS" if delay % 2 else "HANG", delay=delay)
    payload = snapshot(widget, include_stats=True, depth=1)
    stats = payload["stats"]
    buckets = stats["buckets"]
    assert len(buckets) <= 512
    width = stats["bucket"]
    assert width > 1  # coarsened from 1
    for lo, hi, total, ok, hang in buckets:
        assert lo % width == 0
        assert hi == lo + width
        assert total == ok + hang
    assert sum(bucket[2] for bucket in buckets) == 600
    widget.close()


def test_stats_custom_adds_custom_counter_and_payload_key(tmp_path):
    """stats_custom= rides an additive 6th slot + payload key (opt-in only)."""
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"), stats_custom="FAIL")
    widget.update(state="PASS", delay=150)
    widget.update(state="FAIL", delay=155)
    widget.update(state="HANG", delay=160)
    widget.update(state="FAIL", delay=980)
    stats = snapshot(widget, include_stats=True)["stats"]
    assert stats["custom"] == "FAIL"
    assert stats["buckets"] == [
        [100, 200, 3, 1, 1, 1],
        [900, 1000, 1, 0, 0, 1],
    ]
    widget.close()


def test_stats_custom_absent_from_default_payload(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    widget.update(state="FAIL", delay=150)
    stats = snapshot(widget, include_stats=True)["stats"]
    assert "custom" not in stats
    for bucket in stats["buckets"]:
        assert len(bucket) == 5
    widget.close()


def test_stats_custom_mirrors_already_charted_value(tmp_path):
    """stats_custom= equal to success/hang counts independently, not zero."""
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        stats_success="PASS",
        stats_custom="PASS",
    )
    widget.update(state="PASS", delay=10)
    stats = snapshot(widget, include_stats=True)["stats"]
    assert stats["buckets"] == [[0, 100, 1, 1, 0, 1]]
    widget.close()


def test_stats_custom_survives_coarsening(tmp_path):
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        stats_bucket=1,
        stats_custom="FAIL",
        live_rows=10,
        flush_every=1000,
    )
    for delay in range(600):
        widget.update(state="HANG" if delay % 2 else "FAIL", delay=delay)
    stats = snapshot(widget, include_stats=True, depth=1)["stats"]
    assert stats["bucket"] > 1
    for bucket in stats["buckets"]:
        assert len(bucket) == 6
        # rows: [lo, hi, total, ok, hang, custom]; here ok == 0 and every
        # record is FAIL (custom) or HANG, so total = hang + custom.
        assert bucket[3] == 0
        assert bucket[2] == bucket[4] + bucket[5]
    assert sum(bucket[5] for bucket in stats["buckets"]) == 300
    widget.close()


_BUCKET_MESSAGE = (
    "stats_bucket must be a non-negative integer (0 disables the stats pane)"
)


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"stats_bucket": -1}, _BUCKET_MESSAGE),
        ({"stats_bucket": "x"}, _BUCKET_MESSAGE),
        ({"stats_bucket": True}, _BUCKET_MESSAGE),
        ({"stats_interval": 0}, "stats_interval must be a positive integer"),
        ({"stats_interval": 2.5}, "stats_interval must be a positive integer"),
        ({"stats_bars": 0}, "stats_bars must be an integer between 1 and 50"),
        ({"stats_bars": 51}, "stats_bars must be an integer between 1 and 50"),
        ({"stats_state": ""}, "stats_state must be a non-empty string"),
        ({"stats_delay": ""}, "stats_delay must be a non-empty string"),
        ({"stats_success": ""}, "stats_success must be a non-empty string"),
        ({"stats_hang": ""}, "stats_hang must be a non-empty string"),
        (
            {"stats_custom": 123},
            "stats_custom must be a string (an empty string disables the chart)",
        ),
        (
            {"stats_custom": None},
            "stats_custom must be a string (an empty string disables the chart)",
        ),
    ],
)
def test_stats_validation(kwargs, message, tmp_path):
    with pytest.raises(ValueError) as info:
        ViewWidget(csv_path=str(tmp_path / "a.csv"), **kwargs)
    assert str(info.value) == message
