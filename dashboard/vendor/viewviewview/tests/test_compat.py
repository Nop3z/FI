"""Contract conformance tests for csvview/csvplot/start_view_service (ARCHITECTURE §3.3/§3.4)."""

from __future__ import annotations

import pytest

import viewviewview
from viewviewview import compat

HEADER = "state,delay,pulse,reply,errcode\r\n"


def make_csv(tmp_path, rows, name="run.csv"):
    path = tmp_path / name
    body = "".join(",".join(str(value) for value in row) + "\r\n" for row in rows)
    path.write_bytes((HEADER + body).encode("utf-8"))
    return str(path)


def test_start_view_service_is_a_repeating_noop(caplog):
    viewviewview.start_view_service()
    viewviewview.start_view_service(port=12346, max_heap="4g")
    viewviewview.start_view_service(port="bad", max_heap=123)  # never raises
    assert "Deephaven service not required" in caplog.text


def test_csvview_builds_counts_and_newest_first(monkeypatch, tmp_path):
    path = make_csv(
        tmp_path,
        [
            ("PASS", 100, 1.5, "ok", 0),
            ("FAIL", 110, 2.0, "no-reply", 3),
            ("PASS", 120, 2.5, "ok", 0),
        ],
    )
    captured = {}
    monkeypatch.setattr(compat, "render_payload", captured.update)
    compat.csvview(path)
    payload = captured
    assert payload["state_key"] == "state"
    assert payload["counts"] == {"PASS": 2, "FAIL": 1}
    assert payload["rows"][0][1] == "120"  # newest row first (CSV text preserved)
    assert payload["rows"][-1][1] == "100"
    assert payload["columns"][1] == {"name": "delay", "type": "int"}
    assert payload["columns"][2] == {"name": "pulse", "type": "float"}
    assert payload["columns"][3] == {"name": "reply", "type": "str"}
    assert payload["total"] == 3 and payload["window"] == 3


def test_csvview_tail_limit(monkeypatch, tmp_path):
    rows = [("PASS" if index % 2 == 0 else "FAIL", index, 1.0, "ok", 0) for index in range(20)]
    path = make_csv(tmp_path, rows)
    captured = {}
    monkeypatch.setattr(compat, "render_payload", captured.update)
    compat.csvview(path, limit=3)
    assert captured["window"] == 3
    assert [row[1] for row in captured["rows"]] == ["19", "18", "17"]
    assert captured["counts"] == {"PASS": 1, "FAIL": 2}


def test_csvview_full_flag_ignores_limit(monkeypatch, tmp_path):
    rows = [("PASS", index, 1.0, "ok", 0) for index in range(5)]
    path = make_csv(tmp_path, rows)
    captured = {}
    monkeypatch.setattr(compat, "render_payload", captured.update)
    compat.csvview(path, limit=2, full=True)
    assert captured["window"] == 5


def test_csvview_limit_zero_disables_rendering(monkeypatch, tmp_path, caplog):
    path = make_csv(tmp_path, [("PASS", 1, 1.0, "ok", 0)])
    called = []
    monkeypatch.setattr(compat, "render_payload", lambda payload: called.append(payload))
    compat.csvview(path, limit=0)
    assert called == []
    assert "CSV display disabled" in caplog.text


def test_csvview_unknown_state_column(monkeypatch, tmp_path):
    path = make_csv(tmp_path, [("PASS", 1, 1.0, "ok", 0)])
    captured = {}
    monkeypatch.setattr(compat, "render_payload", captured.update)
    compat.csvview(path, state="missing")
    assert captured["state_key"] is None
    assert captured["counts"] == {}


def test_csvview_empty_file_logs(tmp_path, caplog):
    path = make_csv(tmp_path, [])
    compat.csvview(path)
    assert "No data recorded in" in caplog.text


def test_csvview_malformed_record(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_bytes(b"state,delay\r\nPASS,1\r\nBROKEN\r\n")
    with pytest.raises(ValueError, match="Malformed CSV record 2"):
        compat.csvview(str(path))


def test_csvplot_limit_zero_is_a_noop(tmp_path, caplog):
    path = make_csv(tmp_path, [("PASS", 1, 1.0, "ok", 0)])
    compat.csvplot(path, limit=0)
    assert "CSV plot disabled" in caplog.text


def test_csvplot_without_pygwalker_falls_back_to_view(monkeypatch, tmp_path):
    path = make_csv(tmp_path, [("PASS", 1, 1.0, "ok", 0)])
    monkeypatch.setitem(__import__("sys").modules, "pygwalker", None)
    called = []
    monkeypatch.setattr(compat, "csvview", lambda *args, **kwargs: called.append((args, kwargs)))
    compat.csvplot(path, limit=5)
    assert len(called) == 1
    assert called[0][1]["limit"] == 5


def test_csvplot_without_pandas_also_falls_back(monkeypatch, tmp_path):
    path = make_csv(tmp_path, [("PASS", 1, 1.0, "ok", 0)])
    monkeypatch.setitem(__import__("sys").modules, "pandas", None)
    called = []
    monkeypatch.setattr(compat, "csvview", lambda *args, **kwargs: called.append((args, kwargs)))
    compat.csvplot(path)
    assert len(called) == 1


def test_viewviewview_exports():
    assert viewviewview.ViewViewView is viewviewview.ViewWidget
    assert viewviewview.__version__ == "0.6.0"
    for name in ("ViewWidget", "start_view_service", "csvview", "csvplot"):
        assert getattr(viewviewview, name) is not None
