"""Contract conformance tests for the ViewWidget recorder (ARCHITECTURE §2/§3.2)."""

from __future__ import annotations

import csv
import re
import threading
import time
from pathlib import Path

import pytest

from viewviewview import ViewWidget
from viewviewview.core import _TailReader


def read_all(path):
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return list(csv.reader(handle))


def test_first_update_freezes_schema(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    assert widget.update(state="PASS", delay=1, pulse=2.5, reply="ok") is True
    assert widget.update(state="FAIL", delay=2, pulse=3.5, reply="no") is True
    widget.close()
    rows = read_all(tmp_path / "a.csv")
    assert rows == [
        ["state", "delay", "pulse", "reply"],
        ["PASS", "1", "2.5", "ok"],
        ["FAIL", "2", "3.5", "no"],
    ]


def test_first_update_rejects_empty_and_invalid_types(tmp_path, caplog):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    assert widget.update() is False
    assert widget.update(state="PASS", delay=1, flag=True) is False
    assert widget.update(state="PASS", delay=None) is False
    assert widget.update(state="PASS", delay=object()) is False
    assert widget.rows_written == 0
    assert "record names/types mismatch; supported types: int, float, str" in caplog.text
    assert not (tmp_path / "a.csv").exists()  # never created
    widget.close()


def test_schema_rejects_drift_extras_and_missing_keys(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    assert widget.update(state="PASS", delay=1) is True
    assert widget.update(state="PASS", delay=2.5) is False  # float drift
    assert widget.update(state="PASS", delay=3, extra=1) is False  # extra key
    assert widget.update(state="PASS") is False  # missing key
    assert widget.update(state="PASS", delay=True) is False  # bool drift
    assert widget.rows_written == 1
    widget.close()


def test_key_order_is_irrelevant_but_csv_order_is_frozen(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    assert widget.update(state="PASS", delay=1, pulse=2.5) is True
    assert widget.update(pulse=3.5, state="FAIL", delay=2) is True
    widget.close()
    assert read_all(tmp_path / "a.csv")[2] == ["FAIL", "2", "3.5"]


def test_default_csv_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    widget = ViewWidget()
    assert widget.update(state="PASS", delay=1) is True
    widget.close()
    path = widget.csv_path
    assert path is not None
    assert path.startswith(str(tmp_path))
    assert re.fullmatch(r"\d{8}-\d{6}(-\d+)?\.csv", Path(path).name)
    assert read_all(path)[1] == ["PASS", "1"]


def test_default_csv_name_is_widget_start_time(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    widget = ViewWidget()
    path = widget.csv_path
    assert path is not None
    assert not Path(path).exists()  # lazy creation
    assert re.fullmatch(r"\d{8}-\d{6}(-\d+)?\.csv", Path(path).name)
    widget.update(state="PASS", delay=1)
    widget.close()
    assert Path(path).exists()


def test_manual_csv_name_and_parent_directories(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    widget = ViewWidget(csv_path="runs/my_experiment.csv")
    assert widget.csv_path == str(tmp_path / "runs" / "my_experiment.csv")
    widget.update(state="PASS", delay=1)
    widget.close()
    assert read_all(tmp_path / "runs" / "my_experiment.csv")[1] == ["PASS", "1"]


def test_properties(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    assert widget.csv_path == str(tmp_path / "a.csv")
    assert widget.rows_written == 0
    widget.update(state="PASS", delay=1)
    assert widget.rows_written == 1
    widget.close()


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"display_limit": -1}, "limit must be a non-negative integer or None"),
        ({"live_rows": -1}, "limit must be a non-negative integer or None"),
        ({"live_rows": "x"}, "limit must be a non-negative integer or None"),
        ({"flush_every": 0}, "flush_every must be a positive integer"),
        ({"flush_every": True}, "flush_every must be a positive integer"),
        ({"fsync": "yes"}, "fsync must be a bool"),
    ],
)
def test_constructor_validation(kwargs, message):
    with pytest.raises(ValueError) as info:
        ViewWidget(**kwargs)
    assert str(info.value) == message


def test_existing_header_mismatch(tmp_path):
    path = tmp_path / "a.csv"
    path.write_bytes(b"other,columns\r\nx,1\r\n")
    widget = ViewWidget(csv_path=str(path))
    with pytest.raises(ValueError, match="CSV header mismatch"):
        widget.update(state="PASS", delay=1)
    widget.close()


def test_unfinished_last_record(tmp_path):
    path = tmp_path / "a.csv"
    path.write_bytes(b"state,delay\r\nPASS,1")
    widget = ViewWidget(csv_path=str(path))
    with pytest.raises(ValueError, match="unfinished last record"):
        widget.update(state="PASS", delay=1)
    widget.close()


def test_empty_existing_file_is_headerless(tmp_path):
    path = tmp_path / "a.csv"
    path.write_bytes(b"")
    widget = ViewWidget(csv_path=str(path))
    assert widget.update(state="PASS", delay=1) is True
    widget.close()
    assert read_all(path) == [["state", "delay"], ["PASS", "1"]]


def test_resume_existing_csv_appends(tmp_path):
    path = tmp_path / "a.csv"
    first = ViewWidget(csv_path=str(path))
    first.update(state="PASS", delay=1)
    first.close()
    second = ViewWidget(csv_path=str(path))
    second.update(state="FAIL", delay=2)
    second.close()
    assert read_all(path) == [
        ["state", "delay"],
        ["PASS", "1"],
        ["FAIL", "2"],
    ]


def test_flush_every_flushes_on_threshold(tmp_path):
    path = tmp_path / "a.csv"
    widget = ViewWidget(csv_path=str(path), flush_every=5)
    for index in range(5):
        widget.update(state="PASS", delay=index)
    # Rows 1-4 are buffered; the fifth write must hit the disk flush.
    assert len(read_all(path)) == 6
    widget.close()


def test_fsync_option(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"), fsync=True, flush_every=1)
    widget.update(state="PASS", delay=1)
    assert widget.rows_written == 1
    widget.close()


def test_context_manager_and_idempotent_close(tmp_path):
    path = tmp_path / "a.csv"
    with ViewWidget(csv_path=str(path)) as widget:
        widget.update(state="PASS", delay=1)
    widget.close()
    widget.close()
    assert read_all(path)[1] == ["PASS", "1"]


def test_io_failure_latches(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path))  # a directory cannot be opened
    with pytest.raises(OSError):
        widget.update(state="PASS", delay=1)
    with pytest.raises(RuntimeError, match="CSV recording previously failed"):
        widget.update(state="PASS", delay=2)


def test_thread_safety(tmp_path):
    path = tmp_path / "a.csv"
    widget = ViewWidget(csv_path=str(path))
    errors = []

    def worker(worker_id):
        try:
            for index in range(200):
                if not widget.update(state="PASS", seq=worker_id * 1000 + index):
                    errors.append("rejected")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(worker_id,)) for worker_id in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert widget.rows_written == 1600
    widget.close()
    assert len(read_all(path)) == 1601


def test_csv_only_mode(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"), live_rows=0)
    for index in range(25):
        widget.update(state="PASS", delay=index)
    widget.close()
    assert widget.rows_written == 25


def test_ring_window_is_bounded(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"), live_rows=10)
    for index in range(100):
        widget.update(state="PASS", delay=index)
    assert len(widget._ring) == 10
    assert widget._ring[-1] == ("PASS", 99)
    widget.close()


def test_tail_reader_window_and_malformed(tmp_path):
    path = tmp_path / "a.csv"
    path.write_bytes(b"a,b\r\n1,2\r\n3,4\r\n5,6\r\n")
    header, rows = _TailReader(str(path)).read(2)
    assert header == ["a", "b"]
    assert rows == [["3", "4"], ["5", "6"]]
    malformed = tmp_path / "bad.csv"
    malformed.write_bytes(b"a,b\r\n1,2\r\n3\r\n")
    with pytest.raises(ValueError, match="Malformed CSV record 2"):
        _TailReader(str(malformed)).read(None)


def test_colors_override_validation(tmp_path):
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        colors={"count": "#19ff25", "number": "#19ff25", "text": "#ffffff"},
    )
    assert widget._colors == {
        "count": "#19ff25",
        "number": "#19ff25",
        "text": "#ffffff",
    }
    assert widget._number_columns == ["delay", "pulse"]
    widget.close()
    for bad in ({"nope": "#fff"}, {"count": "green"}, {"count": 123}, ["#fff"]):
        with pytest.raises(ValueError):
            ViewWidget(colors=bad)


def test_faultviz_compat_column_attribute(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    assert widget._column == {}
    widget.update(state="PASS", delay=1, pulse=2.5)
    assert widget._column == {"state": str, "delay": int, "pulse": float}
    widget.close()


def test_faultviz_compat_column_attribute_predeclared(tmp_path):
    mapping = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        columns={"state": str, "delay": int},
    )
    assert mapping._column == {"state": str, "delay": int}
    mapping.close()
    sequence = ViewWidget(
        csv_path=str(tmp_path / "b.csv"), columns=["state", "delay"]
    )
    assert dict(sequence._column) == {"state": None, "delay": None}
    sequence.update(state="PASS", delay=1)
    assert sequence._column == {"state": str, "delay": int}
    sequence.close()


def test_number_columns_validation(tmp_path):
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"), number_columns=["delay", "temperature"]
    )
    assert widget._number_columns == ["delay", "temperature"]
    widget.close()
    assert ViewWidget(number_columns=[])._number_columns == []
    for bad in ("delay", [""], [1], 42):
        with pytest.raises(ValueError):
            ViewWidget(number_columns=bad)


def test_show_passes_colors_and_number_columns(tmp_path, monkeypatch):
    import viewviewview.core as core

    captured = {}
    monkeypatch.setattr(
        core,
        "render_payload",
        lambda payload, colors=None, number_columns=None, on_created=None: captured.update(
            {"colors": colors, "number_columns": number_columns}
        ),
    )
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"),
        colors={"count": "#19ff25"},
        number_columns=["delay"],
    )
    widget.update(state="PASS", delay=1, pulse=2, errcode=0)
    widget.show()
    assert captured["colors"] == {"count": "#19ff25"}
    assert captured["number_columns"] == ["delay"]
    widget.close()


def test_show_builds_contract_payload(tmp_path, monkeypatch):
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
    for index in range(10):
        widget.update(state=("PASS", "FAIL")[index % 2], delay=index, pulse=float(index))
    widget.show()
    payload = captured["payload"]
    assert payload["state_key"] == "state"
    assert payload["counts"] == {"PASS": 5, "FAIL": 5}
    assert payload["rows"][0][1] == 9  # newest first
    assert payload["rows"][-1][1] == 0
    assert payload["total"] == 10
    assert payload["window"] == 10
    assert payload["columns"][1] == {"name": "delay", "type": "int"}
    widget.close()


def test_show_limit_zero_is_counts_only(tmp_path, monkeypatch):
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
    widget.update(state="PASS", delay=1)
    widget.show(limit=0)
    assert captured["payload"]["rows"] == []
    assert captured["payload"]["counts"] == {"PASS": 1}
    widget.close()


def test_show_without_state_column(tmp_path, monkeypatch):
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
    widget.update(delay=1, pulse=2.5)
    widget.show()
    assert captured["payload"]["state_key"] is None
    assert captured["payload"]["counts"] == {}
    widget.close()


def test_show_no_data_logs(tmp_path, caplog):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    widget.show()
    assert "No data recorded." in caplog.text
    widget.close()


def test_show_outside_ipython_warns(tmp_path, caplog):
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    widget.update(state="PASS", delay=1)
    widget.show()
    assert "No IPython display environment available" in caplog.text
    widget.close()


def test_show_replace_closes_previous_panel(tmp_path, monkeypatch):
    """S2b: show(replace=True) closes the previous panel; default accumulates."""
    import viewviewview.core as core

    created = []

    class FakePanel:
        def __init__(self):
            self.closed = False
            created.append(self)

        def close(self):
            self.closed = True

    monkeypatch.setattr(
        core,
        "render_payload",
        lambda payload, colors=None, number_columns=None, on_created=None: on_created(
            FakePanel()
        ),
    )
    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    widget.update(state="PASS", delay=1)

    widget.show()  # default: keep old panels
    widget.show()
    assert len(created) == 2
    assert created[0].closed is False
    assert widget.syncer.panel_count() == 2

    widget.show(replace=True)  # closes the previous panel, shows a new one
    assert len(created) == 3
    assert created[1].closed is True
    assert created[2].closed is False
    assert widget.syncer.panel_count() == 2  # detached panel was removed

    widget.close()  # widget teardown closes the live panel too
    assert created[2].closed is True
    assert widget.syncer.panel_count() == 0


def test_frame_delay_parameter():
    """S3: frame_delay is validated and defaults to 0.05 s."""
    import viewviewview.core as core

    widget = ViewWidget()
    assert widget.syncer._frame_delay == 0.05
    widget.close()

    widget = ViewWidget(frame_delay=0.1)
    assert widget.syncer._frame_delay == 0.1
    widget.close()

    for bad in (0, -0.5, "x", True, float("nan")):
        with pytest.raises(ValueError):
            ViewWidget(frame_delay=bad)

    with pytest.raises(ValueError):
        core.Syncer(lambda: None, frame_delay=-1)


def test_syncer_pushes_to_panels(tmp_path):
    class Panel:
        payload = None

    widget = ViewWidget(csv_path=str(tmp_path / "a.csv"))
    panel = Panel()
    widget.syncer.attach(panel)
    widget.update(state="PASS", delay=1)
    widget.show()  # freezes the snapshot selection
    deadline = time.time() + 2.0
    while panel.payload is None and time.time() < deadline:
        widget.update(state="PASS", delay=2)
        time.sleep(0.03)
    assert panel.payload is not None
    assert panel.payload["total"] >= 1
    widget.close()
    assert widget.syncer.panel_count() == 0


def test_predefined_columns_mapping(tmp_path, monkeypatch):
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
        csv_path=str(tmp_path / "a.csv"),
        columns={
            "state": str,
            "delay": int,
            "pulse": float,
            "reply": str,
            "errcode": int,
        },
    )
    widget.show()  # declared columns must render before the first record
    payload = captured["payload"]
    assert [column["name"] for column in payload["columns"]] == [
        "state",
        "delay",
        "pulse",
        "reply",
        "errcode",
    ]
    assert [column["type"] for column in payload["columns"]] == [
        "str",
        "int",
        "float",
        "str",
        "int",
    ]
    assert payload["rows"] == []
    assert payload["state_key"] == "state"

    assert widget.update(state="PASS", delay=1, pulse=2.5, reply="ok", errcode=0) is True
    assert widget.update(state="PASS", delay=1.5) is False  # missing keys
    assert (
        widget.update(state="PASS", delay="1", pulse=2.5, reply="ok", errcode=0) is False
    )
    widget.close()
    assert read_all(tmp_path / "a.csv") == [
        ["state", "delay", "pulse", "reply", "errcode"],
        ["PASS", "1", "2.5", "ok", "0"],
    ]


def test_predefined_columns_sequence_infers_types(tmp_path):
    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"), columns=["state", "delay", "pulse"]
    )
    assert widget.update(state="PASS", delay=1, pulse=2.5) is True
    assert widget.update(state="PASS", delay=2.5) is False  # missing key
    assert widget.update(state="PASS", delay=3, pulse=4.5) is True
    assert widget.update(state="PASS", delay=3.2, pulse=4.5) is False  # int drift
    widget.close()


@pytest.mark.parametrize(
    "columns",
    [
        ["a", "a"],
        [],
        ["a", 1],
        {"a": bool},
        {"": int},
        {1: int},
        "abc",
        42,
    ],
)
def test_predefined_columns_validation(columns):
    with pytest.raises(ValueError):
        ViewWidget(columns=columns)


def test_predefined_columns_csv_header_mismatch(tmp_path):
    path = tmp_path / "a.csv"
    path.write_bytes(b"other,columns\r\nx,1\r\n")
    widget = ViewWidget(csv_path=str(path), columns={"state": str, "delay": int})
    with pytest.raises(ValueError, match="CSV header mismatch"):
        widget.update(state="PASS", delay=1)
    widget.close()


def test_predefined_columns_push_after_empty_show(tmp_path):
    class Panel:
        payload = None

    widget = ViewWidget(
        csv_path=str(tmp_path / "a.csv"), columns={"state": str, "delay": int}
    )
    panel = Panel()
    widget.syncer.attach(panel)
    widget.show()  # empty skeleton, then live records arrive
    widget.update(state="PASS", delay=1)
    deadline = time.time() + 2.0
    while (panel.payload is None or panel.payload["total"] < 2) and time.time() < deadline:
        widget.update(state="PASS", delay=2)
        time.sleep(0.03)
    assert panel.payload is not None
    assert panel.payload["total"] >= 2
    assert panel.payload["rows"][0][1] == 2
    widget.close()
