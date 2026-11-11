"""M1 acceptance smoke test for the ViewViewView core recorder.

Standard library only. Run from anywhere:

    python scripts/smoke_core.py

Exits non-zero when any contract check fails.
"""

from __future__ import annotations

import csv
import logging
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import viewviewview  # noqa: E402

# The package initializer sets INFO; raise it after import to hide expected
# contract rejections (they are asserted below, not read by humans).
logging.getLogger("viewviewview").setLevel(logging.CRITICAL)
from viewviewview.core import _TailReader  # noqa: E402

RESULTS = []


def check(name, func):
    try:
        detail = func()
    except Exception as exc:  # noqa: BLE001 - report and continue
        RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        return
    RESULTS.append((name, True, "" if detail is None else str(detail)))


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def make_widget(path, **kwargs):
    return viewviewview.ViewWidget(csv_path=str(path), **kwargs)


def test_update_performance(tmp):
    path = tmp / "perf.csv"
    widget = make_widget(path, flush_every=100)
    start = time.perf_counter()
    for index in range(1000):
        state = ("PASS", "FAIL", "TIMEOUT")[index % 3]
        ok = widget.update(
            state=state, delay=100 + index % 1900, pulse=10 + index % 40, errcode=index % 8
        )
        expect(ok, "update returned False")
    elapsed = time.perf_counter() - start
    widget.close()
    expect(elapsed < 1.0, f"1000 updates took {elapsed:.3f}s (limit 1s)")
    return f"{elapsed * 1000:.1f} ms for 1000 rows"


def test_csv_round_trip(tmp):
    path = tmp / "roundtrip.csv"
    widget = make_widget(path)
    expected = []
    for index in range(200):
        state = ("PASS", "FAIL", "TIMEOUT")[index % 3]
        widget.update(state=state, delay=index, pulse=float(index) / 2.0, reply="ok")
        expected.append([state, str(index), str(float(index) / 2.0), "ok"])
    widget.close()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        rows = list(reader)
    expect(header == ["state", "delay", "pulse", "reply"], f"bad header {header}")
    expect(rows == expected, "CSV rows differ from the recorded sequence")
    return f"{len(rows)} rows, header ok"


def test_counts(tmp):
    path = tmp / "counts.csv"
    widget = make_widget(path)
    expected = {"PASS": 0, "FAIL": 0, "TIMEOUT": 0}
    for index in range(300):
        state = ("PASS", "FAIL", "TIMEOUT")[index % 3]
        expected[state] += 1
        widget.update(state=state, delay=index)
    expect(widget.rows_written == 300, "rows_written mismatch")
    expect(widget._counts["state"] == expected, f"counts mismatch {widget._counts['state']}")
    expect(widget.csv_path == str(path), "csv_path property mismatch")
    widget.close()
    return str(expected)


def test_schema_matrix(tmp):
    path = tmp / "schema.csv"
    widget = make_widget(path)

    expect(widget.update() is False, "empty kwargs must return False")
    expect(widget.update(state="PASS", delay=1, flag=True) is False, "bool must be rejected")
    expect(widget.update(state="PASS", delay=1.5) is True, "first valid row must be accepted")
    expect(widget.update(state="PASS", delay=2) is False, "type drift must return False")
    expect(widget.update(state="FAIL", delay=3, extra=1) is False, "extra key must return False")
    expect(widget.update(state="FAIL", reply="ok") is False, "missing key must return False")
    # Key insertion order is irrelevant (FaultViz parity); values follow schema order.
    expect(widget.update(delay=4.0, state="PASS") is True, "reordered keys must be accepted")
    expect(widget.rows_written == 2, "rejected rows must not count")
    widget.close()
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    expect(rows[1] == ["PASS", "1.5"], f"schema order broken: {rows[1]}")
    expect(rows[2] == ["PASS", "4.0"], f"schema order broken: {rows[2]}")
    return "type/keys semantics ok"


def test_constructor_validation(tmp):
    cases = [
        (dict(display_limit=-1), "limit must be a non-negative integer or None"),
        (dict(live_rows="x"), "limit must be a non-negative integer or None"),
        (dict(flush_every=0), "flush_every must be a positive integer"),
        (dict(fsync="yes"), "fsync must be a bool"),
    ]
    for kwargs, message in cases:
        try:
            viewviewview.ViewWidget(**kwargs)
        except ValueError as exc:
            expect(str(exc) == message, f"unexpected message: {exc}")
        else:
            raise AssertionError(f"missing ValueError for {kwargs}")
    return "ValueError messages match"


def test_header_mismatch(tmp):
    path = tmp / "mismatch.csv"
    path.write_text("other,columns\r\nx,1\r\n", encoding="utf-8")
    widget = make_widget(path)
    try:
        widget.update(state="PASS", delay=1)
    except ValueError as exc:
        expect("CSV header mismatch" in str(exc), f"unexpected message: {exc}")
    else:
        raise AssertionError("header mismatch did not raise")
    widget.close()
    return "raised ValueError"


def test_unfinished_record(tmp):
    path = tmp / "unfinished.csv"
    path.write_text("state,delay\r\nPASS,1", encoding="utf-8")
    widget = make_widget(path)
    try:
        widget.update(state="PASS", delay=1)
    except ValueError as exc:
        expect("unfinished last record" in str(exc), f"unexpected message: {exc}")
    else:
        raise AssertionError("unfinished record did not raise")
    widget.close()
    return "raised ValueError"


def test_empty_existing_file(tmp):
    path = tmp / "empty.csv"
    path.write_bytes(b"")
    widget = make_widget(path)
    expect(widget.update(state="PASS", delay=1) is True, "empty existing file must be usable")
    widget.close()
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    expect(rows == [["state", "delay"], ["PASS", "1"]], f"unexpected rows {rows}")
    return "header written once"


def test_csv_io_failure(tmp):
    widget = make_widget(tmp)  # a directory path cannot be opened for append
    try:
        widget.update(state="PASS", delay=1)
    except OSError:
        pass
    else:
        raise AssertionError("I/O failure did not raise")
    try:
        widget.update(state="PASS", delay=2)
    except RuntimeError as exc:
        expect("CSV recording previously failed" in str(exc), f"unexpected message: {exc}")
    else:
        raise AssertionError("post-failure update did not raise RuntimeError")
    return "fatal state latched"


def test_tail_reader(tmp):
    path = tmp / "tail.csv"
    path.write_bytes(b"a,b\r\n1,2\r\n3,4\r\n5,6\r\n")
    header, rows = _TailReader(str(path)).read(2)
    expect(header == ["a", "b"], "tail header mismatch")
    expect(rows == [["3", "4"], ["5", "6"]], f"tail rows mismatch {rows}")
    malformed = tmp / "malformed.csv"
    malformed.write_bytes(b"a,b\r\n1,2\r\n3\r\n")
    try:
        _TailReader(str(malformed)).read(None)
    except ValueError as exc:
        expect("Malformed CSV record 2" in str(exc), f"unexpected message: {exc}")
    else:
        raise AssertionError("malformed CSV did not raise")
    return "tail window + malformed detection ok"


def test_threads(tmp):
    path = tmp / "threads.csv"
    widget = make_widget(path)
    errors = []

    def worker(worker_id):
        try:
            for index in range(200):
                if not widget.update(state="PASS", seq=worker_id * 1000 + index):
                    errors.append("update returned False")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(worker_id,)) for worker_id in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    expect(not errors, f"worker errors: {errors[:3]}")
    expect(widget.rows_written == 1600, f"rows_written {widget.rows_written}")
    widget.close()
    with path.open("r", encoding="utf-8", newline="") as handle:
        lines = sum(1 for _ in handle)
    expect(lines == 1601, f"CSV lines {lines}")
    return "8 threads x 200 rows ok"


def test_compat_noop(tmp):
    viewviewview.start_view_service()
    viewviewview.start_view_service(port=99999, max_heap=None)
    viewviewview.start_view_service(port="bad", max_heap=123)  # must never raise
    expect(callable(viewviewview.csvview), "csvview missing")
    expect(callable(viewviewview.csvplot), "csvplot missing")
    return "no-op + exports ok"


def test_csv_only(tmp):
    path = tmp / "csvonly.csv"
    widget = make_widget(path, live_rows=0)
    for index in range(50):
        widget.update(state="PASS", delay=index)
    widget.close()
    expect(widget.rows_written == 50, "csv-only rows_written")
    return "live_rows=0 records without panels"


def test_predefined_columns(tmp):
    path = tmp / "columns.csv"
    widget = make_widget(path, columns={"state": str, "delay": int, "reply": str})
    expect(widget.update(state="PASS", delay=1, reply="ok") is True, "first row rejected")
    expect(widget.update(state="PASS", delay="x", reply="ok") is False, "type drift accepted")
    widget.close()
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    expect(rows[0] == ["state", "delay", "reply"], f"header {rows[0]}")
    expect(rows[1] == ["PASS", "1", "ok"], f"row {rows[1]}")
    return "columns= mapping predefines schema"


def test_start_time_filename(tmp):
    import os
    import re

    previous = os.getcwd()
    os.chdir(tmp)
    try:
        widget = viewviewview.ViewWidget()
        name = os.path.basename(widget.csv_path or "")
        expect(bool(re.fullmatch(r"\d{8}-\d{6}(-\d+)?\.csv", name)), f"name {name}")
        expect(not os.path.exists(widget.csv_path), "file must be created on first write")
        widget.update(state="PASS", delay=1)
        expect(os.path.exists(widget.csv_path), "CSV missing after first write")
        widget.close()
    finally:
        os.chdir(previous)
    return "default name = widget start time"


def main():
    with tempfile.TemporaryDirectory(prefix="vvv-smoke-") as directory:
        tmp = Path(directory)
        check("1 update() 1000 rows < 1s", lambda: test_update_performance(tmp))
        check("2 CSV round-trip", lambda: test_csv_round_trip(tmp))
        check("3 counts / rows_written / csv_path", lambda: test_counts(tmp))
        check("4 schema semantics matrix", lambda: test_schema_matrix(tmp))
        check("5 constructor validation", lambda: test_constructor_validation(tmp))
        check("6 header mismatch", lambda: test_header_mismatch(tmp))
        check("7 unfinished last record", lambda: test_unfinished_record(tmp))
        check("8 empty existing file", lambda: test_empty_existing_file(tmp))
        check("9 CSV I/O failure latching", lambda: test_csv_io_failure(tmp))
        check("10 tail reader", lambda: test_tail_reader(tmp))
        check("11 thread safety", lambda: test_threads(tmp))
        check("12 compat no-op exports", lambda: test_compat_noop(tmp))
        check("13 csv-only mode", lambda: test_csv_only(tmp))
        check("14 predefined columns", lambda: test_predefined_columns(tmp))
        check("15 start-time default filename", lambda: test_start_time_filename(tmp))

    failures = [item for item in RESULTS if not item[1]]
    for name, ok, detail in RESULTS:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    print(f"\n{len(RESULTS) - len(failures)}/{len(RESULTS)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
