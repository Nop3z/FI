"""M3 stress acceptance: throughput, ring boundedness and memory (ARCHITECTURE §6/M3)."""

from __future__ import annotations

import time
import tracemalloc

from viewviewview import ViewWidget

ROWS = 100_000


def percentile(samples, fraction):
    ordered = sorted(samples)
    index = min(len(ordered) - 1, int(len(ordered) * fraction))
    return ordered[index]


def test_100k_rows_throughput_and_latency(tmp_path):
    widget = ViewWidget(csv_path=str(tmp_path / "stress.csv"), flush_every=100)
    samples = []
    started = time.perf_counter()
    for index in range(ROWS):
        state = ("PASS", "FAIL", "TIMEOUT")[index % 3]
        begin = time.perf_counter()
        ok = widget.update(
            state=state, delay=index % 2000, pulse=float(index % 500), errcode=index % 16
        )
        samples.append(time.perf_counter() - begin)
        assert ok
    elapsed = time.perf_counter() - started
    p95 = percentile(samples, 0.95)
    widget.close()

    assert elapsed < 90.0, f"100k rows took {elapsed:.2f}s"
    assert p95 < 100e-6, f"update p95 is {p95 * 1e6:.1f}us (target <= 50us, CI guard 100us)"
    print(f"\n100k rows: {elapsed:.2f}s total, p95 {p95 * 1e6:.1f}us/row")


def test_bounded_memory_with_live_rows(tmp_path):
    tracemalloc.start()
    widget = ViewWidget(csv_path=str(tmp_path / "memory.csv"), live_rows=1000, flush_every=100)
    for index in range(50_000):
        widget.update(state="PASS", delay=index, pulse=float(index % 100), errcode=index % 8)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    widget.close()

    assert len(widget._ring) == 1000
    assert current < 40 * 1024 * 1024, f"current traced memory {current / 1e6:.1f} MB"
    assert peak < 40 * 1024 * 1024, f"peak traced memory {peak / 1e6:.1f} MB"
    print(f"\n50k rows, ring=1000: current {current / 1e6:.1f} MB, peak {peak / 1e6:.1f} MB")


def test_push_loop_memory_bounded(tmp_path):
    """S1 guard: sustained update+syncer pressure must not accumulate Python memory."""
    import threading

    class _Panel:
        payload = None

    widget = ViewWidget(
        csv_path=str(tmp_path / "push.csv"),
        live_rows=1000,
        flush_every=50,
        columns={"state": str, "delay": int},
    )
    panel = _Panel()
    widget.syncer.attach(panel)

    tracemalloc.start()
    threads_before = threading.active_count()
    deadline = time.perf_counter() + 2.0
    n = 0
    while time.perf_counter() < deadline:
        for _ in range(50):
            widget.update(state="PASS", delay=n)
            n += 1
        widget.syncer._refresh()  # simulate the timer firing at Syncer pace
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # The Syncer schedules one short-lived daemon Timer per frame; measure after
    # they had time to finish instead of asserting a live-thread snapshot.
    time.sleep(0.3)
    assert threading.active_count() <= threads_before + 1  # no thread accumulation
    assert current < 5 * 1024 * 1024, f"push loop leaked {current / 1e6:.2f} MB"
    widget.close()
    assert widget.syncer.panel_count() == 0
    print(f"\n{n} rows + {n // 50} pushes in 2s: traced {current / 1e6:.2f} MB")
