"""FaultViz-compatible module-level helpers (ARCHITECTURE.md Section 3.3/3.4).

``start_view_service`` is a compatibility no-op: ViewViewView renders locally
and never needs a JVM or a background server. ``csvview``/``csvplot`` open an
already recorded CSV and feed the same dual-pane frontend as live widgets, so
historical experiments are browsable at any time without any service running.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any, Dict, List, Optional, Tuple

from .core import (
    _DEFAULT_NUMBER_COLUMNS,
    _TailReader,
    _validate_limit,
    render_payload,
)

__all__ = ["start_view_service", "csvview", "csvplot"]

_LOGGER = logging.getLogger("viewviewview")


def start_view_service(port: int = 12345, max_heap: Optional[str] = "2g") -> None:
    """FaultViz compatibility no-op: no JVM or background service is required.

    Kept with the original signature so existing experiment scripts keep
    working unchanged. Invalid arguments are only noted at DEBUG level; this
    function must never raise (contract Section 3.1).
    """
    if type(port) is not int or port < 0:
        _LOGGER.debug("Ignoring invalid port %r; no local service is started", port)
    if max_heap is not None and type(max_heap) is not str:
        _LOGGER.debug("Ignoring invalid max_heap %r; no JVM heap is allocated", max_heap)
    _LOGGER.info("Deephaven service not required; live rendering is local")


def _read_csv_window(
    path: str, limit: Optional[int], full: bool
) -> Tuple[List[str], List[List[str]]]:
    """Read the whole CSV or an O(limit) tail window, in file order (3.3)."""
    if full or limit is None:
        return _TailReader(path, _LOGGER).read(None)
    return _TailReader(path, _LOGGER).read(limit)


def _infer_column_type(values: List[str]) -> str:
    """Best-effort column type for alignment; displayed text stays untouched."""
    has_value = False
    all_int = True
    for value in values:
        if value == "":
            continue
        has_value = True
        try:
            int(value)
        except ValueError:
            all_int = False
            try:
                float(value)
            except ValueError:
                return "str"
    if not has_value:
        return "str"
    return "int" if all_int else "float"


def _build_payload(
    header: List[str], rows: List[List[str]], state: str
) -> Dict[str, Any]:
    """Build the frozen Section 4.3 payload from a CSV window."""
    columns = [
        {"name": name, "type": _infer_column_type([row[index] for row in rows])}
        for index, name in enumerate(header)
    ]
    state_key: Optional[str] = None
    counts: Dict[str, int] = {}
    if state in header:
        state_key = state
        state_index = header.index(state)
        for row in rows:
            bucket = str(row[state_index])
            counts[bucket] = counts.get(bucket, 0) + 1
    newest_first = [list(row) for row in reversed(rows)]
    return {
        "columns": columns,
        "state_key": state_key,
        "counts": counts,
        "rows": newest_first,
        "total": len(rows),
        "window": len(newest_first),
        "version": 0,
    }


def csvview(
    csv: str, state: str = "state", limit: Optional[int] = None, full: bool = False
) -> None:
    """Open a recorded CSV as the dual-pane view (contract Section 3.3).

    ``limit=None`` or ``full=True`` loads the whole history; a positive limit
    loads the newest window with O(limit) memory. ``limit=0`` disables the
    table rendering and only reports where the records remain.
    """
    _validate_limit(limit)
    if not full and limit == 0:
        _LOGGER.info("CSV display disabled; records remain in %s", csv)
        return
    header, rows = _read_csv_window(csv, limit, full)
    if not rows:
        _LOGGER.info("No data recorded in %s", csv)
        return
    render_payload(
        _build_payload(header, rows, state),
        number_columns=list(_DEFAULT_NUMBER_COLUMNS),
    )


def csvplot(name: str, limit: Optional[int] = None, full: bool = False) -> None:
    """Plot a recorded CSV via pygwalker; degrade to the table view if absent.

    Never raises for a plot-related problem: when pygwalker/pandas are missing
    the dual-pane table view is shown instead (contract Section 3.4).
    """
    _validate_limit(limit)
    if not full and limit == 0:
        _LOGGER.info("CSV plot disabled; records remain in %s", name)
        return
    try:
        import pandas as pd
        import pygwalker as pyg
    except ImportError:
        _LOGGER.error(
            "pygwalker is not installed; install viewviewview[plot]; "
            "showing the table view instead"
        )
        csvview(name, limit=limit, full=full)
        return
    if full or limit is None:
        frame = pd.read_csv(name)
        if frame.empty:
            _LOGGER.info("No data recorded in %s", name)
            return
    else:
        header, rows = _TailReader(name, _LOGGER).read(limit)
        if not rows:
            _LOGGER.info("No data recorded in %s", name)
            return
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)
        frame = pd.read_csv(io.StringIO(stream.getvalue()))
    try:
        # FaultViz parity: newest records are plotted first.
        pyg.walk(frame.iloc[::-1])
    except Exception:  # noqa: BLE001 - plot boundary must never raise
        _LOGGER.debug("pygwalker walk failed", exc_info=True)
