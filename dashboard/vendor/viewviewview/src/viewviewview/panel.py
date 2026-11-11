"""Dual-pane live widget for ViewViewView payloads (ARCHITECTURE.md §4.2).

This module holds zero business logic: it declares the anywidget traits and
ships the bundled ESM/CSS assets that render the §4.3 payload snapshot.  The
module stays importable even when ``anywidget`` is missing; in that case
``VvvPanel`` instantiation raises :class:`ImportError` so upstream lazy
exports keep working (§3.5).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).resolve().parent / "static"

try:  # optional dependency guard at the import boundary (contract §4.2)
    import anywidget
    import traitlets as T

    _ANYWIDGET_AVAILABLE = True
    _IMPORT_ERROR: BaseException | None = None
except ImportError as _exc:  # pragma: no cover - environment dependent
    anywidget = None  # type: ignore[assignment]
    T = None  # type: ignore[assignment]
    _ANYWIDGET_AVAILABLE = False
    _IMPORT_ERROR = _exc


def _read_static_asset(name: str) -> str:
    """Return the text of a bundled static asset, or ``""`` when unreadable.

    A missing or moved asset must never break the package import; the missing
    content is logged and left empty so anywidget shows its built-in error view.
    """
    try:
        return (_STATIC_DIR / name).read_text(encoding="utf-8")
    except OSError as exc:  # boundary-level: must log (coding rule §7)
        logger.warning("viewviewview static asset %s is unreadable: %s", name, exc)
        return ""


_ESM = _read_static_asset("index.mjs")
_CSS = _read_static_asset("styles.css")

__all__ = ["VvvPanel"]

if _ANYWIDGET_AVAILABLE:

    class VvvPanel(anywidget.AnyWidget):
        """Live dual-pane widget rendering one payload snapshot.

        Traits
        ------
        payload:
            ``{columns, state_key, counts, rows, total, window, version}``
            snapshot assigned by the core ``Syncer`` (§4.3); rendered as-is.
        theme:
            Palette selector, ``"dark"`` by default (decision D5).
        colors:
            Optional palette overrides (API key -> hex string) applied as CSS
            custom properties by the frontend (decision D13).
        """

        _esm = _ESM
        _css = _CSS

        payload = T.Dict(default_value={}).tag(sync=True)
        theme = T.Unicode("dark").tag(sync=True)
        colors = T.Dict(default_value={}).tag(sync=True)
        number_columns = T.List(
            T.Unicode(), default_value=["delay", "pulse"]
        ).tag(sync=True)
else:

    class VvvPanel:  # type: ignore[no-redef]
        """``anywidget``-free placeholder; instantiation must fail fast (§4.2)."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "viewviewview.panel requires the optional dependency 'anywidget'; "
                "install anywidget to enable live dual-pane rendering"
            ) from _IMPORT_ERROR
