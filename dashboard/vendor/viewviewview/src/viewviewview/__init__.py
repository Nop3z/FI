"""ViewViewView package entry point.

Exposes the public facade described in the architecture contract (Section 3).
Heavy submodules are imported lazily via PEP 562 ``__getattr__`` so that the
package import stays cheap and optional peers (e.g. the panel/anywidget
frontend) may be absent without breaking ``import viewviewview``.
"""

from __future__ import annotations

import importlib
import logging

__version__ = "0.6.0"

__all__ = [
    "ViewWidget",
    "ViewViewView",
    "VvvPanel",
    "__version__",
    "csvplot",
    "csvview",
    "start_view_service",
]

_LOGGER_NAME = "viewviewview"
_LOGGER_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def _configure_logger() -> logging.Logger:
    """Create the package logger with a single console handler.

    The handler is only added once so that module reloads or repeated imports
    never stack duplicate console output. Propagation is left at the default
    (True) so capturers such as ``pytest``'s ``caplog`` still observe records
    emitted through the root logger.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(_LOGGER_FORMAT))
        logger.addHandler(handler)
    return logger


_logger = _configure_logger()

_LAZY_EXPORTS = {
    "ViewWidget": ("viewviewview.core", "ViewWidget"),
    # Compatibility alias (contract Section 3.5).
    "ViewViewView": ("viewviewview.core", "ViewWidget"),
    "start_view_service": ("viewviewview.compat", "start_view_service"),
    "csvview": ("viewviewview.compat", "csvview"),
    "csvplot": ("viewviewview.compat", "csvplot"),
    # Panel is owned by the display engineer and may be incomplete or absent
    # during mid-milestone states; the lazy lookup keeps that survivable.
    "VvvPanel": ("viewviewview.panel", "VvvPanel"),
}


def __getattr__(name: str):  # noqa: ANN201 - PEP 562 hook returns Any
    """Resolve lazily exported names on first access (PEP 562)."""
    try:
        module_name, attribute_name = _LAZY_EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    module = importlib.import_module(module_name)
    try:
        value = getattr(module, attribute_name)
    except AttributeError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    globals()[name] = value
    return value


def __dir__() -> "list[str]":
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
