"""停止原因分类。

两层结构（与 sim-trace 契约对齐）：
- exit_reason（coarse）：normal / exception / timeout / max_instructions / hang_suspected
- detail.kind（fine）：unsupported_csr / unsupported_insn / unmapped_mem_read|write|fetch /
  internal_error 等

分类本身是仿真器判断：分类依据（uc_error、last_insn、访问事件）随 run_end.detail
一并落盘，供人工复核。"hang_suspected" 按纪律用"疑似"命名，不得写成已证实死循环。
"""
from __future__ import annotations

from enum import Enum

import unicorn

EXIT_NORMAL = "normal"
EXIT_EXCEPTION = "exception"
EXIT_TIMEOUT = "timeout"
EXIT_MAX_INSTRUCTIONS = "max_instructions"
EXIT_HANG_SUSPECTED = "hang_suspected"

EXIT_REASONS = (EXIT_NORMAL, EXIT_EXCEPTION, EXIT_TIMEOUT, EXIT_MAX_INSTRUCTIONS, EXIT_HANG_SUSPECTED)

# UcError.errno → 内存访问类别
_MEM_ERRNOS = {
    "UC_ERR_READ_UNMAPPED": "read",
    "UC_ERR_WRITE_UNMAPPED": "write",
    "UC_ERR_FETCH_UNMAPPED": "fetch",
    "UC_ERR_READ_PROT": "read",
    "UC_ERR_WRITE_PROT": "write",
    "UC_ERR_FETCH_PROT": "fetch",
}


def _errno_name(errno: int) -> str | None:
    for name in dir(unicorn):
        if name.startswith("UC_ERR_") and getattr(unicorn, name) == errno:
            return name
    return None


def classify_uc_error(exc: unicorn.UcError, last_insn, unmapped_event: dict | None) -> tuple[str, str, dict]:
    """返回 (exit_reason, detail_kind, extra_detail)。"""
    errno_name = _errno_name(exc.errno) or f"UC_ERR_{exc.errno}"
    extra: dict = {"uc_error": {"errno": exc.errno, "name": errno_name, "message": str(exc)}}

    # 未映射访问
    if errno_name in _MEM_ERRNOS:
        kind = f"unmapped_mem_{_MEM_ERRNOS[errno_name]}"
        if unmapped_event:
            extra["unmapped_access"] = unmapped_event
        return EXIT_EXCEPTION, kind, extra

    # Unicorn RISC-V 对未实现 CSR 抛 UC_ERR_EXCEPTION；非法指令可能也是它
    if errno_name in ("UC_ERR_EXCEPTION", "UC_ERR_INSN_INVALID"):
        if last_insn is not None and last_insn.csr is not None:
            return (
                EXIT_EXCEPTION,
                "unsupported_csr",
                {
                    **extra,
                    "csr": f"0x{last_insn.csr:x}",
                    "csr_op": last_insn.csr_op,
                    "note": "unicorn 未实现该 CSR 访问（判定依据=异常紧跟该 CSR 指令，hypothesis 级）",
                },
            )
        return (
            EXIT_EXCEPTION,
            "unsupported_insn",
            {**extra, "note": "非 CSR 指令引发异常（或 last_insn 缺失）"},
        )

    return EXIT_EXCEPTION, "internal_error", extra
