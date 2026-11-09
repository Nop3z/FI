# -*- coding: utf-8 -*-
"""`python -m fi.discover` 入口（等价于 `fi discover`）。

只做一次转发：discover 的子命令都注册在 `fi.cli.COMMANDS` 里（import 期副作用），
因此复用主 CLI 的 argparse 与退出码约定，避免两套参数解析漂移。
"""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
