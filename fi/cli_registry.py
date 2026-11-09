"""CLI 子命令注册表（单一事实来源，供 fi.cli 与各成员子命令包共用）。

**为什么要独立成模块**（踩过的坑）：注册表若定义在 ``fi.cli`` 里，则
``python -m fi.cli`` 会把该文件当作 ``__main__`` 执行，而成员子命令包里的
``from fi.cli import command`` 又会**再导入一份** ``fi.cli`` 模块 —— 两份
``COMMANDS`` dict 互不相干，注册进了"影子副本"，主入口永远看不到。
把注册表移到独立模块后，无论入口是 ``fi`` 控制台脚本、``python -m fi``
还是 ``python -m fi.cli``，``command()`` 与 ``main()`` 操作的都是同一个对象。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

#: 子命令 handler 签名：接收 argparse.Namespace，返回退出码。
Handler = Callable[[object], int]


@dataclass(frozen=True)
class CommandSpec:
    """一条 CLI 命令的登记项。"""

    group: str
    name: str
    handler: Handler
    help: str


#: 注册表：{(组名, 命令名): CommandSpec}
COMMANDS: dict[tuple[str, str], CommandSpec] = {}


def command(group: str, name: str, help: str) -> Callable[[Handler], Handler]:
    """子命令注册装饰器。

    用法::

        from fi.cli import command

        @command("组名", "命令名", "帮助文本")
        def handler(args) -> int: ...

    专属参数用 ``handler.configure_args(parser)`` 钩子添加。
    """

    def deco(fn: Handler) -> Handler:
        COMMANDS[(group, name)] = CommandSpec(
            group=group, name=name, handler=fn, help=help
        )
        return fn

    return deco
