"""芯片画像（接口层）。

实现归 chip-profile 专职；本包由 core-contract 维护接口契约
（fi/profiles/protocol.py）。Profile 内部格式以其交付为准；
跨契约引用方式见 docs/contracts/schemas/chip-profile-index.schema.json
（profile_id + index_path + format_version 三元组）。
"""

from fi.profiles.protocol import ProfileStore

__all__ = ["ProfileStore"]
