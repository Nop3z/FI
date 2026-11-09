"""ProfileStore 接口契约（core-contract 维护；实现归 chip-profile 专职）。

边界约定（重要）：
- ChipProfile 内部格式（异常入口/寄存器保存/CSR/内存布局/证据管理）
  由 chip-profile 专职定义并版本化，本接口不复制其字段；
- 其他模块只经 profile_id 引用 Profile，读取细节用 load(profile_id)；
- Profile 内容的证据等级由 Profile 自身携带（其契约的一部分），
  本接口的 status 只反映存取层面的生命周期。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ProfileStore(ABC):
    """芯片画像存取接口。"""

    @abstractmethod
    def load(self, profile_id: str) -> dict[str, Any]:
        """按 ID 加载 Profile（内部格式归 chip-profile 契约）。
        不存在时抛 KeyError。"""

    @abstractmethod
    def validate(self, profile: dict[str, Any]) -> list[str]:
        """校验 Profile 完整性与证据链，返回问题列表（空 = 通过）。
        校验规则由 chip-profile 契约定义。"""

    @abstractmethod
    def index(self) -> dict[str, Any]:
        """导出 Profile 索引（chip-profile-index.schema.json 形状），
        供契约交付与 Web 团队消费。"""
