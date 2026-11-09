"""疑似死循环启发式检测。

判定结果是【疑似】（hypothesis 级）：两种启发式
- hot_pc：单条 PC 执行次数超阈值（抓 `j .` 型）
- cycle：最近指令 PC 序列呈长度 ≤ max_cycle_len 的连续重复模式（抓一般循环）
阈值全部可配置；命中即停机并归类 suspected_infinite_loop，附证据。
"""
from __future__ import annotations

from collections import Counter, deque

from .config import LoopPolicy  # 统一从 config 取策略定义，避免两处定义分叉


class LoopDetector:
    def __init__(self, policy: LoopPolicy):
        self.policy = policy
        self.counts: Counter[int] = Counter()
        self.window: deque[int] = deque(maxlen=policy.cycle_window)
        self._since_scan = 0

    def on_insn(self, pc: int) -> dict | None:
        """每条指令调用；返回疑似循环报告 dict 或 None。"""
        self.counts[pc] += 1
        if self.counts[pc] >= self.policy.pc_count_threshold:
            return {"kind": "hot_pc", "pc": pc, "count": self.counts[pc]}
        self.window.append(pc)
        self._since_scan += 1
        if self._since_scan >= self.policy.check_interval:
            self._since_scan = 0
            return self._scan_cycle()
        return None

    def _scan_cycle(self) -> dict | None:
        pcs = list(self.window)
        n = len(pcs)
        if n < self.policy.min_cycle_streak:
            return None
        max_len = min(self.policy.max_cycle_len, n // self.policy.min_cycle_streak)
        for length in range(1, max_len + 1):
            block = pcs[n - length :]
            streak = 1
            while n - length * (streak + 1) >= 0 and pcs[n - length * (streak + 1) : n - length * streak] == block:
                streak += 1
            if streak >= self.policy.min_cycle_streak:
                return {
                    "kind": "cycle",
                    "cycle_len": length,
                    "streak": streak,
                    "cycle_pcs": [hex(p) for p in block],
                }
        return None
