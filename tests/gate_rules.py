"""通用性门禁规则：实例值黑名单与扫描配置。

本文件是 tests/（共同资产）中的门禁配置，被 test_genericity_gate.py 消费。
规则与 chip-profile 的通用性审计（fi.profiles.loader.audit_generality，
lead 已裁定采纳）保持同源：token = SHA-256 / 长 hex / 大整数 / chip.id，
并按 lead 指示**豁免注释与文档字符串**（AST 扫描天然豁免注释，
docstring 由测试精确识别）。
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# 静态兜底黑名单：即使 profiles/ 目录暂无实例也要生效（防门禁空转）。
# 来源：target-chip 样例（基址/错误码/芯片 ID/CSV 原始状态标签）。
# 注意：区分大小写、整值精确匹配 —— 避免误伤 CSV 列名（如小写 unexpected）等。
# --------------------------------------------------------------------------
FORBIDDEN_STRINGS: frozenset[str] = frozenset(
    {
        "target-chip",
        "target-chip",
        "0x<BASE>",
        "0x<CODE_A>",
        "0x<CODE_B>",
        "0x<CODE_C>",
        "0x<CODE_D>",
        "0x<CODE_F>",
        "0xc140",
        "0x0001",
        "FL",
        "HANG",
        "SUCCESS",
        "UNEXPECTED",
        "Fake_Success",
    }
)

FORBIDDEN_INTS: frozenset[int] = frozenset(
    {
        <BASE_DEC>,  # 0x<BASE> target-chip BootROM 基址
        1281,       # 0x<CODE_A>
        260,        # 0x<CODE_B>
        1029,       # 0x<CODE_C>
        1284,       # 0x<CODE_D>
        49472,      # 0x<CODE_F>
    }
)

#: int 常量参与比对的阈值（与 audit_generality 的 abs(v) >= 0x10000 一致）。
INT_TOKEN_THRESHOLD = 0x10000

# --------------------------------------------------------------------------
# 通用架构惯例豁免（GENERIC_CONVENTION_TOKENS）
#
# 问题：动态 token 提取会把 profiles/*.yaml 里出现的**全部**长 hex 当作芯片
# 实例值。但有些数值同时是 **RISC-V 通用地址惯例**，通用代码（fi/discover）
# 用它们做分类启发式默认值是正当的，不是泄漏。
#
# 判定标准（三条同时满足才可加入本豁免集）：
#   1) 该值在 RISC-V 生态中是**公开通用惯例**（内存/外设地址规划），非某芯片特有；
#   2) 通用代码里它只作为**可被调用方覆盖的默认参数**出现（如 regions.py 的
#      DEFAULT_RAM_HINT_RANGES 注释明确写"不是芯片事实，仅用于分类启发式"）；
#   3) 该值**不是**任何已知样例芯片的身份标识（基址/指纹/错误码）。
#
# 维护纪律：本集合只增不减须报 lead；每项必须写明出处与理由。
# --------------------------------------------------------------------------
GENERIC_CONVENTION_TOKENS: frozenset[str] = frozenset(
    {
        # RISC-V 生态常见 DTIM/SRAM 起始地址（0x2000_0000 是 RV32 内存规划的
        # 事实惯例，见 fi/discover/regions.py DEFAULT_RAM_HINT_RANGES 的显式声明）。
        "0x20000000",
    }
)

#: 豁免 token → 理由（供审计与报告引用）。
GENERIC_CONVENTION_REASONS: dict[str, str] = {
    "0x20000000": "RISC-V 常见 DTIM/SRAM 惯例地址；fi/discover 仅作可覆盖的分类启发式默认值",
}

# --------------------------------------------------------------------------
# 白名单：修复责任人在途时的临时豁免；修复完成后移除（移除时在 PR 说明中引用本注释）。
# 历史：2026-11-09 exp-analysis 通用性修复期间挂过 analysis 包 7 文件，
# 当日修复完成收口，现白名单为空。新违规请勿直接加白名单——先与责任人确认
# 在途修复计划并报 lead。
# --------------------------------------------------------------------------
WHITELIST_FILES: dict[str, str] = {}
