"""周期估算与时间映射（instructions → cycles → ns）。

为什么需要（docs/methodology-reverse-first.md 第 4 步"评估运行时间"）：
故障注入的 delay/pulse 是**物理时间参数（ns）**，而指令级仿真天然只有
"第几条指令"。要把 delay 从"盲扫窗口"变成"精确打某条指令"，必须先有
**指令 → 周期 → 时间**的映射。本模块提供该映射的显式、可配置、可审计实现。

## 三个必须分清的概念

1. **指令序号 seq**：仿真已执行指令条数（确定性，事实）。
2. **估算周期 cycles**：按本模块的代价表累加的**估算值**（hypothesis）。
3. **估算时间 ns**：`cycles × ns_per_cycle`，其中 `ns_per_cycle` 是**调用方
   显式给出的假设**（芯片主频 / 每周期纳秒数），本模块**绝不隐式猜测**；
   未提供时所有 ns 字段一律 `"unknown"`。

## 模型形态（v0：类级 CPI + 控制流惩罚）

`cycle_cost(insn) = base_cpi × class_weight[类别]`，另加：
- **taken 控制流惩罚**：分支/跳转的目标 ≠ 顺序下一条时，额外计
  `taken_control_penalty` 周期（流水线冲刷的粗模型）。
- 未识别助记符归 `unknown` 类并计数（报告里显式列出，不静默当 0）。

这是**刻意做粗的 v0**：目的不是精确复现某颗核的流水线，而是给出"某功能点
大致在第几百万周期/第几微秒执行"的量级，用它把 delay 窗口收窄到可搜索范围。
所以**每个默认值都标 hypothesis**，且报告里逐个列出取值与理由——任何使用者
都能看到"这个数字是默认假设，不是芯片实测"。

## 通用性纪律

本模块**不含任何芯片专有常量**（无主频、无 Flash 等待周期、无具体地址）。
默认值全部是"通用 RISC-V 教科书量级"的粗假设，经 `TimingPolicy` 可逐项覆盖；
新芯片接入时由 profile/配置提供实测或 datasheet 值，而不是改本文件。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

UNKNOWN = "unknown"
REPORT_SCHEMA = "fi.sim.time-report-v0"
MODEL_NAME = "fi.sim.timing/generic-cpi-v0"

# ---------------------------------------------------------------------------
# 指令分类（纯助记符规则，芯片无关）
# ---------------------------------------------------------------------------

#: 类别 → 默认权重（相对基础 CPI）。全部为通用粗假设（hypothesis）。
DEFAULT_CLASS_WEIGHTS: dict[str, float] = {
    "alu": 1.0,        # 寄存器/立即数运算、逻辑、移位
    "load": 1.4,       # 取数：命中假设下的平均代价（不含 cache miss，见 boundaries）
    "store": 1.2,
    "branch": 1.2,     # 分支本体；taken 另加惩罚
    "jump": 1.3,       # jal/jalr/jr/ret
    "mul": 1.5,        # 乘法（多周期，粗估）
    "div": 8.0,        # 除法（显著多周期，粗估）
    "csr": 1.5,        # CSR 读写（可能触发流水线串行化）
    "system": 2.0,     # ecall/ebreak/mret/wfi/fence
    "amo": 4.0,        # 原子操作
    "fp": 2.0,         # 浮点（若核无 FPU，本类出现即为异常信号）
    "unknown": 1.0,    # 未识别助记符
}

_ALU_PREFIXES = (
    "add", "sub", "and", "or", "xor", "sll", "srl", "sra", "slt", "lui",
    "auipc", "mv", "li", "not", "neg", "sext", "zext", "nop", "andi", "ori",
    "xori", "slli", "srli", "srai", "slti", "sltiu",
)
_LOAD_PREFIXES = ("lw", "lh", "lb", "ld", "lr.")
_STORE_PREFIXES = ("sw", "sh", "sb", "sd", "sc.")
_BRANCH_PREFIXES = ("beq", "bne", "blt", "bge", "bnez", "beqz", "blez", "bgez", "bgtz", "bltz")
_JUMP_MNEMONICS = {"jal", "jalr", "jr", "ret", "call", "j", "tail"}
_MUL_PREFIXES = ("mul", "macc", "madd")
_DIV_PREFIXES = ("div", "rem")
_CSR_PREFIXES = ("csrr", "csrw", "csrs", "csrc", "csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci")
_SYSTEM_MNEMONICS = {"ecall", "ebreak", "mret", "sret", "uret", "wfi", "fence", "fence.i", "sfence.vma", "ebreak"}
_AMO_PREFIXES = ("amo",)
_FP_PREFIXES = ("flw", "fsw", "fld", "fsd", "fmv", "fadd", "fsub", "fmul", "fdiv", "fsqrt", "fcvt", "fclass", "fmv.x", "fmv.w")


def insn_class(mnemonic: str) -> str:
    """助记符 → 代价类别。压缩前缀 `c.` 先剥离；无法分类归 `unknown`。"""
    m = (mnemonic or "").strip().lower()
    if not m:
        return "unknown"
    if m.startswith("c."):
        m = m[2:]
    # 压缩指令的类别与展开形式一致：先剥前缀后按同一规则判定
    if m.startswith(_FP_PREFIXES):
        return "fp"
    if m.startswith(_AMO_PREFIXES):
        return "amo"
    if m.startswith(_CSR_PREFIXES):
        return "csr"
    if m in _SYSTEM_MNEMONICS:
        return "system"
    if m.startswith(_MUL_PREFIXES):
        return "mul"
    if m.startswith(_DIV_PREFIXES):
        return "div"
    if m.startswith(_LOAD_PREFIXES):
        return "load"
    if m.startswith(_STORE_PREFIXES):
        return "store"
    if m.startswith(_BRANCH_PREFIXES):
        return "branch"
    if m in _JUMP_MNEMONICS:
        return "jump"
    if m.startswith(_ALU_PREFIXES):
        return "alu"
    # 压缩常用简写与汇总助记符
    if m in {"addi16sp", "addi4spn", "addi", "slli", "srli", "srai", "li", "mv", "nop", "j", "jr"}:
        return "alu"
    return "unknown"


# ---------------------------------------------------------------------------
# 策略（可配置；默认值全部为通用假设）
# ---------------------------------------------------------------------------


@dataclass
class TimingPolicy:
    """周期估算策略。所有字段均可由配置覆盖；默认值一律是通用粗假设。"""

    enabled: bool = True
    #: 基础 CPI（每条指令的基准周期数）。默认 1.0 = "单发射、无停顿"的教科书假设。
    base_cpi: float = 1.0
    #: 类别权重（乘在 base_cpi 上）；缺省类别按 1.0。
    class_weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_CLASS_WEIGHTS))
    #: taken 分支/跳转的额外周期（流水线冲刷粗模型）。0=完全不建模。
    taken_control_penalty: float = 2.0
    #: 每周期纳秒数（芯片主频倒数）。None = 不提供，所有 ns 输出 unknown。
    ns_per_cycle: float | None = None
    #: 按 PC 区间累计周期的区间大小（字节）。默认 256B。
    pc_bucket_size: int = 256
    #: 周期刻度标记间隔（周期，旧字段，保留兼容）
    cycle_mark_interval: int = 1000
    #: 每 PC 记录表的上限（防病态程序撑爆内存）；超出后停止登记新 PC 并在报告里标记。
    max_pc_records: int = 60000
    #: 周期刻度标记的指令间隔：每 N 条指令记一个 (cycles, seq) 锚点，供 ns 窗口反查。
    #: 越小越精确、内存越大；64 条指令在 40 万指令运行下约 6250 个锚点。
    mark_every_insns: int = 64
    #: 证据等级（模型整体）。自动产出恒 hypothesis。
    evidence_level: str = "hypothesis"
    #: 依据/来源说明（写进报告，便于审计）
    evidence_note: str = "通用 RISC-V 周期估算默认值，非芯片实测；逐项可由 timing 配置覆盖"

    def weight_of(self, cls: str) -> float:
        return float(self.class_weights.get(cls, 1.0))

    def assumptions(self) -> list[dict]:
        """把模型假设逐条摊开（报告用）：任何数字都能追溯到"这是假设"。"""
        rows = [
            {
                "field": "base_cpi",
                "value": self.base_cpi,
                "evidence_level": self.evidence_level,
                "note": "基础 CPI 假设：单发射、无停顿的理想核",
            },
            {
                "field": "taken_control_penalty",
                "value": self.taken_control_penalty,
                "evidence_level": self.evidence_level,
                "note": "taken 分支/跳转的流水线冲刷粗估；0 表示不建模控制冒险",
            },
        ]
        for cls in sorted(self.class_weights):
            rows.append(
                {
                    "field": f"class_weights.{cls}",
                    "value": self.class_weights[cls],
                    "evidence_level": self.evidence_level,
                    "note": "指令类平均周期权重（相对 base_cpi）",
                }
            )
        rows.append(
            {
                "field": "ns_per_cycle",
                "value": self.ns_per_cycle if self.ns_per_cycle is not None else UNKNOWN,
                "evidence_level": self.evidence_level if self.ns_per_cycle is not None else "unknown",
                "note": (
                    "每周期纳秒数（主频倒数）。必须由调用方显式给出；"
                    "未给出时所有 ns 字段输出 unknown（禁止隐式猜测）"
                ),
            }
        )
        return rows


# ---------------------------------------------------------------------------
# 估算器
# ---------------------------------------------------------------------------


class TimingModel:
    """逐指令累加估算周期，并按 PC/区间记录时间索引。

    调用时序（由 machine 层驱动）：每条指令执行**前**调用 `on_insn`，
    返回值为"该指令开始执行时的累计估算周期"（含此前所有指令的成本，
    以及上一条指令若为 taken 控制流的惩罚）。
    """

    def __init__(self, policy: TimingPolicy | None = None):
        self.policy = policy or TimingPolicy()
        self.cycles: float = 0.0
        self.instructions: int = 0
        self.class_counts: dict[str, int] = {}
        self.class_cycles: dict[str, float] = {}
        self.unknown_mnemonics: dict[str, int] = {}
        self.unknown_insns: int = 0

        self._prev: tuple[int, int, str, float] | None = None  # (pc, size, class, cost)
        self.taken_control_count: int = 0
        self.taken_penalty_cycles: float = 0.0

        #: pc → [first_cycle, first_seq, hits, total_cycles, last_cycle]
        self.pc_records: dict[int, list] = {}
        self.pc_records_truncated = False
        #: bucket_base → [insns, cycles]
        self.buckets: dict[int, list] = {}
        #: (cycle, seq) 刻度标记
        self.marks: list[tuple[float, int]] = []
        self._next_mark: float = 0.0

    # ---- 主入口 ----

    def on_insn(self, pc: int, size: int, mnemonic: str) -> float:
        """登记一条**即将执行**的指令；返回其起始时刻的累计周期估算。

        taken 控制流惩罚的判定方式：看到本条的 PC 与本条上一条（记录在 `_prev`）
        的 fallthrough 目标不一致时，判定上一条为 taken，此刻补记惩罚。
        """
        p = self.policy
        if self._prev is not None:
            prev_pc, prev_size, prev_cls, _prev_cost = self._prev
            if prev_cls in ("branch", "jump") and pc != prev_pc + prev_size:
                self.cycles += p.taken_control_penalty
                self.taken_control_count += 1
                self.taken_penalty_cycles += p.taken_control_penalty

        cls = insn_class(mnemonic)
        cost = p.base_cpi * p.weight_of(cls)
        cycle_now = self.cycles

        self.instructions += 1
        self.class_counts[cls] = self.class_counts.get(cls, 0) + 1
        self.class_cycles[cls] = self.class_cycles.get(cls, 0.0) + cost
        if cls == "unknown":
            self.unknown_insns += 1
            key = (mnemonic or "<empty>")[:32]
            self.unknown_mnemonics[key] = self.unknown_mnemonics.get(key, 0) + 1

        # PC 记录
        rec = self.pc_records.get(pc)
        if rec is None:
            if len(self.pc_records) < p.max_pc_records:
                self.pc_records[pc] = [cycle_now, self.instructions - 1, 1, cost, cycle_now]
            else:
                self.pc_records_truncated = True
        else:
            rec[2] += 1
            rec[3] += cost
            rec[4] = cycle_now

        # PC 区间累计
        base = pc - (pc % p.pc_bucket_size)
        b = self.buckets.get(base)
        if b is None:
            self.buckets[base] = [1, cost]
        else:
            b[0] += 1
            b[1] += cost

        # 周期刻度标记（供 ns 窗口反查指令区间）：
        # 按**指令条数**打点（不是按周期）——周期在密集循环里增长慢，按周期打点会让
        # 窗口边界间隔过大；按条数打点保证插值精度与运行长度无关。
        if self.instructions % max(1, p.mark_every_insns) == 0:
            self.marks.append((cycle_now, self.instructions - 1))

        # 控制流 taken 判定用的边沿信息
        self._prev = (pc, size, cls, cost)
        self.cycles += cost
        return cycle_now

    def observe_next_pc(self, next_pc: int | str) -> None:
        """预留：显式告知下一条 PC。当前 taken 判定在 on_insn 内自动完成，无需调用。"""
        return None

    # ---- 查询 ----

    def cycles_to_ns(self, cycles: float) -> float | str:
        if self.policy.ns_per_cycle is None:
            return UNKNOWN
        return cycles * self.policy.ns_per_cycle

    def _mark_cycle_of_seq(self, seq: int) -> float | None:
        """用刻度标记把指令序号反查为周期（线性插值；标记按 seq 单调）。"""
        if not self.marks:
            return None
        lo, hi = 0, len(self.marks) - 1
        if seq <= self.marks[0][1]:
            return self.marks[0][0]
        if seq >= self.marks[hi][1]:
            return self.marks[hi][0]
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if self.marks[mid][1] <= seq:
                lo = mid
            else:
                hi = mid
        (c0, s0), (c1, s1) = self.marks[lo], self.marks[hi]
        if s1 == s0:
            return c0
        return c0 + (c1 - c0) * (seq - s0) / (s1 - s0)

    def _interp_seq_at_cycle(self, cycle: float, fallback: int) -> int:
        """锚点 (cycle, seq) 序列上按周期线性插值出指令序号。

        锚点按 seq 单调、cycle 单调不减（周期不会倒退），二分定位。
        """
        marks = self.marks
        if len(marks) < 2:
            return fallback
        if cycle <= marks[0][0]:
            return marks[0][1]
        if cycle >= marks[-1][0]:
            return marks[-1][1]
        lo, hi = 0, len(marks) - 1
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if marks[mid][0] <= cycle:
                lo = mid
            else:
                hi = mid
        (c0, s0), (c1, s1) = marks[lo], marks[hi]
        if c1 == c0:
            return s1
        return int(round(s0 + (s1 - s0) * (cycle - c0) / (c1 - c0)))

    def seq_range_for_cycle_window(self, lo_cycle: float, hi_cycle: float) -> dict:
        """周期窗口 → 指令序号区间（边界用标记插值，标为 hypothesis）。"""
        if len(self.marks) < 2:
            return {
                "seq_first": 0 if lo_cycle <= 0 else UNKNOWN,
                "seq_last": self.instructions - 1 if hi_cycle >= self.cycles else UNKNOWN,
                "evidence_level": "unknown",
                "note": "周期刻度标记不足（运行太短或未启用时间模型），无法插值",
            }
        # 窗口整体落在本次运行之后：不假装覆盖，显式报告（这本身是重要观测）
        if lo_cycle >= self.cycles:
            return {
                "seq_first": UNKNOWN,
                "seq_last": UNKNOWN,
                "window_entirely_beyond_run_end": True,
                "window_beyond_run_end": True,
                "evidence_level": "hypothesis",
                "note": (
                    f"窗口整体落在本次运行结束之后：本次运行仅 {self.cycles:.0f} 周期"
                    f"（≈{self.cycles:.0f}×ns_per_cycle ns），窗口下界 {lo_cycle:.0f} 周期。"
                    "含义（hypothesis）：要么需要加大 --count 继续跑，要么说明周期模型/主频假设"
                    "偏低（真实硬件可能有 flash 等待、总线停顿等未建模周期）——后者应用已知时间点校准"
                ),
            }
        marks = self.marks
        lo_seq = marks[0][1]
        hi_seq = marks[-1][1]
        for c, s in marks:
            if c <= lo_cycle:
                lo_seq = s
            if c <= hi_cycle:
                hi_seq = s
            else:
                break
        # 用锚点做更精确的线性插值（锚点间距 = mark_every_insns 条指令）
        lo_seq = self._interp_seq_at_cycle(lo_cycle, lo_seq)
        if hi_cycle >= self.cycles:
            hi_seq = self.instructions - 1
        else:
            hi_seq = self._interp_seq_at_cycle(hi_cycle, hi_seq)
        hi_beyond = hi_cycle >= self.cycles
        notes = [
            f"由指令锚点（每 {self.policy.mark_every_insns} 条一个）线性插值得到；"
            f"边界误差量级=一个锚点间隔；全程 {self.cycles:.0f} 周期 / {self.instructions} 条指令",
        ]
        if hi_beyond:
            notes.append(
                f"窗口上界超出本次运行覆盖（总 {self.cycles:.0f} 周期）："
                f"seq_last 为本次运行末条指令，需加大 --count 才能覆盖整个窗口"
            )
        return {
            "seq_first": int(lo_seq),
            "seq_last": int(hi_seq),
            "insn_count_in_window": int(hi_seq - lo_seq + 1),
            "window_entirely_beyond_run_end": False,
            "window_beyond_run_end": bool(hi_beyond),
            "evidence_level": "hypothesis",
            "note": "；".join(notes),
        }

    def checkpoint(self, addr: int) -> dict:
        rec = self.pc_records.get(addr)
        if rec is None:
            return {
                "addr": addr,
                "addr_hex": f"0x{addr:08x}",
                "reached": False,
                "note": "本运行未执行该地址（不可达或代码路径未覆盖）",
            }
        first_cycle, first_seq, hits, total_cycles, last_cycle = rec
        return {
            "addr": addr,
            "addr_hex": f"0x{addr:08x}",
            "reached": True,
            "first_seq": first_seq,
            "first_cycle": round(first_cycle, 3),
            "first_ns": _round_or_unknown(self.cycles_to_ns(first_cycle)),
            "last_cycle": round(last_cycle, 3),
            "last_ns": _round_or_unknown(self.cycles_to_ns(last_cycle)),
            "hits": hits,
            "total_cycles_including_repeats": round(total_cycles, 3),
            "evidence_level": "hypothesis",
            "note": "周期为估算值；first_* 为该地址首次执行时刻",
        }

    def top_buckets(self, limit: int = 20) -> list[dict]:
        rows = [
            {
                "pc_range": f"0x{base:08x}-0x{base + self.policy.pc_bucket_size - 1:08x}",
                "base": base,
                "base_hex": f"0x{base:08x}",
                "instructions": v[0],
                "cycles": round(v[1], 3),
                "share_of_total_cycles": round(v[1] / self.cycles, 6) if self.cycles else 0.0,
            }
            for base, v in self.buckets.items()
        ]
        rows.sort(key=lambda r: -r["cycles"])
        return rows[:limit]

    # ---- 报告 ----

    def report(
        self,
        *,
        run_id: str = UNKNOWN,
        report_at: Iterable[int] = (),
        window_ns: tuple[float, float] | None = None,
    ) -> dict:
        p = self.policy
        ns_total = self.cycles_to_ns(self.cycles)
        out: dict[str, Any] = {
            "schema": REPORT_SCHEMA,
            "run_id": run_id,
            "model": {
                "name": MODEL_NAME,
                "version": "0.1.0",
                "evidence_level": p.evidence_level,
                "evidence_note": p.evidence_note,
                "assumptions": p.assumptions(),
                "class_counts": dict(sorted(self.class_counts.items())),
                "class_cycles": {k: round(v, 3) for k, v in sorted(self.class_cycles.items())},
                "taken_control_count": self.taken_control_count,
                "taken_penalty_cycles": round(self.taken_penalty_cycles, 3),
                "unknown_insns": self.unknown_insns,
                "unknown_mnemonics": dict(sorted(self.unknown_mnemonics.items(), key=lambda kv: -kv[1])[:20]),
            },
            "time_base": {
                "ns_per_cycle": p.ns_per_cycle if p.ns_per_cycle is not None else UNKNOWN,
                "evidence_level": p.evidence_level if p.ns_per_cycle is not None else "unknown",
                "note": (
                    "ns↔cycle 换算依赖调用方显式给出的 ns_per_cycle（芯片主频倒数假设）；"
                    "未给出则 ns 一律 unknown"
                ),
            },
            "totals": {
                "instructions": self.instructions,
                "cycles": round(self.cycles, 3),
                "ns": _round_or_unknown(ns_total),
                "cycles_per_insn": round(self.cycles / self.instructions, 4) if self.instructions else UNKNOWN,
                "evidence_level": p.evidence_level,
            },
            "checkpoints": [self.checkpoint(int(a)) for a in report_at],
            "top_pc_buckets": self.top_buckets(),
            "boundaries": [
                "周期为类级 CPI 粗估，不含 cache/flash 等待、总线仲裁、中断延迟、外设握手耗时",
                "taken 控制流惩罚是固定值粗模型，未区分分支预测器形态",
                "压缩指令按展开后的类别计价，未单独建模取指带宽",
                "仿真停机（hang_suspected/instruction_limit）时的累计周期只覆盖已执行指令",
            ],
            "pc_records_truncated": self.pc_records_truncated,
            "pc_records_count": len(self.pc_records),
            "confidence": p.evidence_level,
            "evidence_kind": "artifact_derived",
        }
        out["window_map"] = (
            self.window_map(window_ns[0], window_ns[1]) if window_ns is not None else UNKNOWN
        )
        return out

    def window_map(self, lo_ns: float, hi_ns: float) -> dict:
        """ns 窗口 → 该窗口内执行的指令区间与热点 PC（delay 调参的直接输入）。"""
        if self.policy.ns_per_cycle is None:
            return {
                "status": "unknown",
                "note": "未提供 ns_per_cycle 假设，无法把 ns 窗口折算为周期（禁止隐式换算）",
            }
        npc = self.policy.ns_per_cycle
        lo_cycle, hi_cycle = lo_ns / npc, hi_ns / npc
        rng = self.seq_range_for_cycle_window(lo_cycle, hi_cycle)
        # 窗口内热点 PC（按窗口内周期贡献粗排：用 PC 的 first/last 命中落在窗口内做筛选）
        in_window = []
        for pc, rec in self.pc_records.items():
            first_cycle, first_seq, hits, total_cycles, last_cycle = rec
            if last_cycle < lo_cycle or first_cycle > hi_cycle:
                continue
            in_window.append(
                {
                    "pc": pc,
                    "pc_hex": f"0x{pc:08x}",
                    "first_cycle": round(first_cycle, 3),
                    "first_ns": _round_or_unknown(first_cycle * npc),
                    "hits": hits,
                }
            )
        in_window.sort(key=lambda r: -r["hits"])
        return {
            "status": "ok",
            "window_ns": [lo_ns, hi_ns],
            "window_cycles": [round(lo_cycle, 3), round(hi_cycle, 3)],
            "ns_per_cycle": npc,
            "evidence_level": "hypothesis",
            "insn_range": rng,
            "hot_pcs": in_window[:40],
            "hot_pc_count": len(in_window),
            "note": (
                "窗口内指令区间可直接作为注入触发点候选：若 delay=窗口中点，"
                "则 trigger 应落在对应 seq/cycle；命中与否仍需试运行验证"
            ),
        }


def _round_or_unknown(value: float | str) -> float | str:
    return UNKNOWN if isinstance(value, str) else round(value, 3)


# ---------------------------------------------------------------------------
# 配置解析
# ---------------------------------------------------------------------------


def timing_policy_from_raw(raw: dict | None) -> TimingPolicy:
    """从配置 JSON 的 `timing` 节构造策略（宽松：缺省字段用默认假设）。"""
    raw = raw or {}
    weights = dict(DEFAULT_CLASS_WEIGHTS)
    for k, v in (raw.get("class_weights") or {}).items():
        weights[str(k)] = float(v)
    npc = raw.get("ns_per_cycle")
    return TimingPolicy(
        enabled=bool(raw.get("enabled", True)),
        base_cpi=float(raw.get("base_cpi", TimingPolicy.base_cpi)),
        class_weights=weights,
        taken_control_penalty=float(
            raw.get("taken_control_penalty", TimingPolicy.taken_control_penalty)
        ),
        ns_per_cycle=float(npc) if npc is not None else None,
        pc_bucket_size=int(raw.get("pc_bucket_size", TimingPolicy.pc_bucket_size)),
        cycle_mark_interval=int(raw.get("cycle_mark_interval", TimingPolicy.cycle_mark_interval)),
        mark_every_insns=int(raw.get("mark_every_insns", TimingPolicy.mark_every_insns)),
        max_pc_records=int(raw.get("max_pc_records", TimingPolicy.max_pc_records)),
        evidence_level=str(raw.get("evidence_level", TimingPolicy.evidence_level)),
        evidence_note=str(raw.get("evidence_note", TimingPolicy.evidence_note)),
    )
