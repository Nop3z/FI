# 需求基线（2026-11-09，第 2 版，纯离线·自主逆向）

状态：已与用户两轮对齐后定稿。本文件是 FI 技术侧团队的唯一需求依据；与 `output/` 下交接文档冲突时，以本文件为准。
**修订要点（相对第 1 版）**：用户不提供任何内部资料、不提供任何硬件设备；唯一给定信息是 BootROM 基址 0x<BASE>。**自主逆向本身就是项目的核心研究点（探究 AI 在故障注入上的能力）。**

## 1. 定位与范围

- 通用 RISC-V 故障观测、异常捕获、上下文分析、指令级仿真**工具集**；由 AI 编程环境调度调用，CLI + JSON/JSONL 优先，不是 GUI 产品。
- 本团队（FI 技术侧）负责工具集全部技术能力；Web server 与 Dashboard 归另一团队，我们向其交付**数据契约**：字段定义、状态语义、证据分级、样例数据、变更说明。
- 泛化优先：芯片 Profile、Capture Provider、统一数据契约、可插拔仿真后端与注入编排。target-chip 只是首个验证样例，任何样例值禁止写进通用默认。
- **快速接入（TTS）为一等指标（2026-11-09 用户强调）**：项目价值 = 新 RISC-V 芯片从"只有固件 bin（+可选基址）"到"仿真跑起来"要足够快；target-chip-only 的成果只是 lab toy。一切人工分析步骤必须产品化为可复用工具（fi discover 自动管线），目标是下一颗芯片接入时间比 target-chip 基准低一个数量级。

## 2. 项目研究点（用户原话归纳）

用户掌握 target-chip 内部资料但**不会提供**："bootrom 这些错误码都是可以逆向出来的"。项目目的就是考察 AI 能否：
1. 仅凭 `<ROM_IMAGE>` + `<DATASET>.csv` + 基址 0x<BASE>，自主逆向出复位入口、ISA/核心配置、内存布局、CSR 语义（含 0x307）、错误码表与通信协议；
2. 跑通指令级仿真，并用仿真复现/解释 CSV 中 74 万次实验的观测结果；
3. 建成泛化工具集与闭环框架。

**纯离线**：不接任何实机设备（用户明确"什么设备都不会给"）。实机 Provider 只做接口预留，不排期。

## 3. 核心闭环（项目心脏）

给定 delay/pulse 参数窗口（单位 ns，例如 27000–38000ns）→ 注入 → 捕获响应/错误码/异常 → 分类分析（命中哪条指令、造成什么影响，结合仿真轨迹与芯片画像归因）→ 调整参数 → 收敛到稳定命中。

离线验证手段（当前唯一手段）：
- **CSV 重放**：把历史实验数据当作注入器输出回放给分析层；
- **仿真注入**：在指令级仿真器内做参数化故障注入（指定指令位置/时间点/数据翻转），观测输出差异，端到端验证归因与调参机制。

## 4. 里程碑序列

| 里程碑 | 内容 | 依赖 |
| --- | --- | --- |
| M0 | 团队搭建、repo 骨架、数据契约 v0.1 | 无（本轮） |
| M1 | 自主逆向 BootROM：复位入口、ISA/CSR（含 0x307）、内存布局、错误码表；跑通指令级仿真（越过 0x307 卡点，轨迹可复现可解释） | 仅 ROM + 基址 |
| M2 | 实验数据分析层：74 万行 CSV 分布事实、错误码 ↔ ROM 代码路径归因、命中窗口结构、候选评分接口 | M1 交叉验证 |
| M3 | 闭环编排框架离线验证：CSV 重放 + 仿真注入两类离线 Provider | M1/M2 |
| M4 | （远期，仅在用户明确给设备时）实机接入；契约正式交付 Web 团队随时可交 | 用户决定 |

## 5. 资产与事实基线

- `<ROM_IMAGE>`：target-chip BootROM，131072 字节，基址 0x<BASE>（用户确认，唯一给定信息），SHA-256 见 examples/rom-simulation/README.md。原始只读。
- `<DATASET>.csv`：740,209 行，列 `state,delay,pulse,response,glitched,unexpected`。FL 123450（response 全为 0x<CODE_A>）、HANG 12340（无响应）、SUCCESS 1234（unexpected=OK）、UNEXPECTED 1230（0x<CODE_B>/0x<CODE_C>/0x<CODE_D>/0x<CODE_F>/0x0001 等）、Fake_Success 6。状态标签语义需自主逆向归因；delay/pulse 单位 10ns 为工作假设（用户示例窗口 27000–38000ns 与数据 2640–3190 范围吻合）。原始只读。
- `examples/rom-simulation/trace.py`：基址=0 假设下跑到 0x84 的 CSR 0x307 写入即 UC_ERR_EXCEPTION（53 条指令）。未按 0x<BASE> 重验过。
- 设计蓝图：`总结故障注入文章 (1).html`（Chip Profile / CaptureProvider / 三层观测 / 基线对照 / 上下文关联）。

## 6. 用户给定的全部输入

1. `<ROM_IMAGE>`（只读样例）
2. `<DATASET>.csv`（只读样例）
3. BootROM 基址 0x<BASE>
4. 参考文章（设计蓝图）
5. 除此之外无任何资料与设备。公开资料（社区逆向、厂商公开文档）仅作旁证，必须标注来源与 confidence，不得作为主要证据。

## 7. 团队分工（persistent 专职制，需求直达负责人）

| 成员 | 职责范围（写权限） | 核心产出 |
| --- | --- | --- |
| `sim-engine` | fi/sim、examples、docs/sim | 可泛化仿真器（未知 CSR 按 WARL 记录+继续，严格模式可配）、target-chip 仿真跑通、轨迹 JSONL |
| `chip-profile` | fi/profiles、profiles、docs/profiles | Profile 格式+证据校验、target-chip.yaml（自主逆向填充）、错误码表 |
| `exp-analysis` | fi/analysis、data/derived、docs/analysis | CSV 分布事实、错误码↔代码路径归因、命中窗口结构、候选评分接口 |
| `core-contract` | fi 包根/schemas/providers/loop、pyproject、tests、docs/contracts | 契约 v0.1+、Provider/Injector/LoopStrategy 接口、CLI、Web 团队交付件 |
| lead | 协调、集成、需求、验收 | 本基线、任务分派、契约终审 |

## 8. 纪律

- 观测 / 假设 / 未知三级标注进 schema；候选路径不得写成已证实轨迹；缺失字段显式 `unknown`。
- 原始 ROM / CSV 只读，派生数据另存。
- 每个结论附可重放命令与来源引用。
- 逆向结论必须交叉验证：ROM 静态分析 ↔ 仿真行为 ↔ CSV 观测三方对上才可升 confidence。

## 9. 对 UI/Dashboard 团队的交付与同步（2026-11-09 用户新增要求）

- 交接文档：`output/故障注入工具集-Dashboard团队交接-v0.1.docx`（随契约演进升版）。
- 权威同步渠道：`docs/contracts/CHANGELOG.md`；任何字段/标签/Provider/文件类型变更必须记入，并由 lead 出《契约变更通报》简报经用户转发 UI 团队。
- **全体成员硬性要求：每份里程碑/功能交付报告必须含"Dashboard 影响"一节**（新增/变更字段、新数据文件类型、契约版本变化），lead 汇总进 CHANGELOG 与通报。
- 版本纪律：minor 只增字段；破坏性变更进 major 并附迁移说明；样例随契约同步更新。
