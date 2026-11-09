# TTS 基线：从困扰到指标（2026-11-09 用户纠偏后建立）

用户原话要点：**"我们做的项目不是只给 target-chip 的……这样只是一个 Lab toys 根本没有用。我们想做的是通用的框架，riscv 的芯片都适用，这样每次仿真都能快速实现。包括现在在做的 target-chip 用了多少时间去仿真啊，要尽可能快速。"**

本文件是 TTS（Time-To-Simulate，新芯片从"只有固件 bin"到"仿真跑起来并产出可信轨迹"）的度量基线与产品化清单。**它比任何单个芯片的逆向结论都重要：逆向结论会过期，管线不会。**

## 1. target-chip 实测账（诚实记账，非自我表扬）

冷启动：2026-11-09 14:33（团队启动）→ 16:13（首个错误帧真实字节产出）。总计约 **1 小时 40 分**。

| 里程碑 | 时刻 | 启动后 | 产物 |
| --- | --- | --- | --- |
| 0x<BASE> 基址首次运行 | 15:07 | 34 min | 2048 指令即 hang，RO M 只有页 |
| UART 首次打出 boot 文本 | 15:28 | 55 min | boot.log 337 B（占位污染） |
| trap 链复现（Trap_Handler 打印） | 15:40 | 67 min | trap-loop-v3，12302 指令 |
| 首个错误帧真实字节 | 16:13 | 100 min | v13c：`46 4C 01 05`（"FL"+0x<CODE_A>） |

分项归因（按人工投入估）：

| 环节 | 耗时占比 | 是否可自动化 |
| --- | --- | --- |
| 手工逆向（mtvec/handler/帧/错误码） | ~45% | **高**：常量扫描、向量识别、trap 模式识别可脚本化 |
| 手工建模外设/RAM 区域（逐个 stub、反复起跑） | ~30% | **高**：地址常量扫描→自动生成 region 候选→自动试跑收敛 |
| 反复调参重跑（v1→v13c 共 13 轮迭代） | ~15% | **中高**：可自动化的"起跑→看停止原因→补模型"循环 |
| 契约/文档/校验 | ~10% | 已自动化（门禁/契约校验） |

## 2. 性能账（当前实现的问题，比时间更严重）

| 运行 | 指令数 | exit | 轨迹体积 |
| --- | --- | --- | --- |
| target-chip-target-hijack-v13c | 573 | exception | 0.2 MB |
| target-chip-trap-loop-v3 | 12,302 | hang_suspected | 3.2 MB |
| target-chip-poll-chain-v8 | 400,000 | max_instructions | **100.2 MB** |
| target-chip-sec-ready-v9 | 400,000 | max_instructions | **100.2 MB** |

问题：**每指令全字段落 JSONL，体积 ≈ 262 B/指令**。40 万指令=100MB，74 万次实验的历史规模下不可接受；且为调试而生的全量轨迹与"日常扫描跑得动"是矛盾需求。

## 3. TTS 指标定义（今后所有新芯片按此度量）

- **TTS-A（自动接入）**：输入 `bin + base(可缺省)` → 输出可运行仿真配置 + Profile 草稿 + 首条轨迹。目标：**≤ 30 分钟自动化**（target-chip 基准 100 分钟人工，目标低一个数量级）。
- **TTS-B（可信跑通）**：到"轨迹过 sim-trace 契约 + 停止原因分类明确 + 无静默伪造"。
- **吞吐指标**：≥ 1 M instr/s 仿真；轨迹体积 ≤ 8 B/指令（采样/二进制模式）；单次扫描（1 万参数点规模）≤ 10 分钟。
- **复用指标**：新芯片接入不得修改 fi/ 通用代码（门禁强制），只新增 profiles/<chip>.yaml + examples 配置。

## 4. 产品化清单（把 target-chip 的 100 分钟人工，变成管线的 1 条命令）

| # | 手工动作（现已发生过） | 产品化形态 | 负责 |
| --- | --- | --- | --- |
| 1 | 反汇编 + 常量扫描找 RAM/MMIO 区域 | `fi discover regions`（已部分存在于 chip-profile 扫描脚本，需产品化） | chip-profile |
| 2 | 找 mtvec 安装/trap handler/向量 | `fi discover traps`（模式库：csrw mtvec / csrr mcause / mret 邻近匹配） | chip-profile |
| 3 | 迭代补模型直到不 hang | `fi discover iterate`（起跑→读 unmapped/stub 热点→自动生成 region 候选→再跑，自动循环至收敛或需人工） | sim-engine |
| 4 | 手工写仿真配置 | `fi discover config`（从 1/2/3 产出自动生成配置） | sim-engine |
| 5 | 手工定位可注入靶点 | `fi discover targets`（错误码装载点/比较分支/发送函数自动枚举，已手工做过 19 调用点枚举） | chip-profile + sim-engine |
| 6 | 全量 JSONL 轨迹 | 轨迹分级：`--trace-level=off|binary|sampled|full`，二进制格式 + 采样 | sim-engine |
| 7 | 手工改 Profile | Profile 草稿自动生成（claim 全 hypothesis + 来源=artifact_derived，等验证升级） | chip-profile |

## 5. 纪律不变

自动化不等于放松证据标准：自动生成的 claim 一律 `hypothesis` + 来源标 `artifact_derived`，人工/交叉验证后才升 fact；`fi discover` 只产出草稿与候选，**不得自动改写已有 fact 级 claim**。
