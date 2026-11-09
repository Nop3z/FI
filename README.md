# FI — 通用 RISC-V 故障注入工具集

面向 AI Harness（Codex / Claude Code / DSH 等）的通用 RISC-V 故障注入与故障分析工具集。
CLI + JSON/JSONL 契约优先，无 GUI 依赖，可由 AI 自动调度。

> **本仓库只含通用框架与规范，不含任何具体芯片的原始数据、逆向笔记或注入结论。**
> 具体芯片的 Profile、原始固件、实验数据均不入库。

## 一、能力概览

| 能力 | 命令 | 说明 |
| --- | --- | --- |
| 内存区域发现 | `fi discover regions` | 镜像 → RAM/MMIO 区域候选 |
| trap 机制识别 | `fi discover traps` | mtvec 安装点、mcause/mepc、mret、handler 形态 |
| 命令分派表恢复 | `fi discover dispatch` | 从 memcpy 源表恢复运行期分派表 |
| 异常码归因 | `fi discover attribute` | 码 → 命令 → handler → 装载指令 |
| 调用链回溯 | `fi discover chain` | 从入口到目标函数的可达路径 |
| 注入靶点清单 | `fi discover injection-targets` | 靶点 + 位翻转变体 + 建议注入动作 |
| 位翻转枚举 | `fi fault enumerate` | 指令机器码 → 1→0 翻转变体 + 语义分类 |
| 观测反解 | `fi fault explain` | 寄存器差异 → 最可能的损坏指令（多解全列） |
| 观测五色分类 | `fi fault classify` | normal/restart/pc_wrong/missed_target/target_hit |
| 异常数据分析 | `fi analyze anomaly` | 任意观测数据 → 综合报告（非平稳性/命令面/功效/证据链） |
| 参数扫描闭环 | `fi.loop` | 参数窗口 → 注入 → 捕获 → 归因 → 调参 |
| 契约校验 | `fi schema validate` | 14 个 JSON Schema + 语义不变量 |

## 二、快速开始

```sh
# 安装（Python >= 3.11）
pip install -e .

# 查看契约
fi schema list

# 发现区域（--base 为镜像基址，按实际目标填）
fi discover regions --image firmware.bin --base 0x0 --summary

# 恢复命令分派表
fi discover dispatch --image firmware.bin --base 0x0 --summary

# 异常码归因（--codes 逗号分隔）
fi discover attribute --image firmware.bin --base 0x0 --codes 0x0100,0x0200

# 位翻转枚举（--addr 为指令执行地址）
fi fault enumerate --bytes 13051050 --addr 0x0 --max-flips 3

# 异常数据综合分析（可选接入镜像做指令级归因）
fi analyze anomaly --input observations.csv \
    --image firmware.bin --image-base 0x0 --out-prefix out/report
```

## 三、核心设计原则

1. **通用性强制**：`fi/` 通用代码内不得出现任何具体芯片的地址、错误码、ID。
   `tests/test_genericity_gate.py` 用 AST 扫描强制此约束——注释与文档字符串豁免，
   代码构造违规则测试失败。
2. **证据三级分级**：所有结论必须标注
   `observation`（直接观测）/ `hypothesis`（推断）/ `unknown`（无法判定）。
   自动发现类产出**恒为 hypothesis**（契约层 schema 强制，写入 fact 直接拒）。
3. **缺失即 unknown**：未采集字段显式写 `"unknown"`，禁止用 null/0/空串充数。
4. **不伪造**：仿真数据标 `Simulated State`，实机数据标 `Captured State`，
   推导数据标 `Reconstructed State`，三者不得混用。
5. **多解全列**：观测反解允许多个候选，不得只报一个。

## 四、契约（14 个 JSON Schema）

`docs/contracts/schemas/` 下为全部数据契约，配套语义不变量层
（`fi/schemas/invariants.py`）在结构校验之外强制：
证据可回溯、未验证不得标 observation、时间估算禁裸数字（必须带 `ns_per_cycle` 假设）等。

详见 `docs/contracts/README.md`。

## 五、接入 AI Harness

本仓库是**能力提供者**，不实现 Agent 调度。Harness 通过 CLI 调用：

```sh
# 典型任务描述
"请分析 firmware.bin（基址 0x0），用项目工具完成：
 1. fi discover dispatch 恢复命令表
 2. fi discover attribute 把观测到的异常码归因到指令
 3. fi fault enumerate 枚举这些指令的位翻转变体
 4. 结果按 docs/contracts 的 schema 落盘"
```

约定：
- 所有命令支持 `--out <path>` 落盘 JSON，`--summary` 只打印摘要；
- 退出码：0 成功 / 2 数据或输入错误 / 1 参数错误；
- 实时进度建议由 Harness 通过事件上报，不要让看板推测 Agent 内部状态。

## 六、仓库结构

```
fi/
  discover/   自动发现：regions / traps / dispatch / attribute / chain / targets / draft
  fault/      故障效果：位翻转枚举 / 观测反解 / 单步仿真验证
  analysis/   数据分析：异常报告 / 分布 / 归因 / 评分
  sim/        指令级仿真：Unicorn 后端 / 轨迹分级 / 故障注入 / 周期估算
  loop/       闭环编排：参数窗口 / 注入器 / 策略 / 编排器
  hardware/   实机接入：毛刺设备（含 mock 与安全护栏）
  profiles/   芯片画像格式与校验（实例文件不入库）
  schemas/    契约加载、校验、语义不变量
  providers/  上下文捕获 Provider 抽象
tests/        285+ 项测试（含通用性门禁、合成镜像通用性验证）
docs/contracts/  全部数据契约与规范
examples/synthetic/  合成镜像生成器（用于验证通用性，不含真实芯片数据）
```

## 七、测试

```sh
python -m pytest -q
```

包含：
- 通用性门禁（通用代码零芯片实例值）
- 合成陌生镜像自检（自造地址/命令/码值，验证能力不依赖特定芯片）
- 契约结构与语义不变量
- 实机接入层（mock 设备 + 安全护栏）

## 八、许可与边界

本工具集用于**授权的安全测试环境**。使用者须确保对目标固件与硬件拥有合法测试授权。
工具本身不含任何具体芯片的原始数据、密钥或未公开结论。
