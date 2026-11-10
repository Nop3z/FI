# FI 数据契约（面向 Web/Dashboard 团队）v0.5

本目录是 FI 工具集向 Web server / Dashboard 团队交付的**数据契约权威来源**：
字段定义、状态语义、证据分级、样例数据、变更说明。契约变更以本目录
（schema + CHANGELOG）为准，代码注释与口头约定不构成契约。

## 1. 文件清单

| 文件 | 说明 |
| --- | --- |
| `schemas/common.defs.json` | 公共定义：证据等级、`unknown` 标记、通用类型（仅 defs，不可直接校验实例） |
| `schemas/fault-context.schema.json` | **FaultContext**：故障现场统一上下文（三层观测：行为/处理器上下文/执行轨迹） |
| `schemas/campaign-record.schema.json` | **CampaignRecord**：单次注入实验记录（参数/响应/状态标签/原始数据引用） |
| `schemas/experiment-scan.schema.json` | **ExperimentScan**：参数窗口扫描汇总 |
| `schemas/chip-profile-index.schema.json` | **ChipProfile 索引引用约定**（Profile 内部格式归 chip-profile 专职契约；v0.3 补 draft 语义） |
| `schemas/analysis-result.schema.json` | **AnalysisResult**：分析结论（findings/命中窗口/候选路径/基线差异） |
| `schemas/sim-trace.schema.json` | **SimTrace**：指令级仿真轨迹 JSONL（run_meta/trace/fault_event/run_end 四种行） |
| `schemas/reverse-report.schema.json` | **ReverseReport**（v0.3 新增）：功能级逆向结论（目标功能/入口/调用链/时间估算/注入靶点） |
| `schemas/discover-report.schema.json` | **DiscoverReport**（v0.3 新增）：芯片接入自动发现报告（regions/traps/targets，**confidence 只有 hypothesis\|unknown**） |
| `schemas/tts-metrics.schema.json` | **TTSMetrics**（v0.3 新增，待定稿）：芯片接入耗时/吞吐指标，跨芯片对比与效率看板 |
| `schemas/anomaly-report.schema.json` | **AnomalyReport**（v0.4）：异常数据综合分析报告（六块骨架 + 统计警示 + 证据链 + 可选指令级归因） |
| `schemas/fault-effect.schema.json` | **FaultEffect**（v0.4 新增）：位翻转效果枚举（**confidence 恒 hypothesis**） |
| `schemas/fault-explanation.schema.json` | **FaultExplanation**（v0.4 新增）：观测反解（**允许多解且必须全列**，confidence 恒 hypothesis） |
| `schemas/observation-classification.schema.json` | **ObservationClassification**（v0.4 新增）：五色分类（**confidence 恒 observation**） |
| `schemas/bitflip-evidence.schema.json` | **BitflipEvidence**（v0.5 新增）：位翻转关键证据（**寄存器掩码防坑字段 + XOR 不变量**；进 Web 契约） |
| `schemas/live-experiment.schema.json` | **LiveExperiment**（v0.5 新增）：实机实验记录（**Captured State 与 Simulated 严格分开**） |
| `status-semantics.md` | 状态标签语义（v0.2.0：异常机制链路已确认 fact，标签语义仍未确认） |
| `param-mapping.md` | 参数窗口(ns) → 仿真故障事件映射契约 |
| `trace-levels.md` | **轨迹分级契约**（v0.3 新增）：`--trace-level=off\|binary\|sampled\|full` 语义 |
| `CHANGELOG.md` | 契约版本变更记录（语义化版本） |

校验入口：`fi schema list` / `fi schema validate --schema <名称> --file <json|jsonl>`。
语义不变量（跨字段约束，见 §6）与结构校验一起执行。

## 2. 三条全局纪律（消费前必读）

1. **证据分级**：所有契约实例必填 `evidence_level`，
   取值 `observation`（仪器/Provider 直接观测事实）|
   `hypothesis`（推导、未经证实）| `unknown`（无法判定）。
   Dashboard 展示时应把 hypothesis/unknown 与 observation 在视觉上区分。
2. **显式 unknown**：未采集到的字段一律写字符串 `"unknown"`，
   **禁止用 null / 0 / 空串表达缺失**。消费方解析时把 `"unknown"`
   视为合法值（schema 已按 anyOf 约束）。
3. **状态标签语义未确认**：CSV 状态标签（FL/HANG/SUCCESS/UNEXPECTED/Fake_Success）
   一律按原始字面量处理，`state_label_semantics = "unconfirmed-v0.1"`（契约常量，
   status-semantics.md v0.2.0 仅确认机制链路，标签语义仍未确认）。
   语义确认前**不得据标签含义做业务判断**（详见 status-semantics.md）。

## 3. 契约版本化

- 语义化版本：**破坏性变更（删字段/改语义）→ major；加字段（向后兼容）→ minor；修样例/文档 → patch**。
- 每个实例带 `schema_version`（当前 `"0.2"`；v0.3 批次为**向后兼容新增**，
  未改 `schema_version` 常量，见 CHANGELOG `[0.3.0]`）。
- **所有变更必须进 `CHANGELOG.md`**，含"Dashboard 影响"小节
  （新增/变更字段、新数据文件类型、版本 bump）。

## 4. 消费方式

- 数据文件以 **JSON**（单实例）与 **JSONL**（实例流，如扫描明细、仿真轨迹）交付；
  每行一个独立 JSON object，UTF-8，`ensure_ascii=false`。
- 本地校验（仓库内）：`fi schema validate --schema <名称> --file <json|jsonl>`；
  `fi schema list` 查看全部契约名。
- 样例数据：`tests/` 内置最小样例；v0.3 新契约的**可校验完整样例**位于
  `data/derived/contract-samples/`（`discover-report.sample.json` /
  `reverse-report.sample.json` / `tts-metrics.sample.json`），重生成命令：
  `python data/derived/_gen_contract_samples.py --image <bin> --base <addr>`；
  真实派生数据位于 `data/derived/`（原始 `<DATASET>.csv` / `<ROM_IMAGE>` 只读，不修改）。

### 4.1 语义不变量也走 CLI

`fi schema validate` 不只做结构校验：语义不变量（§6）失败同样非零退出并给出行号
（JSONL）或字段路径。示例：

```sh
# 结构对但语义错（调用链标 observation 缺 verified_by）→ EXIT 1
fi schema validate --schema reverse-report --file bad.json
# 输出：call_chain/0: 'verified_by' is a required property
#       call_chain[0]: confidence=observation 但缺 verified_by（…）
```

## 5. 数据流（谁产出什么）

```
fi discover ──► DiscoverReport(自动发现候选, 恒 hypothesis) ──► 仿真配置/迭代补模型
静态逆向     ──► ReverseReport(功能级调用链/时间估算/靶点) ──► 注入实验设计
Injector(注入) ──► CampaignRecord(实验记录, JSONL)
CaptureProvider(观测) ──► FaultContext(现场上下文, JSON)   [三层观测各一条]
扫描聚合 ──► ExperimentScan(窗口汇总) ──► AnalysisResult(分析结论)
仿真引擎 ──► SimTrace JSONL(run_meta 首行 + trace/fault_event + run_end)
            （记录量由 --trace-level 决定，见 trace-levels.md）
接入效率 ──► TTSMetrics(耗时/吞吐, 跨芯片对比)  ──► Dashboard 效率看板
ChipProfile ──► (chip-profile 专职契约) ◄── 其他契约经 profile_id 引用
```

## 6. 语义不变量（v0.3，schema 结构之外的跨字段约束）

JSON Schema 只能表达结构约束；下列**跨字段语义**由 `fi.schemas.invariants` 在
`validate_instance` 与 `fi schema validate` 中一并强制（不是评审纪律，是机器拒绝）：

| 契约 | 不变量 |
| --- | --- |
| `reverse-report` | ①`call_chain`/`entry_points`/`injection_targets`/`error_exits`/`timing_estimate.segments` 的每处 `evidence_ref` 必须存在于 `evidence_refs`（function_addr 必须可回溯到证据）；②`call_chain` 条目 `confidence=observation` 必须给 `verified_by`（static 推断不得写成事实）；③`timing_estimate` 禁止裸数字：`ns_per_cycle` 与 `ns_estimate` 必须是对象，`ns_estimate.formula` 恒为 `cycles * ns_per_cycle`。 |
| `discover-report` | 自动发现证据闸门：顶层与每条 findings 条目的 `confidence` **只能是 `hypothesis` 或 `unknown`**（`fact`/`observation` 直接被 schema 枚举拒绝）；`suggested_action` 限 `skip_insn\|flip_reg_bits\|reg_write\|mem_write\|map_region\|stub_read`；每条 findings 必须附 `sample_evidence`（至少 1 条）。 |
| `chip-profile-index` | 草稿不变量：条目带具体 `generated_by`（非 `unknown`）⇒ 必须 `status=draft` 且 `source=artifact_derived`。自动生成物不得伪装成已验证数据。 |

### 6.1 两个动作词汇表的差异（易错点）

| 契约 | 字段 | 词汇 |
| --- | --- | --- |
| `discover-report` | `findings.*[].suggested_action` | `skip_insn / flip_reg_bits / reg_write / mem_write / map_region / stub_read`（**含发现层动作** `map_region`=映射区域、`stub_read`=占位读） |
| `reverse-report` | `injection_targets[].suggested_action` | `skip / flip_reg_bits / reg_write / mem_write`（**与 `sim-trace.fault_event.action.kind` 完全一致**，无发现层动作） |

映射：发现层 `skip_insn` ↔ 引擎 `skip`（同一动作，语义名 vs 引擎枚举名）；
`map_region`/`stub_read` 是"补模型"动作，不是注入动作，故只出现在发现报告里。
两条词汇表都由契约测试锁定（`tests/test_contracts_v03.py`、
`tests/test_reverse_report_builder.py`），改动须同步 CHANGELOG。

## 7. 草稿（draft）语义 —— 消费方强制规则

`fi discover draft` 等自动管线产出的 Profile 草稿（`profiles/<chip>.draft.yaml`）
与人工/验证过的 Profile 共享索引契约，但语义完全不同：

1. **草稿不进正式索引**：`YamlProfileStore.index()` 与 `fi.profiles.validate --all`
   跳过 `*.draft.yaml`；正式索引里不应出现自动草稿条目。
2. **草稿必须可追溯**：`status=draft` + `generated_by=<工具名 版本>` +
   `source=artifact_derived` 三者齐备（语义不变量强制前两者的搭配）。
   → 回答"这份草稿是谁、在哪一步、用什么自动生成的"。
3. **草稿不得当已验证数据消费**（硬规则）：
   - 不得把草稿里的 `hypothesis` 级 claim 展示为事实；
   - 不得把草稿作为仿真配置/分析结论的**唯一**依据（只能作为候选输入，
     必须同时标注"来源=草稿/未验证"）；
   - Dashboard 对 `status=draft` 条目必须打"草稿·未验证"标识，
     不得与 `validated` 条目同权重并列展示。
4. **升级路径**：草稿 → 人工复核 / 仿真复现 / 数据交叉验证 → 由 chip-profile
   转出 fact 级 claim 并改 `status`；升级后应清空 `generated_by`
   （或保留但不再标 draft——二者语义互斥，见 §6 不变量）。
5. **草稿与发现报告的关系**：`discover-report` 是原始候选（恒 hypothesis），
   草稿 Profile 是其结构化落盘；两者证据等级链条一致，都不得跳级到 fact。

## 8. 轨迹分级（v0.3）

轨迹记录量由 `--trace-level=off|binary|sampled|full` 决定，**级别是契约参数**：
`binary` 的字节布局归 sim-engine 定义并版本化，reader 必须归一为 `sim-trace`
契约行并通过 round-trip 验证；`sampled` 的选样规则必须确定性可重放。
详见 `trace-levels.md`（含 round-trip 验证命令）。

消费方要点：采样轨迹"缺某条指令"= **未记录**，不等于"未执行"；指令数以
`run_end.instruction_count` 为准，不得用轨迹行数。

## 9. Dashboard 影响（本批 v0.3）

- **新增契约（3 个）**：`reverse-report`（功能级逆向结论，单实例 JSON）、
  `discover-report`（自动发现报告，单实例 JSON）、`tts-metrics`（接入效率指标，单实例 JSON）。
- **新增文档（1 个）**：`trace-levels.md`（轨迹分级语义 + binary round-trip 验证）。
- **新增字段**：`chip-profile-index.profiles[].generated_by` / `.source`（可选，
  向后兼容）、`chip-profile-index.draft_semantics`（可选常量）。
- **新增展示语义**：草稿徽标（`status=draft` 且 `generated_by` 非 unknown）、
  自动发现报告的"候选/未验证"水印（confidence 只有 hypothesis|unknown）、
  逆向报告的调用链证据链（每条可点开 `evidence_refs`）、时间估算必须显示
  `ns_per_cycle` 假设（禁止只显示 ns 数字）。
- **新数据文件类型**：无新增文件后缀（仍为 `.json` 单实例）。
- **契约版本变化**：本批为**向后兼容新增**，`schema_version` 常量仍为 `"0.2"`；
  CHANGELOG 记 `[0.3.0] - Unreleased`。
