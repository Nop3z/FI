# 契约变更记录（CHANGELOG）

格式参考 Keep a Changelog；版本语义化：
破坏性变更 → major；向后兼容新增 → minor；文档/样例修正 → patch。
所有变更必须附 **Dashboard 影响** 小节（新增/变更字段、新数据文件类型、版本 bump），
本文件是 Web/Dashboard 团队同步的权威渠道。

## [0.3.0] - Unreleased（逆向先行基线批次）

**变更类型：minor bump（向后兼容新增；`schema_version` 常量未动，仍为 `"0.2"`）。**
触发：2026-11-09 用户纠偏「逆向先行」（`docs/methodology-reverse-first.md`）——
先逆清目标功能（首个目标 = ISP 模式 write）的完整流程与调用链、评估运行时间、
构造精确注入靶点，然后才试运行与迭代。本批为该方法论补**数据契约支撑**，
同时收尾已启动的自动发现管线契约。

### Added（新增契约）

- `schemas/reverse-report.schema.json` —— **ReverseReport 功能级逆向结论**。
  结构：`target_feature{id,title,mode,description,success_criteria}`（第一步"声明目标"）+
  `entry_points[]` + `call_chain[{level,function_addr,function_name,caller_addr,
  call_site_addr,call_site_insn,conditions[],error_exits[],evidence_ref,confidence,
  verified_by}]` + `timing_estimate{cycles,ns_per_cycle,ns_estimate,segments[]}` +
  `injection_targets[{addr,insn,expected_undesired_effect,rationale,evidence_ref,
  suggested_action,trigger_hint,confidence}]` + `evidence_refs[]` + `unknowns[]` + `confidence`。
  **三条不变量（schema + 语义校验双强制）**：
  ① `call_chain` 的 `function_addr` 必须可回溯到 `evidence_refs`（每层必带
  `evidence_ref`，引用悬空即拒；有调用链却无证据表直接拒）；
  ② `call_chain` 条目默认 `hypothesis`，标 `observation` 必须给 `verified_by`
  （simulation/measurement/cross_validation）——静态可达性推断不得写成事实；
  ③ `timing_estimate` **禁止裸数字**：`ns_per_cycle` 必须是 `{value,confidence,basis}`
  对象，`ns_estimate` 必须含常量 `formula: "cycles * ns_per_cycle"`，ns 是假设推导值。
- `schemas/discover-report.schema.json` —— **DiscoverReport 自动发现报告**。
  结构：`schema/tool{name,version}/image{path,sha256,size_bytes,base_address}/
  method{channels[],boundaries[]}/summary/findings{regions[],traps[],targets[]}/
  confidence/evidence_kind`；每条 finding 含 `kind/addr/offset/insn/context/
  suggested_action/confidence/evidence_kind(artifact|artifact_derived)/sample_evidence[]`。
  **硬约束（自动发现证据闸门，schema 层强制）**：`confidence` 枚举**只有
  `hypothesis | unknown`**，`fact`/`observation` 直接被拒——自动发现产出必须经
  人工/交叉验证后才可升级，升级结果写 Chip Profile 或 reverse-report，不回写本报告；
  `suggested_action ∈ {skip_insn, flip_reg_bits, reg_write, mem_write, map_region,
  stub_read}`；每条 finding 至少 1 条 `sample_evidence`（可回溯原始证据）。
- `schemas/tts-metrics.schema.json` —— **TTSMetrics 接入效率指标**（**待定稿**，
  lead 2026-11-09：先等逆向跑通再定口径）。字段：`chip_id / tts_a_minutes /
  tts_b_minutes / instr_per_sec / bytes_per_instr / iterations_to_converge /
  measured_at / notes`，另含可选 `basis{tts_accounting,measured_user,trace_level,
  command}`（可重放核对）与 `dashboard{baseline_chip_id,improvement_factor,
  milestones[]}`（效率看板展示）。全部数值允许 `"unknown"`，禁 0 冒充。
- `trace-levels.md` —— **轨迹分级契约**。定义 `--trace-level=off|binary|sampled|full`
  四级语义（落盘内容/体积量级/能回答与不能回答/默认用途）；明确
  **二进制是传输/存储格式，字节布局归 sim-engine 定义并须带版本号**，契约只要求
  reader 归一为 sim-trace 契约行 + **round-trip 验证方式**（同配置跑 full 与 binary，
  reader 归一后按 seq 对齐逐字段比对，忽略字段须在格式文档声明）；`sampled` 的
  选样规则必须确定性可重放（`every_n`/`around_seq`/`keep_special`/`random_seeded`），
  `keep_special` 保证 run_meta/run_end/fault_event/hypothesis 行/stub 行不被丢弃。
- `fi/schemas/invariants.py` —— **语义不变量执行层**（JSON Schema 表达不了的跨字段
  约束）：`validate_instance()` 与 `fi schema validate` 现在同时执行结构校验与
  契约语义不变量（reverse-report 三条、discover-report 证据闸门、chip-profile-index
  草稿语义）。错误合并返回，CLI 退出码不变。
- `fi/cli_plugins.py` —— 可选子命令模块的**自动注册钩子**（`fi.discover.cli` 等）：
  模块缺失或后端依赖缺失时只跳过并记录原因（`registration_report()` 可查），
  不让主 CLI 不可用。
- `fi/schemas/reverse_report.py` —— **ReverseReport 构造器**（契约层单一实现）：
  证据统一编号（`add_evidence` 返回 id，杜绝悬空引用）；`add_call_chain_level`
  默认 `hypothesis`，标 `observation` 未给 `verified_by` **构造期即抛错**；
  `set_timing` 强制 ns 由 `cycles × ns_per_cycle` 统一换算（禁各工具自乘）；
  `build()` 默认立刻按契约校验。目的：让"错误的形状根本拼不出来"。
- `fi/schemas/discover_report.py` —— **DiscoverReport 归一/构造器**（契约层单一实现）：
  `regions_to_findings` / `traps_to_findings` / `targets_to_findings` 把 discover
  各模块的工程形状转为契约 `findings.{regions,traps,targets}[]`；
  `normalize_module_report` 单模块归一；`merge_reports` 多模块合并；
  `build_report` 组装完整报告（未给指纹时自行计算 SHA-256，镜像不存在直接拒绝，
  禁止占位指纹）。越界 confidence（fact/observation）一律降为 hypothesis、
  越界动作降为保守动作——闸门在任何入口都不破。
- `discover-report.summary.sources`（可选字段）：合并报告的来源工具清单。
- `data/derived/contract-samples/` **可校验样例产物 3 份**（`discover-report` /
  `reverse-report` / `tts-metrics` .sample.json），由
  `data/derived/_gen_contract_samples.py` 从真实发现/逆向产出生成（地址/基址
  全部来自命令行参数，脚本内无芯片实例值）；生成后自校验，失败即非零退出。
  样例由 `tests/test_contract_samples.py` 纳入门禁（契约改而样例未重生成会红）。

### Changed

- `schemas/chip-profile-index.schema.json` —— **draft（草稿）语义进契约**（lead 裁定）：
  新增可选字段 `generated_by`（草稿生成方：工具名+版本）与 `source`
  （`artifact|artifact_derived|user_confirmed|measurement|manual_curated|unknown`），
  新增可选顶层常量 `draft_semantics = "draft-not-validated-v0.3"`；
  `status=draft` 的描述明确"含 fi discover draft 自动生成的草稿，未经任何验证"。
  **语义不变量**：`generated_by` 为具体值（非 `unknown`）⇒ 必须 `status=draft`
  且 `source=artifact_derived`（自动草稿不得伪装成已验证数据；通过验证后要么改
  status，要么清空 generated_by）。
- `docs/contracts/README.md` 升至 v0.3：新增文件清单三行、§6 语义不变量表与
  §6.1 **两个动作词汇表差异表**（发现层 `skip_insn` ↔ 引擎 `skip`；
  `map_region`/`stub_read` 只属发现层）、
  §7 **草稿语义消费方强制规则**（草稿不进正式索引、不得当已验证数据、
  必须打"草稿·未验证"标识、升级路径）、§8 轨迹分级消费方要点、§9 Dashboard 影响。
- **动作词汇对齐修正**（实现期发现）：`reverse-report.injection_targets[].suggested_action`
  由 `skip_insn` 改为 `skip`，与 `sim-trace.fault_event.action.kind` **完全一致**
  （引擎枚举单一来源；`skip_insn` 是发现层语义名，保留在 discover-report 词汇表）。
  该字段为 v0.3 新增未定稿字段，不构成破坏性变更；契约测试锁定两表差异。
- `fi/__init__.py` 版本 `0.1.0 → 0.3.0`；新增包说明 `fi.discover`；
  `pyproject.toml` 同步 `0.3.0`，新增 `discover`（capstone）与 `sim`（unicorn+capstone）
  可选依赖组，packages 增列 `fi.discover`。

### 未变更（明确声明）

- `schema_version` 常量仍为 `"0.2"`：本批全部为**向后兼容新增**（新契约 + 可选字段），
  存量实例不受影响，消费方无需迁移。
- `state_label_semantics` 仍为 `unconfirmed-v0.1`（status-semantics.md v0.2.0 只确认了
  异常机制链路，状态标签语义仍未确认）。

### Fixed（顺带修复，均在本批写范围内）

- `fi/cli.py` 裸调用 `fi`（无子命令）时抛 `AttributeError: 'Namespace' object has no
  attribute 'command'`：改为打印帮助并返回用法错误码 2（与 argparse 一致）。
  已有 `tests/test_cli.py::test_bare_invocation_prints_help_not_crash` 锁定。

### Dashboard 影响

- **新增契约 3 个（均为 `.json` 单实例，无新文件后缀）**：
  - `reverse-report`：建议做"逆向结论页"——目标功能卡片 + 调用链逐层可展开
    （每层显示 `function_addr/call_site/conditions/error_exits`，点击展开
    `evidence_refs` 对应证据）+ 时间估算卡片（**必须同时显示 `ns_per_cycle` 假设
    与 `basis`，不得只显示 ns 数字**）+ 靶点表（`expected_undesired_effect` 与
    `suggested_action`）。`confidence=hypothesis` 的调用链层必须打"未验证"样式；
    `unknowns[]` 可直接驱动"待确认清单"。
  - `discover-report`：建议做"自动发现候选页"——region/trap/target 三类候选列表，
    全部标"候选（未验证）"水印（schema 层已保证不会出现 fact）；每条展开
    `sample_evidence`；`method.boundaries[]` 建议固定在页面顶部展示（噪声边界提示）。
  - `tts-metrics`：建议做"接入效率看板"——芯片间 TTS-A/TTS-B 条形对比 +
    `improvement_factor` 徽标 + 吞吐/体积双指标（注意 `basis.trace_level`，
    不同级别不可直接比较）+ `dashboard.milestones` 时间线。
- **新增字段（向后兼容）**：`chip-profile-index.profiles[].generated_by` /
  `.source`；顶层 `draft_semantics`（可选常量）。
- **新增展示语义**：草稿徽标（`status=draft` 且 `generated_by` 非 unknown →
  "草稿·未验证"）、逆向报告证据链跳转、时间估算必须带频率假设、发现报告候选水印。
- **新数据文件类型**：无新增后缀（仍 `data/derived/*.json` 单实例）。
- **契约版本变化**：`[0.3.0]` minor（向后兼容新增）；实例 `schema_version` 仍 `"0.2"`。

## 归档：0.2.0 定版前的契约层修订记录（历史，内容未删改）

> 说明（core-contract 2026-11-09）：本块原为 `[Unreleased]` 节，内容已随
> `[0.2.0]` 一并定版（见 `[0.2.0]` 节末"Unreleased 节全部内容随本版一并定版"）。
> 现改为非版本标题的归档块，避免与进行中的 `[0.3.0] - Unreleased` 混淆；
> 条目内容原样保留供追溯。

### Changed

- `status-semantics.md` 升至 v0.1.1（内容/结构扩充，来源 target-chip.yaml r0.2.0 +
  exp-analysis 交叉验证 S9）：新增响应帧格式候选（'FL'/'OK' magic，hypothesis 级）；
  错误码表 9→12 字面量（新增 0x<CODE_E>/0x<CODE_G>/0x0140/0x0006，UNEXPECTED 长尾
  2,834 行归因闭环）；全部错误码补 delay_raw_range（fact 级观测）；
  0x<CODE_A>/0x<CODE_B>/0x<CODE_D> 获得 hypothesis 级候选归因。
  **无 fact 级语义变更、schema 未动、无契约版本 bump**（`state_label_semantics`
  仍为 `unconfirmed-v0.1`）。
- 联动收编：`fi.profiles.loader.YamlProfileStore.index()` 已补齐契约必填的
  evidence_level 与建议字段（index_path/format_version/source_of_truth），
  chip-profile-index 契约验收测试转绿（tests/test_profile_index_alignment.py）。

### Changed（exp-analysis v2 §6 变更清单逐条归档，2026-11-09）

**契约层（消费方可见）：**

- `responded` 口径裁定（campaign-record 实例填充规则；**lead 终审定义**）：
  改为**观测级机械事实**——"数据源是否记录了响应 token"（response /
  unexpected 任一列非空即 true），零特例。SUCCESS 行（unexpected='OK'）与
  'NONE' 行（Fake_Success×1，双列 NONE 字面量）均记 true；HANG（双列空）
  记 false。**'NONE' 不是"无响应"判定**：其语义归属（harness 占位 vs 设备
  文本）维持 hypothesis，作为边界案例登记 status-semantics.md §4；解释级
  结论永远走 evidence 分级，不进布尔字段。schema 字段描述已同步修订
  （纯描述修订，Unreleased 不 bump）。实现单一来源
  `fi.loop.records.has_response`（csv_replay/loop 编排共用）。
  **已生成的历史派生 JSONL 需按新口径重生成**（exp-analysis 已完成，
  740,209 行 schema_version=0.2）。schema 结构与字段定义未变，契约未正式
  定版交付，**无需 minor bump**；正式交付（v0.1 定版）后再变更才走版本化。
- `campaign_id` 统一为 csv_replay 单一实现的 `{csv文件名}-{8位行号}` 格式
  （如 `<DATASET>-00000042`）。契约 id 仅要求非空字符串，无破坏性。
- `hit_windows` 产出端开始逐标签多条：契约该字段本为数组（每条自带
  state_label），**契约已天然兼容，无需变更**。

**analysis-internal（非契约，仅供关注）：**

- `success_wilson95`→`target_wilson95` 等 metrics 键名更替：metrics 为契约
  自由对象，键名属分析内部约定。
- clusters `significant_points` 结构调整：同上，findings/candidates 自由对象。
- 新增数据文件 `data/derived/sample-run-<DATE>.json`（含 meta.run_config）：
  分析样例运行产物，属 analysis 内部文件类型，非契约交付类型。
- error-codes 相关键更名：属 chip-profile 的 target-chip.yaml 内部（profile-internal），
  已由 status-semantics.md v0.1.1 同步转写（见上）。

## [0.2.0] - 2026-11-09

**变更类型：minor bump（机制语义正式确认批次）。**

### Changed

- **实例 `schema_version` 常量 0.1 → 0.2**（全契约，common.defs.json 单一定义）。
  升级依据（lead 裁定）：机制类 claim 无 CSV 观测通道（CSV:not-applicable），
  S4 静态编码实测（可重放反汇编）+ S10 sim-engine 仿真动态复现双方一致即 fact。
- `status-semantics.md` v0.1.1 → v0.2.0：新增 §5 **异常机制语义正式确认**
  （trap 入口 CSR mtvec@0x305、入口基址 0x<ADDR>、38 寄存器/144 字节全寄存器
  软件保存帧、mcause 10 位掩码 andi 0x3FF、ecall mepc+=4、诊断打印通道——
  全部 [fact] 双证）；§4 responded 改观测级机械定义（lead 终审，'NONE' 边界
  案例登记）；§7 消费方规则更新（Trap 捕获通道可按 fact 展示）。
  **FL/OK 帧格式保持 [hyp]，不在本批（等 sim 产出真实帧）。**
- `schemas/sim-trace.schema.json` trace 行 csrs_changed examples 补 mtvec 写入
  实测形态（csr 773 = 0x305，value 553648611 = 0x<ADDR>）。
- `schemas/campaign-record.schema.json` responded 字段描述修订为观测级机械
  定义（纯描述修订，随本版定版）。
- `schemas/campaign-record.schema.json` params **新增可选对象 `sim_trigger`**
  （trigger_mode/trigger_value/width_mode/width_value/action_kind）：承载仿真域
  触发参数（SimFaultInjector 产出）。动机：仿真记录的触发序号与 CSV 数据集
  刻度是两个域，禁止混入 raw_delay/raw_pulse（后者对仿真记录应写 unknown）。
  向后兼容（可选字段，存量实例不受影响）。
- Unreleased 节全部内容（status-semantics v0.1.1、chip-profile-index 收编、
  responded 口径、exp-analysis v2 §6 归档）随本版一并定版。

### Dashboard 影响

- **实例 schema_version 字段值 0.1 → 0.2**：消费方校验需接受 "0.2"
  （旧 "0.1" 实例不再通过最新契约校验——这正是 minor bump 的语义）。
- **展示语义升级**：异常机制链路（trap 入口/handler 帧结构/诊断打印通道）
  可按 fact 展示（含 "Trap 捕获可用" 通道徽标）；cause 名称映射、FL/OK
  帧格式仍标"候选"。
- **新增字段**：campaign-record.params.sim_trigger 可选对象（仿真域触发参数，
  向后兼容）；其余为示例/描述修订。
- **新数据文件类型**：无新增。

## [0.1] - 2026-11-09

**变更类型：初始发布（initial release）。**

### Added（新增契约清单）

- `schemas/common.defs.json` —— 公共定义：`evidence_level`
  （observation|hypothesis|unknown，全契约必填）、显式缺失标记 `"unknown"`、
  uint/string/boolean 的 `_or_unknown` 族、`provider_name`、`observation_level`
  （三层观测）、`data_ref`（原始只读数据引用）等。
- `schemas/fault-context.schema.json` —— FaultContext 故障现场统一上下文：
  PC/寄存器/CSR/内存快照/行为观测/执行轨迹/基线关联，缺失字段强制显式 unknown。
- `schemas/campaign-record.schema.json` —— CampaignRecord 单次注入实验记录：
  参数（raw 必填、ns 按假设处理）、响应（原始标签 + unconfirmed 标记）、
  原始数据引用。
- `schemas/experiment-scan.schema.json` —— ExperimentScan 参数窗口扫描汇总：
  多轴窗口（含单位）、明细 JSONL 引用、按原始标签聚合的分布事实。
- `schemas/chip-profile-index.schema.json` —— ChipProfile 索引引用注册表
  （profile_id + index_path + format_version；Profile 内部格式归 chip-profile
  专职契约）。**2026-11-09 收编对齐**：条目形状与
  `fi.profiles.loader.YamlProfileStore.index()` 导出对齐，新增可选字段
  title/revision/updated/valid/stats/error；required 收窄为
  profile_id/status/evidence_level；index_path 约定 `profiles/<profile_id>.yaml`。
- `schemas/analysis-result.schema.json` —— AnalysisResult 分析结论：
  findings/hit_windows/candidates（候选一律 hypothesis 及以下）/baseline_diff
  （confirmed 与 hypothesized 分离）。
- `schemas/sim-trace.schema.json` —— SimTrace 仿真轨迹 JSONL：
  run_meta（首行，自包含可重放）/ trace（stub、region、WARL 标记）/
  fault_event（trigger {pc,seq,cycle_estimate,every} + action {skip,flip_reg_bits,
  预留 reg_write,mem_write} + 生效回填）/ run_end（coarse 枚举 + detail 细分）。
- `status-semantics.md` —— 状态标签语义草案（v0.1 全部待确认）。
- `param-mapping.md` —— 参数窗口(ns) → 仿真故障事件映射契约（与 sim-engine 对齐定稿）。
- `README.md` —— 契约交付说明（面向 Web 团队）。

### Dashboard 影响

- **新增字段**：全部（初始发布，见上清单）。其中 chip-profile-index 条目
  字段于 2026-11-09 收编扩展（title/revision/updated/valid/stats/error，
  均可选，向后兼容）。
- **新数据文件类型**：
  - JSON 单实例：fault-context / analysis-result / chip-profile-index；
  - JSONL 实例流：campaign-record 明细、experiment-scan 明细、sim-trace 轨迹。
- **契约版本变化**：`schema_version` 常量定为 `"0.1"`；本条目建立版本基线。
- **消费方注意**：`"unknown"` 是合法字段值（不是 null）；状态标签语义未确认
  （见 status-semantics.md §5）。

[0.1]: https://example.invalid/fi-contracts/0.1
[0.2.0]: https://example.invalid/fi-contracts/0.2.0
[0.3.0]: https://example.invalid/fi-contracts/0.3.0