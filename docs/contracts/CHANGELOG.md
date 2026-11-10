# 契约变更记录（CHANGELOG）

格式参考 Keep a Changelog；版本语义化：
破坏性变更 → major；向后兼容新增 → minor；文档/样例修正 → patch。
所有变更必须附 **Dashboard 影响** 小节（新增/变更字段、新数据文件类型、版本 bump），
本文件是 Web/Dashboard 团队同步的权威渠道。

## [0.5.0] - 2026-11-10（实机接入与可检验证据批次）

**变更类型：minor bump（向后兼容新增 + 一处可选节 patch 级登记）。**
触发：① 用户预告提供 PowerShorter 实机 → 实机实验记录必须有契约（Captured State 与
Simulated State 严格分开）；② chip-profile-ds 发现并修正一个会导致**注入静默失效**的
真实 bug（机器码位 vs 寄存器值位混淆）→ 把它变成 schema 层强制的防坑字段。

### Added（新增契约）

- `schemas/bitflip-evidence.schema.json` —— **BitflipEvidence 位翻转关键证据**
  （**进 Web 契约，UI 展示核心证据**；`data/derived/injection-targets.json` 属闭环内部
  输入，不进 Web 契约）。
  结构：`title/tool/image/one_sentence/entries[]/code_pair_index[]/counts/how_to_read/
  discipline/confidence/evidence_kind`；`entries[]` 每条含
  `evidence_id/summary/claim/technical_chain/experimental_context/falsifiable_prediction/
  confidence/evidence_kind`。

  **两个防坑字段（schema 层强制，血泪教训）**：
  1. `claim.bit_mask_on_reg_value`（**必填**）—— 注入时施加在**寄存器值**上的位掩码；
  2. `claim.mask_applies_to`（**必填，`const "post_insn_reg_value"`**）—— 明确掩码
     作用于「指令执行后的寄存器值」，不是机器码、不是指令字节。

  **语义不变量（`fi.schemas.invariants` 强制，违反即拒）**：
  - `bit_mask_on_reg_value == source_code XOR target_code` 的位掩码
    （掩码写错立即拒，并给出"I-type 中机器码位 b ↔ 立即数位 b-20"的提示）；
  - `flipped_reg_value_bits` 的位集合必须与 `source XOR target` 的位集合一致；
  - `flipped_machine_code_bits` 与 `flipped_reg_value_bits` 不得完全相同
    （相同即把两套位搞混）；
  - `falsifiable_prediction.injection.bit_mask` / `.mask_applies_to` 必须与 `claim`
    同源（这是真正喂给注入器的字段，最易被手工改错）。

  **证据分级强制分字段（防 UI 混渲级别）**：`claim.confidence` 恒 `hypothesis`
  （预测）；`experimental_context.*.count` 属 `observation`（观测）。
  两者**不得混成一个数字展示**——历史 bug 正是"看起来像事实的预测"。
  背景：`fi.fault.effects` 枚举的是**指令机器码位**，注入翻转的是**寄存器值位**；
  拿机器码位当注入掩码（如 `0x40000000`）会翻到无关高位：码值不变、注入静默失效且不报错。

- `schemas/live-experiment.schema.json` —— **LiveExperiment 实机实验记录**。
  字段：`experiment_id / state_origin（const captured）/ target_chip{chip_id,profile_ref,
  image_ref,image_sha256,mode} / baseline_ref{kind,ref,expected_frame_bytes,expected_code} /
  params{delay_raw,pulse_raw,delay_ns,pulse_ns,unit_scale,unit_source,pattern 原样回执,
  engine,trigger_mode,device} / observation{frame_bytes,code,state_label,
  state_label_semantics,responded,pc,regs,uart_text,captured_at,capture_completeness} /
  classification{kind,label,is_interesting,basis} / safety{limits,max_injections,
  n_injections,stopped,stop_reason,safety_violations} / raw_logs_ref / captured_state /
  simulated_comparison / confidence / operator`。

  **Captured State 标注（本契约最重要的纪律）**：实机数据必须与仿真严格分开——
  - `state_origin` 与 `captured_state.origin` 恒为 `captured`；
  - 仿真对照只能放**独立对象** `simulated_comparison`，其 `origin` 恒 `simulated`、
    `confidence` 恒 `hypothesis`；
  - 语义不变量：`observation` 块出现 `predicted_*`/`simulated` 系字段即拒
    （禁止把仿真推断写进观测字段）。

  其他不变量：`unit_scale` 正整数必填且 `delay_ns/pulse_ns` 必须等于
  `raw × unit_scale`（换算对不上=手工算错，拒）；`pattern` 段数 ≤ 8（设备硬限制，
  超限会静默失效）；`safety.stopped=true` ⇒ 必须给 `stop_reason`；
  `pulse_raw` 不得超 `safety.limits.max_pulse_raw`。

### Changed（patch 级登记）

- `fi/profiles/schema/chip-profile-v0.1.schema.json`（chip-profile 维护，本文件仅登记）
  —— 新增**可选节** `injection_targets` + `$defs.injectionTarget`。
  **纯新增、向后兼容**，存量 Profile 不受影响，无需迁移（建议按 patch 级记录）。

### Changed（文档实测数字补录）

- `docs/contracts/trace-levels.md` 新增 §3.1 **实测达标节**：采样/二进制模式下轨迹
  体积实测 **3.98 B/指令**，达成 `docs/tts-baseline.md` §3 的「≤ 8 B/指令」目标
  （对比 full 模式约 262 B/指令，约 66× 缩减）。该数字来自 `fi.sim` 轨迹分级实测，
  用于回答"日常扫描跑得动吗"。

### 未变更（明确声明）

- `schema_version` 常量仍为 `"0.2"`：本批全部为向后兼容新增，存量实例不受影响。
- 动作词汇表不动：`bitflip-evidence.falsifiable_prediction.injection.action` 沿用
  发现层语义名 `skip_insn`/`flip_reg_bits`（与契约 README §6.1 的映射表一致）。

### Dashboard 影响

- **新增契约 2 个（均 `.json` 单实例，无新文件后缀）**：
  - `bitflip-evidence` → **位翻转证据卡片**：码对卡片（A→B）+ 翻转位数徽标 +
    两码实验出现次数（**必须标为 observation，与 hypothesis 的预测视觉上分开**）+
    `hypothesis` 标识 + 可证伪判据折叠区（`falsifiable_prediction`：
    支持条件/推翻条件/阴性对照）。
    **严禁**把 `claim`（预测）与 `experimental_context.count`（观测）渲染成同一个
    数值块，也不得省略"这是预测"的标注。
  - `live-experiment` → **实机实验页**：Captured 徽标（`state_origin=captured`）、
    五色分类徽标（`classification.label`）、安全状态条（`safety.stopped` 红色警示 +
    `safety_violations`）、采集完整性提示（`observation.capture_completeness`：
    minimal/partial 时提示"现场不完整"）、以及**仿真对照分栏**
    （`simulated_comparison` 必须与观测分区展示，不得混排）。
- **新增字段（向后兼容）**：Profile schema 的 `injection_targets` 可选节。
- **新增展示语义**：位翻转"寄存器掩码 vs 机器码位"提示（UI 若展示位位置，
  须同时标 `mask_applies_to=post_insn_reg_value`）；实机/仿真来源徽标；
  安全停机上报告警。
- **轨迹体积指标**：`trace-levels.md` 实测 3.98 B/指令（≤8 B 目标达标），
  Dashboard 效率页可直接引用该数字与 full 模式对比。
- **契约版本变化**：`[0.5.0]` minor（向后兼容新增）；实例 `schema_version` 仍 `"0.2"`。

## [0.4.0] - 2026-11-10（故障效果推演批次：从"打中哪条指令"到"为什么是这个观测"）

**变更类型：minor bump（向后兼容新增）。**
触发：用户要求对齐 hn security《Fault Injection - Down the Rabbit Hole》方法论
（`docs/methodology-fault-effect-reasoning.md`）——不只要"打中哪条指令"，还要
"指令被打坏后变成什么、为什么产生这个观测"。方法论七步中的第 5-7 步
（五色分类 / 位翻转假设 / 仿真复现解释）需要数据契约承载。

### Added（新增契约 3 个）

- `schemas/fault-effect.schema.json` —— **FaultEffect 位翻转效果枚举**。
  `original_insn{bytes_hex,addr,disasm}` + `physical_assumption{flip_mode
  (one_to_zero|zero_to_one|both),max_flips,fault_level,confidence}` +
  `variants[]{flipped_bit_positions[],mutated_code_hex,mutated_insn,change_kind
  (same|rd_changed|rs_changed|imm_changed|opcode_changed|undecodable|nop_like),
  semantics_changed,raw_diff_hex}` + `summary{by_change_kind,n_variants_total,
  n_variants_semantically_changed,enumeration_complete,reason}`。
  **强制**：报告级/变体级 `confidence` 均 `const "hypothesis"`（变体是候选解释，
  不是已证实物理过程；禁 fact/observation）。
  语义不变量：位位置不得越出指令位宽；`change_kind=undecodable ⇔ mutated_insn=unknown`；
  `semantics_changed` 与 `change_kind` 一致；`mutated_code_hex` 与原始指令等长；
  `variants` 为空必须给 `summary.reason`。

- `schemas/fault-explanation.schema.json` —— **FaultExplanation 观测反解**。
  `observation{regs,pc,source} / pre_state{regs,origin(captured|reconstructed|
  simulated|assumed),confidence} / target_insn / physical_assumption /
  candidates[]{flipped_bit_positions,mutated_insn,mutated_code_hex,change_kind,
  predicted_regs,match_score,match_detail,eval_status,simulation} /
  simulation_verification{executed,matches_observation,exception,n_variants_tested,
  n_matched,engine} / summary{multiple_solutions,n_candidates,...} / reason /
  discipline / confidence / evidence_kind`。
  **允许多解且强制全部列出**（方法论明确：多个损坏指令可产生同一观测，
  只报一个会误导结论）：
  - `summary.multiple_solutions=true` ⇒ `candidates` 至少 2 条（schema + 语义双强制）；
  - `multiple_solutions=false` 时不得有多条候选（标志与明细必须一致）；
  - `candidates` 为空 ⇒ 必须给 `reason`（且不得写 unknown）；
  - `summary.n_candidates` 必须等于实际条数；
  - `simulation_verification.executed=false` ⇒ `matches_observation` 不得为 true。
  `confidence` 恒 `hypothesis`（候选解释，非已证实机理）。

- `schemas/observation-classification.schema.json` —— **ObservationClassification
  观测五色分类**（方法论第 5 步）。
  `kind ∈ {normal, restart, pc_wrong, missed_target, target_hit}` +
  `label ∈ {绿, 品红, 黄, 青, 红}` + `is_interesting` + `evidence{pc_ok,target_reg_ok,
  other_regs_changed,restarted,target_reg,expected_regs,observed_regs,source}` +
  `next_action` + `experiment_ref` + `target_feature_ref`。
  **`confidence` 恒 `observation`**（对已捕获观测的机械比对，不是推断——
  "为什么"走 fault-explanation，那份恒 hypothesis）。
  语义不变量：`kind ↔ label` 固定配对（normal=绿 / restart=品红 / pc_wrong=黄 /
  missed_target=青 / target_hit=红）；`is_interesting` 仅 `target_hit` 为 true；
  `kind` 必须与 `evidence` 的 pc_ok/target_reg_ok/restarted/other_regs_changed 自洽。

### Added（构造层 + CLI）

- `fi/schemas/fault_report.py` —— 三份契约的**单一构造/归一实现**：
  `build_fault_effect` / `build_fault_explanation` /
  `build_observation_classification`（+ `normalize_effect_report` /
  `normalize_reasoning_report`）。不变量前移到构造期：
  confidence 由构造器固定、多解标志由候选数自动推导、空解自动填 reason、
  label/is_interesting 只能由 kind 推导（调用方无权重写）。
- `fi/fault_cli.py` + `fi/cli_plugins.py` 注册 —— **`fi fault` 命令组**：
  - `fi fault enumerate --insn-bytes <hex> --addr <addr> [--max-flips N]
    [--flip-mode one_to_zero|zero_to_one|both] [--include-unchanged] [--out F]`
  - `fi fault explain --insn-bytes <hex> --addr <addr> --pre-regs <json|@file>
    --observed-regs <json|@file> [--no-simulate] [--out F]`
  - `fi fault classify --pc-ok|--pc-wrong --target-reg-ok|--target-reg-wrong
    [--others-changed] [--restarted] [--target-reg a6] [--out F]`
  三个命令产出均**过契约校验后才落盘**，不合法非零退出。
  `@file` 读 JSON 容忍 BOM（Windows 工具常见产物）。

### Changed（异常分析报告扩展）

- `schemas/anomaly-report.schema.json` 新增**可选** `sections.instruction_attribution`
  （第 7 块）：观测到的响应码 → 命令号 → handler → 装载该码的指令地址/文本。
  字段：`schema/available/reason/codes_observed/image/command_table{source_table_addr,
  entry_count}/summary{codes_requested,codes_attributed,total_sites,handler_count}/
  attributions[]{code,status,site_count,handler_count,sites[]{insn_addr,insn,command,
  handler,dest_reg}}/method_boundaries/discipline/confidence/evidence_kind`。
  **换芯片零改动**：镜像路径、基址、码值全部来自调用参数，本块不内置任何芯片常量；
  缺镜像/缺基址/无 hex 码时以 `available=false` + `reason` 明确登记，不推测。
  **向后兼容**：该节为可选，未产出该节的既有报告仍合法。

### 未变更（明确声明）

- `schema_version` 常量仍为 `"0.2"`：本批全部为向后兼容新增。
- `state_label_semantics` 仍 `unconfirmed-v0.1`。

### Dashboard 影响

- **新增契约 3 个（均 `.json` 单实例，无新文件后缀）**：
  - `fault-effect` → "位翻转枚举页"：原指令卡片 + 物理假设徽标
    （`flip_mode`/`max_flips` 必须显示，否则读者会误解枚举范围）+
    变体表（按 `change_kind` 分组，`undecodable` 与 `nop_like` 单独标色）+
    `summary.by_change_kind` 分布图。**所有变体必须标 hypothesis**。
  - `fault-explanation` → "观测反解页"：观测/前置状态卡片 + **候选列表（多解时必须
    全部展示，禁止只显示第一条）** + 每条候选的 `flipped_bit_positions` /
    `mutated_insn` / `predicted_regs` / `match_score` + 仿真验证状态
    （`executed=false` 时要明确标"未仿真验证"）。
  - `observation-classification` → **五色分类徽标**（绿/品红/黄/青/红）：
    仅红色（`target_hit`）进"值得深挖"队列；青色需提示"打到别处"；
    品红需提示"毛刺过长"；`next_action` 可直接渲染为操作建议。
- **新增展示语义**：统计警示条（`statistical_caveats` 四项：
  非平稳/设计看不见窗口/稀疏标签不可靠/时间混杂）——数据非平稳时必须常驻提示；
  时间估算必带频率假设（v0.3 已定，此处重申）。
- **新增可选节（向后兼容）**：`anomaly-report.sections.instruction_attribution`
  → UI 可加"指令级归因"折叠面板（码 → 命令 → handler → 装载指令），
  未提供镜像时显示"未做指令级归因（缺镜像/基址）"而非空白。
- **契约版本变化**：`[0.4.0]` minor（向后兼容新增）；实例 `schema_version` 仍 `"0.2"`。

## [0.3.0] - 2026-11-09（逆向先行基线批次，已定版）

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
[0.4.0]: https://example.invalid/fi-contracts/0.4.0
[0.5.0]: https://example.invalid/fi-contracts/0.5.0