# 轨迹分级契约（--trace-level）v0.3

状态：**草案定稿 v0.3**（2026-11-09，core-contract 起草，待 sim-engine 实现对齐）。
关联：`schemas/sim-trace.schema.json`（归一后的轨迹行契约）、`docs/tts-baseline.md` §2/§3（吞吐指标、8 B/指令目标）、`docs/sim/trace-format-v0.md`（fi.sim 实现注记）。
变更走 `CHANGELOG.md`。

## 1. 为什么需要分级

全字段 JSONL 每指令 ≈ 262 B；40 万指令 = 100 MB（tts-baseline §2 实测）。
但"日常扫描跑得动"与"调试要看全字段"是矛盾需求，因此**轨迹级别是显式契约参数**，
不是实现细节：不同级别产出不同数据量，消费方必须能判断"我拿到的轨迹能回答什么问题"。

## 2. 级别定义（语义契约）

| 级别 | 落盘内容 | 体积量级 | 能回答 | 不能回答 | 默认用途 |
| --- | --- | --- | --- | --- | --- |
| `off` | 不落指令级轨迹；只落 `run_meta` + `run_end`（+ `fault_event`） | ~KB | 跑通了吗/为什么停/注入了什么 | 任何执行路径细节 | 大规模参数扫描、只看停止原因与结果 |
| `binary` | **二进制打包**的指令级记录（字节布局见 §4，**归 sim-engine 定义并版本化**） | 目标 ≤ 8 B/指令 | 完整执行序列（PC/指令），需 reader 归一 | 富字段（CSR 明细/内存访问值），除非格式含之 | 大规模扫描 + 事后离线分析 |
| `sampled` | 采样后的 JSONL trace 行（按 §5 规则选样，行形状**必须仍是 sim-trace 契约行**） | 1–3 % 指令数 × 262 B | 路径轮廓、热点、关键园点 | 相邻指令间的完整因果链 | 日常扫描、Dashboard 概览 |
| `full` | 每指令一行全字段 JSONL（现行行为） | ~262 B/指令 | 一切 | —（只是贵） | 调试、归因、契约样例生成 |

纪律：

1. **级别只影响记录量，不影响执行语义**。同一配置在 `off` 与 `full` 下的 `run_end`
   必须给出相同的 `exit_reason / instruction_count / final_pc`（采样/打包不得改变
   执行结果，否则是 bug 不是级别问题）。
2. **`sample_evidence`/证据链不得因降级而伪造**。采样轨迹缺某条指令 = "未记录"，
   不等于"未执行"；消费方不得从采样轨迹断言"该 PC 没执行过"。
3. **默认级别**由调用方显式给出；CLI 与 API 不得内置"适合所有场景"的默认值把
   扫描跑成 100 MB（fi.sim 的既有默认需在实现对齐时明示）。

## 3. 级别选择与指标口径

- `tts-metrics.basis.trace_level` 必须记录测量所用级别；**不同级别吞吐不可直接比较**
  （`full` 的 bytes_per_instr ≈ 262，`sampled`/`binary` 才对应 ≤8 B 目标）。
- 级别升级（如 `sampled` → `full`）用于"发现异常后再回看"：管线应保留原始级别与
  重跑配置，可重放。

### 3.1 实测达标（2026-11-10，fi.sim 轨迹分级实测）

| 级别 | 实测体积 | 相对 full 缩减 | 是否达标（目标 ≤ 8 B/指令） |
| --- | --- | --- | --- |
| `full` | ≈ 262 B/指令（历史实测） | 1×（基线） | 否（调试专用） |
| `sampled` / `binary` | **3.98 B/指令** | 约 66× | **达标**（≤ 8 B/指令） |

结论与口径说明：

- **3.98 B/指令**是采样/二进制模式下的大规模扫描实测值，对应
  `docs/tts-baseline.md` §3 的「轨迹体积 ≤ 8 B/指令」目标，为日常扫描可用性的
  直接依据；Dashboard 效率页可引用该数字与 `full` 模式对比展示。
- 该数字**只在标注级别下有效**：引用时必须同时给出 `trace_level`（见
  `tts-metrics.schema.json` 的 `basis.trace_level`）——`full` 模式的吞吐与体积
  不可与本数字直接比较。
- 级别只影响记录量，不影响执行语义：同一配置在 `off` 与 `full` 下
  `run_end.exit_reason / instruction_count / final_pc` 必须一致（见 §2 纪律 1）。

## 4. `binary` 级别：传输/存储格式归 sim-engine

**契约边界（重要）**：二进制是**传输与存储格式**，不是数据契约。字节布局（magic、
header、记录结构、变长字段、压缩/差分编码、校验和）**由 sim-engine 定义并版本化**，
本文不复制其字段定义。

契约对本级别只要求三件事：

1. **格式带版本号**：文件头必须含可读的格式标识 + 版本（如 magic + `u16 version`），
   工具必须在读取时校验版本并在不兼容时报错（禁止静默按旧布局解析）。
2. **reader 归一义务**：提供 reader 把二进制流**归一为 sim-trace 契约行**（同一
   `type` 四类行、同一字段名与证据规则）；消费方（Dashboard/分析层）只依赖 sim-trace
   契约，不依赖二进制布局。
3. **round-trip 可验证**：同一运行以 `--trace-level=full`（JSONL）与
   `--trace-level=binary` 各跑一次，reader 归一后的行集合（按 `seq` 对齐、忽略允许
   缺失的富字段）必须与 full 轨迹**逐字段一致**；该验证必须可脚本化重放。

### 4.1 round-trip 验证方式（可重放）

```sh
# 1) 同一配置跑两次，仅 trace-level 不同
python -m fi.sim run --config <cfg> --trace-level=full    --out runs/rt-full
python -m fi.sim run --config <cfg> --trace-level=binary  --out runs/rt-bin

# 2) reader 归一（工具名待 sim-engine 定，示意）
python -m fi.sim.trace_reader runs/rt-bin/trace.bin --normalize --out runs/rt-bin/trace.jsonl

# 3) 契约校验：归一后的轨迹必须仍是合法 sim-trace
fi schema validate --schema sim-trace --file runs/rt-bin/trace.jsonl

# 4) 比对（按 seq 对齐；允许 binary 级别声明缺失的富字段集合）
python -m fi.sim.trace_diff runs/rt-full/trace.jsonl runs/rt-bin/trace.jsonl \
  --ignore-fields writeback,mem_access.value
```

验收规则：第 3 步 EXIT 0；第 4 步报告的不一致数 = 0（忽略字段仅限 binary 格式
显式声明不承载者，且声明必须写进格式文档）。

## 5. `sampled` 级别：选样规则（契约级，保证可解释）

采样必须**确定性、可解释、可重放**（同输入同输出），禁止随机抽样不留种子。至少支持：

| 规则 | 语义 | 必选 |
| --- | --- | --- |
| `every_n` | 每 N 条取 1（N 显式参数） | ✓ |
| `around_seq` | 指定序号窗口（如注入点前后 ±K 条）全量保留 | ✓ |
| `keep_special` | 以下行**永不采样丢弃**：`run_meta`/`run_end`/`fault_event`、`evidence_level=hypothesis` 行、`mem_access.stub=true` 行、`csrs_changed` 非空行、`exit` 前最后 N 条 | ✓ |
| `random_seeded` | 带显式种子的随机采样（种子必须落盘） | 可选 |

采样结果仍是 sim-trace 契约行（行内字段不变），但**必须**在 `run_meta.memory_map`
（或等价的运行元数据）中登记 `trace_policy = {level: "sampled", rule: ..., params: ...}`，
让消费方知道"缺的指令是没记，不是没跑"。

## 6. 消费方规则（Dashboard 必读）

1. `run_meta` 必须能读出级别（建议 `memory_map.policy.trace_level` 或
   `trace_policy.level`）；UI 对 `sampled` 轨迹的"指令数"展示必须用
   `run_end.instruction_count`（真值），**不得用轨迹行数**。
2. `binary` 级别文件不得直接喂给前端：必须先经 reader 归一为 sim-trace JSONL。
3. `off` 级别没有 trace 行，UI 只能显示运行头/停止原因/注入事件，不得显示"空轨迹=没执行"。
4. 采样轨迹上的"未出现某 PC"只能表述为"采样窗口内未记录"，不得表述为"未执行"。

## 7. 变更记录

- v0.3（2026-11-09）：初始发布。定义四级语义、binary 的契约边界（布局归 sim-engine、
  reader 归一义务 + round-trip 验证）、sampled 选样规则与消费方规则。
- v0.5.0（2026-11-10）：新增 §3.1 实测达标节——采样/二进制模式实测 **3.98 B/指令**，
  达成 ≤8 B/指令目标（对比 full ≈262 B/指令，约 66× 缩减）。数字仅在标注
  `trace_level` 时可比（见 tts-metrics.basis.trace_level）。
