# 参数窗口 → 仿真故障事件映射契约 v0.1

状态：**已与 sim-engine 对齐定稿**（2026-11-09）。变更走 `CHANGELOG.md`。
关联契约：`schemas/sim-trace.schema.json`（fault_event 行）、`schemas/campaign-record.schema.json`（params）。

## 1. 为什么需要显式映射

闭环输入的参数窗口是物理单位（**delay/pulse，单位 ns**，如 27000–38000ns）；
指令级仿真器内部没有真实时钟，只有**指令序号（seq）与周期**。
两边不能隐式换算——本文件把 `delay_ns / pulse_ns` 到仿真事件
（触发位置 / 作用宽度 / 动作）的映射定义为**显式可配置项**，
并在结果数据中保留假设标注（evidence_level）。

纪律：任何映射都是**工作假设**；未确认的换算不得影响 observation 级结论。

## 2. 映射总表

| 闭环参数 | 映射目标（sim-trace `fault_event`） | 模式 | 映射规则 | 默认 | 证据等级 |
| --- | --- | --- | --- | --- | --- |
| `delay_ns` | `trigger`（何时打） | `seq` | 触发值 = `int(delay_ns)`，即**第 N 条指令前触发**（N 从 0 起） | **是** | 映射本身是声明约定；效果观测= hypothesis |
| `delay_ns` | `trigger` | `cycle_estimate` | 触发值 = `int(delay_ns / ns_per_cycle)`，`ns_per_cycle` 必须显式提供（如芯片主频假设） | 否 | hypothesis（含频率假设） |
| `delay_ns` | `trigger` | `pc` / `every` | 引擎原生能力：PC 命中触发 / 每 N 条触发。由策略直接给触发值，不经 ns 映射 | 否 | 同上 |
| `pulse_ns` | `pulse`（打多宽） | `instruction_count` | 受影响指令条数 = `int(pulse_ns)`（宽度窗口内每条指令均受作用） | **是** | hypothesis |
| `pulse_ns` | `pulse` | `single_event` | 单事件注入，`pulse_ns` 忽略 | 否 | hypothesis |
| `pulse_ns` | `action.bit_width`（`flip_reg_bits`） | — | 翻转位宽 = `int(pulse_ns)`（脉冲越宽翻越多位，1–32） | — | hypothesis |

配置载体：`fi.loop.sim_injector.ParamMappingSpec`（trigger_mode / width_mode /
action_kind / flip_target_reg / ns_per_cycle / profile_ref）。
引擎层 `trigger.mode` 枚举 = `{pc, seq, cycle_estimate, every}`；
`action.kind` 引擎实现 = `{skip, flip_reg_bits}`，扩展预留 = `{reg_write, mem_write}`。

**轴泛化说明**（闭环调参空间不限于 delay/pulse）：本文件以 delay/pulse 为例
（当前数据集的两轴）；接口层面 `ParamWindow`/`ParamPoint`/`LoopStrategy` 对轴
完全泛化（任意 `axis_name`，单位显式进键名 `{axis}_{unit}`），experiment-scan
契约的 `window[].axis` 为自由字符串。新增轴（如波形形状、电压档位）时：
在 param-mapping.md 追加映射行 + CHANGELOG 记录（minor bump），
接口代码无需改动。

## 3. 数据集换算假设（raw ↔ ns）

历史 CSV（`<DATASET>.csv`）的 delay/pulse 是**原始刻度 raw**（2640–3190 / 2–6）。
「1 raw = 10 ns」是与数据范围吻合的工作假设（用户示例窗口 27000–38000ns），
**未经用户证实**。

- CSVReplayInjector 接收 `delay_ns` 参数点时必须显式构造 `ns_per_raw`
  （禁止默认值携带数据集假设）；换算 = `raw = round(ns / ns_per_raw)`，
  并在 `outcome.detail.unit_assumption` 写明
  `{"scale": "1 raw unit = 10 ns"}`，组装 CampaignRecord 时
  `params.unit_assumption.evidence_level = "hypothesis"`。
- 单位假设确认前，CampaignRecord.params 的 `delay_ns/pulse_ns` 保持
  `unknown`，只有 `raw_delay/raw_pulse` 是事实。

## 4. 一个完整例子

参数点 `{delay_ns: 3000, pulse_ns: 2}`，映射配置
`ParamMappingSpec(trigger_mode="seq", width_mode="instruction_count", action_kind="flip_reg_bits", flip_target_reg="a0")`
产出 fault_event（sim-trace 契约行形状）：

```json
{
  "type": "fault_event",
  "event_id": "fev-a1b2c3d4e5f6",
  "run_id": "run-20261109-000001",
  "campaign_id": "unknown",
  "trigger": {"mode": "seq", "value": 3000, "ns_per_cycle": "unknown"},
  "action": {"kind": "flip_reg_bits", "reg": "a0", "bit_width": 2, "bit_mask": "unknown", "new_value": "unknown"},
  "pulse": {"mode": "instruction_count", "value": 2},
  "applied": "unknown",
  "applied_at_seq": "unknown",
  "applied_result": "unknown",
  "evidence_level": "hypothesis"
}
```

引擎生效后回填：`applied=true`、`applied_at_seq=3000`、
`applied_result={"old_value":..., "new_value":...}`、`bit_mask="0x3"`。

## 5. 变更记录

- v0.1（2026-11-09）：初始发布；与 sim-engine 对齐（trigger.mode 合并枚举、action 定稿 skip/flip_reg_bits + 预留）。
