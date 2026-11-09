# 状态语义文档 v0.2.0（状态标签待确认；机制语义已正式确认）

状态说明分两层：
- **状态标签/错误码语义**：仍待确认（§1-§4 的标签与错误码 `meaning` 均为
  hypothesis/unknown 级候选，无 fact 级语义结论）；
- **异常机制语义**：已正式确认（§5，fact 级——S4 静态编码实测 + S10 仿真
  动态复现双证，lead 裁定机制类 claim CSV:not-applicable）。

数据源：`<DATASET>.csv`（740,209 行，原始只读）。
列：`state,delay,pulse,response,glitched,unexpected`。
证据标注：`[fact]`=实测/双证事实；`[hyp]`=候选归因（未证实）；`[unk]`=未知。

## 1. state 列（原始标签，5 种）

| 原始标签 | 行数 | response 列分布 | delay(raw) 范围 | 候选解释（[hyp]） |
| --- | --- | --- | --- | --- |
| `FL` | 646,289 | 全为 `0x<CODE_A>` | 2640–3190 | **帧 magic 候选**：错误响应帧头两字节即 ASCII `'F','L'`（0x4C46，见 §2）；携码路径 = 认证/流程失败默认返回码 0x<CODE_A> |
| `HANG` | 86,464 | 空（无响应） | 3130–3190 | 待确认（疑似无响应/挂起，无新证据） |
| `SUCCESS` | 4,616 | 空 | 3130–3190 | 成功帧候选：`OK` magic 帧（见 §2）；`unexpected=OK` 与成功帧 'OK' 前缀吻合 |
| `UNEXPECTED` | 2,834 | 见 §3 错误码表 | 3130–3190 | 非预期错误码集合（逐码候选见 §3） |
| `Fake_Success` | 6 | `0x<CODE_D>`×5 / `NONE`×1 | 3145–3182 | 0x<CODE_D> 的 5 行已精确归因（S9）；`NONE`×1 待确认 |

注意：`Fake_Success` 中的 `NONE` 与 `HANG` 的空串是不同的原始字面量，不做合并解释。

## 2. 响应帧格式候选（[hyp]，S4 推理链，**等 sim 产出真实帧，不在 v0.2.0 确认批**）

来源：`target-chip.yaml` error_codes.channel.frame_format_candidate。

| 帧型 | 格式候选 | 说明 |
| --- | --- | --- |
| 错误帧 | 4 字节 = `'F','L',code_lo,code_hi`（数值 `(code << 16) \| 0x4C46`，小端） | 0x4C46 = ASCII 'FL'；`FL` + 错误码 → CSV state=FL、response=0x<CODE_A> 等的候选解释 |
| 成功帧 | 4 字节 = `'O','K',0x00,0x00`（`(0 << 16) \| 0x4B4F`） | 0x4B4F = ASCII 'OK' |
| 文本变体 | 纯文本 2 字节 `'OK'` 发送路径（rom+0x1408 引用后 `c.li a1,2`） | 上位机解析层差异待确认 |

发送函数候选：共享 0x<ADDR>。物理接口（UART 编号/波特率）待确认。

**对 Dashboard 的含义**：`FL`/`OK` 是帧 magic 字面量的候选来源——展示层文案
不得据此改写为业务语义（如"失败/成功"），仍按字面量展示。

## 3. 错误码字面量（state=UNEXPECTED 及关联，12 种，长尾闭环）

代码命中标注：`[fact]` 的静态命中 = ROM 装载指令实测（chip-profile 与
exp-analysis 独立扫描交叉核对，S9 逐字节一致）。`meaning` 全部 hypothesis/unknown。

| 字面量 | CSV 出现 | delay(raw) 范围 | 静态命中 | meaning 候选（v0.1.1 起） |
| --- | --- | --- | --- | --- |
| `0x<CODE_A>` | 646,289（FL 全部） | 2640–3190 | 2 处 [fact] | **[hyp]** 认证/流程失败默认返回码：条件检查失败→装载 0x501→发送函数携码返回；ROM/CSV 双方独立归因一致；待仿真注入复现后升 fact |
| `0x<CODE_B>` | 2,676（UNEXPECTED） | 3130–3190 | 11 处 [fact] | **[hyp]** 命令字段校验失败类通用错误码；语义待仿真复现 |
| `0x<CODE_C>` | 57（UNEXPECTED） | 3130–3190 | 2 处 [fact] | [unk] 有明确错误路径，与 0x<CODE_E> 命中同区域同函数簇，疑同族 |
| `0x<CODE_D>` | 53 UNEXPECTED + 5 Fake_Success | 3131–3190 | 3 处 [fact] | **[hyp]** 响应帧 16 位状态字段值：栈帧构造块内半字字段，与帧格式候选吻合 |
| `0x<CODE_F>` | 16（UNEXPECTED） | 3133–3186 | 0 处（双方零命中互证） | [unk] 可能查表/计算生成 |
| `0x0001` | 14（UNEXPECTED） | 3133–3186 | 无法归因 | [unk] 待结合响应帧字段定位 |
| `0x<CODE_G>` | 11（UNEXPECTED） | 3141–3179 | 0 处（双方零命中互证） | [unk] |
| `0x0140` | 3（UNEXPECTED） | 3142–3151 | 0 处（仅偏移量噪声） | [unk] |
| `0x<CODE_E>` | 1（UNEXPECTED） | 3143–3143 | 11 处 [fact]（S9 新发现） | [unk] 与 0x<CODE_C> 疑同族 |
| `0x0006` | 1（UNEXPECTED） | 3190–3190 | 通用装载 | [unk] |
| `0x<CODE_H>` | 1（UNEXPECTED） | 3131–3131 | 0 处（全镜像无踪迹） | [unk] 疑注入扰动随机输出/协议外噪声（'write' 日志串地址巧合已登记防混淆） |
| `0x6000` | 1（UNEXPECTED） | 3168–3168 | 0 处（双方零命中互证） | [unk] |

长尾合计核对：2,676+57+53+16+14+11+3+1+1+1+1 = 2,834 = UNEXPECTED 总数
[fact]，S9 归因闭环。

## 4. glitched / unexpected 列原始取值与 responded 判定

- `glitched`：`glitched`（全部行）或空串。语义**待确认**；契约转写为
  `glitched_raw` 原样保留。
- `unexpected`：`OK` / 错误码字面量 / `NONE` / 空串。语义**待确认**；
  `OK`×4,616 与成功帧 'OK' magic 候选吻合（§2）。
- **responded 机械定义**（2026-11-09 lead 终审，观测级机械事实，实现单一来源
  `fi.loop.records.has_response`，csv_replay/loop 编排共用）：
  `responded = True` 当且仅当**数据源记录了响应 token**——response /
  unexpected 任一列非空（且非 `unknown`）即 True；两列均空记 False。
  该字段**不是**解释级结论（"芯片是否真的发了响应"）：`'NONE'` 行
  （Fake_Success×1，response/unexpected 双列均为 NONE 字面量）按定义记
  True——零特例（特例就是隐藏的语义判断）；'NONE' 的语义归属
  （上位机 harness 占位 vs 设备文本）维持 **[hyp]**，作为边界案例登记于此，
  解释级结论永远走 evidence 分级，不进布尔字段。

## 5. 异常机制语义（正式确认批次，[fact]，target-chip.yaml r0.4.0 / 契约 v0.2.0）

升级依据（lead 裁定）：机制类 claim 无 CSV 观测通道（CSV:not-applicable），
**S4 静态编码实测（可重放反汇编）+ S10 sim-engine 仿真动态复现** 双方一致即
fact。以下每行均可重放验证（反汇编偏移逐条核对 / runs/2026-11-09 仿真运行件）。

| 机制结论（[fact]） | 内容 |
| --- | --- |
| Trap 入口 CSR | mtvec（CSR 地址 0x305；`csrw mtvec` 编码实测 rom+0x18 / rom+0xC6） |
| Trap 入口基址 | **0x<ADDR>**：静态推导 + 仿真复现写入 0x<ADDR> 后 trap 正常进入 handler（S10 逐字复现 Trap_Handler/mcause=00000005/Load access fault 诊断打印） |
| mtvec 低位写入观测 | install 值低 2 位 0b11（0x<ADDR>）与 0b10（0x<ADDR>）均被硬件接受且正常进入 trap；**低位模式语义解释仍 [hyp]**（非标准 MODE 编码，待逆向） |
| Handler 现场保存 | 固件全寄存器**软件保存**帧：38 寄存器 = 18 GP + 20 FP，帧 144 字节（`c.addi16sp sp, ±0x90`）；完整偏移表（sp+0x00 ft11 … sp+0x8C ra）见 target-chip.yaml exception.context.layout；gp/tp/sp/s0-s11 未保存（显著特征） |
| mcause / mepc 读取 | mcause rom+0x3FAA、mepc rom+0x3FF8（编码实测）；mcause 读取后 `andi 0x3FF`（10 位掩码——非标准高位中断判断方式，该核 mcause 位宽情报） |
| ecall 类处理 | mepc+=4 跳过异常指令后回写 mepc，最后 mret（rom+0x400A-0x400C、rom+0x3F56 实测） |
| CSR 地址表 | mstatus 0x300 / mtvec 0x305 / mepc 0x401 / mhartid 0xF14（编码实测）；**各 CSR 语义解释仍 [hyp]** |
| 诊断打印通道 | `Trap_Handler`、`mcause=%08x`、`mepc:%08x`、`Cause num=%d` 字符串区实测（rom+0x14C74/0x14D60/0x14D64 等），S10 仿真打印逐字复现 → **异常时 ROM 自带诊断输出可作为捕获信号源**（fault-observation 三层观测的 trap 层落地依据） |

**仍为 [hyp]，不在本批确认范围**：mcause cause 名称映射表（cause↔字符串，
待仿真异常注入复现）；mtvec 低位模式语义；复位向量 0x<BASE>；ISA 族/xlen/
扩展集（i/m/c，+f 候选强化）；§2 帧格式（'FL'/'OK'，等 sim 产出真实帧）。

**对 Dashboard 的含义**：异常捕获链路（trap 入口 → 全寄存器保存 → 诊断打印）
已是双证事实，"Trap 捕获"观测通道可按 fact 展示（可用性徽标）；cause 名称
映射与帧格式仍标"候选"。

## 6. 单位假设（影响 delay/pulse 的一切解释）

- 「1 raw = 10 ns」是**工作假设**（未证实）：用户示例窗口 27000–38000ns
  与数据 2640–3190 范围按 10 倍换算吻合，但无实验脚本佐证。
  §3 的 delay_raw_range 均为**原始刻度** [fact]，不受该假设影响。
- 契约表现：`raw_delay/raw_pulse` 为事实（observation）；
  `delay_ns/pulse_ns` 确认前一律 `unknown`；
  `unit_assumption.evidence_level = "hypothesis"`。

## 7. 消费方规则（Dashboard/Web 团队）

1. 标签与错误码一律按字面量展示；候选归因可作悬浮提示，但必须带
   "候选（未证实）"标识与 confidence。
2. `state_label_semantics = "unconfirmed-v0.1"` 的数据集合上仍显示全局
   "状态语义未确认"徽标；§2 帧格式候选不改文案（FL≠"失败"）。
3. [hyp] 级候选结论与 [fact] 观测统计视觉分层；§5 机制结论可按 fact 展示
   （含"Trap 捕获可用"通道徽标）。
4. 语义正式确认后：修订本文件（标签→语义映射定稿）+ CHANGELOG 记录
   （契约版本化走 docs/contracts/CHANGELOG.md，v0.2.0 起实例 schema_version="0.2"）。

## 8. 变更记录

- v0.2.0（2026-11-09 第四轮，契约 minor bump）：新增 §5 异常机制语义正式确认
  （mtvec 入口/0x<ADDR> 基址/38 寄存器帧/10 位 mcause 掩码/ecall +4/诊断打印
  通道，S4+S10 双证 fact）；§7 消费方规则更新；实例 `schema_version` 0.1→0.2。
  **FL/OK 帧格式保持 [hyp]，不在本批。**
- v0.1.1（2026-11-09 第二轮，target-chip.yaml r0.2.0 + S9 交叉验证）：新增 §2 帧格式
  候选；错误码表 9→12、UNEXPECTED 长尾闭环；全部码补 delay_raw_range；
  responded 机械判定规则（§4）。无 fact 级语义变更，无版本 bump。
- v0.1（2026-11-09）：初始发布；全部语义"待确认"，仅登记原始字面量与分布事实。
