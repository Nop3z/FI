# 实机落地方案（PowerShorter + 目标芯片，2026-11-09 用户预告）

用户原话：「到时候我会让你真枪实战 我会给你实际的设备 powershorter 故障注入区间 其他的 notebook 需要你自己编写 bootrom 我也会给你 以及一些芯片手册 SDK 需要你自己将故障打出来」

## 一、设备能力（已核实 pyshort 库）

`power_shorter` 已安装可用，关键 API：

| 能力 | API |
| --- | --- |
| 打开设备 | `PowerShorter(port, timeout=1)` |
| 配置毛刺引擎 | `engine_cfg(engine, pattern, trigger_mode, pattern_repeat, trigger_edges)` |
| 布防 | `arm(engine, init_level=0)` |
| 软触发 | `soft_trigger(...)` |
| GPIO | `.gpio` |
| 继电器 | `.relay` |
| 引擎枚举 | `Engine.E1/E2` |
| 触发沿 | `TRIGGER_MODE.RISE / FALL` |

**最关键的单位事实（来自 `engine_cfg` docstring）**：

> `pattern` 是 `(level, duration)` 列表，**duration 单位是 10ns**，最多 8 段；`level=0` MOSFET 关（断开供电=毛刺），`level=1` MOSFET 开（正常供电）。
> 最后一段的 level 会保持到下次 arm。

**这条直接解释了 CSV 数据**：
- `pulse=2` → 毛刺持续 2×10ns = **20ns**（740,207/740,209 行都是它）
- `delay=2640..3190` → 触发后延迟 26,400–31,900 ns = **26.4–31.9 µs**

所以 CSV 的 `delay`/`pulse` **就是 PowerShorter 的 pattern 参数**，单位确定无疑（此前一直是 hypothesis，现在有设备文档支撑，可升 fact —— 但仍需实机复核一次）。

## 二、实机落地必须新建的东西

### 1. 硬件 Provider（`fi/providers/powershorter.py`）
- 实现既有 `CaptureProvider` 接口（detect/capture/normalize/validate）
- 注入侧：`inject(delay_raw, pulse_raw)` → 构造 pattern → arm → 触发
- **单位换算必须显式**：raw → ns 用 `×10`，不得隐式
- 安全边界：电压/脉宽上限校验、失败重试上限、紧急断开

### 2. 目标通信层（`fi/hardware/uart_target.py`）
- 串口打开/复位/发命令/收响应
- 响应帧解析（复用已 fact 化的帧格式：`46 4C` magic + 码高16位）
- 超时与 HANG 判定

### 3. Notebook（用户要求我自己编写）
按新存档的 8-Cell 模板：
1. 加载固件与实验配置
2. 初始化 UART、连接设备
3. 设备复位与状态确认
4. 执行已批准的测试条件（参数窗口）
5. UART 数据采集
6. 实验数据结构化保存
7. 异常结果分析
8. 结果可视化与报告

### 4. 周期/时间对齐（关键缺口，实机可解）
此前"delay ↔ 仿真时间轴无法对齐"是纯离线死结。实机后有两把钥匙：
- **触发信号 → 示波器**：直接测 trigger 到目标指令的时间
- **扫描法**：delay 从小到大扫，找"第一个出现异常码"的边界点 = 该指令的执行时刻

## 三、实机接入前必须先做好的准备（我现在就能做）

| # | 准备项 | 为什么必须先做 |
| --- | --- | --- |
| 1 | **PowerShorter Provider 实现（含 mock）** | 设备到手即可用，不必现写 |
| 2 | **Mock 设备层**：用假 PowerShorter 跑通全流程 | 无设备也能验证代码路径 |
| 3 | **实验编排脚本**：给定窗口 → 扫描 → 记录 → 分类 | 实机时间宝贵，脚本必须稳 |
| 4 | **安全护栏**：电压/脉宽/次数上限、紧急停止 | 防止烧板子 |
| 5 | **结果分类器接入**（五色分类） | 边扫边分类，不事后补 |
| 6 | **Notebook 模板（8 Cell）** | 用户明确要求我写 |
| 7 | **基线记录模板**：无毛刺正常响应 | 没有基线无法判定"异常" |

## 四、需要用户提供（按重要性）

1. **目标芯片型号 + 目标板**（这决定 UART 引脚、波特率、复位方式、供电点）
2. **PowerShorter 串口号**（bench_list 当前显示 0 台）
3. **目标 BootROM**（已有 `<ROM_IMAGE>`，需确认是否同一颗）
4. **芯片手册/SDK**（用于确认 UART 协议、命令格式、错误码定义）
5. **"故障注入区间"的含义**：是指要打的参数范围（如 delay 27000–38000 ns），还是电路上的注入点？
6. **期望打出的效果**：是要绕过某个校验（如 ISP 权限），还是只要产生可观测异常？

## 五、纪律（不变）

- 实机数据 = `Captured State`，与仿真（`Simulated State`）严格分开标注
- 每个结论带 confidence；实机证实后才升 fact
- 危险操作（长时间毛刺、高电压）必须显式确认
- 原始日志与波形一律保留，不只留结论
