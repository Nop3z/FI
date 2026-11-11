# ViewViewView

> FaultViz 的免 JVM 兼容重实现——轻量、稳定、专为长时间故障注入实验打造。

## 仓库简介（一句话，可直接用于 Gitee/GitHub 简介）

- 中文：轻量稳定的故障注入实验实时记录与双窗可视化工具，FaultViz 的免 JVM 兼容重实现。
- English: Lightweight, JVM-free reimplementation of FaultViz — live dual-pane visualization for fault-injection campaigns.

## 项目描述（中文正文）

**ViewViewView** 是为硬件安全故障注入实验打造的实时结果记录与可视化工具。在一轮注入扫描中（动辄数万至数十万次注入），研究者最关心两件事：当前命中了哪些结果分类，以及最新一次注入的完整参数。ViewViewView 用**上下双窗**直观呈现：

- **上窗 · 分类统计窗**：按分类字段（默认 `state`，可指定任意 str 列）实时统计注入次数，如 `PASS: 8 932 / FAIL: 41 / TIMEOUT: 12`；
- **下窗 · 结果明细窗**：滚动展示注入详细参数——`delay`、`pulse`、`reply`、`errcode` 等，最新一次置顶；列名、列数完全由实验脚本自定义：可在实例化时用 `columns=` 显式声明（列名 + `int`/`float`/`str` 类型，启动即显示空表头），也可由第一条 `update()` 自动定义 schema。

ViewViewView 是 [FaultViz](https://gitee.com/osr-tech/faultviz)（v1.1.0）的**独立兼容重实现**，针对其笨重易卡死的痛点彻底重构：

| 痛点（FaultViz） | ViewViewView 方案 |
| --- | --- |
| 内嵌 Deephaven JVM 服务（默认 2 GB 堆），启动慢、内存大 | 纯 Python 后端，零 JVM、零 JDK 依赖 |
| 每次 update 经 Python→Deephaven→JupyterLab 三层推送，任一环节堵即 UI 卡死 | 本地轻量渲染 + 高频更新自动合帧（coalescing），单点故障不阻塞实验循环 |
| 默认 live 表无限增长，大批量注入时渲染冻结 | `live_rows` 环形窗口限界，任意注入量级内存恒定 |
| 可视化故障可能影响实验主循环 | CSV-first：逐条先落盘后渲染，UI 失败自动降级为“仅记录”模式，数据绝不丢失 |

**接口兼容**：对齐 FaultViz 公开 API——`start_view_service`、`ViewWidget.update/show/plot`、`csvview`、`csvplot`，参数语义一致；CSV 落盘格式完全兼容（同一文件可用 FaultViz 复现/读取）。既有实验脚本只需一行改动即可切换：

```python
- import faultviz
+ import viewviewview as faultviz
```

实例化时可自由定义字段与 CSV 文件名：

```python
vt = faultviz.ViewWidget(
    columns={"state": str, "delay": int, "pulse": int, "reply": str, "errcode": int},
    csv_path="runs/my_experiment.csv",   # 可选；默认以实验开始时间命名
)
vt.show()
```

CSV 默认落地为控件创建时刻的文件名（如 `20261019-213005.csv`），也支持手动命名；表格列宽可拖动表头分隔线调整并在实时刷新间保持；界面采用 FaultViz 风格深色主题——白色字符串字段、绿色计数与 `delay`/`pulse` 数值列（默认 `#19ff25`，`errcode` 等保持白色），并支持 `colors=` / `number_columns=` 自定义。

**非目标**：ViewViewView 不试图重新发明故障注入攻击框架，不绑定任何注入设备与厂商；它只专注把“扫描参数 → 判定结果 → 记录 → 观察”这一环做得又轻又稳。

**适用场景**：电压毛刺、时钟毛刺、电磁脉冲、激光/光注入等各类“参数扫描 + 结果判定”形态的故障注入实验；亦适用于侧信道等需要批量记录结构化实验结果的场景。

## Project Description (English)

**ViewViewView** is a lightweight, stable, JVM-free reimplementation of [FaultViz](https://gitee.com/osr-tech/faultviz) for hardware-security fault-injection campaigns. It presents two live panes: a top **classification pane** counting injection outcomes by an arbitrary string column (default `state`), and a bottom **detail pane** showing the latest injection's full parameters (`delay`, `pulse`, `reply`, `errcode`, …) with fully user-defined columns. It keeps FaultViz one-second-switch API (`start_view_service`, `ViewWidget.update/show/plot`, `csvview`, `csvplot`) and its CSV on-disk format, so existing scripts switch with a single import change — while replacing the embedded Deephaven JVM stack with a pure-Python core: bounded ring-buffer tables, CSV-first crash-safe recording, and frame-coalesced lightweight rendering. No JDK, no 2 GB heap, no frozen UI at 100k+ injections.

## 兼容性声明

ViewViewView 为独立实现（clean-room）：仅对齐 FaultViz 的**公开 API 签名**与 **CSV 数据格式**以保障互操作，代码全部原创，不包含 FaultViz 源代码。FaultViz 由 Open Security Research（OSR）开发，ViewViewView 与其无隶属关系。

## 关键词 / 标签

`fault-injection` `hardware-security` `jupyterlab` `live-table` `csv` `visualization` `faultviz-compatible`
