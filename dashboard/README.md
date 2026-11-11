# FI Dashboard（只读看板）

只读实验看板：无任何注入/执行/控制按钮，仅展示与筛选。

## 启动
```bash
cd <项目根>
python dashboard/app.py        # 端口 8765
```
或双击 `dashboard/start.cmd`。

## 数据集前缀（FI_DATASET_PREFIX）
看板读取的数据文件名以**数据集前缀**拼接（如 `<prefix>.state-counts.json`）。
默认前缀解析优先级：`FI_DATASET_PREFIX` 环境变量 → 扫描到恰有一个数据集时自动选中 → 兜底 `dataset`。
切换数据集（两种方式）：

```bash
# 方式一：环境变量（启动期默认）
set FI_DATASET_PREFIX=<DATASET>
python dashboard/app.py

# 方式二：URL 参数（运行期切换，无需重启，AI/自动化首选）
#   GET /api/datasets            枚举可用数据集与 active 前缀
#   /api/summary?dataset=<prefix>
#   /api/records?dataset=<prefix>
#   /api/histogram?dataset=<prefix>
#   页面：index.html?dataset=<prefix>
```
不合法前缀 → 400 `invalid_dataset`；前缀合法但数据文件缺失 → 404 `dataset_missing`（均含 `missing_reason`）。

## 数据源
看板从 `data/derived/` 与 `docs/contracts/` 读取契约与派生数据（经 `sync.py` 同步到 `dashboard/generated/`）。
注意：本导出**不含任何真实数据**；无数据时数据接口返回错误，前端自动降级为演示模式（页面底部有横幅声明）。

## URL 参数（AI/自动化可编程）
`demo=1`（演示模式）/ `state=<标签>`（预置筛选）/ `limit`（1-500）/ `bin`（1-100）/
`poll_records|poll_activity|poll_histogram`（≥500ms）/ `color_*`（覆盖柱色）。

详见 `docs/reports/dashboard-update-20261111.md`。
