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
默认前缀为 `dataset`。切换数据集：

```bash
# Windows
set FI_DATASET_PREFIX={DATASET_PREFIX}
python dashboard/app.py

# Linux
FI_DATASET_PREFIX={DATASET_PREFIX} python dashboard/app.py
```

## 数据源
看板从 `data/derived/` 与 `docs/contracts/` 读取契约与派生数据（经 `sync.py` 同步到 `dashboard/generated/`）。

## URL 参数（AI/自动化可编程）
`demo=1`（演示模式）/ `state=<标签>`（预置筛选）/ `limit`（1-500）/ `bin`（1-100）/
`poll_records|poll_activity|poll_histogram`（≥500ms）/ `color_*`（覆盖柱色）。

详见 `docs/reports/dashboard-update-20261111.md`。
