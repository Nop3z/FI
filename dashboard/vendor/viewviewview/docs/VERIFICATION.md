# 验证报告 · v0.1.0

日期：2026-10-19　环境：Windows / Python 3.12.0 / anywidget 0.11.0 / pytest 8.3.3 / ruff（py39 target）

## M1 核心验收（`python scripts/smoke_core.py`）

15/15 通过，覆盖：

- 1000 次 `update()` 耗时 **2.6 ms**（契约上限 1 s）
- CSV 回读与写入序列逐字节一致（header、列序、值）
- counts / `rows_written` / `csv_path`（绝对路径）
- schema 语义矩阵：空 kwargs、bool、None、类型漂移、多余键、缺失键 → `False`；键序不敏感 → `True`
- 构造参数 ValueError 文案与契约逐字一致
- 既有文件 header 不匹配、末行未完成 → ValueError
- 空文件可正常续写且只写一次 header
- CSV I/O 失败后锁定实例，后续 update 抛 RuntimeError
- 尾窗读取（O(limit)）与畸形记录定位
- 8 线程 × 200 行并发，1600 行无丢失
- `start_view_service` 任意参数 no-op、不抛异常
- `live_rows=0` CSV-only 模式
- `columns=` 预声明字段（映射/序列两种形式）与类型校验
- 默认文件名 = 控件创建起始时间，文件在首条记录时创建

## M3 测试套件（`python -m pytest -q`）

**61 passed**，覆盖 `tests/test_core.py`、`tests/test_compat.py`、`tests/test_panel.py`、`tests/test_stress.py`。

压测实测：

| 指标 | 契约目标 | 实测 |
| --- | --- | --- |
| 10 万行总耗时 | < 90 s | **0.23 s** |
| `update()` p95 | ≤ 50 µs（CI 护栏 100 µs） | **2.2 µs** |
| 5 万行 + `live_rows=1000` 内存 | < 40 MB | **0.3 MB**（tracemalloc current/peak） |

## M4 打包与文档

- `python -m build` 成功产出 `viewviewview-0.1.0.tar.gz` 与 `viewviewview-0.1.0-py3-none-any.whl`
- wheel 内容核验：`core.py/compat.py/panel.py/static/index.mjs/static/styles.css/LICENSE` 全部包含
- `ruff check src tests scripts`：**All checks passed**
- README（安装、快速开始、自定义字段、兼容矩阵、差异声明、开发命令）
- `example.ipynb`：实时双窗、自定义列、CSV-only 回看、多线程四个场景；JSON 结构校验通过
- LICENSE 替换为 MulanPSL-2.0 中英双语全文；pyproject 元数据（license/keywords/classifiers/urls）就绪

## 视觉验收

`dev/preview.html` 经 Edge 无头渲染截图（`dev/preview.png`）：深色双窗、上窗 `state/count` 分类计数（绿色 `#19ff25`）、下窗白色字段文字明细、底部“已记录 942 行 / 当前窗口 34 行 · live”状态，符合 §4.4 规格。预声明 `columns=` 时可在无数据阶段渲染空表头骨架。

列宽拖拽通过 `dev/preview.html?resize` 在真实浏览器中合成一次拖拽后截图验证：`state` 列收窄、`delay` 列同步加宽，表头分隔线可见；宽度在重绘后保留。`dev/preview.html` 由 `scripts/build_preview.py` 从 `index.mjs`/`styles.css` 生成，避免预览页与源码漂移。

## 真实核心演示（`python scripts/build_demo.py --rows 5000`）

用真实 `ViewWidget`（`columns=` 预声明、CSV 落盘、环形窗口）跑 5000 次模拟注入，捕获实际发给前端的 payload 后渲染截图：

| 指标 | 实测 |
| --- | --- |
| 注入耗时 | 0.019 s |
| CSV | 95 135 字节 / 5 000 行 |
| 分类计数 | PASS 4 461 / FAIL 436 / TIMEOUT 103 |
| 明细窗口 | 1 000 行（`live_rows=1000`） |

效果图：`dev/demo-empty.png`（空表骨架）、`dev/demo-live.png`（真实运行）、`dev/demo-resize.png`（列宽拖拽）、`dev/demo-gallery.png`（三图总览）。

## JupyterLab 实机验证（2026-10-19）

在 JupyterLab 4.6.4 + ipywidgets 8.1.9 + anywidget 0.11.0 中实际执行 `dev/jupyter_demo.ipynb`（800 次注入），双窗、绿色计数与 `delay`/`pulse` 列（`#19ff25`，`errcode` 保持白色）、列宽拖拽均正常，截图见 `dev/jupyter-live.png`。此轮验证发现并修复了两个**仅在 Jupyter 环境暴露**的问题：

1. **anywidget 默认导出契约**：必须是 `export default { render }`；写成 `export default function render(...)` 时 anywidget 会以无参调用，前端报 `Cannot destructure property 'model' of 'undefined'`，widget 完全不渲染。已在 `index.mjs` 修正并加测试断言。
2. **样式挂载位置**：anywidget 在 JupyterLab 中可能把 `_css` 注入普通 DOM（而非 shadow root），`:host` 上的 CSS 变量不生效，导致白底黑字。配色 tokens 已从 `:host` 移到 `.vvv-root`，两种挂载方式下都保持深色 + 白字 + 绿色计数（可自定义）。

复现：`python scripts/capture_jupyter.py`（需要本地 JupyterLab 与 Edge）。

## 已知限制（均为契约内有意设计）

1. 多个 `show()` 面板共享“最后一次 show 的分类列与窗口深度”；FaultViz 亦以最后一次显示为准。
2. counts 仅对 `str` 列维护（分类列语义）；数值列不参与分类计数。
3. 明细窗默认深度 200 行（`limit`/`live_rows`/`full` 可覆盖）——为渲染稳定性有意与 FaultViz 的“默认全量”不同。
4. `columns=` 预声明的 schema 在实例生命周期内固定；需要增删列时请为新一轮实验创建新的 `ViewWidget`。
5. `plot()/csvplot()` 的交互分析依赖可选 `pygwalker`/`pandas`，缺失时降级为双窗表格。
6. 尚未发布 PyPI；安装走 GitHub。
7. 多次 `show()`（或重跑 cell 不清输出）会累积多个面板：每个面板自带 shadow DOM 与 comm 通道，且旧面板仍接收推送。长实验建议复用同一个面板，或对旧 widget 调用 `close()` 后再新建；详见下方“S1 内存优化”。

## S1 前端内存优化（2026-11-01）

**背景**：长时间高强度实验（约一周）后浏览器标签页内存持续增长，实测达 1.4 GB。专项排查结论：Python 侧无泄露（tracemalloc 稳态 0.26 MB）；主体来自前端两条路径——(a) 每帧 `clearChildren` 后全量重建 6048 个 shadow DOM 节点（depth=1000/5 列，20 帧/秒 ≈ 1.2 亿节点/小时的分配压力，V8 堆持续扩张）；(b) 累积的多个 `show()` 面板（僵尸视图）各自重建并接收推送。

**改动**（`index.mjs`）：`renderPayload` 增量渲染——schema/状态列/高亮列集合不变时保留表骨架，仅原地更新 counts tbody、对齐 detail tbody 行数并逐格写变化的 `textContent`、更新 footer 文本；任一身份键变化则回退原全量重建路径。视图卸载（anywidget teardown）时释放 mounted DOM 引用。DOM 契约不变：单元格 class 与最终文本与全量重建完全一致。

**实测**（`python scripts/mem_baseline.py 3000 50 1000 5`，Edge 无头 + `--expose-gc`）：

| 指标 | 改动前 | 改动后 | 判定 |
| --- | --- | --- | --- |
| shadow 节点数（全程） | 每帧重建 6048 个 | **恒定 6048（drift 0）** | PASS |
| 每帧渲染耗时（mean） | 15.9 ms | **9.5 ms** | PASS（预算 13 ms） |
| 强制 GC 后堆漂移 | 持续爬升锯齿 | **-0.3 MB（回落基线）** | PASS（预算 5 MB） |

新增回归：`tests/test_stress.py::test_push_loop_memory_bounded`（持续 update+推送 2 s，Python traced < 5 MB、线程无累积）；套件全绿，ruff 通过。`dev/preview.html`、`dev/demo.html` 由脚本重新生成并保持视觉一致。

**S2/S3（同批落地，默认行为不变）**：

- `show(replace=True)`：显示新面板前关闭并脱离本 widget 的上一个面板，`close()` 亦回收当前面板——根治“多次 show()/重跑 cell 面板累积”；默认 `False` 保持 FaultViz 兼容行为。
- `ViewWidget(frame_delay=...)` / `Syncer(frame_delay=...)`：推送合帧间隔参数化（默认 0.05 s 不变，非法值抛 `ValueError`），供后续按场景调优。
- 版本号升至 **0.2.0**（`pyproject.toml` + `__init__.__version__`），保证 `pip install -U` 能真正拿到本批修复。

## S4 卡顿根因与 K 行位移优化（2026-11-04）

**现象**：内存稳定在 55~75 MB，但注入期间 FPS 从 120 掉到 75~83；另一台机器掉到 10 FPS。

**测量**（JupyterLab 4 + Edge，1000 行窗口、100 条/秒、20 秒，CDP `Performance.getMetrics`）：

| 指标（20 秒窗口累计） | 优化前 | 优化后 |
| --- | --- | --- |
| LayoutDuration（布局） | **4.80 s** | **1.14 s（-76%）** |
| TaskDuration（主线程忙） | 11.98 s | 7.33 s |
| ScriptDuration（JS 执行） | 0.13 s | 0.14 s |
| RecalcStyleDuration | 0.51 s | 0.71 s |
| 注入期间 FPS | 75~83 | **100~107** |

**根因**：payload 为“最新在前”，每帧新增 K 行（`100 条/秒 ÷ 20 帧/秒 = 5 行`）导致整张表错位；按索引逐格 diff 会把 1000×5 个单元格全部改写，每次写入都让表格布局失效。JS 本身只占 0.13 s，**瓶颈是布局（4.8 s）**，所以内存不高但帧率掉。

**修复**（`index.mjs: applyShiftedRows`）：用 `payload.total` 的增量算出本帧新增行数 K，逐格校验“新 rows[K..] == 旧 rows[0..]”后，改用一次 `DocumentFragment` 插入 K 行 + 从底部移除 K 行；校验不通过则回退原逐格 diff。`patchCountsTable` 同时改为原地更新文本。

**正确性**：`scripts/mem_baseline.py` 新增逐格断言——渲染后的 DOM 必须与最后一份 payload 完全一致（3000 帧：0 处不一致）；JS 单帧耗时 4.07 ms → **0.21 ms**。套件 69 项全绿。

## S5 Delay 统计面板（2026-11-10，v0.3.0 / v0.3.1 竖直版）

`ViewWidget(stats_bucket=100, ...)` 打开明细窗右侧的统计面板：delay 分桶（桶标签
`500-600` 形式）、两幅竖直柱状图（成功率 / HANG率）、横轴按 delay 时间轴左→右递增
（安全保护：超出 `stats_bars` 时从最旧一端截断，最新时间轴始终可见）、固定高度节点池；
柱内不放数字，精确值走原生 title 悬停提示（`2700-2800 · HANG 5/6 · 83.3%`）。

**实现要点（全部满足“内存管理/防卡顿”约束）**：

- 数据源 = CSV 本尊：每条被接受的记录在 `_record_stats_locked` 聚合（桶起值 →
  `[总数, 成功数, HANG数]`），滚出显示窗口的旧行继续参与统计；
- 前端节点池恒定：每图 `stats_bars` 个常驻列（fill/label），只在文字/提示变化时
  写 `textContent`/`title`、数值比较通过才写 `style.height`（px 柱高，自下向上
  生长）——不重排序、不重建；
- 推送节流：`stats_interval` 控制“每 N 帧 payload 才携带 `stats` 块”（show() 首帧必带），
  间隔帧 `stats` 缺席时前端沿用最近一次数据（`ctx.lastStats`），布局键不变、DOM 不动；
- 桶数封顶 512：超限自动把桶宽 ×2 并两两合并（`_coarsen_stats_locked`），payload 用新桶宽；
- 关闭（默认 `stats_bucket=0`）payload 无 `stats` 键，界面与 0.2.x 完全一致。

**验收**：套件 98 项全绿（22 个 stats 用例 + 自定义/悬停用例）；`scripts/mem_baseline.py`
默认开启 stats 面板（depth=1000，39 桶 > 30 柱、覆盖截断路径）：shadow 节点恒定
当前构建实测 6245（mode 1，两图 + 悬停浮层，drift 0）/ 6341（mode 2，三图，drift 0）、
mean 帧 0.4-0.5 ms、GC 后堆漂移 -0.3 MB、DOM 与竖柱时间轴逐条比对 0 处不一致
（含 label/悬停文本/px 高度/隐藏池）；`stats=0` 跑法同样通过（节点恒定 6048、无面板）。
7. Python 3.9 环境下 pip 会自动选择兼容的 anywidget 0.9.x（0.11+ 要求 Python ≥3.10）；本地实测环境为 Python 3.12 + anywidget 0.11，Python 3.9–3.12 的兼容性由 CI 矩阵持续验证。

**v0.5.0 增补（同一 S5 面板）**：新增 `stats_custom=`（用户自定义第三状态图，
用法同 `stats_success`/`stats_hang`）——设置后 payload 桶行带第 6 个计数、快照多一个
`custom` 键（仅 opt-in 时，未设置 payload 逐字节不变）；图表布局改为 2×2“象限”：
成功率（左上）/ HANG率（左下）同左列，自定义图表（用户指定的 #18097d 提亮为
#4d33ff；绘图区拉长一倍、贴底与 HANG率 齐平）独占右侧整列，三图靠拢比纵向堆叠省眼力。mem_baseline 新增 stats 模式 2
（400 帧、三图：节点恒定 6341——含悬停浮层节点、DOM 与 6 槽快照逐条比对 0 差异）；
套件 98 项全绿。

**v0.5.1 增补（同一 S5 面板）**：悬停任意柱条**即时**显示精确值浮层
（`500-600 · HANG 12/15 · 80.0%` 式）：每 pane 一个常驻浮层节点 + 两个委托监听，
只在鼠标事件时定位/显隐，实时分帧零参与（400 帧内存基线照旧 drift 0）；
精确值载体由原生 `title`（停留约 1 s 才出现）改为 `data-tip` + `aria-label`。

**v0.6.0 增补（同一 S5 面板）**：三幅图**全部改为分布口径**且**柱高按图内最高桶
归一化拉满**——柱高 = 该桶次数 ÷ 图内最高桶次数（最高桶撑满绘图区，低频状态
也看得清分布轮廓），悬停沿用真实占比（分母 = 该状态累计总数，含截断旧桶，
`1500-1600 · 成功 42/87 · 48.3%`）；50% 虚线随之成为“半峰”参考线。动机：真实
故障注入的非预期状态都是小概率事件，概率/占比直画会几乎全空。payload `stats`
块仍只存原始计数（高度/占比均由前端派生），无新增键；README 同轮精简为速查式。

**v0.4.0 增补（同一 S5 面板）**：统计面板**默认开启**（`stats_bucket` 默认 100，
`stats_bucket=0` 显式关闭并回到 FaultViz 原观感）——这是默认行为变更；针对迁移
用户的列名不一致场景，`show()` 在“面板开着但 state/delay 列不在 schema”时输出
一行 INFO 引导改 `stats_state=`/`stats_delay=`。界面侧统计面板右缘留 32px 边距
（16:9 全屏浏览器下不再贴屏幕边缘）。套件 92 项全绿（新增“默认开启 / 显式关闭
payload 一致”两用例）。

## 后续建议

- GitHub Actions 已配置（Linux/Windows × Python 3.9–3.12）
- 下一版：面板级独立窗口深度、浅色主题、PyPI 发布与 FaultViz 实例的 CSV 双向互通回归
