# ViewViewView 架构契约 v1.0

状态：已批准，团队以本文档为唯一实现依据。
维护人：架构师（Lead）。修订须经 Lead 同意并递增版本号。

## 0. 基本盘

- 产品名 `ViewViewView`，Python 包名 `viewviewview`（PEP 8 全小写），版本 `0.1.0`，MVP 目标：FaultViz（v1.1.0，gitee.com/osr-tech/faultviz）的**免 JVM 兼容重实现**。
- 决策记录（已与项目所有者确认）：
  - D1 零 JVM/JDK，纯 Python 后端。
  - D2 显示形态：JupyterLab 内嵌，anywidget 单文件前端。
  - D3 协议：MulanPSL-2.0。
    - 补充裁定（2026-10-19，项目所有者确认）：GitHub 远端初始提交中的 MIT LICENSE 文件将在 M4 由文档工程师替换为 MulanPSL-2.0 官方全文；pyproject 的 license 表达式为 `MulanPSL-2.0`；README 需标注并附官方链接 http://license.coscl.org.cn/MulanPSL2 。
  - D4 支持 Python ≥ 3.9。
  - D5 配色：深色（Deephaven 深色主题基调）。
  - D6 **Clean-room**：所有实现依据本契约，**禁止阅读** `D:\project\faultviz_reference\` 下任何源码。缺口与本契约冲突一律走 §9 流程。
  - D7 与 FaultViz 的有意偏差（README 中向用户声明）：`start_view_service` 变为可选 no-op；明细窗默认深度 200 行；`plot/csvplot` 中 pygwalker 为可选依赖；新增可选 `columns=` 扩展参数。
  - D8 字段自定义扩展：`ViewWidget(..., columns=...)` 支持映射 `{name: int|float|str}`（显式类型）或名称序列（类型由首条记录推断）；未传时保持 FaultViz“首行定 schema”行为。预声明 schema 时 `show()` 可渲染带表头的空表骨架。
  - D9 CSV 默认文件名 = 控件创建（实验开始）时刻：`YYYYMMDD-HHMMSS.csv`，同名冲突追加 `-1`；仍支持 `csv_path=` 手动命名（自动创建父目录）。
  - D10 视觉：深色主题；字符串字段文字纯白 `#ffffff`；上窗计数与 `delay`/`pulse` 使用 FaultViz 的 positive-number 绿色，默认 `#19ff25`；`errcode` 等其他数值列保持白色。绿色列由 `number_columns=` 控制，颜色由 `colors=` 的 `count`/`number` 控制。
  - D13 配色可自定义：`ViewWidget(..., colors={...})` 接受 `text/count/number/muted/background/panel/header/row_alt/accent/border/live` 十一个 key 的十六进制颜色；仅覆盖传入项，前端以 CSS 变量方式应用（不拼接样式文本）。
  - D11 列宽可拖拽：拖动表头分隔线调整列宽；相邻两列分担增量，最后一列向右扩展表格（容器横向滚动）。宽度按表（统计表/明细表）保存在视图状态中，跨实时刷新保持；拖拽期间暂缓 payload 重绘，释放后立即补上最新快照。
  - D12 紧凑列布局：表格默认按内容宽度排列（`width: max-content`，不再拉伸到面板整宽），上窗 `state` 与 `count` 相邻、明细各列紧贴（对齐 FaultViz 观感）；拖动表头分隔线在此基础上微调列宽。
- 参考工具链：核心依赖仅 `anywidget`；`pygwalker`/`pandas` 仅 plot 路径使用（extras）；打包 hatchling。

## 1. 包结构与文件所有权矩阵（防并行冲突）

| 路径 | 所有者 | 说明 |
| --- | --- | --- |
| `pyproject.toml`, `src/viewviewview/__init__.py`, `src/viewviewview/core.py`, `src/viewviewview/compat.py`, `scripts/smoke_core.py`, `.gitignore` | A 核心库 | M4 时文档工程师只可以改 pyproject 的 readme/keywords 元数据 |
| `src/viewviewview/panel.py`, `src/viewviewview/static/index.mjs`, `src/viewviewview/static/styles.css`, `dev/preview.html` | B 展示 | 静态前端风格与载荷渲染 |
| `tests/**` | C 测试 | 契约一致性 + 压测；可在 `docs/BUG_REPORT.md` 提缺陷清单，不直接改 A/B 文件 |
| `README.md`, `LICENSE`, `example.ipynb` | D 文档 | MulanPSL-2.0 全文来自官方文本 |
| `docs/ARCHITECTURE.md` | Lead | 契约本体 |
| `docs/OPEN_QUESTIONS.md` | 全员追加 | 见 §9 |

## 2. 数据模型（核心不变式）

- 单实例 schema：首个合法 `update(**kwargs)` 的 kwargs 顺序即列集列序。仅接受**精确类型** `int` / `float` / `str`（`type(v) is T`；bool、numpy 标量一律不匹配）。此后每行都必须键集一致、类型逐一精确匹配；**键的传入顺序不敏感**（与 FaultViz 的 `_check_columns` 行为一致；CSV 始终按冻结的 schema 列序落盘）。
- 一行数据同时流入两条通道：
  1. **CSV 通道（权威）**：先于一切显示工作写入；失败则视同致命。
  2. **内存通道**：`counts`（仅 str 列的 `dict[str,int]` 计数，覆盖本实例写入的每一行；可无限增长，属预期）与 `ring`（最近 N 行的 deque 环形缓冲，N 由 live_rows/展示深度控制）。
- 线程安全：`update/flush/close` 必须可在工作线程并发调用（RLock 保护）。UI 同步通过 **Syncer** 合帧，永不阻塞调用方。

## 3. 公开 API 契约（与 FaultViz 逐条对齐）

### 3.1 `start_view_service(port=12345, max_heap="2g") -> None`
No-op：校验后记录日志 `"Deephaven service not required; live rendering is local"` 并返回。多次调用、任意参数不得抛异常。为兼容保留签名（接受任意 port：int 类型校验与非负校验；max_heap 接受 str 或 None）。

### 3.2 `ViewWidget(csv_path=None, display_limit=None, flush_every=1, live_rows=None, fsync=False, columns=None, colors=None, number_columns=None)`
构造校验（语义/错误消息与 FaultViz 相同）：`display_limit`、`live_rows` 须为非负 int 或 None，否则 `ValueError("limit must be a non-negative integer or None")`；`flush_every` 须为正 int，否则 `ValueError("flush_every must be a positive integer")`；`fsync` 须为 bool，否则 `ValueError("fsync must be a bool")`。
`columns`（向后兼容扩展）：`None` = 首行定 schema；`Mapping[str, int|float|str]` = 列名/列序/类型全部显式；序列 `[name, ...]` = 仅固定列名/列序，类型由首条合法记录推断。非法输入（空、重名、非字符串名、非 int/float/str 类型）抛 `ValueError`。
`colors`（向后兼容扩展，D13）：`Mapping[str, str]`，key ∈ `text/count/number/muted/background/panel/header/row_alt/accent/border/live`，value 为 `#rgb`/`#rrggbb`；未知 key 或非法色值抛 `ValueError`。仅覆盖传入项，其余用默认配色。`count` 控制上窗计数，`number` 控制 `number_columns` 指定列的颜色，两者默认都是 `#19ff25`。
`number_columns`（向后兼容扩展，D10）：`Sequence[str]`，默认 `("delay", "pulse")`；只有这些列使用 `number` 颜色，其余数值列（如 `errcode`）保持白色。传空序列表示不高亮任何明细列。
属性：`csv_path -> str`（绝对路径；默认在实例化时按起始时间生成 `YYYYMMDD-HHMMSS.csv`，文件在首条合法记录时才创建），`rows_written -> int`，`_column -> Dict[str, Optional[type]]`（FaultViz 兼容只读快照：列名 → 冻结类型；预声明但尚未定型的列为 `None`）。
上下文管理器协议 + `close()` 幂等可重入。

#### `update(**kwargs) -> bool`
算法（序号即执行顺序）：
1. 若 CSV 曾失败：`raise RuntimeError("CSV recording previously failed; create a new widget")`。
2. `first_row = schema 未定`。首行 kwargs 为空 → 失败分支。
3. 校验：首行后每行要求 `len(kwargs)==len(schema)` 且键名逐一存在且精确类型一致。失败 → 记录 `logger.error("record names/types mismatch; supported types: int, float, str")` 并 **return False，不写 CSV，不进内存通道**。
4. 首行通过则固化 schema（顺序 = kwargs 插入顺序）。
5. CSV 落盘：懒打开文件；首行写 header。默认路径生成规则：CWD 下 `viewviewview-{YYYYmmdd-HHMMSS-ffffff}.csv`，冲突则追加 `-1`、`-2` 递增。显式 `csv_path` 打开既有文件时：header 与 schema 不一致 → `ValueError(f"CSV header mismatch for {path}: expected {expected!r}, found {header!r}")`；文件末字节非 `\n` → `ValueError(f"CSV has an unfinished last record: {path}; inspect the file before resuming or choose a new path")`。编码 UTF-8，`csv.writer` 默认方言，追加模式。**任何 CSV I/O 异常**：`_csv_failed = True`，`logger.exception("CSV recording failed; stopping instead of dropping results")` 后原样 raise。
6. `rows_written += 1`，维护 counts/ring。
7. 通知 Syncer（合帧节流，调用方零等待、零异常）。
8. `return True`。

flush 语义：每 `flush_every` 条 pending 后自动 `flush()`；`flush()` 刷新 pending 且 `fsync=True` 时额外 `os.fsync`。写失败后不得静默续写。

#### `show(state="state", limit=None, full=False) -> None`
- 无数据且未预声明 schema（`rows_written==0`）：`logger.info("No data recorded.")`，不显示任何面板。
- 已通过 `columns=` 预声明 schema 但尚无数据：渲染带表头的空表骨架（上窗计数为空），便于注入开始前确认字段。
- 渲染：实例化 `VvvPanel`（§4.2）并 `IPython.display.display`；非 IPython 环境 `logger.warning("No IPython display environment available")`，不抛异常。
- 有效 limit：`limit is None and not full` 时取 `display_limit`，否则取 `limit`（`0` = 只显示上窗分类计数）。`full=True` 显示完整内存窗口。
- 分类列 `state` 不在 schema 中 → 面板 payload 置 `state_key=None`，上窗空态（faultviz 侧为隐藏计数表，等效）。
- 多次调用 → 多个面板实例同时在线，均接收后续推送。

#### `plot(state="state", limit=None, full=False) -> None`
- 无数据 → 同 show 日志。CSV-only 模式（`live_rows==0` 或无面板数据）→ `flush()` 后走 `csvplot(self.csv_path, ...)`。
- 否则优先 `pygwalker`（传 reversed DataFrame）；pygwalker/pandas 缺失 → 降级 `csvplot`，再缺失 → `logger.error("pygwalker is not installed; install viewviewview[plot] or use csvplot")`，不抛异常。

### 3.3 `csvview(csv, state="state", limit=None, full=False) -> None`
- `limit is None or full` → 读全量；否则 O(limit) 尾窗扫描（deque(maxlen=limit)，行字段数与 header 不符 → `ValueError(f"Malformed CSV record {i} in {path}")`）。
- 非法 limit → 同 §3.2 ValueError。文件不存在 → FileNotFoundError 自然抛出。
- 有 `state` 列 → 上窗计数 + 下窗明细（最新在前）。
- 空数据 → `logger.info("No data recorded in %s", csv)`。

### 3.4 `csvplot(name, limit=None, full=False) -> None`
- `limit==0 and not full` → `logger.info("CSV plot disabled; records remain in %s", name)` 返回。
- 尾窗逻辑同 §3.3；默认全量 → `pd.read_csv` 后依参考实现语义**逆序**传入 pygwalker；无 pygwalker → 降级为显示明细面板或日志提示，不抛异常。

### 3.5 日志与包初始化
包级 logger `viewviewview`，INFO 级，控制台 handler，格式 `%(asctime)s - %(name)s - %(levelname)s - %(message)s`。`__init__.py` 以 **PEP 562 `__getattr__` 懒导出**`ViewWidget/ViewViewView=ViewWidget` 别名、`start_view_service/csvview/csvplot` 及 `panel.VvvPanel`（ noqa 保护，为面板缺失时留余地）。

## 4. 内部设计

### 4.1 `core.py` — A 实现
`ViewWidget`（§3.2 全部）+ `_TailReader`（尾窗扫描，O(limit) 内存）+ **`Syncer`**：
- `attach(panel)` / `detach(panel)` / `wake()`；内部 `threading.Timer`（daemon）推迟 50ms 合帧；到期时在锁内快照 payload（§4.3）逐面板 `panel.payload = snapshot`。
- 任何 Syncer 异常吞掉并 debug 日志，绝不反噬 update()。
- `close()` 时 detach 全部面板。

### 4.2 `panel.py` — B 实现
`class VvvPanel(anywidget.AnyWidget)`：
- traits：`payload: Dict(sync=True)`、`theme: Unicode("dark", sync=True)`、`colors: Dict(sync=True)`（用户配色覆盖，D13）、`number_columns: List(Unicode, sync=True)`（使用 number 颜色的列，默认 `delay`/`pulse`）、`_esm`/`_css`（import 时读 `static/index.mjs`、`static/styles.css` 生成）。
- 不含任何业务逻辑；只按 §4.3 渲染。
- `anywidget` 缺失时 `panel.py` 可被 import 但实例化 raise `ImportError`；`__init__` 懒导出兜底。

### 4.3 载荷契约（跨 A/B 的冻结接口）
```json
{
  "columns":  [{"name": "delay", "type": "int"}],   // 仅用户列；type ∈ int|float|str
  "state_key": "state",                             // null = 无分类列，上窗空态
  "counts":   {"PASS": 123},                        // 本实例全量计数，key 为 str
  "rows":     [[1234, 50, "ok", 0]],                // 最新在前；深度 = min(有效limit或live_rows或200, 2000)
  "total":    100000,                               // rows_written
  "window":   200,                                  // 本次 rows 深度
  "version":  1000                                  // 单调递增
}
```
CSV 值类型：int/float 原样，str 原样；`state_key` 对应列值以 `str()` 强转为 key。

### 4.4 前端规格 — B 实现（Deephaven 深色基调）
- 布局：单容器两窗。表格**按内容紧凑排列**（不撑满面板，`state` 与 `count` 相邻，明细列紧贴），上窗“分类统计”（表头 `state 桶 | count`，高度自适应≈150px），下窗明细（schema 列，sticky 表头，斑马纹，最新行置顶）。数字等宽 `font-variant-numeric: tabular-nums`。
- 主题 tokens（styles.css `.vvv-root` 变量，Deephaven 深色近似）：`--vvv-bg:#1c2126; --vvv-panel:#232931; --vvv-header:#2b323a; --vvv-row-alt:#20252b; --vvv-fg:#ffffff; --vvv-fg-dim:#8b95a1; --vvv-accent:#3d6fe0; --vvv-border:#333b45; --vvv-live:#2ea043; --vvv-count:#19ff25; --vvv-number:#19ff25;`。字符串字段为纯白；上窗计数使用 `--vvv-count`，明细中 `number_columns` 指定列（默认 `delay`/`pulse`）使用 `--vvv-number`；其余数值列保持白色。覆盖项以 inline CSS 变量应用。
- DOM 构造**只用 textContent/createElement**，禁 innerHTML（载荷字符串不可信 = 防注入）。
- 列宽拖拽（D11）：每个 `<th>` 右侧带 8px `col-resize` 手柄；首次拖拽冻结当前列宽（`table-layout: fixed` + `<colgroup>` 像素宽度），相邻列分担增量、末列扩展表格；宽度按表存储在视图状态（`counts` / `detail`），实时重绘后自动恢复；拖拽期间挂起重绘，`pointerup` 后补最新帧。拖拽时给根节点加 `vvv-root--resizing`（shadow DOM 内锁定 `col-resize` 光标与禁止选中）。
- 渲染性能：≤200 行全量重绘 + DocumentFragment，无虚拟化框架、零 npm 依赖、纯单文件 ESM。
- `dev/preview.html`：静态 mock（含 state/delay/pulse/reply/errcode 示例载荷、≥30 行），浏览器直开可独立预览双窗效果（用于无需 Jupyter 的视觉验收）。

## 5. CSV 格式规范（与 FaultViz 二进制级兼容）
- UTF-8；`csv.writer` 默认 dialect（`,` 分隔、`"` 引用、`\r\n` 行尾）；首行 header = 列名原样；值顺序 = schema 顺序；无索引列。
- 默认文件名：控件创建时刻 `YYYYMMDD-HHMMSS.csv`（同名冲突追加 `-1`、`-2`）；`csv_path=` 可手动指定相对/绝对路径，父目录自动创建。
- 验收基线：`viewviewview` 写出的 CSV 可被 FaultViz 的 `csvview`/`csvplot`（即 pandas/deephaven read_csv）无损读取。

## 6. 里程碑与验收

- M1 核心 + 兼容层（A）：`scripts/smoke_core.py`：1000 次 update < 1s（fsync=False, flush_every=100）；CSV 回读与内存 counts 一致；契约 §3.1–§3.2 全语义自检（含 `columns=` 预声明与起始时间文件名）全部 PASS。
- M1' 展示（B，与 M1 并行）：preview.html 视觉达标 + §4.3 载荷渲染契约满足。
- M2 集成（Lead）：`__init__` 懒导出联调、panel 与 core 挂通、console 干净。
- M3 测试（C）：全绿 + 压测：10 万行 CSV-only < 90s；MRI 增幅 < 40MB（live_rows=1000）；`update` 纯记录路径 p95 < 50µs；载荷 ≤ 250KB@200rows。
- M4 文档（D）：README（含 FaultViz 迁移指南）、example.ipynb（场景 1/2/3 + 自定义字段 + `state/delay/pulse/reply/errcode` demo）、LICENSE（MulanPSL-2.0 全文）、pyproject 上 readme/keywords 并成功构建 sdist+wheel。
- M5 验收（Lead + 用户）：双窗实机演示、FaultViz CSV 互通抽检、错误路径（坏 header/未结束行/类型漂移/线程并发）回归。

## 7. 编码规范
- Python 3.9 兼容，`from __future__ import annotations` 预置；公共 API 必须带类型注解与英文 docstring（风格与 faultviz 一致：简洁、以行为为准）。
- 行长 ≤ 100；标准库优先；禁重量级依赖入 core；异常优先 raise 原始异常或 ValueError，禁止裸 `except:`；`except Exception:` 仅允许在边界层且必须 log。
- ruff（line-length 100）+ pytest 为主工具链；测试命名 `test_<契约条目>.py`。
- 日志短语以契约原文为准，逐字一致（兼容 UX）。

## 8. 协作规则
- 成员不得改动他人所有权文件；契约缺口：先查 §7 默认值，再无 → `docs/OPEN_QUESTIONS.md` 追加（格式 `- [ ] <ID> <提出人> <一句话> <建议>`）并于交付报告中列出，**不得阻塞自选合理默认**。
- 交付报告固定四段：①文件清单 ②自检方法与结果 ③与契约的偏差/理由 ④遗留问题。
- 一切代码与文档不含 FaultViz 版权文本/代码；提及兼容时用引用性表述。
