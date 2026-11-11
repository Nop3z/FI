# ViewViewView 可复用资产清单（REUSE.md）

> 上游：https://github.com/Nop3z/ViewViewView（本目录即完整克隆，HEAD `ef692eb`，v0.6.0）
> 用途：为 <PROJECT_ROOT> 的新 Web Dashboard 提供可直接复用的 CSV 读取、双窗渲染与 delay 分布图实现。
> 结论先行：**三项核心资产全部可直接复用**，无需重写。License 为 MulanPSL-2.0，义务见 §4。

---

## 0. 数据格式兼容性（已实测核对）

| 项目 | 本项目 (FI) | ViewViewView | 兼容性 |
|---|---|---|---|
| CSV 表头 | `state,delay,pulse,response,glitched,unexpected` | 任意 header（首行定义 schema） | ✅ 完全兼容，无需转换 |
| state 取值 | `FL` / `HANG` / `SUCCESS` / `UNEXPECTED` / `Fake_Success` | 任意字符串，由 `stats_success=` / `stats_hang=` / `stats_custom=` 三个参数逐字匹配 | ✅ 直接映射 |
| delay | int（如 2640） | int/float 均可分桶 | ✅ |
| CSV 尾行完整性 | 服务器异常退出可能产生不完整行 | `_TailReader` 遇坏行抛 `ValueError` 指明行号 | ✅ 有防护 |

**建议 stats 参数映射**（供前端/后端直接使用）：

```python
ViewWidget(
    stats_success="SUCCESS",      # 默认是 "PASS"，必须改
    stats_hang="HANG",            # 与本项目一致，默认值即可
    stats_custom="UNEXPECTED",    # 可选：第三张分布图
    # FL 数量庞大(64.6万)，作为明细行展示即可，不单独画图
)
```

---

## 1. CSV 解析（Python 侧）— ✅ 可直接复用，无 anywidget 依赖

| 交付物 | 位置 | 签名 |
|---|---|---|
| 尾窗读取器 | `src/viewviewview/core.py:255`（`_TailReader` 类） | `_TailReader(path, logger).read(limit: Optional[int]) -> Tuple[List[str], List[List[str]]]` |
| 全量读取 | 同上，`read(None)` | 同上 |
| 坏行校验 | `core.py:283` / `core.py:298` | 字段数 ≠ header 字段数 → `ValueError(f"Malformed CSV record {i} in {path}")`（i 为 0-based 数据行号，header 不计入） |
| header 校验 | `core.py:933`（`ViewWidget._validate_existing_csv_locked`） | 追加写入前校验既有 CSV 的 header 一致性 + **末字节非 `\n` 判定"未完成行"** 并 raise `ValueError` |
| 面向 CSV 文件的读取入口 | `src/viewviewview/compat.py:100`（`csvview`） | `csvview(csv, state="state", limit=None, full=False) -> None` |
| payload 组装 | `compat.py:72`（`_build_payload`） | `(header, rows, state) -> payload dict`（§4.3 冻结格式） |

- **纯标准库**（`csv` / `os` / `collections.deque`），无 pandas，无 anywidget。`_TailReader` 是自足类，可直接 `from viewviewview.core import _TailReader` 使用（下划线前缀只是命名约定，无任何隐藏依赖）。
- **推荐复用方式**：后端只需两个函数——`_TailReader.read(limit)` 拿 `(header, rows)`，`compat._build_payload(header, rows, state)` 组装成前端载荷。如需实现"轮询增量刷新"，参考 `Syncer`（`core.py:305`）的 50ms 合帧 + `payload["version"]` 单调递增机制，但 Syncer 本身绑定 threading/Timer，Web 服务场景建议只抄思路或直接用 payload 的 `total`/`version` 字段做轮询对比。
- `csvview()`/`csvplot()` 本身是 Jupyter/IPython 入口（内部调 `render_payload` → IPython display），**不要**在 Web server 里调用它们；只取 `_TailReader` + `_build_payload` 即可。

### 1.1 具体复用建议（可直接贴）

```python
# 从 vendor 目录导入（假设 vendor 在 sys.path 或包化）
from viewviewview.core import _TailReader
from viewviewview.compat import _build_payload

header, rows = _TailReader("<DATASET>.csv").read(200)   # O(200) 内存尾窗
payload = _build_payload(header, rows, state="state")
# payload = {columns, state_key, counts, rows(最新在前), total, window, version}
```

---

## 2. 前端资产 — ✅ 主体可直接复用，仅入口需适配

### 2.1 关键路径

| 资产 | 路径 | 说明 |
|---|---|---|
| 单文件 ESM 前端 | `src/viewviewview/static/index.mjs`（1087 行） | 零 npm 依赖、零 import，纯浏览器 ESM；**写前端的智能体重点看 §2.3 与 §2.4** |
| 全部样式 | `src/viewviewview/static/styles.css`（407 行） | 深色主题，CSS 变量驱动，可整体复用 |
| 生成 preview.html 的脚本 | `scripts/build_preview.py`（`python scripts/build_preview.py`） | 把 index.mjs + styles.css + mock 数据内联成 `dev/preview.html` |
| 现成的浏览器直开预览页 | `dev/preview.html`（已生成） | **双击即可在普通网页（非 Jupyter）看到全部功能演示** |
| 架构契约文档 | `docs/ARCHITECTURE.md` | §4.3 payload 冻结格式 + §4.4 前端规格，前后端对接必读 |

### 2.2 preview.html 生成机制

`build_preview.py` 的做法 = 它已经证明了这个前端**不依赖 Jupyter**：
1. 把 `styles.css` 塞进 `<script type="text/plain" id="vvv-css-src">`；
2. 把 `index.mjs` 全文内联进 `<script type="module">`；
3. 手写一个 **~20 行的 mock model**：`{ get(key), on(event, cb), off(event, cb) }`，语义对齐 ipywidgets（`build_preview.py:88-104`）；
4. Shadow DOM 挂载：`host.attachShadow({mode:"open"})` → 注入 style → `render({model: mockModel, el})`。

**这 20 行 mock（build_preview.py:85-104）就是复用入口的全部 anywidget 适配面**——只要提供同样的 model 接口（Web 场景里把 `on("change:payload")` 换成 WebSocket/polling 回调即可），`render()` 以下约 1000 行代码全部原样可用。

### 2.3 分布图（delay 归一化柱状图 + 悬停 tooltip）代码位置

| 功能 | 函数 | index.mjs 行号 | anywidget 依赖 |
|---|---|---|---|
| 图表窗格骨架（成功/HANG/自定义三图象限布局） | `buildStatsPane` | 569–624 | ❌ 无 |
| 单图表骨架（固定 bars 根柱子池 + 50% 网格线 + 基线） | `buildStatChart` | 637–672 | ❌ 无 |
| **归一化渲染核心** | `updateStatChart` | 735–815 | ❌ 无 |
| **悬停 tooltip**（事件委托 + 浮动标签） | `attachStatsHoverTag` | 520–552 | ❌ 无 |
| 从 payload.stats 补丁式更新两/三张图 | `patchStatsPane` | 681–705 | ❌ 无 |
| 图表相关 CSS | `styles.css` | `.vvv-band` 起（约 76–250 行），`.vvv-stats-tip`（约 250 行处） | ❌ 无 |

`updateStatChart` 的归一化逻辑（如需抄逻辑而非整文件）：
- 柱高 = `hits / maxHits`（按**各图最高桶**归一化，罕见状态也可见）→ `height = rate * plotPx`（px 单位，122px 绘图区）；
- tooltip 文本 = `"{lo}-{hi} · {成功|HANG} {hits}/{totalHits} · {share*100:.1f}%"`，share 是该桶占该状态累计数的**真实占比**（悬停显示绝对量+占比）；
- 写入 `data-tip` 属性，悬停时由 `attachStatsHoverTag` 的 `mouseover` 事件委托读取并定位浮动 div。

### 2.4 在普通网页中复用的两种方式

**方式 A（推荐）：整文件复用 + mock model**
```html
<style>/* 内联 styles.css */</style>
<div id="vvv-preview"></div>
<script type="module">
  import { render } from "./vendor/viewviewview/src/viewviewview/static/index.mjs";
  // 注意：index.mjs 导出的是 export default { render }，需调整为具名导出或用默认导出
</script>
```
实际上最省事的是照抄 `build_preview.py` 的内联模板（方式 B）。

**方式 B（最省事）：照抄 build_preview.py 模板**
1. 复制 `scripts/build_preview.py` 的 TEMPLATE + DEMO 结构；
2. 把 mock model 的 `get("payload")` 指向 WebSocket/polling 拿到的实时 payload；
3. 推送新 payload 时手动触发 `payloadListeners`（或改成直接调用 `renderPayload`）。

### 2.5 ❌ 不可直接复用的部分（约 40 行）

| 不可复用 | 位置 | 原因 | 等价实现要点 |
|---|---|---|---|
| `render()` 的 model 绑定段 | index.mjs:42–101 | `model.on("change:payload", ...)` 是 ipywidgets comm 协议（**写前端的智能体必读本表**） | 只保留 `draw(payload)` 调用链；把 `on/off` 换成自己的实时通道（WebSocket `onmessage` → `renderPayload(root, payload, ctx)`），theme/colors/number_columns 若不动态改可删对应监听 |
| `export default { render }` | index.mjs:1086 | anywidget 合同 | Web 页面直接调用 `render({model: mockModel, el})` 或更低层 `renderPayload` |
| `applyTheme`/`applyColors` 的动态切换 | index.mjs:1031–1052 | 绑定 model 变更事件 | 如不需运行时换肤可整体删除；如需要，直接调用这两个函数即可（本身不依赖 model） |

其余约 1040 行（表格渲染、patch 算法、列宽拖拽、分布图、footer、防注入的 createElement/textContent 构建）**全部无 anywidget 依赖，可原样搬走**。

### 2.6 安全性说明（前端团队直接受益）

前端 DOM 构造全程 `createElement` + `textContent`，**完全禁用 innerHTML**（index.mjs:5-6 注释、全文无 innerHTML 调用）。payload 中的字符串（state 名等）天然防 XSS。复用时请保持这一约定。

---

## 3. 统计逻辑（delay 分桶）— ✅ 可直接复用

| 逻辑 | 位置 | 签名/要点 |
|---|---|---|
| 分桶归入 | `core.py:826`（`_record_stats_locked`） | `bucket_start = floor(delay) // bucket_width * bucket_width`；桶值 `[total, success, hang(, custom)]` |
| 桶上限合并 | `core.py:869`（`_coarsen_stats_locked`） | 桶数 > 512 时桶宽翻倍两两合并，payload 中携带新桶宽，前端同帧重标 |
| 快照序列化 | `core.py:1056`（`_build_stats_snapshot_locked`） | 输出 `{bucket, bars, success, hang, rows, buckets: [[lo, hi, total, ok, hang], ...]}`，custom 开启时附加 `custom` 键与第 6 列计数 |
| payload 携带 stats 的节流 | `core.py:1009`（`_build_payload_locked`） | 每 `stats_interval × frame_delay`（默认 0.25s）附加一次 stats 块 + 静默期 settle timer 兜底 |
| 校验函数 | `core.py:174–202` | `stats_bucket`(≥0，0=关图) / `stats_interval`(≥1) / `stats_bars`(1–50) / `stats_state` / `stats_delay` 等参数校验 |

- 统计逻辑**绑定在 `ViewWidget.update()` 写入路径**（core.py:607 调 `_record_stats_locked`）。若我们的 dashboard 是**读已有 CSV** 而非实时记录，需要自己从 CSV 行重建分桶：逻辑极简（按上式对 delay 取桶、按 state 计数），**后端可参照 `_record_stats_locked` + `_build_stats_snapshot_locked` 写一个 ~30 行的"从 CSV 行聚合 stats"函数**，输出同样的 `{bucket, buckets: [[lo,hi,total,ok,hang]]}` 结构，前端零改动。
- 如果后端要实时记录（走 `ViewWidget`），则 stats 全自动，零额外工作。

**示例：读已有 CSV 重建 stats 块（伪代码要点）**

```python
def build_stats_from_rows(header, rows, bucket_width=100, state_col="state",
                          delay_col="delay", success="SUCCESS", hang="HANG",
                          custom="UNEXPECTED", bars=30):
    si, di = header.index(state_col), header.index(delay_col)
    stats = {}
    for row in rows:
        d = int(row[di]); b = (d // bucket_width) * bucket_width
        cell = stats.setdefault(b, [0, 0, 0, 0])  # [total, ok, hang, custom]
        cell[0] += 1
        s = row[si]
        if s == success: cell[1] ≈ ...  # 同 _record_stats_locked 逻辑
        elif s == hang: cell[2] += 1
        elif s == custom: cell[3] += 1
    return {
        "bucket": bucket_width, "bars": bars,
        "success": success, "hang": hang, "rows": sum(c[0] for c in stats.values()),
        "buckets": [[k, k + bucket_width, c[0], c[1], c[2], c[3]] for k, c in sorted(stats.items())],
    }
```
（把返回值挂到 payload["stats"]，前端 `patchStatsPane` 直接吃；`readStats`（index.mjs:421）已对 custom 第 6 列防御性处理。）

---

## 4. License 义务（MulanPSL-2.0）

- 许可证全文：`dashboard/vendor/viewviewview/LICENSE`（即仓库根的 LICENSE），pyproject 声明 `license = "MulanPSL-2.0"`。
- 对复用/修改的要求（许可证第 1、4 条）：
  1. **保留声明**：在我们的复用文件中保留原文件的版权与免责声明（原文件无独立版权头，因此**在每个复用文件头部加入来源声明**即可，推荐格式见下）。
  2. **随附许可证副本**：分发（无论修改与否）时必须向接收者提供 MulanPSL-2.0 副本。保留 `dashboard/vendor/viewviewview/LICENSE` 不删即满足；若把复用代码拷贝到其他位置，请随附一份 LICENSE 副本。
  3. 修改不受限：可自由修改、闭源使用（MulanPSL-2.0 是宽松许可证，无传染性）。
  4. 无商标许可：不要以 "ViewViewView" 名义对外宣传衍生品。

**复用文件头推荐声明**（每个从 VVV 拷出代码的文件加）：

```
// 基于 ViewViewView (https://github.com/Nop3z/ViewViewView) 的代码修改/复制而来。
// 原项目以 MulanPSL-2.0 (http://license.coscl.org.cn/MulanPSL2) 许可。
// 本文件按 MulanPSL-2.0 第 4 条保留原版权与许可声明。
```

（Python 文件用 `#` 注释，HTML 用 `<!-- -->`。）

---

## 5. 给两个智能体的"直接拿走"清单

### 给后端智能体（Python 侧）

| 拿什么 | 路径 | 用法 |
|---|---|---|
| CSV 尾窗/全量读取 | `src/viewviewview/core.py` 的 `_TailReader`（core.py:255） | 直接 import；`read(limit)` 返回 `(header, rows)`，自带坏行防护 |
| payload 组装 | `src/viewviewview/compat.py` 的 `_build_payload`（compat.py:72） | 直接 import，输出 §4.3 冻结格式 payload，与前端配套 |
| stats 分桶逻辑参考 | `core.py:826` `_record_stats_locked` / `core.py:1056` `_build_stats_snapshot_locked` | 若走 `ViewWidget` 实时记录则零改动全自动；若读已有 CSV，照 §3 伪代码写 ~30 行聚合函数 |
| 实时记录（可选） | `core.py` 的 `ViewWidget` | 如 dashboard 需要自己写 CSV 时用；`stats_success="SUCCESS"` 务必传 |
| 全部源码 | 整个 `dashboard/vendor/viewviewview/` 目录已就位 | import 方式见 §1.1 |

### 给前端智能体（JS/CSS 侧）

| 拿什么 | 路径 | 用法 |
|---|---|---|
| 前端主体（约 1040 行，无 anywidget 依赖） | `src/viewviewview/static/index.mjs` | 整文件复用；只按 §2.5 替换 `render()` 入口的 model 绑定段（约 40 行）为自己的实时通道 |
| 全部样式 | `src/viewviewview/static/styles.css` | 整文件复用，深色主题，CSS 变量驱动 |
| 适配模板 | `scripts/build_preview.py:85–106`（mock model + Shadow DOM 挂载） | 照抄这 ~20 行，把 `get("payload")` 指向自己的数据通道 |
| 视觉验收基准 | `dev/preview.html` | 浏览器直开，就是最终效果的 1:1 预览 |
| payload 格式契约 | `docs/ARCHITECTURE.md` §4.3 | 前后端接口冻结格式，勿改字段名 |

### 唯一必须自己写的（双方协作点）

1. **实时通道**：`model.on("change:payload")` → WebSocket/SSE/polling（前端 ~40 行改造，见 §2.5）。
2. **从已有 CSV 聚合 stats**：若不走 `ViewWidget` 实时记录，后端需按 §3 伪代码写 ~30 行聚合函数。
