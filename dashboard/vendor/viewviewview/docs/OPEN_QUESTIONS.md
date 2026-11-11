# OPEN_QUESTIONS / 待澄清与裁定记录

> 规则（ARCHITECTURE §8）：按格式追加，不得阻塞交付自选合理默认；架构师裁定后在此标注 RESOLVED 并同步契约。

- [x] R1 RESOLVED（架构师，2026-10-19）：许可证冲突——GitHub 远端初始 LICENSE 为 MIT，与契约 D3 MulanPSL-2.0 不一致；所有者裁定 **MulanPSL-2.0**。影响：M4 文档工程师替换 LICENSE 文件、pyproject license 表达式与 README 标注；架构契约 §0-D3 已补充裁定记录。
- [x] R2 RESOLVED（架构师，2026-10-19）：schema 键序语义。契约最初要求“键名+键序完全一致”，但 FaultViz 的 `_check_columns` 实际只校验键集与类型（顺序不敏感）；为最大化兼容性，裁定 **键传入顺序不敏感**，CSV 始终按冻结的 schema 列序落盘。契约 §2 已修订，测试 `test_key_order_is_irrelevant_but_csv_order_is_frozen` 覆盖。
- [x] B1 RESOLVED（展示，2026-10-19）：主题仅实现 `dark`（D5）；`theme` trait 与 `data-vvv-theme` 属性已保留，未来可扩展浅色/跟随 JupyterLab 主题，无需改协议。
- [x] B2 RESOLVED（展示，2026-10-19）：上窗分类桶按**首次出现顺序**（dict 插入序）展示，不做额外排序；与 FaultViz `count_by` 的呈现方式一致，避免每次刷新导致行位置跳动。
- [x] R3 RESOLVED（架构师，2026-10-19）：`csvplot` 缺 pygwalker 时的日志文案与 §3.4 的 `plot` 文案区分——“showing the table view instead” 明确告知已降级为双窗表格；行为不变（不抛异常）。
- [x] R4 RESOLVED（所有者需求，2026-10-19）：字段自定义前移到实例化阶段——新增可选 `columns=`（映射显式类型 / 序列仅列名），未传时保持首行定 schema。契约 D8 与 §3.2 已更新。
- [x] R5 RESOLVED（所有者需求，2026-10-19）：CSV 默认文件名改为控件创建（实验开始）时刻 `YYYYMMDD-HHMMSS.csv`；`csv_path=` 手动命名保持不变并自动创建父目录。契约 D9 与 §5 已更新。
- [x] R6 RESOLVED（所有者需求，2026-10-19）：配色为深色背景 + 纯白字段文字 + 荧光绿计数（`#39ff14`）。契约 D10 与 §4.4 已更新，前端与预览页同步。（计数颜色后由 R9 调整为 `#19ff25`。）
- [x] R7 RESOLVED（所有者需求，2026-10-19）：列宽可拖动调整——表头分隔线拖拽，相邻列分担增量、末列扩展表格；宽度跨实时刷新保持，拖拽期间暂缓重绘。契约 D11 与 §4.4 已更新。
- [x] R8 RESOLVED（所有者需求，2026-10-19）：列间距过散——表格不再 `width:100%` 拉伸，改为按内容紧凑排列（`width:max-content`）；上窗 `state`/`count` 相邻、明细各列紧贴，分隔线继续支持拖拽微调。契约 D12 与 §4.4 已更新。
- [x] R9 RESOLVED（所有者需求，2026-10-19）：取消荧光绿计数。经源码求证，FaultViz 的 count 是 Deephaven positive-number 绿；深色主题为 `#ace97e`，浅色为 `#008f5d`。所有者最终指定 **`#19ff25`** 作为默认计数色，并新增 `colors=` 自定义接口（契约 D13/§3.2/§4.4 已更新）。
- [x] R11 RESOLVED（所有者需求，2026-10-19）：明细表数值列默认高亮色 `#19ff25`；但**仅 `delay`/`pulse` 使用绿色，`errcode` 等其他数值列保持白色**。新增 `number_columns=` 控制高亮列（默认 `delay`/`pulse`），字符串列始终白色。契约 D10/D13/§3.2/§4.4 已更新。
- [x] R12 RESOLVED（所有者需求，2026-10-20）：FaultViz 脚本兼容性——实验脚本会读取 `vt._column`（列名→类型）来检测 schema 变化；ViewViewView 新增只读属性 `_column` 作为兼容快照，预声明但类型未定的列为 `None`。契约 §3.2 已更新。
