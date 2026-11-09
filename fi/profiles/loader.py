"""Chip Profile 加载器与校验器（v0.1）。

核心约定（详见 docs/profiles/profile-guide.md）：
- Profile 数据文件位于仓库 ``profiles/<chip_id>.yaml``，``profile_id`` 必须与文件名一致；
- 除元数据结构（sources/open_questions 等）外，一切语义字段必须是
  claim 形状 ``{value, evidence}``；
- evidence.confidence ∈ fact | hypothesis | unknown，且：
  * fact        → value 非空，source 必须登记且 kind 可支撑事实；
  * hypothesis  → value 建议为候选值，source 必填且 note 必填（写明推理链）；
  * unknown     → value 必须为 null 或 []（显式未知，禁止猜测值）；
- 来源 kind 矩阵：
  * user_confirmed / internal_document / artifact / artifact_derived / measurement
    可支撑 fact；
  * public_doc / public_secondary / article_archive / inference 只能支撑
    hypothesis（公开资料仅旁证）；
  * pending 只能搭配 unknown（占位，等待资料）。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml
from jsonschema import Draft7Validator

SCHEMA_PATH = Path(__file__).parent / "schema" / "chip-profile-v0.1.schema.json"

FACT_KINDS = {
    "user_confirmed",
    "internal_document",
    "artifact",
    "artifact_derived",
    "measurement",
}
NON_FACT_KINDS = {"public_doc", "public_secondary", "article_archive", "inference"}
PENDING_KIND = "pending"

_HEX_RE = re.compile(r"^0[xX][0-9A-Fa-f]+$")
_SOURCE_ID_RE = re.compile(r"^S\d+$")
_PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

#: 自动生成草稿的文件名后缀（`<chip_id>.draft.yaml`）。
#: 规则（lead 2026-11-09 授权）：
#:   1) 草稿是 fi discover 自动生成的**候选**，不是已验证实例——因此不参与
#:      "profile_id 必须与文件名一致"检查（stem 会是 `<chip_id>.draft`，
#:      而 profile_id 是 `<chip_id>`），并在报告里标 is_draft=True；
#:   2) `validate --all` 与 YamlProfileStore.index() 跳过草稿——草稿不进正式
#:      Profile 索引，避免 Dashboard 出现重复 profile_id 条目。
DRAFT_SUFFIX = ".draft"


def _is_draft_path(path: str | Path) -> bool:
    """判断路径是否为自动生成草稿（`*.draft.yaml`）。"""
    return Path(path).stem.endswith(DRAFT_SUFFIX)


class ProfileValidationError(Exception):
    """Profile 校验失败。errors 为人类可读的错误列表。"""

    def __init__(self, errors: list[str], warnings: list[str] | None = None):
        self.errors = errors
        self.warnings = warnings or []
        super().__init__("; ".join(errors))


# ---------------------------------------------------------------------------
# 基础加载
# ---------------------------------------------------------------------------

def load_raw(path: str | Path) -> dict[str, Any]:
    """读取 YAML 文件并返回原始字典（不校验）。"""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ProfileValidationError([f"{path}: 顶层必须是 YAML 映射"])
    return data


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------

@dataclass
class ValidationReport:
    path: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    #: True = 自动生成草稿（`*.draft.yaml`）；此类文件豁免 profile_id/文件名一致性检查
    is_draft: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors

    def summary(self) -> str:
        head = f"{self.path}: " + ("PASS" if self.ok else f"FAIL ({len(self.errors)} errors)")
        if self.is_draft:
            head += " [draft]"
        s = self.stats
        tail = (
            f" claims: fact={s.get('fact', 0)} hypothesis={s.get('hypothesis', 0)} "
            f"unknown={s.get('unknown', 0)} total={s.get('total', 0)}; "
            f"warnings={len(self.warnings)}"
        )
        return head + " | " + tail


def _walk_claims(node: Any, path: str) -> Iterator[tuple[str, dict]]:
    """深度优先遍历，产出所有 claim 形状的节点。

    typed claim（value 为数组/结构的容器，如 regions/entries）整体算一个 claim，
    但必须继续深入 value 内部——条目级字段（region.base、errorEntry.meaning 等）
    也是 claim，漏掉会导致语义规则对其失效。evidence 内部不含 claim，不深入。
    """
    if isinstance(node, dict):
        if "value" in node and "evidence" in node and len(node) == 2:
            yield path, node
            yield from _walk_claims(node["value"], f"{path}.value")
            return
        for k, v in node.items():
            yield from _walk_claims(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_claims(v, f"{path}[{i}]")


def _claim_value_is_empty(value: Any) -> bool:
    return value is None or value == []


def validate_profile(data: dict[str, Any], path: str | Path) -> ValidationReport:
    """完整校验一个已解析的 Profile 字典。

    层次：
    1. JSON Schema 结构校验；
    2. evidence 语义完整性（confidence × source kind 矩阵、值约束）；
    3. sources 登记一致性（引用存在、无悬空）；
    4. profile_id 与文件名一致性；
    5. open_questions 覆盖度统计。
    """
    rep = ValidationReport(path=str(path), is_draft=_is_draft_path(path))
    name = Path(path).name

    # 1. schema
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path)):
        loc = ".".join(str(p) for p in err.absolute_path) or "<root>"
        rep.errors.append(f"schema: {loc}: {err.message}")

    # 2. sources 登记表
    sources: dict[str, dict] = {}
    seen_ids: set[str] = set()
    for i, src in enumerate(data.get("sources", [])):
        sid = src.get("id", f"<sources[{i}]>")
        if sid in seen_ids:
            rep.errors.append(f"sources: id 重复: {sid}")
        seen_ids.add(sid)
        sources[sid] = src
    referenced: set[str] = set()

    # 3. claim 语义
    counts = {"fact": 0, "hypothesis": 0, "unknown": 0, "total": 0}
    sections: dict[str, dict[str, int]] = {}
    for cpath, claim in _walk_claims(data, ""):
        ev = claim.get("evidence", {})
        conf = ev.get("confidence")
        src_id = ev.get("source")
        value = claim.get("value")
        counts["total"] += 1
        counts[conf] = counts.get(conf, 0) + 1
        section = (cpath.split(".")[0] if cpath else "<root>").split("[")[0]
        sections.setdefault(section, {"fact": 0, "hypothesis": 0, "unknown": 0})
        sections[section][conf] = sections[section].get(conf, 0) + 1

        # 十六进制字符串统一格式（可比较、可审计）
        if isinstance(value, str) and value.lower().startswith("0x") and not _HEX_RE.match(value):
            rep.errors.append(f"{cpath}: 非法十六进制字面量 {value!r}")

        if src_id is not None:
            if not _SOURCE_ID_RE.match(str(src_id)):
                rep.errors.append(f"{cpath}: source id 格式非法: {src_id!r}")
            elif src_id not in sources:
                rep.errors.append(f"{cpath}: source {src_id} 未在顶层 sources 登记")
            else:
                referenced.add(src_id)

        if conf == "unknown":
            if not _claim_value_is_empty(value):
                rep.errors.append(
                    f"{cpath}: confidence=unknown 但 value={value!r}（未知必须置 null/[]）"
                )
            if src_id is not None and src_id in sources:
                if sources[src_id].get("kind") != PENDING_KIND:
                    rep.warnings.append(
                        f"{cpath}: unknown 引用了非 pending 来源 {src_id}（允许，但建议用 pending 占位）"
                    )
        elif conf == "fact":
            if _claim_value_is_empty(value):
                rep.errors.append(f"{cpath}: confidence=fact 但 value 为空（事实必须有值）")
            if src_id is None:
                rep.errors.append(f"{cpath}: confidence=fact 但缺少 source")
            elif src_id in sources:
                kind = sources[src_id].get("kind")
                if kind in NON_FACT_KINDS or kind == PENDING_KIND:
                    rep.errors.append(
                        f"{cpath}: source {src_id} kind={kind} 不能支撑 fact"
                        "（公开/推断来源仅可作旁证）"
                    )
                if kind in NON_FACT_KINDS and not sources[src_id].get("trust"):
                    rep.errors.append(f"sources[{src_id}]: 公开类来源必须标注 trust")
        elif conf == "hypothesis":
            if src_id is None:
                rep.errors.append(f"{cpath}: confidence=hypothesis 但缺少 source（假设也要有依据）")
            elif src_id in sources and sources[src_id].get("kind") == PENDING_KIND:
                rep.errors.append(f"{cpath}: source {src_id} kind=pending 只能搭配 unknown")
            if not ev.get("note"):
                rep.errors.append(f"{cpath}: hypothesis 必须填写 evidence.note（推理链/旁证关系）")
        else:
            rep.errors.append(f"{cpath}: 未知 confidence: {conf!r}")

    # 4. 来源引用完备性
    for sid in sources:
        if sid not in referenced:
            rep.warnings.append(f"sources: {sid} 已登记但未被任何 claim 引用")

    # 4b. 自动生成标记的语义不变量（core-contract 契约口径，lead 2026-11-09 裁定）：
    #     generated_by 存在（非 unknown）⇒ status 必须 draft，且来源须含 artifact_derived。
    #     目的：自动草稿不得冒充已验证画像，消费方据此可安全拒绝。
    gen_by = data.get("generated_by")
    if gen_by is not None and str(gen_by).strip().lower() not in ("", "unknown"):
        if data.get("status") != "draft":
            rep.errors.append(
                f"generated_by={gen_by!r} 但 status={data.get('status')!r}："
                "自动生成内容必须 status=draft（不得冒充已验证画像）"
            )
        kinds = {src.get("kind") for src in sources.values()}
        if "artifact_derived" not in kinds:
            rep.errors.append(
                f"generated_by={gen_by!r} 但 sources 中没有 kind=artifact_derived 的来源："
                "自动生成内容必须标注派生来源"
            )
        rep.stats["auto_generated"] = True
    else:
        rep.stats["auto_generated"] = False

    # 5. profile_id 与文件名一致（草稿豁免：stem 为 `<chip_id>.draft`，属文件名约定差异）
    pid = data.get("profile_id")
    stem = Path(path).stem
    if rep.is_draft:
        # 草稿由 fi discover 自动生成，文件名固定为 <chip_id>.draft.yaml；
        # 只校验 profile_id 格式与"合理对应"（避免复制粘贴错芯片），不做严格相等。
        if pid is not None and not _PROFILE_ID_RE.match(pid):
            rep.errors.append(f"profile_id 非法: {pid!r}")
        elif pid is not None and stem != f"{pid}{DRAFT_SUFFIX}":
            rep.errors.append(
                f"草稿文件名 {stem!r} 与 profile_id={pid!r} 不对应"
                f"（应为 {pid}{DRAFT_SUFFIX}.yaml）"
            )
    else:
        if pid is not None and pid != stem:
            rep.errors.append(f"profile_id={pid!r} 与文件名 {stem!r} 不一致")
        if pid is not None and not _PROFILE_ID_RE.match(pid):
            rep.errors.append(f"profile_id 非法: {pid!r}")

    rep.stats = {
        **counts,
        "sections": sections,
        "sources": len(sources),
        "open_questions": len(data.get("open_questions", [])),
    }
    return rep


def validate_file(path: str | Path) -> ValidationReport:
    """读取并校验一个 Profile 文件。"""
    data = load_raw(path)
    return validate_profile(data, path)


# ---------------------------------------------------------------------------
# 加载为对象
# ---------------------------------------------------------------------------

class ChipProfile:
    """已校验 Profile 的轻量只读包装。

    引擎用法示例::

        p = load_profile("profiles/<chip_id>.yaml")
        p.get("chip.id")            # -> value
        p.claim("chip.id")          # -> {"value": ..., "evidence": ...}
        for cpath, value, ev in p.claims(): ...
    """

    def __init__(self, raw: dict[str, Any], path: str | Path):
        self._raw = raw
        self.path = Path(path)

    @property
    def raw(self) -> dict[str, Any]:
        return self._raw

    @property
    def profile_id(self) -> str:
        return self._raw["profile_id"]

    def _resolve(self, dotted: str) -> Any:
        node: Any = self._raw
        for part in dotted.split("."):
            if "[" in part:
                key, idx = part[:-1].split("[")
                node = node[key][int(idx)]
            else:
                node = node[part]
        return node

    def claim(self, dotted: str) -> dict[str, Any]:
        node = self._resolve(dotted)
        if not (isinstance(node, dict) and "value" in node and "evidence" in node):
            raise KeyError(f"{dotted} 不是 claim 节点")
        return node

    def get(self, dotted: str, default: Any = None) -> Any:
        try:
            return self.claim(dotted)["value"]
        except KeyError:
            return default

    def confidence(self, dotted: str) -> str:
        return self.claim(dotted)["evidence"]["confidence"]

    def claims(self) -> Iterator[tuple[str, Any, dict]]:
        for cpath, node in _walk_claims(self._raw, ""):
            yield cpath, node["value"], node["evidence"]

    def unknown_fields(self) -> list[str]:
        return [cpath for cpath, _v, ev in self.claims() if ev.get("confidence") == "unknown"]


def load_profile(path: str | Path) -> ChipProfile:
    """读取、校验并加载 Profile；校验失败抛 ProfileValidationError。"""
    data = load_raw(path)
    rep = validate_profile(data, path)
    if not rep.ok:
        raise ProfileValidationError(rep.errors, rep.warnings)
    return ChipProfile(data, path)


# ---------------------------------------------------------------------------
# ProfileStore 接口实现（接口契约见本包 protocol.py，归 core-contract 维护）
# ---------------------------------------------------------------------------

class YamlProfileStore:
    """基于仓库 profiles/ 目录的 ProfileStore 实现。

    导出形状按 docs/contracts/schemas/chip-profile-index.schema.json（v0.1，
    core-contract 维护）。status 映射：契约枚举 {draft, validated, deprecated,
    unknown}，Profile 的 review 状态导出时映射为 unknown（契约约定导出方映射）。
    """

    FORMAT_VERSION = "0.1"
    SOURCE_OF_TRUTH = "chip-profile-contract"
    _CONTRACT_STATUS = {"draft", "validated", "deprecated", "unknown"}

    def __init__(self, profiles_dir: str | Path | None = None):
        self.profiles_dir = Path(profiles_dir) if profiles_dir else _default_profiles_dir()

    def _path(self, profile_id: str) -> Path:
        return self.profiles_dir / f"{profile_id}.yaml"

    def load(self, profile_id: str) -> dict[str, Any]:
        path = self._path(profile_id)
        if not path.exists():
            raise KeyError(profile_id)
        return load_profile(path).raw

    def validate(self, profile: dict[str, Any]) -> list[str]:
        name = f"{profile.get('profile_id', 'unnamed')}.yaml"
        rep = validate_profile(profile, name)
        return rep.errors

    def index(self) -> dict[str, Any]:
        entries = []
        for path in sorted(self.profiles_dir.glob("*.yaml")):
            if _is_draft_path(path):
                # 自动生成草稿不进正式索引（避免 Dashboard 出现重复 profile_id 条目）
                continue
            try:
                raw = load_raw(path)
                rep = validate_profile(raw, path)
                pid = raw.get("profile_id")
                stats = {k: rep.stats.get(k) for k in
                         ("fact", "hypothesis", "unknown", "total", "open_questions")}
                valid = rep.ok
                entry = {
                    "profile_id": pid,
                    "index_path": f"profiles/{pid}.yaml" if pid else None,
                    "format_version": raw.get("schema_version", self.FORMAT_VERSION),
                    "source_of_truth": self.SOURCE_OF_TRUTH,
                    "title": raw.get("title"),
                    "status": raw.get("status")
                    if raw.get("status") in self._CONTRACT_STATUS else "unknown",
                    "revision": raw.get("revision"),
                    "updated": raw.get("updated"),
                    # 整体证据等级：通过校验 = 有直接观测支撑；否则 hypothesis
                    "evidence_level": "observation" if valid else "hypothesis",
                    "valid": valid,
                    "stats": stats if valid else None,
                }
                entries.append(entry)
            except ProfileValidationError:
                entries.append({
                    "profile_id": path.stem,
                    "index_path": f"profiles/{path.stem}.yaml",
                    "format_version": self.FORMAT_VERSION,
                    "source_of_truth": self.SOURCE_OF_TRUTH,
                    "status": "unknown",
                    "evidence_level": "hypothesis",
                    "valid": False,
                    "error": "unreadable",
                })
        return {"format_version": self.FORMAT_VERSION, "profiles": entries}


def _default_profiles_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "profiles"


# ---------------------------------------------------------------------------
# 通用性审计：实例值不得泄漏进通用代码
# ---------------------------------------------------------------------------

_HEXTOKEN_RE = re.compile(r"0[xX][0-9A-Fa-f]{4,}")
_SHA_RE = re.compile(r"\b[0-9a-f]{64}\b")

# 通用常量豁免（非芯片专有）：页大小、常见位宽/掩码、2 的幂。
# 理由（lead 2026-11-09 实测裁定）：这些值会自然出现在任何芯片的 Profile 里
# （如 memory_map 区域的页对齐基址），把它们当"实例 token"会让门禁对通用代码
# 误报——实测 `0x1000` 页大小就误伤了 fi/discover 的合法默认参数。
# 判据：值是 2 的幂且 ≤ 0x100000（页/位宽/容量量级），无芯片辨识度。
_GENERIC_HEX_VALUES: frozenset[int] = frozenset(
    1 << i for i in range(4, 21)          # 0x10 .. 0x100000
) | frozenset({0xFF, 0xFFFF, 0xFFFFFFFF, 0x1000, 0x2000, 0x4000, 0x8000})


def _is_generic_hex(value_str: str) -> bool:
    """判断一个 hex 字面量是否属通用常量（非芯片专有），应豁免门禁。"""
    try:
        v = int(value_str, 16)
    except ValueError:
        return False
    return v in _GENERIC_HEX_VALUES


def _iter_tokens(node: Any, path: str) -> Iterator[tuple[str, str]]:
    """提取实例 Profile 中的芯片专有字面量（hex 地址/错误码、SHA-256）。

    只提取强 token：profile_id 由 audit_generality 单独从 chip.id 取；
    通用架构枚举值（如 isa_family）不提取，避免对通用代码误报。
    """
    if isinstance(node, dict):
        if "value" in node and "evidence" in node and len(node) == 2:
            yield from _iter_tokens(node["value"], f"{path}.value")
            return
        for k, v in node.items():
            yield from _iter_tokens(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_tokens(v, f"{path}[{i}]")
    elif isinstance(node, str):
        if _SHA_RE.match(node):
            yield path, node.lower()
        for m in _HEXTOKEN_RE.finditer(node):
            tok = m.group(0)
            if _is_generic_hex(tok):
                continue          # 通用常量（页大小/掩码等）不具芯片辨识度，豁免
            yield path, tok
    elif isinstance(node, int) and abs(node) >= 0x10000:
        if abs(node) in _GENERIC_HEX_VALUES:
            return
        yield path, hex(node)


def _strip_py_comments_and_docstrings(text: str) -> str:
    """剥离 Python 注释与 docstring 行，只保留代码构造文本（供通用性审计）。

    裁定口径（lead 2026-11-09）：文档字符串中的示例引用可接受（豁免）；
    代码构造中的实例值（常量、默认值、过滤字符串）仍为违规。
    """
    import ast
    import io
    import tokenize

    lines = text.splitlines(keepends=True)
    excluded: list[tuple[int, int]] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text  # 解析失败则保守地全文扫描
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (isinstance(body, list) and body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            excluded.append((body[0].lineno, body[0].end_lineno or body[0].lineno))
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                excluded.append((tok.start[0], tok.end[0]))
    except (tokenize.TokenizeError, IndentationError):
        pass
    for start, end in excluded:
        for i in range(start - 1, min(end, len(lines))):
            lines[i] = ""
    return "".join(lines)


def audit_generality(
    instance_paths: list[str | Path],
    code_roots: list[str | Path],
) -> list[str]:
    """检查通用代码/schema 中是否泄漏了实例 Profile 的专有值。

    Python 文件只扫代码构造（注释与 docstring 豁免）；JSON 无注释概念，全文扫描。
    返回错误列表；空列表 = 审计通过。
    """
    tokens: dict[str, list[str]] = {}
    for p in instance_paths:
        raw = load_raw(p)
        for tpath, tok in _iter_tokens(raw, Path(p).stem):
            tokens.setdefault(tok.lower(), []).append(f"{Path(p).name}:{tpath}")
        pid = raw.get("chip", {}).get("id", {})
        pid = pid.get("value") if isinstance(pid, dict) else None
        if isinstance(pid, str) and pid:
            tokens.setdefault(pid.lower(), []).append(f"{Path(p).name}:chip.id")

    errors: list[str] = []
    for root in code_roots:
        root = Path(root)
        files = list(root.rglob("*.py")) + list(root.rglob("*.json"))
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if f.suffix == ".py":
                text = _strip_py_comments_and_docstrings(text)
            low = text.lower()
            for tok, where in tokens.items():
                if tok in low:
                    errors.append(
                        f"通用性审计: {f} 包含实例值 {tok!r}（出现于 {where[0]} 等）；"
                        "芯片实例值禁止写进通用代码/schema"
                    )
    return errors
