"""从 docs/contracts/schemas/ 加载契约并构建 jsonschema 校验器。

目录解析顺序：
1. 环境变量 ``FI_CONTRACTS_DIR``（显式覆盖，CI/打包场景用）；
2. 从本包位置向上查找 ``docs/contracts/schemas``（开发仓库场景）。

跨文件 $ref：所有契约的 ``$id`` 都挂在 ``fi.schemas.registry.URI_PREFIX`` 下，
相对引用（``"common.defs.json"``）经本地 ``referencing.Registry`` 解析，
全程离线，不访问网络。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import referencing
from jsonschema import Draft202012Validator

from fi.schemas.invariants import check_semantics
from fi.schemas.registry import SCHEMA_REGISTRY, URI_PREFIX, SchemaEntry

#: 环境变量名：显式指定契约目录。
CONTRACT_SCHEMA_DIR_ENV = "FI_CONTRACTS_DIR"

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]


class SchemaNotFoundError(FileNotFoundError):
    """找不到契约 schema 文件或注册名。"""


def default_schema_dir() -> Path:
    """定位契约 schema 目录；找不到时抛 SchemaNotFoundError。"""
    env_dir = os.environ.get(CONTRACT_SCHEMA_DIR_ENV)
    if env_dir:
        p = Path(env_dir)
        if not p.is_dir():
            raise SchemaNotFoundError(
                f"{CONTRACT_SCHEMA_DIR_ENV} 指向的目录不存在: {p}"
            )
        return p

    # 开发仓库场景：fi 包的上层应有 docs/contracts/schemas
    for base in (_PACKAGE_ROOT, *_PACKAGE_ROOT.parents):
        candidate = base / "docs" / "contracts" / "schemas"
        if candidate.is_dir():
            return candidate

    raise SchemaNotFoundError(
        "未找到 docs/contracts/schemas；"
        f"可设置环境变量 {CONTRACT_SCHEMA_DIR_ENV} 指定契约目录"
    )


def schema_path(name: str, schema_dir: Path | None = None) -> Path:
    """把注册短名或文件名解析为实际路径。"""
    directory = schema_dir if schema_dir is not None else default_schema_dir()
    entry = SCHEMA_REGISTRY.get(name)
    filename = entry.filename if entry else name
    p = directory / filename
    if not p.is_file():
        raise SchemaNotFoundError(
            f"契约文件不存在: {p}（可用名: {', '.join(sorted(SCHEMA_REGISTRY))}）"
        )
    return p


def load_schema(name: str, schema_dir: Path | None = None) -> dict[str, Any]:
    """加载单个契约 schema 为 dict。``name`` 可为注册短名或文件名。"""
    p = schema_path(name, schema_dir)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SchemaNotFoundError(f"契约文件顶层必须是 JSON object: {p}")
    return data


def list_schemas(schema_dir: Path | None = None) -> list[dict[str, str]]:
    """列出全部已登记契约（CLI `fi schema list` 使用）。"""
    directory = schema_dir if schema_dir is not None else default_schema_dir()
    rows = []
    for entry in SCHEMA_REGISTRY.values():
        rows.append(
            {
                "name": entry.name,
                "file": entry.filename,
                "title": entry.title,
                "instantiable": "yes" if entry.instantiable else "no (defs only)",
                "present": "yes" if (directory / entry.filename).is_file() else "MISSING",
            }
        )
    return rows


def load_schema_registry(
    schema_dir: Path | None = None,
) -> referencing.Registry:
    """构建离线 $ref 注册表：把全部契约文件注册到 URI_PREFIX 对应 URI。"""
    directory = schema_dir if schema_dir is not None else default_schema_dir()
    registry: referencing.Registry = referencing.Registry()
    for entry in SCHEMA_REGISTRY.values():
        data = load_schema(entry.filename, directory)
        uri = f"{URI_PREFIX}/{entry.filename}"
        registry = registry.with_resource(uri, referencing.Resource.from_contents(data))
    return registry


def validate_instance(
    schema_name: str,
    instance: Any,
    schema_dir: Path | None = None,
) -> list[str]:
    """按注册名校验实例，返回人类可读错误列表；空列表 = 通过。

    校验 = JSON Schema 结构校验 + 该契约的**语义不变量**
    （``fi.schemas.invariants``，如 reverse-report 的 evidence_ref 引用完整性、
    discover-report 的 confidence 闸门）。两类错误合并返回。

    非可实例化契约（common）与未知名称均抛 SchemaNotFoundError。
    """
    entry: SchemaEntry | None = SCHEMA_REGISTRY.get(schema_name)
    if entry is None or not entry.instantiable:
        raise SchemaNotFoundError(
            f"不可校验的契约名: {schema_name}（可用: "
            f"{', '.join(n for n, e in SCHEMA_REGISTRY.items() if e.instantiable)}）"
        )

    schema = load_schema(entry.filename, schema_dir)
    registry = load_schema_registry(schema_dir)
    validator = Draft202012Validator(schema, registry=registry)

    errors: list[str] = []
    for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"{loc}: {err.message}")
    errors.extend(check_semantics(schema_name, instance))
    return errors
