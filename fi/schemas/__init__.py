"""数据契约加载与校验。

契约 JSON Schema 文件位于仓库 ``docs/contracts/schemas/``（版本化交付物，
面向 Web/Dashboard 团队与本工具集内部共用）。Python 侧只做加载、注册、校验，
不在代码里复制字段定义——单一事实来源是 schema 文件本身。
"""

from fi.schemas.invariants import (
    DISCOVER_CONFIDENCE_ALLOWED,
    DISCOVER_SUGGESTED_ACTIONS,
    SEMANTIC_CHECKS,
    check_semantics,
)
from fi.schemas.loader import (
    CONTRACT_SCHEMA_DIR_ENV,
    SchemaNotFoundError,
    default_schema_dir,
    load_schema,
    load_schema_registry,
    list_schemas,
    validate_instance,
)
from fi.schemas.registry import SCHEMA_REGISTRY

__all__ = [
    "CONTRACT_SCHEMA_DIR_ENV",
    "DISCOVER_CONFIDENCE_ALLOWED",
    "DISCOVER_SUGGESTED_ACTIONS",
    "SCHEMA_REGISTRY",
    "SEMANTIC_CHECKS",
    "SchemaNotFoundError",
    "check_semantics",
    "default_schema_dir",
    "load_schema",
    "load_schema_registry",
    "list_schemas",
    "validate_instance",
]
