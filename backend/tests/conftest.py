"""Root test configuration and dialect compilers for testing."""

import itertools
import json
from typing import Any

from sqlalchemy import event
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
from sqlalchemy.dialects.postgresql import INET, INT4RANGE, INT8RANGE, JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.types import ARRAY as BASE_ARRAY

from backend.app.db.models.audit import AuditLog
from backend.app.db.models.identity import ScopeDecision

# Enable SQLite serialization/deserialization for PostgreSQL ARRAY types during tests
_orig_array_bind = PG_ARRAY.bind_processor
_orig_array_result = PG_ARRAY.result_processor


def _array_bind_processor(self: Any, dialect: Any) -> Any:
    if dialect.name == "sqlite":
        return lambda val: json.dumps(val, default=str) if val is not None else None
    return _orig_array_bind(self, dialect)


def _array_result_processor(self: Any, dialect: Any, coltype: Any) -> Any:
    if dialect.name == "sqlite":
        return lambda val: json.loads(val) if val is not None else None
    return _orig_array_result(self, dialect, coltype)


PG_ARRAY.bind_processor = _array_bind_processor  # type: ignore[method-assign]
PG_ARRAY.result_processor = _array_result_processor  # type: ignore[method-assign]
BASE_ARRAY.bind_processor = _array_bind_processor  # type: ignore[method-assign]
BASE_ARRAY.result_processor = _array_result_processor  # type: ignore[method-assign]


@compiles(BASE_ARRAY, "sqlite")
@compiles(PG_ARRAY, "sqlite")
def compile_array_sqlite(type_: Any, compiler: Any, **kw: Any) -> str:
    """Render PostgreSQL ARRAY types as TEXT in SQLite test runs."""
    return "TEXT"


@compiles(INET, "sqlite")
def compile_inet_sqlite(type_: Any, compiler: Any, **kw: Any) -> str:
    """Render PostgreSQL INET types as VARCHAR in SQLite test runs."""
    return "VARCHAR(45)"


@compiles(INT4RANGE, "sqlite")
def compile_int4range_sqlite(type_: Any, compiler: Any, **kw: Any) -> str:
    """Render PostgreSQL INT4RANGE types as TEXT in SQLite test runs."""
    return "TEXT"


@compiles(INT8RANGE, "sqlite")
def compile_int8range_sqlite(type_: Any, compiler: Any, **kw: Any) -> str:
    """Render PostgreSQL INT8RANGE types as TEXT in SQLite test runs."""
    return "TEXT"


@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_: Any, compiler: Any, **kw: Any) -> str:
    """Render PostgreSQL JSONB types as JSON in SQLite test runs."""
    return "JSON"


# Auto-populate AuditLog.id and ScopeDecision.id on SQLite test runs where Identity(always=True) on
# composite PK is not automatically auto-incremented by SQLite
_audit_id_counter = itertools.count(1)
_scope_decision_id_counter = itertools.count(1)


@event.listens_for(AuditLog, "before_insert")
def _set_audit_log_id_sqlite(mapper: Any, connection: Any, target: Any) -> None:
    if connection.dialect.name == "sqlite" and getattr(target, "id", None) is None:
        target.id = next(_audit_id_counter)


@event.listens_for(ScopeDecision, "before_insert")
def _set_scope_decision_id_sqlite(mapper: Any, connection: Any, target: Any) -> None:
    if connection.dialect.name == "sqlite" and getattr(target, "id", None) is None:
        target.id = next(_scope_decision_id_counter)
