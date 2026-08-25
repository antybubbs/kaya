"""Safe, standalone SQLite-to-PostgreSQL conversion for disposable/offline use."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

try:
    import resource
except ImportError:  # pragma: no cover - Windows has no resource module
    resource = None

from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import Boolean, Date, DateTime, LargeBinary, create_engine, inspect, text
from sqlalchemy.engine import Engine

from app.db.backup import MigrationBackup, create_sqlite_backup
from app.core.config import get_settings, postgres_engine_options
from app.db.migrations import _alembic_config
from app.db.sqlite_temp import configure_sqlite_temp_directory
from app.db.phase6_test_hooks import hit as test_failpoint, record as test_record
from app.db.validation import validate_engine_schema
from app.models.models import Base

logger = logging.getLogger(__name__)
STATE_TABLE = "kaya_migration_state"
STATE_PREPARING = "PREPARING"
STATE_COPYING = "COPYING"
STATE_VALIDATING = "VALIDATING"
STATE_COMPLETED = "COMPLETED"
STATE_FAILED = "FAILED"
DEFAULT_BATCH_SIZE = 2_000
SUPPORTED_POSTGRES_MAJOR = 16
ALEMBIC_SEEDED_DATA_TABLES = {"hardware_asset_tag_sequences"}


@dataclass(frozen=True)
class ForeignKeyDependency:
    """One reflected child-to-parent dependency in the PostgreSQL target."""

    child_table: str
    child_columns: tuple[str, ...]
    parent_table: str
    parent_columns: tuple[str, ...]
    nullable: bool

    @property
    def label(self) -> str:
        child = ",".join(self.child_columns)
        parent = ",".join(self.parent_columns)
        return f"{self.child_table}.{child}->{self.parent_table}.{parent}"


@dataclass(frozen=True)
class DependencyPlan:
    order: tuple[str, ...]
    cycles: tuple[tuple[str, ...], ...]
    deferred: tuple[ForeignKeyDependency, ...]


class SQLiteToPostgresError(RuntimeError):
    """A safe conversion failure; the source and target remain inspectable."""

    migration_id: str | None = None


def _memory_snapshot() -> dict[str, int | None]:
    """Read process RSS/high-water memory; excludes PostgreSQL and filesystem cache."""
    values: dict[str, int | None] = {"rss_kb": None, "hwm_kb": None}
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            key, _, value = line.partition(":")
            if key in {"VmRSS", "VmHWM"}:
                values[{"VmRSS": "rss_kb", "VmHWM": "hwm_kb"}[key]] = int(value.strip().split()[0])
    except (OSError, ValueError):
        pass
    if values["hwm_kb"] is None and resource is not None:
        values["hwm_kb"] = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return values


def _record_memory(report: dict[str, Any], stage: str) -> None:
    snapshot = {"stage": stage, **_memory_snapshot()}
    report.setdefault("memory_stages", []).append(snapshot)
    logger.info(
        "migration_memory stage=%s rss_kb=%s hwm_kb=%s",
        stage,
        snapshot["rss_kb"],
        snapshot["hwm_kb"],
    )


def _filesystem_accounting(path: Path, required_bytes: int) -> dict[str, Any]:
    """Return capacity for the filesystem containing *path* without following stale paths."""
    resolved = path.resolve()
    existing = resolved
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    usage = shutil.disk_usage(existing)
    return {
        "path": str(resolved),
        "filesystem_path": str(existing),
        "device": getattr(existing.stat(), "st_dev", None),
        "available_bytes": usage.free,
        "required_bytes": required_bytes,
        "capacity_status": "sufficient" if usage.free >= required_bytes else "insufficient",
    }


def _local_preflight_filesystems(
    source_path: Path, backup_directory: Path, sqlite_temp_directory: Path
) -> tuple[dict[str, Any], int]:
    source_size = source_path.stat().st_size
    # One source-sized verified backup plus one source-sized conversion/temp
    # allowance. Shared devices are grouped so capacity is never counted twice.
    required_by_device: dict[Any, int] = defaultdict(int)
    records = {
        "sqlite_source": _filesystem_accounting(source_path, source_size * 2),
        "sqlite_backup": _filesystem_accounting(backup_directory, source_size),
        "sqlite_temp": _filesystem_accounting(sqlite_temp_directory, source_size),
    }
    for record in records.values():
        required_by_device[record["device"]] += source_size
    for name, record in records.items():
        record["shared_required_bytes"] = required_by_device[record["device"]]
        record["capacity_status"] = (
            "sufficient"
            if record["available_bytes"] >= record["shared_required_bytes"]
            else "insufficient"
        )
        logger.info(
            "migration_filesystem name=%s path=%s filesystem_path=%s device=%s available_bytes=%s required_bytes=%s shared_required_bytes=%s status=%s",
            name,
            record["path"],
            record["filesystem_path"],
            record["device"],
            record["available_bytes"],
            record["required_bytes"],
            record["shared_required_bytes"],
            record["capacity_status"],
        )
    insufficient = [record for record in records.values() if record["capacity_status"] == "insufficient"]
    if insufficient:
        names = ", ".join(name for name, record in records.items() if record["capacity_status"] == "insufficient")
        raise SQLiteToPostgresError(
            f"Insufficient known local filesystem capacity for migration workspace(s): {names}."
        )
    return records, source_size * 3


def _classify_sqlite_storage_error(
    exc: BaseException, source_path: Path, sqlite_temp_directory: Path
) -> str | None:
    """Classify SQLite ENOSPC using filesystem state available to Kaya."""
    message = str(exc).lower()
    if "database or disk is full" not in message and "no space left on device" not in message:
        return None
    try:
        temp_free = shutil.disk_usage(sqlite_temp_directory).free
        source_free = shutil.disk_usage(source_path.parent).free
    except OSError:
        return "SQLite storage exhausted; filesystem attribution unavailable."
    if temp_free == 0 and source_free > 0:
        return "SQLite managed temporary workspace exhausted."
    if temp_free == 0:
        return "SQLite managed temporary workspace or shared SQLite filesystem exhausted."
    return "SQLite source filesystem or another SQLite workspace exhausted."


def _source_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    for label, candidate in ((b"database\0", path), (b"wal\0", path.with_name(path.name + "-wal"))):
        digest.update(label)
        if not candidate.is_file():
            digest.update(b"missing\0")
            continue
        digest.update(str(candidate.stat().st_size).encode("ascii") + b"\0")
        with candidate.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def _heads() -> tuple[str, ScriptDirectory]:
    config = _alembic_config("sqlite:///:memory:")
    script = ScriptDirectory.from_config(config)
    heads = script.get_heads()
    if len(heads) != 1:
        raise SQLiteToPostgresError(f"Expected one Alembic head, found: {', '.join(heads) or 'none'}.")
    return heads[0], script


def _read_source_revision(connection: sqlite3.Connection) -> str:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'"
    ).fetchone()
    if row is None:
        raise SQLiteToPostgresError("Source SQLite database has no Alembic revision table.")
    revisions = [item[0] for item in connection.execute("SELECT version_num FROM alembic_version")]
    if len(revisions) != 1:
        raise SQLiteToPostgresError("Source SQLite database must contain exactly one Alembic revision.")
    return revisions[0]


def _source_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'alembic_version'"
        )
    }


def _validate_source(
    path: Path, expected_head: str, *, allow_historical: bool = False
) -> tuple[str, str, set[str]]:
    if not path.is_file():
        raise SQLiteToPostgresError("Source SQLite database is not a regular file.")
    fingerprint_before = _source_fingerprint(path)
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise SQLiteToPostgresError("Source SQLite database could not be opened read-only.") from exc
    try:
        connection.execute("PRAGMA query_only=ON")
        quick = connection.execute("PRAGMA quick_check").fetchall()
        if quick != [("ok",)]:
            raise SQLiteToPostgresError(f"SQLite quick_check failed: {quick[:3]!r}")
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_keys:
            raise SQLiteToPostgresError("SQLite foreign_key_check found orphaned rows.")
        revision = _read_source_revision(connection)
        if revision != expected_head and not allow_historical:
            raise SQLiteToPostgresError(
                f"Source revision {revision!r} is unsupported; upgrade it explicitly to {expected_head!r} first."
            )
        tables = _source_tables(connection)
    except sqlite3.Error as exc:
        raise SQLiteToPostgresError("Source SQLite integrity validation failed.") from exc
    finally:
        connection.close()
    return revision, fingerprint_before, tables


def _application_tables() -> set[str]:
    return set(Base.metadata.tables)


def _target_version(engine: Engine) -> str:
    try:
        with engine.connect() as connection:
            version = connection.execute(text("SHOW server_version_num")).scalar_one()
    except Exception as exc:
        raise SQLiteToPostgresError("PostgreSQL target is unavailable or credentials are invalid.") from exc
    major = int(str(version)[:2])
    if major != SUPPORTED_POSTGRES_MAJOR:
        raise SQLiteToPostgresError(f"PostgreSQL {major} is unsupported; PostgreSQL 16 is required.")
    return str(version)


def _target_eligibility(engine: Engine) -> None:
    _target_version(engine)
    tables = set(inspect(engine).get_table_names())
    if tables:
        raise SQLiteToPostgresError(
            "PostgreSQL target is not empty; refusing to overwrite an existing or incomplete target."
        )


def _prepare_target(engine: Engine, target_url: str, expected_head: str) -> None:
    command.upgrade(_alembic_config(target_url), "head")
    validate_engine_schema(
        engine,
        Base.metadata,
        require_revision=expected_head,
        required_indexes=(("hardware_asset_photos", "uq_hardware_asset_photos_primary"),),
        required_triggers=("hardware_asset_photos_max_five",),
    )


def _dependency_edges(engine: Engine) -> tuple[list[str], list[ForeignKeyDependency]]:
    inspector = inspect(engine)
    tables = sorted(_application_tables())
    nullability = {
        table: {column["name"]: bool(column.get("nullable", True)) for column in inspector.get_columns(table)}
        for table in tables
    }
    edges: list[ForeignKeyDependency] = []
    for child_table in tables:
        for foreign_key in inspector.get_foreign_keys(child_table):
            parent_table = foreign_key.get("referred_table")
            child_columns = tuple(foreign_key.get("constrained_columns") or ())
            parent_columns = tuple(foreign_key.get("referred_columns") or ())
            if parent_table not in nullability or not child_columns or len(child_columns) != len(parent_columns):
                continue
            edges.append(
                ForeignKeyDependency(
                    child_table=child_table,
                    child_columns=child_columns,
                    parent_table=parent_table,
                    parent_columns=parent_columns,
                    nullable=all(nullability[child_table].get(column, True) for column in child_columns),
                )
            )
    return tables, sorted(edges, key=lambda edge: edge.label)


def _strongly_connected_components(tables: list[str], edges: list[ForeignKeyDependency]) -> list[tuple[str, ...]]:
    adjacency: dict[str, set[str]] = {table: set() for table in tables}
    for edge in edges:
        adjacency[edge.parent_table].add(edge.child_table)
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[tuple[str, ...]] = []

    def visit(table: str) -> None:
        nonlocal index
        indices[table] = index
        lowlinks[table] = index
        index += 1
        stack.append(table)
        on_stack.add(table)
        for child in sorted(adjacency[table]):
            if child not in indices:
                visit(child)
                lowlinks[table] = min(lowlinks[table], lowlinks[child])
            elif child in on_stack:
                lowlinks[table] = min(lowlinks[table], indices[child])
        if lowlinks[table] == indices[table]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == table:
                    break
            components.append(tuple(sorted(component)))

    for table in tables:
        if table not in indices:
            visit(table)
    return sorted(components)


def _cyclic_components(tables: list[str], edges: list[ForeignKeyDependency]) -> list[tuple[str, ...]]:
    components = _strongly_connected_components(tables, edges)
    return [
        component
        for component in components
        if len(component) > 1
        or any(edge.child_table == edge.parent_table == component[0] for edge in edges)
    ]


def _dependency_plan(engine: Engine) -> DependencyPlan:
    tables, all_edges = _dependency_edges(engine)
    original_cycles = _cyclic_components(tables, all_edges)
    deferred: list[ForeignKeyDependency] = []
    active_edges = list(all_edges)
    while cycles := _cyclic_components(tables, active_edges):
        component = cycles[0]
        members = set(component)
        candidates = sorted(
            (edge for edge in active_edges if edge.child_table in members and edge.parent_table in members and edge.nullable),
            key=lambda edge: edge.label,
        )
        if not candidates:
            raise SQLiteToPostgresError(
                f"Foreign-key cycle has no nullable edge that can be safely deferred: {', '.join(component)}."
            )
        deferred.append(candidates[0])
        active_edges.remove(candidates[0])

    parents: dict[str, set[str]] = {table: set() for table in tables}
    children: dict[str, set[str]] = defaultdict(set)
    for edge in active_edges:
        if edge.parent_table != edge.child_table:
            parents[edge.child_table].add(edge.parent_table)
            children[edge.parent_table].add(edge.child_table)
    ready = deque(sorted(table for table, dependencies in parents.items() if not dependencies))
    ordered: list[str] = []
    while ready:
        table = ready.popleft()
        ordered.append(table)
        for child in sorted(children[table]):
            parents[child].discard(table)
            if not parents[child]:
                ready.append(child)
    if len(ordered) != len(tables):
        raise SQLiteToPostgresError("Unable to produce a complete foreign-key-safe table order.")
    return DependencyPlan(tuple(ordered), tuple(original_cycles), tuple(sorted(deferred, key=lambda edge: edge.label)))


def _copy_order(engine: Engine) -> tuple[list[str], list[list[str]]]:
    """Compatibility wrapper for callers that only need the ordered tables."""
    plan = _dependency_plan(engine)
    return list(plan.order), [list(cycle) for cycle in plan.cycles]


def _state_create(
    engine: Engine,
    migration_id: str,
    source_fingerprint: str,
    source_revision: str,
    target_revision: str,
    *,
    original_source_fingerprint: str | None = None,
    conversion_source_fingerprint: str | None = None,
    original_source_snapshot_fingerprint: str | None = None,
) -> None:
    original_source_fingerprint = original_source_fingerprint or source_fingerprint
    conversion_source_fingerprint = conversion_source_fingerprint or source_fingerprint
    if not original_source_snapshot_fingerprint:
        raise SQLiteToPostgresError("A verified original SQLite snapshot is required for migration state.")
    with engine.begin() as connection:
        connection.execute(text(f"""
            CREATE TABLE {STATE_TABLE} (
                migration_id VARCHAR(80) PRIMARY KEY,
                source_fingerprint VARCHAR(64) NOT NULL,
                original_source_fingerprint VARCHAR(64) NOT NULL,
                conversion_source_fingerprint VARCHAR(64) NOT NULL,
                original_source_snapshot_fingerprint VARCHAR(64) NOT NULL,
                source_revision VARCHAR(80) NOT NULL,
                target_revision VARCHAR(80) NOT NULL,
                started_at TIMESTAMP NOT NULL,
                state VARCHAR(20) NOT NULL,
                current_table VARCHAR(255),
                copied_rows BIGINT NOT NULL DEFAULT 0,
                validation_state VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                completed_at TIMESTAMP,
                error_message TEXT
            )
        """))
        connection.execute(
            text(f"INSERT INTO {STATE_TABLE} (migration_id, source_fingerprint, original_source_fingerprint, conversion_source_fingerprint, original_source_snapshot_fingerprint, source_revision, target_revision, started_at, state) VALUES (:id, :fingerprint, :original_fingerprint, :conversion_fingerprint, :original_snapshot_fingerprint, :source_revision, :target_revision, :started_at, :state)"),
            {"id": migration_id, "fingerprint": source_fingerprint, "original_fingerprint": original_source_fingerprint, "conversion_fingerprint": conversion_source_fingerprint, "original_snapshot_fingerprint": original_source_snapshot_fingerprint, "source_revision": source_revision, "target_revision": target_revision, "started_at": datetime.now(UTC).replace(tzinfo=None), "state": STATE_PREPARING},
        )


def _state_update(engine: Engine, migration_id: str, **values: Any) -> None:
    assignments = ", ".join(f"{key} = :{key}" for key in values)
    values["migration_id"] = migration_id
    with engine.begin() as connection:
        connection.execute(text(f"UPDATE {STATE_TABLE} SET {assignments} WHERE migration_id = :migration_id"), values)


def _canonical(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"binary_sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
    if isinstance(value, (datetime,)):
        return value.isoformat()
    return value


def _hash_rows(rows: list[dict[str, Any]], columns: list[str]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        encoded = json.dumps({column: _canonical(row.get(column)) for column in columns}, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        digest.update(encoded + b"\n")
    return digest.hexdigest()


def _update_digest(digest: Any, rows: list[dict[str, Any]], columns: list[str], table_name: str) -> None:
    table = Base.metadata.tables[table_name]
    for row in rows:
        encoded = json.dumps(
            {column: _canonical(_convert_value(row.get(column), table.c[column])) for column in columns},
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        digest.update(encoded + b"\n")


def _stream_source_hash(connection: sqlite3.Connection, table_name: str, columns: list[str]) -> tuple[int, str, Any, Any]:
    digest = hashlib.sha256()
    cursor = connection.execute(f"SELECT {', '.join(columns)} FROM {table_name} ORDER BY {('id' if 'id' in columns else ', '.join(columns))}")
    count = 0
    minimum = maximum = None
    while rows := cursor.fetchmany(DEFAULT_BATCH_SIZE):
        mapped = [dict(zip(columns, row, strict=True)) for row in rows]
        _update_digest(digest, mapped, columns, table_name)
        count += len(mapped)
        if "id" in columns:
            minimum = mapped[0]["id"] if minimum is None else minimum
            maximum = mapped[-1]["id"]
    return count, digest.hexdigest(), minimum, maximum


def _stream_target_hash(engine: Engine, table_name: str, columns: list[str]) -> tuple[int, str, Any, Any]:
    digest = hashlib.sha256()
    count = 0
    minimum = maximum = None
    with engine.connect() as connection:
        streaming_connection = connection.execution_options(
            stream_results=True,
            max_row_buffer=DEFAULT_BATCH_SIZE,
        )
        result = streaming_connection.execute(
            text(f"SELECT {', '.join(columns)} FROM {table_name} ORDER BY {('id' if 'id' in columns else ', '.join(columns))}")
        )
        try:
            while rows := result.mappings().fetchmany(DEFAULT_BATCH_SIZE):
                mapped = [dict(row) for row in rows]
                _update_digest(digest, mapped, columns, table_name)
                count += len(mapped)
                if "id" in columns:
                    minimum = mapped[0]["id"] if minimum is None else minimum
                    maximum = mapped[-1]["id"]
        finally:
            result.close()
    return count, digest.hexdigest(), minimum, maximum


def _convert_value(value: Any, column: Any) -> Any:
    if value is None:
        return None
    if isinstance(column.type, Boolean):
        if value in (0, False, "0", "false", "FALSE"):
            return False
        if value in (1, True, "1", "true", "TRUE"):
            return True
        raise SQLiteToPostgresError(f"Malformed Boolean value encountered in column {column.name!r}.")
    if isinstance(column.type, LargeBinary) and isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(column.type, DateTime) and isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    if isinstance(column.type, Date) and isinstance(value, str):
        return date.fromisoformat(value)
    return value


def _table_source_rows(connection: sqlite3.Connection, table: str, columns: list[str], batch_size: int):
    order = "id" if "id" in columns else ", ".join(columns)
    cursor = connection.execute(f"SELECT {', '.join(columns)} FROM {table} ORDER BY {order}")
    while rows := cursor.fetchmany(batch_size):
        yield [dict(zip(columns, row, strict=True)) for row in rows]


def _copy_table(
    source: sqlite3.Connection,
    target: Engine,
    table_name: str,
    batch_size: int,
    memory_callback: Any = None,
    deferred_columns: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    source_columns = [row[1] for row in source.execute(f"PRAGMA table_info({table_name})")]
    target_table = Base.metadata.tables[table_name]
    columns = [column.name for column in target_table.columns if column.name in source_columns]
    primary_key = [column.name for column in target_table.primary_key.columns]
    existing: dict[tuple[Any, ...], dict[str, Any]] = {}
    if primary_key:
        with target.connect() as connection:
            existing = {
                tuple(row[column] for column in primary_key): dict(row)
                for row in connection.execute(text(f"SELECT {', '.join(columns)} FROM {table_name}")).mappings()
            }
        if table_name in ALEMBIC_SEEDED_DATA_TABLES and existing:
            with target.begin() as connection:
                connection.execute(text(f"DELETE FROM {table_name}"))
            existing = {}
    count = 0
    batches = 0
    started = time.monotonic()
    source_hash = hashlib.sha256()
    for rows in _table_source_rows(source, table_name, columns, batch_size):
        converted = [{column: _convert_value(row[column], target_table.c[column]) for column in columns} for row in rows]
        insert_rows = [row.copy() for row in converted]
        for row in insert_rows:
            for column in deferred_columns:
                if column in row:
                    row[column] = None
        to_insert = []
        for row, insert_row in zip(converted, insert_rows, strict=True):
            key = tuple(row[column] for column in primary_key)
            if key in existing:
                if _hash_rows([row], columns) != _hash_rows([existing[key]], columns):
                    raise SQLiteToPostgresError(f"Target contains conflicting pre-existing data in {table_name} primary key {key!r}.")
                continue
            to_insert.append(insert_row)
        if to_insert:
            with target.begin() as connection:
                connection.execute(target_table.insert(), to_insert)
        encoded = _hash_rows(converted, columns).encode("ascii")
        source_hash.update(encoded)
        count += len(converted)
        batches += 1
        logger.info("copy table=%s state=progress copied=%s batch=%s", table_name, count, batches)
        if memory_callback is not None and batches % 25 == 0:
            memory_callback(f"copy:{table_name}:batch={batches}")
    elapsed = time.monotonic() - started
    return {"source_rows": count, "copied_rows": count, "batches": batches, "elapsed_seconds": round(elapsed, 3), "rows_per_second": round(count / max(elapsed, 0.001), 2), "source_hash": source_hash.hexdigest()}


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _restore_deferred_foreign_keys(
    source: sqlite3.Connection,
    target: Engine,
    dependencies: tuple[ForeignKeyDependency, ...],
) -> None:
    for dependency in dependencies:
        primary_key = [column.name for column in Base.metadata.tables[dependency.child_table].primary_key.columns]
        if not primary_key:
            raise SQLiteToPostgresError(f"Cannot restore deferred foreign key without a primary key: {dependency.label}.")
        columns = list(dict.fromkeys((*primary_key, *dependency.child_columns)))
        selected = ", ".join(_quote_identifier(column) for column in columns)
        rows = source.execute(
            f"SELECT {selected} FROM {_quote_identifier(dependency.child_table)} ORDER BY "
            f"{', '.join(_quote_identifier(column) for column in primary_key)}"
        ).fetchall()
        if not rows:
            continue
        assignments = ", ".join(f"{_quote_identifier(column)} = :set_{column}" for column in dependency.child_columns)
        predicate = " AND ".join(f"{_quote_identifier(column)} = :key_{column}" for column in primary_key)
        statement = text(
            f"UPDATE {_quote_identifier(dependency.child_table)} SET {assignments} WHERE {predicate}"
        )
        parameters = []
        for row in rows:
            values = dict(zip(columns, row, strict=True))
            parameters.append(
                {
                    **{f"set_{column}": values[column] for column in dependency.child_columns},
                    **{f"key_{column}": values[column] for column in primary_key},
                }
            )
        with target.begin() as connection:
            connection.execute(statement, parameters)
        logger.info("copy deferred_fk=restored dependency=%s rows=%s", dependency.label, len(rows))


def _repair_sequences(engine: Engine) -> list[dict[str, Any]]:
    repaired = []
    inspector = inspect(engine)
    for table in sorted(_application_tables()):
        for column in inspector.get_columns(table):
            if column["name"] != "id":
                continue
            with engine.begin() as connection:
                sequence = connection.execute(text("SELECT pg_get_serial_sequence(:table_name, 'id')"), {"table_name": table}).scalar_one_or_none()
                if not sequence:
                    continue
                maximum = connection.execute(text(f"SELECT max(id) FROM {table}")).scalar_one()
                if maximum is None:
                    connection.execute(text("SELECT setval(:sequence, 1, false)"), {"sequence": sequence})
                    next_value = 1
                else:
                    connection.execute(text("SELECT setval(:sequence, :maximum, true)"), {"sequence": sequence, "maximum": maximum})
                    next_value = maximum + 1
            repaired.append({"table": table, "sequence": sequence, "max_imported_id": maximum, "next_value": next_value, "status": "repaired"})
    return repaired


def _validate_target(engine: Engine, source_path: Path, source_connection: sqlite3.Connection, report: dict[str, Any]) -> None:
    validation_started = time.monotonic()
    _state_update(engine, report["migration_id"], state=STATE_VALIDATING, validation_state="RUNNING")
    for table_name in sorted(_application_tables()):
        source_count = source_connection.execute(f"SELECT count(*) FROM {table_name}").fetchone()[0]
        with engine.connect() as connection:
            target_count = connection.execute(text(f"SELECT count(*) FROM {table_name}")).scalar_one()
        if source_count != target_count:
            raise SQLiteToPostgresError(f"Row-count mismatch for {table_name}: source={source_count} target={target_count}.")
        columns = [column.name for column in Base.metadata.tables[table_name].columns]
        _record_memory(report, f"validation:{table_name}:before_source_hash")
        source_count, source_hash, source_min_id, source_max_id = _stream_source_hash(source_connection, table_name, columns)
        _record_memory(report, f"validation:{table_name}:after_source_hash")
        target_count, target_hash, target_min_id, target_max_id = _stream_target_hash(engine, table_name, columns)
        _record_memory(report, f"validation:{table_name}:after_target_hash")
        if source_count != target_count or source_hash != target_hash:
            raise SQLiteToPostgresError(f"Deterministic integrity hash mismatch for {table_name}.")
        report["tables"][table_name]["target_rows"] = target_count
        report["tables"][table_name]["source_min_id"] = source_min_id
        report["tables"][table_name]["target_min_id"] = target_min_id
        report["tables"][table_name]["source_max_id"] = source_max_id
        report["tables"][table_name]["target_max_id"] = target_max_id
        report["tables"][table_name]["source_hash"] = source_hash
        report["tables"][table_name]["target_hash"] = target_hash
        report["tables"][table_name]["validation"] = "passed"
        _record_memory(report, f"validation:{table_name}")
    with engine.connect() as connection:
        violations = connection.execute(text("SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND convalidated = false")).scalar_one()
    if violations:
        raise SQLiteToPostgresError("PostgreSQL contains unvalidated foreign-key constraints.")
    report["foreign_key_violations"] = 0
    _state_update(engine, report["migration_id"], state=STATE_COMPLETED, validation_state="PASSED", completed_at=datetime.now(UTC).replace(tzinfo=None), current_table=None)
    report["validation_seconds"] = round(time.monotonic() - validation_started, 3)


def preflight(
    source_path: Path, target_url: str, allow_historical: bool = False
) -> dict[str, Any]:
    expected_head, _ = _heads()
    source_path = source_path.resolve()
    sqlite_temp_directory = configure_sqlite_temp_directory(source_path)
    backup_directory = source_path.parent / "backups"
    test_failpoint("before_source_capture")
    revision, fingerprint, tables = _validate_source(
        source_path, expected_head, allow_historical=allow_historical
    )
    test_record("sqlite.source_capture", boundary="preflight", fingerprint=fingerprint)
    test_failpoint("after_source_capture")
    target = create_engine(target_url, **postgres_engine_options(get_settings()))
    _target_eligibility(target)
    filesystems, estimated = _local_preflight_filesystems(source_path, backup_directory, sqlite_temp_directory)
    return {"source_engine": "sqlite", "source_revision": revision, "target_engine": "postgresql", "target_revision": expected_head, "source_size_bytes": source_path.stat().st_size, "source_fingerprint": fingerprint, "source_tables": len(tables), "estimated_working_bytes": estimated, "known_local_filesystems": filesystems, "postgresql_target_capacity": "unknown_remote_or_container_filesystem", "dry_run": True}


def migrate(
    source_path: Path,
    target_url: str,
    backup_directory: Path,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    dry_run: bool = False,
    state_callback: Callable[[str], None] | None = None,
    original_source_fingerprint: str | None = None,
    original_source_snapshot_fingerprint: str | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    source_path = source_path.resolve()
    sqlite_temp_directory = configure_sqlite_temp_directory(source_path)
    filesystems, estimated = _local_preflight_filesystems(source_path, backup_directory, sqlite_temp_directory)
    expected_head, _ = _heads()
    test_failpoint("before_source_capture")
    revision, fingerprint_before, tables = _validate_source(source_path, expected_head)
    test_record("sqlite.source_capture", boundary="migration", fingerprint=fingerprint_before)
    test_failpoint("after_source_capture")
    expected_tables = _application_tables()
    if tables != expected_tables:
        missing = sorted(expected_tables - tables)
        extra = sorted(tables - expected_tables)
        raise SQLiteToPostgresError(f"Source table inventory is unsupported; missing={missing[:8]} extra={extra[:8]}.")
    target = create_engine(target_url, **postgres_engine_options(get_settings()))
    _target_eligibility(target)
    original_source_fingerprint = original_source_fingerprint or fingerprint_before
    report: dict[str, Any] = {"migration_id": str(uuid4()), "source_engine": "sqlite", "target_engine": "postgresql", "source_revision": revision, "target_revision": expected_head, "source_size_bytes": source_path.stat().st_size, "target_size_bytes": None, "batch_size": batch_size, "tables": {}, "sequence_repair": [], "rejected_rows": 0, "started_at": datetime.now(UTC).isoformat(), "result": "DRY_RUN" if dry_run else "INCOMPLETE", "original_source_fingerprint": original_source_fingerprint, "conversion_source_fingerprint": fingerprint_before}
    report["original_source_snapshot_fingerprint"] = original_source_snapshot_fingerprint
    _record_memory(report, "after_source_validation")
    report["known_local_filesystems"] = filesystems
    report["postgresql_target_capacity"] = "unknown_remote_or_container_filesystem"
    report["estimated_working_bytes"] = estimated
    if dry_run:
        return report
    try:
        backup: MigrationBackup = create_sqlite_backup(source_path, backup_directory, source_revision=revision, target_revision=expected_head)
    except Exception as exc:
        raise SQLiteToPostgresError("Verified SQLite backup could not be created; target preparation was not started.") from exc
    logger.info("migration_source_backup action=%s", backup.action)
    report["source_backup"] = {
        "action": backup.action,
        "path": backup.database_path.name,
        "size_bytes": backup.database_path.stat().st_size,
    }
    original_source_snapshot_fingerprint = original_source_snapshot_fingerprint or backup.snapshot_fingerprint
    if not original_source_snapshot_fingerprint:
        raise SQLiteToPostgresError("Verified SQLite backup has no stable snapshot identity.")
    report["original_source_snapshot_fingerprint"] = original_source_snapshot_fingerprint
    test_record("sqlite.source_capture", boundary="after_backup", fingerprint=_source_fingerprint(source_path))
    if state_callback is not None:
        state_callback("BACKED_UP")
    _record_memory(report, "after_backup")
    source_connection = sqlite3.connect(f"file:{source_path.as_posix()}?mode=ro", uri=True)
    source_connection.execute("PRAGMA query_only=ON")
    try:
        # Create the marker before Alembic changes the target.  A hard interruption
        # during schema preparation must remain visibly non-authoritative at startup.
        _state_create(
            target,
            report["migration_id"],
            fingerprint_before,
            revision,
            expected_head,
            original_source_fingerprint=original_source_fingerprint,
            conversion_source_fingerprint=fingerprint_before,
            original_source_snapshot_fingerprint=original_source_snapshot_fingerprint,
        )
        _prepare_target(target, target_url, expected_head)
        _record_memory(report, "after_target_preparation")
        if state_callback is not None:
            state_callback("POSTGRES_PREPARED")
        test_failpoint("after_postgres_prepare")
        with target.connect() as connection:
            wal_start = connection.execute(text("SELECT pg_current_wal_lsn()")).scalar_one()
        plan = _dependency_plan(target)
        report["dependency_order"] = list(plan.order)
        report["dependency_cycles"] = [list(cycle) for cycle in plan.cycles]
        report["deferred_foreign_keys"] = [dependency.label for dependency in plan.deferred]
        logger.info(
            "migration_copy_order tables=%s deferred_foreign_keys=%s order=%s",
            len(plan.order),
            len(plan.deferred),
            ",".join(plan.order),
        )
        _state_update(target, report["migration_id"], state=STATE_COPYING)
        if state_callback is not None:
            state_callback("MIGRATING")
        copy_started = time.monotonic()
        completed_tables = 0
        deferred_by_table: dict[str, frozenset[str]] = defaultdict(frozenset)
        for dependency in plan.deferred:
            deferred_by_table[dependency.child_table] = frozenset(
                (*deferred_by_table[dependency.child_table], *dependency.child_columns)
            )
        for table_name in plan.order:
            _state_update(target, report["migration_id"], current_table=table_name)
            total_rows = source_connection.execute(f"SELECT count(*) FROM {table_name}").fetchone()[0]
            logger.info("copy table=%s state=starting rows=%s", table_name, total_rows)
            report["tables"][table_name] = _copy_table(
                source_connection,
                target,
                table_name,
                batch_size,
                memory_callback=lambda stage: _record_memory(report, stage),
                deferred_columns=deferred_by_table[table_name],
            )
            _record_memory(report, f"after_table:{table_name}")
            logger.info(
                "copy table=%s state=complete elapsed=%s rows_per_second=%s",
                table_name,
                report["tables"][table_name]["elapsed_seconds"],
                report["tables"][table_name]["rows_per_second"],
            )
            completed_tables += 1
            logger.info("migration progress tables=%s/%s", completed_tables, len(plan.order))
            _state_update(target, report["migration_id"], copied_rows=report["tables"][table_name]["copied_rows"])
            test_failpoint("fail_during_copy")
        _restore_deferred_foreign_keys(source_connection, target, plan.deferred)
        report["data_copy_seconds"] = round(time.monotonic() - copy_started, 3)
        sequence_started = time.monotonic()
        report["sequence_repair"] = _repair_sequences(target)
        report["sequence_repair_seconds"] = round(time.monotonic() - sequence_started, 3)
        _record_memory(report, "after_sequence_repair")
        if state_callback is not None:
            state_callback("VALIDATING")
        test_failpoint("fail_during_validation")
        _validate_target(target, source_path, source_connection, report)
        _record_memory(report, "after_validation")
        if _source_fingerprint(source_path) != fingerprint_before:
            raise SQLiteToPostgresError("Source SQLite fingerprint changed during conversion; source was not stable.")
        test_record("sqlite.source_capture", boundary="before_cutover", fingerprint=fingerprint_before)
        if state_callback is not None:
            state_callback("POSTGRES_READY")
        with target.connect() as connection:
            report["target_size_bytes"] = connection.execute(text("SELECT pg_database_size(current_database())")).scalar_one()
        with target.connect() as connection:
            report["wal_bytes_generated"] = connection.execute(
                text("SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), :start_lsn)"), {"start_lsn": wal_start}
            ).scalar_one()
        report["result"] = "COMPLETED"
    except Exception as exc:
        storage_classification = _classify_sqlite_storage_error(
            exc, source_path, sqlite_temp_directory
        )
        if storage_classification:
            report["failure_attribution"] = storage_classification
        try:
            _state_update(target, report["migration_id"], state=STATE_FAILED, validation_state="FAILED", error_message=str(exc)[:500])
        except Exception:
            logger.exception("Could not mark failed migration target as incomplete")
        detail = f" {storage_classification}" if storage_classification else ""
        failure = SQLiteToPostgresError(
            f"SQLite-to-PostgreSQL migration failed; source and target were preserved.{detail}"
        )
        failure.migration_id = report["migration_id"]
        raise failure from exc
    finally:
        source_connection.close()
    report["duration_seconds"] = round(time.monotonic() - started, 3)
    report["peak_memory_kb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if resource else None
    _record_memory(report, "report_generation")
    report["rows_total"] = sum(item["source_rows"] for item in report["tables"].values())
    report["rows_per_second"] = round(report["rows_total"] / max(report["duration_seconds"], 0.001), 2)
    return report
