from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    String,
    inspect,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.sql.type_api import TypeEngine

logger = logging.getLogger(__name__)

# SQLite's lock wait and VM execution limit are deliberately separate. A lock
# should fail quickly, while a healthy large database gets enough time to scan.
SQLITE_BUSY_TIMEOUT_MS = 15_000
TARGETED_VALIDATION_TIMEOUT_SECONDS = 30.0
QUICK_CHECK_TIMEOUT_SECONDS = 120.0
VALIDATION_PROGRESS_INTERVAL_SECONDS = 5.0
_PROGRESS_HANDLER_INSTRUCTIONS = 1_000

# These columns were originally declared INTEGER and changed to Float in
# ec21740 without rebuilding existing SQLite tables. SQLite preserves fractional
# values in INTEGER-affinity columns as REAL, so the declaration is safe only
# while every stored value remains NULL, INTEGER, or REAL.
APPROVED_HISTORICAL_FLOAT_INTEGER_COLUMNS = frozenset(
    {
        ("network_monitors", "last_latency_ms"),
        ("network_monitor_checks", "latency_ms"),
        ("network_monitor_checks", "response_time_ms"),
        ("network_monitor_statistics", "avg_latency_ms"),
        ("network_monitor_statistics", "max_latency_ms"),
    }
)


class DatabaseValidationError(RuntimeError):
    pass


class DatabaseLockedError(DatabaseValidationError):
    pass


class DatabaseCorruptError(DatabaseValidationError):
    pass


class DatabaseValidationTimeoutError(DatabaseValidationError):
    pass


class DatabaseUnreadableError(DatabaseValidationError):
    pass


class UnexpectedSQLiteError(DatabaseValidationError):
    pass


def validate_engine_schema(
    engine: Engine,
    metadata: MetaData,
    *,
    required_seed_tables: Iterable[str] = (),
    require_revision: str | None = None,
    required_indexes: Iterable[tuple[str, str]] = (),
    required_triggers: Iterable[str] = (),
) -> None:
    """Validate portable schema invariants through SQLAlchemy inspection."""
    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())
    missing_tables = set(metadata.tables) - actual_tables
    if missing_tables:
        raise DatabaseValidationError(
            f"Required tables are missing: {', '.join(sorted(missing_tables))}"
        )
    for table in metadata.tables.values():
        actual_columns = {column["name"] for column in inspector.get_columns(table.name)}
        missing_columns = {column.name for column in table.columns} - actual_columns
        if missing_columns:
            raise DatabaseValidationError(
                f"Table {table.name} is missing columns: {', '.join(sorted(missing_columns))}"
            )
        actual_indexes = {
            index.get("name") for index in inspector.get_indexes(table.name)
        }
        actual_indexes.update(
            constraint.get("name")
            for constraint in inspector.get_unique_constraints(table.name)
        )
        expected_indexes = {
            index.name for index in table.indexes if index.name
        }
        expected_indexes.update(
            constraint.name
            for constraint in table.constraints
            if constraint.name and constraint.__class__.__name__ == "UniqueConstraint"
        )
        missing_indexes = expected_indexes - actual_indexes
        if missing_indexes:
            raise DatabaseValidationError(
                f"Table {table.name} is missing indexes or unique constraints: {', '.join(sorted(missing_indexes))}"
            )
        actual_foreign_keys = {
            (
                column,
                foreign_key.get("referred_table"),
                (foreign_key.get("referred_columns") or [None])[0],
            )
            for foreign_key in inspector.get_foreign_keys(table.name)
            for column in (foreign_key.get("constrained_columns") or [None])
        }
        expected_foreign_keys = {
            (foreign_key.parent.name, foreign_key.column.table.name, foreign_key.column.name)
            for foreign_key in table.foreign_keys
        }
        if not expected_foreign_keys <= actual_foreign_keys:
            raise DatabaseValidationError(
                f"Table {table.name} is missing one or more required foreign keys."
            )
    for table_name in required_seed_tables:
        with engine.connect() as connection:
            if connection.execute(text(f'SELECT 1 FROM "{table_name}" LIMIT 1')).first() is None:
                raise DatabaseValidationError(f"Required seed table is empty: {table_name}")
    actual_required_indexes = {
        (table_name, index.get("name"))
        for table_name in actual_tables
        for index in inspect(engine).get_indexes(table_name)
    }
    missing_required_indexes = set(required_indexes) - actual_required_indexes
    if missing_required_indexes:
        raise DatabaseValidationError(
            "Required indexes are missing: "
            + ", ".join(f"{table}.{index}" for table, index in sorted(missing_required_indexes))
        )
    if required_triggers:
        if engine.dialect.name == "postgresql":
            with engine.connect() as connection:
                actual_triggers = {
                    row[0]
                    for row in connection.execute(
                        text("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal")
                    )
                }
        else:
            with engine.connect() as connection:
                actual_triggers = {
                    row[0]
                    for row in connection.execute(
                        text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
                    )
                }
        missing_triggers = set(required_triggers) - actual_triggers
        if missing_triggers:
            raise DatabaseValidationError(
                f"Required triggers are missing: {', '.join(sorted(missing_triggers))}"
            )
    if require_revision is not None:
        with engine.connect() as connection:
            revisions = [
                row[0]
                for row in connection.execute(text("SELECT version_num FROM alembic_version"))
            ]
        if revisions != [require_revision]:
            raise DatabaseValidationError(
                f"Database revision {revisions!r} does not match {require_revision!r}."
            )


def validate_engine_startup(engine: Engine, *, required_tables: Iterable[str] = ()) -> None:
    """Run portable startup object-presence checks."""
    actual_tables = set(inspect(engine).get_table_names())
    missing_tables = set(required_tables) - actual_tables
    if missing_tables:
        raise DatabaseValidationError(
            f"Required tables are missing: {', '.join(sorted(missing_tables))}"
        )


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@contextmanager
def _timed_operation(name: str) -> Iterator[None]:
    started = time.monotonic()
    logger.debug("%s started at %s", name, _timestamp())
    try:
        yield
    except Exception:
        logger.debug(
            "%s failed after %.3fs", name, time.monotonic() - started, exc_info=True
        )
        raise
    else:
        logger.debug(
            "%s completed at %s (elapsed %.3fs)",
            name,
            _timestamp(),
            time.monotonic() - started,
        )


def classify_sqlite_error(
    exc: sqlite3.Error, *, operation: str, timed_out: bool = False
) -> DatabaseValidationError:
    message = str(exc).lower()
    code = getattr(exc, "sqlite_errorcode", None)
    primary_code = code & 0xFF if isinstance(code, int) else None
    if timed_out or "interrupted" in message:
        return DatabaseValidationTimeoutError(
            f"SQLite validation timed out while {operation}."
        )
    if primary_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} or any(
        marker in message
        for marker in ("database is locked", "database table is locked")
    ):
        return DatabaseLockedError(
            f"SQLite database locked while {operation}; the {SQLITE_BUSY_TIMEOUT_MS}ms busy timeout expired."
        )
    if primary_code in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB} or any(
        marker in message
        for marker in ("database disk image is malformed", "file is not a database")
    ):
        return DatabaseCorruptError(f"SQLite database corrupt while {operation}.")
    unreadable_codes = {
        sqlite3.SQLITE_CANTOPEN,
        sqlite3.SQLITE_IOERR,
        sqlite3.SQLITE_PERM,
    }
    if primary_code in unreadable_codes or any(
        marker in message
        for marker in (
            "unable to open database file",
            "disk i/o error",
            "permission denied",
        )
    ):
        return DatabaseUnreadableError(f"SQLite database unreadable while {operation}.")
    return UnexpectedSQLiteError(f"Unexpected SQLite error while {operation}.")


def _read_only_uri(path: Path) -> str:
    encoded_path = quote(path.resolve().as_posix(), safe="/:")
    return f"file:{encoded_path}?mode=ro"


@contextmanager
def _validation_connection(path: Path) -> Iterator[sqlite3.Connection]:
    connection: sqlite3.Connection | None = None
    try:
        with _timed_operation("Opening read-only validation connection"):
            if not path.is_file():
                raise DatabaseUnreadableError(
                    "SQLite database unreadable: the validation target is missing or is not a regular file."
                )
            try:
                connection = sqlite3.connect(
                    _read_only_uri(path),
                    uri=True,
                    timeout=SQLITE_BUSY_TIMEOUT_MS / 1_000,
                )
                connection.execute(
                    f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}"
                ).close()
                connection.execute("PRAGMA query_only=ON").close()
            except sqlite3.Error as exc:
                raise classify_sqlite_error(
                    exc, operation="opening the read-only validation connection"
                ) from exc
        yield connection
    finally:
        if connection is not None:
            with _timed_operation("Closing validation connection"):
                try:
                    connection.close()
                except sqlite3.Error as exc:
                    raise classify_sqlite_error(
                        exc, operation="closing the validation connection"
                    ) from exc


def _rows(
    connection: sqlite3.Connection,
    sql: str,
    *,
    operation: str,
    timeout_seconds: float | None = None,
    log_timing: bool = False,
) -> list[tuple]:
    if timeout_seconds is None:
        timeout_seconds = TARGETED_VALIDATION_TIMEOUT_SECONDS
    started = time.monotonic()
    deadline = started + timeout_seconds
    next_progress = started + VALIDATION_PROGRESS_INTERVAL_SECONDS
    timed_out = False

    def progress() -> int:
        nonlocal next_progress, timed_out
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            return 1
        if now >= next_progress:
            logger.debug("%s still running (elapsed %.3fs)", operation, now - started)
            next_progress = now + VALIDATION_PROGRESS_INTERVAL_SECONDS
        return 0

    cursor: sqlite3.Cursor | None = None
    context = _timed_operation(operation) if log_timing else nullcontext()
    try:
        with context:
            connection.set_progress_handler(progress, _PROGRESS_HANDLER_INSTRUCTIONS)
            cursor = connection.execute(sql)
            return cursor.fetchall()
    except sqlite3.Error as exc:
        raise classify_sqlite_error(
            exc, operation=operation.lower(), timed_out=timed_out
        ) from exc
    finally:
        connection.set_progress_handler(None, 0)
        if cursor is not None:
            cursor.close()


def sqlite_type_affinity(declared_type: str) -> str:
    """Return SQLite's documented affinity for a declared column type."""
    declared = declared_type.strip().upper()
    if "INT" in declared:
        return "INTEGER"
    if any(marker in declared for marker in ("CHAR", "CLOB", "TEXT")):
        return "TEXT"
    if not declared or "BLOB" in declared:
        return "BLOB"
    if any(marker in declared for marker in ("REAL", "FLOA", "DOUB")):
        return "REAL"
    return "NUMERIC"


def _has_only_numeric_storage(
    connection: sqlite3.Connection, table_name: str, column_name: str
) -> bool:
    rows = _rows(
        connection,
        f'SELECT typeof("{column_name}"), count(*) FROM "{table_name}" '
        f'WHERE "{column_name}" IS NOT NULL GROUP BY typeof("{column_name}")',
        operation=f"checking numeric storage for {table_name}.{column_name}",
    )
    return {row[0] for row in rows} <= {"integer", "real"}


def _has_only_boolean_storage(
    connection: sqlite3.Connection, table_name: str, column_name: str
) -> bool:
    rows = _rows(
        connection,
        f'SELECT count(*) FROM "{table_name}" WHERE "{column_name}" IS NOT NULL '
        f'AND (typeof("{column_name}") != \'integer\' OR "{column_name}" NOT IN (0, 1))',
        operation=f"checking boolean storage for {table_name}.{column_name}",
    )
    return rows == [(0,)]


def _compatible_declared_type(
    connection: sqlite3.Connection,
    *,
    table_name: str,
    column_name: str,
    declared: str,
    expected: str,
    model_type: TypeEngine,
) -> bool:
    if declared == expected:
        return True

    actual_affinity = sqlite_type_affinity(declared)
    expected_affinity = sqlite_type_affinity(expected)

    if isinstance(model_type, Boolean):
        if actual_affinity == "INTEGER" and _has_only_boolean_storage(
            connection, table_name, column_name
        ):
            logger.debug(
                "Accepted SQLite type compatibility: %s.%s %s -> %s",
                table_name,
                column_name,
                declared,
                expected,
            )
            return True
        return False

    # Kaya's DateTime columns are declared DATETIME and SQLite stores their
    # values as text. Affinity alone cannot distinguish a date from arbitrary
    # NUMERIC data, so non-exact DateTime declarations remain unsupported.
    if isinstance(model_type, DateTime):
        return False

    if isinstance(model_type, Float):
        if actual_affinity == "REAL":
            return True
        if actual_affinity == "NUMERIC" and _has_only_numeric_storage(
            connection, table_name, column_name
        ):
            logger.debug(
                "Accepted SQLite type compatibility: %s.%s %s -> %s",
                table_name,
                column_name,
                declared,
                expected,
            )
            return True
        if (
            actual_affinity == "INTEGER"
            and (table_name, column_name) in APPROVED_HISTORICAL_FLOAT_INTEGER_COLUMNS
            and _has_only_numeric_storage(connection, table_name, column_name)
        ):
            logger.info(
                "Accepted historical SQLite type compatibility: %s.%s %s -> %s",
                table_name,
                column_name,
                declared,
                expected,
            )
            return True
        return False

    compatible_affinity = (
        (
            isinstance(model_type, Integer)
            and actual_affinity == expected_affinity == "INTEGER"
        )
        or (
            isinstance(model_type, String)
            and actual_affinity == expected_affinity == "TEXT"
        )
        or (
            isinstance(model_type, LargeBinary)
            and actual_affinity == expected_affinity == "BLOB"
        )
        or (
            isinstance(model_type, Numeric)
            and actual_affinity == expected_affinity == "NUMERIC"
            and _has_only_numeric_storage(connection, table_name, column_name)
        )
    )
    if compatible_affinity:
        logger.debug(
            "Accepted SQLite type compatibility: %s.%s %s -> %s",
            table_name,
            column_name,
            declared,
            expected,
        )
    return compatible_affinity


def validate_sqlite_readable(path: Path) -> None:
    """Confirm that SQLite can open and parse the database schema."""
    with _validation_connection(path) as connection:
        _rows(
            connection,
            "SELECT count(*) FROM sqlite_master",
            operation="Reading SQLite schema catalogue",
            log_timing=True,
        )


def validate_sqlite_integrity(
    path: Path, *, quick_check_timeout_seconds: float = QUICK_CHECK_TIMEOUT_SECONDS
) -> None:
    """Run explicit strict integrity diagnostics; routine startup does not call this."""
    with _validation_connection(path) as connection:
        try:
            quick_check = _rows(
                connection,
                "PRAGMA quick_check",
                operation="Running PRAGMA quick_check",
                timeout_seconds=quick_check_timeout_seconds,
                log_timing=True,
            )
        except DatabaseValidationTimeoutError as exc:
            raise DatabaseValidationTimeoutError(
                "SQLite quick_check timed out; strict database validation aborted."
            ) from exc
        if quick_check != [("ok",)]:
            raise DatabaseCorruptError("SQLite quick_check reported corruption.")
        foreign_keys = _rows(
            connection,
            "PRAGMA foreign_key_check",
            operation="Running PRAGMA foreign_key_check",
            log_timing=True,
        )
        if foreign_keys:
            raise DatabaseCorruptError(
                "SQLite foreign_key_check reported invalid references."
            )


def validate_legacy_database(path: Path) -> None:
    validate_sqlite_readable(path)
    with _validation_connection(path) as connection:
        tables = {
            row[0]
            for row in _rows(
                connection,
                "SELECT name FROM sqlite_master WHERE type='table'",
                operation="reading the legacy table list",
            )
        }
    if "users" not in tables:
        raise DatabaseValidationError(
            "The pre-Alembic database is missing the required users table."
        )


def validate_startup_database(
    path: Path, *, required_tables: Iterable[str] = ()
) -> None:
    """Run bounded object-presence checks for a clean startup."""
    validate_sqlite_readable(path)
    with _validation_connection(path) as connection:
        actual_tables = {
            row[0]
            for row in _rows(
                connection,
                "SELECT name FROM sqlite_master WHERE type='table'",
                operation="reading the startup table list",
            )
        }
    missing_tables = set(required_tables) - actual_tables
    if missing_tables:
        raise DatabaseValidationError(
            f"Required tables are missing: {', '.join(sorted(missing_tables))}"
        )


def validate_schema(
    path: Path,
    metadata: MetaData,
    *,
    required_seed_tables: Iterable[str] = (),
    require_revision: bool = True,
) -> None:
    validate_sqlite_readable(path)
    with _validation_connection(path) as connection:
        actual_tables = {
            row[0]
            for row in _rows(
                connection,
                "SELECT name FROM sqlite_master WHERE type='table'",
                operation="reading the schema table list",
            )
        }
        missing_tables = set(metadata.tables) - actual_tables
        if missing_tables:
            raise DatabaseValidationError(
                f"Required tables are missing: {', '.join(sorted(missing_tables))}"
            )
        for table in metadata.tables.values():
            actual_columns = {
                row[1]: row
                for row in _rows(
                    connection,
                    f'PRAGMA table_info("{table.name}")',
                    operation=f"reading columns for table {table.name}",
                )
            }
            missing_columns = {column.name for column in table.columns} - set(
                actual_columns
            )
            if missing_columns:
                raise DatabaseValidationError(
                    f"Table {table.name} is missing columns: {', '.join(sorted(missing_columns))}"
                )
            for column in table.columns:
                declared = actual_columns[column.name][2].upper()
                expected = str(column.type.compile()).upper()
                if (
                    declared
                    and expected
                    and not _compatible_declared_type(
                        connection,
                        table_name=table.name,
                        column_name=column.name,
                        declared=declared,
                        expected=expected,
                        model_type=column.type,
                    )
                ):
                    logger.error(
                        "Unsupported SQLite type mismatch: %s.%s actual=%s expected=%s",
                        table.name,
                        column.name,
                        declared,
                        expected,
                    )
                    raise DatabaseValidationError(
                        f"Table {table.name} column {column.name} has type {declared}; expected {expected}."
                    )
            index_rows = _rows(
                connection,
                f'PRAGMA index_list("{table.name}")',
                operation=f"reading indexes for table {table.name}",
            )
            actual_index_names = {row[1] for row in index_rows}
            expected_index_names = {index.name for index in table.indexes if index.name}
            missing_indexes = expected_index_names - actual_index_names
            if missing_indexes:
                raise DatabaseValidationError(
                    f"Table {table.name} is missing indexes: {', '.join(sorted(missing_indexes))}"
                )
            actual_unique_columns = {
                tuple(
                    row[2]
                    for row in _rows(
                        connection,
                        f'PRAGMA index_info("{index_row[1]}")',
                        operation=f"reading unique index {index_row[1]}",
                    )
                )
                for index_row in index_rows
                if index_row[2]
            }
            expected_unique_columns = {
                tuple(column.name for column in constraint.columns)
                for constraint in table.constraints
                if constraint.__class__.__name__ == "UniqueConstraint"
            }
            if not expected_unique_columns <= actual_unique_columns:
                raise DatabaseValidationError(
                    f"Table {table.name} is missing one or more required unique constraints."
                )
            actual_foreign_keys = {
                (row[3], row[2], row[4])
                for row in _rows(
                    connection,
                    f'PRAGMA foreign_key_list("{table.name}")',
                    operation=f"reading foreign keys for table {table.name}",
                )
            }
            expected_foreign_keys = {
                (
                    foreign_key.parent.name,
                    foreign_key.column.table.name,
                    foreign_key.column.name,
                )
                for foreign_key in table.foreign_keys
            }
            if not expected_foreign_keys <= actual_foreign_keys:
                raise DatabaseValidationError(
                    f"Table {table.name} is missing one or more required foreign keys."
                )
        for table_name in required_seed_tables:
            _rows(
                connection,
                f'SELECT 1 FROM "{table_name}" LIMIT 1',
                operation=f"checking seed table {table_name}",
            )
        if require_revision:
            revisions = _rows(
                connection,
                "SELECT version_num FROM alembic_version",
                operation="reading the Alembic revision",
            )
            if len(revisions) != 1 or not revisions[0][0]:
                raise DatabaseValidationError(
                    "The Alembic revision state is missing or ambiguous."
                )
