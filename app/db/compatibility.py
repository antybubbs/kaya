"""Temporary bridge for Kaya databases created before Alembic.

This bridge preserves the v0.18.x-v0.25.x additive SQLite migration path. It is
targeted for review no earlier than v0.28, after the minimum supported upgrade
version and real-world recovery evidence are documented.
"""

import logging
import sqlite3
from pathlib import Path

from sqlalchemy import MetaData

logger = logging.getLogger(__name__)

# Kaya's models declare defaults only on the Python/ORM side (`default=...`),
# never as SQLite `server_default`. A column with `nullable=False` and no
# server default therefore has no literal DEFAULT in the baseline DDL, so a
# plain "ALTER TABLE ... ADD COLUMN ... NOT NULL" is rejected by SQLite for
# any existing legacy table ("Cannot add a NOT NULL column with default value
# NULL"). This module resolves that gap deterministically instead of copying
# the raw baseline DDL blindly:
#
#   * nullable columns                         -> ADD COLUMN, no default needed.
#   * NOT NULL with a literal baseline default  -> single ADD COLUMN ... DEFAULT ... NOT NULL.
#   * NOT NULL with a scalar ORM default        -> same as above, using the ORM's
#                                                  default.arg (so legacy rows get
#                                                  exactly what a new row would get).
#   * NOT NULL with a callable ORM default      -> resolved via _LEGACY_BACKFILL_RULES
#     (e.g. datetime.utcnow on created_at/updated_at) below, then the table is
#     rebuilt (SQLite's documented copy-and-rename procedure) so the final
#     column is genuinely NOT NULL.
#   * an empty legacy table (0 rows)            -> the whole table is recreated
#     directly from the baseline's own CREATE TABLE statement; there is no data
#     to lose or infer a value for.
#   * anything else                             -> migration stops with a clear,
#     actionable error naming the table/column, rather than a bare sqlite3 crash.
#
# Adding a new NOT NULL model column with only a client-side `default=`? It is
# covered automatically for scalar defaults. For a new callable default beyond
# created_at/updated_at, add an explicit entry to _LEGACY_BACKFILL_RULES -
# never let this module guess a value.

_TIMESTAMP_BACKFILL_COLUMNS = frozenset({"created_at", "updated_at"})

# Maps (table, column) -> a SQL expression (evaluated against the *existing*
# row) used to backfill a NOT NULL column that has no scalar default. Keep
# this list explicit and reviewed; do not add a wildcard fallback here.
_LEGACY_BACKFILL_RULES: dict[tuple[str, str], str] = {
    ("users", "updated_at"): "COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)",
}


class BaselineCompatibilityError(RuntimeError):
    """A legacy column cannot be added automatically and needs manual review."""


def migrate_pre_alembic_database(database_path: Path) -> None:
    # Keep one implementation during the transition. The script is retained for
    # manual recovery compatibility; ordinary startup invokes it through here.
    from scripts import migrate_sqlite

    previous_path = migrate_sqlite.DB_PATH
    try:
        migrate_sqlite.DB_PATH = database_path
        migrate_sqlite.main(quiet=True)
    finally:
        migrate_sqlite.DB_PATH = previous_path


def _sql_literal(value: object) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    raise TypeError(f"Unsupported literal default type: {type(value)!r}")


def _model_scalar_default(
    model_metadata: MetaData, table_name: str, column_name: str
) -> tuple[str | None, bool]:
    """Return (sql_literal, found) for a column's ORM-side scalar default."""
    table = model_metadata.tables.get(table_name)
    if table is None or column_name not in table.columns:
        return None, False
    default = table.columns[column_name].default
    if default is not None and getattr(default, "is_scalar", False):
        return _sql_literal(default.arg), True
    return None, False


def _column_has_callable_default(
    model_metadata: MetaData, table_name: str, column_name: str
) -> bool:
    table = model_metadata.tables.get(table_name)
    if table is None or column_name not in table.columns:
        return False
    default = table.columns[column_name].default
    return bool(default is not None and getattr(default, "is_callable", False))


def _backfill_expression(table_name: str, column_name: str) -> str | None:
    explicit = _LEGACY_BACKFILL_RULES.get((table_name, column_name))
    if explicit is not None:
        return explicit
    if column_name in _TIMESTAMP_BACKFILL_COLUMNS:
        return "CURRENT_TIMESTAMP"
    return None


def _log_step(
    object_type: str,
    table_name: str,
    *,
    column_name: str | None = None,
    index_name: str | None = None,
    nullable: bool | None = None,
    strategy: str | None = None,
) -> None:
    logger.info(
        "Kaya database: compatibility step type=%s table=%s column=%s index=%s "
        "nullable=%s strategy=%s",
        object_type,
        table_name,
        column_name or "-",
        index_name or "-",
        nullable if nullable is not None else "-",
        strategy or "-",
    )


def _create_missing_tables(
    target: sqlite3.Connection,
    table_rows: list[tuple[str, str]],
    target_tables: set[str],
) -> None:
    for name, sql in table_rows:
        if name in {"alembic_version", "sqlite_sequence"} or name in target_tables:
            continue
        _log_step("table", name, strategy="create_from_baseline")
        try:
            target.execute(sql)
        except sqlite3.OperationalError:
            logger.error(
                "Kaya database: compatibility step failed type=table table=%s "
                "operation=create_from_baseline",
                name,
            )
            raise


def _add_column(
    target: sqlite3.Connection,
    table_name: str,
    column_name: str,
    data_type: str,
    *,
    foreign_key: tuple[str, str, str] | None,
    not_null: bool,
    default_literal: str | None,
    strategy: str,
) -> None:
    parts = [f'ALTER TABLE "{table_name}" ADD COLUMN "{column_name}"', data_type]
    if foreign_key:
        referred_table, referred_column, on_delete = foreign_key
        parts.append(f'REFERENCES "{referred_table}"("{referred_column}")')
        if on_delete and on_delete != "NO ACTION":
            parts.append(f"ON DELETE {on_delete}")
    if default_literal is not None:
        parts.append(f"DEFAULT {default_literal}")
    if not_null:
        parts.append("NOT NULL")
    _log_step(
        "column",
        table_name,
        column_name=column_name,
        nullable=not not_null,
        strategy=strategy,
    )
    try:
        target.execute(" ".join(parts))
    except sqlite3.OperationalError:
        logger.error(
            "Kaya database: compatibility step failed type=column table=%s column=%s "
            "operation=add_column strategy=%s",
            table_name,
            column_name,
            strategy,
        )
        raise


def _rebuild_table_with_baseline_schema(
    target: sqlite3.Connection,
    baseline: sqlite3.Connection,
    table_name: str,
) -> None:
    """Recreate table_name using the baseline's CREATE TABLE, copying existing rows.

    Used once a table's newly-backfilled columns are all non-null in practice,
    so the physical schema can finally carry the real NOT NULL constraint that
    ADD COLUMN cannot express in a single step. Mirrors the copy/rename
    procedure already used by scripts/migrate_sqlite.py for users.password_hash.
    """
    baseline_sql = baseline.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
    ).fetchone()
    if baseline_sql is None:
        raise BaselineCompatibilityError(
            f"Cannot rebuild {table_name}: baseline schema definition is missing."
        )
    tmp_name = f"{table_name}__kaya_rebuild"
    rebuild_sql = (
        baseline_sql[0]
        .replace(f'"{table_name}"', f'"{tmp_name}"', 1)
        .replace(f" {table_name} ", f" {tmp_name} ", 1)
    )
    if tmp_name not in rebuild_sql:
        raise BaselineCompatibilityError(
            f"Cannot safely rebuild {table_name}: baseline CREATE TABLE statement "
            "could not be retargeted to a temporary name."
        )
    columns = [row[1] for row in target.execute(f'PRAGMA table_info("{table_name}")')]
    column_list = ", ".join(f'"{name}"' for name in columns)
    _log_step("table", table_name, strategy="rebuild_enforce_not_null")
    try:
        target.execute(rebuild_sql)
        target.execute(
            f'INSERT INTO "{tmp_name}" ({column_list}) '
            f'SELECT {column_list} FROM "{table_name}"'
        )
        target.execute(f'DROP TABLE "{table_name}"')
        target.execute(f'ALTER TABLE "{tmp_name}" RENAME TO "{table_name}"')
    except sqlite3.OperationalError:
        logger.error(
            "Kaya database: compatibility step failed type=table table=%s "
            "operation=rebuild_enforce_not_null",
            table_name,
        )
        raise


def _recreate_empty_table_from_baseline(
    target: sqlite3.Connection, baseline: sqlite3.Connection, table_name: str
) -> None:
    baseline_sql = baseline.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
    ).fetchone()
    if baseline_sql is None:
        raise BaselineCompatibilityError(
            f"Cannot recreate empty table {table_name}: baseline schema is missing."
        )
    _log_step("table", table_name, strategy="recreate_empty_from_baseline")
    try:
        target.execute(f'DROP TABLE "{table_name}"')
        target.execute(baseline_sql[0])
    except sqlite3.OperationalError:
        logger.error(
            "Kaya database: compatibility step failed type=table table=%s "
            "operation=recreate_empty_from_baseline",
            table_name,
        )
        raise


def _plan_column(
    model_metadata: MetaData,
    table_name: str,
    column_name: str,
    not_null: bool,
    default: str | None,
) -> tuple[str, str | None]:
    """Return (strategy, default_literal) for a missing column.

    strategy is one of: "nullable", "literal_default", "backfill", "empty_table_rebuild".
    Raises BaselineCompatibilityError if the column cannot be safely handled.
    """
    if not not_null:
        return "nullable", None
    if default is not None:
        return "literal_default", default
    model_default, found = _model_scalar_default(
        model_metadata, table_name, column_name
    )
    if found:
        return "literal_default", model_default
    if _backfill_expression(table_name, column_name) is not None:
        return "backfill", None
    if _column_has_callable_default(model_metadata, table_name, column_name):
        raise BaselineCompatibilityError(
            f"Column {table_name}.{column_name} is NOT NULL with a callable ORM "
            "default that has no registered backfill rule. Add an entry to "
            "_LEGACY_BACKFILL_RULES in app/db/compatibility.py after confirming "
            "the correct legacy-data value, then retry the migration."
        )
    raise BaselineCompatibilityError(
        f"Column {table_name}.{column_name} is NOT NULL with no server default, "
        "no ORM default and no registered backfill rule. This column cannot be "
        "added to an existing populated table automatically; it needs a "
        "reviewed migration rule before Kaya can start against this database."
    )


def create_missing_baseline_objects(
    database_path: Path, baseline_path: Path, model_metadata: MetaData
) -> None:
    """Create objects absent from an old release using the static baseline DDL.

    The legacy script historically ran after ``create_all``. During the bridge
    period this comparison preserves that additive behaviour without importing
    mutable model metadata or recreating any existing table, except where a
    legacy table must be rebuilt to add a genuinely NOT NULL column (see the
    module docstring for the full decision tree).

    The whole operation runs inside one explicit SQLite transaction
    (``autocommit=False``): SQLite auto-commits DDL under Python's legacy
    transaction mode, so without this a failure partway through would leave
    some columns/tables permanently added while others are missing, and the
    next startup attempt would face an unknown partially-migrated database
    instead of a clean retry.
    """
    with (
        sqlite3.connect(baseline_path) as baseline,
        sqlite3.connect(database_path, autocommit=False) as target,
    ):
        try:
            target_tables = {
                row[0]
                for row in target.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            table_rows = baseline.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL ORDER BY name"
            ).fetchall()
            _create_missing_tables(target, table_rows, target_tables)

            baseline_table_names = {row[0] for row in table_rows}
            for table_name in sorted(target_tables & baseline_table_names):
                target_columns = {
                    row[1]
                    for row in target.execute(f'PRAGMA table_info("{table_name}")')
                }
                baseline_columns = baseline.execute(
                    f'PRAGMA table_info("{table_name}")'
                ).fetchall()
                missing_columns = [
                    row for row in baseline_columns if row[1] not in target_columns
                ]
                if not missing_columns:
                    continue

                row_count = target.execute(
                    f'SELECT COUNT(*) FROM "{table_name}"'
                ).fetchone()[0]
                if row_count == 0:
                    # An empty legacy table has no data to lose or infer a value
                    # for. Recreating it from the baseline's own CREATE TABLE
                    # is always safe and sidesteps every backfill question below
                    # (including a missing primary-key column, which would
                    # otherwise be refused for a populated table).
                    _recreate_empty_table_from_baseline(target, baseline, table_name)
                    continue

                baseline_foreign_keys = {
                    row[3]: (row[2], row[4], row[6])
                    for row in baseline.execute(
                        f'PRAGMA foreign_key_list("{table_name}")'
                    )
                }

                needs_rebuild = False
                plans = []
                for (
                    _cid,
                    column_name,
                    data_type,
                    not_null,
                    default,
                    primary_key,
                ) in missing_columns:
                    if primary_key:
                        raise BaselineCompatibilityError(
                            f"Cannot safely add missing primary-key column "
                            f"{table_name}.{column_name}."
                        )
                    strategy, default_literal = _plan_column(
                        model_metadata, table_name, column_name, bool(not_null), default
                    )
                    plans.append(
                        (
                            column_name,
                            data_type,
                            bool(not_null),
                            default_literal,
                            baseline_foreign_keys.get(column_name),
                            strategy,
                        )
                    )
                    if strategy == "backfill":
                        needs_rebuild = True

                for (
                    column_name,
                    data_type,
                    not_null,
                    default_literal,
                    foreign_key,
                    strategy,
                ) in plans:
                    _add_column(
                        target,
                        table_name,
                        column_name,
                        data_type,
                        foreign_key=foreign_key,
                        not_null=False if strategy == "backfill" else not_null,
                        default_literal=default_literal,
                        strategy=strategy,
                    )

                for column_name, _dt, _nn, _dl, _fk, strategy in plans:
                    if strategy != "backfill":
                        continue
                    expression = _backfill_expression(table_name, column_name)
                    _log_step(
                        "backfill",
                        table_name,
                        column_name=column_name,
                        strategy=expression,
                    )
                    try:
                        target.execute(
                            f'UPDATE "{table_name}" SET "{column_name}" = {expression} '
                            f'WHERE "{column_name}" IS NULL'
                        )
                    except sqlite3.OperationalError:
                        logger.error(
                            "Kaya database: compatibility step failed type=backfill "
                            "table=%s column=%s",
                            table_name,
                            column_name,
                        )
                        raise

                if needs_rebuild:
                    _rebuild_table_with_baseline_schema(target, baseline, table_name)

            target_indexes = {
                row[0]
                for row in target.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )
            }
            index_rows = baseline.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY name"
            ).fetchall()
            for name, sql in index_rows:
                if name in target_indexes:
                    continue
                _log_step(
                    "index",
                    sql.split(" ON ")[-1].split("(")[0].strip(' "'),
                    index_name=name,
                )
                try:
                    target.execute(sql)
                except sqlite3.OperationalError:
                    logger.error(
                        "Kaya database: compatibility step failed type=index index=%s",
                        name,
                    )
                    raise
        except Exception:
            target.rollback()
            raise
        target.commit()
