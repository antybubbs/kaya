"""Temporary bridge for Kaya databases created before Alembic.

This bridge preserves the v0.18.x-v0.25.x additive SQLite migration path. It is
targeted for review no earlier than v0.28, after the minimum supported upgrade
version and real-world recovery evidence are documented.
"""

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


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


def create_missing_baseline_objects(database_path: Path, baseline_path: Path) -> None:
    """Create objects absent from an old release using the static baseline DDL.

    The legacy script historically ran after ``create_all``. During the bridge
    period this comparison preserves that additive behaviour without importing
    mutable model metadata or recreating any existing table.
    """
    with sqlite3.connect(baseline_path) as baseline, sqlite3.connect(
        database_path
    ) as target:
        target_tables = {
            row[0]
            for row in target.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        table_rows = baseline.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL ORDER BY name"
        ).fetchall()
        for name, sql in table_rows:
            if name in {"alembic_version", "sqlite_sequence"} or name in target_tables:
                continue
            logger.debug("Compatibility step: create missing baseline table %s", name)
            target.execute(sql)
        for table_name in sorted(target_tables & {row[0] for row in table_rows}):
            target_columns = {
                row[1] for row in target.execute(f'PRAGMA table_info("{table_name}")')
            }
            baseline_columns = baseline.execute(
                f'PRAGMA table_info("{table_name}")'
            ).fetchall()
            baseline_foreign_keys = {
                row[3]: (row[2], row[4], row[6])
                for row in baseline.execute(f'PRAGMA foreign_key_list("{table_name}")')
            }
            for (
                _cid,
                column_name,
                data_type,
                not_null,
                default,
                primary_key,
            ) in baseline_columns:
                if column_name in target_columns:
                    continue
                if primary_key:
                    raise RuntimeError(
                        f"Cannot safely add missing primary-key column {table_name}.{column_name}."
                    )
                parts = [
                    f'ALTER TABLE "{table_name}" ADD COLUMN "{column_name}"',
                    data_type,
                ]
                foreign_key = baseline_foreign_keys.get(column_name)
                if foreign_key:
                    referred_table, referred_column, on_delete = foreign_key
                    parts.append(f'REFERENCES "{referred_table}"("{referred_column}")')
                    if on_delete and on_delete != "NO ACTION":
                        parts.append(f"ON DELETE {on_delete}")
                if default is not None:
                    parts.append(f"DEFAULT {default}")
                if not_null:
                    parts.append("NOT NULL")
                logger.debug(
                    "Compatibility step: add missing baseline column %s.%s",
                    table_name,
                    column_name,
                )
                target.execute(" ".join(parts))
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
            logger.debug("Compatibility step: create missing baseline index %s", name)
            target.execute(sql)
        target.commit()
