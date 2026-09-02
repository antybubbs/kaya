"""Add indexes used by DNS client detail history queries."""

import logging
import os
import shutil
import time
from pathlib import Path

from alembic import op
from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)

INDEXES = (
    (
        "dns_client_ip_history",
        "ix_dns_client_ip_history_client_last_seen",
        ("dns_client_id", "last_seen_at"),
    ),
    (
        "dns_client_hostname_history",
        "ix_dns_client_hostname_history_client_last_seen",
        ("dns_client_id", "last_seen_at"),
    ),
    (
        "dns_client_events",
        "ix_dns_client_events_client_created",
        ("dns_client_id", "created_at"),
    ),
    (
        "dns_client_traffic_events",
        "ix_dns_client_traffic_client_observed",
        ("dns_client_id", "observed_at"),
    ),
    (
        "dns_client_traffic_events",
        "ix_dns_client_traffic_client_blocked_observed",
        ("dns_client_id", "is_blocked", "observed_at"),
    ),
)


revision = "20260818_01"
down_revision = "20260813_01"
branch_labels = None
depends_on = None


def _existing_indexes(bind) -> dict[str, tuple[str, tuple[str, ...], bool]]:
    """Return all SQLite indexes, including indexes on unexpected tables."""
    inspector = inspect(bind)
    found = {}
    for table in inspector.get_table_names():
        for index in inspector.get_indexes(table):
            name = index.get("name")
            if name:
                found[name] = (
                    table,
                    tuple(index.get("column_names") or ()),
                    bool(index.get("unique")),
                )
    return found


def _storage_snapshot(bind) -> dict[str, int | str]:
    if bind.dialect.name == "postgresql":
        return {
            "database_bytes": int(
                bind.execute(text("SELECT pg_database_size(current_database())")).scalar_one()
            ),
            "available_bytes": None,
            "sqlite_temp_bytes": 0,
        }
    database_path = Path(bind.exec_driver_sql("PRAGMA database_list").first()[2])
    temp_directory = Path(os.environ.get("SQLITE_TMPDIR", "/tmp"))
    database_bytes = database_path.stat().st_size if database_path.is_file() else 0
    temp_bytes = sum(
        item.stat().st_size for item in temp_directory.iterdir() if item.is_file()
    ) if temp_directory.is_dir() else 0
    return {
        "database_bytes": database_bytes,
        "available_bytes": shutil.disk_usage(database_path.parent).free,
        "sqlite_temp_bytes": temp_bytes,
    }


def _ensure_index(bind, table: str, name: str, columns: tuple[str, ...]) -> None:
    existing = _existing_indexes(bind).get(name)
    expected = (table, columns, False)
    if existing is not None:
        if existing != expected:
            raise RuntimeError(
                f"Migration index collision for {name}: expected "
                f"{table}({', '.join(columns)}) unique=False, found "
                f"{existing[0]}({', '.join(existing[1])}) unique={existing[2]}"
            )
        logger.info("migration_index action=skip name=%s reason=already_exact", name)
        return
    started = time.monotonic()
    before = _storage_snapshot(bind)
    logger.info(
        "migration_index action=start name=%s database_bytes=%s available_bytes=%s sqlite_temp_bytes=%s",
        name,
        before["database_bytes"],
        before["available_bytes"],
        before["sqlite_temp_bytes"],
    )
    try:
        op.create_index(name, table, list(columns))
    except Exception:
        after = _storage_snapshot(bind)
        logger.error(
            "migration_index action=failed name=%s duration_seconds=%.3f database_bytes=%s available_bytes=%s sqlite_temp_bytes=%s",
            name,
            time.monotonic() - started,
            after["database_bytes"],
            after["available_bytes"],
            after["sqlite_temp_bytes"],
        )
        raise
    after = _storage_snapshot(bind)
    logger.info(
        "migration_index action=complete name=%s duration_seconds=%.3f database_bytes=%s available_bytes=%s sqlite_temp_bytes=%s",
        name,
        time.monotonic() - started,
        after["database_bytes"],
        after["available_bytes"],
        after["sqlite_temp_bytes"],
    )


def upgrade() -> None:
    bind = op.get_bind()
    for table, name, columns in INDEXES:
        _ensure_index(bind, table, name, columns)


def downgrade() -> None:
    bind = op.get_bind()
    for table, name, columns in reversed(INDEXES):
        existing = _existing_indexes(bind).get(name)
        if existing is None:
            continue
        if existing != (table, columns, False):
            raise RuntimeError(
                f"Cannot downgrade {name}: existing definition does not belong "
                "to this migration."
            )
        op.drop_index(name, table_name=table)
