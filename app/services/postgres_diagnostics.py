"""Redacted PostgreSQL operational diagnostics for administrators."""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from app.db.migrations import CURRENT_REVISION
from app.db.platform_compatibility import SUPPORTED_POSTGRES_MAJOR

logger = logging.getLogger(__name__)


def collect_postgres_diagnostics(engine: Engine, backup_directory: Path) -> dict:
    if engine.dialect.name != "postgresql":
        return {"available": False, "reason": "PostgreSQL is not the active database"}
    with engine.connect() as connection:
        database = connection.execute(
            text("SELECT current_database(), pg_database_size(current_database()), version(), current_setting('server_version_num')")
        ).one()
        activity = connection.execute(
            text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()")
        ).scalar_one()
        deadlocks = connection.execute(
            text("SELECT COALESCE(deadlocks, 0) FROM pg_stat_database WHERE datname = current_database()")
        ).scalar_one()
        tables = connection.execute(
            text("""
                SELECT relname, pg_total_relation_size(relid)
                FROM pg_catalog.pg_statio_user_tables
                ORDER BY pg_total_relation_size(relid) DESC LIMIT 10
            """)
        ).all()
        indexes = connection.execute(
            text("""
                SELECT indexrelname, relname, pg_relation_size(indexrelid)
                FROM pg_catalog.pg_stat_user_indexes
                ORDER BY pg_relation_size(indexrelid) DESC LIMIT 10
            """)
        ).all()
        blocking = _blocking_diagnostics(connection)
    pool = engine.pool
    archives = sorted(backup_directory.glob("kaya-*.dump"), key=lambda path: path.stat().st_mtime, reverse=True) if backup_directory.exists() else []
    return {
        "available": True,
        "database": database[0],
        "database_bytes": int(database[1]),
        "server_version": str(database[2]).split(" on ", 1)[0],
        "server_version_num": int(database[3]),
        "postgres_major_supported": SUPPORTED_POSTGRES_MAJOR,
        "current_alembic_revision": _revision(engine),
        "expected_alembic_head": CURRENT_REVISION,
        "compatibility_state": "compatible" if int(database[3]) // 10000 == SUPPORTED_POSTGRES_MAJOR else "unsupported_postgresql_major",
        "active_connections": int(activity),
        "deadlocks": int(deadlocks or 0),
        "pool": {
            "size": pool.size() if hasattr(pool, "size") else None,
            "checked_out": pool.checkedout() if hasattr(pool, "checkedout") else None,
            "checked_in": pool.checkedin() if hasattr(pool, "checkedin") else None,
            "overflow": pool.overflow() if hasattr(pool, "overflow") else None,
            "status": pool.status(),
        },
        "largest_tables": [{"name": row[0], "bytes": int(row[1])} for row in tables],
        "largest_indexes": [{"name": row[0], "table": row[1], "bytes": int(row[2])} for row in indexes],
        "latest_backup": archives[0].name if archives else None,
        "backup_count": len(archives),
        "blocking": blocking,
    }


def _revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        try:
            return connection.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar_one_or_none()
        except Exception:
            return None


def _blocking_diagnostics(connection: Connection) -> dict:
    """Session-level lock-contention summary, using pg_stat_activity and
    pg_blocking_pids() -- no SQL text, client address or application name is
    read or returned, matching the redaction the rest of this module applies.

    Best-effort: some roles cannot see other sessions' pg_stat_activity rows
    (track_activities/pg_read_all_stats), and pg_blocking_pids() is
    unavailable before PostgreSQL 9.6. Either failing must not take down the
    rest of collect_postgres_diagnostics, which administrators already rely
    on for backup/version/pool visibility.
    """
    try:
        summary = connection.execute(
            text(
                """
                SELECT
                    count(*) FILTER (WHERE state = 'active') AS active_queries,
                    count(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_transaction,
                    count(*) FILTER (WHERE wait_event_type = 'Lock') AS waiting_sessions,
                    MAX(EXTRACT(EPOCH FROM (clock_timestamp() - xact_start)))
                        FILTER (WHERE state = 'idle in transaction') AS longest_idle_in_transaction_seconds,
                    MAX(EXTRACT(EPOCH FROM (clock_timestamp() - query_start)))
                        FILTER (WHERE state = 'active') AS longest_active_query_seconds
                FROM pg_stat_activity
                WHERE datname = current_database()
                """
            )
        ).one()
        blocked_rows = connection.execute(
            text(
                """
                SELECT
                    blocked.pid AS blocked_pid,
                    blocker.pid AS blocking_pid,
                    blocked.wait_event_type,
                    blocked.wait_event,
                    blocked.state,
                    EXTRACT(EPOCH FROM (clock_timestamp() - blocked.query_start)) AS blocked_seconds
                FROM pg_stat_activity AS blocked
                JOIN LATERAL unnest(pg_blocking_pids(blocked.pid)) AS blocker_pid(pid) ON true
                JOIN pg_stat_activity AS blocker ON blocker.pid = blocker_pid.pid
                WHERE blocked.datname = current_database()
                ORDER BY blocked_seconds DESC NULLS LAST
                LIMIT 20
                """
            )
        ).all()
    except Exception as exc:
        logger.warning("postgres diagnostics blocking query unavailable error=%s", type(exc).__name__)
        return {"available": False, "reason": "blocking-session diagnostics unavailable"}
    return {
        "available": True,
        "active_queries": int(summary.active_queries or 0),
        "idle_in_transaction": int(summary.idle_in_transaction or 0),
        "waiting_sessions": int(summary.waiting_sessions or 0),
        "longest_idle_in_transaction_seconds": (
            float(summary.longest_idle_in_transaction_seconds)
            if summary.longest_idle_in_transaction_seconds is not None
            else None
        ),
        "longest_active_query_seconds": (
            float(summary.longest_active_query_seconds) if summary.longest_active_query_seconds is not None else None
        ),
        "blocked_sessions": [
            {
                "blocked_pid": int(row.blocked_pid),
                "blocking_pid": int(row.blocking_pid),
                "wait_event_type": row.wait_event_type,
                "wait_event": row.wait_event,
                "state": row.state,
                "blocked_seconds": float(row.blocked_seconds) if row.blocked_seconds is not None else None,
            }
            for row in blocked_rows
        ],
    }
