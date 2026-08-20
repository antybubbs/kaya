"""Redacted PostgreSQL operational diagnostics for administrators."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Engine


def collect_postgres_diagnostics(engine: Engine, backup_directory: Path) -> dict:
    if engine.dialect.name != "postgresql":
        return {"available": False, "reason": "PostgreSQL is not the active database"}
    with engine.connect() as connection:
        database = connection.execute(
            text("SELECT current_database(), pg_database_size(current_database()), version()")
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
    pool = engine.pool
    archives = sorted(backup_directory.glob("kaya-*.dump"), key=lambda path: path.stat().st_mtime, reverse=True) if backup_directory.exists() else []
    return {
        "available": True,
        "database": database[0],
        "database_bytes": int(database[1]),
        "server_version": str(database[2]).split(" on ", 1)[0],
        "active_connections": int(activity),
        "deadlocks": int(deadlocks or 0),
        "pool": {
            "size": pool.size() if hasattr(pool, "size") else None,
            "checked_out": pool.checkedout() if hasattr(pool, "checkedout") else None,
            "overflow": pool.overflow() if hasattr(pool, "overflow") else None,
            "status": pool.status(),
        },
        "largest_tables": [{"name": row[0], "bytes": int(row[1])} for row in tables],
        "latest_backup": archives[0].name if archives else None,
        "backup_count": len(archives),
    }
