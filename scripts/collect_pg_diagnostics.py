"""Collect a short, read-only PostgreSQL contention snapshot for Kaya.

The collector deliberately omits SQL text, parameters, client addresses and
session user names. It is intended for a production operator to run during a
slow navigation window without changing database state.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import time

from sqlalchemy import create_engine, text


MAX_SECONDS = 30
MAX_INTERVAL_SECONDS = 5
MAX_SAMPLES = 12


def _database_url(value: str) -> str:
    if value:
        return value
    return os.environ.get("DATABASE_URL", "")


def _read_password_file(url: str) -> str:
    password_file = os.environ.get("DATABASE_PASSWORD_FILE", "").strip()
    if not password_file or "://" not in url:
        return url
    password = Path(password_file).read_text(encoding="utf-8").strip()
    if not password:
        return url
    marker = "postgresql+psycopg://kaya@"
    if url.startswith(marker):
        return url.replace(marker, f"postgresql+psycopg://kaya:{password}@", 1)
    return url


def _snapshot(connection) -> dict:
    activity = connection.execute(
        text(
            """
            SELECT count(*) FILTER (WHERE state = 'active') AS active_sessions,
                   count(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_transaction,
                   count(*) FILTER (WHERE wait_event IS NOT NULL) AS waiting_sessions,
                   count(*) FILTER (WHERE cardinality(pg_blocking_pids(pid)) > 0) AS blocked_sessions,
                   COALESCE(EXTRACT(EPOCH FROM (now() - min(xact_start))
                       FILTER (WHERE xact_start IS NOT NULL)), 0) AS oldest_transaction_seconds,
                   COALESCE(EXTRACT(EPOCH FROM (now() - min(query_start))
                       FILTER (WHERE query_start IS NOT NULL AND state = 'active')), 0) AS oldest_active_query_seconds
            FROM pg_stat_activity
            WHERE datname = current_database()
            """
        )
    ).mappings().one()
    waits = connection.execute(
        text(
            """
            SELECT COALESCE(wait_event_type, 'none') AS wait_event_type,
                   COALESCE(wait_event, 'none') AS wait_event,
                   count(*) AS sessions
            FROM pg_stat_activity
            WHERE datname = current_database()
            GROUP BY wait_event_type, wait_event
            ORDER BY sessions DESC
            LIMIT 20
            """
        )
    ).mappings().all()
    locks = connection.execute(
        text(
            """
            SELECT mode, granted, count(*) AS locks
            FROM pg_locks
            GROUP BY mode, granted
            ORDER BY granted, mode
            """
        )
    ).mappings().all()
    database = connection.execute(
        text(
            """
            SELECT numbackends AS connections,
                   xact_commit,
                   xact_rollback,
                   blks_read,
                   blks_hit,
                   deadlocks
            FROM pg_stat_database
            WHERE datname = current_database()
            """
        )
    ).mappings().one()
    statement_rows = []
    extension = connection.execute(
        text("SELECT to_regclass('pg_catalog.pg_stat_statements') IS NOT NULL")
    ).scalar_one()
    if extension:
        statement_rows = connection.execute(
            text(
                """
                SELECT queryid, calls, total_exec_time, mean_exec_time,
                       rows, shared_blks_read, temp_blks_written
                FROM pg_stat_statements
                ORDER BY total_exec_time DESC
                LIMIT 20
                """
            )
        ).mappings().all()
    return {
        "captured_at": datetime.now(UTC).isoformat(),
        "activity": dict(activity),
        "waits": [dict(row) for row in waits],
        "locks": [dict(row) for row in locks],
        "database": dict(database),
        "top_statements": [dict(row) for row in statement_rows],
    }


def collect(database_url: str, *, seconds: int = 15, interval: int = 5) -> dict:
    seconds = max(1, min(int(seconds), MAX_SECONDS))
    interval = max(1, min(int(interval), MAX_INTERVAL_SECONDS))
    url = _read_password_file(_database_url(database_url))
    if not url:
        raise ValueError("--database-url or DATABASE_URL is required")
    engine = create_engine(
        url,
        pool_size=1,
        max_overflow=0,
        pool_timeout=3,
        connect_args={
            "options": "-c default_transaction_read_only=on -c statement_timeout=1500 -c lock_timeout=500",
        },
    )
    samples = []
    started = time.monotonic()
    try:
        with engine.connect() as connection:
            while len(samples) < MAX_SAMPLES:
                samples.append(_snapshot(connection))
                if time.monotonic() - started >= seconds:
                    break
                time.sleep(min(interval, max(0, seconds - (time.monotonic() - started))))
    finally:
        engine.dispose()
    return {
        "collector": "kaya_pg_diagnostics",
        "started_at": datetime.now(UTC).isoformat(),
        "duration_seconds": seconds,
        "interval_seconds": interval,
        "sample_count": len(samples),
        "samples": samples,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default="")
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = collect(args.database_url, seconds=args.seconds, interval=args.interval)
    except Exception as exc:
        raise SystemExit(f"PostgreSQL diagnostics failed: {type(exc).__name__}") from None
    rendered = json.dumps(report, indent=2, default=str)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
