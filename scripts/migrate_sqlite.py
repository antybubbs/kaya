#!/usr/bin/env python3

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path("/app/data/kaya.db")


def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    return column in [row[1] for row in cursor.fetchall()]


def table_exists(cursor, table):
    cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    )
    return cursor.fetchone() is not None


def main():
    if not DB_PATH.exists():
        print("Database does not exist yet. Skipping migrations.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    migrations_applied = []

    # Public releases before v0.18 do not have compute_hosts yet. In that case,
    # application startup creates the complete current table via SQLAlchemy.
    # May the migration God bless us all.
    if table_exists(cur, "compute_hosts"):
        if not column_exists(cur, "compute_hosts", "agent_last_seen_at"):
            cur.execute(
                "ALTER TABLE compute_hosts ADD COLUMN agent_last_seen_at DATETIME"
            )
            migrations_applied.append("compute_hosts.agent_last_seen_at")

        if not column_exists(cur, "compute_hosts", "encrypted_agent_token"):
            cur.execute(
                "ALTER TABLE compute_hosts ADD COLUMN encrypted_agent_token TEXT"
            )
            migrations_applied.append("compute_hosts.encrypted_agent_token")

    if not table_exists(cur, "backup_records"):
        cur.execute(
            "CREATE TABLE backup_records (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, source_type VARCHAR(40) DEFAULT 'manual' NOT NULL, source_ref VARCHAR(500), target VARCHAR(500), schedule VARCHAR(255), owner VARCHAR(255), last_status VARCHAR(40), last_run_at DATETIME, notes TEXT, is_enabled BOOLEAN DEFAULT 1 NOT NULL, created_at DATETIME, updated_at DATETIME)"
        )
        for column in ["name", "source_type", "source_ref", "owner", "last_status", "last_run_at", "is_enabled"]:
            cur.execute(f"CREATE INDEX ix_backup_records_{column} ON backup_records ({column})")
        migrations_applied.append("backup_records")

    if not table_exists(cur, "backup_jobs"):
        cur.execute(
            "CREATE TABLE backup_jobs (id INTEGER NOT NULL PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES compute_hosts(id), workload_id INTEGER REFERENCES compute_workloads(id), operation VARCHAR(30) NOT NULL, status VARCHAR(40) DEFAULT 'queued' NOT NULL, encryption_enabled BOOLEAN DEFAULT 1 NOT NULL, encrypted_backup_key TEXT, artifact_path VARCHAR(1000), size_bytes INTEGER, error TEXT, log TEXT, metadata_json TEXT, requested_by_id INTEGER REFERENCES users(id), created_at DATETIME, dispatched_at DATETIME, started_at DATETIME, finished_at DATETIME, updated_at DATETIME)"
        )
        for column in ["host_id", "workload_id", "operation", "status", "encryption_enabled", "requested_by_id", "created_at", "dispatched_at", "started_at", "finished_at"]:
            cur.execute(f"CREATE INDEX ix_backup_jobs_{column} ON backup_jobs ({column})")
        migrations_applied.append("backup_jobs")

    conn.commit()
    conn.close()

    if migrations_applied:
        print("Applied migrations:")
        for migration in migrations_applied:
            print(f" - {migration}")
    else:
        print("Database schema already up to date.")


if __name__ == "__main__":
    try:
        main()
    except sqlite3.OperationalError as exc:
        if "database or disk is full" in str(exc).lower():
            print(
                "Database migration failed because SQLite reported that the database or disk is full.",
                file=sys.stderr,
            )
            print(
                "Free space on the host path mounted to /app/data, then start Kaya again.",
                file=sys.stderr,
            )
        raise
