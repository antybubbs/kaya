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

    if not table_exists(cur, "dns_providers"):
        cur.execute(
            "CREATE TABLE dns_providers (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, provider_type VARCHAR(40) DEFAULT 'pihole' NOT NULL, base_url VARCHAR(500) NOT NULL, auth_method VARCHAR(40) DEFAULT 'password' NOT NULL, encrypted_secret TEXT, ssl_verify BOOLEAN DEFAULT 1 NOT NULL, timeout_seconds INTEGER DEFAULT 10 NOT NULL, is_enabled BOOLEAN DEFAULT 1 NOT NULL, description TEXT, last_status VARCHAR(40), last_error TEXT, last_checked_at DATETIME, created_at DATETIME, updated_at DATETIME)"
        )
        for column in ["name", "provider_type", "is_enabled", "last_status", "last_checked_at"]:
            cur.execute(f"CREATE INDEX ix_dns_providers_{column} ON dns_providers ({column})")
        migrations_applied.append("dns_providers")

    if not table_exists(cur, "dns_investigations"):
        cur.execute(
            "CREATE TABLE dns_investigations (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, domain VARCHAR(500) NOT NULL, client_name VARCHAR(255), client_ip VARCHAR(80), query_type VARCHAR(40), status VARCHAR(40) DEFAULT 'open' NOT NULL, reply_type VARCHAR(120), reply_time VARCHAR(80), upstream VARCHAR(255), observed_at VARCHAR(80), notes TEXT, created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME, updated_at DATETIME)"
        )
        for column in ["provider_id", "domain", "client_name", "client_ip", "query_type", "status", "reply_type", "created_by_id", "created_at"]:
            cur.execute(f"CREATE INDEX ix_dns_investigations_{column} ON dns_investigations ({column})")
        migrations_applied.append("dns_investigations")

    runbook_image_columns = {row[1] for row in cur.execute("PRAGMA table_info(runbook_images)").fetchall()} if table_exists(cur, "runbook_images") else set()
    if not runbook_image_columns:
        cur.execute(
            "CREATE TABLE runbook_images (id INTEGER NOT NULL PRIMARY KEY, original_filename VARCHAR(255), content_type VARCHAR(120) NOT NULL, size_bytes INTEGER DEFAULT 0 NOT NULL, data BLOB, uploaded_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME)"
        )
        for column in ["uploaded_by_id", "created_at"]:
            cur.execute(f"CREATE INDEX ix_runbook_images_{column} ON runbook_images ({column})")
        migrations_applied.append("runbook_images")
    elif "stored_filename" in runbook_image_columns:
        cur.execute("ALTER TABLE runbook_images RENAME TO runbook_images_legacy")
        cur.execute(
            "CREATE TABLE runbook_images (id INTEGER NOT NULL PRIMARY KEY, original_filename VARCHAR(255), content_type VARCHAR(120) NOT NULL, size_bytes INTEGER DEFAULT 0 NOT NULL, data BLOB, uploaded_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME)"
        )
        cur.execute(
            "INSERT INTO runbook_images (id, original_filename, content_type, size_bytes, uploaded_by_id, created_at) SELECT id, original_filename, content_type, size_bytes, uploaded_by_id, created_at FROM runbook_images_legacy"
        )
        cur.execute("DROP TABLE runbook_images_legacy")
        for column in ["uploaded_by_id", "created_at"]:
            cur.execute(f"CREATE INDEX ix_runbook_images_{column} ON runbook_images ({column})")
        migrations_applied.append("runbook_images.blob_storage")
    elif "data" not in runbook_image_columns:
        cur.execute("ALTER TABLE runbook_images ADD COLUMN data BLOB")
        migrations_applied.append("runbook_images.data")

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
