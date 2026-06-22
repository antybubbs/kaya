#!/usr/bin/env python3

import sqlite3
from pathlib import Path

DB_PATH = Path("/app/data/homelab.db")


def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    return column in [row[1] for row in cursor.fetchall()]


def main():
    if not DB_PATH.exists():
        print("Database does not exist yet. Skipping migrations.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    migrations_applied = []

    # ------------------------------------------------------------------
    # ComputeHost Docker Agent fields
    # ------------------------------------------------------------------

    if not column_exists(cur, "compute_hosts", "agent_token"):
        cur.execute(
            "ALTER TABLE compute_hosts ADD COLUMN agent_token VARCHAR(128)"
        )
        migrations_applied.append("compute_hosts.agent_token")

    if not column_exists(cur, "compute_hosts", "agent_last_seen_at"):
        cur.execute(
            "ALTER TABLE compute_hosts ADD COLUMN agent_last_seen_at DATETIME"
        )
        migrations_applied.append("compute_hosts.agent_last_seen_at")

    conn.commit()
    conn.close()

    if migrations_applied:
        print("Applied migrations:")
        for migration in migrations_applied:
            print(f" - {migration}")
    else:
        print("Database schema already up to date.")


if __name__ == "__main__":
    main()
