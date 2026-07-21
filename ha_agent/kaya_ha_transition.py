#!/usr/bin/env python3
"""Keepalived transition hook. Milestone 5 never controls DHCP."""

import fcntl
import json
import secrets
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path("/var/lib/kaya-ha-agent")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"master", "backup", "fault"}:
        return 2
    try: generation = int(sys.argv[2])
    except ValueError: return 2
    ROOT.mkdir(parents=True, exist_ok=True)
    with (ROOT / "transition.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db = sqlite3.connect(ROOT / "state.sqlite3")
        db.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)")
        row = db.execute("SELECT value FROM state WHERE key='keepalived_generation'").fetchone()
        if not row or int(json.loads(row[0])) != generation:
            db.close(); return 3
        role = {"master": "ACTIVE", "backup": "STANDBY", "fault": "FAULT"}[sys.argv[1]]
        values = {"observed_role": role, "vip_owned": sys.argv[1] == "master", "keepalived_runtime_state": "FAULT" if sys.argv[1] == "fault" else "RUNNING"}
        for key, value in values.items(): db.execute("INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
        occurred = datetime.now(timezone.utc).isoformat()
        event = {"event_id": secrets.token_hex(16), "event_type": f"keepalived_{sys.argv[1]}", "severity": "critical" if sys.argv[1] == "fault" else "info", "message": f"Keepalived reported {sys.argv[1]} state. DHCP control remained disabled.", "occurred_at": occurred, "details": {"generation": generation}}
        db.execute("INSERT INTO events(event_id,payload,created_at) VALUES(?,?,?)", (event["event_id"], json.dumps(event), occurred)); db.commit(); db.close()
    return 0


if __name__ == "__main__": raise SystemExit(main())
