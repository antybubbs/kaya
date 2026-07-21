#!/usr/bin/env python3
"""Keepalived transition hook with fail-closed, opt-in local DHCP ownership."""

import fcntl
import json
import secrets
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path("/var/lib/kaya-ha-agent")
HELPER = "/usr/lib/kaya-ha-agent/kaya_ha_failover_helper.py"


def get_value(db, key, default=None):
    row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return json.loads(row[0]) if row else default


def put_value(db, key, value):
    db.execute("INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))


def queue_event(db, event_type, severity, message, generation, details=None):
    occurred = datetime.now(timezone.utc).isoformat()
    event = {"event_id": secrets.token_hex(16), "event_type": event_type, "severity": severity, "message": message, "occurred_at": occurred, "details": {"generation": generation, **(details or {})}}
    db.execute("INSERT INTO events(event_id,payload,created_at) VALUES(?,?,?)", (event["event_id"], json.dumps(event), occurred))


def automatic_transition(db, transition, generation):
    if not get_value(db, "automatic_failover", False) or get_value(db, "maintenance_mode", False) or not get_value(db, "dhcp_managed", False):
        return
    command = "automatic-demote"
    if transition == "master":
        hold_down = max(5, min(60, int(get_value(db, "automatic_hold_down_seconds", 10))))
        db.commit()
        time.sleep(hold_down)
        dns = subprocess.run(["/usr/lib/kaya-ha-agent/check-pihole-dns", "--observe"], capture_output=True, timeout=10, check=False)
        put_value(db, "dns_healthy", dns.returncode == 0)
        interface = str(get_value(db, "network_interface", "") or "")
        vip = str(get_value(db, "desired_virtual_ip", "") or "").split("/", 1)[0]
        duplicate = subprocess.run(["/usr/bin/arping", "-D", "-I", interface, "-c", "3", "-w", "3", vip], capture_output=True, timeout=5, check=False) if interface and vip else None
        if duplicate is None or duplicate.returncode != 0:
            queue_event(db, "split_brain_prevented", "critical", "Automatic promotion was blocked because exclusive virtual-IP ownership could not be established.", generation)
            return
        if get_value(db, "observed_role") != "ACTIVE" or not get_value(db, "vip_owned", False) or dns.returncode != 0:
            queue_event(db, "automatic_failover_blocked", "critical", "Automatic promotion was blocked because local ownership or DNS health was not safe after the hold-down.", generation)
            return
        command = "automatic-promote"
    result = subprocess.run(["sudo", "-n", HELPER, command, str(generation)], capture_output=True, text=True, timeout=30, check=False)
    try:
        output = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        output = {}
    if result.returncode or output.get("status") != "applied":
        if transition == "master":
            subprocess.run(["sudo", "-n", HELPER, "automatic-demote", str(generation)], capture_output=True, timeout=20, check=False)
        queue_event(db, "automatic_failover_blocked", "critical", str(output.get("message") or "The local DHCP safety transition failed.")[:500], generation)
        return
    put_value(db, "dhcp_running", transition == "master")
    queue_event(db, "automatic_failover_completed" if transition == "master" else "automatic_demotion_completed", "warning" if transition == "master" else "info", "Local failover completed without requiring Kaya." if transition == "master" else "DHCP was disabled locally before this node remained standby.", generation, {"automatic": True})


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
        for key, value in values.items(): put_value(db, key, value)
        queue_event(db, f"keepalived_{sys.argv[1]}", "critical" if sys.argv[1] == "fault" else "info", f"Keepalived reported {sys.argv[1]} state.", generation)
        automatic_transition(db, sys.argv[1], generation)
        db.commit(); db.close()
    return 0


if __name__ == "__main__": raise SystemExit(main())
