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
SQLITE_BUSY_ATTEMPTS = 6
# Must match keepalived_runtime.PENDING_GENERATION_WINDOW_SECONDS.
PENDING_GENERATION_WINDOW_SECONDS = 60


def _write(db, statement, parameters):
    for attempt in range(SQLITE_BUSY_ATTEMPTS):
        try:
            db.execute(statement, parameters)
            db.commit()
            return
        except sqlite3.OperationalError as exc:
            db.rollback()
            if not ("locked" in str(exc).lower() or "busy" in str(exc).lower()):
                raise
            if attempt + 1 == SQLITE_BUSY_ATTEMPTS:
                raise
            time.sleep(0.05 * (attempt + 1))


def get_value(db, key, default=None):
    row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return json.loads(row[0]) if row else default


def put_value(db, key, value):
    _write(
        db,
        "INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )


def queue_event(db, event_type, severity, message, generation, details=None):
    occurred = datetime.now(timezone.utc).isoformat()
    event = {
        "event_id": secrets.token_hex(16),
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "occurred_at": occurred,
        "details": {"generation": generation, **(details or {})},
    }
    _write(
        db,
        "INSERT INTO events(event_id,payload,created_at) VALUES(?,?,?)",
        (event["event_id"], json.dumps(event), occurred),
    )


def generation_accepted(db, generation):
    """Accept the deployed generation, or one the agent is applying right now.

    The pending generation is set by the agent immediately before the helper
    reloads Keepalived and cleared when activation finishes or fails, so a hook
    fired by that reload is recorded rather than fenced out.  It is honoured only
    inside a short expiry window, so a marker left by a crashed agent (or a
    clock that jumped backwards) can never become a standing authorisation.
    Anything else exits 3.
    """
    try:
        current = int(get_value(db, "keepalived_generation"))
    except (TypeError, ValueError):
        return False
    if generation == current:
        return True
    pending = get_value(db, "pending_keepalived_generation")
    if not isinstance(pending, dict):
        return False
    pending_generation = pending.get("generation")
    expires_at = pending.get("expires_at")
    if (
        not isinstance(pending_generation, int)
        or isinstance(pending_generation, bool)
        or not isinstance(expires_at, (int, float))
        or isinstance(expires_at, bool)
    ):
        return False
    remaining = expires_at - time.time()
    return (
        pending_generation == generation
        and pending_generation > current
        and 0 < remaining <= PENDING_GENERATION_WINDOW_SECONDS
    )


def automatic_transition(db, transition, generation):
    if (
        not get_value(db, "automatic_failover", False)
        or get_value(db, "maintenance_mode", False)
        or not get_value(db, "dhcp_managed", False)
    ):
        return
    if transition == "master":
        # Revised protocol: a node never promotes DHCP on its own.  Silence of the
        # peer (VRRP, ARP or DHCP) does not prove the peer stopped serving DHCP.
        # Kaya promotes the Virtual IP owner only after verified release.
        return
    command = "automatic-demote"
    result = subprocess.run(
        ["sudo", "-n", HELPER, command, str(generation)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    try:
        output = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        output = {}
    if result.returncode or output.get("status") != "applied":
        queue_event(
            db,
            "automatic_failover_blocked",
            "critical",
            str(output.get("message") or "The local DHCP safety transition failed.")[
                :500
            ],
            generation,
        )
        return
    if output.get("observation_status") == "FRESH":
        put_value(db, "dhcp_configured", output.get("configured"))
        put_value(db, "dhcp_listener_active", output.get("listening"))
        put_value(db, "ftl_active", output.get("service_active"))
        put_value(db, "dhcp_runtime_state", output.get("runtime_state"))
        put_value(db, "dhcp_observation_status", "FRESH")
        put_value(db, "dhcp_observed_at", datetime.now(timezone.utc).isoformat())
        put_value(db, "dhcp_running", output.get("dhcp_running") is True)
    queue_event(
        db,
        "automatic_demotion_completed",
        "info",
        "DHCP was disabled locally because this node gave up (or never held) the Virtual IP.",
        generation,
        {"automatic": True, "transition": transition},
    )


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"master", "backup", "fault", "stop"}:
        return 2
    try:
        generation = int(sys.argv[2])
    except ValueError:
        return 2
    ROOT.mkdir(parents=True, exist_ok=True)
    with (ROOT / "transition.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db = sqlite3.connect(ROOT / "state.sqlite3", timeout=5)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute(
            "CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        if not generation_accepted(db, generation):
            db.close()
            return 3
        # "stop": Keepalived is shutting down on this node and gives up the Virtual IP.
        # Without this, a graceful stop ran no hook and the node kept serving DHCP while
        # the peer took the Virtual IP and promoted DHCP (lab-reproduced dual DHCP).
        role = {"master": "ACTIVE", "backup": "STANDBY", "fault": "FAULT", "stop": "STANDBY"}[sys.argv[1]]
        values = {
            "observed_role": role,
            "vip_owned": sys.argv[1] == "master",
            "keepalived_runtime_state": (
                "FAULT" if sys.argv[1] == "fault" else "STOPPED" if sys.argv[1] == "stop" else "RUNNING"
            ),
        }
        for key, value in values.items():
            put_value(db, key, value)
        queue_event(
            db,
            f"keepalived_{sys.argv[1]}",
            "critical" if sys.argv[1] == "fault" else "warning" if sys.argv[1] == "stop" else "info",
            f"Keepalived reported {sys.argv[1]} state.",
            generation,
        )
        automatic_transition(db, sys.argv[1], generation)
        db.commit()
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
