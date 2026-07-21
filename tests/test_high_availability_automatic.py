import json
import sqlite3
import subprocess

from ha_agent import kaya_ha_transition as transition


def state_database():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)")
    values = {
        "automatic_failover": True,
        "maintenance_mode": False,
        "dhcp_managed": True,
        "automatic_hold_down_seconds": 10,
        "observed_role": "ACTIVE",
        "vip_owned": True,
        "dns_healthy": True,
        "network_interface": "eth0",
        "desired_virtual_ip": "192.0.2.53/24",
    }
    db.executemany("INSERT INTO state(key,value) VALUES(?,?)", ((key, json.dumps(value)) for key, value in values.items()))
    db.commit()
    return db


def test_local_promotion_waits_checks_duplicate_vip_and_enables_dhcp(monkeypatch):
    db = state_database()
    commands = []
    monkeypatch.setattr(transition.time, "sleep", lambda seconds: None)

    def run(command, **kwargs):
        commands.append(command)
        if command[0].endswith("check-pihole-dns") or command[0].endswith("arping"):
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, '{"status":"applied"}', "")

    monkeypatch.setattr(transition.subprocess, "run", run)
    transition.automatic_transition(db, "master", 8)
    assert any("automatic-promote" in command for command in commands)
    assert json.loads(db.execute("SELECT value FROM state WHERE key='dhcp_running'").fetchone()[0]) is True
    payloads = [json.loads(row[0]) for row in db.execute("SELECT payload FROM events")]
    assert payloads[-1]["event_type"] == "automatic_failover_completed"


def test_duplicate_vip_blocks_local_dhcp_promotion(monkeypatch):
    db = state_database()
    commands = []
    monkeypatch.setattr(transition.time, "sleep", lambda seconds: None)

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 1 if command[0].endswith("arping") else 0, "", "")

    monkeypatch.setattr(transition.subprocess, "run", run)
    transition.automatic_transition(db, "master", 8)
    assert not any("automatic-promote" in command for command in commands)
    payloads = [json.loads(row[0]) for row in db.execute("SELECT payload FROM events")]
    assert payloads[-1]["event_type"] == "split_brain_prevented"
