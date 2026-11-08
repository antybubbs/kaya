import json
import sqlite3
import subprocess
from pathlib import Path

from ha_agent import kaya_ha_transition as transition


def test_dns_health_probe_never_controls_dhcp_directly():
    probe = Path("ha_agent/check-pihole-dns").read_text(encoding="utf-8")
    assert "automatic-demote" not in probe
    assert "kaya_ha_failover_helper" not in probe


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


def test_master_hook_never_promotes_dhcp_locally(monkeypatch):
    """Revised DHCP handover protocol: no hold-down, ARP or discovery check can prove the peer stopped
    serving, so the master hook records the Virtual IP and leaves promotion to Kaya's verified release."""
    db = state_database()
    commands = []
    monkeypatch.setattr(transition.time, "sleep", lambda seconds: None)

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"status":"applied"}', "")

    monkeypatch.setattr(transition.subprocess, "run", run)
    transition.automatic_transition(db, "master", 8)
    assert commands == []
    assert db.execute("SELECT value FROM state WHERE key='dhcp_running'").fetchone() is None


def test_backup_hook_still_releases_dhcp_when_automatic_failover_is_on(monkeypatch):
    db = state_database()
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"status":"applied","observation_status":"FRESH","dhcp_running":false}', "")

    monkeypatch.setattr(transition.subprocess, "run", run)
    transition.automatic_transition(db, "backup", 8)
    assert any("automatic-demote" in command for command in commands)
