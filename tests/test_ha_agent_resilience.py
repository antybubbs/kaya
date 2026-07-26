import json
import sqlite3
from pathlib import Path

import pytest

from ha_agent.kaya_ha_agent import State
from ha_agent.resolver_runtime import ResolverRuntimeError, apply_resolver_action


def test_agent_state_uses_wal_and_busy_telemetry_is_non_fatal(tmp_path):
    state = State(tmp_path)
    assert state.db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    state.db.execute("PRAGMA busy_timeout=1")
    competing = sqlite3.connect(state.database_path, timeout=0.001)
    competing.execute("PRAGMA busy_timeout=1")
    competing.execute("BEGIN IMMEDIATE")
    competing.execute("INSERT INTO state(key,value) VALUES('contender','true')")
    try:
        assert state.set_telemetry("peer_dns_reachable", False) is False
        assert state.telemetry_deferred is True
    finally:
        competing.rollback()
        competing.close()
    assert state.set_telemetry("peer_dns_reachable", False) is True
    assert state.get("peer_dns_reachable") is False


def test_resolver_action_is_fixed_and_checksum_bound():
    vip, interface = "192.0.2.53", "eth0"
    content = f"# Managed by Kaya HA\n[Resolve]\nDNS={vip}\nDomains=~.\n"
    import hashlib
    checksum = hashlib.sha256(f"{vip}:{interface}:{content}".encode()).hexdigest()
    action = {
        "action_id": "resolver:cluster:node:1",
        "action_type": "RESOLVER_REPAIR",
        "generation": 1,
        "virtual_ip": vip,
        "network_interface": interface,
        "checksum": checksum,
    }
    commands = []

    def runner(command, **kwargs):
        commands.append(command)
        return type("Result", (), {"returncode": 0, "stdout": json.dumps({"status": "applied", "message": "verified", "backup_reference": "a" * 24})})()

    result = apply_resolver_action(action, runner=runner)
    assert result["status"] == "APPLIED"
    assert commands == [["sudo", "-n", "/usr/lib/kaya-ha-agent/kaya_ha_resolver_helper.py", "apply", vip, interface, checksum]]

    action["checksum"] = "0" * 64
    try:
        apply_resolver_action(action, runner=runner)
    except ResolverRuntimeError:
        pass
    else:
        raise AssertionError("A modified resolver action must be rejected before invoking sudo.")


def test_upgrade_scripts_preserve_identity_and_install_resolver_components():
    update = Path("ha_agent/update.sh").read_text(encoding="utf-8")
    install = Path("ha_agent/install.sh").read_text(encoding="utf-8")
    assert "kaya_ha_resolver_helper.py" in update and "resolver_runtime.py" in update
    assert "kaya_ha_resolver_helper.py" in install and "resolver_runtime.py" in install
    assert "config.json" in update and "agent.key" in update
    assert "rm -rf /var/lib/kaya-ha-agent" not in update


def test_kaya_outage_does_not_stop_fresh_observation_or_event_replay(tmp_path, monkeypatch):
    from ha_agent import failover_runtime, kaya_ha_agent as transport, keepalived_runtime

    state = State(tmp_path)
    state.config_path.write_text('{"agent_id":"fake","kaya_url":"https://kaya.invalid"}', encoding="utf-8")
    event_id = state.queue_event("automatic_failover_completed", "warning", "Local failover completed without requiring Kaya.")

    monkeypatch.setattr(keepalived_runtime, "refresh_vip_state", lambda value: value.set_telemetry("vip_owned", True))
    monkeypatch.setattr(failover_runtime, "refresh_dhcp_state", lambda value: (value.set_telemetry("dhcp_running", True), value.set_telemetry("dhcp_runtime_state", "RUNNING")))
    monkeypatch.setattr(transport.subprocess, "run", lambda *args, **kwargs: type("Result", (), {"returncode": 0, "stdout": ""})())
    calls = []

    def unavailable(_state, method, path, payload=None):
        raise transport.AgentRequestError("name_resolution_failed", "Synthetic Kaya outage.")

    monkeypatch.setattr(transport, "signed_request", unavailable)
    with pytest.raises(transport.AgentRequestError):
        transport.run_once(state)
    assert state.queued_events()[0]["event_id"] == event_id

    desired = {
        "cluster_generation": 1, "role_generation": 1, "desired_role": "ACTIVE",
        "automatic_failover": True, "maintenance_mode": False, "dhcp_managed": True,
        "keepalived": None, "lease_snapshot": None, "failover": None, "resolver_repair": None,
    }

    def restored(_state, method, path, payload=None):
        calls.append((path, payload))
        return {"accepted": True, "desired": desired} if path.endswith("/heartbeat") else {"accepted": 1}

    monkeypatch.setattr(transport, "signed_request", restored)
    transport.run_once(state)
    heartbeat = calls[0][1]
    assert calls[0][0].endswith("/heartbeat") and calls[1][0].endswith("/events")
    assert heartbeat["vip_owned"] is True
    assert heartbeat["dns_healthy"] is True
    assert heartbeat["dhcp_running"] is True
    assert state.queued_events() == []
