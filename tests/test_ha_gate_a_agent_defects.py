"""Gate A: agent-side behaviour during autonomous VRRP transitions.

These exercise the real agent modules with an isolated temporary state
directory and stubbed process execution.  No Keepalived, sudo or Pi-hole is
invoked.  Linux-only because the agent imports ``fcntl``.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess

import pytest

pytest.importorskip("fcntl")

from ha_agent import kaya_ha_transition as transition  # noqa: E402
from ha_agent.kaya_ha_agent import State  # noqa: E402
from ha_agent.keepalived_runtime import apply_desired_keepalived  # noqa: E402

from app.schemas.high_availability import HAAgentHeartbeat  # noqa: E402
from app.services.ha_keepalived import desired_keepalived_action, prepare_deployment  # noqa: E402
from test_high_availability_keepalived import database, ready_cluster  # noqa: E402


def agent_state(root, **values) -> None:
    root.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(root / "state.sqlite3")
    db.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)")
    defaults = {
        "keepalived_generation": 37, "observed_role": "STANDBY", "vip_owned": False,
        "automatic_failover": False, "maintenance_mode": True, "dhcp_managed": True,
        "network_interface": "eth0", "desired_virtual_ip": "192.0.2.10/24",
    }
    for key, value in {**defaults, **values}.items():
        db.execute("INSERT OR REPLACE INTO state(key,value) VALUES(?,?)", (key, json.dumps(value)))
    db.commit()
    db.close()


def read_state(root) -> dict:
    db = sqlite3.connect(root / "state.sqlite3")
    try:
        return {key: json.loads(value) for key, value in db.execute("SELECT key, value FROM state")}
    finally:
        db.close()


def run_hook(monkeypatch, root, transition_name: str, generation: int):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"status":"applied"}', "")

    monkeypatch.setattr(transition, "ROOT", root)
    monkeypatch.setattr(transition.subprocess, "run", fake_run)
    monkeypatch.setattr(transition.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(transition.sys, "argv", ["kaya_ha_transition.py", transition_name, str(generation)])
    return transition.main(), commands


@pytest.mark.parametrize(
    "gates",
    [
        {"automatic_failover": False, "maintenance_mode": True},
        {"automatic_failover": False, "maintenance_mode": False},
        {"automatic_failover": True, "maintenance_mode": True},
    ],
    ids=["af-off-maint-on", "af-off-maint-off", "af-on-maint-on"],
)
def test_master_hook_records_vip_but_never_touches_dhcp_or_leases_when_gated(tmp_path, monkeypatch, gates):
    root = tmp_path / "agent"
    agent_state(root, **gates)
    lease_file = tmp_path / "dhcp.leases"
    lease_file.write_bytes(b"synthetic-lease-file\n")
    code, commands = run_hook(monkeypatch, root, "master", 37)
    assert code == 0
    assert commands == []  # no DNS probe, arping or failover helper invocation
    assert lease_file.read_bytes() == b"synthetic-lease-file\n"
    state = read_state(root)
    assert state["observed_role"] == "ACTIVE" and state["vip_owned"] is True


def test_backup_hook_on_original_owner_never_demotes_dhcp_when_gated(tmp_path, monkeypatch):
    root = tmp_path / "agent"
    agent_state(root, observed_role="ACTIVE", vip_owned=True, dhcp_running=True)
    code, commands = run_hook(monkeypatch, root, "backup", 37)
    assert code == 0 and commands == []
    assert read_state(root)["observed_role"] == "STANDBY"


def test_hook_with_mismatched_generation_is_fenced_and_records_nothing(tmp_path, monkeypatch):
    root = tmp_path / "agent"
    agent_state(root, observed_role="STANDBY", vip_owned=False)
    code, commands = run_hook(monkeypatch, root, "master", 38)
    assert code == 3 and commands == []
    state = read_state(root)
    assert state["observed_role"] == "STANDBY" and state["vip_owned"] is False


def test_d10_notify_hook_during_apply_window_is_not_fenced_out(tmp_path, monkeypatch):
    """A hook fired by the reload, before the helper returns, must be recorded (P1 fix).

    Gate A asserted keepalived_generation itself moved early; P1 instead publishes a
    pending generation, so the behavioural property is tested directly.
    """
    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        action = desired_keepalived_action(cluster, cluster.nodes[0])
    state = State(tmp_path)
    state.set("keepalived_generation", action["generation"] - 1)
    state.set("config_generation", action["generation"] - 1)
    state.set("observed_role", "STANDBY")
    seen = {}

    def runner(argv, **kwargs):
        # The reload can make Keepalived run notify_master before the helper returns.
        seen["code"], seen["commands"] = run_hook(monkeypatch, tmp_path, "master", action["generation"])
        return subprocess.CompletedProcess(argv, 0, json.dumps({"ok": True, "backup_reference": "keepalived-synthetic"}), "")

    apply_desired_keepalived(state, action, runner=runner)
    assert seen["code"] == 0 and seen["commands"] == []
    assert state.get("observed_role") == "ACTIVE"
    assert state.get("keepalived_generation") == action["generation"]
    assert state.get("pending_keepalived_generation") is None
    state.db.close()


def test_d11_helper_never_restarts_keepalived_when_reload_fails(tmp_path, monkeypatch, capsys):
    import ha_agent.kaya_ha_keepalived_helper as helper
    from app.services.ha_keepalived import render_keepalived_config

    source = tmp_path / "pending-keepalived.conf"
    main = tmp_path / "keepalived.conf"
    target = tmp_path / "conf.d" / "kaya-ha.conf"
    with database() as db:
        cluster = prepare_deployment(db, ready_cluster(db), 51, True)
        source.write_text(render_keepalived_config(cluster, cluster.nodes[0]).content, encoding="utf-8")
    main.write_text("global_defs { router_id EXISTING }\n", encoding="utf-8")
    for name, value in {"SOURCE": source, "MAIN": main, "TARGET": target, "BACKUPS": tmp_path / "backups"}.items():
        monkeypatch.setattr(helper, name, value)
    calls = []

    def command(argv, timeout=15):
        calls.append(argv)
        failed = argv[:2] == ["systemctl", "reload"]
        return subprocess.CompletedProcess(argv, 1 if failed else 0, "", "synthetic reload failure" if failed else "")

    monkeypatch.setattr(helper, "command", command)
    helper.apply(str(source))
    capsys.readouterr()
    assert ["systemctl", "restart", "keepalived"] not in calls


def test_d12_heartbeat_reports_agent_automation_gates():
    assert "automation_gates" in HAAgentHeartbeat.model_fields
