"""P7 safety close-out: dual-DHCP fencing, agent update confirmation and reliability fixes.  Synthetic data only.

Dual DHCP (lab-reproduced with the real transition hook, the real privileged DHCP helper, real
sudo/sudoers and a real DHCP server): a graceful Keepalived stop on the DHCP owner ran no hook, so
the old owner kept serving DHCP while the new Virtual IP owner promoted itself after the hold-down.
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

pytest.importorskip("fcntl")

from ha_agent import kaya_ha_transition as transition  # noqa: E402
from ha_agent.kaya_ha_agent import AGENT_VERSION, State  # noqa: E402
from test_ha_gate_a_agent_defects import agent_state, read_state, run_hook  # noqa: E402

AUTOMATIC = {"automatic_failover": True, "maintenance_mode": False, "dhcp_managed": True}


# --------------------------------------------------------------------------------------
# Agent update confirmation
# --------------------------------------------------------------------------------------


def _transport(tmp_path, monkeypatch, response):
    from ha_agent import failover_runtime, kaya_ha_agent as transport, keepalived_runtime

    state = State(tmp_path)
    state.config_path.write_text('{"agent_id":"fake-agent","kaya_url":"https://kaya.invalid"}', encoding="utf-8")
    monkeypatch.setattr(keepalived_runtime, "refresh_vip_state", lambda value: None)
    monkeypatch.setattr(failover_runtime, "refresh_dhcp_state", lambda value: None)
    monkeypatch.setattr(transport.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""))
    desired = {"cluster_generation": 4, "desired_role": "STANDBY", "role_generation": 2, "automatic_failover": False,
               "maintenance_mode": False, "dhcp_managed": True, "keepalived": None, "lease_snapshot": None, "failover": None}

    def signed_request(_state, method, path, payload=None):
        if path == "/api/ha/agent/v1/heartbeat":
            return {**response, "desired": desired}
        return {"accepted": 1}

    monkeypatch.setattr(transport, "signed_request", signed_request)
    return transport, state


def test_agent_records_the_version_kaya_accepted_for_update_confirmation(tmp_path, monkeypatch):
    transport, state = _transport(tmp_path, monkeypatch, {"accepted": True})
    transport.run_once(state)
    accepted = state.get("last_accepted_heartbeat")
    assert accepted["agent_version"] == AGENT_VERSION and accepted["at"]
    state.db.close()


def test_a_rejected_heartbeat_is_never_recorded_as_accepted(tmp_path, monkeypatch):
    transport, state = _transport(tmp_path, monkeypatch, {"accepted": False, "reason": "stale"})
    transport.run_once(state)
    assert state.get("last_accepted_heartbeat") is None
    state.db.close()


def test_updater_confirms_sustained_health_and_a_versioned_heartbeat_before_success():
    from app.services.ha_agent_installer import agent_file

    updater = agent_file("update.sh").decode().replace("\r\n", "\n")
    assert "confirm_updated_agent" in updater
    # The success message is printed only after the confirmation, never straight after "systemctl start".
    assert updater.index('confirm_updated_agent "$EXPECTED_VERSION"') < updater.index("UPDATE_OK=1")
    assert "last_accepted_heartbeat" in updater and "MainPID" in updater
    # A failed update stops the new agent before restoring, so the old code really runs again.
    restore = updater[updater.index("Update did not complete"):updater.index('cp -a "$BACKUP_DIR/lib/."')]
    assert "systemctl stop kaya-ha-agent.service" in restore


# --------------------------------------------------------------------------------------
# Old owner: a graceful Keepalived stop releases DHCP (notify_stop)
# --------------------------------------------------------------------------------------


def test_stop_hook_releases_dhcp_on_the_node_giving_up_the_virtual_ip(tmp_path, monkeypatch):
    root = tmp_path / "agent"
    agent_state(root, observed_role="ACTIVE", vip_owned=True, dhcp_running=True, **AUTOMATIC)
    code, commands = run_hook(monkeypatch, root, "stop", 37)
    assert code == 0
    assert any("automatic-demote" in command for command in commands)
    assert not any("automatic-promote" in command for command in commands)
    state = read_state(root)
    assert state["observed_role"] == "STANDBY" and state["vip_owned"] is False and state["keepalived_runtime_state"] == "STOPPED"


@pytest.mark.parametrize("gates", [{"automatic_failover": False, "maintenance_mode": False}, {"automatic_failover": True, "maintenance_mode": True}],
                         ids=["automatic-failover-off", "maintenance-held"])
def test_stop_hook_never_touches_dhcp_when_gated(tmp_path, monkeypatch, gates):
    root = tmp_path / "agent"
    agent_state(root, observed_role="ACTIVE", vip_owned=True, dhcp_running=True, **{**AUTOMATIC, **gates})
    code, commands = run_hook(monkeypatch, root, "stop", 37)
    assert code == 0 and commands == []


def test_stop_hook_with_a_stale_generation_is_fenced(tmp_path, monkeypatch):
    root = tmp_path / "agent"
    agent_state(root, observed_role="ACTIVE", vip_owned=True, **AUTOMATIC)
    code, commands = run_hook(monkeypatch, root, "stop", 36)
    assert code == 3 and commands == []


def _rendered(agent_versions):
    from app.services.ha_keepalived import render_keepalived_config
    from test_high_availability_keepalived import database, ready_cluster

    db = database()
    cluster = ready_cluster(db)
    cluster.keepalived_generation = 5
    for node, version in zip(cluster.nodes, agent_versions):
        node.agent_version = version
        node.vrrp_priority = node.vrrp_priority or 100
    return render_keepalived_config(cluster, cluster.nodes[0]).content


def _current():
    from app.services.ha_keepalived import STOP_HOOK_AGENT_VERSION

    return ".".join(str(part) for part in STOP_HOOK_AGENT_VERSION)


def test_notify_stop_is_rendered_only_when_both_agents_understand_it():
    current = _current()
    assert 'notify_stop "/usr/lib/kaya-ha-agent/kaya_ha_transition.py stop ' in _rendered([current, current])
    for versions in (["0.2.15", current], [current, None], ["0.2.14", "0.2.14"]):
        assert "notify_stop" not in _rendered(versions)  # older agents reject unknown directives


def test_agent_keepalived_helper_accepts_only_a_matching_notify_stop_line():
    from ha_agent import kaya_ha_keepalived_helper as helper

    content = _rendered([_current(), _current()])
    assert helper.validate_managed_document(content.encode())
    assert helper.validate_managed_document(_rendered(["0.2.15", "0.2.15"]).encode())
    tampered = content.replace("kaya_ha_transition.py stop", "kaya_ha_transition.py master")
    assert not helper.validate_managed_document(tampered.encode())
    doubled = content.replace("    notify_fault", '    notify_stop "/usr/lib/kaya-ha-agent/kaya_ha_transition.py stop 1"\n    notify_fault')
    assert not helper.validate_managed_document(doubled.encode())


# --------------------------------------------------------------------------------------
# New owner: the privileged helper refuses automatic promotion while another server answers
# --------------------------------------------------------------------------------------


def _automatic_promote(tmp_path, monkeypatch, probe_result):
    from ha_agent import kaya_ha_failover_helper as helper

    monkeypatch.setattr(helper, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(helper, "LOCK_FILE", tmp_path / "dhcp.lock")
    monkeypatch.setattr(helper.sys, "argv", ["helper", "automatic-promote", "37"])
    monkeypatch.setattr(helper.time, "sleep", lambda seconds: None)
    values = {**AUTOMATIC, "keepalived_generation": 37, "dns_healthy": True, "observed_role": "ACTIVE", "vip_owned": True,
              "network_interface": "eth0", "lease_generation": 8}
    monkeypatch.setattr(helper, "_state", lambda key, default=None: values.get(key, default))
    monkeypatch.setattr(helper, "_owns_vip", lambda: True)
    calls = {"set_dhcp": [], "probes": 0, "lease_writes": 0}
    monkeypatch.setattr(helper, "_set_dhcp", lambda enabled: calls["set_dhcp"].append(enabled) or {"configured": enabled})
    monkeypatch.setattr(helper, "_wait_for_dns", lambda: None)
    monkeypatch.setattr(helper, "_backup", lambda generation: (tmp_path / "backup", (0, 0, 0o644)))
    monkeypatch.setattr(helper, "_lease_lines", lambda generation: "")
    monkeypatch.setattr(helper, "_atomic_write", lambda *args, **kwargs: calls.__setitem__("lease_writes", calls["lease_writes"] + 1))

    def probe(interface):
        calls["probes"] += 1
        return probe_result(calls["probes"]) if callable(probe_result) else probe_result

    monkeypatch.setattr(helper, "_other_dhcp_server", probe)
    return helper, calls


@pytest.mark.parametrize("probe_result, reason", [("192.0.2.2", "still answering"), (None, "could not confirm")],
                         ids=["peer-still-serving", "probe-unavailable"])
def test_automatic_promotion_refuses_while_another_dhcp_server_answers_or_cannot_be_ruled_out(tmp_path, monkeypatch, probe_result, reason):
    helper, calls = _automatic_promote(tmp_path, monkeypatch, probe_result)
    with pytest.raises(RuntimeError) as raised:
        helper.main()
    assert reason in str(raised.value)
    assert calls["set_dhcp"] == [] and calls["lease_writes"] == 0  # DHCP never enabled, leases never touched


def test_automatic_promotion_waits_briefly_for_the_peer_to_release(tmp_path, monkeypatch, capsys):
    helper, calls = _automatic_promote(tmp_path, monkeypatch, lambda attempt: "192.0.2.2" if attempt < 3 else False)
    helper.main()
    assert calls["probes"] == 3 and calls["set_dhcp"] == [True]
    assert json.loads(capsys.readouterr().out)["status"] == "applied"


def test_promotion_fence_ignores_this_nodes_own_server_and_unrelated_replies():
    from ha_agent import kaya_ha_failover_helper as helper

    def offer(xid, server, kind=2):
        body = bytearray(240)
        body[0] = 2
        body[4:8] = xid.to_bytes(4, "big")
        body[236:240] = b"\x63\x82\x53\x63"
        return bytes(body) + bytes([53, 1, kind, 54, 4]) + bytes(int(part) for part in server.split(".")) + b"\xff"

    own = {"192.0.2.8"}
    assert helper._offer_server(offer(7, "192.0.2.2"), 7, own) == "192.0.2.2"
    assert helper._offer_server(offer(7, "192.0.2.8"), 7, own) is None  # this node
    assert helper._offer_server(offer(8, "192.0.2.2"), 7, own) is None  # another client's transaction
    assert helper._offer_server(offer(7, "192.0.2.2", kind=5), 7, own) is None  # not an OFFER
    assert helper._offer_server(b"short", 7, own) is None


def test_hook_records_a_refused_promotion_and_never_reports_dhcp_running(monkeypatch):
    from test_high_availability_automatic import state_database

    db = state_database()
    monkeypatch.setattr(transition.time, "sleep", lambda seconds: None)

    def run(command, **kwargs):
        if "automatic-promote" in command:
            return subprocess.CompletedProcess(command, 1, '{"status":"failed","message":"Another DHCP server (192.0.2.2) is still answering; promotion refused."}', "")
        return subprocess.CompletedProcess(command, 0, '{"status":"applied"}', "")

    monkeypatch.setattr(transition.subprocess, "run", run)
    transition.automatic_transition(db, "master", 8)
    events = [json.loads(row[0]) for row in db.execute("SELECT payload FROM events")]
    assert events[-1]["event_type"] == "automatic_failover_blocked" and "still answering" in events[-1]["message"]
    assert db.execute("SELECT value FROM state WHERE key='dhcp_running'").fetchone() is None


# --------------------------------------------------------------------------------------
# Repair outcome notifications are queued in the same transaction as the outcome
# --------------------------------------------------------------------------------------


def test_outcome_and_notification_commit_together(monkeypatch):
    """A crash between the outcome commit and a separate publish can no longer lose the notification."""
    from app.models.models import HAMaintenanceRun, NotificationOutbox
    from app.services import ha_alignment
    from test_ha_p6_align_ownership import mismatch, start

    sim = mismatch()
    run = start(sim)
    commits = []
    real_commit = sim.db.commit

    def commit():
        commits.append(sim.db.query(NotificationOutbox).filter(NotificationOutbox.event_type == "pihole.repair.failed").count())
        return real_commit()

    monkeypatch.setattr(sim.db, "commit", commit)
    ha_alignment._fail(sim.db, sim.db.get(HAMaintenanceRun, run.id), "Synthetic stop for the transaction test.")
    # The first commit after the failure already carries the outbox row.
    assert commits and commits[0] == 1


def test_a_notification_failure_never_blocks_the_safety_outcome(monkeypatch):
    from app.models.models import HAMaintenanceRun
    from app.services import ha_alignment, ha_repair_outcomes
    from test_ha_p6_align_ownership import mismatch, start

    sim = mismatch()
    run = start(sim)

    def broken(*args, **kwargs):
        raise RuntimeError("synthetic outbox failure")

    monkeypatch.setattr(ha_repair_outcomes, "enqueue_notification", broken)
    ha_alignment._fail(sim.db, sim.db.get(HAMaintenanceRun, run.id), "Synthetic stop with a broken outbox.")
    sim.db.expire_all()
    assert sim.db.get(HAMaintenanceRun, run.id).status == "FAILED_SAFE"


# --------------------------------------------------------------------------------------
# No dead ends: every protected repair's end state has a usable next step
# --------------------------------------------------------------------------------------


def _failed_controlled_failover():
    from app.models.models import HAFailoverRun
    from ha_simulation import hal_like_cluster, sqlite_session

    sim = hal_like_cluster(sqlite_session(), maintenance_mode=True, suffix="failover-hold")
    sim.report_both(2)
    sim.cluster.failover_runs.append(HAFailoverRun(source_node_id=sim.one.id, target_node_id=sim.two.id, status="FAILED_SAFE", phase="FAILED_SAFE",
                                                   role_generation=sim.cluster.role_generation, error_redacted="Synthetic failed transition"))
    sim.db.commit()
    return sim


def test_a_hold_left_by_a_failed_controlled_failover_points_to_its_rollback():
    from app.services.ha_assessment import APPROVAL_REQUIRED, assess_cluster, health_summary

    sim = _failed_controlled_failover()
    assessment = assess_cluster(sim.db, sim.cluster)
    hold = next(item for item in assessment.findings if item.code == "MAINTENANCE_HOLD")
    assert hold.disposition == APPROVAL_REQUIRED and hold.repair.key == "FAILOVER_ROLLBACK"
    assert hold.repair.path.endswith("/testing")
    assert health_summary(assessment).action is not None


def test_a_rejected_apply_on_a_cluster_that_must_revalidate_points_to_the_safety_checks():
    from app.services.ha_assessment import assess_cluster
    from test_ha_p6_align_ownership import mismatch

    sim = mismatch()
    sim.one.keepalived_status = "ERROR"
    sim.one.keepalived_last_error = "Synthetic: the previous configuration was restored and reloaded."
    for status, page in (("DEGRADED", "/validation"), ("HEALTHY", "/deployment")):
        sim.cluster.status = status
        sim.db.commit()
        finding = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "KEEPALIVED_REJECTED")
        assert finding.repair.path.endswith(page), (status, finding.repair)


def _end_states():
    from test_ha_assessment import SCENARIOS
    from test_ha_p6_align_ownership import apply_keepalived, report
    from test_ha_p7_health_repair import approve, stopped_alignment
    from app.services.ha_maintenance import acknowledge_failed_safe_latch

    states = {name: build() for name, build in SCENARIOS.items()}
    sim, _run = stopped_alignment()
    states["alignment_stopped"] = sim
    sim, _run = stopped_alignment()
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    approve(sim)
    apply_keepalived(sim, reject={"SimPiHole1"}, vrrp_moves=False)
    report(sim)
    states["restoration_blocked"] = sim
    states["failover_failed_safe"] = _failed_controlled_failover()
    return states


def test_no_end_state_leaves_the_administrator_without_a_next_step():
    from app.services.ha_assessment import APPROVAL_REQUIRED, BLOCKED, HEALTHY, assess_cluster, health_summary

    for name, sim in _end_states().items():
        assessment = assess_cluster(sim.db, sim.cluster)
        for finding in assessment.findings:
            if finding.disposition == APPROVAL_REQUIRED:
                assert finding.repair is not None, (name, finding.code)
            if finding.disposition == BLOCKED:
                assert finding.no_repair_reason, (name, finding.code)
        summary = health_summary(assessment)
        if summary.state != HEALTHY:
            assert summary.action is not None or summary.detail, (name, summary)
