"""P7 safety close-out: agent update confirmation, transactional repair notifications and recovery routes.

The DHCP handover protocol work is kept separately (tests/test_ha_dhcp_handover_protocol.py) because it
is not approved.  Synthetic data only.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("fcntl")

from ha_agent.kaya_ha_agent import AGENT_VERSION, State  # noqa: E402



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
