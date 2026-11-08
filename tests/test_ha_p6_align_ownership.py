"""P6: administrator-approved Align service ownership (moves only the Virtual IP).

Agents are simulated through the real signed-heartbeat and action-result paths.
They report the local automation gates they applied from Kaya's desired state
(as agent 0.2.15 does) and apply Kaya's Keepalived actions with the behaviour
measured in the isolated real-VRRP lab: a reload never moves the Virtual IP by
itself, and only a preempt-capable node with the higher priority takes it from
the MASTER.  Every step records the actions Kaya offered, so the tests prove no
DHCP or lease action is ever issued.  Synthetic data only.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timedelta
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.main import app
from app.models.models import AuditLog, HAEvent, HAMaintenanceRun, HASyncRun
from app.routers import high_availability as router
from app.schemas.high_availability import HAAgentActionResult, HAAgentAutomationGates
from app.services import ha_alignment
from app.services.ha_agents import desired_state, record_action_result, record_heartbeat
from app.services.ha_alignment import (
    DUAL_VIP_TOLERANCE_SECONDS,
    GATE_TIMEOUT_SECONDS,
    MOVE_TIMEOUT_SECONDS,
    HAAlignmentError,
    alignment_preview,
    start_alignment,
)
from app.services.ha_assessment import APPROVAL_REQUIRED, BLOCKED, assess_cluster
from app.services.ha_keepalived import desired_keepalived_action, prepare_deployment
from app.services.ha_keepalived_baseline import _applied_stable, outstanding
from app.services.ha_maintenance import acknowledge_failed_safe_latch, latch_preview
from app.services.ha_watchdog import drain_evaluations, reconcile_cluster
from ha_simulation import hal_like_cluster, heartbeat_for, ownership_snapshot, sqlite_session

GATED_AGENT = "0.2.15"
FORBIDDEN_ACTIONS = {"DHCP_PROMOTE", "DHCP_DEMOTE", "LEASE_SNAPSHOT_STAGE", "RESOLVER_REPAIR"}


# --------------------------------------------------------------------------------------
# Simulated 0.2.15 agents
# --------------------------------------------------------------------------------------


def pairs(sim):
    return ((sim.sim_one, sim.one), (sim.sim_two, sim.two))


def beat(sim, simnode, node, *, agent_version=GATED_AGENT, gates=True):
    heartbeat = heartbeat_for(simnode, observed_generation=sim.cluster.role_generation)
    update = {"agent_version": agent_version}
    if gates:
        update["automation_gates"] = HAAgentAutomationGates(**simnode.gates)
    record_heartbeat(sim.db, node, heartbeat.model_copy(update=update))
    desired = desired_state(node)
    sim.offered.extend(desired["allowed_actions"])
    # The agent stores the gates from Kaya's reply and reports them in its next heartbeat.
    simnode.gates = {key: desired[key] for key in ("automatic_failover", "maintenance_mode", "dhcp_managed")}


def report(sim, *, silent=frozenset(), frozen_gates=frozenset(), **kwargs):
    for simnode, node in pairs(sim):
        if simnode.name in silent:
            continue
        saved = dict(simnode.gates)
        beat(sim, simnode, node, **kwargs)
        if simnode.name in frozen_gates:
            simnode.gates = saved  # the agent never applies Kaya's settings
    drain_evaluations(sim.db)


def apply_keepalived(sim, *, reject=frozenset(), reject_message="Keepalived could not be reloaded. The previous configuration was restored and reloaded.",
                     skip=frozenset(), vrrp_moves=True):
    """Apply pending Keepalived actions; real-VRRP outcome: only a preempt-capable higher-priority node takes the VIP."""
    for simnode, node in pairs(sim):
        action = desired_keepalived_action(sim.cluster, node)
        if action is None or simnode.name in skip:
            continue
        failed = simnode.name in reject
        record_action_result(sim.db, node, HAAgentActionResult(
            action_id=action["action_id"], action_type="KEEPALIVED_APPLY", generation=action["generation"],
            status="FAILED" if failed else "APPLIED", checksum=None if failed else action["checksum"],
            message=reject_message if failed else "Generated Keepalived configuration validated and activated."))
        if failed:
            continue
        simnode.keepalived_generation = action["generation"]
        simnode.priority = int(re.search(r"priority (\d+)", action["configuration"]).group(1))
        simnode.nopreempt = "nopreempt" in action["configuration"]
    if vrrp_moves:
        for simnode, _node in pairs(sim):
            peer = sim.vrrp.peer(simnode)
            if (not simnode.nopreempt and simnode.dns_healthy and simnode.keepalived_running and simnode.vrrp_state == "BACKUP"
                    and peer.vrrp_state == "MASTER" and simnode.priority > peer.priority):
                simnode.vrrp_state, peer.vrrp_state = "MASTER", "BACKUP"
    drain_evaluations(sim.db)


def mismatch(*, maintenance_mode=False, automatic_failover=False, suffix="p6", db=None):
    """4 November: the Virtual IP on node two, DHCP on node one; both agents 0.2.15."""
    sim = hal_like_cluster(db or sqlite_session(), maintenance_mode=maintenance_mode, automatic_failover=automatic_failover, suffix=suffix)
    sim.offered = []
    report(sim)
    report(sim)
    sim.vrrp.stop("SimPiHole1")
    report(sim)
    sim.vrrp.start("SimPiHole1")
    report(sim)
    report(sim)
    snapshot = ownership_snapshot(sim)
    assert "OWNERSHIP_MISMATCH" in snapshot["issues"], snapshot
    assert snapshot["vip_owners"] == ["SimPiHole2"] and snapshot["dhcp_owners"] == ["SimPiHole1"]
    sim.offered.clear()
    return sim


def start(sim, *, latch_authorised=False, confirmation=None, **overrides):
    preview = alignment_preview(sim.db, sim.cluster)
    assert preview.allowed, preview.blockers
    arguments = {"target_public_id": preview.dhcp_owner.public_id, "fingerprint": preview.fingerprint,
                 "confirmation": sim.cluster.name if confirmation is None else confirmation, "acknowledged": True,
                 "latch_authorised": latch_authorised}
    arguments.update(overrides)
    run = start_alignment(sim.db, sim.cluster, sim.admin, **arguments)
    drain_evaluations(sim.db)
    return run


def cycle(sim, run, **kwargs):
    apply_keepalived(sim, **{key: kwargs.pop(key) for key in ("reject", "skip", "vrrp_moves", "reject_message") if key in kwargs})
    report(sim, **kwargs)
    sim.db.refresh(run)
    return run


def drive(sim, run, *, steps=12, **kwargs):
    phases = [run.phase]
    for _ in range(steps):
        if run.status != "RUNNING":
            break
        cycle(sim, run, **kwargs)
        if phases[-1] != run.phase:
            phases.append(run.phase)
    return phases


def to_phase(sim, run, phase, *, steps=6, **kwargs):
    """Cycle agents until the run reaches ``phase`` (gates take two heartbeats, as with a real agent)."""
    for _ in range(steps):
        if run.phase == phase or run.status != "RUNNING":
            break
        cycle(sim, run, **kwargs)
    assert run.phase == phase, (run.status, run.phase, run.error_redacted)
    return run


def age_phase(sim, run, seconds):
    run.phase_started_at = run.phase_started_at - timedelta(seconds=seconds)
    sim.db.commit()


def assert_no_dhcp_or_lease_action(sim):
    assert not FORBIDDEN_ACTIONS & set(sim.offered), sorted(set(sim.offered))
    assert sim.sim_one.dhcp_running and not sim.sim_two.dhcp_running  # DHCP never moved
    assert sim.sim_one.lease_file == sim.sim_two.lease_file == b"synthetic-lease-file\n"


def audits(sim, action):
    return sim.db.query(AuditLog).filter(AuditLog.entity == "ha_service_alignment", AuditLog.action == action).all()


def finding(sim, code):
    return next((item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == code), None)


# --------------------------------------------------------------------------------------
# Preview and Health assessment
# --------------------------------------------------------------------------------------


def test_older_agents_block_alignment_with_an_exact_explanation():
    """The live incident shape (agents older than 0.2.15): blocked, never offered."""
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False)
    sim.report_both(2)
    sim.vrrp.stop("SimPiHole1")
    sim.report_both(1)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(2)
    preview = alignment_preview(sim.db, sim.cluster)
    assert preview.condition == "MISMATCH" and not preview.allowed
    failing = {check.code for check in preview.checks if not check.passed}
    assert failing == {"AGENT_VERSION", "AGENT_GATES"}
    mismatch_finding = finding(sim, "OWNERSHIP_MISMATCH")
    assert (mismatch_finding.disposition, mismatch_finding.repair) == (BLOCKED, None)
    assert "Align service ownership" in mismatch_finding.no_repair_reason and "0.2.15" in mismatch_finding.no_repair_reason


def test_ready_preview_is_offered_for_approval_with_impact_and_owners():
    sim = mismatch()
    preview = alignment_preview(sim.db, sim.cluster)
    assert preview.allowed and preview.condition == "MISMATCH"
    assert (preview.vip_owner.display_name, preview.dhcp_owner.display_name) == ("SimPiHole2", "SimPiHole1")
    assert any("from SimPiHole2 to SimPiHole1" in line for line in preview.impact)
    assert any("does not start, stop, promote or demote DHCP" in line for line in preview.impact)
    item = finding(sim, "OWNERSHIP_MISMATCH")
    assert item.disposition == APPROVAL_REQUIRED
    assert item.repair.key == "ALIGN_OWNERSHIP" and item.repair.path.endswith("/maintenance#align-ownership")
    assert all(prerequisite.satisfied for prerequisite in item.prerequisites)
    assert alignment_preview(sim.db, sim.cluster).fingerprint == preview.fingerprint  # stable for unchanged evidence
    assert sim.db.query(HAMaintenanceRun).count() == 0  # preview never writes


@pytest.mark.parametrize("fault, expected", [
    ("duplicate_vip", "DUPLICATE_VIP"),
    ("no_vip_owner", "NO_VIP_OWNER"),
    ("multiple_dhcp", "MULTIPLE_DHCP"),
    ("stale_report", "UNKNOWN"),
])
def test_ownership_faults_are_never_treated_as_alignment(fault, expected):
    sim = mismatch()
    if fault == "duplicate_vip":
        sim.sim_one.vrrp_state = "MASTER"  # e.g. a stale address after Keepalived was killed
    elif fault == "no_vip_owner":
        sim.sim_two.vrrp_state = "BACKUP"
    elif fault == "multiple_dhcp":
        sim.sim_two.dhcp_running = True
    report(sim)
    if fault == "stale_report":
        sim.make_stale(sim.sim_two)
    preview = alignment_preview(sim.db, sim.cluster)
    assert preview.condition == expected and not preview.allowed
    with pytest.raises(HAAlignmentError):
        start_alignment(sim.db, sim.cluster, sim.admin, target_public_id=sim.one.public_id, fingerprint=preview.fingerprint,
                        confirmation=sim.cluster.name, acknowledged=True, latch_authorised=False)
    assert sim.db.query(HAMaintenanceRun).count() == 0
    if fault == "duplicate_vip":
        assert "Kaya never removes Virtual IP addresses itself" in preview.checks[0].detail
        assert "stale owner" in finding(sim, "DUPLICATE_VIP").no_repair_reason


# --------------------------------------------------------------------------------------
# End-to-end success
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("automatic_failover", [False, True], ids=["auto-failover-off", "auto-failover-on"])
def test_alignment_moves_only_the_vip_restores_the_baseline_and_verifies(automatic_failover):
    sim = mismatch(automatic_failover=automatic_failover)
    settings = (sim.cluster.automatic_failover_enabled, sim.cluster.automatic_sync_enabled, sim.cluster.automatic_sync_allow_deletions)
    generation = sim.cluster.keepalived_generation
    run = start(sim)
    assert run.operation == "ALIGN_OWNERSHIP" and sim.cluster.maintenance_mode is True  # hooks held while it runs
    phases = drive(sim, run)
    # VERIFYING completes within the cycle that delivers the owner's reload and fresh reports.
    assert phases == ["CONFIRMING_GATES", "MOVING_VIP", "RESTORING_STANDBY_BASELINE", "RESTORING_OWNER_BASELINE", "COMPLETE"]
    assert run.status == "SUCCEEDED", run.error_redacted
    assert any("verifying from fresh reports" in row for row in json.loads(run.result_json)["progress"])
    snapshot = ownership_snapshot(sim)
    assert snapshot["vip_owners"] == snapshot["dhcp_owners"] == ["SimPiHole1"]
    assert snapshot["roles"] == {"SimPiHole1": "ACTIVE", "SimPiHole2": "STANDBY"}
    assert "OWNERSHIP_MISMATCH" not in snapshot["issues"]
    assert finding(sim, "OWNERSHIP_MISMATCH") is None  # resolved only by the fresh verification
    assert sim.cluster.maintenance_mode is False  # restored: it was off before the run
    assert (sim.cluster.automatic_failover_enabled, sim.cluster.automatic_sync_enabled, sim.cluster.automatic_sync_allow_deletions) == settings
    assert sim.cluster.keepalived_generation == generation + 2  # one move generation, one restoration generation
    assert outstanding(sim.cluster) is None
    assert all(_applied_stable(sim.cluster, node) for node in (sim.one, sim.two))
    assert sim.sim_one.nopreempt and sim.sim_two.nopreempt
    assert set(sim.offered) == {"KEEPALIVED_APPLY"}
    assert_no_dhcp_or_lease_action(sim)
    assert [len(audits(sim, action)) for action in ("started", "complete")] == [1, 1]
    events = {event.event_type for event in sim.events()}
    assert {"service_alignment_started", "service_alignment_moving_vip", "service_ownership_aligned"} <= events
    result = json.loads(run.result_json)
    assert result["verification"]["vip_owners"] == ["SimPiHole1"] and result["dhcp_actions_issued"] == 0


def test_restoration_is_staged_non_owner_first_then_owner():
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP")  # gates confirmed: move requested
    assert desired_keepalived_action(sim.cluster, sim.one)["configuration"].count("preempt_delay") == 1
    assert "nopreempt" in desired_keepalived_action(sim.cluster, sim.two)["configuration"]
    cycle(sim, run)
    assert run.phase == "RESTORING_STANDBY_BASELINE"
    assert desired_keepalived_action(sim.cluster, sim.two) is not None  # the node without the VIP
    assert desired_keepalived_action(sim.cluster, sim.one) is None
    cycle(sim, run)
    assert run.phase == "RESTORING_OWNER_BASELINE"
    owner_action = desired_keepalived_action(sim.cluster, sim.one)
    assert owner_action is not None and "nopreempt" in owner_action["configuration"]


# --------------------------------------------------------------------------------------
# Approval and the retained maintenance safety latch
# --------------------------------------------------------------------------------------


def test_start_requires_typed_confirmation_and_the_reviewed_preview():
    sim = mismatch()
    generation = sim.cluster.keepalived_generation
    preview = alignment_preview(sim.db, sim.cluster)
    cases = [
        {"confirmation": "wrong name"},
        {"acknowledged": False},
        {"fingerprint": "0" * 64},
        {"target_public_id": sim.two.public_id},
    ]
    for override in cases:
        arguments = {"target_public_id": preview.dhcp_owner.public_id, "fingerprint": preview.fingerprint,
                     "confirmation": sim.cluster.name, "acknowledged": True, "latch_authorised": False, **override}
        with pytest.raises(HAAlignmentError):
            start_alignment(sim.db, sim.cluster, sim.admin, **arguments)
    assert sim.db.query(HAMaintenanceRun).count() == 0
    denied = audits(sim, "denied")
    assert len(denied) == len(cases)
    assert {json.loads(row.metadata_json or "{}").get("reason_code") for row in denied} >= {"CONFIRMATION_REQUIRED", "PREVIEW_CHANGED"}
    assert sim.cluster.maintenance_mode is False and sim.cluster.keepalived_generation == generation


def test_second_request_while_running_is_refused():
    sim = mismatch()
    run = start(sim)
    preview = alignment_preview(sim.db, sim.cluster)
    assert not preview.allowed and "NO_OPERATION" in {check.code for check in preview.checks if not check.passed}
    with pytest.raises(HAAlignmentError):
        start_alignment(sim.db, sim.cluster, sim.admin, target_public_id=sim.one.public_id, fingerprint=preview.fingerprint,
                        confirmation=sim.cluster.name, acknowledged=True, latch_authorised=True)
    assert sim.db.query(HAMaintenanceRun).filter(HAMaintenanceRun.operation == "ALIGN_OWNERSHIP").count() == 1
    assert run.status == "RUNNING"


def latched_mismatch():
    """The incident with a retained latch from an earlier failed reinitialisation."""
    sim = mismatch(maintenance_mode=True, suffix="latch")
    failed = HAMaintenanceRun(cluster_id=sim.cluster.id, operation="REINITIALISE", status="FAILED_SAFE", phase="PAUSED",
                              desired_active_node_id=sim.one.id, authoritative_node_id=sim.one.id,
                              error_redacted="Synthetic earlier failure", completed_at=datetime.utcnow() - timedelta(hours=1),
                              created_at=datetime.utcnow() - timedelta(hours=1))
    sim.cluster.maintenance_runs.append(failed)
    sim.db.commit()
    return sim, failed


def test_retained_latch_requires_acknowledgement_and_explicit_authorisation_and_stays_held():
    sim, failed = latched_mismatch()
    preview = alignment_preview(sim.db, sim.cluster)
    latch = next(check for check in preview.checks if check.code == "LATCH")
    assert not latch.passed and "Acknowledge" in latch.detail and preview.latch_failed_run_id == failed.public_id
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    preview = alignment_preview(sim.db, sim.cluster)
    assert preview.allowed and preview.latch_retained
    assert latch_preview(sim.db, sim.cluster)["acknowledged"] is True
    with pytest.raises(HAAlignmentError):
        start(sim, latch_authorised=False)
    assert sim.db.query(HAMaintenanceRun).filter(HAMaintenanceRun.operation == "ALIGN_OWNERSHIP").count() == 0
    run = start(sim, latch_authorised=True)
    drive(sim, run)
    assert run.status == "SUCCEEDED", run.error_redacted
    assert sim.cluster.maintenance_mode is True  # the latch was not cleared
    assert sim.cluster.maintenance_latch_released_at is None
    started = json.loads(audits(sim, "started")[0].metadata_json)
    assert started["authorised_under_retained_latch"] is True and started["latch_released"] is False
    assert started["latch_failed_run_id"] == failed.public_id
    assert_no_dhcp_or_lease_action(sim)
    # The latch can now be reviewed with every ownership check passing.
    checks = {item["code"]: item["passed"] for item in latch_preview(sim.db, sim.cluster)["checks"]}
    assert checks["EXCLUSIVE_VIP"] and checks["EXCLUSIVE_DHCP"] and checks["DHCP_VIP_MATCH"]


def test_latch_without_an_identifiable_failed_operation_fails_closed():
    sim = mismatch(maintenance_mode=True, suffix="unknown-latch")
    preview = alignment_preview(sim.db, sim.cluster)
    latch = next(check for check in preview.checks if check.code == "LATCH")
    assert not latch.passed and "cannot identify" in latch.detail
    assert not preview.allowed


def test_stale_latch_acknowledgement_is_not_treated_as_current():
    sim, failed = latched_mismatch()
    sim.cluster.maintenance_latch_acknowledged_at = datetime.utcnow()
    sim.cluster.maintenance_latch_acknowledgement_json = json.dumps({"failed_run_id": "different-failed-run"})
    sim.db.commit()

    preview = alignment_preview(sim.db, sim.cluster)
    latch = next(check for check in preview.checks if check.code == "LATCH")
    assert not latch.passed and not preview.allowed
    assert latch_preview(sim.db, sim.cluster)["acknowledged"] is False
    assert failed.public_id != "different-failed-run"


# --------------------------------------------------------------------------------------
# Failures and interruptions: stop safely, no retry, no VIP return, evidence kept
# --------------------------------------------------------------------------------------


def assert_failed_safe(sim, run, *, changed: bool, text: str):
    assert run.status == "FAILED_SAFE" and run.phase == "PAUSED", (run.status, run.phase)
    assert text in run.error_redacted, run.error_redacted
    result = json.loads(run.result_json)
    assert result["latch_active"] is changed and result["keepalived_change_issued"] is changed
    assert result["failure_evidence"]["nodes"]  # evidence preserved
    assert sim.cluster.maintenance_mode is (True if changed else False)
    assert len(audits(sim, "fail_safe")) == 1
    assert_no_dhcp_or_lease_action(sim)
    # No retry: further evaluations change nothing.
    before = (run.status, run.phase, sim.cluster.keepalived_generation)
    report(sim)
    report(sim)
    sim.db.refresh(run)
    assert (run.status, run.phase, sim.cluster.keepalived_generation) == before


@pytest.mark.parametrize("message, expected", [
    ("Keepalived could not be reloaded. The previous configuration was restored and reloaded.", "previous configuration was restored"),
    ("Keepalived could not be reloaded. Rollback could not be confirmed, so the running Keepalived configuration is unknown.", "could not be confirmed"),
])
def test_reload_failure_stops_without_claiming_the_rollback_succeeded(message, expected):
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    cycle(sim, run, reject={"SimPiHole1"}, reject_message=message)
    assert_failed_safe(sim, run, changed=True, text="Kaya has not verified the running configuration")
    assert expected in run.error_redacted
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole2"]  # never moved back or forward by Kaya
    assert {item.code for item in assess_cluster(sim.db, sim.cluster).findings} >= {"KEEPALIVED_REJECTED", "MAINTENANCE_HOLD"}


def test_gate_timeout_changes_nothing():
    sim = mismatch()
    generation = sim.cluster.keepalived_generation
    run = start(sim)
    cycle(sim, run, frozen_gates={"SimPiHole2"})
    cycle(sim, run, frozen_gates={"SimPiHole2"})
    assert run.phase == "CONFIRMING_GATES"
    age_phase(sim, run, GATE_TIMEOUT_SECONDS + 1)
    cycle(sim, run, frozen_gates={"SimPiHole2"})
    assert_failed_safe(sim, run, changed=False, text="did not confirm")
    assert sim.cluster.keepalived_generation == generation and outstanding(sim.cluster) is None


def test_vip_that_never_moves_times_out_and_is_tracked():
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP")
    cycle(sim, run, vrrp_moves=False)
    assert run.phase == "MOVING_VIP"
    age_phase(sim, run, MOVE_TIMEOUT_SECONDS + 1)
    cycle(sim, run, vrrp_moves=False)
    assert_failed_safe(sim, run, changed=True, text="did not move")
    assert outstanding(sim.cluster)["preempt_node_id"] == sim.one.id  # the retained preempt grant stays visible


@pytest.mark.parametrize("phase", ["CONFIRMING_GATES", "MOVING_VIP", "RESTORING_STANDBY_BASELINE", "RESTORING_OWNER_BASELINE"])
def test_agent_disconnection_stops_the_repair(phase):
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, phase, vrrp_moves=phase != "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"} if phase == "MOVING_VIP" else frozenset())
    sim.make_stale(sim.sim_two)
    reconcile_cluster(sim.db, sim.cluster)  # the periodic pass still runs while Keepalived is pending
    sim.db.refresh(run)
    assert_failed_safe(sim, run, changed=phase != "CONFIRMING_GATES", text="Lost contact")


def test_dhcp_change_during_the_move_stops_without_touching_dhcp():
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    sim.sim_one.dhcp_running = False  # e.g. someone disables DHCP in Pi-hole mid-repair
    cycle(sim, run)
    assert run.status == "FAILED_SAFE" and "DHCP ownership changed" in run.error_redacted
    assert not FORBIDDEN_ACTIONS & set(sim.offered)


def test_dns_deterioration_stops_the_repair():
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    sim.sim_one.dns_healthy = False
    cycle(sim, run)
    assert_failed_safe(sim, run, changed=True, text="DNS health deteriorated")


def test_generation_change_during_the_repair_stops_it():
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    sim.cluster.keepalived_generation += 1  # another Keepalived change raced the repair
    sim.db.commit()
    cycle(sim, run)
    assert_failed_safe(sim, run, changed=True, text="Another change")


def test_persistent_dual_vip_ownership_stops_the_repair():
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    sim.sim_one.vrrp_state = "MASTER"  # both claim the VIP (as after a partition)
    report(sim)
    sim.db.refresh(run)
    assert run.status == "RUNNING" and json.loads(run.result_json).get("dual_vip_since")  # a brief overlap is tolerated
    result = json.loads(run.result_json)
    result["dual_vip_since"] = (datetime.utcnow() - timedelta(seconds=DUAL_VIP_TOLERANCE_SECONDS + 1)).isoformat()
    run.result_json = json.dumps(result)
    sim.db.commit()
    report(sim)
    sim.db.refresh(run)
    assert run.status == "FAILED_SAFE" and "split-brain" in run.error_redacted


def test_kaya_restart_in_every_phase_resumes_from_fresh_reports(monkeypatch):
    sim = mismatch()
    run = start(sim)
    restarts = 0
    for _ in range(12):
        if run.status != "RUNNING":
            break
        monkeypatch.setattr(ha_alignment, "PROCESS_STARTED_AT", datetime.utcnow())  # Kaya restarted before this step
        sim.db.expire_all()
        restarts += 1
        cycle(sim, run)
    assert run.status == "SUCCEEDED", run.error_redacted
    assert len(sim.events("service_alignment_resumed")) == restarts  # one event per restart, never repeated within a process
    assert_no_dhcp_or_lease_action(sim)


def test_no_lease_staging_is_offered_while_aligning():
    sim = mismatch()
    run = start(sim)
    state = sim.cluster.lease_replication
    state.status, state.target_node_id = "PENDING", sim.two.id
    sim.db.commit()
    assert "LEASE_SNAPSHOT_STAGE" not in desired_state(sim.two)["allowed_actions"]
    assert desired_state(sim.two)["lease_snapshot"] is None
    assert run.status == "RUNNING"


# --------------------------------------------------------------------------------------
# Reconcile workspace and route
# --------------------------------------------------------------------------------------


def page_request(path: str) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request({"type": "http", "method": "GET", "scheme": "https", "path": path, "raw_path": path.encode(),
                    "query_string": b"", "headers": [], "client": ("198.51.100.2", 1234),
                    "server": ("kaya.example.com", 443), "session": {"csrf_token": "csrf"}, "app": app}, receive)


def form_request(path: str, values: dict[str, str]) -> Request:
    body = urlencode(values).encode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({"type": "http", "method": "POST", "scheme": "https", "path": path, "raw_path": path.encode(),
                    "query_string": b"", "client": ("198.51.100.2", 1234), "server": ("kaya.example.com", 443),
                    "headers": [(b"content-type", b"application/x-www-form-urlencoded"), (b"content-length", str(len(body)).encode())],
                    "session": {"csrf_token": "csrf"}, "app": app}, receive)


def test_reconcile_workspace_shows_owners_prerequisites_impact_and_confirmation():
    sim = mismatch()
    base = f"/high-availability/clusters/{sim.cluster.public_id}"
    body = router.cluster_maintenance(sim.cluster.public_id, page_request(base + "/maintenance"), db=sim.db, user=sim.admin).body.decode()
    assert 'id="align-ownership"' in body and 'data-ha-align-form' in body
    assert "data-ha-align-vip>SimPiHole2<" in body and "data-ha-align-dhcp>SimPiHole1<" in body
    assert "Why Kaya recommends this repair" in body and "Expected service impact" in body
    assert body.count('data-ha-align-check="') == len(alignment_preview(sim.db, sim.cluster).checks)
    assert 'name="confirmation"' in body and 'name="authorise_under_latch"' not in body
    # Reinitialise is not the repair for this condition: it sits, closed, under Advanced.
    assert '<details class="panel ha-advanced" id="advanced" data-ha-advanced>' in body and '<details class="ha-action-disclosure">' in body


def test_route_is_admin_only_csrf_protected_and_validates_input(monkeypatch):
    async def inline(function, *args, **kwargs):  # in-memory SQLite cannot cross threads
        return function(*args, **kwargs)

    monkeypatch.setattr(router, "run_in_threadpool", inline)
    route = next(item for item in router.router.routes if getattr(item, "path", "") == "/high-availability/clusters/{public_id}/maintenance/align")
    assert "POST" in route.methods
    assert any(getattr(dependency.call, "__name__", "") == "require_ha_admin" for dependency in route.dependant.dependencies)
    sim = mismatch()
    preview = alignment_preview(sim.db, sim.cluster)
    path = f"/high-availability/clusters/{sim.cluster.public_id}/maintenance/align"
    good = {"csrf_token": "csrf", "target_node_id": sim.one.public_id, "preview_fingerprint": preview.fingerprint,
            "confirmation": sim.cluster.name, "acknowledge_alignment": "1"}
    for bad in ({"csrf_token": "forged"}, {"preview_fingerprint": "not-hex"}, {"target_node_id": "../x"}, {"confirmation": "x" * 201}):
        with pytest.raises(HTTPException) as raised:
            asyncio.run(router.align_service_ownership(sim.cluster.public_id, form_request(path, {**good, **bad}), db=sim.db, user=sim.admin))
        assert raised.value.status_code == 400
    assert sim.db.query(HAMaintenanceRun).count() == 0
    blocked = asyncio.run(router.align_service_ownership(sim.cluster.public_id, form_request(path, {**good, "confirmation": "nope"}), db=sim.db, user=sim.admin))
    assert blocked.status_code == 409 and "Type" in blocked.body.decode()
    started = asyncio.run(router.align_service_ownership(sim.cluster.public_id, form_request(path, good), db=sim.db, user=sim.admin))
    assert started.status_code == 303 and started.headers["location"].endswith("align=started#align-ownership")
    assert sim.db.query(HAMaintenanceRun).filter(HAMaintenanceRun.operation == "ALIGN_OWNERSHIP").count() == 1


def test_supported_sync_history_is_untouched():
    """The repair never creates a configuration sync run or backup (no Pi-hole configuration change)."""
    sim = mismatch()
    before = sim.db.query(HASyncRun).count()
    run = start(sim)
    drive(sim, run)
    assert run.status == "SUCCEEDED"
    assert sim.db.query(HASyncRun).count() == before
    assert not sim.db.query(HAEvent).filter(HAEvent.event_type.like("%dhcp_self_heal%")).count()


def test_prepared_deployment_during_the_repair_is_detected():
    """An administrator redeploying Keepalived mid-repair is caught by generation fencing."""
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    sim.cluster.status = "HEALTHY"
    prepare_deployment(sim.db, sim.cluster, sim.cluster.vrrp_router_id, True)
    cycle(sim, run)
    assert run.status == "FAILED_SAFE" and "Another change" in run.error_redacted


def test_periodic_pass_enforces_step_limits_while_keepalived_is_pending():
    """The production periodic pass must cover an aligning cluster even though its Keepalived status is PENDING_AGENT."""
    from sqlalchemy.orm import sessionmaker

    from app.models.models import RemoteManagerSetting
    from app.services import ha_watchdog

    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    assert sim.cluster.keepalived_status == "PENDING_AGENT"
    sim.db.add(RemoteManagerSetting(key="high_availability_enabled", value="1"))
    sim.db.commit()
    sim.make_stale(sim.sim_one)  # no heartbeat will signal the coordinator any more
    ha_watchdog.run_ha_watchdog_pass(sessionmaker(bind=sim.db.get_bind()))
    sim.db.refresh(run)
    assert run.status == "FAILED_SAFE" and "Lost contact" in run.error_redacted


def test_brief_absence_of_a_vip_report_during_the_move_is_tolerated_but_a_lasting_one_stops():
    """Lab finding: asynchronous heartbeats can show no owner for one interval although VRRP had no gap."""
    from app.services.ha_alignment import NO_VIP_OWNER_TOLERANCE_SECONDS

    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    sim.sim_two.vrrp_state = "BACKUP"  # the old owner's report says released; the new owner has not reported yet
    report(sim)
    sim.db.refresh(run)
    assert run.status == "RUNNING" and json.loads(run.result_json).get("no_vip_owner_since")
    sim.sim_one.vrrp_state = "MASTER"  # the target took the VIP (no real gap); its next report says so
    drive(sim, run)
    assert run.status == "SUCCEEDED", run.error_redacted

    lasting = mismatch(suffix="absent")
    run = start(lasting)
    to_phase(lasting, run, "MOVING_VIP", skip={"SimPiHole1", "SimPiHole2"})
    lasting.sim_two.vrrp_state = "BACKUP"
    report(lasting)
    lasting.db.refresh(run)
    result = json.loads(run.result_json)
    result["no_vip_owner_since"] = (datetime.utcnow() - timedelta(seconds=NO_VIP_OWNER_TOLERANCE_SECONDS + 1)).isoformat()
    run.result_json = json.dumps(result)
    lasting.db.commit()
    report(lasting)
    lasting.db.refresh(run)
    assert run.status == "FAILED_SAFE" and "No node reported the Virtual IP" in run.error_redacted
