"""P7: Health & Repair workspace, approved baseline restoration and repair outcomes.

Reuses the P6 simulated 0.2.15 agents (real signed heartbeat and action-result
paths, lab-validated VRRP behaviour).  Synthetic data only.
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.models import AuditLog, HAMaintenanceRun, NotificationEvent, NotificationOutbox
from app.routers import high_availability as router
from app.services.ha_alignment import MOVE_TIMEOUT_SECONDS, alignment_preview
from app.services.ha_assessment import (
    BLOCKED,
    HEALTHY,
    NEEDS_APPROVAL,
    RECOVERING,
    assess_cluster,
    health_summary,
)
from app.services.ha_baseline_repair import HABaselineRepairError, approve_restoration, restoration_preview
from app.services.ha_keepalived import desired_keepalived_action
from app.services.ha_keepalived_baseline import STEP_TIMEOUT_SECONDS, outstanding
from app.services.ha_maintenance import acknowledge_failed_safe_latch
from app.services.ha_repair_outcomes import failure_key
from app.services.ha_watchdog import reconcile_cluster
from app.services.notification_outbox import process_outbox
from ha_simulation import ownership_snapshot
from test_ha_assessment import SCENARIOS
from test_ha_p6_align_ownership import (
    age_phase,
    apply_keepalived,
    assert_no_dhcp_or_lease_action,
    cycle,
    drive,
    form_request,
    mismatch,
    page_request,
    report,
    start,
    to_phase,
)


def summary(sim):
    return health_summary(assess_cluster(sim.db, sim.cluster))


def page(sim, user=None) -> str:
    base = f"/high-availability/clusters/{sim.cluster.public_id}"
    return router.cluster_maintenance(sim.cluster.public_id, page_request(base + "/maintenance"), db=sim.db, user=user or sim.admin).body.decode()


def targets(sim) -> set[str]:
    return {node.display_name for node in sim.cluster.nodes if desired_keepalived_action(sim.cluster, node) is not None}


def restoration_audits(sim, action):
    return sim.db.query(AuditLog).filter(AuditLog.entity == "ha_keepalived_baseline", AuditLog.action == action).all()


def outbox(sim, event_type):
    return sim.db.query(NotificationOutbox).filter(NotificationOutbox.event_type == event_type).all()


def stopped_alignment():
    """Align service ownership stopped after changing Keepalived: the VIP never moved and a preempt grant remains."""
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP")
    cycle(sim, run, vrrp_moves=False)
    age_phase(sim, run, MOVE_TIMEOUT_SECONDS + 1)
    cycle(sim, run, vrrp_moves=False)
    assert run.status == "FAILED_SAFE" and sim.cluster.maintenance_mode is True
    report(sim)  # the coordinator moves the outstanding grant to PENDING_APPROVAL
    assert outstanding(sim.cluster)["state"] == "PENDING_APPROVAL"
    assert outstanding(sim.cluster)["preempt_node_id"] == sim.one.id
    return sim, run


def approve(sim, *, latch_authorised=True, **overrides):
    preview = restoration_preview(sim.db, sim.cluster)
    arguments = {"fingerprint": preview.fingerprint, "confirmation": sim.cluster.name, "acknowledged": True, "latch_authorised": latch_authorised}
    arguments.update(overrides)
    return approve_restoration(sim.db, sim.cluster, sim.admin, **arguments)


# --------------------------------------------------------------------------------------
# One status, one action
# --------------------------------------------------------------------------------------


def test_healthy_cluster_needs_no_action():
    sim = SCENARIOS["healthy"]()
    result = summary(sim)
    assert result.state == HEALTHY and result.action is None and result.headline == "No action required"


def test_mismatch_with_capable_agents_needs_approval_with_exactly_one_action():
    sim = mismatch()
    result = summary(sim)
    assert result.state == NEEDS_APPROVAL
    assert result.action.key == "ALIGN_OWNERSHIP" and result.action.path.endswith("/maintenance#align-ownership")
    body = page(sim)
    assert 'data-ha-health-state="needs_approval"' in body
    assert body.count("data-ha-health-action=") == 1 and 'data-ha-health-action="ALIGN_OWNERSHIP"' in body


def test_live_incident_shape_is_blocked_with_the_next_safe_step():
    """Agents older than 0.2.15 and a retained latch: blocked, and the next safe step is the agent update."""
    sim = SCENARIOS["incident"]()
    result = summary(sim)
    assert result.state == BLOCKED
    assert result.primary.code in {"OWNERSHIP_MISMATCH", "DUPLICATE_VIP", "NO_VIP_OWNER", "MULTIPLE_DHCP", "NO_DHCP_OWNER"}
    assert result.detail  # the exact reason
    if result.primary.code == "OWNERSHIP_MISMATCH":
        assert "0.2.15" in result.detail
        assert result.action is not None and result.action.key == "AGENT_UPDATE"


def test_running_repair_is_shown_as_recovering_with_what_kaya_is_doing():
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "MOVING_VIP")
    result = summary(sim)
    assert result.state == RECOVERING and result.action is None
    assert result.primary.code == "MAINTENANCE_IN_PROGRESS" and "Align service ownership" in result.primary.title
    body = page(sim)
    assert 'data-ha-health-state="recovering"' in body and "What Kaya is doing" in body
    assert "data-ha-align-form" not in body  # no second approval while it runs


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_routine_findings_never_require_reinitialise_or_another_maintenance_screen(scenario):
    sim = SCENARIOS[scenario]()
    findings = assess_cluster(sim.db, sim.cluster).findings
    for finding in findings:
        if finding.repair is None:
            continue
        assert finding.repair.key != "REINITIALISE", finding.code
        assert "reinitialise" not in finding.repair.label.lower(), finding.code
        if finding.category in {"OWNERSHIP", "MAINTENANCE", "RECOVERY"} or finding.repair.key in {"RESTORE_BASELINE", "RELEASE_HOLD", "RECONCILE"}:
            assert "/maintenance" in finding.repair.path, (finding.code, finding.repair.path)
    result = health_summary(assess_cluster(sim.db, sim.cluster))
    assert result.action is None or result.action.key != "REINITIALISE"


def test_workspace_shows_owners_roles_readiness_sync_and_holds():
    sim = mismatch()
    body = page(sim)
    for key in ("vip_owner", "dhcp_owner", "roles", "standby", "config_sync", "lease_sync", "keepalived", "holds", "automation"):
        assert f'data-ha-overview="{key}"' in body, key
    assert re.search(r'data-ha-overview="vip_owner" data-ha-overview-tone="ok">\s*<dt>[^<]+</dt>\s*<dd>SimPiHole2', body)
    assert re.search(r'data-ha-overview="dhcp_owner" data-ha-overview-tone="bad">\s*<dt>[^<]+</dt>\s*<dd>SimPiHole1', body)
    assert "automatic Keepalived restoration off" in body
    assert 'data-ha-nav="health-repair"' in body and 'aria-current="page" href="/high-availability/clusters/' in body
    assert "Reconcile or reinitialise" not in body
    # Reinitialise is advanced and closed; Reconcile State stays available.
    assert '<details class="panel ha-advanced" id="advanced" data-ha-advanced>' in body and 'id="reconcile"' in body


def test_viewers_see_the_status_but_no_repair_forms():
    sim = mismatch()
    sim.admin.role = "viewer"
    sim.db.commit()
    body = page(sim)
    assert 'data-ha-health-state="needs_approval"' in body
    assert "data-ha-align-form" not in body and "data-ha-restore-form" not in body and 'name="confirmation"' not in body


# --------------------------------------------------------------------------------------
# Incomplete repair: exact remaining condition and an approved restoration path
# --------------------------------------------------------------------------------------


def test_stopped_alignment_shows_exactly_what_remains():
    sim, run = stopped_alignment()
    body = page(sim)
    assert "data-ha-align-remaining" in body
    assert 'href="#restore-baseline"' in body and 'href="#latch-review"' in body
    assert "Still split: Virtual IP on SimPiHole2, DHCP on SimPiHole1" in body
    assert "SimPiHole1 may still hold the preempt-capable configuration" in body
    assert 'id="restore-baseline"' in body and 'data-ha-restoration-state="pending_approval"' in body
    finding = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "KEEPALIVED_PREEMPT_RETAINED")
    assert finding.disposition == BLOCKED and "Acknowledge" in finding.no_repair_reason  # latch not yet acknowledged


def test_approved_restoration_under_the_latch_restores_the_baseline_without_moving_anything():
    sim, run = stopped_alignment()
    blocked = restoration_preview(sim.db, sim.cluster)
    assert not blocked.allowed and {c.code for c in blocked.checks if not c.passed} == {"LATCH"}
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    preview = restoration_preview(sim.db, sim.cluster)
    assert preview.allowed and preview.latch_retained and preview.latch_failed_run_id == run.public_id
    assert preview.owner.display_name == "SimPiHole2" and preview.standby.display_name == "SimPiHole1"
    finding = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "KEEPALIVED_PREEMPT_RETAINED")
    assert finding.repair.key == "RESTORE_BASELINE" and finding.repair.path.endswith("#restore-baseline")
    with pytest.raises(HABaselineRepairError):
        approve(sim, latch_authorised=False)
    assert restoration_audits(sim, "denied") and outstanding(sim.cluster)["state"] == "PENDING_APPROVAL"
    generation = sim.cluster.keepalived_generation
    approve(sim)
    assert outstanding(sim.cluster)["state"] == "RESTORING_STANDBY"
    assert sim.cluster.keepalived_generation == generation + 1
    assert targets(sim) == {"SimPiHole1"}  # the node without the Virtual IP first
    for _ in range(6):
        if outstanding(sim.cluster) is None:
            break
        apply_keepalived(sim)
        report(sim)
    assert outstanding(sim.cluster) is None, outstanding(sim.cluster)
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole2"]  # never moved
    assert sim.sim_one.nopreempt and sim.sim_two.nopreempt  # what both nodes actually applied
    assert sim.cluster.maintenance_mode is True and sim.cluster.maintenance_latch_released_at is None  # latch held
    approved = json.loads(restoration_audits(sim, "approved")[0].metadata_json)
    assert approved["authorised_under_retained_latch"] is True and approved["latch_released"] is False
    assert approved["vip_move_authorised"] is False and approved["dhcp_change_authorised"] is False
    assert restoration_audits(sim, "restored")
    assert_no_dhcp_or_lease_action(sim)
    assert len(outbox(sim, "pihole.repair.failed")) == 1 and len(outbox(sim, "pihole.repair.completed")) == 1
    # The mismatch remains and Align service ownership can be approved again, under the same acknowledged latch.
    assert alignment_preview(sim.db, sim.cluster).allowed
    again = start(sim, latch_authorised=True)
    drive(sim, again)
    assert again.status == "SUCCEEDED", again.error_redacted
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole1"]
    assert_no_dhcp_or_lease_action(sim)


def test_a_failed_restoration_is_never_retried_without_a_new_approval():
    sim, _run = stopped_alignment()
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    approve(sim)
    apply_keepalived(sim, reject={"SimPiHole1"}, vrrp_moves=False)
    report(sim)
    state = outstanding(sim.cluster)
    assert state["state"] == "BLOCKED" and "does not assume it succeeded" in state["detail"]
    generation = sim.cluster.keepalived_generation
    for _ in range(3):
        report(sim)
        reconcile_cluster(sim.db, sim.cluster)
    assert sim.cluster.keepalived_generation == generation and outstanding(sim.cluster)["state"] == "BLOCKED"
    preview = restoration_preview(sim.db, sim.cluster)
    keepalived = next(check for check in preview.checks if check.code == "KEEPALIVED")
    assert not preview.allowed and not keepalived.passed and "will not stage another change" in keepalived.detail
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole2"]
    assert_no_dhcp_or_lease_action(sim)
    # Both stops share one active-condition key: the second collapses into the pending notification.
    failures = outbox(sim, "pihole.repair.failed")
    assert len(failures) == 1 and failures[0].deduplication_key == failure_key(sim.cluster)
    assert sim.events("keepalived_restoration_blocked") and sim.events("service_alignment_failed_safe")  # both kept in Activity


def test_a_stalled_approved_restoration_times_out_and_blocks():
    sim, _run = stopped_alignment()
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    approve(sim)
    state = outstanding(sim.cluster)
    from datetime import datetime, timedelta

    state["phase_started_at"] = (datetime.utcnow() - timedelta(seconds=STEP_TIMEOUT_SECONDS + 1)).isoformat()
    sim.cluster.keepalived_restoration_json = json.dumps(state)
    sim.db.commit()
    reconcile_cluster(sim.db, sim.cluster)  # the periodic pass covers a pending restoration
    assert outstanding(sim.cluster)["state"] == "BLOCKED"


@pytest.mark.parametrize("fault, code", [
    ("dual_vip", "VIP_OWNER"),
    ("stale", "FRESH_REPORTS"),
    ("dns", "OWNER_DNS"),
    ("old_agent", "AGENT_VERSION"),
])
def test_restoration_is_blocked_on_unsafe_evidence(fault, code):
    sim, _run = stopped_alignment()
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    if fault == "dual_vip":
        sim.sim_one.vrrp_state = "MASTER"
        report(sim)
    elif fault == "stale":
        sim.make_stale(sim.sim_one)
    elif fault == "dns":
        sim.sim_two.dns_healthy = False
        report(sim)
    elif fault == "old_agent":
        report(sim, agent_version="0.2.14")
    preview = restoration_preview(sim.db, sim.cluster)
    failing = {check.code for check in preview.checks if not check.passed}
    assert code in failing and not preview.allowed, failing
    with pytest.raises(HABaselineRepairError):
        approve(sim)
    assert outstanding(sim.cluster)["state"] in {"PENDING_APPROVAL", "OUTSTANDING"}


def test_restoration_with_older_agents_keeps_the_p5_redeploy_path():
    sim, _run = stopped_alignment()
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    report(sim, agent_version="0.2.14", gates=False)
    finding = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "KEEPALIVED_PREEMPT_RETAINED")
    # The cluster is degraded, so a redeployment must be preceded by the safety checks (close-out: no dead end).
    assert sim.cluster.status == "DEGRADED"
    assert finding.repair is not None and finding.repair.key == "VALIDATE_THEN_REDEPLOY" and finding.repair.path.endswith("/validation")
    sim.cluster.status = "HEALTHY"
    sim.db.commit()
    finding = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "KEEPALIVED_PREEMPT_RETAINED")
    assert finding.repair.key == "KEEPALIVED_DEPLOY" and finding.repair.path.endswith("/deployment")


def test_restoration_route_is_admin_only_csrf_protected_and_validates_input(monkeypatch):
    async def inline(function, *args, **kwargs):  # in-memory SQLite cannot cross threads
        return function(*args, **kwargs)

    monkeypatch.setattr(router, "run_in_threadpool", inline)
    route = next(item for item in router.router.routes if getattr(item, "path", "") == "/high-availability/clusters/{public_id}/maintenance/restore-baseline")
    assert "POST" in route.methods
    assert any(getattr(dependency.call, "__name__", "") == "require_ha_admin" for dependency in route.dependant.dependencies)
    sim, _run = stopped_alignment()
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    preview = restoration_preview(sim.db, sim.cluster)
    path = f"/high-availability/clusters/{sim.cluster.public_id}/maintenance/restore-baseline"
    good = {"csrf_token": "csrf", "preview_fingerprint": preview.fingerprint, "confirmation": sim.cluster.name,
            "acknowledge_restoration": "1", "authorise_under_latch": "1"}
    for bad in ({"csrf_token": "forged"}, {"preview_fingerprint": "zz"}, {"confirmation": "x" * 201}):
        with pytest.raises(HTTPException) as raised:
            asyncio.run(router.restore_keepalived_baseline(sim.cluster.public_id, form_request(path, {**good, **bad}), db=sim.db, user=sim.admin))
        assert raised.value.status_code == 400
    assert outstanding(sim.cluster)["state"] == "PENDING_APPROVAL"
    refused = asyncio.run(router.restore_keepalived_baseline(sim.cluster.public_id, form_request(path, {**good, "authorise_under_latch": ""}), db=sim.db, user=sim.admin))
    assert refused.status_code == 409 and "latch" in refused.body.decode()
    started = asyncio.run(router.restore_keepalived_baseline(sim.cluster.public_id, form_request(path, good), db=sim.db, user=sim.admin))
    assert started.status_code == 303 and started.headers["location"].endswith("restore=started#restore-baseline")
    assert outstanding(sim.cluster)["state"] == "RESTORING_STANDBY"


def test_no_restoration_offered_when_nothing_is_outstanding():
    sim = mismatch()
    preview = restoration_preview(sim.db, sim.cluster)
    assert not preview.relevant and not preview.allowed
    assert 'id="restore-baseline"' not in page(sim)


# --------------------------------------------------------------------------------------
# Repair outcome notifications (deduplicated)
# --------------------------------------------------------------------------------------


def test_repair_outcomes_notify_once_and_success_resolves_the_failure():
    sim, run = stopped_alignment()
    failures = outbox(sim, "pihole.repair.failed")
    assert len(failures) == 1 and failures[0].deduplication_key == failure_key(sim.cluster)
    assert failures[0].target_route.endswith("/maintenance")
    message = failures[0].message
    assert "secret" not in message.lower() and "password" not in message.lower()
    factory = lambda: Session(sim.db.get_bind(), expire_on_commit=False)  # noqa: E731
    process_outbox(session_factory=factory)
    events = sim.db.query(NotificationEvent).filter(NotificationEvent.deduplication_key == failure_key(sim.cluster)).all()
    assert len(events) == 1 and events[0].resolved_at is None
    # A second stop while the first is unresolved is recorded in Activity but not notified again.
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    approve(sim)
    apply_keepalived(sim, reject={"SimPiHole1"}, vrrp_moves=False)
    report(sim)
    process_outbox(session_factory=factory)
    sim.db.expire_all()
    events = sim.db.query(NotificationEvent).filter(NotificationEvent.deduplication_key == failure_key(sim.cluster)).all()
    assert len(events) == 1
    assert sim.events("keepalived_restoration_blocked") and sim.events("service_alignment_failed_safe")


def test_successful_alignment_notifies_completion():
    sim = mismatch()
    run = start(sim)
    drive(sim, run)
    assert run.status == "SUCCEEDED"
    completed = outbox(sim, "pihole.repair.completed")
    assert len(completed) == 1 and run.public_id in completed[0].deduplication_key
    assert completed[0].resolve_deduplication_key == failure_key(sim.cluster)
    assert not outbox(sim, "pihole.repair.failed")


def test_after_a_verified_restoration_with_services_aligned_the_next_step_is_reconcile_not_a_dead_end():
    """Lab-observed: the VIP had moved before the stop; once restored, only Kaya's records lag."""
    sim = mismatch()
    run = start(sim)
    to_phase(sim, run, "RESTORING_OWNER_BASELINE")  # the VIP is already on the DHCP owner
    sim.make_stale(sim.sim_one)
    reconcile_cluster(sim.db, sim.cluster)
    assert run.status == "FAILED_SAFE" or sim.db.get(HAMaintenanceRun, run.id).status == "FAILED_SAFE"
    apply_keepalived(sim)  # the reconnected agent applies its pending stable configuration
    report(sim)
    report(sim)
    acknowledge_failed_safe_latch(sim.db, sim.cluster, sim.admin)
    if outstanding(sim.cluster) is not None and restoration_preview(sim.db, sim.cluster).allowed:
        approve(sim)
        for _ in range(6):
            if outstanding(sim.cluster) is None:
                break
            apply_keepalived(sim)
            report(sim)
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole1"] and outstanding(sim.cluster) is None
    hold = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "MAINTENANCE_HOLD")
    assert hold.repair is not None and hold.repair.key in {"RECONCILE", "RELEASE_HOLD"}, (hold.disposition, hold.no_repair_reason)
    assert summary(sim).action is not None

