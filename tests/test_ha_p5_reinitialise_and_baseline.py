"""P5: D4 reinitialisation ordering and D8/D9 Keepalived baseline restoration.

Agents are simulated: they report through the real heartbeat and action-result
paths, apply Kaya's Keepalived actions with the outcome observed in the
isolated real-VRRP lab (the only preempt-capable node becomes MASTER), and
stage leases through the real lease-stage result path.  Only Pi-hole reads are
replaced by synthetic stand-ins; lease authority, generation and fencing checks
are real.  Every step asserts that no DHCP action was issued and DHCP never
moved.  Synthetic data only.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta

import pytest

from app.models.models import AuditLog, HAEvent, HAMaintenanceRun, HASyncRun
from app.schemas.high_availability import HAAgentActionResult
from app.services import ha_keepalived_baseline as baseline
from app.services import ha_leases
from app.services.ha_agents import desired_state, record_action_result, record_heartbeat
from app.services.ha_assessment import assess_cluster
from app.services.ha_keepalived import desired_keepalived_action, prepare_deployment
from app.services.ha_leases import HALeaseError, LeasePlan, desired_lease_action
from app.services.ha_maintenance import advance_reinitialisation, desired_maintenance_action, start_reinitialisation
from app.services.ha_topology import reconcile_topology
from app.services.ha_watchdog import drain_evaluations, reconcile_cluster
from ha_simulation import hal_like_cluster, heartbeat_for, ownership_snapshot, sqlite_session

DHCP_ACTIONS = {"DHCP_PROMOTE", "DHCP_DEMOTE"}


@pytest.fixture
def offline(monkeypatch):
    """Synthetic Pi-hole reads only; lease authority and fencing stay real."""
    def live_configuration(endpoint):
        return None, {"dns": {"upstreams": ["192.0.2.53"]}}

    def create_sync_plan(db, cluster, user):
        source = next(node for node in cluster.nodes if node.id == cluster.authoritative_node_id)
        target = next(node for node in cluster.nodes if node.id != source.id)
        run = HASyncRun(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="IN_SYNC",
                        plan_json='{"groups":[]}', completed_at=datetime.utcnow())
        db.add(run)
        db.flush()
        return run

    def inspect_lease_plan(inputs, **kwargs):
        lease = {"expires": 2_000_000_000, "hwaddr": "02:00:00:00:00:41", "ip": "192.0.2.70", "name": "synthetic-client", "clientid": ""}
        return LeasePlan(True, inputs.source_id, inputs.source_public_id, inputs.target_id, [lease], set(),
                         ipaddress.IPv4Address("192.0.2.20"), ipaddress.IPv4Address("192.0.2.200"),
                         inputs.role_generation, inputs.keepalived_generation, inputs.cluster_generation)

    monkeypatch.setattr("app.services.ha_maintenance._live_configuration", live_configuration)
    monkeypatch.setattr("app.services.ha_maintenance.create_sync_plan", create_sync_plan)
    monkeypatch.setattr(ha_leases, "inspect_lease_plan", inspect_lease_plan)


@pytest.fixture
def restoration_on(monkeypatch):
    monkeypatch.setattr(baseline, "restoration_enabled", lambda: True)


def split_sim():
    """4 November: VIP on node two, DHCP on node one (the assigned Active)."""
    sim = hal_like_cluster(sqlite_session())
    sim.report_both(2)
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_one)
    sim.report(sim.sim_two)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(2)
    assert "OWNERSHIP_MISMATCH" in ownership_snapshot(sim)["issues"]
    return sim


def pairs(sim):
    return ((sim.sim_one, sim.one), (sim.sim_two, sim.two))


def report(sim):
    """Fresh signed reports from both agents, then the coordinator evaluates."""
    for simnode, node in pairs(sim):
        record_heartbeat(sim.db, node, heartbeat_for(simnode, observed_generation=sim.cluster.role_generation))
    drain_evaluations(sim.db)


def assert_no_dhcp_action(sim):
    for _simnode, node in pairs(sim):
        assert not DHCP_ACTIONS & set(desired_state(node)["allowed_actions"])
        action = desired_maintenance_action(sim.cluster, node)
        assert action is None or action["action_type"] not in DHCP_ACTIONS


def agents_apply_keepalived(sim, *, reject: set[str] = frozenset()):
    """Apply pending Keepalived actions through the real result path; the lab-validated VRRP outcome follows."""
    preempting = None
    for simnode, node in pairs(sim):
        action = desired_keepalived_action(sim.cluster, node)
        if action is None:
            continue
        failed = simnode.name in reject
        record_action_result(sim.db, node, HAAgentActionResult(
            action_id=action["action_id"], action_type="KEEPALIVED_APPLY", generation=action["generation"],
            status="FAILED" if failed else "APPLIED", checksum=None if failed else action["checksum"],
            message="Keepalived could not be reloaded. The previous configuration was restored and reloaded." if failed else "applied"))
        if not failed:
            simnode.keepalived_generation = action["generation"]
            if "preempt_delay" in action["configuration"] and simnode.dns_healthy:
                preempting = simnode
    if preempting is not None:
        for simnode, _node in pairs(sim):
            simnode.vrrp_state = "MASTER" if simnode is preempting else "BACKUP"
    drain_evaluations(sim.db)
    return preempting


def agent_stages_leases(sim):
    action = desired_lease_action(sim.cluster, sim.two)
    if action is None:
        return False
    record_action_result(sim.db, sim.two, HAAgentActionResult(
        action_id=action["action_id"], action_type="LEASE_SNAPSHOT_STAGE", generation=action["generation"],
        status="APPLIED", checksum=action["checksum"], message="staged"))
    sim.sim_two.lease_generation = action["generation"]
    return True


def run_of(sim) -> HAMaintenanceRun:
    return sim.db.query(HAMaintenanceRun).order_by(HAMaintenanceRun.id.desc()).first()


def drive(sim, run, *, steps=20, before_step=None):
    phases = [run.phase]
    for _ in range(steps):
        if run.status != "RUNNING":
            break
        if before_step:
            before_step(run)
        agents_apply_keepalived(sim)
        agent_stages_leases(sim)
        report(sim)
        advance_reinitialisation(sim.db, run)
        assert_no_dhcp_action(sim)
        assert sim.sim_one.dhcp_running and not sim.sim_two.dhcp_running  # DHCP never moves
        if phases[-1] != run.phase:
            phases.append(run.phase)
    return phases


# --- D4: reinitialisation ordering -----------------------------------------------------


def test_d4_sole_dhcp_owner_aligns_the_vip_before_staging_leases(offline):
    sim = split_sim()
    automation_before = (sim.cluster.automatic_failover_enabled, sim.cluster.automatic_sync_enabled)
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    phases = drive(sim, run)
    assert run.status == "SUCCEEDED", (run.error_redacted, phases)
    staging = min(phases.index(phase) for phase in ("STAGING_DHCP", "WAITING_FOR_DHCP_STAGE") if phase in phases)
    assert phases.index("WAITING_FOR_VIP") < staging  # leases staged only after the Virtual IP moved
    assert "DEMOTING_STANDBY" not in phases and "PROMOTING_ACTIVE" not in phases
    snapshot = ownership_snapshot(sim)
    assert snapshot["vip_owners"] == snapshot["dhcp_owners"] == ["SimPiHole1"]
    assert sim.cluster.current_active_node_id == sim.cluster.authoritative_node_id == sim.one.id
    assert sim.cluster.lease_replication.status == "CURRENT" and sim.two.lease_generation == sim.cluster.lease_replication.desired_generation
    assert (sim.cluster.automatic_failover_enabled, sim.cluster.automatic_sync_enabled) == automation_before


def test_d4_lease_staging_keeps_its_authority_checks_after_alignment(offline, monkeypatch):
    sim = split_sim()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)

    def unsafe_staging(inputs, **kwargs):
        raise HALeaseError("Kaya cannot verify one safe VIP owner for lease replication.")

    monkeypatch.setattr(ha_leases, "inspect_lease_plan", unsafe_staging)
    drive(sim, run)
    assert run.status == "FAILED_SAFE" and "lease replication" in run.error_redacted
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole1"]  # DHCP untouched
    assert sim.cluster.authoritative_node_id == sim.one.id


def test_d4_dhcp_ownership_change_during_the_vip_move_stops_safely(offline):
    sim = split_sim()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    for _ in range(10):
        if run.phase == "WAITING_FOR_VIP":
            break
        report(sim)
        advance_reinitialisation(sim.db, run)
    assert run.phase == "WAITING_FOR_VIP"
    sim.sim_two.dhcp_running = True  # an unexpected second DHCP server appears
    agents_apply_keepalived(sim)
    report(sim)
    advance_reinitialisation(sim.db, run)
    assert run.status == "FAILED_SAFE"
    assert "DHCP ownership changed" in run.error_redacted
    for _simnode, node in pairs(sim):
        action = desired_maintenance_action(sim.cluster, node)
        assert action is None


def test_d4_vip_that_never_moves_fails_safe_and_preserves_authority_and_baselines(offline):
    sim = split_sim()
    sim.one.configuration_checksum, sim.two.configuration_checksum = "a" * 64, "b" * 64
    sim.db.commit()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.two, acknowledged=True)
    sim.sim_one.dns_healthy = False  # the destination cannot become MASTER
    for _ in range(12):
        if run.phase == "WAITING_FOR_VIP" or run.status != "RUNNING":
            break
        report(sim)
        advance_reinitialisation(sim.db, run)
    assert run.phase == "WAITING_FOR_VIP", run.error_redacted
    agents_apply_keepalived(sim)
    report(sim)
    run.phase_started_at = datetime.utcnow() - timedelta(seconds=91)
    sim.db.commit()
    advance_reinitialisation(sim.db, run)
    assert run.status == "FAILED_SAFE" and "No additional DHCP service was started" in run.error_redacted
    assert sim.cluster.authoritative_node_id == sim.one.id  # previous authority restored
    assert (sim.one.configuration_checksum, sim.two.configuration_checksum) == ("a" * 64, "b" * 64)
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole1"]
    assert baseline.outstanding(sim.cluster)["preempt_node_id"] == sim.one.id  # D9 recorded


def test_d4_kaya_restart_after_the_vip_moved_resumes_from_fresh_reports(offline, monkeypatch):
    sim = split_sim()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    for _ in range(12):
        if run.phase in {"STAGING_DHCP", "WAITING_FOR_DHCP_STAGE"} or run.status != "RUNNING":
            break
        agents_apply_keepalived(sim)
        report(sim)
        advance_reinitialisation(sim.db, run)
    assert run.phase in {"STAGING_DHCP", "WAITING_FOR_DHCP_STAGE"}
    monkeypatch.setattr("app.services.ha_maintenance.PROCESS_STARTED_AT", datetime.utcnow() + timedelta(seconds=1))
    advance_reinitialisation(sim.db, run)
    assert run.phase == "WAITING_FOR_REPORTS"
    phases = drive(sim, run)
    assert run.status == "SUCCEEDED", (run.error_redacted, phases)
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole1"]


def test_selecting_the_vip_owner_keeps_the_existing_order_and_is_not_the_split_repair(offline):
    """Reinitialise is not the VIP/DHCP split repair: choosing the VIP owner still stops before moving DHCP."""
    sim = split_sim()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.two, authority=sim.two, acknowledged=True)
    for _ in range(8):
        if run.status != "RUNNING":
            break
        report(sim)
        advance_reinitialisation(sim.db, run)
    assert run.status == "FAILED_SAFE" and "lease replication" in (run.error_redacted or "")
    assert ownership_snapshot(sim)["dhcp_owners"] == ["SimPiHole1"]


# --- D8 / D9: Keepalived baseline restoration ------------------------------------------


def finished_reinitialisation(offline_fixture=None):
    sim = split_sim()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    drive(sim, run)
    assert run.status == "SUCCEEDED", run.error_redacted
    return sim


def keepalived_targets(sim):
    return {node.display_name for _simnode, node in pairs(sim) if desired_keepalived_action(sim.cluster, node)}


def test_d8_restoration_is_reported_but_not_applied_while_disabled(offline):
    sim = finished_reinitialisation()
    reconcile_cluster(sim.db, sim.cluster)
    state = baseline.outstanding(sim.cluster)
    assert state["state"] == "PENDING_APPROVAL" and state["preempt_node_id"] == sim.one.id
    assert keepalived_targets(sim) == set()  # nothing pushed
    reconcile_cluster(sim.db, sim.cluster)
    assert len(sim.events("keepalived_restoration_pending")) == 1
    finding = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "KEEPALIVED_PREEMPT_RETAINED")
    assert finding.repair is not None and finding.repair.path.endswith("/deployment")


def test_d8_restoration_applies_to_the_standby_first_then_verifies_the_owner(offline, restoration_on):
    sim = finished_reinitialisation()  # restoration starts in the same coordinator evaluation
    reconcile_cluster(sim.db, sim.cluster)
    state = baseline.outstanding(sim.cluster)
    assert state["state"] == "RESTORING_STANDBY" and state["preempt_node_id"] == sim.one.id
    generation = sim.cluster.keepalived_generation
    assert generation == state["restore_generation"]
    assert keepalived_targets(sim) == {"SimPiHole2"}  # the node without the VIP only
    reconcile_cluster(sim.db, sim.cluster)
    assert sim.cluster.keepalived_generation == generation  # idempotent: no second bump
    agents_apply_keepalived(sim)
    reconcile_cluster(sim.db, sim.cluster)
    assert keepalived_targets(sim) == {"SimPiHole1"}  # then the owner
    configuration = desired_keepalived_action(sim.cluster, sim.one)["configuration"]
    assert "nopreempt" in configuration and "preempt_delay" not in configuration
    agents_apply_keepalived(sim)
    reconcile_cluster(sim.db, sim.cluster)
    assert baseline.outstanding(sim.cluster)["state"] == "VERIFYING"  # applied is not yet verified
    report(sim)
    reconcile_cluster(sim.db, sim.cluster)
    assert baseline.outstanding(sim.cluster) is None
    assert len(sim.events("keepalived_baseline_restored")) == 1
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole1"]
    assert sim.db.query(AuditLog).filter_by(entity="ha_keepalived_baseline", action="restored").count() == 1


def test_d9_failed_safe_move_restores_the_preempting_non_owner_first(offline, restoration_on):
    sim = split_sim()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    sim.sim_one.dns_healthy = False
    for _ in range(12):
        if run.phase == "WAITING_FOR_VIP" or run.status != "RUNNING":
            break
        report(sim)
        advance_reinitialisation(sim.db, run)
    agents_apply_keepalived(sim)
    report(sim)
    run.phase_started_at = datetime.utcnow() - timedelta(seconds=91)
    sim.db.commit()
    advance_reinitialisation(sim.db, run)
    assert run.status == "FAILED_SAFE"
    sim.sim_one.dns_healthy = True
    report(sim)
    reconcile_cluster(sim.db, sim.cluster)
    assert keepalived_targets(sim) == {"SimPiHole1"}  # the preempt-capable non-owner first
    agents_apply_keepalived(sim)
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole2"]  # nopreempt: it never takes the VIP
    for _ in range(3):
        reconcile_cluster(sim.db, sim.cluster)
        agents_apply_keepalived(sim)
        report(sim)
    reconcile_cluster(sim.db, sim.cluster)
    assert baseline.outstanding(sim.cluster) is None
    assert ownership_snapshot(sim)["vip_owners"] == ["SimPiHole2"]


def test_ownership_change_during_restoration_blocks_without_retry(offline, restoration_on):
    sim = finished_reinitialisation()
    reconcile_cluster(sim.db, sim.cluster)
    agents_apply_keepalived(sim)
    reconcile_cluster(sim.db, sim.cluster)
    # Keepalived on the owner crashes (lab: the VIP moves to the peer within a second).
    sim.sim_one.vrrp_state, sim.sim_two.vrrp_state = "BACKUP", "MASTER"
    report(sim)
    reconcile_cluster(sim.db, sim.cluster)
    state = baseline.outstanding(sim.cluster)
    assert state["state"] == "BLOCKED" and "Virtual IP owner changed" in state["detail"]
    generation = sim.cluster.keepalived_generation
    for _ in range(3):
        reconcile_cluster(sim.db, sim.cluster)
    assert sim.cluster.keepalived_generation == generation  # never retried automatically
    assert not sim.events("keepalived_baseline_restored")
    assert sim.db.query(AuditLog).filter_by(entity="ha_keepalived_baseline", action="blocked").count() == 1


def test_a_rejected_restoration_is_blocked_with_the_agent_outcome(offline, restoration_on):
    sim = finished_reinitialisation()
    reconcile_cluster(sim.db, sim.cluster)
    agents_apply_keepalived(sim, reject={"SimPiHole2"})
    reconcile_cluster(sim.db, sim.cluster)
    state = baseline.outstanding(sim.cluster)
    assert state["state"] == "BLOCKED" and "previous configuration was restored" in state["detail"]
    assert not sim.events("keepalived_baseline_restored")


def test_a_stalled_restoration_times_out_and_blocks(offline, restoration_on):
    sim = finished_reinitialisation()
    reconcile_cluster(sim.db, sim.cluster)
    state = baseline.outstanding(sim.cluster)
    state["phase_started_at"] = (datetime.utcnow() - timedelta(seconds=baseline.STEP_TIMEOUT_SECONDS + 1)).isoformat()
    sim.cluster.keepalived_restoration_json = json.dumps(state)
    sim.db.commit()
    reconcile_cluster(sim.db, sim.cluster)
    assert baseline.outstanding(sim.cluster)["state"] == "BLOCKED"


def test_an_administrator_redeploy_satisfies_a_blocked_or_pending_restoration(offline):
    sim = finished_reinitialisation()
    reconcile_cluster(sim.db, sim.cluster)
    assert baseline.outstanding(sim.cluster)["state"] == "PENDING_APPROVAL"
    sim.cluster.maintenance_mode = False
    sim.db.commit()
    prepare_deployment(sim.db, sim.cluster, sim.cluster.vrrp_router_id or 51, True)
    assert keepalived_targets(sim) == {"SimPiHole1", "SimPiHole2"}
    agents_apply_keepalived(sim)
    report(sim)
    reconcile_cluster(sim.db, sim.cluster)
    assert baseline.outstanding(sim.cluster) is None
    restored = sim.events("keepalived_baseline_restored")[-1]
    assert json.loads(restored.details_json_redacted)["owner_verified"] is False  # not claimed


def test_restoration_state_survives_a_kaya_restart(offline, restoration_on):
    sim = finished_reinitialisation()
    reconcile_cluster(sim.db, sim.cluster)
    agents_apply_keepalived(sim)
    persisted = sim.cluster.keepalived_restoration_json
    sim.db.expire_all()  # a new process reads the persisted state only
    assert sim.cluster.keepalived_restoration_json == persisted
    for _ in range(3):
        reconcile_cluster(sim.db, sim.cluster)
        agents_apply_keepalived(sim)
        report(sim)
    reconcile_cluster(sim.db, sim.cluster)
    assert baseline.outstanding(sim.cluster) is None
    assert len(sim.events("keepalived_restoration_started")) == 1


def test_no_dhcp_or_lease_change_is_ever_issued_by_restoration(offline, restoration_on):
    sim = finished_reinitialisation()
    leases_before = (sim.cluster.lease_replication.desired_generation, sim.cluster.lease_replication.applied_generation)
    for _ in range(4):
        reconcile_cluster(sim.db, sim.cluster)
        assert_no_dhcp_action(sim)
        for _simnode, node in pairs(sim):
            assert desired_lease_action(sim.cluster, node) is None
        agents_apply_keepalived(sim)
        report(sim)
    assert (sim.cluster.lease_replication.desired_generation, sim.cluster.lease_replication.applied_generation) == leases_before
    assert sim.sim_one.dhcp_running and not sim.sim_two.dhcp_running
    assert reconcile_topology(sim.cluster).vip_owner_ids == (sim.one.id,)
    assert not sim.db.query(HAEvent).filter(HAEvent.event_type.like("%dhcp%promot%")).count()


# --- notifications: one alert per incident --------------------------------------------


def healthy_sim():
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False)
    sim.report_both(2)
    return sim


def outbox_types(sim):
    from app.models.models import NotificationOutbox

    counts = {}
    for row in sim.db.query(NotificationOutbox).all():
        counts[row.event_type] = counts.get(row.event_type, 0) + 1
    return counts


def test_a_transient_vrrp_election_never_alerts():
    sim = healthy_sim()
    sim.vrrp.stop("SimPiHole1")  # lab: the peer takes the VIP within a second
    sim.report(sim.sim_one)  # momentarily nobody reports the VIP
    sim.vrrp.start("SimPiHole1")
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = True, False  # DHCP follows locally
    sim.report_both(3)
    assert outbox_types(sim) == {}
    assert sim.cluster.missing_owner_since is None and sim.cluster.ownership_mismatch_since is None


def test_a_sustained_missing_owner_raises_one_specific_degraded_alert_then_recovers():
    from app.services.ha_ownership_alerts import MISSING_OWNER_CONFIRM_SECONDS

    sim = healthy_sim()
    sim.vrrp.stop("SimPiHole1")
    sim.vrrp.stop("SimPiHole2")
    sim.report_both(2)
    assert sim.cluster.status != "HEALTHY" and outbox_types(sim) == {}  # dashboard shows it; alert waits
    sim.cluster.missing_owner_since -= timedelta(seconds=MISSING_OWNER_CONFIRM_SECONDS + 1)
    sim.db.commit()
    sim.report_both(3)
    from app.models.models import NotificationOutbox

    [alert] = sim.db.query(NotificationOutbox).filter(NotificationOutbox.event_type == "pihole.cluster.degraded").all()
    assert "No node holds the virtual IP" in alert.message
    sim.vrrp.start("SimPiHole1")
    sim.vrrp.start("SimPiHole2")
    sim.report_both(3)
    assert sim.cluster.status == "HEALTHY"
    assert outbox_types(sim) == {"pihole.cluster.degraded": 1, "pihole.cluster.recovered": 1}
    assert len(sim.events("missing_owner_resolved")) == 1


def test_a_non_ownership_degradation_still_alerts_immediately():
    sim = healthy_sim()
    sim.sim_two.dns_healthy = False
    sim.report_both(2)
    assert sim.cluster.status == "DEGRADED"
    assert outbox_types(sim) == {"pihole.cluster.degraded": 1}
