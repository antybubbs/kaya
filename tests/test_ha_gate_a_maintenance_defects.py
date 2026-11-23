"""Gate A: maintenance-workflow behaviour during a VIP/DHCP ownership split.

Unlike the existing REINITIALISE split tests, the deadlock reproduction here
uses the REAL ``reconcile_cluster_leases`` so lease-staging authority is not
mocked away.  Only Pi-hole HTTP reads (``_live_configuration``) and sync-plan
creation are replaced by synthetic stand-ins; no network is contacted.

``xfail(strict=True)`` tests assert desired invariants for known defects.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.models.models import HAMaintenanceRun, HASyncRun
from app.services.ha_keepalived import desired_keepalived_action
from app.services.ha_maintenance import advance_reinitialisation, desired_maintenance_action, start_reinitialisation
from ha_simulation import hal_like_cluster, ownership_snapshot, sqlite_session

SYNTHETIC_CONFIG = {"dns": {"upstreams": ["192.0.2.53"], "domainNeeded": True}}


@pytest.fixture
def offline_pihole(monkeypatch):
    """Replace Pi-hole HTTP reads and plan creation with synthetic, IN_SYNC results."""
    calls = {"live": 0, "plans": 0}

    def live_configuration(node):
        calls["live"] += 1
        return None, dict(SYNTHETIC_CONFIG)

    def create_sync_plan(db, cluster, user):
        calls["plans"] += 1
        source = next(node for node in cluster.nodes if node.id == cluster.authoritative_node_id)
        target = next(node for node in cluster.nodes if node.id != source.id)
        run = HASyncRun(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="IN_SYNC",
                        plan_json='{"groups":[]}', completed_at=datetime.utcnow())
        db.add(run)
        db.flush()
        return run

    monkeypatch.setattr("app.services.ha_maintenance._live_configuration", live_configuration)
    monkeypatch.setattr("app.services.ha_maintenance.create_sync_plan", create_sync_plan)
    return calls


def split_cluster():
    """Post-incident state: VIP on node two, DHCP on node one, latch-free start."""
    sim = hal_like_cluster(sqlite_session())
    sim.report_both(2)
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_one)
    sim.report(sim.sim_two)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(2)
    assert "OWNERSHIP_MISMATCH" in ownership_snapshot(sim)["issues"]
    return sim


def drive(sim, run: HAMaintenanceRun, limit: int = 12) -> HAMaintenanceRun:
    """Fresh signed reports after the run starts, then advance until it stops moving."""
    for _ in range(limit):
        if run.status != "RUNNING":
            break
        sim.report_both()  # heartbeats themselves also advance REINITIALISE today
        before = run.phase
        advance_reinitialisation(sim.db, run)
        if run.phase == before and run.status == "RUNNING" and run.phase not in {"WAITING_FOR_REPORTS"}:
            break
    return run


def test_d4_sole_dhcp_owner_no_longer_deadlocks_and_moves_no_dhcp(offline_pihole):
    """Fixed in P5 (was the 13:47 lease-staging deadlock).

    With the selected Active the verified sole DHCP owner, lease staging waits
    until it also holds the Virtual IP.  The run reaches the Virtual IP move;
    DHCP stays where it is and no DHCP action is issued.  End-to-end completion
    is covered in test_ha_p5_reinitialise_and_baseline.py.
    """
    sim = split_cluster()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    drive(sim, run)
    assert (run.status, run.phase) == ("RUNNING", "WAITING_FOR_VIP"), run.error_redacted
    assert sim.cluster.lease_replication.status != "BLOCKED"
    assert sim.sim_one.dhcp_running and not sim.sim_two.dhcp_running
    assert "preempt_delay" in desired_keepalived_action(sim.cluster, sim.one)["configuration"]
    assert "nopreempt" in desired_keepalived_action(sim.cluster, sim.two)["configuration"]
    assert desired_maintenance_action(sim.cluster, sim.one) is None and desired_maintenance_action(sim.cluster, sim.two) is None


def fail_while_waiting_for_vip(sim, run):
    """The runtime rebuild is never applied: the bounded wait fails the run safely."""
    drive(sim, run)
    assert run.phase == "WAITING_FOR_VIP", run.error_redacted
    run.phase_started_at = datetime.utcnow() - timedelta(seconds=181)
    sim.db.commit()
    advance_reinitialisation(sim.db, run)
    assert run.status == "FAILED_SAFE"
    return run


def test_d5_failed_safe_reinitialise_preserves_previous_authority(offline_pihole):
    sim = split_cluster()
    before = sim.cluster.authoritative_node_id
    assert before == sim.one.id
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.two, acknowledged=True)
    fail_while_waiting_for_vip(sim, run)
    assert sim.cluster.authoritative_node_id == before


def test_d6_failed_safe_reinitialise_preserves_configuration_baselines(offline_pihole):
    sim = split_cluster()
    sim.one.configuration_checksum = "a" * 64
    sim.two.configuration_checksum = "b" * 64
    sim.db.commit()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    fail_while_waiting_for_vip(sim, run)
    assert (sim.one.configuration_checksum, sim.two.configuration_checksum) == ("a" * 64, "b" * 64)


def test_d7_already_correct_reinitialise_never_reenables_automatic_failover_from_stale_state():
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False, automatic_failover=False)
    sim.report_both(2)
    stale = HAMaintenanceRun(
        cluster_id=sim.cluster.id, operation="REINITIALISE", status="FAILED_SAFE", phase="PAUSED",
        desired_active_node_id=sim.one.id, authoritative_node_id=sim.one.id,
        previous_state_json=json.dumps({"automatic_failover_enabled": True, "automatic_sync_enabled": False}),
        requested_by_user_id=sim.admin.id,
        created_at=datetime.utcnow() - timedelta(days=3), started_at=datetime.utcnow() - timedelta(days=3),
        completed_at=datetime.utcnow() - timedelta(days=3),
    )
    sim.db.add(stale)
    sim.db.commit()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    drive(sim, run)
    assert run.status == "SUCCEEDED"
    assert sim.cluster.automatic_failover_enabled is False


# ---------------------------------------------------------------------------
# nopreempt restoration (reuses the existing maintenance-test drivers, which
# stub lease staging; that is acceptable here because only Keepalived
# rendering is under test)
# ---------------------------------------------------------------------------


def _reinitialise_to_waiting_for_vip(monkeypatch):
    from test_high_availability_maintenance import database, drive_to_runtime_rebuild, pair

    db = database()
    user, cluster, first, second = pair(db, split=True)
    cluster.vrrp_router_id = 51  # synthetic VRRP settings the shared fixture omits
    first.vrrp_priority, second.vrrp_priority = 100, 150
    db.commit()
    run = start_reinitialisation(db, cluster, user, desired_active=first, authority=first, acknowledged=True)
    drive_to_runtime_rebuild(db, monkeypatch, run, first, second)
    advance_reinitialisation(db, run)
    assert run.phase == "WAITING_FOR_VIP", run.error_redacted
    pushed = desired_keepalived_action(cluster, first)["configuration"]
    assert "preempt_delay 3" in pushed and "nopreempt" not in pushed  # destination may preempt
    return db, run, cluster, first, second


def test_controlled_reinitialise_pushes_preempt_only_to_the_destination(monkeypatch):
    db, run, cluster, first, second = _reinitialise_to_waiting_for_vip(monkeypatch)
    assert "nopreempt" in desired_keepalived_action(cluster, second)["configuration"]
    db.close()


def test_d8_successful_reinitialise_records_and_restores_the_stable_baseline(monkeypatch):
    """Fixed in P5: the grant is recorded; restoration reaches the non-owner first (when enabled)."""
    from test_high_availability_maintenance import complete_runtime

    from app.services import ha_keepalived_baseline as baseline
    from app.services.ha_watchdog import reconcile_cluster

    db, run, cluster, first, second = _reinitialise_to_waiting_for_vip(monkeypatch)
    complete_runtime(db, run, first, second)
    assert run.status == "SUCCEEDED", run.error_redacted
    assert baseline.outstanding(cluster)["preempt_node_id"] == first.id
    cluster.keepalived_status = "DEPLOYED"  # as the agents' apply results record
    db.commit()
    monkeypatch.setattr(baseline, "restoration_enabled", lambda: True)
    reconcile_cluster(db, cluster)
    assert desired_keepalived_action(cluster, first) is None  # the Virtual IP owner waits
    restore = desired_keepalived_action(cluster, second)
    assert restore is not None and "nopreempt" in restore["configuration"]
    db.close()


def test_d9_failed_safe_after_vip_wait_records_and_restores_the_stable_baseline(monkeypatch):
    """Fixed in P5: the preempt-capable non-owner is restored first (when enabled)."""
    from app.services import ha_keepalived_baseline as baseline
    from app.services.ha_watchdog import reconcile_cluster

    db, run, cluster, first, second = _reinitialise_to_waiting_for_vip(monkeypatch)
    for node in (first, second):
        node.keepalived_status = "DEPLOYED"
        node.config_generation = cluster.keepalived_generation
        node.last_heartbeat_at = datetime.utcnow()
        node.dhcp_observed_at = node.last_heartbeat_at
    cluster.keepalived_status = "DEPLOYED"
    run.phase_started_at = datetime.utcnow() - timedelta(seconds=91)
    db.commit()
    advance_reinitialisation(db, run)
    assert run.status == "FAILED_SAFE"
    assert baseline.outstanding(cluster)["preempt_node_id"] == first.id
    monkeypatch.setattr(baseline, "restoration_enabled", lambda: True)
    reconcile_cluster(db, cluster)
    restore = desired_keepalived_action(cluster, first)  # first never took the VIP: it is the non-owner
    assert restore is not None and "nopreempt" in restore["configuration"]
    assert desired_keepalived_action(cluster, second) is None
    db.close()
