"""P4: truthful HA state, stable readiness and confirmed ownership notifications.

D1  The assigned ACTIVE node changes only through verified, authorised
    operations; the observed Virtual IP owner comes from fresh signed reports.
D2  Standby readiness follows current evidence: the sole DHCP owner is never a
    "recovering standby", unchanged evidence causes no transitions, a lease
    renewal does not reset readiness, and a stale or unhealthy standby is never
    shown as ready.
D3  A confirmed VIP/DHCP mismatch raises one actionable notification; genuine
    split-brain raises an urgent one; both deduplicate while they persist and
    resolve once when they clear; transient observations never notify.

Synthetic data only (RFC 5737 addresses, example.invalid accounts).
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from sqlalchemy import event
from starlette.requests import Request

from app.main import app
from app.models.models import HAEvent, HALeaseSnapshot, NotificationOutbox
from app.routers import high_availability as router
from app.services import ha_watchdog
from app.services.ha_assessment import assess_cluster
from app.services.ha_leases import LeasePlan, reconcile_cluster_leases
from app.services.ha_ownership_alerts import (
    MISMATCH_CONFIRM_SECONDS,
    SPLIT_BRAIN_CONFIRM_SECONDS,
    update_ownership_alerts,
)
from app.services.ha_recovery import evaluate_recovery, recovery_snapshot
from app.services.ha_topology import assigned_active_node, reconcile_topology
from ha_simulation import hal_like_cluster, sqlite_session

RECOVERY_EVENTS = {"node_offline", "node_recovered", "node_recovery_synchronising", "node_recovery_verifying",
                   "node_standby_ready", "node_active", "node_standby", "node_ownership_conflict"}


def healthy(automatic_failover: bool = False):
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False, automatic_failover=automatic_failover)
    sim.report_both(2)
    return sim


def incident():
    """4 November: Keepalived restarts on node one; the VIP moves, DHCP stays."""
    sim = healthy()
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_one)
    sim.report(sim.sim_two)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(3)
    return sim


def names(sim, ids):
    return sorted(node.display_name for node in (sim.one, sim.two) if node.id in set(ids))


def recovery_events(sim):
    return [row for row in sim.events() if row.event_type in RECOVERY_EVENTS]


def outbox(sim, event_type):
    return sim.db.query(NotificationOutbox).filter(NotificationOutbox.event_type == event_type).all()


def page_request(path: str) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request({"type": "http", "method": "GET", "scheme": "https", "path": path, "raw_path": path.encode(),
                    "query_string": b"", "headers": [], "client": ("198.51.100.2", 1234),
                    "server": ("kaya.example.com", 443), "session": {"csrf_token": "csrf"}, "app": app}, receive)


# --- D1: assigned versus observed --------------------------------------------------


def test_incident_keeps_the_assignment_and_shows_both_states():
    sim = incident()
    assert names(sim, reconcile_topology(sim.cluster).vip_owner_ids) == ["SimPiHole2"]
    assert sim.cluster.current_active_node_id == sim.one.id == assigned_active_node(sim.cluster).id
    finding = next(item for item in assess_cluster(sim.db, sim.cluster).findings if item.code == "OWNERSHIP_MISMATCH")
    observed = dict(finding.observations)
    assert observed["Assigned Active node"] == "SimPiHole1" and observed["Virtual IP reported by"] == "SimPiHole2"
    path = f"/high-availability/clusters/{sim.cluster.public_id}"
    body = router.cluster_detail(sim.cluster.public_id, page_request(path), db=sim.db, user=sim.admin).body.decode()
    assert 'data-ha-cluster-field="active_node">SimPiHole2<' in body
    assert "Assigned Active: SimPiHole1" in body


def test_verified_automatic_adoption_moves_the_assignment():
    sim = healthy(automatic_failover=True)
    sim.vrrp.stop("SimPiHole1")
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = True, False
    sim.report(sim.sim_one)
    sim.report(sim.sim_two)
    sim.report_both(2)
    assert sim.cluster.current_active_node_id == sim.two.id == assigned_active_node(sim.cluster).id
    assert sim.events("automatic_failover_reconciled")


def test_a_pointer_left_by_the_previous_behaviour_realigns_with_the_assignment():
    sim = healthy()
    sim.cluster.current_active_node_id = sim.two.id  # as an unverified VIP move used to leave it
    sim.db.commit()
    ha_watchdog.reconcile_cluster(sim.db, sim.cluster)  # the periodic pass, even with no heartbeat signal
    assert sim.cluster.current_active_node_id == sim.one.id


def test_no_vip_owner_or_two_owners_never_clear_the_assignment():
    sim = healthy()
    sim.vrrp.partition()
    sim.report_both(2)
    assert len(reconcile_topology(sim.cluster).vip_owner_ids) == 2
    assert sim.cluster.current_active_node_id == sim.one.id


# --- D2: stable, truthful readiness -------------------------------------------------


def test_the_sole_dhcp_owner_is_an_ownership_conflict_not_a_recovering_standby():
    sim = incident()
    assert sim.one.recovery_state == "OWNERSHIP_CONFLICT"
    assert not sim.events("node_recovered")
    assert len(sim.events("node_ownership_conflict")) == 1
    before = len(recovery_events(sim))
    sim.report_both(5)
    assert len(recovery_events(sim)) == before  # the persisting condition causes no further transitions


def test_unchanged_evidence_causes_no_recovery_transitions():
    sim = healthy()
    before = len(recovery_events(sim))
    sim.report_both(10)
    assert len(recovery_events(sim)) == before
    assert sim.two.recovery_state == "STANDBY_READY"


def test_a_stale_standby_is_never_shown_ready_even_between_evaluations():
    sim = healthy()
    assert recovery_snapshot(sim.db, sim.cluster)[sim.two.id].ready
    sim.two.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=10)
    sim.db.commit()
    snapshot = recovery_snapshot(sim.db, sim.cluster)[sim.two.id]
    assert sim.two.recovery_state == "STANDBY_READY"  # stored state not yet re-evaluated
    assert snapshot.state == "OFFLINE" and not snapshot.ready
    assert evaluate_recovery(sim.db, sim.cluster)[sim.two.id].state == "OFFLINE"


def test_an_unhealthy_standby_is_never_shown_ready():
    sim = healthy()
    sim.two.dns_healthy = False
    sim.db.commit()
    snapshot = recovery_snapshot(sim.db, sim.cluster)[sim.two.id]
    assert snapshot.state == "RECOVERING" and not snapshot.ready


def lease_plan(sim, expires: int) -> LeasePlan:
    lease = {"expires": expires, "hwaddr": "02:00:00:00:00:31", "ip": "192.0.2.60", "name": "synthetic-client", "clientid": ""}
    return LeasePlan(True, sim.one.id, sim.one.public_id, sim.two.id, [lease], set(),
                     ipaddress.IPv4Address("192.0.2.20"), ipaddress.IPv4Address("192.0.2.200"),
                     sim.cluster.role_generation, sim.cluster.keepalived_generation, sim.cluster.cluster_generation)


def stage(sim, generation: int) -> None:
    state = sim.cluster.lease_replication
    state.applied_generation, state.status = generation, "CURRENT"
    sim.two.lease_generation = generation
    for snapshot in sim.db.query(HALeaseSnapshot).filter(HALeaseSnapshot.generation == generation):
        snapshot.status = "STAGED"
    sim.db.commit()


def test_a_lease_renewal_causes_no_recovery_transition():
    sim = healthy()
    first = reconcile_cluster_leases(sim.db, sim.cluster, precomputed_inspection=lease_plan(sim, 2_000_000_000))
    stage(sim, first.desired_generation)
    evaluate_recovery(sim.db, sim.cluster, stability_seconds=0)
    assert sim.two.recovery_state == "STANDBY_READY"
    before = len(recovery_events(sim))
    reconcile_cluster_leases(sim.db, sim.cluster, precomputed_inspection=lease_plan(sim, 2_000_003_600))
    evaluate_recovery(sim.db, sim.cluster, stability_seconds=0)
    assert sim.two.recovery_state == "STANDBY_READY"
    assert len(recovery_events(sim)) == before


# --- D3: confirmed, deduplicated notifications -----------------------------------------


def confirmed(sim, kind):
    return sim.events(f"{kind}_confirmed")


def age(sim, kind, seconds):
    """The condition has persisted for ``seconds`` (reports stay fresh)."""
    attribute = f"{kind}_since"
    setattr(sim.cluster, attribute, getattr(sim.cluster, attribute) - timedelta(seconds=seconds))
    sim.db.commit()


def test_a_transient_mismatch_never_notifies():
    sim = healthy(automatic_failover=False)
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_one)
    sim.report(sim.sim_two)
    assert sim.cluster.ownership_mismatch_since is not None
    # DHCP follows the VIP before the condition is confirmed (a normal hand-over).
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = True, False
    sim.report_both(2)
    assert sim.cluster.ownership_mismatch_since is None
    assert not outbox(sim, "pihole.ownership.mismatch") and not confirmed(sim, "ownership_mismatch")
    assert not outbox(sim, "pihole.ownership.recovered")


def test_a_confirmed_mismatch_notifies_once_then_resolves_once():
    sim = incident()
    age(sim, "ownership_mismatch", MISMATCH_CONFIRM_SECONDS - 5)
    update_ownership_alerts(sim.db, sim.cluster)
    assert not outbox(sim, "pihole.ownership.mismatch")  # not yet confirmed
    age(sim, "ownership_mismatch", 10)
    for _ in range(4):
        update_ownership_alerts(sim.db, sim.cluster)
        sim.report_both(1)  # later heartbeats re-evaluate the persisting condition
    [notification] = outbox(sim, "pihole.ownership.mismatch")
    assert len(confirmed(sim, "ownership_mismatch")) == 1
    assert "SimPiHole2 holds the virtual IP but DHCP is served by SimPiHole1" in notification.message
    assert "Assigned Active: SimPiHole1" in notification.message
    assert not outbox(sim, "pihole.ownership.split_brain")
    # The administrator resolves it; the condition clears once.
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = True, False
    sim.report_both(3)
    assert sim.cluster.ownership_mismatch_since is None
    assert len(sim.events("ownership_mismatch_resolved")) == 1
    assert len(outbox(sim, "pihole.ownership.recovered")) == 1


def test_split_brain_is_urgent_and_deduplicated():
    sim = healthy()
    sim.vrrp.partition()
    sim.report_both(2)
    assert sim.cluster.split_brain_since is not None and sim.cluster.ownership_mismatch_since is None
    age(sim, "split_brain", SPLIT_BRAIN_CONFIRM_SECONDS + 1)
    for _ in range(3):
        update_ownership_alerts(sim.db, sim.cluster)
        sim.report_both(1)
    [notification] = outbox(sim, "pihole.ownership.split_brain")
    assert "Both SimPiHole1 and SimPiHole2 report the virtual IP" in notification.message
    [event_row] = confirmed(sim, "split_brain")
    assert event_row.severity == "critical"
    assert not outbox(sim, "pihole.ownership.mismatch")


def test_a_new_episode_after_resolution_notifies_again():
    sim = incident()
    age(sim, "ownership_mismatch", MISMATCH_CONFIRM_SECONDS + 1)
    update_ownership_alerts(sim.db, sim.cluster)
    for row in outbox(sim, "pihole.ownership.mismatch"):
        row.status = "sent"  # delivered by the notification worker
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = True, False
    sim.report_both(2)
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = False, True
    sim.report_both(2)
    age(sim, "ownership_mismatch", MISMATCH_CONFIRM_SECONDS + 1)
    update_ownership_alerts(sim.db, sim.cluster)
    assert len(outbox(sim, "pihole.ownership.mismatch")) == 2
    assert len(confirmed(sim, "ownership_mismatch")) == 2


def test_the_periodic_pass_confirms_without_a_heartbeat():
    sim = incident()
    sim.cluster.ownership_mismatch_since = datetime.utcnow() - timedelta(seconds=MISMATCH_CONFIRM_SECONDS + 5)
    sim.db.commit()
    ha_watchdog.reconcile_cluster(sim.db, sim.cluster)
    assert len(outbox(sim, "pihole.ownership.mismatch")) == 1


def test_consistent_ownership_costs_no_queries():
    sim = healthy()
    reconcile_topology(sim.cluster)  # nodes already loaded, as in the coordinator
    statements = []
    listener = lambda *args: statements.append(1)  # noqa: E731
    engine = sim.db.get_bind()
    event.listen(engine, "before_cursor_execute", listener)
    try:
        for _ in range(5):
            update_ownership_alerts(sim.db, sim.cluster)
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert statements == []
    assert not sim.db.query(HAEvent).filter(HAEvent.event_type.like("%_confirmed")).count()


def test_losing_sight_of_the_nodes_never_resolves_an_alert():
    sim = incident()
    age(sim, "ownership_mismatch", MISMATCH_CONFIRM_SECONDS + 1)
    update_ownership_alerts(sim.db, sim.cluster)
    assert len(outbox(sim, "pihole.ownership.mismatch")) == 1
    later = datetime.utcnow() + timedelta(minutes=10)  # every report is now stale
    update_ownership_alerts(sim.db, sim.cluster, now=later)
    assert sim.cluster.ownership_mismatch_since is not None
    assert not sim.events("ownership_mismatch_resolved") and not outbox(sim, "pihole.ownership.recovered")
