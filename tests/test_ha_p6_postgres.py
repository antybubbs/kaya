"""P6 on PostgreSQL: Align service ownership under concurrent administrators and coordinators.

Separate sessions and connections stand in for separate request workers,
coordinator workers and Kaya processes.  The per-cluster advisory lock must
let exactly one administrator start the repair, and concurrent coordinator
evaluations, periodic passes and heartbeats must advance it exactly once per
step: one Virtual IP move, one restoration, one completion.  Synthetic data only.
"""

from __future__ import annotations

import threading
from uuid import uuid4

from app.models.models import AuditLog, HACluster, HAEvent, HAMaintenanceRun, HANode
from app.services.ha_alignment import HAAlignmentError, advance_alignment, alignment_preview, start_alignment
from app.services.ha_watchdog import drain_evaluations, reconcile_cluster
from test_ha_p2a_coordination_postgres import WORKERS, gate, pg, pytestmark, run_parallel  # noqa: F401
from test_ha_p6_align_ownership import apply_keepalived, beat, mismatch, pairs, report


def count(factory, model, **filters) -> int:
    db = factory()
    try:
        query = db.query(model)
        for key, value in filters.items():
            query = query.filter(getattr(model, key) == value)
        return query.count()
    finally:
        db.close()


def test_concurrent_administrators_start_exactly_one_alignment(pg):  # noqa: F811 (imported fixture)
    factory, _admin = pg
    db = factory(expire_on_commit=False)
    try:
        _concurrent_administrators(factory, db)
    finally:
        db.rollback()
        db.close()


def _concurrent_administrators(factory, db):
    sim = mismatch(db=db, suffix=uuid4().hex[:8])
    preview = alignment_preview(db, sim.cluster)
    assert preview.allowed, preview.blockers
    cluster_id, admin_id, target, fingerprint, name = sim.cluster.id, sim.admin.id, preview.dhcp_owner.public_id, preview.fingerprint, sim.cluster.name
    barrier = threading.Barrier(WORKERS)
    outcomes: list[str] = []

    def administrator():
        session = factory()
        try:
            cluster = session.get(HACluster, cluster_id)
            from app.models.models import User

            user = session.get(User, admin_id)
            gate(barrier)
            try:
                start_alignment(session, cluster, user, target_public_id=target, fingerprint=fingerprint, confirmation=name,
                                acknowledged=True, latch_authorised=False, wait_seconds=2.0)
                outcomes.append("started")
            except HAAlignmentError as exc:
                outcomes.append(type(exc).__name__)
        finally:
            session.close()

    errors = run_parallel(*[administrator for _ in range(WORKERS)])
    assert errors == []
    assert outcomes.count("started") == 1, outcomes
    assert count(factory, HAMaintenanceRun, cluster_id=cluster_id, operation="ALIGN_OWNERSHIP") == 1
    assert count(factory, AuditLog, entity="ha_service_alignment", action="started") == 1


def test_concurrent_coordinators_and_heartbeats_advance_each_step_once(pg):  # noqa: F811 (imported fixture)
    factory, _admin = pg
    db = factory(expire_on_commit=False)
    try:
        _concurrent_coordinators(factory, db)
    finally:
        db.rollback()
        db.close()


def _concurrent_coordinators(factory, db):
    sim = mismatch(db=db, suffix=uuid4().hex[:8])
    preview = alignment_preview(db, sim.cluster)
    run = start_alignment(db, sim.cluster, sim.admin, target_public_id=preview.dhcp_owner.public_id, fingerprint=preview.fingerprint,
                          confirmation=sim.cluster.name, acknowledged=True, latch_authorised=False)
    drain_evaluations(db)
    cluster_id, run_id = sim.cluster.id, run.id
    generation = sim.cluster.keepalived_generation
    node_ids = {simnode.name: node.id for simnode, node in pairs(sim)}

    def callers():
        barrier = threading.Barrier(WORKERS)

        def coordinator():
            session = factory()
            try:
                current = session.get(HAMaintenanceRun, run_id)
                gate(barrier)
                advance_alignment(session, current)
            finally:
                session.close()

        def periodic():
            session = factory()
            try:
                cluster = session.get(HACluster, cluster_id)
                gate(barrier)
                reconcile_cluster(session, cluster)
            finally:
                session.close()

        def heartbeat(name):
            def inner():
                session = factory()
                try:
                    simnode = next(item for item, _node in pairs(sim) if item.name == name)
                    node = session.get(HANode, node_ids[name])
                    proxy = type("Proxy", (), {"db": session, "cluster": node.cluster, "offered": sim.offered})()
                    gate(barrier)
                    beat(proxy, simnode, node)
                finally:
                    session.close()
            return inner

        return [coordinator, coordinator, periodic, periodic, heartbeat("SimPiHole1"), heartbeat("SimPiHole2")]

    for _ in range(12):
        db.expire_all()
        current = db.get(HAMaintenanceRun, run_id)
        if current.status != "RUNNING":
            break
        apply_keepalived(sim)
        errors = run_parallel(*callers())
        assert errors == [], errors
        report(sim)  # one ordinary evaluation round as well
    db.expire_all()
    final = db.get(HAMaintenanceRun, run_id)
    assert final.status == "SUCCEEDED", final.error_redacted
    cluster = db.get(HACluster, cluster_id)
    assert cluster.keepalived_generation == generation + 2  # exactly one move and one restoration generation
    for event_type in ("service_alignment_started", "service_alignment_moving_vip", "service_ownership_aligned"):
        assert count(factory, HAEvent, cluster_id=cluster_id, event_type=event_type) == 1, event_type
    assert count(factory, AuditLog, entity="ha_service_alignment", action="complete") == 1
    assert not {"DHCP_PROMOTE", "DHCP_DEMOTE", "LEASE_SNAPSHOT_STAGE"} & set(sim.offered)
