"""P4 on PostgreSQL: ownership notifications stay single under concurrent coordinators.

Several coordinator passes (separate sessions and connections, as separate
workers or Kaya processes would use) confirm and later clear the same
persisting VIP/DHCP mismatch at once.  The per-cluster advisory lock must
yield exactly one confirmation, one notification, one resolution and one
"restored" notification.  Synthetic data only.
"""

from __future__ import annotations

import threading
from datetime import timedelta

from app.models.models import HACluster, HAEvent, NotificationOutbox
from app.services.ha_ownership_alerts import MISMATCH_CONFIRM_SECONDS
from app.services.ha_watchdog import reconcile_cluster
from test_ha_p2a_coordination_postgres import WORKERS, gate, pg, pytestmark, run_parallel, split_cluster  # noqa: F401


def coordinator_passes(factory, cluster_id: int, barrier: threading.Barrier):
    def one():
        db = factory()
        try:
            cluster = db.get(HACluster, cluster_id)
            gate(barrier)
            reconcile_cluster(db, cluster)
        finally:
            db.close()

    return [one for _ in range(WORKERS)]


def count(factory, cluster_id: int, model, **filters) -> int:
    db = factory()
    try:
        query = db.query(model)
        if model is HAEvent:
            query = query.filter(HAEvent.cluster_id == cluster_id)
        for key, value in filters.items():
            query = query.filter(getattr(model, key) == value)
        return query.count()
    finally:
        db.close()


def test_concurrent_coordinators_confirm_and_resolve_a_mismatch_once(pg):  # noqa: F811 (imported fixture)
    factory, _admin = pg
    db, sim = split_cluster(factory)
    cluster_id = sim.cluster.id
    sim.cluster.ownership_mismatch_since = sim.cluster.ownership_mismatch_since - timedelta(seconds=MISMATCH_CONFIRM_SECONDS + 1)
    db.commit()

    errors = run_parallel(*coordinator_passes(factory, cluster_id, threading.Barrier(WORKERS)))
    assert errors == []
    assert count(factory, cluster_id, HAEvent, event_type="ownership_mismatch_confirmed") == 1
    assert count(factory, cluster_id, NotificationOutbox, event_type="pihole.ownership.mismatch") == 1

    # Ownership becomes consistent (DHCP follows the VIP); every coordinator sees it at once.
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = True, False
    sim.report_both(2)
    errors = run_parallel(*coordinator_passes(factory, cluster_id, threading.Barrier(WORKERS)))
    assert errors == []
    assert count(factory, cluster_id, HAEvent, event_type="ownership_mismatch_resolved") == 1
    assert count(factory, cluster_id, NotificationOutbox, event_type="pihole.ownership.recovered") == 1
    assert count(factory, cluster_id, NotificationOutbox, event_type="pihole.ownership.mismatch") == 1
    db.close()


def test_concurrent_coordinators_start_one_keepalived_restoration(pg, monkeypatch):  # noqa: F811 (imported fixture)
    """P5: a recorded preempt grant is restored once, even with several coordinators at once."""
    from uuid import uuid4

    from ha_simulation import hal_like_cluster

    from app.services import ha_keepalived_baseline as baseline

    factory, _admin = pg
    db = factory(expire_on_commit=False)
    sim = hal_like_cluster(db, maintenance_mode=False, suffix=uuid4().hex[:8])
    sim.report_both(2)
    baseline.record_preemption(sim.cluster, sim.one, reason="reinitialisation")
    db.commit()
    generation, cluster_id = sim.cluster.keepalived_generation, sim.cluster.id
    monkeypatch.setattr(baseline, "restoration_enabled", lambda: True)
    errors = run_parallel(*coordinator_passes(factory, cluster_id, threading.Barrier(WORKERS)))
    assert errors == []
    check = factory()
    try:
        cluster = check.get(HACluster, cluster_id)
        assert cluster.keepalived_generation == generation + 1
        assert baseline.outstanding(cluster)["state"] == "RESTORING_STANDBY"
    finally:
        check.close()
    assert count(factory, cluster_id, HAEvent, event_type="keepalived_restoration_started") == 1
    db.close()
