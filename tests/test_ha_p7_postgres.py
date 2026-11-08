"""P7 on PostgreSQL: concurrent approvals of one Keepalived baseline restoration.

Separate sessions stand in for separate request workers.  The per-cluster
coordination lock and the fingerprint must let exactly one administrator start
the attempt (exactly one new Keepalived generation).  Synthetic data only.
"""

from __future__ import annotations

import threading
from uuid import uuid4

from app.models.models import AuditLog, HACluster, User
from app.services.ha_alignment import MOVE_TIMEOUT_SECONDS
from app.services.ha_baseline_repair import HABaselineRepairError, approve_restoration, restoration_preview
from app.services.ha_keepalived_baseline import outstanding
from app.services.ha_maintenance import acknowledge_failed_safe_latch
from test_ha_p2a_coordination_postgres import WORKERS, gate, pg, pytestmark, run_parallel  # noqa: F401
from test_ha_p6_align_ownership import age_phase, cycle, mismatch, report, start, to_phase


def test_concurrent_administrators_start_exactly_one_restoration(pg):  # noqa: F811 (imported fixture)
    factory, _admin = pg
    db = factory(expire_on_commit=False)
    try:
        sim = mismatch(db=db, suffix=uuid4().hex[:8])
        run = start(sim)
        to_phase(sim, run, "MOVING_VIP")
        cycle(sim, run, vrrp_moves=False)
        age_phase(sim, run, MOVE_TIMEOUT_SECONDS + 1)
        cycle(sim, run, vrrp_moves=False)
        report(sim)
        acknowledge_failed_safe_latch(db, sim.cluster, sim.admin)
        preview = restoration_preview(db, sim.cluster)
        assert preview.allowed, preview.blockers
        cluster_id, admin_id, fingerprint, name = sim.cluster.id, sim.admin.id, preview.fingerprint, sim.cluster.name
        generation = sim.cluster.keepalived_generation
        barrier = threading.Barrier(WORKERS)
        outcomes: list[str] = []

        def administrator():
            session = factory()
            try:
                cluster = session.get(HACluster, cluster_id)
                user = session.get(User, admin_id)
                gate(barrier)
                try:
                    approve_restoration(session, cluster, user, fingerprint=fingerprint, confirmation=name, acknowledged=True,
                                        latch_authorised=True, wait_seconds=2.0)
                    outcomes.append("started")
                except HABaselineRepairError as exc:
                    outcomes.append(type(exc).__name__)
            finally:
                session.close()

        errors = run_parallel(*[administrator for _ in range(WORKERS)])
        assert errors == []
        assert outcomes.count("started") == 1, outcomes
        db.expire_all()
        cluster = db.get(HACluster, cluster_id)
        assert cluster.keepalived_generation == generation + 1
        assert outstanding(cluster)["state"] == "RESTORING_STANDBY" and outstanding(cluster)["attempts"] == 1
        assert db.query(AuditLog).filter(AuditLog.entity == "ha_keepalived_baseline", AuditLog.action == "approved").count() == 1
    finally:
        db.rollback()
        db.close()
