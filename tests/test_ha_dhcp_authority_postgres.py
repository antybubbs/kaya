"""PostgreSQL: concurrent coordinator passes start exactly one DHCP handover and move authority once.

DHCP handover PROPOSAL.  Watchdog passes and both nodes' heartbeats evaluate the same unplanned
Virtual IP move at the same instant; the per-cluster coordination lock must let exactly one of them
start the handover, so DHCP authority advances by exactly one epoch and only one promotion is ever
offered.  Throw-away schema; synthetic data only.
"""

from __future__ import annotations

import json
import threading
from datetime import timedelta
from uuid import uuid4

from app.models.models import HACluster, HAFailoverRun, HANode
from app.services import ha_dhcp_handover, ha_evaluation_queue
from app.services.ha_agents import record_heartbeat
from app.services.ha_dhcp_authority import authority
from app.services.ha_watchdog import drain_evaluations, evaluate_cluster, reconcile_cluster
from ha_simulation import hal_like_cluster, heartbeat_for
from test_ha_dhcp_handover_protocol import AGENT, stage_snapshot
from test_ha_p2a_coordination_postgres import WORKERS, gate, pg, pytestmark, run_parallel  # noqa: F401


def _report(db, sim, *, evaluate=True):
    for simnode, node in ((sim.sim_one, sim.one), (sim.sim_two, sim.two)):
        beat = heartbeat_for(simnode, observed_generation=sim.cluster.role_generation).model_copy(update={"agent_version": AGENT})
        record_heartbeat(db, node, beat)
    if evaluate:
        drain_evaluations(db)
    else:
        ha_evaluation_queue.take_pending()  # the concurrent workers below make the decision, not the setup


def test_concurrent_coordinator_passes_start_one_handover_and_move_authority_once(pg, monkeypatch):  # noqa: F811
    factory, _admin = pg
    db = factory(expire_on_commit=False)
    try:
        cluster_id, one_id, two_id, before, sim = _prepare(db)
    finally:
        db.close()
    beats = {one_id: heartbeat_for(sim.sim_one), two_id: heartbeat_for(sim.sim_two)}
    _race(factory, monkeypatch, cluster_id, one_id, two_id, beats, before, sim)


def _prepare(db):
    sim = hal_like_cluster(db, maintenance_mode=False, automatic_failover=True, suffix=uuid4().hex[:8])
    stage_snapshot(sim, sim.one, sim.two)  # loop-b holds a verified snapshot of the holder's leases
    _report(db, sim)
    _report(db, sim)
    before = authority(db.get(HACluster, sim.cluster.id))
    assert before is not None and before["node_id"] == sim.one.public_id
    sim.vrrp.stop("SimPiHole1")
    sim.sim_one.dhcp_running = False  # verified release (the stop hook released DHCP)
    _report(db, sim, evaluate=False)
    _report(db, sim, evaluate=False)
    for node in (sim.one, sim.two):
        if node.vip_stable_since:
            node.vip_stable_since -= timedelta(seconds=30)
    db.commit()
    cluster_id, one_id, two_id = sim.cluster.id, sim.one.id, sim.two.id
    assert db.query(HAFailoverRun).filter(HAFailoverRun.cluster_id == cluster_id).count() == 0
    return cluster_id, one_id, two_id, before, sim


def _race(factory, monkeypatch, cluster_id, one_id, two_id, beats, before, sim):

    barrier = threading.Barrier(WORKERS)
    local = threading.local()
    real = ha_dhcp_handover.handover_assessment

    def gated(cluster, *, now=None):
        if not getattr(local, "waited", False):
            local.waited = True
            gate(barrier)
        return real(cluster, now=now)

    monkeypatch.setattr(ha_dhcp_handover, "handover_assessment", gated)

    def watchdog():
        session = factory()
        try:
            reconcile_cluster(session, session.get(HACluster, cluster_id))
        finally:
            session.close()

    def heartbeat(node_id):
        def inner():
            session = factory()
            try:
                record_heartbeat(session, session.get(HANode, node_id),
                                 beats[node_id].model_copy(update={"agent_version": AGENT}))
                # What the evaluation queue's worker runs for this heartbeat (the queue itself is in-process).
                evaluate_cluster(session, session.get(HACluster, cluster_id), reporting_node_id=node_id)
            finally:
                session.close()
        return inner

    assert run_parallel(*([watchdog] * (WORKERS - 2)), heartbeat(one_id), heartbeat(two_id)) == []

    check = factory()
    try:
        cluster = check.get(HACluster, cluster_id)
        runs = check.query(HAFailoverRun).filter(HAFailoverRun.cluster_id == cluster_id).all()
        kinds = [json.loads(run.report_json or "{}").get("transition_kind") for run in runs]
        assert kinds == ["AUTOMATIC_DHCP_HANDOVER"], kinds  # exactly one handover
        after = authority(cluster)
        assert after["node_id"] == sim.two.public_id and after["epoch"] == before["epoch"] + 1  # moved exactly once
    finally:
        check.close()
