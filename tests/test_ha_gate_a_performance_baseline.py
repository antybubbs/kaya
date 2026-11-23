"""Gate A: performance baseline for HA heartbeat paths, preserving C1.

Counts SQL statements and ORM-materialised lease snapshots (C1's concern) for:
  * a steady healthy heartbeat,
  * a heartbeat during the ownership mismatch (full reconciliation chain),
  * ``desired_state`` for both nodes.
The bounds are the values measured at Gate A (2026-11-04) so Gate B cannot
silently regress them; a lower count is always acceptable.  Wall-clock time is
recorded for information only because container timing is not deterministic.

Synthetic data only; PostgreSQL runs only with KAYA_TEST_POSTGRES_URL.
"""

from __future__ import annotations

import json
import time

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.models.models import HACluster, HALeaseSnapshot, HANode
from app.services.ha_agents import desired_state, record_heartbeat
from ha_simulation import hal_like_cluster, heartbeat_for
from test_ha_lease_snapshot_queries import engine, seed  # noqa: F401  (engine is a pytest fixture)

SNAPSHOT_HISTORY = 200
# Statement counts per scenario and backend.  Gate A measured 26 / 23 / 6 for a
# heartbeat request that also made every HA decision inline; P2A raised that to
# 30 / 27 on PostgreSQL (coordination lock and re-read).  From P2B a heartbeat
# request only records and signals; the decisions run in the coordinator, so
# both parts are bounded, and so is their total, which must not exceed P2A's
# inline heartbeat (total workload must not simply move elsewhere).
STATEMENT_BOUNDS = {
    "steady_heartbeat": {"sqlite": 5, "postgresql": 5},
    "steady_evaluation": {"sqlite": 19, "postgresql": 21},
    "mismatch_heartbeat": {"sqlite": 5, "postgresql": 5},
    "mismatch_evaluation": {"sqlite": 16, "postgresql": 18},
    "desired_state_both": {"sqlite": 6, "postgresql": 6},
}
P2A_INLINE_HEARTBEAT = {"steady": {"sqlite": 28, "postgresql": 30}, "mismatch": {"sqlite": 25, "postgresql": 27}}


@pytest.fixture
def measured(engine):  # noqa: F811
    statements: list[str] = []
    snapshots: list[HALeaseSnapshot] = []

    def on_statement(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    def on_load(target, context):
        snapshots.append(target)

    event.listen(engine, "before_cursor_execute", on_statement)
    event.listen(HALeaseSnapshot, "load", on_load)
    yield engine, statements, snapshots
    event.remove(engine, "before_cursor_execute", on_statement)
    event.remove(HALeaseSnapshot, "load", on_load)


def measure(statements, snapshots, operation):
    statements.clear()
    snapshots.clear()
    started = time.perf_counter()
    operation()
    return {"statements": len(statements), "snapshots_loaded": len(snapshots), "milliseconds": round((time.perf_counter() - started) * 1000, 1)}


def per_request(bound_engine, operation):
    """Mirror production: a fresh SessionLocal-style session per request."""
    def run():
        session = Session(bound_engine, autoflush=False)  # production default expire_on_commit=True
        try:
            operation(session)
        finally:
            session.close()
    return run


def test_heartbeat_and_desired_state_baseline_preserves_c1(measured):
    from app.services.ha_watchdog import run_pending_evaluations

    bound_engine, statements, snapshots = measured
    backend = bound_engine.dialect.name
    db = Session(bound_engine, expire_on_commit=False)
    sim = hal_like_cluster(db, suffix=f"perf-{backend}")
    seed(db, sim.cluster.id, sim.one.id, sim.two.id, generations=range(1, SNAPSHOT_HISTORY + 1), state_status=None)
    sim.report_both(2)
    one_id, two_id, cluster_id = sim.one.id, sim.two.id, sim.cluster.id
    db.close()

    def heartbeat(node_id, sim_node):
        return per_request(bound_engine, lambda session: record_heartbeat(session, session.get(HANode, node_id), heartbeat_for(sim_node)))

    def evaluate():  # the production coordinator path: its own session per signalled cluster
        run_pending_evaluations(lambda: Session(bound_engine, autoflush=False))

    def desired(session):
        desired_state(session.get(HANode, one_id))
        desired_state(session.get(HANode, two_id))

    results = {"backend": backend, "snapshot_history": SNAPSHOT_HISTORY}
    results["steady_heartbeat"] = measure(statements, snapshots, heartbeat(two_id, sim.sim_two))
    results["steady_evaluation"] = measure(statements, snapshots, evaluate)
    sim.vrrp.stop("SimPiHole1")
    for node_id, sim_node in ((one_id, sim.sim_one), (two_id, sim.sim_two)):
        heartbeat(node_id, sim_node)()
        evaluate()
    sim.vrrp.start("SimPiHole1")
    for node_id, sim_node in ((one_id, sim.sim_one), (two_id, sim.sim_two)):
        heartbeat(node_id, sim_node)()
        evaluate()
    check = Session(bound_engine)
    try:
        assert check.get(HACluster, cluster_id).status == "DEGRADED"
    finally:
        check.close()
    results["mismatch_heartbeat"] = measure(statements, snapshots, heartbeat(two_id, sim.sim_two))
    results["mismatch_evaluation"] = measure(statements, snapshots, evaluate)
    results["desired_state_both"] = measure(statements, snapshots, per_request(bound_engine, desired))
    for phase in ("steady", "mismatch"):
        results[f"{phase}_total"] = results[f"{phase}_heartbeat"]["statements"] + results[f"{phase}_evaluation"]["statements"]
    print("GATE-A-BASELINE " + json.dumps(results, sort_keys=True))

    for scenario, bounds in STATEMENT_BOUNDS.items():
        # C1: no path may materialise the lease-snapshot history.
        assert results[scenario]["snapshots_loaded"] <= 1, (scenario, results[scenario])
        assert results[scenario]["statements"] <= bounds[backend], (scenario, results[scenario])
    for phase, bounds in P2A_INLINE_HEARTBEAT.items():
        assert results[f"{phase}_total"] <= bounds[backend], (phase, results[f"{phase}_total"])
