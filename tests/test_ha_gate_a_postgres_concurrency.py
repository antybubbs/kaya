"""Gate A: PostgreSQL concurrency characterisation for HA control paths.

Runs only when KAYA_TEST_POSTGRES_URL points at a disposable database.  Each
test uses its own throw-away schema.  Threads are synchronised with barriers
so the interleaving is deterministic rather than timing-dependent.  A barrier
timeout (for example once Gate B adds row locking) is treated as "the second
caller was serialised", which is the desired behaviour.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.models import HACluster, HAEvent, HAMaintenanceRun, HANode, HASyncRun
from app.services import ha_maintenance, ha_recovery
from app.services.ha_agents import record_heartbeat
from app.services.ha_maintenance import advance_reinitialisation
from app.services.ha_recovery import evaluate_recovery
from ha_simulation import hal_like_cluster, heartbeat_for, SimNode

POSTGRES_URL = os.environ.get("KAYA_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="KAYA_TEST_POSTGRES_URL is not configured")


@pytest.fixture
def factory():
    schema = f"kaya_gatea_{uuid4().hex[:10]}"
    admin = create_engine(POSTGRES_URL)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(POSTGRES_URL, connect_args={"options": f"-c search_path={schema}"}, pool_size=5)
    Base.metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine)
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def seed(factory, **kwargs) -> dict:
    db = factory()
    sim = hal_like_cluster(db, suffix=uuid4().hex[:8], **kwargs)
    ids = {"cluster": sim.cluster.id, "one": sim.one.id, "two": sim.two.id, "admin": sim.admin.id}
    db.close()
    return ids


def run_parallel(*targets, timeout: float = 20.0) -> list[BaseException]:
    errors: list[BaseException] = []

    def wrap(target):
        try:
            target()
        except BaseException as exc:  # surfaced to the test
            errors.append(exc)

    threads = [threading.Thread(target=wrap, args=(target,)) for target in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout)
        assert not thread.is_alive(), "worker thread hung"
    return errors


def wait(barrier: threading.Barrier) -> None:
    try:
        barrier.wait(timeout=3)
    except threading.BrokenBarrierError:
        pass  # the peer was serialised behind a lock: desired behaviour


def test_concurrent_heartbeats_from_both_nodes_converge_on_the_mismatch(factory):
    """P2B: heartbeats record concurrently; racing coordinator evaluations converge."""
    from app.services.ha_watchdog import evaluate_cluster

    ids = seed(factory)
    one = SimNode("SimPiHole1", "192.0.2.2", 150, vrrp_state="BACKUP", dhcp_running=True, report_sequence=10)
    two = SimNode("SimPiHole2", "192.0.2.8", 100, vrrp_state="MASTER", dhcp_running=False, report_sequence=10)

    def beat(node_id, sim):
        def inner():
            db = factory()
            try:
                record_heartbeat(db, db.get(HANode, node_id), heartbeat_for(sim))
            finally:
                db.close()
        return inner

    def evaluate():
        db = factory()
        try:
            evaluate_cluster(db, db.get(HACluster, ids["cluster"]))
        finally:
            db.close()

    assert run_parallel(beat(ids["one"], one), beat(ids["two"], two)) == []
    assert run_parallel(evaluate, evaluate) == []
    evaluate()  # whichever evaluator was turned away is covered by the next evaluation
    db = factory()
    try:
        cluster = db.get(HACluster, ids["cluster"])
        assert cluster.status == "DEGRADED"
        assert {node.display_name: (node.vip_owned, node.dhcp_running) for node in cluster.nodes} == {
            "SimPiHole1": (False, True),
            "SimPiHole2": (True, False),
        }
    finally:
        db.close()


def test_d13_concurrent_reinitialise_advancement_backs_up_once(factory, monkeypatch):
    ids = seed(factory)
    db = factory()
    run = HAMaintenanceRun(cluster_id=ids["cluster"], operation="REINITIALISE", status="RUNNING", phase="BACKING_UP",
                           desired_active_node_id=ids["one"], authoritative_node_id=ids["one"],
                           requested_by_user_id=ids["admin"], started_at=datetime.utcnow(), phase_started_at=datetime.utcnow())
    db.add(run)
    db.commit()
    run_id = run.id
    db.close()
    barrier = threading.Barrier(2)
    calls = []

    def backups(db, run):
        wait(barrier)
        calls.append(run.id)
        sync = HASyncRun(cluster_id=run.cluster_id, source_node_id=ids["one"], target_node_id=ids["two"], status="IN_SYNC",
                         plan_json='{"groups":[]}', completed_at=datetime.utcnow())
        db.add(sync)
        db.flush()
        run.sync_run_id = sync.id
        db.commit()
        return sync

    monkeypatch.setattr(ha_maintenance, "_create_two_node_backups", backups)

    def advance():
        session = factory()
        try:
            advance_reinitialisation(session, session.get(HAMaintenanceRun, run_id))
        finally:
            session.close()

    assert run_parallel(advance, advance) == []
    assert len(calls) == 1


def test_d14_concurrent_recovery_evaluation_emits_one_transition_event(factory, monkeypatch):
    ids = seed(factory)
    db = factory()
    db.get(HANode, ids["two"]).dns_healthy = False  # standby must leave STANDBY_READY
    db.commit()
    db.close()
    barrier = threading.Barrier(2)
    local = threading.local()
    real_checks = ha_recovery.recovery_checks

    def gated_checks(db, cluster, node, *, now=None):
        if not getattr(local, "waited", False):
            local.waited = True
            wait(barrier)
        return real_checks(db, cluster, node, now=now)

    monkeypatch.setattr(ha_recovery, "recovery_checks", gated_checks)

    def evaluate():
        session = factory()
        try:
            evaluate_recovery(session, session.get(HACluster, ids["cluster"]))
        finally:
            session.close()

    assert run_parallel(evaluate, evaluate) == []
    db = factory()
    events = db.query(HAEvent).filter(HAEvent.node_id == ids["two"], HAEvent.event_type == "node_recovered").count()
    db.close()
    assert events == 1
