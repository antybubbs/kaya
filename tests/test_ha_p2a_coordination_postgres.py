"""P2A: per-cluster PostgreSQL coordination of maintenance and recovery changes.

Proves, against a disposable PostgreSQL database, that concurrent heartbeats,
watchdog passes and administrator requests produce exactly one effective
advancement, with no duplicate external calls, events or audit rows; that the
coordination lock holds no row locks while a slow step runs; and that it is
released when its holder dies.  Each test uses a throw-away schema.  Pi-hole
access is replaced by synthetic stand-ins; no network is contacted.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.models import AuditLog, HABackup, HACluster, HAEvent, HAMaintenanceRun, HANode, HASyncRun
from app.services import ha_maintenance, ha_recovery
from app.services.ha_agents import record_heartbeat
from app.services.ha_coordination import ADVISORY_NAMESPACE, cluster_coordination
from app.services.ha_maintenance import PROCESS_STARTED_AT, advance_reinitialisation, reconcile_cluster_state, start_reconciliation
from app.services.ha_recovery import evaluate_recovery
from app.services.ha_watchdog import reconcile_cluster
from ha_simulation import hal_like_cluster, heartbeat_for

POSTGRES_URL = os.environ.get("KAYA_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="KAYA_TEST_POSTGRES_URL is not configured")
WORKERS = 6


@pytest.fixture
def pg():
    schema = f"kaya_p2a_{uuid4().hex[:10]}"
    admin = create_engine(POSTGRES_URL)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(POSTGRES_URL, connect_args={"options": f"-c search_path={schema}"}, pool_size=WORKERS + 2, max_overflow=WORKERS)
    Base.metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine), admin
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def run_parallel(*targets, timeout: float = 30.0) -> list[BaseException]:
    errors: list[BaseException] = []

    def wrap(target):
        try:
            target()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=wrap, args=(target,)) for target in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout)
        assert not thread.is_alive(), "worker thread hung"
    return errors


def gate(barrier: threading.Barrier) -> None:
    try:
        barrier.wait(timeout=2)
    except threading.BrokenBarrierError:
        pass  # the other workers were turned away by the coordination lock


def split_cluster(factory):
    """Post-incident topology: VIP on node two, DHCP on node one, maintenance latch held.

    The setup session keeps attributes after commit so ids stay readable once it closes.
    """
    db = factory(expire_on_commit=False)
    sim = hal_like_cluster(db, suffix=uuid4().hex[:8])
    sim.report_both(2)
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_one)
    sim.report(sim.sim_two)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(2)
    return db, sim


def counts(factory, cluster_id: int, *, event_type: str, audit_action: str, audit_entity: str) -> tuple[int, int]:
    db = factory()
    try:
        cluster = db.get(HACluster, cluster_id)
        events = db.query(HAEvent).filter(HAEvent.cluster_id == cluster_id, HAEvent.event_type == event_type).count()
        audits = db.query(AuditLog).filter(AuditLog.entity == audit_entity, AuditLog.action == audit_action, AuditLog.entity_id == cluster.public_id).count()
        return events, audits
    finally:
        db.close()


def mixed_callers(factory, sim, run_id):
    """Administrator route, watchdog pass and both nodes' heartbeats, as in production."""
    cluster_id, one_id, two_id = sim.cluster.id, sim.one.id, sim.two.id
    beats = {one_id: heartbeat_for(sim.sim_one), two_id: heartbeat_for(sim.sim_two)}

    def route():
        db = factory()
        try:
            advance_reinitialisation(db, db.get(HAMaintenanceRun, run_id))
        finally:
            db.close()

    def watchdog():
        db = factory()
        try:
            reconcile_cluster(db, db.get(HACluster, cluster_id))
        finally:
            db.close()

    def heartbeat(node_id):
        def inner():
            db = factory()
            try:
                record_heartbeat(db, db.get(HANode, node_id), beats[node_id])
            finally:
                db.close()
        return inner

    return [route, route, watchdog, watchdog, heartbeat(one_id), heartbeat(two_id)]


def test_concurrent_callers_fail_a_reinitialise_step_exactly_once(pg, monkeypatch):
    factory, _ = pg
    db, sim = split_cluster(factory)
    run = HAMaintenanceRun(cluster_id=sim.cluster.id, operation="REINITIALISE", status="RUNNING", phase="STAGING_DHCP",
                           desired_active_node_id=sim.one.id, authoritative_node_id=sim.one.id, requested_by_user_id=sim.admin.id,
                           started_at=datetime.utcnow(), phase_started_at=datetime.utcnow(), previous_state_json="{}", result_json="{}")
    db.add(run)
    db.commit()
    run_id, cluster_id = run.id, sim.cluster.id
    db.close()
    barrier = threading.Barrier(WORKERS)
    calls = []
    real = ha_maintenance.reconcile_cluster_leases

    def gated(db, cluster, **kwargs):
        calls.append(threading.get_ident())
        gate(barrier)
        return real(db, cluster, **kwargs)

    monkeypatch.setattr(ha_maintenance, "reconcile_cluster_leases", gated)
    assert run_parallel(*mixed_callers(factory, sim, run_id)) == []
    check = factory()
    final = check.get(HAMaintenanceRun, run_id)
    assert final.status == "FAILED_SAFE" and "cannot verify one safe VIP owner" in final.error_redacted
    check.close()
    assert len(calls) == 1
    assert counts(factory, cluster_id, event_type="cluster_reinitialisation_failed", audit_action="fail_safe", audit_entity="ha_cluster_reinitialisation") == (1, 1)


def test_concurrent_callers_run_backups_and_external_reads_once(pg, monkeypatch):
    factory, _ = pg
    db, sim = split_cluster(factory)
    run = HAMaintenanceRun(cluster_id=sim.cluster.id, operation="REINITIALISE", status="RUNNING", phase="BACKING_UP",
                           desired_active_node_id=sim.one.id, authoritative_node_id=sim.one.id, requested_by_user_id=sim.admin.id,
                           started_at=datetime.utcnow(), phase_started_at=datetime.utcnow(), previous_state_json="{}", result_json="{}")
    db.add(run)
    db.commit()
    run_id, cluster_id = run.id, sim.cluster.id
    db.close()
    barrier = threading.Barrier(WORKERS)
    reads, plans = [], []

    def live_configuration(node):
        reads.append(node.id)
        if len(reads) == 1:
            gate(barrier)  # hold the step open while every other caller arrives
        return None, {"dns": {"upstreams": ["192.0.2.53"]}}

    def create_sync_plan(db, cluster, user):
        plans.append(cluster.id)
        source = next(node for node in cluster.nodes if node.id == cluster.authoritative_node_id)
        target = next(node for node in cluster.nodes if node.id != source.id)
        sync = HASyncRun(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="IN_SYNC",
                         plan_json='{"groups":[]}', completed_at=datetime.utcnow())
        db.add(sync)
        db.flush()
        return sync

    monkeypatch.setattr(ha_maintenance, "_live_configuration", live_configuration)
    monkeypatch.setattr(ha_maintenance, "create_sync_plan", create_sync_plan)
    monkeypatch.setattr(ha_maintenance, "reconcile_cluster_leases", lambda db, cluster, **kwargs: (_ for _ in ()).throw(AssertionError("not reached")))
    assert run_parallel(*mixed_callers(factory, sim, run_id)) == []
    check = factory()
    assert check.get(HAMaintenanceRun, run_id).phase in {"SYNCHRONISING", "STAGING_DHCP", "PAUSED"}
    assert check.query(HABackup).count() == 2  # one encrypted backup per node, not one per caller
    check.close()
    assert sorted(reads) == sorted([sim.one.id, sim.two.id]) and len(plans) == 1
    events = counts(factory, cluster_id, event_type="cluster_reinitialisation_backups_completed", audit_action="-", audit_entity="-")[0]
    assert events == 1


def test_concurrent_reconciliation_completes_once(pg, monkeypatch):
    factory, _ = pg
    db, sim = split_cluster(factory)
    sim.cluster.maintenance_mode = False
    db.commit()
    run = start_reconciliation(db, sim.cluster, sim.admin)
    run.started_at = datetime.utcnow() - timedelta(seconds=30)  # the setup reports count as fresh for this run
    db.commit()
    run_id, cluster_id = run.id, sim.cluster.id
    db.close()
    barrier = threading.Barrier(4)
    entered = []
    real = ha_maintenance.inspect_cluster

    def gated(cluster, **kwargs):
        if not entered:
            entered.append(1)
            gate(barrier)
        return real(cluster, **kwargs)

    monkeypatch.setattr(ha_maintenance, "inspect_cluster", gated)

    def worker():
        session = factory()
        try:
            reconcile_cluster_state(session, session.get(HAMaintenanceRun, run_id))
        finally:
            session.close()

    assert run_parallel(worker, worker, worker, worker) == []
    check = factory()
    final = check.get(HAMaintenanceRun, run_id)
    check.close()
    assert final.status != "RUNNING"
    terminal_events = sum(counts(factory, cluster_id, event_type=name, audit_action="-", audit_entity="-")[0]
                          for name in ("cluster_reconciliation_completed", "cluster_reconciliation_needs_attention"))
    audits = sum(counts(factory, cluster_id, event_type="-", audit_action=action, audit_entity="ha_cluster_reconciliation")[1]
                 for action in ("complete", "fail_safe"))
    assert (terminal_events, audits) == (1, 1)


def test_many_concurrent_recovery_evaluations_record_one_transition(pg, monkeypatch):
    factory, _ = pg
    db = factory(expire_on_commit=False)
    sim = hal_like_cluster(db, suffix=uuid4().hex[:8])
    sim.report_both(2)
    cluster_id = sim.cluster.id
    db.get(HANode, sim.two.id).dns_healthy = False  # the ready standby must leave STANDBY_READY
    db.commit()
    db.close()
    barrier = threading.Barrier(WORKERS)
    local = threading.local()
    real = ha_recovery.recovery_checks

    def gated(db, cluster, node, *, now=None):
        if not getattr(local, "waited", False):
            local.waited = True
            gate(barrier)
        return real(db, cluster, node, now=now)

    monkeypatch.setattr(ha_recovery, "recovery_checks", gated)

    def recorded():
        check = factory()
        try:
            events = check.query(HAEvent).filter(HAEvent.cluster_id == cluster_id, HAEvent.source == "kaya",
                                                 HAEvent.message.like("%recovery%") | HAEvent.event_type.like("node_%")).count()
            audits = check.query(AuditLog).filter(AuditLog.entity == "ha_node", AuditLog.action.like("ha_recovery_%")).count()
            return events, audits
        finally:
            check.close()

    events_before, audits_before = recorded()

    def worker():
        session = factory()
        try:
            evaluate_recovery(session, session.get(HACluster, cluster_id))
        finally:
            session.close()

    assert run_parallel(*[worker] * WORKERS) == []
    events_after, audits_after = recorded()
    # The standby's state changes once: one transition event and one audit row, not one per caller.
    assert (events_after - events_before, audits_after - audits_before) == (1, 1)


def test_coordination_lock_never_blocks_heartbeat_writes_during_a_slow_step(pg, monkeypatch):
    factory, _ = pg
    db, sim = split_cluster(factory)
    run = HAMaintenanceRun(cluster_id=sim.cluster.id, operation="REINITIALISE", status="RUNNING", phase="STAGING_DHCP",
                           desired_active_node_id=sim.one.id, authoritative_node_id=sim.one.id, requested_by_user_id=sim.admin.id,
                           started_at=datetime.utcnow(), phase_started_at=datetime.utcnow(), previous_state_json="{}", result_json="{}")
    db.add(run)
    db.commit()
    run_id, one_id = run.id, sim.one.id
    beat = heartbeat_for(sim.sim_one)
    db.close()
    in_step, release = threading.Event(), threading.Event()

    def slow_external_step(db, cluster, **kwargs):
        in_step.set()
        assert release.wait(10)
        raise ha_maintenance.HALeaseError("synthetic slow Pi-hole step ended")

    monkeypatch.setattr(ha_maintenance, "reconcile_cluster_leases", slow_external_step)

    def holder():
        session = factory()
        try:
            advance_reinitialisation(session, session.get(HAMaintenanceRun, run_id))
        finally:
            session.close()

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert in_step.wait(10)
        started = time.monotonic()
        session = factory()
        try:
            record_heartbeat(session, session.get(HANode, one_id), beat)  # writes node and cluster rows
            elapsed = time.monotonic() - started
        finally:
            session.close()
        assert elapsed < 5, f"heartbeat waited {elapsed:.1f}s behind the coordination lock"
        check = factory()
        assert check.get(HANode, one_id).last_report_sequence == beat.report_sequence
        check.close()
    finally:
        release.set()
        thread.join(15)
    assert not thread.is_alive()


def test_lock_is_released_when_its_holder_dies(pg):
    factory, admin = pg
    db, sim = split_cluster(factory)
    cluster_id = sim.cluster.id
    db.close()
    holding, finish = threading.Event(), threading.Event()
    errors = []

    def holder():
        session = factory()
        try:
            with cluster_coordination(session, cluster_id, operation="test_holder") as acquired:
                assert acquired
                holding.set()
                finish.wait(15)
        except BaseException as exc:
            errors.append(exc)
        finally:
            session.close()

    thread = threading.Thread(target=holder)
    thread.start()
    assert holding.wait(10)
    contender = factory()
    with cluster_coordination(contender, cluster_id, operation="test_contender") as acquired:
        assert acquired is False
    with admin.begin() as connection:  # simulate the holder's process dying
        pids = connection.execute(text(
            "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = :namespace AND objid = :cluster_id AND granted"
        ), {"namespace": ADVISORY_NAMESPACE, "cluster_id": cluster_id}).scalars().all()
        assert len(pids) == 1
        connection.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pids[0]})
    deadline = time.monotonic() + 5
    acquired_after = False
    while time.monotonic() < deadline and not acquired_after:
        with cluster_coordination(contender, cluster_id, operation="test_after_crash") as acquired_after:
            pass
        time.sleep(0.05)
    contender.close()
    finish.set()
    thread.join(10)
    assert acquired_after, "lock survived its holder's connection"
    assert errors == []  # the holder's failed unlock is handled, not raised


def test_restart_resumes_an_interrupted_operation_once(pg, monkeypatch):
    factory, _ = pg
    db, sim = split_cluster(factory)
    earlier = PROCESS_STARTED_AT - timedelta(minutes=5)
    run = HAMaintenanceRun(cluster_id=sim.cluster.id, operation="REINITIALISE", status="RUNNING", phase="BACKING_UP",
                           desired_active_node_id=sim.one.id, authoritative_node_id=sim.one.id, requested_by_user_id=sim.admin.id,
                           started_at=earlier, phase_started_at=earlier, previous_state_json="{}", result_json="{}")
    db.add(run)
    db.commit()
    run_id = run.id
    db.close()
    monkeypatch.setattr(ha_maintenance, "_create_two_node_backups",
                        lambda db, run: (_ for _ in ()).throw(AssertionError("an interrupted step must not run before fresh reports")))
    assert run_parallel(*mixed_callers(factory, sim, run_id)) == []
    check = factory()
    final = check.get(HAMaintenanceRun, run_id)
    progress = final.result_json
    check.close()
    assert final.status == "RUNNING" and final.phase in {"WAITING_FOR_REPORTS", "BACKING_UP"}
    assert progress.count("Kaya restarted; the repair sequence is restarting from fresh signed node reports") <= 1


def test_skipped_caller_changes_nothing(pg):
    factory, _ = pg
    db, sim = split_cluster(factory)
    run = HAMaintenanceRun(cluster_id=sim.cluster.id, operation="REINITIALISE", status="RUNNING", phase="STAGING_DHCP",
                           desired_active_node_id=sim.one.id, authoritative_node_id=sim.one.id, requested_by_user_id=sim.admin.id,
                           started_at=datetime.utcnow(), phase_started_at=datetime.utcnow(), previous_state_json="{}", result_json="{}")
    db.add(run)
    db.commit()
    run_id, cluster_id = run.id, sim.cluster.id
    db.close()
    holding, finish = threading.Event(), threading.Event()

    def holder():  # another worker (thread) is advancing this cluster
        session = factory()
        try:
            with cluster_coordination(session, cluster_id, operation="test_holder") as acquired:
                assert acquired
                holding.set()
                finish.wait(10)
        finally:
            session.close()

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert holding.wait(10)
        session = factory()
        try:
            result = advance_reinitialisation(session, session.get(HAMaintenanceRun, run_id))
            assert (result.status, result.phase) == ("RUNNING", "STAGING_DHCP")
        finally:
            session.close()
    finally:
        finish.set()
        thread.join(10)
    check = factory()
    assert check.get(HAMaintenanceRun, run_id).status == "RUNNING"
    check.close()
