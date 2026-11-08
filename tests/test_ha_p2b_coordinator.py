"""P2B: one authoritative HA decision process.

Heartbeats, action results and events record and signal; the coordinator
(ha_watchdog) decides.  Covers the recording contract, the live coordinator
loop (prompt decisions, bounded waits, failure isolation), cross-process
SQLite coordination, advisory-lock release on an unconfirmed unlock, and that
no database transaction is open during Pi-hole calls.  Synthetic data only.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.models import HACluster, HANode
from app.schemas.high_availability import HAAgentEventItem
from app.services import ha_coordination, ha_evaluation_queue, ha_leases, ha_maintenance, ha_watchdog
from app.services.ha_agents import ingest_events, record_heartbeat
from app.services.ha_coordination import cluster_coordination
from app.services.ha_watchdog import drain_evaluations
from ha_simulation import hal_like_cluster, heartbeat_for, sqlite_session
from test_ha_gate_a_lease_churn import plan as lease_plan

POSTGRES_URL = os.environ.get("KAYA_TEST_POSTGRES_URL")


def healthy(db=None, **kwargs):
    sim = hal_like_cluster(db or sqlite_session(), maintenance_mode=False, **kwargs)
    sim.report_both(2)  # the harness drains the coordinator after each report
    assert sim.cluster.status == "HEALTHY"
    return sim


def record_only(sim, simnode):
    record_heartbeat(sim.db, sim.node_for(simnode), heartbeat_for(simnode))


# --- recording paths never decide ------------------------------------------------


def test_heartbeat_records_and_signals_but_does_not_decide():
    sim = healthy()
    sim.vrrp.stop("SimPiHole1")
    record_only(sim, sim.sim_two)
    record_only(sim, sim.sim_one)
    sim.db.expire_all()
    assert sim.cluster.status == "HEALTHY"  # observation recorded, no decision yet
    assert sim.two.vip_owned is True and sim.cluster.current_active_node_id == sim.one.id
    pending = ha_evaluation_queue.take_pending()
    assert set(pending) == {sim.cluster.id} and pending[sim.cluster.id].reporting_node_id == sim.one.id
    ha_evaluation_queue.requeue(sim.cluster.id, pending[sim.cluster.id])
    drain_evaluations(sim.db)
    # The coordinator decided (status), and the assignment did not follow the observation (P4/D1).
    assert sim.cluster.status == "DEGRADED" and sim.cluster.current_active_node_id == sim.one.id


def test_completion_event_is_adopted_by_the_coordinator_not_the_event_request():
    sim = healthy(automatic_failover=True)
    sim.vrrp.stop("SimPiHole1")
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = True, False
    sim.report(sim.sim_two)
    before = sim.cluster.role_generation
    event = HAAgentEventItem(event_id="p2b-automatic-completed-01", event_type="automatic_failover_completed", severity="warning",
                             message="Local failover completed without requiring Kaya.", occurred_at=datetime.utcnow(),
                             details={"generation": sim.cluster.keepalived_generation, "automatic": True})
    assert ingest_events(sim.db, sim.two, [event]) == (1, 0)
    pending = ha_evaluation_queue.take_pending()[sim.cluster.id]
    assert [node_id for node_id, _ in pending.adoptions] == [sim.two.id]
    ha_evaluation_queue.requeue(sim.cluster.id, pending)
    drain_evaluations(sim.db)
    assert sim.cluster.current_active_node_id == sim.two.id and sim.cluster.authoritative_node_id == sim.two.id
    assert sim.cluster.role_generation >= before


def test_first_heartbeat_after_process_start_requests_evaluation():
    sim = healthy()
    ha_evaluation_queue.reset()  # a new process: nothing evaluated yet
    record_only(sim, sim.sim_one)  # unchanged, healthy observation
    assert sim.cluster.id in ha_evaluation_queue.take_pending()


def test_unchanged_healthy_heartbeat_after_evaluation_requests_nothing():
    sim = healthy()
    ha_evaluation_queue.take_pending()
    record_only(sim, sim.sim_one)
    assert ha_evaluation_queue.take_pending() == {}


# --- the live coordinator loop ------------------------------------------------------


@pytest.fixture
def file_factory(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'coordinator.db').as_posix()}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine)
    engine.dispose()


def run_with_coordinator(factory, body, *, monkeypatch, startup_delay=3600):
    """Run ``body`` in a worker thread while the real coordinator loop runs."""
    monkeypatch.setattr(ha_watchdog, "STARTUP_DELAY_SECONDS", startup_delay)

    async def main():
        loop_task = asyncio.create_task(ha_watchdog.ha_watchdog_loop(session_factory=factory))
        for _ in range(100):  # until the loop has registered its wake-up
            if ha_evaluation_queue.coordinator_running():
                break
            await asyncio.sleep(0.01)
        try:
            return await asyncio.to_thread(body)
        finally:
            loop_task.cancel()
            await asyncio.gather(loop_task, return_exceptions=True)

    return asyncio.run(main())


def test_heartbeat_reply_already_reflects_the_coordinator_decision(file_factory, monkeypatch):
    setup = file_factory(expire_on_commit=False)
    sim = healthy(setup)
    cluster_id, one_id, two_id = sim.cluster.id, sim.one.id, sim.two.id
    sim.vrrp.stop("SimPiHole1")
    beats = [(two_id, heartbeat_for(sim.sim_two)), (one_id, heartbeat_for(sim.sim_one))]
    setup.close()
    ha_evaluation_queue.reset()

    def body():
        timings = []
        for node_id, beat in beats:
            db = file_factory()
            try:
                started = time.perf_counter()
                record_heartbeat(db, db.get(HANode, node_id), beat)
                ticket = db.info.pop("ha_evaluation_ticket")
                assert ha_evaluation_queue.wait_for_evaluation(cluster_id, ticket, 2.0)
                timings.append(time.perf_counter() - started)
                db.expire_all()
                status = db.get(HACluster, cluster_id).status
            finally:
                db.close()
        return status, timings

    status, timings = run_with_coordinator(file_factory, body, monkeypatch=monkeypatch)
    assert status == "DEGRADED"  # decided before the (second) heartbeat replied
    assert max(timings) < 1.0, timings


def test_slow_coordinator_never_holds_a_heartbeat_beyond_the_bound(file_factory, monkeypatch):
    setup = file_factory(expire_on_commit=False)
    sim = healthy(setup)
    one_id, cluster_id = sim.one.id, sim.cluster.id
    beat = heartbeat_for(sim.sim_one)
    setup.close()
    ha_evaluation_queue.reset()
    release = threading.Event()
    monkeypatch.setattr(ha_watchdog, "evaluate_cluster", lambda *args, **kwargs: release.wait(10) or True)

    def body():
        db = file_factory()
        try:
            started = time.perf_counter()
            record_heartbeat(db, db.get(HANode, one_id), beat)
            done = ha_evaluation_queue.wait_for_evaluation(cluster_id, db.info.pop("ha_evaluation_ticket"), 0.5)
            return done, time.perf_counter() - started
        finally:
            release.set()
            db.close()

    done, elapsed = run_with_coordinator(file_factory, body, monkeypatch=monkeypatch)
    assert done is False and elapsed < 1.5  # replies with current desired state; agents act locally regardless


def test_failed_evaluation_releases_waiters_and_the_loop_keeps_running(file_factory, monkeypatch):
    setup = file_factory(expire_on_commit=False)
    sim = healthy(setup)
    cluster_id = sim.cluster.id
    setup.close()
    ha_evaluation_queue.reset()
    calls = []

    def flaky(db, cluster, **kwargs):
        calls.append(cluster.id)
        if len(calls) == 1:
            raise RuntimeError("synthetic coordinator fault")
        return True

    monkeypatch.setattr(ha_watchdog, "evaluate_cluster", flaky)

    def body():
        first = ha_evaluation_queue.request_and_wait(cluster_id, 2.0)
        second = ha_evaluation_queue.request_and_wait(cluster_id, 2.0)
        return first, second

    assert run_with_coordinator(file_factory, body, monkeypatch=monkeypatch) == (True, True)
    assert calls == [cluster_id, cluster_id]


def test_periodic_pass_still_runs_without_any_heartbeat(file_factory, monkeypatch):
    from app.models.models import RemoteManagerSetting

    setup = file_factory(expire_on_commit=False)
    setup.add(RemoteManagerSetting(key="high_availability_enabled", value="1"))
    sim = healthy(setup)
    sim.cluster.keepalived_status = "DEPLOYED"
    setup.commit()
    setup.close()
    ha_evaluation_queue.reset()
    seen = []
    monkeypatch.setattr(ha_watchdog, "reconcile_cluster", lambda db, cluster: seen.append(cluster.id))

    def body():
        deadline = time.monotonic() + 3
        while not seen and time.monotonic() < deadline:
            time.sleep(0.05)
        return list(seen)

    assert run_with_coordinator(file_factory, body, monkeypatch=monkeypatch, startup_delay=0)


# --- coordination primitives ---------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file locks")
def test_sqlite_coordination_excludes_another_process(file_factory):
    db = file_factory()
    directory = ha_coordination._sqlite_lock_directory(db.get_bind())
    assert directory is not None and ha_coordination.cross_process_protection(db.get_bind())
    directory.mkdir(exist_ok=True)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import fcntl, os, sys, time\n"
         "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
         "fcntl.flock(fd, fcntl.LOCK_EX)\n"
         "print('held', flush=True)\n"
         "time.sleep(30)\n",
         str(directory / "cluster-4242.lock")],
        stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        with cluster_coordination(db, 4242, operation="test") as acquired:
            assert acquired is False
    finally:
        holder.kill()
        holder.wait(10)
    with cluster_coordination(db, 4242, operation="test") as acquired:
        assert acquired is True  # released by the operating system when the holder died
    db.close()


def test_in_memory_sqlite_reports_no_cross_process_protection():
    engine = create_engine("sqlite:///:memory:")
    assert ha_coordination.cross_process_protection(engine) is False


@pytest.mark.skipif(not POSTGRES_URL, reason="KAYA_TEST_POSTGRES_URL is not configured")
def test_unconfirmed_unlock_discards_the_connection_and_releases_the_lock(monkeypatch):
    engine = create_engine(POSTGRES_URL, pool_size=1, max_overflow=0)
    factory = sessionmaker(bind=engine)
    cluster_id = 900_000 + int(uuid4().int % 1000)
    monkeypatch.setattr(ha_coordination, "UNLOCK_SQL", text("SELECT false"))  # release not confirmed
    db = factory()
    try:
        with cluster_coordination(db, cluster_id, operation="test") as acquired:
            assert acquired
        monkeypatch.undo()
        held, deadline = None, time.monotonic() + 2  # the discarded backend exits asynchronously
        while held != 0 and time.monotonic() < deadline:
            with engine.connect() as connection:  # the only pooled connection is a fresh one
                held = connection.execute(text(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = :ns AND objid = :id"
                ), {"ns": ha_coordination.ADVISORY_NAMESPACE, "id": cluster_id}).scalar()
            time.sleep(0.05)
        assert held == 0
        with cluster_coordination(db, cluster_id, operation="test") as acquired:
            assert acquired
    finally:
        db.close()
        engine.dispose()


# --- no transaction open across Pi-hole calls ------------------------------------------


def test_lease_inspection_runs_with_no_transaction_open(monkeypatch):
    sim = healthy()
    observed = []

    def inspect(inputs, **kwargs):
        observed.append(sim.db.in_transaction())
        return lease_plan(sim, 2_000_000_000)

    monkeypatch.setattr(ha_leases, "inspect_lease_plan", inspect)
    ha_leases.reconcile_cluster_leases(sim.db, sim.cluster)
    assert observed == [False]


def test_maintenance_backups_read_pihole_with_no_transaction_open(monkeypatch):
    from app.services.ha_maintenance import advance_reinitialisation, start_reinitialisation
    from test_ha_gate_a_maintenance_defects import split_cluster

    sim = split_cluster()
    observed = []

    def live_configuration(endpoint):
        observed.append((endpoint.display_name, sim.db.in_transaction()))
        return None, {"dns": {"upstreams": ["192.0.2.53"]}}

    monkeypatch.setattr(ha_maintenance, "_live_configuration", live_configuration)
    monkeypatch.setattr("app.services.ha_watchdog.advance_reinitialisation", lambda db, run: run)
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    for _ in range(2):
        sim.report_both()
        advance_reinitialisation(sim.db, run)
    assert sorted(name for name, _ in observed) == ["SimPiHole1", "SimPiHole2"]
    assert not any(open_ for _, open_ in observed)


# --- P2B close-out ------------------------------------------------------------------


def _counting_evaluations(monkeypatch):
    calls = []
    real = ha_watchdog.evaluate_cluster

    def counting(db, cluster, **kwargs):
        calls.append(cluster.id)
        return real(db, cluster, **kwargs)

    monkeypatch.setattr(ha_watchdog, "evaluate_cluster", counting)
    return calls


def test_restart_sweep_evaluates_a_persisted_observation_without_another_heartbeat(file_factory, monkeypatch):
    setup = file_factory(expire_on_commit=False)
    sim = healthy(setup)
    cluster_id = sim.cluster.id
    sim.vrrp.stop("SimPiHole1")
    record_only(sim, sim.sim_two)  # persisted before the "crash", never evaluated
    record_only(sim, sim.sim_one)
    setup.close()
    ha_evaluation_queue.reset()  # the restarted process remembers nothing
    monkeypatch.setattr(ha_watchdog, "CHECK_INTERVAL_SECONDS", 0.2)
    calls = _counting_evaluations(monkeypatch)

    def body():
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            db = file_factory()
            try:
                if db.get(HACluster, cluster_id).status == "DEGRADED":
                    break
            finally:
                db.close()
            time.sleep(0.05)
        time.sleep(0.6)  # several more periodic passes: none may re-evaluate

    run_with_coordinator(file_factory, body, monkeypatch=monkeypatch, startup_delay=0)
    db = file_factory()
    try:
        assert db.get(HACluster, cluster_id).status == "DEGRADED"
    finally:
        db.close()
    assert calls == [cluster_id]  # exactly one evaluation: no repeated decisions or actions


def test_failed_evaluation_is_retried_by_the_periodic_pass(file_factory, monkeypatch):
    setup = file_factory(expire_on_commit=False)
    sim = healthy(setup)
    cluster_id = sim.cluster.id
    setup.close()
    ha_evaluation_queue.reset()
    monkeypatch.setattr(ha_watchdog, "CHECK_INTERVAL_SECONDS", 0.1)
    calls = []

    def flaky(db, cluster, **kwargs):
        calls.append(cluster.id)
        if len(calls) == 1:
            raise RuntimeError("synthetic coordinator fault")
        return True

    monkeypatch.setattr(ha_watchdog, "evaluate_cluster", flaky)

    def body():
        ha_evaluation_queue.request_evaluation(cluster_id)  # one signal only
        deadline = time.monotonic() + 3
        while len(calls) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        return list(calls)

    assert run_with_coordinator(file_factory, body, monkeypatch=monkeypatch, startup_delay=0)[:2] == [cluster_id, cluster_id]


def test_completion_event_difference_is_bookkeeping_only():
    """The one P2A/P2B decision difference: after a signed failover-completion
    event the coordinator also evaluates recovery, so the adopted node's
    recovery state is ACTIVE one heartbeat earlier.  It must not create any
    service action, operation or generation change, and the next heartbeat
    must leave the decision state exactly as P2A reached it."""
    from app.services.ha_agents import desired_state

    sim = healthy(automatic_failover=True)
    sim.vrrp.stop("SimPiHole1")
    sim.sim_two.dhcp_running, sim.sim_one.dhcp_running = True, False
    sim.report(sim.sim_two)
    generations_before = (sim.cluster.cluster_generation, sim.cluster.keepalived_generation)
    event = HAAgentEventItem(event_id="p2b-closeout-completed-01", event_type="automatic_failover_completed", severity="warning",
                             message="Local failover completed without requiring Kaya.", occurred_at=datetime.utcnow(),
                             details={"generation": sim.cluster.keepalived_generation, "automatic": True})
    ingest_events(sim.db, sim.two, [event])
    drain_evaluations(sim.db)

    def decision_state():
        sim.db.expire_all()
        nodes = {node.display_name: (node.role, node.desired_role, node.vip_owned, node.recovery_state) for node in sim.cluster.nodes}
        actions = {}
        for node in sim.cluster.nodes:
            desired = desired_state(node)
            actions[node.display_name] = (desired["allowed_actions"], desired["failover"], desired["keepalived"], desired["lease_snapshot"])
        return nodes, actions

    nodes, actions = decision_state()
    assert nodes["SimPiHole2"] == ("ACTIVE", "ACTIVE", True, "ACTIVE")  # the earlier bookkeeping update
    for allowed, failover, keepalived, _lease in actions.values():
        assert failover is None and keepalived is None  # no DHCP, VIP or Keepalived action
        assert not {"DHCP_PROMOTE", "DHCP_DEMOTE", "KEEPALIVED_APPLY"} & set(allowed)
    assert not sim.cluster.failover_runs and not sim.cluster.maintenance_runs
    assert (sim.cluster.cluster_generation, sim.cluster.keepalived_generation) == generations_before
    sim.report(sim.sim_two)  # P2A reached this state here
    assert decision_state() == (nodes, actions)


def test_all_workers_busy_heartbeat_waits_stay_bounded(file_factory, monkeypatch):
    setup = file_factory(expire_on_commit=False)
    ids = []
    for index in range(ha_watchdog.COORDINATOR_WORKERS + 2):
        sim = hal_like_cluster(setup, maintenance_mode=False, suffix=f"busy{index}-{uuid4().hex[:6]}")
        sim.cluster.virtual_ip = f"192.0.2.{120 + index}"
        setup.commit()
        ids.append(sim.cluster.id)
    setup.close()
    ha_evaluation_queue.reset()
    release = threading.Event()
    started = []

    def blocked(db, cluster, **kwargs):
        started.append(cluster.id)
        release.wait(10)
        return True

    monkeypatch.setattr(ha_watchdog, "evaluate_cluster", blocked)

    def body():
        for cluster_id in ids:
            ha_evaluation_queue.request_evaluation(cluster_id)
        time.sleep(0.3)
        began = time.perf_counter()
        queued_done = ha_evaluation_queue.wait_for_evaluation(ids[-1], ha_evaluation_queue.request_evaluation(ids[-1]), 0.5)
        waited = time.perf_counter() - began
        busy = len(started)
        release.set()
        finished = all(ha_evaluation_queue.request_and_wait(cluster_id, 3.0) for cluster_id in ids)
        return queued_done, waited, busy, finished

    queued_done, waited, busy, finished = run_with_coordinator(file_factory, body, monkeypatch=monkeypatch)
    assert busy == ha_watchdog.COORDINATOR_WORKERS  # never more evaluations than workers
    assert queued_done is False and waited < 1.0  # the wait is bounded, not blocked
    assert finished  # every cluster evaluated once workers free up


def test_exhausted_connection_pool_fails_safe_and_recovers(tmp_path, monkeypatch):
    from sqlalchemy.pool import QueuePool

    engine = create_engine(f"sqlite:///{(tmp_path / 'pool.db').as_posix()}", connect_args={"check_same_thread": False},
                           poolclass=QueuePool, pool_size=1, max_overflow=0, pool_timeout=0.3)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    setup = factory(expire_on_commit=False)
    sim = healthy(setup)
    cluster_id = sim.cluster.id
    setup.close()
    ha_evaluation_queue.reset()
    monkeypatch.setattr(ha_watchdog, "CHECK_INTERVAL_SECONDS", 0.2)
    calls = _counting_evaluations(monkeypatch)

    def body():
        time.sleep(0.5)  # let the start-up sweep finish
        before = len(calls)
        hog = engine.connect()  # every pooled connection is in use
        try:
            began = time.perf_counter()
            released = ha_evaluation_queue.request_and_wait(cluster_id, 3.0)
            waited = time.perf_counter() - began
            during = len(calls)
        finally:
            hog.close()
        deadline = time.monotonic() + 3
        while len(calls) == during and time.monotonic() < deadline:  # the periodic pass retries the failure
            time.sleep(0.05)
        return released, waited, before, during, len(calls)

    released, waited, before, during, after = run_with_coordinator(factory, body, monkeypatch=monkeypatch, startup_delay=0)
    assert released and waited < 2.0  # the waiter is released by the failure, bounded by pool_timeout
    assert during == before  # no evaluation ran without a connection
    assert after == during + 1  # retried once the pool recovered, without another heartbeat
    engine.dispose()
