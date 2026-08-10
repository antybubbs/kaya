import asyncio
from datetime import datetime, timedelta
import logging
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    IPAddress,
    NetworkMonitor,
    NotificationEvent,
    NotificationOutbox,
    NotificationReconciliationFailure,
    User,
)
from app.services import notification_runtime as runtime


@pytest.fixture()
def runtime_db(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(runtime, "SessionLocal", factory)
    runtime._tasks.clear()
    runtime._unhealthy_alerts.clear()
    runtime._restart_counts.update(outbox=0, delivery=0, reconciliation=0)
    for name in runtime._worker_states:
        runtime._worker_states[name] = runtime._initial_worker_state(name)
    yield factory
    runtime._tasks.clear()
    runtime._unhealthy_alerts.clear()


def _monitor(session: Session, suffix: int, status: str = "offline") -> NetworkMonitor:
    address = IPAddress(
        address=f"192.0.2.{suffix}",
        name=f"Synthetic host {suffix}",
    )
    session.add(address)
    session.flush()
    monitor = NetworkMonitor(
        ip_address_id=address.id,
        is_enabled=True,
        is_in_maintenance=False,
        last_status=status,
    )
    session.add(monitor)
    session.commit()
    return monitor


def test_reconciliation_idle_schedule_is_not_a_stale_worker(runtime_db):
    now = datetime.utcnow()
    runtime._set_state(
        "reconciliation",
        current_operation="idle",
        last_heartbeat=now - timedelta(minutes=4),
        next_run_at=now + timedelta(seconds=60),
    )

    assert runtime._worker_is_stale("reconciliation", now) is False


def test_reconciliation_isolates_a_malformed_item_and_continues(
    runtime_db, monkeypatch
):
    with runtime_db() as db:
        first = _monitor(db, 10)
        second = _monitor(db, 11)
        first_id = first.id
        second_id = second.id

    def reconcile_item(monitor_id, operation):
        if monitor_id == first_id:
            raise ValueError("synthetic malformed monitor")
        assert monitor_id == second_id
        assert operation == "offline"
        return "created"

    monkeypatch.setattr(runtime, "_reconcile_monitor_item", reconcile_item)

    result = runtime.reconcile_notifications()

    assert result["failed_items"] == 1
    assert result["missing_alerts_repaired"] == 1
    with runtime_db() as db:
        failure = db.query(NotificationReconciliationFailure).one()
        assert failure.item_id == str(first_id)
        assert failure.status == "retry"
        assert failure.last_exception_type == "ValueError"


def test_permanently_failing_reconciliation_item_is_quarantined(runtime_db):
    for _ in range(runtime.MAX_RECONCILIATION_ITEM_ATTEMPTS):
        runtime._record_item_failure(42, "offline", ValueError("synthetic invalid row"))

    with runtime_db() as db:
        failure = db.query(NotificationReconciliationFailure).one()
        assert failure.status == "quarantined"
        assert failure.attempt_count == runtime.MAX_RECONCILIATION_ITEM_ATTEMPTS
        assert failure.quarantined_at is not None
        assert "synthetic invalid row" not in (failure.last_error_code or "")
        warning = db.query(NotificationOutbox).filter_by(
            deduplication_key=(
                "system:notification-reconciliation-item:network_monitor:"
                "42:offline:quarantined"
            )
        ).one()
        assert warning.correlation_id == failure.correlation_id


def test_worker_failure_alert_is_a_single_active_condition(runtime_db):
    with runtime_db() as db:
        db.add(
            User(
                email="runtime-admin@example.invalid",
                password_hash="clearly-fake-hash",
                role="admin",
                is_active=True,
            )
        )
        db.commit()

    runtime._queue_worker_failure("reconciliation", "task_stopped", "a" * 32)
    runtime._queue_worker_failure("reconciliation", "task_stopped", "b" * 32)

    with runtime_db() as db:
        assert (
            db.query(NotificationOutbox)
            .filter_by(
                deduplication_key="system:notification-worker:reconciliation:failed"
            )
            .count()
            == 1
        )


def test_worker_failure_recovery_resolves_the_active_condition(runtime_db):
    with runtime_db() as db:
        db.add(
            NotificationEvent(
                event_type="system.background_task.failed",
                module="system",
                category="operations",
                severity="critical",
                title="Synthetic worker failure",
                message="Synthetic test record.",
                deduplication_key="system:notification-worker:reconciliation:failed",
                correlation_id="c" * 32,
            )
        )
        db.commit()
    runtime._unhealthy_alerts.add("reconciliation")

    runtime._resolve_worker_failure("reconciliation")

    with runtime_db() as db:
        assert db.query(NotificationEvent).one().resolved_at is not None
    assert "reconciliation" not in runtime._unhealthy_alerts


def test_runtime_start_is_idempotent_and_shutdown_cancellation_is_not_a_failure(
    runtime_db, monkeypatch
):
    alerts = []
    monkeypatch.setattr(runtime, "SUPERVISOR_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(
        runtime,
        "WORKER_INTERVALS",
        {"outbox": 0.01, "delivery": 0.01, "reconciliation": 0.01},
    )
    monkeypatch.setattr(runtime, "_operation_for", lambda _name: lambda: None)
    monkeypatch.setattr(
        runtime,
        "_queue_worker_failure",
        lambda name, reason, correlation_id: alerts.append((name, reason)),
    )

    async def exercise():
        first = runtime.start_notification_runtime()
        second = runtime.start_notification_runtime()
        assert first is second
        await asyncio.sleep(0.06)
        assert len(runtime._tasks) == 3
        assert len({task.get_name() for task in runtime._tasks.values()}) == 3
        await runtime.stop_notification_runtime()

    asyncio.run(exercise())

    assert alerts == []
    assert runtime._tasks == {}


def test_unexpected_worker_cancellation_restarts_once_with_backoff(
    runtime_db, monkeypatch
):
    alerts = []
    monkeypatch.setattr(runtime, "SUPERVISOR_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(runtime, "RESTART_BACKOFF_SECONDS", (0.02, 0.03, 0.04, 0.05))
    monkeypatch.setattr(
        runtime,
        "WORKER_INTERVALS",
        {"outbox": 0.1, "delivery": 0.1, "reconciliation": 0.1},
    )
    monkeypatch.setattr(runtime, "_operation_for", lambda _name: lambda: None)
    monkeypatch.setattr(
        runtime,
        "_queue_worker_failure",
        lambda name, reason, correlation_id: alerts.append((name, reason)),
    )
    monkeypatch.setattr(runtime, "_resolve_worker_failure", lambda _name: None)

    async def exercise():
        runtime.start_notification_runtime()
        await asyncio.sleep(0.03)
        original = runtime._tasks["reconciliation"]
        original.cancel()
        await asyncio.gather(original, return_exceptions=True)
        await asyncio.sleep(0.07)
        replacement = runtime._tasks["reconciliation"]
        assert replacement is not original
        assert not replacement.done()
        await runtime.stop_notification_runtime()

    asyncio.run(exercise())

    assert alerts == [("reconciliation", "unexpected_cancellation")]
    assert runtime._restart_counts["reconciliation"] == 1


def test_idle_reconciliation_survives_watchdog_longer_than_operation_timeout(
    runtime_db, monkeypatch
):
    monkeypatch.setattr(runtime, "SUPERVISOR_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(runtime, "WORKER_OPERATION_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(
        runtime,
        "WORKER_INTERVALS",
        {"outbox": 0.01, "delivery": 0.01, "reconciliation": 0.2},
    )
    monkeypatch.setattr(runtime, "_operation_for", lambda _name: lambda: None)
    alerts = []
    monkeypatch.setattr(
        runtime,
        "_queue_worker_failure",
        lambda name, reason, correlation_id: alerts.append((name, reason)),
    )

    async def exercise():
        runtime.start_notification_runtime()
        await asyncio.sleep(0.04)
        original = runtime._tasks["reconciliation"]
        await asyncio.sleep(0.08)
        assert runtime._tasks["reconciliation"] is original
        assert runtime._restart_counts["reconciliation"] == 0
        await runtime.stop_notification_runtime()

    asyncio.run(exercise())

    assert alerts == []


def test_iteration_exception_logs_traceback_then_recovers(
    runtime_db, monkeypatch, caplog
):
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OperationalError(
                "synthetic operation",
                {},
                sqlite3.OperationalError("database is locked"),
            )

    monkeypatch.setattr(runtime, "_operation_for", lambda _name: operation)
    monkeypatch.setattr(
        runtime, "ITERATION_FAILURE_BACKOFF_SECONDS", (0.01, 0.02, 0.03, 0.04)
    )
    monkeypatch.setattr(
        runtime,
        "WORKER_INTERVALS",
        {"outbox": 0.01, "delivery": 0.01, "reconciliation": 0.01},
    )

    async def exercise():
        task = runtime._create_worker("reconciliation")
        await asyncio.sleep(0.08)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    with caplog.at_level(logging.ERROR):
        asyncio.run(exercise())

    state = runtime._state_snapshot("reconciliation")
    failure_log = next(
        row
        for row in caplog.records
        if row.getMessage().startswith("notification.worker.iteration_failed")
    )
    assert calls >= 2
    assert state["last_loop_completed"] is not None
    assert state["consecutive_failures"] == 0
    assert state["last_exception_type"] == "OperationalError"
    assert state["last_exception_correlation_id"]
    assert failure_log.exc_info is not None
