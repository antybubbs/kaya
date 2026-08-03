"""Supervision, reconciliation, and health for notification background workers."""

from __future__ import annotations

import asyncio
import logging
import re
import threading
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import func

from app.db.session import SessionLocal
from app.models.models import (
    NetworkMonitor,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationOutbox,
    NotificationReconciliationFailure,
    PushSubscription,
    UserNotification,
)
from app.services.network_monitor import monitor_label
from app.services.notification_delivery import deliver_queued
from app.services.notification_outbox import enqueue_notification, process_outbox

logger = logging.getLogger(__name__)
SUPERVISOR_INTERVAL_SECONDS = 5
WORKER_OPERATION_TIMEOUT_SECONDS = 120
RECONCILIATION_INTERVAL_SECONDS = 300
HEALTHY_RECOVERY_SECONDS = 120
MAX_RECONCILIATION_ITEM_ATTEMPTS = 5
RESTART_BACKOFF_SECONDS = (5, 15, 30, 60)
ITERATION_FAILURE_BACKOFF_SECONDS = (5, 15, 30, 60)
WORKER_INTERVALS = {"outbox": 5, "delivery": 10, "reconciliation": 300}

_guard = threading.Lock()
_supervisor_task: asyncio.Task | None = None
_shutdown_requested = False
_tasks: dict[str, asyncio.Task] = {}
_restart_counts = {"outbox": 0, "delivery": 0, "reconciliation": 0}
_started_at: datetime | None = None
_last_reconciliation: datetime | None = None
_last_reconciliation_result: dict[str, int] | None = None
_unhealthy_alerts: set[str] = set()


def _initial_worker_state(name: str) -> dict:
    return {
        "worker_name": name,
        "task_name": f"notification-{name}-worker",
        "task_id": None,
        "started_at": None,
        "last_loop_started": None,
        "last_loop_completed": None,
        "last_successful_reconciliation": None,
        "last_heartbeat": None,
        "next_run_at": None,
        "current_operation": "not_started",
        "current_record_id": None,
        "loop_iteration": 0,
        "consecutive_failures": 0,
        "consecutive_restarts": 0,
        "last_exception_type": None,
        "last_exception_message": None,
        "last_exception_correlation_id": None,
        "last_exception_at": None,
        "restart_not_before": None,
        "healthy_since": None,
        "degraded_since": None,
    }


_worker_states = {
    name: _initial_worker_state(name)
    for name in ("outbox", "delivery", "reconciliation")
}


def _utc(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") + "Z" if value else None


def _safe_exception_message(exc: BaseException) -> str:
    message = " ".join(str(exc).split())[:500]
    message = re.sub(r"https?://\S+", "[redacted-url]", message)
    message = re.sub(r"\b[A-Za-z0-9_-]{40,}\b", "[redacted-value]", message)
    return message or type(exc).__name__


def _state_snapshot(name: str) -> dict:
    with _guard:
        return dict(_worker_states[name])


def _set_state(name: str, **values) -> None:
    with _guard:
        _worker_states[name].update(values)


def _operation_for(name: str):
    if name == "outbox":
        return process_outbox
    if name == "delivery":
        return deliver_queued
    return reconcile_notifications


def _queue_worker_failure(name: str, reason: str, correlation_id: str) -> None:
    """Queue one active-condition alert without feeding a restart alert loop."""
    key = f"system:notification-worker:{name}:failed"
    try:
        with SessionLocal() as db:
            active = db.query(NotificationEvent.id).filter_by(
                deduplication_key=key, resolved_at=None
            ).first()
            pending = db.query(NotificationOutbox.id).filter(
                NotificationOutbox.deduplication_key == key,
                NotificationOutbox.status.in_(["pending", "processing", "retry"]),
            ).first()
            if active or pending:
                _unhealthy_alerts.add(name)
                return
            restarts = _restart_counts[name] + 1
            title = (
                "Notification processing degraded"
                if restarts >= 3
                else f"Notification {name} worker stopped"
            )
            message = (
                f"The {name} worker has failed {restarts} times. Some notifications "
                f"may be delayed. Review Delivery Health. Reference: {correlation_id[:8]}."
                if restarts >= 3
                else f"Kaya will restart the {name} worker after controlled backoff. "
                f"Notification processing may be delayed. Reference: {correlation_id[:8]}."
            )
            enqueue_notification(
                db,
                event_type_id="system.background_task.failed",
                title=title,
                message=message,
                target_route="/system/site-administration/notifications",
                source_entity_type="notification_worker",
                source_entity_id=name,
                deduplication_key=key,
                correlation_id=correlation_id,
                metadata={"worker": name, "reason_code": reason},
            )
            db.commit()
        _unhealthy_alerts.add(name)
    except Exception:
        logger.exception(
            "notification.worker.failure_alert_queue_failed worker_name=%s "
            "correlation_id=%s",
            name,
            correlation_id,
        )


def _resolve_worker_failure(name: str) -> None:
    try:
        with SessionLocal() as db:
            changed = db.query(NotificationEvent).filter(
                NotificationEvent.deduplication_key
                == f"system:notification-worker:{name}:failed",
                NotificationEvent.resolved_at.is_(None),
            ).update(
                {NotificationEvent.resolved_at: datetime.utcnow()},
                synchronize_session=False,
            )
            db.commit()
        if changed:
            logger.info("notification.worker.recovered worker_name=%s", name)
        _unhealthy_alerts.discard(name)
    except Exception:
        logger.exception("notification.worker.failure_alert_resolve_failed worker_name=%s", name)


def _failure_due(db, monitor_id: int, operation: str, now: datetime) -> bool:
    failure = db.query(NotificationReconciliationFailure).filter_by(
        item_type="network_monitor", item_id=str(monitor_id), operation=operation
    ).first()
    if not failure or failure.status == "resolved":
        return True
    if failure.status in {"quarantined", "dismissed"}:
        return False
    return failure.next_retry_at is None or failure.next_retry_at <= now


def _resolve_item_failure(db, monitor_id: int, operation: str, now: datetime) -> None:
    failure = db.query(NotificationReconciliationFailure).filter_by(
        item_type="network_monitor", item_id=str(monitor_id), operation=operation
    ).first()
    if failure and failure.status not in {"resolved", "dismissed"}:
        failure.status = "resolved"
        failure.resolved_at = now
        failure.next_retry_at = None
        db.query(NotificationEvent).filter(
            NotificationEvent.deduplication_key
            == f"system:notification-reconciliation-item:network_monitor:{monitor_id}:{operation}:quarantined",
            NotificationEvent.resolved_at.is_(None),
        ).update(
            {NotificationEvent.resolved_at: now}, synchronize_session=False
        )


def _record_item_failure(monitor_id: int, operation: str, exc: Exception) -> None:
    now = datetime.utcnow()
    with SessionLocal() as db:
        failure = db.query(NotificationReconciliationFailure).filter_by(
            item_type="network_monitor", item_id=str(monitor_id), operation=operation
        ).first()
        if not failure:
            failure = NotificationReconciliationFailure(
                item_type="network_monitor",
                item_id=str(monitor_id),
                operation=operation,
                correlation_id=uuid4().hex,
            )
            db.add(failure)
            db.flush()
        failure.attempt_count = (failure.attempt_count or 0) + 1
        failure.last_exception_type = type(exc).__name__[:120]
        failure.last_error_code = "reconciliation_item_error"
        failure.resolved_at = None
        if failure.attempt_count >= MAX_RECONCILIATION_ITEM_ATTEMPTS:
            failure.status = "quarantined"
            failure.quarantined_at = now
            failure.next_retry_at = None
            enqueue_notification(
                db,
                event_type_id="system.background_task.failed",
                title="Notification reconciliation item quarantined",
                message=(
                    "Kaya isolated a repeatedly failing reconciliation item. "
                    f"Review Delivery Health. Reference: {failure.correlation_id[:8]}."
                ),
                target_route="/system/site-administration/notifications",
                source_entity_type="notification_reconciliation_failure",
                source_entity_id=failure.id,
                deduplication_key=(
                    "system:notification-reconciliation-item:network_monitor:"
                    f"{monitor_id}:{operation}:quarantined"
                ),
                correlation_id=failure.correlation_id,
                metadata={
                    "item_type": "network_monitor",
                    "operation": operation,
                    "reason_code": "reconciliation_item_quarantined",
                },
            )
        else:
            failure.status = "retry"
            failure.next_retry_at = now + timedelta(
                seconds=min(3600, 15 * (2 ** failure.attempt_count))
            )
        db.commit()
        correlation_id = failure.correlation_id
        quarantined = failure.status == "quarantined"
    logger.error(
        "notification.reconciliation.item_failed item_type=network_monitor item_id=%s "
        "operation=%s exception_type=%s exception_message=%r quarantined=%s "
        "correlation_id=%s",
        monitor_id,
        operation,
        type(exc).__name__,
        _safe_exception_message(exc),
        quarantined,
        correlation_id,
        exc_info=(type(exc), exc, exc.__traceback__),
    )


def _reconcile_monitor_item(monitor_id: int, operation: str) -> str:
    now = datetime.utcnow()
    with SessionLocal() as db:
        if not _failure_due(db, monitor_id, operation, now):
            return "deferred"
        monitor = db.get(NetworkMonitor, monitor_id)
        if not monitor:
            _resolve_item_failure(db, monitor_id, operation, now)
            db.commit()
            return "stale_source"
        incident_key = f"ipwan:host:{monitor.id}:offline"
        if operation == "offline":
            if (
                not monitor.is_enabled
                or monitor.is_in_maintenance
                or monitor.last_status not in {"offline", "down"}
            ):
                _resolve_item_failure(db, monitor_id, operation, now)
                db.commit()
                return "stale_source"
            active = db.query(NotificationEvent.id).filter_by(
                deduplication_key=incident_key, resolved_at=None
            ).first()
            pending = db.query(NotificationOutbox.id).filter(
                NotificationOutbox.deduplication_key == incident_key,
                NotificationOutbox.status.in_(["pending", "processing", "retry"]),
            ).first()
            if active or pending:
                outcome = "existing"
            else:
                enqueue_notification(
                    db,
                    event_type_id="ipwan.host.offline",
                    title="Host offline",
                    message=f"{monitor_label(monitor)} is no longer responding.",
                    target_route=f"/networking/ip-wan-monitor/{monitor.id}",
                    source_entity_type="network_monitor",
                    source_entity_id=monitor.id,
                    deduplication_key=incident_key,
                    metadata={"reconciled": True},
                )
                outcome = "created"
        else:
            if monitor.is_in_maintenance or monitor.last_status not in {
                "healthy",
                "warning",
                "critical",
            }:
                _resolve_item_failure(db, monitor_id, operation, now)
                db.commit()
                return "stale_source"
            active = db.query(NotificationEvent).filter_by(
                deduplication_key=incident_key, resolved_at=None
            ).order_by(NotificationEvent.created_at.desc()).first()
            if not active:
                outcome = "existing"
            else:
                repair_key = (
                    f"ipwan:host:{monitor.id}:reconciled-recovery:{active.id}"
                )
                existing = db.query(NotificationOutbox.id).filter_by(
                    deduplication_key=repair_key
                ).first()
                if existing:
                    outcome = "existing"
                else:
                    enqueue_notification(
                        db,
                        event_type_id="ipwan.host.recovered",
                        title="Host recovered",
                        message=f"{monitor_label(monitor)} is responding again.",
                        target_route=f"/networking/ip-wan-monitor/{monitor.id}",
                        source_entity_type="network_monitor",
                        source_entity_id=monitor.id,
                        deduplication_key=repair_key,
                        resolve_deduplication_key=incident_key,
                        resolved=True,
                        metadata={"reconciled": True},
                    )
                    outcome = "created"
        _resolve_item_failure(db, monitor_id, operation, now)
        db.commit()
        return outcome


def reconcile_notifications() -> dict[str, int]:
    """Repair each monitor independently so one malformed row cannot stop the pass."""
    global _last_reconciliation, _last_reconciliation_result
    with SessionLocal() as db:
        candidates = db.query(NetworkMonitor.id, NetworkMonitor.last_status).filter(
            NetworkMonitor.is_enabled.is_(True),
            NetworkMonitor.is_in_maintenance.is_(False),
            NetworkMonitor.last_status.in_(
                ["offline", "down", "healthy", "warning", "critical"]
            ),
        ).order_by(NetworkMonitor.id.asc()).limit(1000).all()
    result = {
        "candidates": len(candidates),
        "missing_alerts_repaired": 0,
        "existing_alerts": 0,
        "stale_alerts_queued_for_resolution": 0,
        "deferred_items": 0,
        "failed_items": 0,
    }
    for monitor_id, status in candidates:
        operation = "offline" if status in {"offline", "down"} else "recovery"
        _set_state("reconciliation", current_record_id=str(monitor_id))
        try:
            outcome = _reconcile_monitor_item(monitor_id, operation)
            if outcome == "created" and operation == "offline":
                result["missing_alerts_repaired"] += 1
            elif outcome == "created":
                result["stale_alerts_queued_for_resolution"] += 1
            elif outcome == "existing":
                result["existing_alerts"] += 1
            elif outcome == "deferred":
                result["deferred_items"] += 1
        except Exception as exc:
            result["failed_items"] += 1
            _record_item_failure(monitor_id, operation, exc)
        finally:
            _set_state("reconciliation", current_record_id=None)
    with _guard:
        _last_reconciliation = datetime.utcnow()
        _last_reconciliation_result = dict(result)
    logger.info("notification.reconciliation.completed result=%s", result)
    return result


async def _worker_loop(name: str) -> None:
    operation = _operation_for(name)
    interval = WORKER_INTERVALS[name]
    while True:
        started = datetime.utcnow()
        state = _state_snapshot(name)
        _set_state(
            name,
            last_loop_started=started,
            next_run_at=None,
            current_operation=f"{name}_iteration",
            loop_iteration=state["loop_iteration"] + 1,
        )
        failed = False
        try:
            await asyncio.to_thread(operation)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failed = True
            correlation_id = uuid4().hex
            current = _state_snapshot(name)
            _set_state(
                name,
                consecutive_failures=current["consecutive_failures"] + 1,
                last_exception_type=type(exc).__name__,
                last_exception_message=_safe_exception_message(exc),
                last_exception_correlation_id=correlation_id,
                last_exception_at=datetime.utcnow(),
                healthy_since=None,
                degraded_since=current["degraded_since"] or datetime.utcnow(),
            )
            details = _state_snapshot(name)
            logger.error(
                "notification.worker.iteration_failed worker_name=%s task_id=%s "
                "exception_type=%s exception_message=%r last_heartbeat=%s "
                "current_operation=%s current_record_id=%s loop_iteration=%s "
                "restart_count=%s correlation_id=%s",
                name,
                details["task_id"],
                type(exc).__name__,
                _safe_exception_message(exc),
                _utc(details["last_heartbeat"]),
                details["current_operation"],
                details["current_record_id"],
                details["loop_iteration"],
                _restart_counts[name],
                correlation_id,
                exc_info=(type(exc), exc, exc.__traceback__),
            )
        completed = datetime.utcnow()
        current = _state_snapshot(name)
        if not failed:
            _set_state(
                name,
                last_loop_completed=completed,
                last_heartbeat=completed,
                last_successful_reconciliation=(
                    completed
                    if name == "reconciliation"
                    else current["last_successful_reconciliation"]
                ),
                consecutive_failures=0,
                healthy_since=current["healthy_since"] or completed,
            )
        delay = (
            ITERATION_FAILURE_BACKOFF_SECONDS[
                min(
                    max(0, current["consecutive_failures"] - 1),
                    len(ITERATION_FAILURE_BACKOFF_SECONDS) - 1,
                )
            ]
            if failed
            else interval
        )
        _set_state(
            name,
            current_operation="idle",
            current_record_id=None,
            next_run_at=datetime.utcnow() + timedelta(seconds=delay),
        )
        await asyncio.sleep(delay)


def _create_worker(name: str) -> asyncio.Task:
    with _guard:
        existing = _tasks.get(name)
        if existing and not existing.done():
            return existing
        task_id = uuid4().hex[:12]
        task = asyncio.create_task(
            _worker_loop(name), name=f"notification-{name}-worker"
        )
        _tasks[name] = task
        state = _worker_states[name]
        state.update(
            task_id=task_id,
            started_at=datetime.utcnow(),
            current_operation="starting",
            restart_not_before=None,
        )
        return task


def _worker_is_stale(name: str, now: datetime) -> bool:
    state = _state_snapshot(name)
    if state["current_operation"] == "idle":
        due = state["next_run_at"]
        return bool(
            due
            and now > due + timedelta(seconds=SUPERVISOR_INTERVAL_SECONDS * 2)
        )
    started = state["last_loop_started"] or state["started_at"]
    return bool(
        started
        and now > started + timedelta(seconds=WORKER_OPERATION_TIMEOUT_SECONDS)
    )


def _log_unhealthy(name: str, reason: str, exc: BaseException | None = None) -> str:
    state = _state_snapshot(name)
    correlation_id = state["last_exception_correlation_id"] or uuid4().hex
    _set_state(
        name,
        last_exception_type=type(exc).__name__ if exc else reason,
        last_exception_message=_safe_exception_message(exc) if exc else reason,
        last_exception_correlation_id=correlation_id,
        last_exception_at=datetime.utcnow(),
        healthy_since=None,
        degraded_since=state["degraded_since"] or datetime.utcnow(),
    )
    logger.critical(
        "notification.worker.unhealthy worker_name=%s task_id=%s exception_type=%s "
        "exception_message=%r last_heartbeat=%s current_operation=%s "
        "current_record_id=%s loop_iteration=%s restart_count=%s correlation_id=%s",
        name,
        state["task_id"],
        type(exc).__name__ if exc else reason,
        _safe_exception_message(exc) if exc else reason,
        _utc(state["last_heartbeat"]),
        state["current_operation"],
        state["current_record_id"],
        state["loop_iteration"],
        _restart_counts[name],
        correlation_id,
        exc_info=(type(exc), exc, exc.__traceback__) if exc else None,
    )
    return correlation_id


async def notification_supervisor_loop() -> None:
    logger.info("notification.supervisor.started")
    for name in ("outbox", "delivery", "reconciliation"):
        _create_worker(name)
    try:
        while True:
            await asyncio.sleep(SUPERVISOR_INTERVAL_SECONDS)
            now = datetime.utcnow()
            for name in ("outbox", "delivery", "reconciliation"):
                with _guard:
                    task = _tasks.get(name)
                    restart_not_before = _worker_states[name]["restart_not_before"]
                if task and not task.done() and not _worker_is_stale(name, now):
                    state = _state_snapshot(name)
                    if state["consecutive_failures"]:
                        correlation_id = (
                            state["last_exception_correlation_id"] or uuid4().hex
                        )
                        await asyncio.to_thread(
                            _queue_worker_failure,
                            name,
                            "iteration_failure",
                            correlation_id,
                        )
                        continue
                    healthy_since = state["healthy_since"]
                    if (
                        name in _unhealthy_alerts
                        and healthy_since
                        and now - healthy_since
                        >= timedelta(seconds=HEALTHY_RECOVERY_SECONDS)
                    ):
                        await asyncio.to_thread(_resolve_worker_failure, name)
                        _set_state(
                            name,
                            degraded_since=None,
                            consecutive_restarts=0,
                        )
                    continue
                if not task and restart_not_before and now < restart_not_before:
                    continue
                if task:
                    exc = None
                    reason = "stale_operation" if not task.done() else "task_stopped"
                    if task.done():
                        if task.cancelled():
                            reason = "unexpected_cancellation"
                        else:
                            try:
                                exc = task.exception()
                            except asyncio.CancelledError:
                                reason = "unexpected_cancellation"
                    correlation_id = _log_unhealthy(name, reason, exc)
                    await asyncio.to_thread(
                        _queue_worker_failure, name, reason, correlation_id
                    )
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    with _guard:
                        _tasks.pop(name, None)
                        _restart_counts[name] += 1
                        _worker_states[name]["consecutive_restarts"] += 1
                        consecutive_restarts = _worker_states[name][
                            "consecutive_restarts"
                        ]
                        delay = RESTART_BACKOFF_SECONDS[
                            min(
                                consecutive_restarts - 1,
                                len(RESTART_BACKOFF_SECONDS) - 1,
                            )
                        ]
                        _worker_states[name]["restart_not_before"] = (
                            datetime.utcnow() + timedelta(seconds=delay)
                        )
                    continue
                _create_worker(name)
    except asyncio.CancelledError:
        raise
    finally:
        with _guard:
            children = list(_tasks.values())
            _tasks.clear()
        for task in children:
            task.cancel()
        await asyncio.gather(*children, return_exceptions=True)
        logger.info("notification.supervisor.stopped")


def start_notification_runtime() -> asyncio.Task:
    global _supervisor_task, _shutdown_requested, _started_at
    with _guard:
        if _supervisor_task and not _supervisor_task.done():
            return _supervisor_task
        _shutdown_requested = False
        _started_at = datetime.utcnow()
        _supervisor_task = asyncio.create_task(
            notification_supervisor_loop(), name="notification-supervisor"
        )
        return _supervisor_task


async def stop_notification_runtime() -> None:
    global _supervisor_task, _shutdown_requested, _started_at
    with _guard:
        _shutdown_requested = True
        task = _supervisor_task
    if task and not task.done():
        task.cancel()
    if task:
        await asyncio.gather(task, return_exceptions=True)
    with _guard:
        _supervisor_task = None
        _started_at = None


def notification_health() -> dict:
    now = datetime.utcnow()
    with _guard:
        tasks = dict(_tasks)
        states = {name: dict(value) for name, value in _worker_states.items()}
        restarts = dict(_restart_counts)
        started_at = _started_at
        reconciliation_at = _last_reconciliation
        reconciliation_result = dict(_last_reconciliation_result or {})
    with SessionLocal() as db:
        pending_outbox = db.query(NotificationOutbox).filter(
            NotificationOutbox.status.in_(["pending", "retry", "processing"])
        )
        queued_delivery = db.query(NotificationDeliveryAttempt).filter(
            NotificationDeliveryAttempt.status.in_(
                ["queued", "temporary_failure", "retry", "processing"]
            )
        )
        oldest_outbox = pending_outbox.with_entities(
            func.min(NotificationOutbox.created_at)
        ).scalar()
        oldest_delivery = queued_delivery.with_entities(
            func.min(NotificationDeliveryAttempt.created_at)
        ).scalar()
        counts = {
            "pending_outbox_items": pending_outbox.count(),
            "stuck_outbox_items": db.query(NotificationOutbox).filter(
                NotificationOutbox.status == "processing",
                NotificationOutbox.claimed_at
                < now - timedelta(seconds=300),
            ).count(),
            "quarantined_outbox_items": db.query(NotificationOutbox)
            .filter_by(status="quarantined").count(),
            "quarantined_reconciliation_items": db.query(
                NotificationReconciliationFailure
            ).filter_by(status="quarantined").count(),
            "retrying_reconciliation_items": db.query(
                NotificationReconciliationFailure
            ).filter_by(status="retry").count(),
            "queued_deliveries": queued_delivery.count(),
            "stuck_delivery_items": db.query(NotificationDeliveryAttempt).filter(
                NotificationDeliveryAttempt.status == "processing",
                NotificationDeliveryAttempt.processing_started_at
                < now - timedelta(seconds=300),
            ).count(),
            "retry_pending_deliveries": db.query(NotificationDeliveryAttempt)
            .filter(NotificationDeliveryAttempt.status.in_(["temporary_failure", "retry"]))
            .count(),
            "active_subscriptions": db.query(PushSubscription)
            .filter_by(status="active", revoked_at=None).count(),
            "expired_subscriptions": db.query(PushSubscription)
            .filter_by(status="expired").count(),
            "in_app_notifications_today": db.query(UserNotification)
            .filter(UserNotification.created_at >= now.replace(hour=0, minute=0, second=0))
            .count(),
        }
        failures = db.query(NotificationReconciliationFailure).filter(
            NotificationReconciliationFailure.status.in_(["retry", "quarantined"])
        ).order_by(NotificationReconciliationFailure.updated_at.desc()).limit(50).all()
        safe_failures = [
            {
                "id": row.id,
                "item_type": row.item_type,
                "item_id": row.item_id,
                "operation": row.operation,
                "status": row.status,
                "attempt_count": row.attempt_count,
                "error_code": row.last_error_code,
                "correlation_id": row.correlation_id,
                "updated_at": _utc(row.updated_at),
            }
            for row in failures
        ]
        push_base = db.query(NotificationDeliveryAttempt).filter_by(channel="push")
        email_base = db.query(NotificationDeliveryAttempt).filter_by(channel="email")
        last_push_attempt = push_base.with_entities(func.max(NotificationDeliveryAttempt.attempted_at)).scalar()
        last_push_accepted = push_base.filter(
            NotificationDeliveryAttempt.status.in_(["accepted", "accepted_by_push_service"])
        ).with_entities(func.max(NotificationDeliveryAttempt.accepted_at)).scalar()
        last_push_failure = push_base.filter(
            NotificationDeliveryAttempt.status.in_([
                "temporary_failure", "permanent_failure", "expired_subscription", "retry_exhausted"
            ])
        ).with_entities(func.max(NotificationDeliveryAttempt.attempted_at)).scalar()
        temporary_failure_count = push_base.filter_by(status="temporary_failure").count()
        permanent_failure_count = push_base.filter(
            NotificationDeliveryAttempt.status.in_([
                "permanent_failure", "expired_subscription", "retry_exhausted"
            ])
        ).count()
        email_queued = email_base.filter(
            NotificationDeliveryAttempt.status.in_(["queued", "temporary_failure", "retry", "processing"])
        ).count()
    workers = {}
    for name in ("outbox", "delivery", "reconciliation"):
        state = states[name]
        running = bool(tasks.get(name) and not tasks[name].done())
        stale = running and _worker_is_stale(name, now)
        workers[name] = {
            "worker_name": name,
            "task_name": state["task_name"],
            "task_id": state["task_id"],
            "running": running,
            "stale": stale,
            "started_at": _utc(state["started_at"]),
            "last_loop_started": _utc(state["last_loop_started"]),
            "last_loop_completed": _utc(state["last_loop_completed"]),
            "last_successful_reconciliation": _utc(state["last_successful_reconciliation"]),
            "last_heartbeat": _utc(state["last_heartbeat"]),
            "next_run_at": _utc(state["next_run_at"]),
            "current_operation": state["current_operation"],
            "current_record_id": state["current_record_id"],
            "loop_iteration": state["loop_iteration"],
            "consecutive_failures": state["consecutive_failures"],
            "consecutive_restarts": state["consecutive_restarts"],
            "restart_count": restarts[name],
            "last_exception": state["last_exception_type"],
            "last_exception_at": _utc(state["last_exception_at"]),
            "last_exception_correlation_id": state["last_exception_correlation_id"],
        }
    degraded = any(
        not item["running"] or item["stale"] or item["consecutive_failures"]
        for item in workers.values()
    )
    degraded = degraded or counts["quarantined_outbox_items"] > 0
    degraded = degraded or counts["quarantined_reconciliation_items"] > 0
    return {
        "status": "degraded" if degraded else "healthy",
        "worker_uptime_seconds": max(0, int((now - started_at).total_seconds())) if started_at else None,
        "workers": workers,
        "oldest_outbox_item": _utc(oldest_outbox),
        "oldest_queued_delivery": _utc(oldest_delivery),
        "last_reconciliation_run": _utc(reconciliation_at),
        "last_reconciliation_result": reconciliation_result,
        "last_reconciliation_exception": workers["reconciliation"]["last_exception"],
        "reconciliation_failures": safe_failures,
        "outbox_worker_running": workers["outbox"]["running"],
        "last_outbox_worker_heartbeat": workers["outbox"]["last_heartbeat"],
        "push_worker_running": workers["delivery"]["running"],
        "last_push_worker_heartbeat": workers["delivery"]["last_heartbeat"],
        "email_worker_running": workers["delivery"]["running"],
        "last_email_worker_heartbeat": workers["delivery"]["last_heartbeat"],
        "last_push_attempt": _utc(last_push_attempt),
        "last_push_accepted": _utc(last_push_accepted),
        "last_push_failure": _utc(last_push_failure),
        "temporary_failure_count": temporary_failure_count,
        "permanent_failure_count": permanent_failure_count,
        "retry_queue_count": counts["retry_pending_deliveries"],
        "email_queued_deliveries": email_queued,
        "watchdog_restart_count": sum(restarts.values()),
        **counts,
    }
