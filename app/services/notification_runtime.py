"""Supervision, reconciliation, and health for notification background workers."""

from __future__ import annotations

import asyncio
import logging
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
    PushSubscription,
    UserNotification,
)
from app.services.network_monitor import monitor_label, reconcile_offline_notifications
from app.services.notification_delivery import notification_delivery_loop
from app.services.notification_outbox import enqueue_notification, notification_outbox_loop

logger = logging.getLogger(__name__)
SUPERVISOR_INTERVAL_SECONDS = 15
WORKER_STALE_SECONDS = 120
RECONCILIATION_INTERVAL_SECONDS = 300

_guard = threading.Lock()
_supervisor_task: asyncio.Task | None = None
_shutdown_requested = False
_tasks: dict[str, asyncio.Task] = {}
_heartbeats: dict[str, datetime | None] = {
    "outbox": None,
    "delivery": None,
    "reconciliation": None,
}
_restart_counts = {"outbox": 0, "delivery": 0, "reconciliation": 0}
_started_at: datetime | None = None
_last_reconciliation: datetime | None = None
_last_reconciliation_result: dict[str, int] | None = None
_last_reconciliation_exception: str | None = None
_unhealthy_alerts: set[str] = set()


def _heartbeat(name: str) -> None:
    with _guard:
        _heartbeats[name] = datetime.utcnow()


def _utc(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") + "Z" if value else None


def _queue_worker_failure(name: str, reason: str) -> None:
    try:
        with SessionLocal() as db:
            enqueue_notification(
                db,
                event_type_id="system.background_task.failed",
                title="Notification worker failure",
                message=f"The {name} notification worker stopped and Kaya initiated recovery.",
                target_route="/system/site-administration/notifications",
                source_entity_type="notification_worker",
                source_entity_id=name,
                deduplication_key=f"system:notification-worker:{name}:failed",
                correlation_id=uuid4().hex,
                metadata={"worker": name, "reason_code": reason},
            )
            db.commit()
        _unhealthy_alerts.add(name)
    except Exception:
        logger.exception("notification.worker.failure_alert_queue_failed worker=%s", name)


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
            _unhealthy_alerts.discard(name)
    except Exception:
        logger.exception("notification.worker.failure_alert_resolve_failed worker=%s", name)


def reconcile_notifications() -> dict[str, int]:
    """Idempotently repair missing IP/WAN alerts and stale active conditions."""
    global _last_reconciliation, _last_reconciliation_result, _last_reconciliation_exception
    _heartbeat("reconciliation")
    with SessionLocal() as db:
        repaired = reconcile_offline_notifications(db)
        healthy_monitors = (
            db.query(NetworkMonitor)
            .filter(
                NetworkMonitor.last_status.in_(["healthy", "warning", "critical"]),
                NetworkMonitor.is_in_maintenance.is_(False),
            )
            .order_by(NetworkMonitor.id.asc())
            .limit(1000)
            .all()
        )
        stale_resolved = 0
        for monitor in healthy_monitors:
            incident_key = f"ipwan:host:{monitor.id}:offline"
            active = (
                db.query(NotificationEvent)
                .filter_by(deduplication_key=incident_key, resolved_at=None)
                .order_by(NotificationEvent.created_at.desc())
                .first()
            )
            if not active:
                continue
            repair_key = f"ipwan:host:{monitor.id}:reconciled-recovery:{active.id}"
            existing = db.query(NotificationOutbox.id).filter_by(
                deduplication_key=repair_key
            ).first()
            if existing:
                continue
            correlation_id = uuid4().hex
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
                correlation_id=correlation_id,
                resolved=True,
                metadata={"reconciled": True},
            )
            stale_resolved += 1
        db.commit()
    result = {
        "missing_alerts_repaired": repaired["created"],
        "existing_alerts": repaired["existing"],
        "stale_alerts_queued_for_resolution": stale_resolved,
    }
    with _guard:
        _last_reconciliation = datetime.utcnow()
        _last_reconciliation_result = result
        _last_reconciliation_exception = None
    logger.info("notification.reconciliation.completed result=%s", result)
    return result


async def _reconciliation_loop() -> None:
    global _last_reconciliation_exception
    while True:
        _heartbeat("reconciliation")
        try:
            await asyncio.to_thread(reconcile_notifications)
        except Exception as exc:
            with _guard:
                _last_reconciliation_exception = type(exc).__name__
            logger.exception("notification.reconciliation.failed")
        await asyncio.sleep(RECONCILIATION_INTERVAL_SECONDS)


def _create_worker(name: str) -> asyncio.Task:
    if name == "outbox":
        coroutine = notification_outbox_loop(lambda: _heartbeat("outbox"))
    elif name == "delivery":
        coroutine = notification_delivery_loop(lambda: _heartbeat("delivery"))
    else:
        coroutine = _reconciliation_loop()
    task = asyncio.create_task(coroutine, name=f"notification-{name}-worker")
    with _guard:
        _tasks[name] = task
        _heartbeats[name] = datetime.utcnow()
    return task


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
                    heartbeat = _heartbeats.get(name)
                stale = bool(
                    heartbeat
                    and heartbeat < now - timedelta(seconds=WORKER_STALE_SECONDS)
                )
                if task and not task.done() and not stale:
                    if name in _unhealthy_alerts:
                        await asyncio.to_thread(_resolve_worker_failure, name)
                    continue
                reason = "stale_heartbeat" if stale else "task_stopped"
                logger.critical(
                    "notification.worker.unhealthy worker=%s reason=%s", name, reason
                )
                await asyncio.to_thread(_queue_worker_failure, name, reason)
                if task and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                with _guard:
                    _restart_counts[name] += 1
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
        heartbeats = dict(_heartbeats)
        restarts = dict(_restart_counts)
        started_at = _started_at
        reconciliation_at = _last_reconciliation
        reconciliation_result = dict(_last_reconciliation_result or {})
        reconciliation_exception = _last_reconciliation_exception
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
            "quarantined_outbox_items": db.query(NotificationOutbox)
            .filter_by(status="quarantined")
            .count(),
            "queued_deliveries": queued_delivery.count(),
            "retry_pending_deliveries": db.query(NotificationDeliveryAttempt)
            .filter(NotificationDeliveryAttempt.status.in_(["temporary_failure", "retry"]))
            .count(),
            "active_subscriptions": db.query(PushSubscription)
            .filter_by(status="active", revoked_at=None)
            .count(),
            "expired_subscriptions": db.query(PushSubscription)
            .filter_by(status="expired")
            .count(),
            "in_app_notifications_today": db.query(UserNotification)
            .filter(UserNotification.created_at >= now.replace(hour=0, minute=0, second=0))
            .count(),
        }
        push_base = db.query(NotificationDeliveryAttempt).filter_by(channel="push")
        email_base = db.query(NotificationDeliveryAttempt).filter_by(channel="email")
        last_push_attempt = push_base.with_entities(
            func.max(NotificationDeliveryAttempt.attempted_at)
        ).scalar()
        last_push_accepted = push_base.filter(
            NotificationDeliveryAttempt.status.in_(
                ["accepted", "accepted_by_push_service"]
            )
        ).with_entities(func.max(NotificationDeliveryAttempt.accepted_at)).scalar()
        last_push_failure = push_base.filter(
            NotificationDeliveryAttempt.status.in_(
                [
                    "temporary_failure",
                    "permanent_failure",
                    "expired_subscription",
                    "retry_exhausted",
                ]
            )
        ).with_entities(func.max(NotificationDeliveryAttempt.attempted_at)).scalar()
        temporary_failure_count = push_base.filter_by(
            status="temporary_failure"
        ).count()
        permanent_failure_count = push_base.filter(
            NotificationDeliveryAttempt.status.in_(
                ["permanent_failure", "expired_subscription", "retry_exhausted"]
            )
        ).count()
        email_queued = email_base.filter(
            NotificationDeliveryAttempt.status.in_(
                ["queued", "temporary_failure", "retry", "processing"]
            )
        ).count()
    workers = {}
    for name in ("outbox", "delivery", "reconciliation"):
        heartbeat = heartbeats.get(name)
        running = bool(tasks.get(name) and not tasks[name].done())
        stale = bool(
            heartbeat and heartbeat < now - timedelta(seconds=WORKER_STALE_SECONDS)
        )
        workers[name] = {
            "running": running,
            "stale": stale,
            "last_heartbeat": _utc(heartbeat),
            "restart_count": restarts[name],
        }
    degraded = any(not item["running"] or item["stale"] for item in workers.values())
    degraded = degraded or counts["quarantined_outbox_items"] > 0
    return {
        "status": "degraded" if degraded else "healthy",
        "worker_uptime_seconds": (
            max(0, int((now - started_at).total_seconds())) if started_at else None
        ),
        "workers": workers,
        "oldest_outbox_item": _utc(oldest_outbox),
        "oldest_queued_delivery": _utc(oldest_delivery),
        "last_reconciliation_run": _utc(reconciliation_at),
        "last_reconciliation_result": reconciliation_result,
        "last_reconciliation_exception": reconciliation_exception,
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
