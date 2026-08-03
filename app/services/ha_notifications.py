"""Safe notification publication helpers for the High Availability module."""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import (
    HACluster,
    HAFailoverRun,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationOutbox,
    UserNotification,
)
from app.services.notification_outbox import enqueue_notification


logger = logging.getLogger(__name__)


def resolve_ha_notification(db: Session, deduplication_key: str) -> bool:
    """Resolve an active HA incident without emitting or exposing its payload."""
    rows = db.query(NotificationEvent).filter_by(
        deduplication_key=deduplication_key,
        resolved_at=None,
    ).all()
    for row in rows:
        row.resolved_at = datetime.utcnow()
    pending = db.query(NotificationOutbox.id).filter(
        NotificationOutbox.deduplication_key == deduplication_key,
        NotificationOutbox.status.in_(["pending", "processing", "retry"]),
    ).first()
    if rows:
        db.commit()
    return bool(rows or pending)


def delivery_summary(db: Session, event_id: int) -> dict[str, dict[str, int]]:
    rows = (
        db.query(NotificationDeliveryAttempt.channel, NotificationDeliveryAttempt.status)
        .join(UserNotification, UserNotification.id == NotificationDeliveryAttempt.user_notification_id)
        .filter(UserNotification.notification_event_id == event_id)
        .all()
    )
    summary: dict[str, dict[str, int]] = {}
    for channel in ("push", "email"):
        counts = Counter(status for row_channel, status in rows if row_channel == channel)
        summary[channel] = {str(status): count for status, count in sorted(counts.items())}
        summary[channel]["total"] = sum(counts.values())
    return summary


def refresh_notification_diagnostics(db: Session, diagnostics: dict) -> dict:
    """Refresh delivery state from safe relational counts for operation history."""
    refreshed: dict = {}
    for stage, value in list(diagnostics.items())[:10]:
        item = dict(value) if isinstance(value, dict) else {}
        event_id = item.get("event_id")
        outbox_id = item.get("outbox_id")
        if not isinstance(event_id, int) and isinstance(outbox_id, int):
            outbox = db.get(NotificationOutbox, outbox_id)
            if outbox:
                event_id = outbox.notification_event_id
                item["status"] = outbox.status
                item["reason"] = outbox.failure_reason_code
        event = db.get(NotificationEvent, event_id) if isinstance(event_id, int) else None
        if event is not None:
            recipients = db.query(UserNotification).filter_by(notification_event_id=event.id).count()
            item.update({
                "status": "created",
                "recipients": recipients,
                "in_app": recipients,
                "delivery": delivery_summary(db, event.id),
            })
        refreshed[str(stage)[:40]] = item
    return refreshed


def publish_ha_notification(
    db: Session,
    cluster: HACluster,
    *,
    event_type_id: str,
    title: str,
    message: str,
    deduplication_key: str,
    source_entity_type: str,
    source_entity_id: str,
    correlation_id: str,
    created_by_user_id: int | None = None,
    metadata: dict | None = None,
) -> dict:
    """Publish after source-state commit and return only safe operational counts."""
    try:
        outbox = enqueue_notification(
            db,
            event_type_id=event_type_id,
            title=title,
            message=message,
            target_route=f"/high-availability/clusters/{cluster.public_id}/testing",
            source_entity_type=source_entity_type,
            source_entity_id=source_entity_id,
            deduplication_key=deduplication_key,
            created_by_user_id=created_by_user_id,
            correlation_id=correlation_id,
            metadata=metadata,
        )
        db.commit()
        return {
            "event_type": event_type_id,
            "status": "queued",
            "outbox_id": outbox.id,
            "recipients": 0,
            "in_app": 0,
            "delivery": {"push": {"total": 0}, "email": {"total": 0}},
        }
    except Exception:
        # The HA source transition was committed before this helper was entered;
        # an outbox persistence failure must not undo that completed operation.
        db.rollback()
        logger.exception(
            "ha.notification.failed",
            extra={
                "cluster_id": cluster.public_id,
                "event_type": event_type_id,
                "correlation_id": correlation_id,
            },
        )
        return {"event_type": event_type_id, "status": "failed", "reason": "publication_error"}


def record_run_notification_diagnostic(db: Session, run_id: int, stage: str, diagnostic: dict) -> None:
    """Persist a bounded, non-sensitive diagnostic without altering HA outcome state."""
    run = db.get(HAFailoverRun, run_id)
    if run is None:
        return
    try:
        report = json.loads(run.report_json or "{}")
    except (TypeError, json.JSONDecodeError):
        report = {}
    notifications = dict(report.get("notifications") or {})
    notifications[str(stage)[:40]] = diagnostic
    report["notifications"] = notifications
    run.report_json = json.dumps(report, sort_keys=True)
    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception(
            "ha.notification.diagnostic_failed",
            extra={"run_id": run.public_id, "stage": str(stage)[:40]},
        )
