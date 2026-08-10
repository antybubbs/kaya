"""Transactional notification outbox creation and restart-safe processing."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from app.db.session import SessionLocal, database_write_context
from app.models.models import NotificationEvent, NotificationOutbox
from app.services.notification_registry import event_type
from app.services.notifications import publish, safe_target_route

logger = logging.getLogger(__name__)
MAX_OUTBOX_RETRIES = 6
STALE_CLAIM_SECONDS = 300


def _clean(value: str, maximum: int, field: str) -> str:
    cleaned = " ".join(str(value or "").split())
    if not cleaned or len(cleaned) > maximum or any(ord(char) < 32 for char in cleaned):
        raise ValueError(f"Invalid notification outbox {field}")
    return cleaned


def _safe_metadata(metadata: dict | None) -> dict:
    result = {}
    for key, value in list((metadata or {}).items())[:20]:
        if isinstance(value, str):
            value = value[:500]
        if isinstance(value, (str, int, float, bool, type(None))):
            result[str(key)[:80]] = value
    return result


def enqueue_notification(
    db: Session,
    *,
    event_type_id: str,
    title: str,
    message: str,
    target_route: str | None = None,
    source_entity_type: str | None = None,
    source_entity_id: str | int | None = None,
    deduplication_key: str | None = None,
    resolve_deduplication_key: str | None = None,
    recipient_ids: list[int] | None = None,
    severity: str | None = None,
    metadata: dict | None = None,
    created_by_user_id: int | None = None,
    correlation_id: str | None = None,
    resolved: bool = False,
    available_at: datetime | None = None,
) -> NotificationOutbox:
    """Add a validated outbox row without committing the caller's transaction."""
    definition = event_type(event_type_id)
    title = _clean(title, 160, "title")
    message = _clean(message, 500, "message")
    if definition.sensitive_payload:
        title = definition.display_name
        message = "Open Kaya to review this security-sensitive event."
    target_route = safe_target_route(target_route)
    deduplication_key = (
        _clean(deduplication_key, 255, "deduplication key")
        if deduplication_key
        else None
    )
    resolve_deduplication_key = (
        _clean(resolve_deduplication_key, 255, "resolution key")
        if resolve_deduplication_key
        else None
    )
    clean_recipient_ids = None
    if recipient_ids is not None:
        clean_recipient_ids = sorted(
            {value for value in recipient_ids if isinstance(value, int) and value > 0}
        )[:10000]
    correlation_id = _clean(correlation_id or uuid4().hex, 64, "correlation ID")

    if deduplication_key:
        existing = (
            db.query(NotificationOutbox)
            .filter(
                NotificationOutbox.event_type == event_type_id,
                NotificationOutbox.deduplication_key == deduplication_key,
                NotificationOutbox.status.in_(["pending", "processing", "retry"]),
            )
            .order_by(NotificationOutbox.created_at.desc())
            .first()
        )
        if existing:
            logger.info(
                "notification.outbox.suppressed reason=duplicate_outbox outbox_id=%s "
                "event_type=%s correlation_id=%s",
                existing.id,
                event_type_id,
                correlation_id,
            )
            return existing

    row = NotificationOutbox(
        event_type=event_type_id,
        title=title,
        message=message,
        target_route=target_route,
        source_entity_type=(str(source_entity_type)[:80] if source_entity_type else None),
        source_entity_id=(
            str(source_entity_id)[:120] if source_entity_id is not None else None
        ),
        deduplication_key=deduplication_key,
        resolve_deduplication_key=resolve_deduplication_key,
        recipient_ids_json=(
            json.dumps(clean_recipient_ids, separators=(",", ":"))
            if clean_recipient_ids is not None
            else None
        ),
        severity=severity,
        metadata_json=(
            json.dumps(_safe_metadata(metadata), separators=(",", ":"))
            if metadata
            else None
        ),
        created_by_user_id=created_by_user_id,
        correlation_id=correlation_id,
        resolved=resolved,
        next_retry_at=available_at,
    )
    db.add(row)
    db.flush()
    logger.info(
        "notification.outbox.created outbox_id=%s event_type=%s source_entity_type=%s "
        "source_entity_id=%s correlation_id=%s",
        row.id,
        row.event_type,
        row.source_entity_type or "",
        row.source_entity_id or "",
        row.correlation_id,
    )
    return row


def _claim_due(session_factory=SessionLocal) -> int | None:
    now = datetime.utcnow()
    stale_before = now - timedelta(seconds=STALE_CLAIM_SECONDS)
    with database_write_context("notification_outbox", "claim_due"), session_factory() as db:
        stale = (
            db.query(NotificationOutbox)
            .filter(
                NotificationOutbox.status == "processing",
                NotificationOutbox.claimed_at < stale_before,
            )
            .all()
        )
        for row in stale:
            row.status = "retry"
            row.failure_reason_code = "stale_claim_recovered"
            row.next_retry_at = now
        row = (
            db.query(NotificationOutbox)
            .filter(
                NotificationOutbox.status.in_(["pending", "retry"]),
                (
                    NotificationOutbox.next_retry_at.is_(None)
                    | (NotificationOutbox.next_retry_at <= now)
                ),
            )
            .order_by(NotificationOutbox.created_at.asc(), NotificationOutbox.id.asc())
            .first()
        )
        if not row:
            db.commit()
            return None
        row.status = "processing"
        row.claimed_at = now
        row.failure_reason_code = None
        row_id = row.id
        db.commit()
        return row_id


def _decode_json(value: str | None, fallback):
    if not value:
        return fallback
    parsed = json.loads(value)
    return parsed


def _process_claimed(row_id: int, session_factory=SessionLocal) -> bool:
    with database_write_context("notification_outbox", "publish_claimed"), session_factory() as db:
        row = db.get(NotificationOutbox, row_id)
        if not row or row.status != "processing":
            return False
        try:
            diagnostics: dict = {}
            if row.resolve_deduplication_key:
                db.query(NotificationEvent).filter(
                    NotificationEvent.deduplication_key
                    == row.resolve_deduplication_key,
                    NotificationEvent.resolved_at.is_(None),
                ).update(
                    {NotificationEvent.resolved_at: datetime.utcnow()},
                    synchronize_session=False,
                )
            event = publish(
                db,
                event_type_id=row.event_type,
                title=row.title,
                message=row.message,
                target_route=row.target_route,
                source_entity_type=row.source_entity_type,
                source_entity_id=row.source_entity_id,
                deduplication_key=row.deduplication_key,
                recipient_ids=_decode_json(row.recipient_ids_json, None),
                severity=row.severity,
                metadata=_decode_json(row.metadata_json, {}),
                created_by_user_id=row.created_by_user_id,
                correlation_id=row.correlation_id,
                resolved=row.resolved,
                commit=False,
                diagnostics=diagnostics,
            )
            now = datetime.utcnow()
            row.status = "processed" if event else "suppressed"
            row.failure_reason_code = (
                None
                if event
                else diagnostics.get("suppression_reason", "publication_suppressed")
            )
            row.result_json = json.dumps(diagnostics, separators=(",", ":"))
            row.notification_event_id = event.id if event else None
            row.processed_at = now
            row.claimed_at = None
            row.next_retry_at = None
            db.commit()
            logger.info(
                "notification.outbox.processed outbox_id=%s event_id=%s event_type=%s "
                "status=%s correlation_id=%s",
                row.id,
                row.notification_event_id,
                row.event_type,
                row.status,
                row.correlation_id,
            )
            return True
        except Exception as exc:
            db.rollback()
            failed = db.get(NotificationOutbox, row_id)
            if not failed:
                return False
            failed.retry_count = (failed.retry_count or 0) + 1
            failed.claimed_at = None
            failed.failure_reason_code = "publication_error"
            if failed.retry_count >= MAX_OUTBOX_RETRIES:
                failed.status = "quarantined"
                failed.quarantined_at = datetime.utcnow()
                failed.next_retry_at = None
            else:
                failed.status = "retry"
                failed.next_retry_at = datetime.utcnow() + timedelta(
                    seconds=min(3600, 2 ** failed.retry_count * 15)
                )
            db.commit()
            logger.warning(
                "notification.outbox.failed outbox_id=%s event_type=%s reason_code=%s "
                "retry_count=%s quarantined=%s exception_type=%s correlation_id=%s",
                failed.id,
                failed.event_type,
                failed.failure_reason_code,
                failed.retry_count,
                failed.status == "quarantined",
                type(exc).__name__,
                failed.correlation_id,
            )
            return False


def process_outbox(limit: int = 50, session_factory=SessionLocal) -> int:
    processed = 0
    for _ in range(max(1, min(limit, 250))):
        row_id = _claim_due(session_factory)
        if row_id is None:
            break
        processed += int(_process_claimed(row_id, session_factory))
    return processed


async def notification_outbox_loop(heartbeat=None) -> None:
    while True:
        if heartbeat:
            heartbeat()
        try:
            await asyncio.to_thread(process_outbox)
        except Exception:
            logger.exception("notification.outbox.worker_iteration_failed")
        await asyncio.sleep(5)
