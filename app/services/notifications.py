"""Central notification publication, policy, deduplication and retention service."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from app.models.models import (
    NotificationCategoryPolicy,
    NotificationEvent,
    NotificationPreference,
    NotificationDeliveryAttempt,
    PushSubscription,
    User,
    UserNotification,
)
from app.services.modules import has_module_access
from app.services.notification_registry import EVENT_TYPES, SEVERITY_ORDER, event_type
from app.services.site_settings import get_site_setting

SAFE_ROUTE = re.compile(r"^/[A-Za-z0-9/_-]{0,480}$")
PUSH_SERVICE_SUFFIXES = (
    "fcm.googleapis.com",
    ".push.services.mozilla.com",
    ".push.apple.com",
    ".notify.windows.com",
)
logger = logging.getLogger(__name__)


def safe_target_route(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) > 500 or not SAFE_ROUTE.fullmatch(value):
        raise ValueError(
            "Notification target must be a Kaya-relative route without a query or fragment"
        )
    parsed = urlsplit(value)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or value.startswith("//")
    ):
        raise ValueError("Unsafe notification target")
    return value


def validate_push_endpoint(value: str) -> str:
    """Deny arbitrary outbound targets; browsers use a small set of push vendors."""
    if len(value) > 2048:
        raise ValueError("Push endpoint is too long")
    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid push endpoint port") from exc
    approved_host = any(
        hostname == suffix or (suffix.startswith(".") and hostname.endswith(suffix))
        for suffix in PUSH_SERVICE_SUFFIXES
    )
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or port not in {None, 443}
        or not approved_host
    ):
        raise ValueError("Push endpoint is not an approved browser push service")
    try:
        addresses = {result[4][0] for result in socket.getaddrinfo(hostname, 443)}
    except socket.gaierror as exc:
        raise ValueError("Push endpoint could not be resolved") from exc
    if not addresses or any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        raise ValueError("Push endpoint did not resolve only to public addresses")
    return value


def _clean_text(value: str, maximum: int, field: str) -> str:
    clean = " ".join(str(value or "").split())
    if not clean or len(clean) > maximum or any(ord(char) < 32 for char in clean):
        raise ValueError(f"Invalid notification {field}")
    return clean


def policy_for(db: Session, identifier: str) -> NotificationCategoryPolicy | None:
    return db.get(NotificationCategoryPolicy, identifier)


def preference_allows(
    db: Session, user_id: int, identifier: str, severity: str, channel: str
) -> bool:
    policy = policy_for(db, identifier)
    definition = event_type(identifier)
    if policy and (
        not policy.enabled
        or SEVERITY_ORDER[severity] < SEVERITY_ORDER.get(policy.minimum_severity, 0)
        or (definition.recovery and not policy.recovery_enabled)
    ):
        return False
    allowed = {"in_app": True, "push": False, "email": False}
    if policy:
        allowed = {
            "in_app": policy.in_app_allowed,
            "push": policy.push_allowed,
            "email": policy.email_allowed,
        }
    preference = (
        db.query(NotificationPreference)
        .filter_by(user_id=user_id, event_type=identifier)
        .first()
    )
    if preference:
        if definition.recovery and not preference.recovery_enabled:
            return False
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER.get(
            preference.minimum_severity, 0
        ):
            return False
        if (
            channel != "in_app"
            and severity != "critical"
            and preference.quiet_hours_start
            and preference.quiet_hours_end
        ):
            try:
                local_time = datetime.now(
                    ZoneInfo(preference.timezone or "UTC")
                ).strftime("%H:%M")
            except ZoneInfoNotFoundError:
                local_time = datetime.utcnow().strftime("%H:%M")
            start, end = preference.quiet_hours_start, preference.quiet_hours_end
            quiet = (
                start <= local_time < end
                if start < end
                else local_time >= start or local_time < end
            )
            if quiet:
                return False
        chosen = {
            "in_app": preference.in_app_enabled,
            "push": preference.push_enabled,
            "email": preference.email_enabled,
        }[channel]
        return allowed[channel] and (
            chosen or bool(policy and not policy.user_can_opt_out)
        )
    return allowed[channel] and bool(
        policy.default_enabled if policy else channel == "in_app"
    )


def resolve_recipients(
    db: Session, module: str, recipient_ids: list[int] | None
) -> list[User]:
    query = db.query(User).filter(User.is_active.is_(True))
    if recipient_ids is not None:
        clean_ids = {
            int(value)
            for value in recipient_ids
            if isinstance(value, int) and value > 0
        }
        if not clean_ids:
            return []
        query = query.filter(User.id.in_(clean_ids))
    try:
        maximum = max(
            1,
            min(int(get_site_setting(db, "notifications_max_per_event") or 250), 10000),
        )
    except ValueError:
        maximum = 250
    users = query.order_by(User.id.asc()).limit(maximum).all()
    if module == "system" and recipient_ids is None:
        return [user for user in users if user.role == "admin"]
    if module == "system":
        return users
    # Administrators are infrastructure-wide notification recipients even when
    # an older installation lacks a materialised module-allocation row. This
    # does not grant route or object access; those checks remain independent.
    return [
        user
        for user in users
        if user.role == "admin" or has_module_access(db, user, module)
    ]


def publish(
    db: Session,
    *,
    event_type_id: str,
    title: str,
    message: str,
    target_route: str | None = None,
    source_entity_type: str | None = None,
    source_entity_id: str | int | None = None,
    deduplication_key: str | None = None,
    recipient_ids: list[int] | None = None,
    severity: str | None = None,
    metadata: dict | None = None,
    created_by_user_id: int | None = None,
    correlation_id: str | None = None,
    resolved: bool = False,
    commit: bool = True,
    diagnostics: dict | None = None,
) -> NotificationEvent | None:
    # Diagnostic requests may explicitly exercise one channel.  This is kept
    # in the persisted metadata so the outbox remains restart-safe, while
    # ordinary production publications continue to use category policy.
    diagnostic_channel = (metadata or {}).get("diagnostic_channel")
    if diagnostic_channel not in {"in_app", "push", "email"}:
        diagnostic_channel = None
    diagnostic_subscription_id = (metadata or {}).get("diagnostic_subscription_id")
    if not isinstance(diagnostic_subscription_id, int) or diagnostic_subscription_id <= 0:
        diagnostic_subscription_id = None
    if diagnostics is not None:
        diagnostics.clear()
        diagnostics["event_registered"] = False
    safe_log_fields = {
        "event_type": str(event_type_id)[:120],
        "source_entity_type": str(source_entity_type or "")[:80],
        "source_entity_id": str(source_entity_id or "")[:120],
        "deduplication_key": str(deduplication_key or "")[:255],
        "correlation_id": str(correlation_id or "")[:64],
    }
    try:
        definition = event_type(event_type_id)
    except ValueError:
        logger.error(
            "notification.publish.failed reason=unknown_event %s", safe_log_fields
        )
        raise
    safe_log_fields["module"] = definition.module
    if diagnostics is not None:
        diagnostics["event_registered"] = True
    logger.info("notification.publish.started %s", safe_log_fields)
    resolved_severity = severity or definition.default_severity
    if resolved_severity not in SEVERITY_ORDER:
        raise ValueError("Invalid notification severity")
    if (
        get_site_setting(db, "notifications_enabled") == "0"
        or get_site_setting(db, "notifications_in_app_enabled") == "0"
    ):
        logger.info(
            "notification.publish.suppressed reason=%s %s",
            "framework_disabled"
            if get_site_setting(db, "notifications_enabled") == "0"
            else "channel_disabled",
            safe_log_fields,
        )
        if diagnostics is not None:
            diagnostics["suppression_reason"] = (
                "framework_disabled"
                if get_site_setting(db, "notifications_enabled") == "0"
                else "channel_disabled"
            )
        return None
    policy = policy_for(db, event_type_id)
    if policy and not policy.enabled:
        logger.info(
            "notification.publish.suppressed reason=category_disabled %s",
            safe_log_fields,
        )
        if diagnostics is not None:
            diagnostics["suppression_reason"] = "category_disabled"
        return None
    target_route = safe_target_route(target_route)
    title = _clean_text(title, 160, "title")
    message = _clean_text(message, 500, "message")
    if definition.sensitive_payload:
        title = definition.display_name
        message = "Open Kaya to review this security-sensitive event."
    if deduplication_key:
        deduplication_key = _clean_text(deduplication_key, 255, "deduplication key")
        active = (
            db.query(NotificationEvent)
            .filter_by(deduplication_key=deduplication_key, resolved_at=None)
            .order_by(NotificationEvent.created_at.desc())
            .first()
        )
        if active:
            logger.info(
                "notification.publish.suppressed reason=duplicate_event existing_event_id=%s %s",
                active.id,
                safe_log_fields,
            )
            if diagnostics is not None:
                diagnostics.update(
                    {
                        "duplicate_event": True,
                        "notification_event_id": active.id,
                    }
                )
            return active
    safe_metadata = {}
    for key, value in list((metadata or {}).items())[:20]:
        if isinstance(value, str):
            value = value[:500]
        if isinstance(value, (str, int, float, bool, type(None))):
            safe_metadata[str(key)[:80]] = value
    row = NotificationEvent(
        event_type=event_type_id,
        module=definition.module,
        category=definition.category,
        severity=resolved_severity,
        title=title,
        message=message,
        metadata_json=(
            json.dumps(safe_metadata, separators=(",", ":")) if safe_metadata else None
        ),
        target_route=target_route,
        source_entity_type=str(source_entity_type)[:80] if source_entity_type else None,
        source_entity_id=(
            str(source_entity_id)[:120] if source_entity_id is not None else None
        ),
        deduplication_key=deduplication_key,
        created_by_user_id=created_by_user_id,
        correlation_id=str(correlation_id)[:64] if correlation_id else None,
        resolved_at=datetime.utcnow() if resolved else None,
    )
    recipients = resolve_recipients(db, definition.module, recipient_ids)
    candidate_query = db.query(User).filter(User.is_active.is_(True))
    if recipient_ids is not None:
        candidate_query = candidate_query.filter(
            User.id.in_([value for value in recipient_ids if isinstance(value, int)])
        )
    candidate_count = candidate_query.count()
    created_count = 0
    queued_channels: dict[str, int] = {"push": 0, "email": 0}
    try:
        db.add(row)
        db.flush()
        for recipient in recipients:
            if diagnostic_channel in {None, "in_app"} and not preference_allows(
                db, recipient.id, event_type_id, resolved_severity, "in_app"
            ):
                continue
            user_notification = UserNotification(
                notification_event_id=row.id, user_id=recipient.id
            )
            db.add(user_notification)
            db.flush()
            created_count += 1
            if diagnostic_channel in {None, "push"} and get_site_setting(
                db, "notifications_push_enabled"
            ) == "1" and preference_allows(
                db, recipient.id, event_type_id, resolved_severity, "push"
            ):
                subscriptions = (
                    db.query(PushSubscription)
                    .filter_by(user_id=recipient.id, status="active", revoked_at=None)
                    .filter(
                        PushSubscription.id == diagnostic_subscription_id
                        if diagnostic_subscription_id
                        else True
                    )
                    .limit(20)
                    .all()
                )
                for subscription in subscriptions:
                    db.add(
                        NotificationDeliveryAttempt(
                            user_notification_id=user_notification.id,
                            channel="push",
                            push_subscription_id=subscription.id,
                        )
                    )
                    queued_channels["push"] += 1
            if diagnostic_channel in {None, "email"} and get_site_setting(
                db, "notifications_email_enabled"
            ) == "1" and preference_allows(
                db, recipient.id, event_type_id, resolved_severity, "email"
            ):
                db.add(
                    NotificationDeliveryAttempt(
                        user_notification_id=user_notification.id, channel="email"
                    )
                )
                queued_channels["email"] += 1
        if commit:
            db.commit()
        else:
            db.flush()
    except Exception:
        db.rollback()
        logger.exception("notification.publish.failed reason=persistence_error %s", safe_log_fields)
        raise
    if created_count == 0:
        reason = "no_recipients" if not recipients else "user_opted_out"
        logger.info(
            "notification.publish.suppressed reason=%s candidate_recipients=%s eligible_recipients=%s user_notifications_created=0 %s",
            reason,
            candidate_count,
            len(recipients),
            safe_log_fields,
        )
        if diagnostics is not None:
            diagnostics["suppression_reason"] = reason
    if diagnostics is not None:
        diagnostics.update(
            {
                "candidate_recipients": candidate_count,
                "eligible_recipients": len(recipients),
                "suppressed_recipients": max(0, candidate_count - created_count),
                "user_notifications_created": created_count,
                "push_queued": queued_channels["push"],
                "email_queued": queued_channels["email"],
                "notification_event_id": row.id,
            }
        )
    logger.info(
        "notification.publish.completed event_id=%s candidate_recipients=%s eligible_recipients=%s suppressed_recipients=%s user_notifications_created=%s channels_queued=%s %s",
        row.id,
        candidate_count,
        len(recipients),
        max(0, candidate_count - created_count),
        created_count,
        queued_channels,
        safe_log_fields,
    )
    return row


def cleanup_retention(db: Session) -> dict[str, int]:
    try:
        read_days = max(
            1,
            min(
                int(get_site_setting(db, "notifications_read_retention_days") or 90),
                3650,
            ),
        )
        unread_days = max(
            read_days,
            min(
                int(get_site_setting(db, "notifications_unread_retention_days") or 365),
                3650,
            ),
        )
    except ValueError:
        read_days, unread_days = 90, 365
    now = datetime.utcnow()
    read_deleted = (
        db.query(UserNotification)
        .filter(UserNotification.read_at < now - timedelta(days=read_days))
        .delete(synchronize_session=False)
    )
    unread_deleted = (
        db.query(UserNotification)
        .filter(
            UserNotification.read_at.is_(None),
            UserNotification.created_at < now - timedelta(days=unread_days),
        )
        .delete(synchronize_session=False)
    )
    orphan_events = (
        db.query(NotificationEvent)
        .filter(
            ~NotificationEvent.id.in_(db.query(UserNotification.notification_event_id))
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    return {"read": read_deleted, "unread": unread_deleted, "events": orphan_events}


def registered_categories(db: Session) -> list[dict]:
    result = []
    for definition in EVENT_TYPES.values():
        if not definition.implemented_publisher:
            continue
        if definition.module != "system" and definition.module not in {
            module for (module,) in db.query(NotificationEvent.module).distinct()
        }:
            # Installed modules are registered in the central module registry; events need not have fired yet.
            from app.services.modules import enabled_module_keys

            if definition.module not in enabled_module_keys(db):
                continue
        policy = policy_for(db, definition.identifier)
        result.append({"definition": definition, "policy": policy})
    return result
