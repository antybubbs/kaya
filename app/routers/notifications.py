from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, joinedload

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import encrypt_secret
from app.core.templating import templates
from app.db.session import get_db
from app.models.models import (
    NotificationCategoryPolicy,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationPreference,
    AuditLog,
    PushSubscription,
    RemoteManagerSetting,
    UserNotification,
)
from app.routers.auth import require_admin, require_user
from app.services.audit import write_audit
from app.services.modules import has_module_access
from app.services.notification_registry import EVENT_TYPES, SEVERITY_ORDER
from app.services.notifications import (
    publish,
    registered_categories,
    validate_push_endpoint,
)
from app.services.site_settings import get_site_setting

router = APIRouter()
TIME_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")


class PreferenceUpdate(BaseModel):
    event_type: str = Field(max_length=120)
    in_app_enabled: bool = True
    push_enabled: bool = False
    email_enabled: bool = False
    minimum_severity: str = Field(default="info", max_length=20)
    recovery_enabled: bool = True
    quiet_hours_start: str | None = Field(default=None, max_length=5)
    quiet_hours_end: str | None = Field(default=None, max_length=5)
    timezone: str = Field(default="UTC", max_length=80)


class SubscriptionCreate(BaseModel):
    endpoint: str = Field(min_length=12, max_length=2048)
    keys: dict[str, str]
    device_label: str = Field(default="Browser", min_length=1, max_length=120)
    browser_family: str | None = Field(default=None, max_length=80)
    operating_system: str | None = Field(default=None, max_length=80)


class AdminSettingsUpdate(BaseModel):
    enabled: bool = True
    in_app_enabled: bool = True
    push_enabled: bool = False
    email_enabled: bool = False
    allow_customisation: bool = True
    allow_push_registration: bool = True
    read_retention_days: int = Field(default=90, ge=1, le=3650)
    unread_retention_days: int = Field(default=365, ge=1, le=3650)
    default_severity: str = Field(default="info", max_length=20)
    maximum_per_event: int = Field(default=250, ge=1, le=10000)


class CategoryUpdate(BaseModel):
    enabled: bool = True
    in_app_allowed: bool = True
    push_allowed: bool = False
    email_allowed: bool = False
    minimum_severity: str = Field(default="info", max_length=20)
    user_can_opt_out: bool = True
    recovery_enabled: bool = True
    default_enabled: bool = True
    cooldown_seconds: int = Field(default=300, ge=0, le=604800)
    repeat_interval_seconds: int | None = Field(default=None, ge=60, le=2592000)
    acknowledgement_required: bool = False


def _csrf(request: Request) -> None:
    validate_csrf_token(request, request.headers.get("x-csrf-token"))


def _serialise(
    row: UserNotification, policies: dict[str, NotificationCategoryPolicy]
) -> dict:
    event = row.event
    policy = policies.get(event.event_type)
    return {
        "id": row.id,
        "event_type": event.event_type,
        "module": event.module,
        "category": event.category,
        "severity": event.severity,
        "title": event.title,
        "message": event.message,
        "target_route": event.target_route,
        "created_at": event.created_at.isoformat() + "Z",
        "read": row.read_at is not None,
        "acknowledgement_required": bool(policy and policy.acknowledgement_required),
        "acknowledged": row.acknowledged_at is not None,
    }


def _owned(db: Session, user_id: int, notification_id: int) -> UserNotification:
    row = (
        db.query(UserNotification)
        .options(joinedload(UserNotification.event))
        .filter_by(id=notification_id, user_id=user_id)
        .first()
    )
    if not row:
        raise HTTPException(404, "Notification not found")
    return row


@router.get("/notifications")
def notification_centre(
    request: Request,
    state: str = Query("all", pattern="^(all|read|unread)$"),
    severity: str = "",
    module: str = "",
    page: int = Query(1, ge=1, le=100000),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    query = (
        db.query(UserNotification)
        .options(joinedload(UserNotification.event))
        .join(NotificationEvent)
        .filter(
            UserNotification.user_id == user.id, UserNotification.dismissed_at.is_(None)
        )
    )
    if state == "read":
        query = query.filter(UserNotification.read_at.is_not(None))
    elif state == "unread":
        query = query.filter(UserNotification.read_at.is_(None))
    if severity in SEVERITY_ORDER:
        query = query.filter(NotificationEvent.severity == severity)
    if module and module in {definition.module for definition in EVENT_TYPES.values()}:
        query = query.filter(NotificationEvent.module == module)
    total = query.count()
    page_size = 25
    rows = (
        query.order_by(NotificationEvent.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    policies = {
        row.event_type: row
        for row in db.query(NotificationCategoryPolicy)
        .filter(
            NotificationCategoryPolicy.event_type.in_(
                {item.event.event_type for item in rows}
            )
        )
        .all()
    }
    return templates.TemplateResponse(
        request,
        "notifications.html",
        {
            "user": user,
            "rows": rows,
            "state": state,
            "active_severity": severity,
            "active_module": module,
            "page": page,
            "pages": max(1, (total + page_size - 1) // page_size),
            "modules": sorted(
                {definition.module for definition in EVENT_TYPES.values()}
            ),
            "policies": policies,
            **csrf_context(request),
        },
    )


@router.get("/profile/notifications")
def notification_preferences_page(
    request: Request, db: Session = Depends(get_db), user=Depends(require_user)
):
    preferences = {
        row.event_type: row
        for row in db.query(NotificationPreference).filter_by(user_id=user.id).all()
    }
    devices = (
        db.query(PushSubscription)
        .filter_by(user_id=user.id)
        .order_by(PushSubscription.created_at.desc())
        .all()
    )
    return templates.TemplateResponse(
        request,
        "notification_preferences.html",
        {
            "user": user,
            "categories": registered_categories(db),
            "preferences": preferences,
            "devices": devices,
            "settings": _settings(db),
            "vapid_configured": bool(
                get_settings().vapid_public_key and get_settings().vapid_private_key
            ),
            **csrf_context(request),
        },
    )


@router.get("/system/site-administration/notifications")
def notification_admin_page(
    request: Request, db: Session = Depends(get_db), user=Depends(require_admin)
):
    now = datetime.utcnow()
    active_devices = (
        db.query(PushSubscription).filter_by(status="active", revoked_at=None).count()
    )
    accepted = (
        db.query(NotificationDeliveryAttempt)
        .filter(
            NotificationDeliveryAttempt.status == "accepted",
            NotificationDeliveryAttempt.attempted_at
            >= now.replace(hour=0, minute=0, second=0),
        )
        .count()
    )
    failed = (
        db.query(NotificationDeliveryAttempt)
        .filter(
            NotificationDeliveryAttempt.status.in_(["failed", "permanent_failure"]),
            NotificationDeliveryAttempt.attempted_at
            >= now.replace(hour=0, minute=0, second=0),
        )
        .count()
    )
    return templates.TemplateResponse(
        request,
        "notification_admin.html",
        {
            "user": user,
            "settings": _settings(db),
            "categories": registered_categories(db),
            "active_devices": active_devices,
            "accepted_today": accepted,
            "failed_today": failed,
            "vapid_public_key": get_settings().vapid_public_key,
            **csrf_context(request),
        },
    )


@router.get("/api/notifications")
def list_notifications(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    rows = (
        db.query(UserNotification)
        .options(joinedload(UserNotification.event))
        .join(NotificationEvent)
        .filter(
            UserNotification.user_id == user.id, UserNotification.dismissed_at.is_(None)
        )
        .order_by(NotificationEvent.created_at.desc())
        .limit(limit)
        .all()
    )
    policies = {
        policy.event_type: policy
        for policy in db.query(NotificationCategoryPolicy)
        .filter(
            NotificationCategoryPolicy.event_type.in_(
                {row.event.event_type for row in rows}
            )
        )
        .all()
    }
    return {"notifications": [_serialise(row, policies) for row in rows]}


@router.get("/api/notifications/unread-count")
def unread_count(db: Session = Depends(get_db), user=Depends(require_user)):
    count = (
        db.query(UserNotification)
        .filter_by(user_id=user.id, read_at=None, dismissed_at=None)
        .count()
    )
    critical = (
        db.query(UserNotification)
        .join(NotificationEvent)
        .filter(
            UserNotification.user_id == user.id,
            UserNotification.read_at.is_(None),
            UserNotification.dismissed_at.is_(None),
            NotificationEvent.severity == "critical",
        )
        .count()
    )
    return {"count": count, "critical": critical > 0}


@router.post("/api/notifications/{notification_id}/read")
def mark_read(
    notification_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    _csrf(request)
    row = _owned(db, user.id, notification_id)
    row.read_at = datetime.utcnow()
    db.commit()
    return {"ok": True}


@router.post("/api/notifications/{notification_id}/unread")
def mark_unread(
    notification_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    _csrf(request)
    row = _owned(db, user.id, notification_id)
    row.read_at = None
    db.commit()
    return {"ok": True}


@router.post("/api/notifications/{notification_id}/dismiss")
def dismiss(
    notification_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    _csrf(request)
    row = _owned(db, user.id, notification_id)
    row.dismissed_at = datetime.utcnow()
    db.commit()
    return {"ok": True}


@router.post("/api/notifications/{notification_id}/acknowledge")
def acknowledge(
    notification_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    _csrf(request)
    row = _owned(db, user.id, notification_id)
    row.acknowledged_at = datetime.utcnow()
    row.read_at = row.read_at or row.acknowledged_at
    db.commit()
    return {"ok": True}


@router.post("/api/notifications/mark-all-read")
def mark_all_read(
    request: Request, db: Session = Depends(get_db), user=Depends(require_user)
):
    _csrf(request)
    now = datetime.utcnow()
    db.query(UserNotification).filter_by(
        user_id=user.id, read_at=None, dismissed_at=None
    ).update({UserNotification.read_at: now}, synchronize_session=False)
    db.commit()
    return {"ok": True}


@router.post("/api/notifications/clear-read")
def clear_read(
    request: Request, db: Session = Depends(get_db), user=Depends(require_user)
):
    _csrf(request)
    db.query(UserNotification).filter(
        UserNotification.user_id == user.id,
        UserNotification.read_at.is_not(None),
        UserNotification.dismissed_at.is_(None),
    ).update(
        {UserNotification.dismissed_at: datetime.utcnow()}, synchronize_session=False
    )
    db.commit()
    return {"ok": True}


@router.get("/api/notification-preferences")
def get_preferences(db: Session = Depends(get_db), user=Depends(require_user)):
    rows = db.query(NotificationPreference).filter_by(user_id=user.id).all()
    return {
        "preferences": [
            {
                key: getattr(row, key)
                for key in (
                    "event_type",
                    "in_app_enabled",
                    "push_enabled",
                    "email_enabled",
                    "minimum_severity",
                    "recovery_enabled",
                    "quiet_hours_start",
                    "quiet_hours_end",
                    "timezone",
                )
            }
            for row in rows
        ]
    }


@router.put("/api/notification-preferences/{identifier}")
def update_preference(
    identifier: str,
    payload: PreferenceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    _csrf(request)
    if (
        identifier not in EVENT_TYPES
        or payload.event_type != identifier
        or payload.minimum_severity not in SEVERITY_ORDER
    ):
        raise HTTPException(400, "Invalid notification preference")
    if payload.quiet_hours_start and not TIME_RE.fullmatch(payload.quiet_hours_start):
        raise HTTPException(400, "Invalid quiet-hours start")
    if payload.quiet_hours_end and not TIME_RE.fullmatch(payload.quiet_hours_end):
        raise HTTPException(400, "Invalid quiet-hours end")
    if bool(payload.quiet_hours_start) != bool(payload.quiet_hours_end):
        raise HTTPException(400, "Both quiet-hours values are required")
    try:
        ZoneInfo(payload.timezone)
    except ZoneInfoNotFoundError as exc:
        raise HTTPException(400, "Invalid timezone") from exc
    if get_site_setting(db, "notifications_allow_customisation") != "1":
        raise HTTPException(403, "Notification customisation is disabled")
    definition = EVENT_TYPES[identifier]
    if definition.module != "system" and not has_module_access(
        db, user, definition.module
    ):
        raise HTTPException(403, "Module access required")
    policy = db.get(NotificationCategoryPolicy, identifier)
    if policy and not policy.user_can_opt_out and not payload.in_app_enabled:
        raise HTTPException(400, "This notification is mandatory")
    settings = get_settings()
    if payload.push_enabled and (
        get_site_setting(db, "notifications_push_enabled") != "1"
        or not settings.vapid_public_key
        or not settings.vapid_private_key
        or (policy and not policy.push_allowed)
    ):
        raise HTTPException(400, "Web Push is unavailable for this event")
    if payload.email_enabled and (
        get_site_setting(db, "notifications_email_enabled") != "1"
        or (policy and not policy.email_allowed)
    ):
        raise HTTPException(400, "Email is unavailable for this event")
    row = db.query(NotificationPreference).filter_by(
        user_id=user.id, event_type=identifier
    ).first() or NotificationPreference(user_id=user.id, event_type=identifier)
    for field in (
        "in_app_enabled",
        "push_enabled",
        "email_enabled",
        "minimum_severity",
        "recovery_enabled",
        "quiet_hours_start",
        "quiet_hours_end",
        "timezone",
    ):
        setattr(row, field, getattr(payload, field))
    db.add(row)
    db.commit()
    return {"ok": True}


def _valid_subscription(payload: SubscriptionCreate) -> dict:
    try:
        validate_push_endpoint(payload.endpoint)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    p256dh, auth = payload.keys.get("p256dh", ""), payload.keys.get("auth", "")
    if not (
        20 <= len(p256dh) <= 200
        and 8 <= len(auth) <= 100
        and re.fullmatch(r"[A-Za-z0-9_-]+", p256dh)
        and re.fullmatch(r"[A-Za-z0-9_-]+", auth)
    ):
        raise HTTPException(400, "Invalid push subscription keys")
    return {"endpoint": payload.endpoint, "keys": {"p256dh": p256dh, "auth": auth}}


@router.get("/api/push-subscriptions")
def get_subscriptions(db: Session = Depends(get_db), user=Depends(require_user)):
    rows = (
        db.query(PushSubscription)
        .filter_by(user_id=user.id)
        .order_by(PushSubscription.created_at.desc())
        .all()
    )
    return {
        "subscriptions": [
            {
                "id": row.id,
                "device_label": row.device_label,
                "browser_family": row.browser_family,
                "operating_system": row.operating_system,
                "status": row.status,
                "created_at": row.created_at.isoformat() + "Z",
                "last_success_at": (
                    row.last_success_at.isoformat() + "Z"
                    if row.last_success_at
                    else None
                ),
            }
            for row in rows
        ]
    }


@router.post("/api/push-subscriptions")
def create_subscription(
    payload: SubscriptionCreate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    _csrf(request)
    if (
        get_site_setting(db, "notifications_push_enabled") != "1"
        or get_site_setting(db, "notifications_allow_push_registration") != "1"
    ):
        raise HTTPException(403, "Push registration is disabled")
    safe = _valid_subscription(payload)
    endpoint_hash = hashlib.sha256(payload.endpoint.encode()).hexdigest()
    row = (
        db.query(PushSubscription)
        .filter_by(user_id=user.id, endpoint_hash=endpoint_hash)
        .first()
    )
    if not row:
        active_count = (
            db.query(PushSubscription)
            .filter_by(user_id=user.id, status="active", revoked_at=None)
            .count()
        )
        if active_count >= 20:
            raise HTTPException(429, "Remove an existing device before adding another")
        row = PushSubscription(
            user_id=user.id, endpoint_hash=endpoint_hash, encrypted_subscription=""
        )
    row.encrypted_subscription = encrypt_secret(json.dumps(safe, separators=(",", ":")))
    row.device_label = " ".join(payload.device_label.split())
    row.browser_family = payload.browser_family
    row.operating_system = payload.operating_system
    row.status = "active"
    row.revoked_at = None
    row.last_used_at = datetime.utcnow()
    db.add(row)
    db.commit()
    return {"id": row.id, "device_label": row.device_label, "status": row.status}


@router.delete("/api/push-subscriptions/{subscription_id}")
def delete_subscription(
    subscription_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    _csrf(request)
    row = (
        db.query(PushSubscription)
        .filter_by(id=subscription_id, user_id=user.id)
        .first()
    )
    if not row:
        raise HTTPException(404, "Subscription not found")
    row.status = "revoked"
    row.revoked_at = datetime.utcnow()
    db.commit()
    return {"ok": True}


@router.get("/api/notifications/vapid-public-key")
def vapid_public_key(db: Session = Depends(get_db), user=Depends(require_user)):
    settings = get_settings()
    if (
        get_site_setting(db, "notifications_push_enabled") != "1"
        or not settings.vapid_public_key
    ):
        raise HTTPException(404, "Web Push is not configured")
    return {"public_key": settings.vapid_public_key}


@router.post("/api/notifications/test")
def test_notification(
    request: Request, db: Session = Depends(get_db), user=Depends(require_admin)
):
    _csrf(request)
    recent_tests = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == user.id,
            AuditLog.action == "notification_test_sent",
            AuditLog.created_at >= datetime.utcnow() - timedelta(minutes=10),
        )
        .count()
    )
    if recent_tests >= 5:
        raise HTTPException(429, "Notification test limit reached; try again later")
    row = publish(
        db,
        event_type_id="system.notification.test",
        title="Kaya test notification",
        message="This is a test notification requested from Kaya.",
        target_route="/notifications",
        recipient_ids=[user.id],
        created_by_user_id=user.id,
    )
    user_notification = (
        db.query(UserNotification)
        .filter_by(notification_event_id=row.id, user_id=user.id)
        .first()
        if row
        else None
    )
    attempts = (
        db.query(NotificationDeliveryAttempt)
        .filter_by(user_notification_id=user_notification.id)
        .all()
        if user_notification
        else []
    )
    configured = get_settings()
    write_audit(
        db,
        user,
        "notification_test_sent",
        "notification",
        str(row.id) if row else None,
        detail="User requested a notification test",
    )
    return {
        "ok": bool(user_notification),
        "event_created": bool(row),
        "recipient_resolved": bool(user_notification),
        "user_notification_created": bool(user_notification),
        "in_app": "available" if user_notification else "suppressed",
        "push": (
            "queued"
            if any(item.channel == "push" for item in attempts)
            else "skipped: not configured"
            if not configured.vapid_public_key or not configured.vapid_private_key
            else "skipped: disabled or no enabled subscription"
        ),
        "email": (
            "queued"
            if any(item.channel == "email" for item in attempts)
            else "skipped: disabled"
            if get_site_setting(db, "notifications_email_enabled") != "1"
            else "skipped: user preference or delivery unavailable"
        ),
    }


def _settings(db: Session) -> dict:
    keys = (
        "notifications_enabled",
        "notifications_in_app_enabled",
        "notifications_push_enabled",
        "notifications_email_enabled",
        "notifications_allow_customisation",
        "notifications_allow_push_registration",
        "notifications_read_retention_days",
        "notifications_unread_retention_days",
        "notifications_default_severity",
        "notifications_max_per_event",
    )
    return {key: get_site_setting(db, key) for key in keys}


def _save_setting(db: Session, key: str, value: str) -> None:
    row = db.query(RemoteManagerSetting).filter_by(key=key).first()
    if row:
        row.value = value
    else:
        db.add(RemoteManagerSetting(key=key, value=value))
    db.info.pop("site_settings", None)


@router.get("/api/admin/notification-settings")
def admin_settings(db: Session = Depends(get_db), user=Depends(require_admin)):
    return _settings(db)


@router.put("/api/admin/notification-settings")
def update_admin_settings(
    payload: AdminSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    if (
        payload.default_severity not in SEVERITY_ORDER
        or payload.unread_retention_days < payload.read_retention_days
    ):
        raise HTTPException(400, "Invalid notification settings")
    values = {
        "notifications_enabled": payload.enabled,
        "notifications_in_app_enabled": payload.in_app_enabled,
        "notifications_push_enabled": payload.push_enabled,
        "notifications_email_enabled": payload.email_enabled,
        "notifications_allow_customisation": payload.allow_customisation,
        "notifications_allow_push_registration": payload.allow_push_registration,
        "notifications_read_retention_days": payload.read_retention_days,
        "notifications_unread_retention_days": payload.unread_retention_days,
        "notifications_default_severity": payload.default_severity,
        "notifications_max_per_event": payload.maximum_per_event,
    }
    for key, value in values.items():
        _save_setting(
            db, key, "1" if value is True else "" if value is False else str(value)
        )
    db.commit()
    write_audit(
        db,
        user,
        "notification_settings_changed",
        "notification_settings",
        detail="Global notification settings changed",
        metadata={"changed_keys": sorted(values)},
    )
    return _settings(db)


@router.get("/api/admin/notification-categories")
def admin_categories(db: Session = Depends(get_db), user=Depends(require_admin)):
    return {
        "categories": [
            {
                "event_type": item["definition"].identifier,
                "display_name": item["definition"].display_name,
                "module": item["definition"].module,
            }
            for item in registered_categories(db)
        ]
    }


@router.put("/api/admin/notification-categories/{identifier}")
def update_category(
    identifier: str,
    payload: CategoryUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    if identifier not in EVENT_TYPES or payload.minimum_severity not in SEVERITY_ORDER:
        raise HTTPException(400, "Invalid notification category")
    row = db.get(NotificationCategoryPolicy, identifier) or NotificationCategoryPolicy(
        event_type=identifier
    )
    for field in payload.model_fields:
        setattr(row, field, getattr(payload, field))
    db.add(row)
    db.commit()
    write_audit(
        db,
        user,
        "notification_category_changed",
        "notification_category",
        identifier,
        detail="Notification category policy changed",
        metadata={"event_type": identifier},
    )
    return {"ok": True}
