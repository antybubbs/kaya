from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, joinedload

from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import encrypt_secret
from app.core.templating import templates
from app.db.session import get_db
from app.models.models import (
    NotificationCategoryPolicy,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationOutbox,
    NotificationPreference,
    NotificationReconciliationFailure,
    AuditLog,
    PushSubscription,
    User,
    RemoteManagerSetting,
    UserNotification,
)
from app.routers.auth import require_admin, require_user
from app.services.audit import write_audit
from app.services.client_ip import client_ip as trusted_client_ip
from app.services.modules import has_module_access
from app.services.notification_registry import EVENT_TYPES, SEVERITY_ORDER
from app.services.notification_outbox import enqueue_notification
from app.services.notification_runtime import notification_health
from app.services.notifications import (
    publish,
    registered_categories,
    validate_push_endpoint,
)
from app.services.site_settings import get_site_setting
from app.services.web_push_config import (
    WebPushEncryptionUnavailableError,
    WebPushConfigurationError,
    configuration_status,
    create_ui_configuration,
    effective_credentials,
    normalise_subject,
    revoke_all_subscriptions,
    ui_configuration,
)

router = APIRouter()
TIME_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
logger = logging.getLogger(__name__)


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
    push_enabled: bool | None = None
    email_enabled: bool = False
    allow_customisation: bool = True
    allow_push_registration: bool | None = None
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


class DelayedDiagnostic(BaseModel):
    delay_seconds: int = Field(default=45, ge=30, le=60)


class ProductionEventDiagnostic(BaseModel):
    event_type: str = Field(default="ipwan.host.offline", max_length=120)


class WebPushKeyRequest(BaseModel):
    contact_email: str | None = Field(default=None, max_length=254)
    contact_url: str | None = Field(default=None, max_length=500)
    installation_label: str | None = Field(default=None, max_length=120)
    confirmation: str = Field(min_length=1, max_length=40)


class ConfirmedWebPushAction(BaseModel):
    confirmation: str = Field(min_length=1, max_length=40)


class ReconciliationFailureAction(BaseModel):
    action: str = Field(min_length=5, max_length=7)


def _csrf(request: Request) -> None:
    validate_csrf_token(request, request.headers.get("x-csrf-token"))


def _admin_rate_limit(
    db: Session,
    user_id: int,
    actions: tuple[str, ...],
    *,
    limit: int,
    minutes: int,
) -> None:
    recent = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == user_id,
            AuditLog.action.in_(actions),
            AuditLog.created_at >= datetime.utcnow() - timedelta(minutes=minutes),
        )
        .count()
    )
    if recent >= limit:
        raise HTTPException(429, "Web Push administration rate limit reached")


def _audit_or_fail(db: Session, *args, **kwargs) -> None:
    kwargs.setdefault("category", "security")
    if write_audit(db, *args, **kwargs) is None:
        raise HTTPException(500, "The operation could not be recorded safely")


def _safe_request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "unavailable"))[:64]


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
    push_status = configuration_status(db)
    return templates.TemplateResponse(
        request,
        "notification_preferences.html",
        {
            "user": user,
            "categories": registered_categories(db),
            "preferences": preferences,
            "devices": devices,
            "settings": _settings(db),
            "vapid_configured": push_status["valid"],
            "push_registration_available": push_status[
                "browser_registration_available"
            ],
            **csrf_context(request),
        },
    )


@router.get("/system/site-administration/notifications")
def notification_admin_page(
    request: Request, db: Session = Depends(get_db), user=Depends(require_admin)
):
    now = datetime.utcnow()
    subscriptions = (
        db.query(PushSubscription)
        .join(User, User.id == PushSubscription.user_id)
        .add_entity(User)
        .order_by(PushSubscription.created_at.desc())
        .limit(250)
        .all()
    )
    registered_device_count = db.query(PushSubscription).count()
    active_devices = db.query(PushSubscription).filter_by(status="active", revoked_at=None).count()
    subscription_ids = [row.id for row, _user in subscriptions]
    attempts = (
        db.query(NotificationDeliveryAttempt)
        .filter(
            NotificationDeliveryAttempt.channel == "push",
            NotificationDeliveryAttempt.push_subscription_id.in_(subscription_ids or [0]),
        )
        .order_by(NotificationDeliveryAttempt.created_at.desc())
        .limit(1000)
        .all()
    )
    latest_failure = {}
    for attempt in attempts:
        if attempt.status in {"permanent_failure", "expired_subscription", "retry_exhausted", "temporary_failure"}:
            latest_failure.setdefault(attempt.push_subscription_id, attempt)

    def platform(row):
        value = (row.operating_system or "").lower()
        for label, needles in (("iOS", ("ios", "iphone", "ipad")), ("Android", ("android",)), ("Windows", ("windows",)), ("macOS", ("mac", "darwin")), ("Linux", ("linux",))):
            if any(needle in value for needle in needles):
                return label
        return "Unknown"

    def device_status(row):
        if row.status == "expired":
            return "Expired"
        if row.status != "active" or row.revoked_at:
            return "Disabled"
        failure = latest_failure.get(row.id)
        if failure and failure.status in {"permanent_failure", "expired_subscription"}:
            return "Needs refresh"
        if failure and failure.status in {"temporary_failure", "retry_exhausted"}:
            return "Retrying"
        return "Active"

    push_devices = [{
        "id": row.id,
        "user": user.email,
        "device": row.device_label or "Browser device",
        "platform": platform(row),
        "status": device_status(row),
        "registered_at": row.created_at,
        "last_success_at": row.last_success_at,
        "last_failure_at": row.last_failure_at,
        "failure_reason": latest_failure.get(row.id).failure_reason_code if latest_failure.get(row.id) else None,
    } for row, user in subscriptions]
    web_push = configuration_status(db)
    web_push.update({"registered_devices": registered_device_count, "devices": push_devices})
    if web_push["state"] == "not_configured":
        web_push["overview_status"] = "Not configured"
    elif not subscriptions:
        web_push["overview_status"] = "No registered devices"
    elif any(device["status"] != "Active" for device in push_devices):
        web_push["overview_status"] = "Attention required"
    else:
        web_push["overview_status"] = "Enabled" if web_push["enabled"] else web_push["status_label"]
    accepted = (
        db.query(NotificationDeliveryAttempt)
        .filter(
            NotificationDeliveryAttempt.status.in_(
                ["accepted", "accepted_by_push_service"]
            ),
            NotificationDeliveryAttempt.channel == "push",
            NotificationDeliveryAttempt.attempted_at
            >= now.replace(hour=0, minute=0, second=0),
        )
        .count()
    )
    failed = (
        db.query(NotificationDeliveryAttempt)
        .filter(
            NotificationDeliveryAttempt.status.in_(
                [
                    "failed",
                    "permanent_failure",
                    "expired_subscription",
                    "retry_exhausted",
                ]
            ),
            NotificationDeliveryAttempt.channel == "push",
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
            "delivery_health": notification_health(),
            "web_push": web_push,
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
    push_status = configuration_status(db)
    if payload.push_enabled and (
        get_site_setting(db, "notifications_push_enabled") != "1"
        or not push_status["valid"]
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
        or not configuration_status(db)["valid"]
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
    if get_site_setting(db, "notifications_push_enabled") != "1":
        raise HTTPException(404, "Web Push is not configured")
    try:
        credentials = effective_credentials(db)
    except WebPushConfigurationError as exc:
        raise HTTPException(503, "Web Push configuration is invalid") from exc
    if not credentials:
        raise HTTPException(404, "Web Push is not configured")
    return {"public_key": credentials.public_key}


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
    outbox = enqueue_notification(
        db,
        event_type_id="system.notification.test",
        title="Kaya test notification",
        message="This is a test notification requested from Kaya.",
        target_route="/notifications",
        recipient_ids=[user.id],
        created_by_user_id=user.id,
        metadata={"diagnostic": True, "diagnostic_channel": "in_app"},
    )
    write_audit(
        db,
        user,
        "notification_test_sent",
        "notification",
        str(outbox.id),
        detail="User requested a notification test",
    )
    return {
        "ok": True,
        "outbox_created": True,
        "outbox_id": outbox.id,
        "status": "queued",
        "in_app": "pending outbox processing",
        "push": "not requested",
        "email": "not requested",
    }


@router.post("/api/admin/notifications/test-delayed")
def delayed_background_test(
    payload: DelayedDiagnostic,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    _admin_rate_limit(
        db, user.id, ("notification_delayed_test_queued",), limit=5, minutes=10
    )
    available_at = datetime.utcnow() + timedelta(seconds=payload.delay_seconds)
    outbox = enqueue_notification(
        db,
        event_type_id="system.notification.test",
        title="Kaya delayed background test",
        message="This delayed test used Kaya's durable background notification pipeline.",
        target_route="/notifications",
        recipient_ids=[user.id],
        created_by_user_id=user.id,
        metadata={"diagnostic": True, "delayed": True},
        available_at=available_at,
    )
    write_audit(
        db,
        user,
        "notification_delayed_test_queued",
        "notification_outbox",
        str(outbox.id),
        trusted_client_ip(request),
        detail="Administrator queued a delayed background notification test",
        metadata={"delay_seconds": payload.delay_seconds},
    )
    return {
        "ok": True,
        "outbox_id": outbox.id,
        "status": "scheduled",
        "available_at": available_at.isoformat() + "Z",
        "instruction": "Close Kaya, lock the phone, and wait for the notification.",
    }


@router.post("/api/admin/notifications/simulate-production-event")
def simulate_production_event(
    payload: ProductionEventDiagnostic,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    allowed = {"ipwan.host.offline", "backup.job.failed", "pihole.cluster.degraded"}
    if payload.event_type not in allowed:
        raise HTTPException(400, "Unsupported diagnostic production event")
    _admin_rate_limit(
        db, user.id, ("notification_production_test_queued",), limit=5, minutes=10
    )
    correlation_id = f"diagnostic-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    definition = EVENT_TYPES[payload.event_type]
    outbox = enqueue_notification(
        db,
        event_type_id=payload.event_type,
        title=f"Diagnostic: {definition.display_name}",
        message="This is a simulated production event. No infrastructure state was changed.",
        target_route="/notifications",
        source_entity_type="notification_diagnostic",
        source_entity_id=correlation_id,
        deduplication_key=f"diagnostic:{payload.event_type}:{correlation_id}",
        recipient_ids=[user.id],
        created_by_user_id=user.id,
        correlation_id=correlation_id,
        metadata={"diagnostic": True},
    )
    write_audit(
        db,
        user,
        "notification_production_test_queued",
        "notification_outbox",
        str(outbox.id),
        trusted_client_ip(request),
        detail="Administrator queued a simulated production notification event",
        metadata={"event_type": payload.event_type},
    )
    return {"ok": True, "outbox_id": outbox.id, "status": "queued"}


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


@router.get("/api/admin/notifications/delivery-health")
def admin_delivery_health(user=Depends(require_admin)):
    return notification_health()


@router.put("/api/admin/notifications/reconciliation-failures/{failure_id}")
def update_reconciliation_failure(
    failure_id: int,
    payload: ReconciliationFailureAction,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    _admin_rate_limit(
        db,
        user.id,
        ("notification_reconciliation_failure_retried", "notification_reconciliation_failure_dismissed"),
        limit=30,
        minutes=10,
    )
    if payload.action not in {"retry", "dismiss"}:
        raise HTTPException(400, "Invalid reconciliation failure action")
    row = db.get(NotificationReconciliationFailure, failure_id)
    if not row or row.status not in {"retry", "quarantined"}:
        raise HTTPException(404, "Active reconciliation failure not found")
    if payload.action == "retry":
        row.status = "retry"
        row.attempt_count = 0
        row.next_retry_at = datetime.utcnow()
        row.quarantined_at = None
        row.resolved_at = None
        action = "notification_reconciliation_failure_retried"
    else:
        row.status = "dismissed"
        row.next_retry_at = None
        row.resolved_at = datetime.utcnow()
        db.query(NotificationEvent).filter(
            NotificationEvent.deduplication_key
            == (
                "system:notification-reconciliation-item:"
                f"{row.item_type}:{row.item_id}:{row.operation}:quarantined"
            ),
            NotificationEvent.resolved_at.is_(None),
        ).update(
            {NotificationEvent.resolved_at: datetime.utcnow()},
            synchronize_session=False,
        )
        action = "notification_reconciliation_failure_dismissed"
    db.commit()
    _audit_or_fail(
        db,
        user,
        action,
        "notification_reconciliation_failure",
        str(row.id),
        ip_address=trusted_client_ip(request),
        detail=f"Administrator requested {payload.action} for a reconciliation failure",
        metadata={
            "item_type": row.item_type,
            "operation": row.operation,
            "correlation_id": row.correlation_id,
        },
    )
    return {"ok": True, "status": row.status}


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
        "notifications_email_enabled": payload.email_enabled,
        "notifications_allow_customisation": payload.allow_customisation,
        "notifications_read_retention_days": payload.read_retention_days,
        "notifications_unread_retention_days": payload.unread_retention_days,
        "notifications_default_severity": payload.default_severity,
        "notifications_max_per_event": payload.maximum_per_event,
    }
    if payload.push_enabled is not None or payload.allow_push_registration is not None:
        push_status = configuration_status(db)
        if (payload.push_enabled or payload.allow_push_registration) and not push_status[
            "valid"
        ]:
            raise HTTPException(400, "Valid VAPID keys are required before enabling Web Push")
    if payload.push_enabled is not None:
        values["notifications_push_enabled"] = payload.push_enabled
    if payload.allow_push_registration is not None:
        values["notifications_allow_push_registration"] = (
            payload.allow_push_registration
        )
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


@router.get("/api/admin/web-push")
def admin_web_push_status(
    db: Session = Depends(get_db), user=Depends(require_admin)
):
    return configuration_status(db)


@router.post("/api/admin/web-push/generate")
def generate_web_push_keys(
    payload: WebPushKeyRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    if payload.confirmation != "GENERATE":
        raise HTTPException(400, "Explicit generation confirmation is required")
    _admin_rate_limit(
        db,
        user.id,
        ("web_push_keys_generated", "web_push_keys_rotated"),
        limit=3,
        minutes=60,
    )
    request_id = _safe_request_id(request)
    source = "unknown"
    try:
        source = str(configuration_status(db)["source"])
    except Exception:
        # The operation itself will produce the safe failure response and log
        # below (including when the schema migration has not been applied).
        db.rollback()
    logger.info(
        "vapid.generate.requested user_id=%s request_id=%s configuration_source=%s",
        user.id,
        request_id,
        source,
    )
    try:
        subject = normalise_subject(payload.contact_email, payload.contact_url)
        row = create_ui_configuration(
            db,
            subject=subject,
            installation_label=payload.installation_label,
            rotate=False,
        )
        _save_setting(db, "notifications_push_enabled", "1")
        _save_setting(db, "notifications_allow_push_registration", "1")
        _audit_or_fail(
            db,
            user,
            "web_push_keys_generated",
            "web_push_configuration",
            "1",
            trusted_client_ip(request),
            detail="UI-managed Web Push keys generated and enabled",
            metadata={
                "public_key_fingerprint": row.public_key_fingerprint,
                "key_source": "kaya",
            },
        )
    except WebPushEncryptionUnavailableError as exc:
        db.rollback()
        logger.error(
            "vapid.generate.failed user_id=%s request_id=%s "
            "configuration_source=%s reason=encryption_unavailable",
            user.id,
            request_id,
            source,
        )
        raise HTTPException(503, str(exc)) from exc
    except WebPushConfigurationError as exc:
        db.rollback()
        logger.warning(
            "vapid.generate.validation_failed user_id=%s request_id=%s "
            "configuration_source=%s reason=invalid_configuration",
            user.id,
            request_id,
            source,
        )
        raise HTTPException(400, str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.error(
            "vapid.generate.failed user_id=%s request_id=%s "
            "configuration_source=%s reason=internal",
            user.id,
            request_id,
            source,
        )
        raise HTTPException(500, "Web Push keys could not be generated safely") from exc
    result = configuration_status(db)
    logger.info(
        "vapid.generate.completed user_id=%s request_id=%s configuration_source=kaya",
        user.id,
        request_id,
    )
    return result


@router.post("/api/admin/web-push/rotate")
def rotate_web_push_keys(
    payload: WebPushKeyRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    if payload.confirmation != "ROTATE":
        raise HTTPException(400, "Explicit rotation confirmation is required")
    _admin_rate_limit(
        db,
        user.id,
        ("web_push_keys_generated", "web_push_keys_rotated"),
        limit=3,
        minutes=60,
    )
    try:
        subject = normalise_subject(payload.contact_email, payload.contact_url)
        row = create_ui_configuration(
            db,
            subject=subject,
            installation_label=payload.installation_label,
            rotate=True,
        )
        affected = revoke_all_subscriptions(db, "vapid_key_rotated")
        _save_setting(db, "notifications_push_enabled", "1")
        _save_setting(db, "notifications_allow_push_registration", "1")
        publish(
            db,
            event_type_id="system.web_push.keys_rotated",
            title="Web Push keys rotated",
            message=f"Web Push keys were rotated; {affected} browser subscription(s) require renewal.",
            target_route="/system/site-administration/notifications",
            source_entity_type="web_push_configuration",
            source_entity_id=1,
            created_by_user_id=user.id,
            metadata={"affected_subscriptions": affected},
            commit=False,
        )
        _audit_or_fail(
            db,
            user,
            "web_push_keys_rotated",
            "web_push_configuration",
            "1",
            trusted_client_ip(request),
            detail="UI-managed Web Push keys rotated",
            metadata={
                "public_key_fingerprint": row.public_key_fingerprint,
                "key_source": "kaya",
                "affected_subscriptions": affected,
            },
        )
    except WebPushEncryptionUnavailableError as exc:
        db.rollback()
        logger.error(
            "vapid.rotate.failed user_id=%s request_id=%s "
            "reason=encryption_unavailable",
            user.id,
            _safe_request_id(request),
        )
        raise HTTPException(503, str(exc)) from exc
    except WebPushConfigurationError as exc:
        db.rollback()
        logger.warning("web_push.configuration.rotate_failed reason=validation")
        raise HTTPException(400, str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.error("web_push.configuration.rotate_failed reason=internal")
        raise HTTPException(500, "Web Push keys could not be rotated safely") from exc
    result = configuration_status(db)
    result["affected_subscriptions"] = affected
    return result


@router.post("/api/admin/web-push/disable")
def disable_web_push(
    payload: ConfirmedWebPushAction,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    if payload.confirmation != "DISABLE":
        raise HTTPException(400, "Explicit disable confirmation is required")
    _admin_rate_limit(
        db, user.id, ("web_push_disabled",), limit=10, minutes=10
    )
    row = ui_configuration(db)
    if row:
        row.enabled = False
    _save_setting(db, "notifications_push_enabled", "")
    _save_setting(db, "notifications_allow_push_registration", "")
    _audit_or_fail(
        db,
        user,
        "web_push_disabled",
        "web_push_configuration",
        "1" if row else None,
        trusted_client_ip(request),
        detail="Web Push disabled; keys and subscriptions preserved",
        metadata={"key_source": configuration_status(db)["source"]},
    )
    return configuration_status(db)


@router.post("/api/admin/web-push/enable")
def enable_web_push(
    payload: ConfirmedWebPushAction,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    if payload.confirmation != "ENABLE":
        raise HTTPException(400, "Explicit enable confirmation is required")
    _admin_rate_limit(db, user.id, ("web_push_enabled",), limit=10, minutes=10)
    try:
        credentials = effective_credentials(db)
    except WebPushConfigurationError as exc:
        raise HTTPException(400, "Web Push configuration is invalid") from exc
    if not credentials:
        raise HTTPException(400, "Web Push keys are not configured")
    row = ui_configuration(db)
    if row and credentials.source == "kaya":
        row.enabled = True
    _save_setting(db, "notifications_push_enabled", "1")
    _save_setting(db, "notifications_allow_push_registration", "1")
    _audit_or_fail(
        db,
        user,
        "web_push_enabled",
        "web_push_configuration",
        "1" if row else None,
        trusted_client_ip(request),
        detail="Web Push enabled",
        metadata={"key_source": credentials.source},
    )
    return configuration_status(db)


@router.delete("/api/admin/web-push")
def delete_web_push_configuration(
    payload: ConfirmedWebPushAction,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    if payload.confirmation != "DELETE":
        raise HTTPException(400, "Explicit deletion confirmation is required")
    _admin_rate_limit(
        db, user.id, ("web_push_configuration_deleted",), limit=3, minutes=60
    )
    status = configuration_status(db)
    if status["source"] == "deployment":
        raise HTTPException(409, "Deployment-managed Web Push keys cannot be deleted")
    row = ui_configuration(db)
    if not row:
        raise HTTPException(404, "UI-managed Web Push configuration was not found")
    affected = revoke_all_subscriptions(db, "vapid_configuration_deleted")
    db.delete(row)
    _save_setting(db, "notifications_push_enabled", "")
    _save_setting(db, "notifications_allow_push_registration", "")
    _audit_or_fail(
        db,
        user,
        "web_push_configuration_deleted",
        "web_push_configuration",
        "1",
        trusted_client_ip(request),
        detail="UI-managed Web Push configuration deleted",
        metadata={"key_source": "kaya", "affected_subscriptions": affected},
    )
    result = configuration_status(db)
    result["affected_subscriptions"] = affected
    return result


@router.post("/api/admin/web-push/revoke-subscriptions")
def revoke_web_push_subscriptions(
    payload: ConfirmedWebPushAction,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    if payload.confirmation != "REVOKE ALL":
        raise HTTPException(400, "Explicit subscription revocation confirmation is required")
    _admin_rate_limit(
        db, user.id, ("web_push_subscriptions_revoked",), limit=5, minutes=10
    )
    affected = revoke_all_subscriptions(db, "revoked_by_administrator")
    _audit_or_fail(
        db,
        user,
        "web_push_subscriptions_revoked",
        "push_subscription",
        None,
        trusted_client_ip(request),
        detail="All browser push subscriptions revoked",
        metadata={"affected_subscriptions": affected},
    )
    return {"ok": True, "affected_subscriptions": affected}


@router.post("/api/admin/web-push/test")
def admin_push_test(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    _csrf(request)
    _admin_rate_limit(
        db,
        user.id,
        ("web_push_test_sent", "web_push_test_failed"),
        limit=5,
        minutes=10,
    )
    status = configuration_status(db)
    subscriptions = (
        db.query(PushSubscription)
        .filter_by(user_id=user.id, status="active", revoked_at=None)
        .limit(20)
        .all()
    )
    if not status["enabled"] or not subscriptions:
        reason = "not_enabled" if not status["enabled"] else "no_active_subscription"
        _audit_or_fail(
            db,
            user,
            "web_push_test_failed",
            "web_push_configuration",
            None,
            trusted_client_ip(request),
            detail="Administrator Web Push test was not queued",
            metadata={"reason": reason},
        )
        raise HTTPException(
            409,
            "Web Push is not enabled"
            if reason == "not_enabled"
            else "No active browser subscription is registered for this administrator",
        )
    outbox = enqueue_notification(
        db,
        event_type_id="system.notification.test",
        title="Kaya Web Push test",
        message="This is a Web Push test requested from Kaya.",
        target_route="/notifications",
        recipient_ids=[user.id],
        created_by_user_id=user.id,
    )
    queued_devices = len(subscriptions)
    _audit_or_fail(
        db,
        user,
        "web_push_test_sent",
        "notification",
        str(outbox.id),
        trusted_client_ip(request),
        detail="Administrator Web Push test queued",
        metadata={
            "queued_devices": queued_devices,
            "outbox_id": outbox.id,
            "key_source": status["source"],
        },
    )
    return {
        "ok": True,
        "queued_devices": queued_devices,
        "outbox_id": outbox.id,
        "status": "queued",
    }


@router.post("/api/admin/web-push/subscriptions/{subscription_id}/test")
def admin_push_subscription_test(subscription_id: int, request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    _admin_rate_limit(db, user.id, ("web_push_test_sent", "web_push_test_failed"), limit=10, minutes=10)
    subscription = db.get(PushSubscription, subscription_id)
    if not subscription or subscription.status != "active" or subscription.revoked_at:
        raise HTTPException(404, "Registered device is not active")
    if not configuration_status(db)["enabled"]:
        raise HTTPException(409, "Web Push is not enabled")
    outbox = enqueue_notification(db, event_type_id="system.notification.test", title="Kaya Web Push test", message="This is a Web Push test requested from Kaya.", target_route="/notifications", recipient_ids=[subscription.user_id], created_by_user_id=user.id, metadata={"diagnostic": True, "diagnostic_channel": "push", "diagnostic_subscription_id": subscription.id})
    _audit_or_fail(db, user, "web_push_test_sent", "push_subscription", str(subscription.id), trusted_client_ip(request), detail="Administrator queued a per-device Web Push test", metadata={"subscription_id": subscription.id, "outbox_id": outbox.id})
    return {"ok": True, "outbox_id": outbox.id, "subscription_id": subscription.id, "status": "queued"}


@router.delete("/api/admin/web-push/subscriptions/{subscription_id}")
def remove_admin_push_subscription(subscription_id: int, request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    subscription = db.get(PushSubscription, subscription_id)
    if not subscription:
        raise HTTPException(404, "Registered device not found")
    subscription.status = "revoked"
    subscription.revoked_at = datetime.utcnow()
    _audit_or_fail(db, user, "web_push_subscription_removed", "push_subscription", str(subscription.id), trusted_client_ip(request), detail="Administrator removed one registered Web Push device", metadata={"subscription_id": subscription.id, "user_id": subscription.user_id})
    return {"ok": True, "subscription_id": subscription.id, "status": "revoked"}


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


@router.get("/api/admin/notifications/registry-report")
def notification_registry_report(
    db: Session = Depends(get_db), user=Depends(require_admin)
):
    return {
        "events": [
            {
                "event_type": item.identifier,
                "module": item.module,
                "friendly_name": item.display_name,
                "default_severity": item.default_severity,
                "supported_channels": list(item.supported_channels),
                "default_channels": list(item.default_channels),
                "user_configurable": item.user_configurable,
                "recovery_event": item.recovery,
                "deduplication_strategy": item.deduplication_strategy,
                "recipient_strategy": item.recipient_strategy,
                "implemented_publisher": item.implemented_publisher,
                "automated_test_present": item.automated_test_present,
                "available": bool(item.implemented_publisher),
            }
            for item in EVENT_TYPES.values()
        ]
    }


@router.get("/api/admin/notifications/outbox/{outbox_id}")
def notification_pipeline_report(
    outbox_id: int, db: Session = Depends(get_db), user=Depends(require_admin)
):
    row = db.get(NotificationOutbox, outbox_id)
    if not row:
        raise HTTPException(404, "Notification outbox item not found")
    event = db.get(NotificationEvent, row.notification_event_id) if row.notification_event_id else None
    user_notifications = (
        db.query(UserNotification).filter_by(notification_event_id=event.id).all()
        if event
        else []
    )
    user_notification_ids = [item.id for item in user_notifications]
    attempts = (
        db.query(NotificationDeliveryAttempt)
        .filter(NotificationDeliveryAttempt.user_notification_id.in_(user_notification_ids))
        .all()
        if user_notification_ids
        else []
    )
    try:
        outbox_result = json.loads(row.result_json or "{}")
    except (TypeError, json.JSONDecodeError):
        outbox_result = {}
    return {
        "event_registered": row.event_type in EVENT_TYPES,
        "outbox_created": True,
        "outbox_status": row.status,
        "outbox_processed": row.status in {"processed", "suppressed"},
        "reason_code": row.failure_reason_code,
        "event_created": bool(event),
        "candidate_recipients": outbox_result.get("candidate_recipients"),
        "eligible_recipients": outbox_result.get("eligible_recipients"),
        "user_notifications_created": len(user_notifications),
        "push_queued": sum(item.channel == "push" for item in attempts),
        "push_accepted": sum(
            item.channel == "push"
            and item.status in {"accepted", "accepted_by_push_service"}
            for item in attempts
        ),
        "email_queued": sum(item.channel == "email" for item in attempts),
        "email_accepted": sum(
            item.channel == "email" and item.status == "accepted_by_email_service"
            for item in attempts
        ),
        "correlation_id": row.correlation_id,
    }


@router.get("/api/admin/notifications/{notification_id}/delivery-history")
def notification_delivery_history(
    notification_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    row = (
        db.query(UserNotification)
        .options(joinedload(UserNotification.event))
        .filter_by(id=notification_id)
        .first()
    )
    if not row:
        raise HTTPException(404, "Notification not found")
    attempts = (
        db.query(NotificationDeliveryAttempt)
        .filter_by(user_notification_id=row.id)
        .order_by(NotificationDeliveryAttempt.created_at.asc())
        .all()
    )
    history = []
    for attempt in attempts:
        subscription = (
            db.get(PushSubscription, attempt.push_subscription_id)
            if attempt.push_subscription_id
            else None
        )
        history.append(
            {
                "channel": attempt.channel,
                "status": attempt.status,
                "queued_at": attempt.created_at.isoformat() + "Z",
                "last_attempt_at": attempt.attempted_at.isoformat() + "Z",
                "accepted_at": (
                    attempt.accepted_at.isoformat() + "Z"
                    if attempt.accepted_at
                    else None
                ),
                "next_retry_at": (
                    attempt.next_retry_at.isoformat() + "Z"
                    if attempt.next_retry_at
                    else None
                ),
                "reason_code": attempt.failure_reason_code,
                "retry_count": attempt.retry_count,
                "device_label": subscription.device_label if subscription else None,
            }
        )
    return {
        "event_created_at": row.event.created_at.isoformat() + "Z",
        "user_notification_created_at": row.created_at.isoformat() + "Z",
        "in_app": "available",
        "deliveries": history,
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
