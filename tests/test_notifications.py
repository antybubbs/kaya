from datetime import datetime, timedelta
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    NotificationCategoryPolicy,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationPreference,
    PushSubscription,
    RemoteManagerSetting,
    User,
    UserModulePermission,
    UserNotification,
)
from app.core.security import encrypt_secret
from app.routers import notifications as notification_router
from app.routers.auth import require_admin
from app.routers.notifications import PreferenceUpdate, _owned
from app.services.notification_registry import EVENT_TYPES
from app.services.notifications import (
    cleanup_retention,
    preference_allows,
    publish,
    safe_target_route,
    validate_push_endpoint,
)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def user(db: Session, email: str, role: str = "viewer", modules=()) -> User:
    row = User(
        email=email, password_hash="clearly-fake-hash", role=role, is_active=True
    )
    db.add(row)
    db.flush()
    for module in modules:
        db.add(
            UserModulePermission(
                user_id=row.id, module_key=module, allowed=True, created_by=row.id
            )
        )
    db.commit()
    return row


def test_event_registry_is_central_and_structured():
    assert EVENT_TYPES["ipwan.host.offline"].module == "network_monitor"
    assert EVENT_TYPES["ipwan.host.offline"].default_severity == "critical"
    assert EVENT_TYPES["secure_vault.security_event"].sensitive_payload is True
    assert EVENT_TYPES["system.notification.test"].module == "system"


def test_unknown_event_is_rejected_with_structured_log(db, caplog):
    with pytest.raises(ValueError, match="Unknown notification event type"):
        publish(
            db,
            event_type_id="ipwan.host.down",
            title="Synthetic unknown event",
            message="This event must be rejected.",
        )
    assert "notification.publish.failed reason=unknown_event" in caplog.text
    assert "ipwan.host.down" in caplog.text


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/path",
        "//evil.example",
        "/ok?token=secret",
        "/ok#fragment",
        "javascript:alert(1)",
    ],
)
def test_unsafe_notification_routes_are_rejected(target):
    with pytest.raises(ValueError):
        safe_target_route(target)
    assert (
        safe_target_route("/networking/ip-wan-monitor/12")
        == "/networking/ip-wan-monitor/12"
    )


def test_push_endpoint_validation_blocks_ssrf_and_unapproved_hosts(monkeypatch):
    monkeypatch.setattr(
        "app.services.notifications.socket.getaddrinfo",
        lambda *_args: [(None, None, None, None, ("8.8.8.8", 443))],
    )
    assert validate_push_endpoint("https://fcm.googleapis.com/fcm/send/fake")
    with pytest.raises(ValueError, match="approved browser push service"):
        validate_push_endpoint("https://127.0.0.1/internal")
    with pytest.raises(ValueError, match="approved browser push service"):
        validate_push_endpoint("https://attacker.example/collect")

    monkeypatch.setattr(
        "app.services.notifications.socket.getaddrinfo",
        lambda *_args: [(None, None, None, None, ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="public addresses"):
        validate_push_endpoint("https://fcm.googleapis.com/fcm/send/fake")


def test_publish_filters_inactive_and_unauthorised_recipients(db):
    allowed = user(db, "allowed@example.invalid", modules=("network_monitor",))
    denied = user(db, "denied@example.invalid")
    inactive = user(db, "inactive@example.invalid", modules=("network_monitor",))
    inactive.is_active = False
    db.commit()
    event = publish(
        db,
        event_type_id="ipwan.host.offline",
        title="Host offline",
        message="Synthetic router is unavailable.",
        recipient_ids=[allowed.id, denied.id, inactive.id],
        target_route="/networking/ip-wan-monitor/1",
    )
    recipients = {
        row.user_id
        for row in db.query(UserNotification).filter_by(notification_event_id=event.id)
    }
    assert recipients == {allowed.id}


def test_deduplication_prevents_polling_storms(db):
    allowed = user(db, "monitor@example.invalid", modules=("network_monitor",))
    first = publish(
        db,
        event_type_id="ipwan.host.offline",
        title="Host offline",
        message="Synthetic router is unavailable.",
        recipient_ids=[allowed.id],
        deduplication_key="ipwan:host:1:offline",
    )
    second = publish(
        db,
        event_type_id="ipwan.host.offline",
        title="Host offline",
        message="Synthetic router remains unavailable.",
        recipient_ids=[allowed.id],
        deduplication_key="ipwan:host:1:offline",
    )
    assert second.id == first.id
    assert db.query(NotificationEvent).count() == 1
    assert db.query(UserNotification).count() == 1


def test_sensitive_event_payload_is_minimised(db):
    recipient = user(db, "vault@example.invalid", modules=("secret_vault",))
    event = publish(
        db,
        event_type_id="secure_vault.security_event",
        title="Firewall Root Password viewed",
        message="Secret value abc123 was viewed by a person",
        recipient_ids=[recipient.id],
    )
    assert event.title == "Vault security event"
    assert event.message == "Open Kaya to review this security-sensitive event."


def test_mandatory_policy_cannot_be_opted_out(db):
    recipient = user(db, "admin@example.invalid", role="admin")
    db.add(
        NotificationCategoryPolicy(
            event_type="system.security.warning",
            user_can_opt_out=False,
            enabled=True,
            in_app_allowed=True,
        )
    )
    db.add(
        NotificationPreference(
            user_id=recipient.id,
            event_type="system.security.warning",
            in_app_enabled=False,
        )
    )
    db.commit()
    assert (
        preference_allows(
            db, recipient.id, "system.security.warning", "critical", "in_app"
        )
        is True
    )


def test_enabled_user_channels_create_delivery_jobs_without_exposing_secrets(db):
    recipient = user(db, "delivery@example.invalid", role="admin")
    db.add_all(
        [
            RemoteManagerSetting(key="notifications_push_enabled", value="1"),
            RemoteManagerSetting(key="notifications_email_enabled", value="1"),
            NotificationCategoryPolicy(
                event_type="system.security.warning",
                enabled=True,
                in_app_allowed=True,
                push_allowed=True,
                email_allowed=True,
            ),
            NotificationPreference(
                user_id=recipient.id,
                event_type="system.security.warning",
                push_enabled=True,
                email_enabled=True,
            ),
            PushSubscription(
                user_id=recipient.id,
                endpoint_hash="0" * 64,
                encrypted_subscription=encrypt_secret(
                    '{"endpoint":"https://fcm.googleapis.com/fcm/send/fake","keys":{"p256dh":"fake","auth":"fake"}}'
                ),
            ),
        ]
    )
    db.commit()
    event = publish(
        db,
        event_type_id="system.security.warning",
        title="Synthetic delivery warning",
        message="Review Kaya.",
        recipient_ids=[recipient.id],
    )
    notification = (
        db.query(UserNotification).filter_by(notification_event_id=event.id).one()
    )
    attempts = {
        row.channel
        for row in db.query(NotificationDeliveryAttempt).filter_by(
            user_notification_id=notification.id
        )
    }
    assert attempts == {"push", "email"}


def test_notification_lookup_is_object_scoped(db):
    first = user(db, "first@example.invalid", role="admin")
    second = user(db, "second@example.invalid", role="admin")
    event = publish(
        db,
        event_type_id="system.security.warning",
        title="Synthetic warning",
        message="Review Kaya.",
        recipient_ids=[first.id],
    )
    notification = (
        db.query(UserNotification).filter_by(notification_event_id=event.id).one()
    )
    assert _owned(db, first.id, notification.id).id == notification.id
    with pytest.raises(Exception) as exc:
        _owned(db, second.id, notification.id)
    assert getattr(exc.value, "status_code", None) == 404


def test_admin_in_app_diagnostic_uses_registered_event_and_reports_channels(db):
    admin = user(db, "diagnostic-admin@example.invalid", role="admin")
    request = SimpleNamespace(
        headers={"x-csrf-token": "fake-csrf-token"},
        session={"csrf_token": "fake-csrf-token"},
    )
    result = notification_router.test_notification(request, db=db, user=admin)
    assert result == {
        "ok": True,
        "event_created": True,
        "recipient_resolved": True,
        "user_notification_created": True,
        "in_app": "available",
        "push": "skipped: not configured",
        "email": "skipped: disabled",
    }
    event = db.query(NotificationEvent).one()
    assert event.event_type == "system.notification.test"
    dependency = inspect.signature(notification_router.test_notification).parameters[
        "user"
    ].default
    assert dependency.dependency is require_admin


def test_unavailable_push_preference_cannot_be_saved(db):
    recipient = user(db, "push-preference@example.invalid", role="admin")
    request = SimpleNamespace(
        headers={"x-csrf-token": "fake-csrf-token"},
        session={"csrf_token": "fake-csrf-token"},
    )
    payload = PreferenceUpdate(
        event_type="system.notification.test", push_enabled=True, timezone="UTC"
    )
    with pytest.raises(Exception) as exc:
        notification_router.update_preference(
            "system.notification.test", payload, request, db=db, user=recipient
        )
    assert getattr(exc.value, "status_code", None) == 400
    assert "Web Push is unavailable" in getattr(exc.value, "detail", "")


def test_retention_removes_old_read_records_but_keeps_recent_unread(db):
    recipient = user(db, "retention@example.invalid", role="admin")
    db.add_all(
        [
            RemoteManagerSetting(key="notifications_read_retention_days", value="30"),
            RemoteManagerSetting(
                key="notifications_unread_retention_days", value="365"
            ),
        ]
    )
    db.commit()
    old = publish(
        db,
        event_type_id="system.security.warning",
        title="Old synthetic warning",
        message="Review Kaya.",
        recipient_ids=[recipient.id],
    )
    recent = publish(
        db,
        event_type_id="system.security.warning",
        title="Recent synthetic warning",
        message="Review Kaya.",
        recipient_ids=[recipient.id],
    )
    old_user = db.query(UserNotification).filter_by(notification_event_id=old.id).one()
    old_user.read_at = datetime.utcnow() - timedelta(days=31)
    old_user.created_at = datetime.utcnow() - timedelta(days=31)
    db.commit()
    result = cleanup_retention(db)
    assert result["read"] == 1
    assert (
        db.query(UserNotification).filter_by(notification_event_id=recent.id).count()
        == 1
    )


def test_push_assets_never_trust_payload_urls_or_prompt_on_load():
    root = Path(__file__).resolve().parents[1]
    worker = (root / "app/static/service-worker.js").read_text(encoding="utf-8")
    client = (root / "app/static/js/notifications.js").read_text(encoding="utf-8")
    assert "safeNotificationTarget" in worker
    assert "target.origin !== self.location.origin" in worker
    assert "Notification.requestPermission()" in client
    assert "[data-enable-push]" in client
    assert client.index("Notification.requestPermission()") > client.index(
        'addEventListener("click"'
    )
