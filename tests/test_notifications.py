from datetime import datetime, timedelta
import base64
import inspect
import json
import logging
import sqlite3
from sqlalchemy import event
from sqlalchemy.exc import OperationalError
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    AuditLog,
    NotificationCategoryPolicy,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationOutbox,
    NotificationPreference,
    NotificationReconciliationFailure,
    PushSubscription,
    RemoteManagerSetting,
    User,
    UserModulePermission,
    UserNotification,
    WebPushConfiguration,
)
from app.core.security import decrypt_secret, encrypt_secret
from app.routers import notifications as notification_router
from app.routers.auth import require_admin
from app.routers.notifications import (
    ConfirmedWebPushAction,
    PreferenceUpdate,
    ReconciliationFailureAction,
    WebPushKeyRequest,
    _owned,
)
from app.services.notification_registry import EVENT_TYPES
from app.services.notification_outbox import enqueue_notification, process_outbox
from app.services import notification_outbox
from app.services import notification_delivery
from app.services.notifications import (
    cleanup_retention,
    preference_allows,
    publish,
    safe_target_route,
    validate_push_endpoint,
)
from app.services.web_push_config import (
    InvalidVapidSubjectError,
    WebPushConfigurationError,
    configuration_status,
    create_ui_configuration,
    effective_credentials,
    generate_key_pair,
    validate_subject_uri,
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


def csrf_request():
    return SimpleNamespace(
        headers={"x-csrf-token": "fake-csrf-token"},
        session={"csrf_token": "fake-csrf-token"},
        state=SimpleNamespace(),
        scope={"client": ("127.0.0.1", 12345), "headers": []},
    )


def test_event_registry_is_central_and_structured():
    assert EVENT_TYPES["ipwan.host.offline"].module == "network_monitor"
    assert EVENT_TYPES["ipwan.host.offline"].default_severity == "critical"
    assert EVENT_TYPES["secure_vault.security_event"].sensitive_payload is True
    assert EVENT_TYPES["system.notification.test"].module == "system"
    assert EVENT_TYPES["pihole.failover.started"].module == "high_availability"
    assert EVENT_TYPES["pihole.failback.completed"].default_severity == "success"


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


def test_infrastructure_events_include_active_administrator_without_module_row(db):
    admin = user(db, "implicit-admin@example.invalid", role="admin")
    event = publish(
        db,
        event_type_id="ipwan.host.offline",
        title="Host offline",
        message="Synthetic target is unavailable.",
    )
    assert db.query(UserNotification).filter_by(
        notification_event_id=event.id, user_id=admin.id
    ).count() == 1


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


def test_outbox_survives_session_boundary_and_retries_publication(db, monkeypatch):
    recipient = user(db, "outbox-retry@example.invalid", role="admin")
    outbox = enqueue_notification(
        db,
        event_type_id="system.notification.test",
        title="Synthetic durable notification",
        message="This synthetic event verifies restart-safe retry.",
        recipient_ids=[recipient.id],
    )
    db.commit()
    outbox_id = outbox.id
    factory = sessionmaker(bind=db.bind)
    original_publish = notification_outbox.publish
    calls = 0

    def transient_publish(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic transient publication failure")
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(notification_outbox, "publish", transient_publish)
    assert process_outbox(session_factory=factory) == 0
    db.expire_all()
    failed = db.get(NotificationOutbox, outbox_id)
    assert failed.status == "retry"
    assert failed.failure_reason_code == "publication_error"
    failed.next_retry_at = datetime.utcnow()
    db.commit()

    assert process_outbox(session_factory=factory) == 1
    db.expire_all()
    completed = db.get(NotificationOutbox, outbox_id)
    assert completed.status == "processed"
    assert completed.notification_event_id is not None


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

    outbox = enqueue_notification(
        db,
        event_type_id="secure_vault.security_event",
        title="Synthetic secret name",
        message="Synthetic secret value must not persist",
        recipient_ids=[recipient.id],
    )
    assert outbox.title == "Vault security event"
    assert outbox.message == "Open Kaya to review this security-sensitive event."


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


def test_one_invalid_push_device_does_not_block_another(db, monkeypatch):
    recipient = user(db, "push-isolation@example.invalid", role="admin")
    db.add_all(
        [
            RemoteManagerSetting(key="notifications_push_enabled", value="1"),
            NotificationCategoryPolicy(
                event_type="system.security.warning",
                enabled=True,
                in_app_allowed=True,
                push_allowed=True,
            ),
            NotificationPreference(
                user_id=recipient.id,
                event_type="system.security.warning",
                push_enabled=True,
            ),
            PushSubscription(
                user_id=recipient.id,
                endpoint_hash="1" * 64,
                encrypted_subscription=encrypt_secret(
                    '{"endpoint":"https://fcm.googleapis.com/bad","keys":{}}'
                ),
            ),
            PushSubscription(
                user_id=recipient.id,
                endpoint_hash="2" * 64,
                encrypted_subscription=encrypt_secret(
                    '{"endpoint":"https://fcm.googleapis.com/good","keys":{}}'
                ),
            ),
        ]
    )
    db.commit()
    publish(
        db,
        event_type_id="system.security.warning",
        title="Synthetic warning",
        message="Review Kaya.",
        recipient_ids=[recipient.id],
    )
    factory = sessionmaker(bind=db.bind)
    monkeypatch.setattr(notification_delivery, "SessionLocal", factory)
    monkeypatch.setattr(
        notification_delivery,
        "effective_credentials",
        lambda _db: SimpleNamespace(private_key="fake", subject="mailto:fake@example.invalid"),
    )

    def fake_send(subscription, _payload, _credentials):
        if subscription["endpoint"].endswith("/bad"):
            raise RuntimeError("synthetic provider failure")

    monkeypatch.setattr(notification_delivery, "_send_push", fake_send)
    assert notification_delivery.deliver_queued() == 1
    db.expire_all()
    statuses = sorted(
        row.status for row in db.query(NotificationDeliveryAttempt).order_by(
            NotificationDeliveryAttempt.id
        )
    )
    assert statuses == ["accepted_by_push_service", "temporary_failure"]


def test_delivery_does_not_issue_stale_recovery_update_when_nothing_is_stale(
    db, monkeypatch
):
    factory = sessionmaker(bind=db.bind)
    monkeypatch.setattr(notification_delivery, "SessionLocal", factory)
    statements = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement.lower())

    event.listen(db.bind, "before_cursor_execute", capture)
    try:
        assert notification_delivery.deliver_queued() == 0
    finally:
        event.remove(db.bind, "before_cursor_execute", capture)

    assert not any(
        "update notification_delivery_attempts" in statement for statement in statements
    )


def test_targeted_push_test_returns_controlled_503_after_sqlite_busy(db, monkeypatch):
    admin = user(db, "busy-admin@example.invalid", role="admin")
    subscription = PushSubscription(
        user_id=admin.id,
        endpoint_hash="b" * 64,
        encrypted_subscription=encrypt_secret("{}"),
        status="active",
    )
    db.add(subscription)
    db.commit()
    monkeypatch.setattr(notification_router, "_csrf", lambda _request: None)
    monkeypatch.setattr(notification_router, "_admin_rate_limit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(notification_router, "configuration_status", lambda _db: {"enabled": True})

    def locked_enqueue(*_args, **_kwargs):
        raise OperationalError("INSERT", {}, sqlite3.OperationalError("database is locked"))

    monkeypatch.setattr(notification_router, "enqueue_notification", locked_enqueue)

    with pytest.raises(Exception) as exc:
        notification_router.admin_push_subscription_test(
            subscription.id, csrf_request(), db=db, user=admin
        )

    assert getattr(exc.value, "status_code", None) == 503
    assert "temporarily busy" in getattr(exc.value, "detail", "")
    assert db.get(PushSubscription, subscription.id) is not None


def test_windows_push_uses_only_documented_wns_extension():
    windows = {"endpoint": "https://wns2-ln2p.notify.windows.com/w/?fake"}
    apple = {"endpoint": "https://web.push.apple.com/QH/fake"}

    assert notification_delivery._windows_push_headers(windows) == (
        {
            "X-WNS-Type": "wns/raw",
            "Content-Type": "application/octet-stream",
        },
        notification_delivery.WINDOWS_PUSH_TTL_SECONDS,
    )
    assert notification_delivery._windows_push_headers(apple) == ({}, 0)


def test_vapid_diagnostics_redact_jwt_and_extract_only_safe_claims():
    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    now = datetime.now().astimezone()
    token = ".".join(
        [
            b64(b'{"alg":"ES256"}'),
            b64(
                json.dumps(
                    {
                        "aud": "https://wns2-ln2p.notify.windows.com",
                        "exp": int(now.timestamp()) + 600,
                        "sub": "mailto:secret@example.invalid",
                    }
                ).encode()
            ),
            "signature-is-not-logged",
        ]
    )

    result = notification_delivery._safe_vapid_claims(
        f"vapid t={token}, k=public-key-is-not-logged", now
    )

    assert result == {
        "authorization_style": "vapid",
        "vapid_key_location": "authorization",
        "jwt_aud": "https://wns2-ln2p.notify.windows.com",
        "jwt_exp": int(now.timestamp()) + 600,
        "jwt_seconds_until_expiry": 600,
    }


def test_windows_response_diagnostics_keep_safe_wns_values_only():
    class Response:
        status_code = 400
        headers = {
            "X-WNS-Error-Description": "  malformed content type  ",
            "X-WNS-NotificationStatus": "Dropped",
            "X-WNS-Status": "400",
            "X-WNS-Msg-ID": "synthetic-message-id",
        }

    error = RuntimeError("synthetic provider failure")
    error.response = Response()
    assert notification_delivery._safe_response_diagnostics(error) == {
        "response_header_names": [
            "x-wns-error-description",
            "x-wns-msg-id",
            "x-wns-notificationstatus",
            "x-wns-status",
        ],
        "provider_request_id": "x-wns-msg-id:synthetic-message-id",
        "wns_error_description": "malformed content type",
        "wns_notification_status": "Dropped",
        "wns_status": "400",
    }


def test_vapid_subject_is_canonical_and_empty_mailto_is_rejected():
    assert validate_subject_uri("mailto:Admin@example.com") == "mailto:Admin@example.com"
    assert validate_subject_uri("https://kaya.example.com/contact") == "https://kaya.example.com/contact"
    for invalid in (None, "", "mailto:", "mailto", "@"):
        with pytest.raises(InvalidVapidSubjectError):
            validate_subject_uri(invalid)


def test_delivery_subject_diagnostics_are_unambiguous_and_redacted():
    assert notification_delivery._safe_subject_diagnostics(
        "mailto:admin@example.com"
    ) == {
        "vapid_subject_scheme": "mailto",
        "vapid_subject_present": True,
        "vapid_subject_length": len("mailto:admin@example.com"),
        "vapid_subject_valid": True,
    }


def test_malformed_persisted_vapid_subject_fails_before_delivery(db):
    public_key, private_key = generate_key_pair()
    db.add(
        WebPushConfiguration(
            id=1,
            public_key=public_key,
            public_key_fingerprint="synthetic",
            encrypted_private_key=encrypt_secret(private_key),
            subject="mailto:",
            enabled=True,
        )
    )
    db.commit()

    with pytest.raises(InvalidVapidSubjectError):
        effective_credentials(db)
    status = configuration_status(db)
    assert status["state"] == "configuration_error"
    assert status["configured_contact_present"] is True
    assert status["configured_contact_scheme"] == "mailto"
    assert status["configured_contact_length"] == len("mailto:")


def test_admin_can_correct_vapid_contact_without_rotating_keys_or_subscriptions(db):
    admin = user(db, "contact-admin@example.invalid", role="admin")
    row = create_ui_configuration(
        db,
        subject="mailto:old@example.invalid",
        installation_label="Synthetic",
        rotate=False,
    )
    subscription = PushSubscription(
        user_id=admin.id,
        endpoint_hash="c" * 64,
        encrypted_subscription=encrypt_secret("{}"),
        status="active",
    )
    db.add(subscription)
    db.commit()
    original_public_key = row.public_key
    original_private_key = row.encrypted_private_key

    result = notification_router.update_web_push_contact(
        notification_router.WebPushContactRequest(
            contact_email="new@example.com"
        ),
        csrf_request(),
        db=db,
        user=admin,
    )

    db.expire_all()
    corrected = db.get(WebPushConfiguration, 1)
    assert result["subject"] == "mailto:new@example.com"
    assert corrected.subject == "mailto:new@example.com"
    assert corrected.public_key == original_public_key
    assert corrected.encrypted_private_key == original_private_key
    assert db.get(PushSubscription, subscription.id).status == "active"


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


def test_admin_in_app_diagnostic_uses_only_in_app_channel(db):
    admin = user(db, "diagnostic-admin@example.invalid", role="admin")
    request = SimpleNamespace(
        headers={"x-csrf-token": "fake-csrf-token"},
        session={"csrf_token": "fake-csrf-token"},
    )
    result = notification_router.test_notification(request, db=db, user=admin)
    assert result == {
        "ok": True,
        "outbox_created": True,
        "outbox_id": 1,
        "status": "queued",
        "in_app": "pending outbox processing",
        "push": "not requested",
        "email": "not requested",
    }
    assert db.query(NotificationOutbox).filter_by(status="pending").count() == 1
    process_outbox(session_factory=sessionmaker(bind=db.bind))
    db.expire_all()
    event = db.query(NotificationEvent).one()
    assert event.event_type == "system.notification.test"
    assert db.query(NotificationDeliveryAttempt).count() == 0
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


def test_admin_generates_encrypted_ui_vapid_configuration_without_secret_response(
    db, caplog
):
    admin = user(db, "vapid-admin@example.invalid", role="admin")
    request = csrf_request()
    request.state.request_id = "synthetic-request-id"
    caplog.set_level(logging.INFO, logger="app.routers.notifications")
    result = notification_router.generate_web_push_keys(
        WebPushKeyRequest(
            contact_email="admin@example.com",
            installation_label="Synthetic installation",
            confirmation="GENERATE",
        ),
        request,
        db=db,
        user=admin,
    )
    row = db.get(WebPushConfiguration, 1)
    recovered_private = decrypt_secret(row.encrypted_private_key)
    assert result["state"] == "configured"
    assert result["source"] == "kaya"
    assert result["browser_registration_available"] is True
    assert result["public_key_fingerprint"].startswith("SHA256:")
    assert "private" not in json.dumps(result).lower()
    assert row.encrypted_private_key != recovered_private
    assert len(recovered_private) == 43
    assert recovered_private not in row.encrypted_private_key
    assert notification_router.vapid_public_key(db=db, user=admin) == {
        "public_key": row.public_key
    }
    audit = db.query(AuditLog).filter_by(action="web_push_keys_generated").one()
    assert recovered_private not in (audit.metadata_json or "")
    assert recovered_private not in (audit.detail or "")
    assert "vapid.generate.requested" in caplog.text
    assert "vapid.generate.completed" in caplog.text
    assert "request_id=synthetic-request-id" in caplog.text
    assert recovered_private not in caplog.text


def test_generation_fails_visibly_before_key_creation_when_encryption_is_unavailable(
    db, monkeypatch, caplog
):
    admin = user(db, "encryption-failure@example.invalid", role="admin")
    monkeypatch.setattr(
        "app.services.web_push_config.encrypt_secret",
        lambda _value: (_ for _ in ()).throw(ValueError("synthetic key failure")),
    )
    monkeypatch.setattr(
        "app.services.web_push_config.generate_key_pair",
        lambda: (_ for _ in ()).throw(AssertionError("key generation must not run")),
    )
    caplog.set_level(logging.INFO, logger="app.routers.notifications")

    with pytest.raises(Exception) as exc:
        notification_router.generate_web_push_keys(
            WebPushKeyRequest(
                contact_email="admin@example.com", confirmation="GENERATE"
            ),
            csrf_request(),
            db=db,
            user=admin,
        )

    assert getattr(exc.value, "status_code", None) == 503
    assert "installation encryption key is unavailable or invalid" in getattr(
        exc.value, "detail", ""
    )
    assert db.get(WebPushConfiguration, 1) is None
    assert "vapid.generate.failed" in caplog.text
    assert "reason=encryption_unavailable" in caplog.text


def test_generation_validation_failure_is_safe_and_logged(db, caplog):
    admin = user(db, "validation-failure@example.invalid", role="admin")
    caplog.set_level(logging.INFO, logger="app.routers.notifications")

    with pytest.raises(Exception) as exc:
        notification_router.generate_web_push_keys(
            WebPushKeyRequest(
                contact_email="not-an-email", confirmation="GENERATE"
            ),
            csrf_request(),
            db=db,
            user=admin,
        )

    assert getattr(exc.value, "status_code", None) == 400
    assert "Invalid contact email" in getattr(exc.value, "detail", "")
    assert "vapid.generate.validation_failed" in caplog.text
    assert "not-an-email" not in caplog.text


def test_web_push_key_management_routes_are_admin_only():
    for endpoint in (
        notification_router.admin_web_push_status,
        notification_router.generate_web_push_keys,
        notification_router.rotate_web_push_keys,
        notification_router.disable_web_push,
        notification_router.enable_web_push,
        notification_router.delete_web_push_configuration,
        notification_router.revoke_web_push_subscriptions,
        notification_router.admin_push_test,
        notification_router.admin_push_subscription_test,
        notification_router.admin_push_subscription_status,
        notification_router.remove_admin_push_subscription,
    ):
        dependency = inspect.signature(endpoint).parameters["user"].default
        assert dependency.dependency is require_admin


def test_admin_mobile_pwa_health_uses_latest_success_over_historical_failure(db):
    admin = user(db, "health-admin@example.invalid", role="admin")
    failure_at = datetime(2026, 8, 10, 11, 55)
    success_at = datetime(2026, 8, 10, 12, 1)
    subscription = PushSubscription(
        user_id=admin.id,
        endpoint_hash="h" * 64,
        encrypted_subscription=encrypt_secret("{}"),
        last_failure_at=failure_at,
        last_success_at=success_at,
        failure_count=0,
    )
    db.add(subscription)
    db.commit()

    event = NotificationEvent(
        event_type="system.notification.test",
        module="system",
        category="system",
        severity="info",
        title="Synthetic test",
        message="Synthetic test",
    )
    db.add(event)
    db.flush()
    user_notification = UserNotification(
        notification_event_id=event.id,
        user_id=admin.id,
    )
    db.add(user_notification)
    db.flush()
    attempt = NotificationDeliveryAttempt(
        user_notification_id=user_notification.id,
        channel="push",
        push_subscription_id=subscription.id,
        status="permanent_failure",
        failure_reason_code="provider_rejected",
        attempted_at=failure_at,
        created_at=failure_at,
    )
    db.add(attempt)
    db.commit()

    response = notification_router.notification_admin_page(
        SimpleNamespace(), db=db, user=admin
    )
    device = response.context["web_push"]["devices"][0]
    assert device["status"] == "Active"
    assert device["failure_is_historical"] is True
    assert response.context["web_push"]["healthy_devices"] == 1
    assert response.context["web_push"]["attention_devices"] == 0
    assert db.query(NotificationDeliveryAttempt).count() == 1


def test_push_device_status_follows_latest_outcome_and_preserves_invalidation():
    row = SimpleNamespace(
        status="active",
        revoked_at=None,
        last_success_at=datetime(2026, 8, 10, 12, 1),
        last_failure_at=datetime(2026, 8, 10, 11, 55),
    )
    failure = SimpleNamespace(status="permanent_failure")
    assert notification_router.push_device_status(row, failure) == "Active"

    row.last_failure_at = datetime(2026, 8, 10, 12, 2)
    assert notification_router.push_device_status(row, failure) == "Delivery rejected"

    row.status = "expired"
    assert notification_router.push_device_status(row, failure) == "Needs refresh"


def test_ui_vapid_configuration_survives_a_new_database_session(db):
    create_ui_configuration(
        db,
        subject="mailto:restart@example.com",
        installation_label="Restart test",
        rotate=False,
    )
    db.commit()
    with Session(db.get_bind()) as restarted:
        credentials = effective_credentials(restarted)
        assert credentials is not None
        assert credentials.source == "kaya"
        assert credentials.subject == "mailto:restart@example.com"


def test_rotation_revokes_subscriptions_and_notifies_administrators(db):
    admin = user(db, "rotate-admin@example.invalid", role="admin")
    notification_router.generate_web_push_keys(
        WebPushKeyRequest(
            contact_email="rotate@example.com", confirmation="GENERATE"
        ),
        csrf_request(),
        db=db,
        user=admin,
    )
    original = db.get(WebPushConfiguration, 1).public_key_fingerprint
    subscription = PushSubscription(
        user_id=admin.id,
        endpoint_hash="a" * 64,
        encrypted_subscription=encrypt_secret(
            '{"endpoint":"https://fcm.googleapis.com/fcm/send/fake","keys":{"p256dh":"fake","auth":"fake"}}'
        ),
    )
    db.add(subscription)
    db.commit()
    result = notification_router.rotate_web_push_keys(
        WebPushKeyRequest(
            contact_email="rotate@example.com", confirmation="ROTATE"
        ),
        csrf_request(),
        db=db,
        user=admin,
    )
    db.refresh(subscription)
    assert result["affected_subscriptions"] == 1
    assert result["public_key_fingerprint"] != original
    assert subscription.status == "revoked" and subscription.revoked_at is not None
    assert db.query(NotificationEvent).filter_by(
        event_type="system.web_push.keys_rotated"
    ).count() == 1


def test_disable_preserves_keys_subscriptions_preferences_and_in_app(db):
    admin = user(db, "disable-admin@example.invalid", role="admin")
    notification_router.generate_web_push_keys(
        WebPushKeyRequest(
            contact_email="disable@example.com", confirmation="GENERATE"
        ),
        csrf_request(),
        db=db,
        user=admin,
    )
    subscription = PushSubscription(
        user_id=admin.id,
        endpoint_hash="b" * 64,
        encrypted_subscription=encrypt_secret("{}"),
    )
    preference = NotificationPreference(
        user_id=admin.id,
        event_type="system.notification.test",
        in_app_enabled=True,
        push_enabled=True,
    )
    db.add_all([subscription, preference])
    db.commit()
    notification_router.disable_web_push(
        ConfirmedWebPushAction(confirmation="DISABLE"),
        csrf_request(),
        db=db,
        user=admin,
    )
    assert db.get(WebPushConfiguration, 1) is not None
    assert db.get(PushSubscription, subscription.id).status == "active"
    assert db.get(NotificationPreference, preference.id).push_enabled is True
    event = publish(
        db,
        event_type_id="system.notification.test",
        title="Synthetic in-app test",
        message="In-app remains available.",
        recipient_ids=[admin.id],
    )
    assert db.query(UserNotification).filter_by(
        notification_event_id=event.id, user_id=admin.id
    ).count() == 1
    assert db.query(NotificationDeliveryAttempt).filter_by(
        user_notification_id=db.query(UserNotification.id).filter_by(
            notification_event_id=event.id, user_id=admin.id
        ).scalar()
    ).count() == 0


def test_delete_removes_ui_keys_and_revokes_subscriptions(db):
    admin = user(db, "delete-admin@example.invalid", role="admin")
    notification_router.generate_web_push_keys(
        WebPushKeyRequest(
            contact_email="delete@example.com", confirmation="GENERATE"
        ),
        csrf_request(),
        db=db,
        user=admin,
    )
    subscription = PushSubscription(
        user_id=admin.id,
        endpoint_hash="c" * 64,
        encrypted_subscription=encrypt_secret("{}"),
    )
    db.add(subscription)
    db.commit()
    result = notification_router.delete_web_push_configuration(
        ConfirmedWebPushAction(confirmation="DELETE"),
        csrf_request(),
        db=db,
        user=admin,
    )
    assert result["state"] == "not_configured"
    assert result["affected_subscriptions"] == 1
    assert db.get(WebPushConfiguration, 1) is None
    assert db.get(PushSubscription, subscription.id).status == "revoked"


def test_environment_keys_override_ui_and_invalid_environment_fails_closed(
    db, monkeypatch
):
    ui_public, ui_private = generate_key_pair()
    db.add(
        WebPushConfiguration(
            id=1,
            encrypted_private_key=encrypt_secret(ui_private),
            public_key=ui_public,
            public_key_fingerprint="SHA256:UI",
            subject="mailto:ui@example.com",
        )
    )
    db.commit()
    deployment_public, deployment_private = generate_key_pair()
    monkeypatch.setattr(
        "app.services.web_push_config.get_settings",
        lambda: SimpleNamespace(
            vapid_public_key=deployment_public,
            vapid_private_key=deployment_private,
            vapid_subject="mailto:deployment@example.com",
        ),
    )
    credentials = effective_credentials(db)
    assert credentials.source == "deployment"
    assert credentials.public_key == deployment_public
    assert configuration_status(db)["state"] == "managed_by_deployment"
    admin = user(db, "deployment-admin@example.invalid", role="admin")
    with pytest.raises(Exception) as exc:
        notification_router.delete_web_push_configuration(
            ConfirmedWebPushAction(confirmation="DELETE"),
            csrf_request(),
            db=db,
            user=admin,
        )
    assert getattr(exc.value, "status_code", None) == 409

    monkeypatch.setattr(
        "app.services.web_push_config.get_settings",
        lambda: SimpleNamespace(
            vapid_public_key=deployment_public,
            vapid_private_key="",
            vapid_subject="mailto:deployment@example.com",
        ),
    )
    assert configuration_status(db)["state"] == "invalid_configuration"
    with pytest.raises(WebPushConfigurationError):
        effective_credentials(db)


def test_admin_push_test_distinguishes_missing_and_active_subscription(db):
    admin = user(db, "push-test-admin@example.invalid", role="admin")
    notification_router.generate_web_push_keys(
        WebPushKeyRequest(
            contact_email="push-test@example.com", confirmation="GENERATE"
        ),
        csrf_request(),
        db=db,
        user=admin,
    )
    with pytest.raises(Exception) as missing:
        notification_router.admin_push_test(csrf_request(), db=db, user=admin)
    assert getattr(missing.value, "status_code", None) == 409
    assert "No active browser subscription" in getattr(missing.value, "detail", "")
    db.add(
        PushSubscription(
            user_id=admin.id,
            endpoint_hash="d" * 64,
            encrypted_subscription=encrypt_secret("{}"),
        )
    )
    db.commit()
    result = notification_router.admin_push_test(csrf_request(), db=db, user=admin)
    assert result["queued_devices"] == 1
    assert result["status"] == "queued"
    assert db.query(NotificationOutbox).filter_by(status="pending").count() == 1


def test_admin_can_retry_quarantined_reconciliation_item_with_csrf_and_audit(db):
    admin = user(db, "reconciliation-admin@example.invalid", role="admin")
    failure = NotificationReconciliationFailure(
        item_type="network_monitor",
        item_id="42",
        operation="offline",
        status="quarantined",
        attempt_count=5,
        last_exception_type="ValueError",
        last_error_code="reconciliation_item_error",
        correlation_id="d" * 32,
        quarantined_at=datetime.utcnow(),
    )
    db.add(failure)
    db.commit()

    result = notification_router.update_reconciliation_failure(
        failure.id,
        ReconciliationFailureAction(action="retry"),
        csrf_request(),
        db=db,
        user=admin,
    )

    db.refresh(failure)
    assert result == {"ok": True, "status": "retry"}
    assert failure.attempt_count == 0
    assert failure.quarantined_at is None
    assert db.query(AuditLog).filter_by(
        action="notification_reconciliation_failure_retried"
    ).count() == 1


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


def test_web_push_modal_is_inside_admin_js_scope_and_has_mobile_safe_feedback():
    root = Path(__file__).resolve().parents[1]
    template = (root / "app/templates/notification_admin.html").read_text(
        encoding="utf-8"
    )
    client = (root / "app/static/js/notifications.js").read_text(encoding="utf-8")
    css = (root / "app/static/css/notifications.css").read_text(encoding="utf-8")
    base = (root / "app/templates/base.html").read_text(encoding="utf-8")
    worker = (root / "app/static/service-worker.js").read_text(encoding="utf-8")

    scope_start = template.index('data-notification-admin data-csrf-token=')
    scope_end = template.rindex("</div>\n{% endblock %}")
    web_push_card = template.index('class="panel web-push-configuration"')
    general_form_end = template.index("</form></section>")
    assert scope_start < general_form_end < web_push_card < scope_end
    assert '<button type="button" data-web-push-open="generate">' in template
    assert "<h2>Mobile PWA</h2>" in template
    assert "Registered devices" in template
    assert "mobile-pwa-device" in template
    assert "mobile-pwa-overview" in css
    assert "healthy_devices" in template
    assert "mobile-pwa-device-actions" in template
    assert "data-web-push-form-status" in template
    assert "openWebPushDialog" in client
    assert 'keyForm.dataset.submitting==="1"' in client
    assert 'submit.textContent=mode==="rotate"?"Rotating…":"Generating…"' in client
    assert "100dvh" in css
    assert "safe-area-inset-top" in css
    assert "js/notifications.js') }}?v={{ asset_version }}" in base
    navigate_handler = worker.index('if (request.mode === "navigate")')
    assert worker.index("fetch(request).catch", navigate_handler) > navigate_handler


def test_admin_event_policies_use_accessible_responsive_cards():
    root = Path(__file__).resolve().parents[1]
    template = (root / "app/templates/notification_admin.html").read_text(
        encoding="utf-8"
    )
    css = (root / "app/static/css/notifications.css").read_text(encoding="utf-8")
    client = (root / "app/static/js/notifications.js").read_text(encoding="utf-8")

    assert 'class="notification-policy-list" data-category-list' in template
    assert 'class="notification-policy-card" data-category=' in template
    assert "<legend>Delivery</legend>" in template
    assert "<legend>User controls</legend>" in template
    assert 'data-category-status role="status" aria-live="polite"' in template
    assert "notification-number-with-unit" in template
    assert "@media(max-width:720px)" in css
    assert ".notification-policy-card{grid-template-columns:1fr}" in css
    assert 'querySelector("[data-category-list]")' in client
    assert 'status.textContent="Savingâ€¦"' in client


def test_global_notification_menu_closes_outside_and_escape():
    root = Path(__file__).resolve().parents[1]
    base = (root / "app/templates/base.html").read_text(encoding="utf-8")
    client = (root / "app/static/js/notifications.js").read_text(encoding="utf-8")
    assert 'aria-expanded="false"' in base
    assert 'event.key === "Escape"' in client
    assert 'menu.contains(event.target)' in client
    assert 'menu.open = false' in client


def test_generate_api_is_post_only_and_csrf_protected(db):
    route = next(
        item
        for item in notification_router.router.routes
        if item.path == "/api/admin/web-push/generate"
    )
    assert route.methods == {"POST"}
    admin = user(db, "csrf-vapid-admin@example.invalid", role="admin")
    request = csrf_request()
    request.headers["x-csrf-token"] = "wrong-token"

    with pytest.raises(Exception) as exc:
        notification_router.generate_web_push_keys(
            WebPushKeyRequest(
                contact_email="admin@example.com", confirmation="GENERATE"
            ),
            request,
            db=db,
            user=admin,
        )

    assert getattr(exc.value, "status_code", None) == 400
    assert getattr(exc.value, "detail", "") == "Invalid form token"
    assert db.get(WebPushConfiguration, 1) is None
