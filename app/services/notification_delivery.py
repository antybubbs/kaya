"""Bounded background delivery for queued notification channels."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import urlsplit
from datetime import datetime, timedelta

from app.core.security import decrypt_secret
from app.db.session import SessionLocal, sqlite_lock_error
from app.models.models import (
    NotificationDeliveryAttempt,
    PushSubscription,
    UserNotification,
)
from app.services.mail import MailConfigurationError, send_mail
from app.services.site_settings import get_site_setting
from app.services.notifications import validate_push_endpoint
from app.services.web_push_config import (
    VapidCredentials,
    WebPushConfigurationError,
    effective_credentials,
)

logger = logging.getLogger(__name__)


def _provider_name(subscription: dict | None) -> str:
    host = (urlsplit(str((subscription or {}).get("endpoint") or "")).hostname or "").lower().rstrip(".")
    if host == "fcm.googleapis.com" or host.endswith(".fcm.googleapis.com"):
        return "FCM"
    if host.endswith("push.services.mozilla.com"):
        return "Mozilla Push"
    if host.endswith("push.apple.com"):
        return "Apple Web Push"
    if host.endswith("notify.windows.com"):
        return "Microsoft/Windows Push"
    return "Unknown"


def _safe_provider_reason(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    text = getattr(response, "text", None) or getattr(response, "reason", None)
    if not text:
        return None
    text = " ".join(str(text).split())[:160]
    text = text.replace("https://", "[url]").replace("http://", "[url]")
    text = re.sub(r"[A-Za-z0-9_-]{32,}", "[redacted]", text)
    return text


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unknown"
MAX_RETRIES = 4
STALE_PROCESSING_SECONDS = 300


def _send_push(
    subscription: dict, payload: dict, credentials: VapidCredentials
) -> dict:
    from pywebpush import webpush
    import requests

    class NoRedirectSession(requests.Session):
        def request(self, method, url, **kwargs):
            kwargs["allow_redirects"] = False
            return super().request(method, url, **kwargs)

    validate_push_endpoint(str(subscription.get("endpoint") or ""))
    webpush(
        subscription_info=subscription,
        data=json.dumps(payload, separators=(",", ":")),
        vapid_private_key=credentials.private_key,
        vapid_claims={"sub": credentials.subject},
        timeout=10,
        requests_session=NoRedirectSession(),
    )
    endpoint = urlsplit(str(subscription.get("endpoint") or ""))
    return {
        "audience": f"{endpoint.scheme}://{endpoint.hostname}" + (f":{endpoint.port}" if endpoint.port else ""),
        "payload_bytes": len(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        "content_encoding": "aes128gcm",
    }


def deliver_queued(heartbeat=None) -> int:
    db = SessionLocal()
    delivered = 0
    try:
        now = datetime.utcnow()
        db.query(NotificationDeliveryAttempt).filter(
            NotificationDeliveryAttempt.status == "processing",
            NotificationDeliveryAttempt.processing_started_at
            < now - timedelta(seconds=STALE_PROCESSING_SECONDS),
        ).update(
            {
                NotificationDeliveryAttempt.status: "temporary_failure",
                NotificationDeliveryAttempt.failure_reason_code: "stale_claim_recovered",
                NotificationDeliveryAttempt.next_retry_at: now,
                NotificationDeliveryAttempt.processing_started_at: None,
            },
            synchronize_session=False,
        )
        attempts = (
            db.query(NotificationDeliveryAttempt)
            .filter(
                NotificationDeliveryAttempt.status.in_(
                    ["queued", "retry", "temporary_failure"]
                ),
                (
                    NotificationDeliveryAttempt.next_retry_at.is_(None)
                    | (NotificationDeliveryAttempt.next_retry_at <= now)
                ),
            )
            .order_by(
                NotificationDeliveryAttempt.created_at.asc(),
                NotificationDeliveryAttempt.id.asc(),
            )
            .limit(50)
            .all()
        )
        for attempt in attempts:
            attempt.status = "processing"
            attempt.processing_started_at = now
        db.commit()
        for attempt in attempts:
            if heartbeat:
                heartbeat()
            attempt = db.get(NotificationDeliveryAttempt, attempt.id)
            if not attempt or attempt.status != "processing":
                continue
            subscription = db.get(PushSubscription, attempt.push_subscription_id)
            user_notification = db.get(UserNotification, attempt.user_notification_id)
            if (
                not user_notification
                or not user_notification.user.is_active
                or (
                    attempt.channel == "push"
                    and (not subscription or subscription.status != "active")
                )
            ):
                attempt.status = "cancelled"
                attempt.failure_reason_code = "inactive_target"
                attempt.processing_started_at = None
                if attempt.channel == "push":
                    logger.info(
                        "notification.delivery.push.skipped reason=inactive_target attempt_id=%s",
                        attempt.id,
                    )
                db.commit()
                continue
            event = user_notification.event
            correlation_id = str(event.correlation_id or "")[:64]
            payload = {
                "title": event.title,
                "message": event.message,
                "severity": event.severity,
                "target": event.target_route or "/notifications",
                "notification_id": user_notification.id,
            }
            # End the read transaction before the outbound provider boundary.
            channel = attempt.channel
            subscription_id = subscription.id if subscription else None
            user_email = user_notification.user.email
            encrypted_subscription = (
                subscription.encrypted_subscription if subscription else None
            )
            decoded = None
            push_metadata = {}
            db.commit()
            try:
                if channel == "push":
                    if get_site_setting(db, "notifications_push_enabled") != "1":
                        raise RuntimeError("push_not_configured")
                    credentials = effective_credentials(db)
                    if not credentials:
                        raise RuntimeError("push_not_configured")
                    decoded = json.loads(
                        decrypt_secret(encrypted_subscription)
                    )
                    endpoint = urlsplit(str(decoded.get("endpoint") or ""))
                    push_metadata = {
                        "audience": f"{endpoint.scheme}://{endpoint.hostname}" + (f":{endpoint.port}" if endpoint.port else ""),
                        "payload_bytes": len(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
                        "content_encoding": "aes128gcm",
                    }
                    db.commit()
                    push_metadata = _send_push(decoded, payload, credentials) or {}
                elif channel == "email":
                    base_url = get_site_setting(db, "base_url").rstrip("/")
                    action_url = f"{base_url}{payload['target']}"
                    send_mail(
                        db,
                        user_email,
                        f"[Kaya] {payload['title']}",
                        payload["message"],
                        action_url=action_url,
                        action_label="Open Kaya",
                        before_send=db.commit,
                    )
                else:
                    attempt.status = "cancelled"
                    attempt.failure_reason_code = "unknown_channel"
                    attempt.processing_started_at = None
                    db.commit()
                    continue
                attempt = db.get(NotificationDeliveryAttempt, attempt.id)
                subscription = db.get(PushSubscription, subscription_id)
                attempt.status = (
                    "accepted_by_push_service"
                    if channel == "push"
                    else "accepted_by_email_service"
                )
                attempt.attempted_at = now
                attempt.accepted_at = now
                attempt.processing_started_at = None
                attempt.next_retry_at = None
                attempt.failure_reason_code = None
                if subscription:
                    subscription.last_success_at = now
                    subscription.last_used_at = now
                    subscription.failure_count = 0
                delivered += 1
                db.commit()
            except (
                Exception
            ) as exc:  # genuine outbound-provider boundary; never log endpoint or key material
                if sqlite_lock_error(exc):
                    db.rollback()
                    raise
                status_code = getattr(
                    getattr(exc, "response", None), "status_code", None
                )
                attempt = db.get(NotificationDeliveryAttempt, attempt.id)
                subscription = db.get(PushSubscription, subscription_id)
                attempt.retry_count += 1
                attempt.attempted_at = now
                attempt.processing_started_at = None
                if subscription:
                    subscription.last_failure_at = now
                    subscription.failure_count = (subscription.failure_count or 0) + 1
                if (
                    isinstance(exc, (MailConfigurationError, WebPushConfigurationError))
                    or str(exc) == "push_not_configured"
                ):
                    attempt.status = "cancelled"
                    attempt.failure_reason_code = "channel_not_configured"
                elif status_code in {404, 410} and subscription:
                    subscription.status = "expired"
                    subscription.revoked_at = now
                    attempt.status = "expired_subscription"
                    attempt.failure_reason_code = "subscription_expired"
                elif (
                    isinstance(status_code, int)
                    and 400 <= status_code < 500
                    and status_code not in {408, 429}
                ):
                    attempt.status = "permanent_failure"
                    attempt.failure_reason_code = "provider_rejected"
                elif attempt.retry_count >= MAX_RETRIES:
                    attempt.status = "retry_exhausted"
                    attempt.failure_reason_code = "provider_unavailable"
                else:
                    attempt.status = "temporary_failure"
                    attempt.next_retry_at = now + timedelta(
                        minutes=2**attempt.retry_count
                    )
                    attempt.failure_reason_code = "temporary_failure"
                if channel == "push" and attempt.failure_reason_code == "channel_not_configured":
                    logger.info(
                        "notification.delivery.push.skipped reason=not_configured attempt_id=%s",
                        attempt.id,
                    )
                elif channel == "push":
                    logger.warning(
                        "notification.delivery.push.failed classification=%s status_code=%s provider=%s subscription_id=%s retryable=%s attempt_number=%s attempt_id=%s correlation_id=%s audience=%s payload_bytes=%s content_encoding=%s pywebpush=%s py_vapid=%s http_ece=%s provider_reason=%s",
                        attempt.failure_reason_code,
                        status_code or "unknown",
                        _provider_name(decoded if 'decoded' in locals() else None),
                        subscription_id,
                        attempt.status not in {"permanent_failure", "expired_subscription"},
                        attempt.retry_count,
                        attempt.id,
                        correlation_id,
                        push_metadata.get("audience", "unknown"),
                        push_metadata.get("payload_bytes", "unknown"),
                        push_metadata.get("content_encoding", "unknown"),
                        _package_version("pywebpush"),
                        _package_version("py-vapid"),
                        _package_version("http-ece"),
                        _safe_provider_reason(exc) or "unknown",
                    )
                else:
                    logger.warning(
                        "notification.delivery.email.failed classification=%s retry=%s attempt_id=%s",
                        attempt.failure_reason_code,
                        attempt.retry_count,
                        attempt.id,
                    )
                db.commit()
        db.commit()
        return delivered
    except Exception:
        # Never leave a failed transaction available to subsequent work in the
        # same iteration. The next loop always starts with a fresh Session.
        db.rollback()
        raise
    finally:
        db.close()


async def notification_delivery_loop(heartbeat=None) -> None:
    while True:
        if heartbeat:
            heartbeat()
        try:
            await asyncio.to_thread(deliver_queued, heartbeat)
        except Exception:
            logger.exception("notification.delivery.worker_iteration_failed")
        await asyncio.sleep(10)
