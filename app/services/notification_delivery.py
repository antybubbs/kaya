"""Bounded background delivery for queued notification channels."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta

from app.core.security import decrypt_secret
from app.db.session import SessionLocal
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
MAX_RETRIES = 4


def _send_push(
    subscription: dict, payload: dict, credentials: VapidCredentials
) -> None:
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


def deliver_queued() -> int:
    db = SessionLocal()
    delivered = 0
    try:
        now = datetime.utcnow()
        attempts = (
            db.query(NotificationDeliveryAttempt)
            .filter(
                NotificationDeliveryAttempt.status.in_(["queued", "retry"]),
                (
                    NotificationDeliveryAttempt.next_retry_at.is_(None)
                    | (NotificationDeliveryAttempt.next_retry_at <= now)
                ),
            )
            .order_by(NotificationDeliveryAttempt.attempted_at.asc())
            .limit(50)
            .all()
        )
        for attempt in attempts:
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
                if attempt.channel == "push":
                    logger.info(
                        "notification.delivery.push.skipped reason=inactive_target attempt_id=%s",
                        attempt.id,
                    )
                continue
            event = user_notification.event
            payload = {
                "title": event.title,
                "message": event.message,
                "severity": event.severity,
                "target": event.target_route or "/notifications",
                "notification_id": user_notification.id,
            }
            try:
                if attempt.channel == "push":
                    if get_site_setting(db, "notifications_push_enabled") != "1":
                        raise RuntimeError("push_not_configured")
                    credentials = effective_credentials(db)
                    if not credentials:
                        raise RuntimeError("push_not_configured")
                    decoded = json.loads(
                        decrypt_secret(subscription.encrypted_subscription)
                    )
                    _send_push(decoded, payload, credentials)
                    subscription.last_success_at = now
                    subscription.last_used_at = now
                    subscription.failure_count = 0
                elif attempt.channel == "email":
                    base_url = get_site_setting(db, "base_url").rstrip("/")
                    action_url = f"{base_url}{event.target_route or '/notifications'}"
                    send_mail(
                        db,
                        user_notification.user.email,
                        f"[Kaya] {event.title}",
                        event.message,
                        action_url=action_url,
                        action_label="Open Kaya",
                    )
                else:
                    attempt.status = "cancelled"
                    attempt.failure_reason_code = "unknown_channel"
                    continue
                attempt.status = "accepted"
                attempt.attempted_at = now
                delivered += 1
            except (
                Exception
            ) as exc:  # genuine outbound-provider boundary; never log endpoint or key material
                status_code = getattr(
                    getattr(exc, "response", None), "status_code", None
                )
                attempt.retry_count += 1
                attempt.attempted_at = now
                if subscription:
                    subscription.last_failure_at = now
                    subscription.failure_count = (subscription.failure_count or 0) + 1
                if (
                    isinstance(exc, (MailConfigurationError, WebPushConfigurationError))
                    or str(exc) == "push_not_configured"
                ):
                    attempt.status = "failed"
                    attempt.failure_reason_code = "channel_not_configured"
                elif status_code in {404, 410} and subscription:
                    subscription.status = "expired"
                    subscription.revoked_at = now
                    attempt.status = "permanent_failure"
                    attempt.failure_reason_code = "subscription_expired"
                elif attempt.retry_count >= MAX_RETRIES:
                    attempt.status = "failed"
                    attempt.failure_reason_code = "provider_unavailable"
                else:
                    attempt.status = "retry"
                    attempt.next_retry_at = now + timedelta(
                        minutes=2**attempt.retry_count
                    )
                    attempt.failure_reason_code = "temporary_failure"
                if attempt.channel == "push" and attempt.failure_reason_code == "channel_not_configured":
                    logger.info(
                        "notification.delivery.push.skipped reason=not_configured attempt_id=%s",
                        attempt.id,
                    )
                elif attempt.channel == "push":
                    logger.warning(
                        "notification.delivery.push.failed classification=%s retry=%s attempt_id=%s",
                        attempt.failure_reason_code,
                        attempt.retry_count,
                        attempt.id,
                    )
                else:
                    logger.warning(
                        "notification.delivery.email.failed classification=%s retry=%s attempt_id=%s",
                        attempt.failure_reason_code,
                        attempt.retry_count,
                        attempt.id,
                    )
        db.commit()
        return delivered
    finally:
        db.close()


async def notification_delivery_loop() -> None:
    while True:
        await asyncio.sleep(10)
        await asyncio.to_thread(deliver_queued)
