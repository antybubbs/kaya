"""Bounded background delivery for queued notification channels."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import urlsplit
from datetime import datetime, timedelta, timezone

from app.core.security import decrypt_secret
from app.db.session import SessionLocal, database_write_context, sqlite_lock_error
from app.models.models import (
    NotificationDeliveryAttempt,
    PushSubscription,
    UserNotification,
)
from app.services.mail import MailConfigurationError, send_mail
from app.services.site_settings import get_site_setting
from app.services.notifications import validate_push_endpoint
from app.services.web_push_config import (
    InvalidVapidSubjectError,
    VapidCredentials,
    WebPushConfigurationError,
    effective_credentials,
    validate_subject_uri,
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
WINDOWS_PUSH_TTL_SECONDS = 600


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _safe_subscription_structure(subscription: dict) -> dict:
    """Validate and describe a browser subscription without exposing its keys."""
    endpoint = str(subscription.get("endpoint") or "")
    validate_push_endpoint(endpoint)
    keys = subscription.get("keys")
    if not isinstance(keys, dict):
        raise ValueError("Push subscription keys are missing")
    p256dh = str(keys.get("p256dh") or "")
    auth = str(keys.get("auth") or "")
    try:
        p256dh_bytes = _b64url_decode(p256dh)
        auth_bytes = _b64url_decode(auth)
    except (TypeError, ValueError) as exc:
        raise ValueError("Push subscription keys are not valid base64url") from exc
    if len(p256dh_bytes) != 65 or p256dh_bytes[0] != 4:
        raise ValueError("Push subscription p256dh key is not an uncompressed P-256 key")
    if len(auth_bytes) != 16:
        raise ValueError("Push subscription auth secret has an invalid length")
    return {
        "p256dh_present": bool(p256dh),
        "p256dh_decoded_bytes": len(p256dh_bytes),
        "p256dh_uncompressed_p256": True,
        "auth_present": bool(auth),
        "auth_decoded_bytes": len(auth_bytes),
    }


def _safe_subject_diagnostics(subject: str) -> dict:
    canonical = validate_subject_uri(subject)
    if canonical.startswith("mailto:"):
        return {
            "vapid_subject_scheme": "mailto",
            "vapid_subject_present": True,
            "vapid_subject_length": len(canonical),
            "vapid_subject_valid": True,
        }
    parsed = urlsplit(canonical)
    if parsed.scheme == "https" and parsed.hostname:
        return {
            "vapid_subject_scheme": "https",
            "vapid_subject_present": True,
            "vapid_subject_length": len(canonical),
            "vapid_subject_valid": True,
        }
    raise WebPushConfigurationError("Invalid VAPID subject")


def _windows_push_headers(subscription: dict) -> tuple[dict[str, str], int]:
    """Apply only the documented WNS extension; other providers remain standard Web Push."""
    if _provider_name(subscription) == "Microsoft/Windows Push":
        # pywebpush passes caller headers through unchanged. WNS requires the
        # Content-Type to match X-WNS-Type; its documented Edge example uses
        # this pair. The encrypted Web Push body is still produced by
        # pywebpush and is not replaced with native toast XML here.
        return {
            "X-WNS-Type": "wns/toast",
            "Content-Type": "text/xml",
        }, WINDOWS_PUSH_TTL_SECONDS
    return {}, 0


def _safe_vapid_claims(authorization: str | None, now: datetime) -> dict:
    """Extract non-secret JWT claims from the RFC 8292 Authorization header."""
    result = {
        "authorization_style": "unknown",
        "vapid_key_location": "unknown",
        "jwt_aud": None,
        "jwt_exp": None,
        "jwt_seconds_until_expiry": None,
    }
    if not authorization:
        return result
    if authorization.lower().startswith("vapid "):
        result.update({"authorization_style": "vapid", "vapid_key_location": "authorization"})
        match = re.search(r"(?:^|,)\s*t=([^,]+)", authorization[6:])
        if not match:
            return result
        try:
            payload = json.loads(_b64url_decode(match.group(1).split(".")[1]))
            exp = int(payload.get("exp"))
            result.update(
                {
                    "jwt_aud": str(payload.get("aud") or "")[:200] or None,
                    "jwt_exp": exp,
                    "jwt_seconds_until_expiry": exp - int(now.timestamp()),
                }
            )
        except (IndexError, TypeError, ValueError, json.JSONDecodeError):
            result["authorization_style"] = "vapid_unparseable"
    return result


def _safe_response_diagnostics(exc: Exception) -> dict:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", {}) or {}
    safe_names = sorted(str(name).lower() for name in headers)
    safe_values = {}
    for name in (
        "x-wns-error-description",
        "x-wns-notificationstatus",
        "x-wns-status",
    ):
        value = headers.get(name)
        if value is not None:
            safe_values[name.replace("-", "_")] = " ".join(str(value).split())[:160]
    request_id = None
    for name in ("x-wns-msg-id", "ms-cv", "x-correlation-id", "x-request-id"):
        value = headers.get(name)
        if value and len(str(value)) <= 160:
            request_id = f"{name}:{str(value)}"
            break
    return {
        "response_header_names": safe_names,
        "provider_request_id": request_id,
        "wns_error_description": safe_values.get("x_wns_error_description"),
        "wns_notification_status": safe_values.get("x_wns_notificationstatus"),
        "wns_status": safe_values.get("x_wns_status"),
    }


def _send_push(
    subscription: dict, payload: dict, credentials: VapidCredentials
) -> dict:
    from pywebpush import webpush
    import requests

    request_trace: dict = {}

    class NoRedirectSession(requests.Session):
        def request(self, method, url, **kwargs):
            kwargs["allow_redirects"] = False
            return super().request(method, url, **kwargs)

        def send(self, request, **kwargs):
            headers = request.headers
            body = request.body
            endpoint = urlsplit(str(request.url))
            now = datetime.now(timezone.utc)
            request_trace.update(
                {
                    "http_method": str(request.method).upper(),
                    "audience": f"{endpoint.scheme}://{endpoint.hostname}"
                    + (f":{endpoint.port}" if endpoint.port else ""),
                    "request_header_names": sorted(str(name).lower() for name in headers),
                    "wns_type": headers.get("x-wns-type"),
                    "content_encoding": headers.get("content-encoding"),
                    "content_type": headers.get("content-type"),
                    "content_length": headers.get("content-length")
                    or (len(body) if body is not None else 0),
                    "ttl": headers.get("ttl"),
                    "urgency": headers.get("urgency"),
                    "request_utc": now.isoformat(),
                    **_safe_vapid_claims(headers.get("authorization"), now),
                }
            )
            return super().send(request, **kwargs)

    subscription_structure = _safe_subscription_structure(subscription)
    endpoint = urlsplit(str(subscription.get("endpoint") or ""))
    extra_headers, ttl = _windows_push_headers(subscription)
    request_trace.update(
        {
            "audience": f"{endpoint.scheme}://{endpoint.hostname}"
            + (f":{endpoint.port}" if endpoint.port else ""),
            "payload_bytes": len(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
            **_safe_subject_diagnostics(credentials.subject),
            "vapid_public_key_fingerprint": "SHA256:"
            + hashlib.sha256(_b64url_decode(credentials.public_key)).hexdigest()[:16],
            **subscription_structure,
        }
    )
    try:
        webpush(
            subscription_info=subscription,
            data=json.dumps(payload, separators=(",", ":")),
            vapid_private_key=credentials.private_key,
            vapid_claims={"sub": credentials.subject},
            timeout=10,
            ttl=ttl,
            headers=extra_headers,
            requests_session=NoRedirectSession(),
        )
    except Exception as exc:
        setattr(exc, "kaya_push_diagnostics", request_trace)
        raise
    return {
        **request_trace,
    }


def deliver_queued(heartbeat=None) -> int:
    with database_write_context("notification_delivery", "delivery_iteration"):
        return _deliver_queued(heartbeat)


def _deliver_queued(heartbeat=None) -> int:
    db = SessionLocal()
    delivered = 0
    try:
        now = datetime.utcnow()
        stale_ids = [
            row_id
            for (row_id,) in db.query(NotificationDeliveryAttempt.id)
            .filter(
                NotificationDeliveryAttempt.status == "processing",
                NotificationDeliveryAttempt.processing_started_at
                < now - timedelta(seconds=STALE_PROCESSING_SECONDS),
            )
            .limit(50)
            .all()
        ]
        if stale_ids:
            db.query(NotificationDeliveryAttempt).filter(
                NotificationDeliveryAttempt.id.in_(stale_ids)
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
                if channel == "push":
                    push_metadata.update(
                        getattr(exc, "kaya_push_diagnostics", {}) or {}
                    )
                    push_metadata.update(_safe_response_diagnostics(exc))
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
                if isinstance(exc, InvalidVapidSubjectError):
                    attempt.status = "cancelled"
                    attempt.failure_reason_code = "invalid_vapid_configuration"
                elif (
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
                if channel == "push" and attempt.failure_reason_code in {
                    "channel_not_configured",
                    "invalid_vapid_configuration",
                }:
                    logger.info(
                        "notification.delivery.push.skipped reason=%s attempt_id=%s",
                        attempt.failure_reason_code,
                        attempt.id,
                    )
                elif channel == "push":
                    logger.warning(
                        "notification.delivery.push.failed classification=%s status_code=%s provider=%s subscription_id=%s retryable=%s attempt_number=%s attempt_id=%s correlation_id=%s audience=%s payload_bytes=%s content_encoding=%s http_method=%s request_headers=%s wns_type=%s content_type=%s content_length=%s ttl=%s urgency=%s vapid_authorization_style=%s vapid_key_location=%s jwt_aud=%s jwt_exp=%s jwt_seconds_until_expiry=%s vapid_subject_scheme=%s vapid_subject_present=%s vapid_subject_length=%s vapid_subject_valid=%s vapid_public_key_fingerprint=%s p256dh_present=%s p256dh_decoded_bytes=%s p256dh_uncompressed_p256=%s auth_present=%s auth_decoded_bytes=%s request_utc=%s response_headers=%s provider_request_id=%s wns_error_description=%s wns_notification_status=%s wns_status=%s pywebpush=%s py_vapid=%s http_ece=%s provider_reason=%s",
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
                        push_metadata.get("http_method", "unknown"),
                        push_metadata.get("request_header_names", []),
                        push_metadata.get("wns_type", "none"),
                        push_metadata.get("content_type", "none"),
                        push_metadata.get("content_length", "unknown"),
                        push_metadata.get("ttl", "unknown"),
                        push_metadata.get("urgency", "none"),
                        push_metadata.get("authorization_style", "unknown"),
                        push_metadata.get("vapid_key_location", "unknown"),
                        push_metadata.get("jwt_aud", "unknown"),
                        push_metadata.get("jwt_exp", "unknown"),
                        push_metadata.get("jwt_seconds_until_expiry", "unknown"),
                        push_metadata.get("vapid_subject_scheme", "unknown"),
                        push_metadata.get("vapid_subject_present", "unknown"),
                        push_metadata.get("vapid_subject_length", "unknown"),
                        push_metadata.get("vapid_subject_valid", "unknown"),
                        push_metadata.get("vapid_public_key_fingerprint", "unknown"),
                        push_metadata.get("p256dh_present", "unknown"),
                        push_metadata.get("p256dh_decoded_bytes", "unknown"),
                        push_metadata.get("p256dh_uncompressed_p256", "unknown"),
                        push_metadata.get("auth_present", "unknown"),
                        push_metadata.get("auth_decoded_bytes", "unknown"),
                        push_metadata.get("request_utc", "unknown"),
                        push_metadata.get("response_header_names", []),
                        push_metadata.get("provider_request_id", "none"),
                        push_metadata.get("wns_error_description", "none"),
                        push_metadata.get("wns_notification_status", "none"),
                        push_metadata.get("wns_status", "none"),
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
