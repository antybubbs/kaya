"""Validated VAPID configuration with deployment precedence and encrypted UI storage."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from email_validator import EmailNotValidError, validate_email
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import decrypt_secret, encrypt_secret
from app.models.models import (
    NotificationDeliveryAttempt,
    PushSubscription,
    WebPushConfiguration,
)
from app.services.site_settings import get_site_setting


class WebPushConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class VapidCredentials:
    public_key: str
    private_key: str
    subject: str
    source: str


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_public_key(value: str) -> bytes:
    clean = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{80,100}", clean):
        raise WebPushConfigurationError("Invalid VAPID public key")
    try:
        decoded = base64.urlsafe_b64decode(clean + "=" * (-len(clean) % 4))
    except (ValueError, TypeError) as exc:
        raise WebPushConfigurationError("Invalid VAPID public key") from exc
    if len(decoded) != 65 or decoded[0] != 4:
        raise WebPushConfigurationError("Invalid VAPID public key")
    return decoded


def public_key_fingerprint(public_key: str) -> str:
    digest = hashlib.sha256(_decode_public_key(public_key)).hexdigest().upper()
    return "SHA256:" + ":".join(digest[index : index + 2] for index in range(0, 64, 2))


def normalise_subject(contact_email: str | None, contact_url: str | None) -> str:
    email = str(contact_email or "").strip()
    url = str(contact_url or "").strip()
    if bool(email) == bool(url):
        raise WebPushConfigurationError("Provide either a contact email or contact URL")
    if email:
        if len(email) > 254:
            raise WebPushConfigurationError("Contact email is too long")
        try:
            normalised = validate_email(email, check_deliverability=False).normalized
        except EmailNotValidError as exc:
            raise WebPushConfigurationError("Invalid contact email") from exc
        return f"mailto:{normalised}"
    if len(url) > 500:
        raise WebPushConfigurationError("Contact URL is too long")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise WebPushConfigurationError("Contact URL must be a valid HTTPS URL")
    return url


def _normalise_label(value: str | None) -> str | None:
    clean = " ".join(str(value or "").split())
    if not clean:
        return None
    if len(clean) > 120 or any(ord(character) < 32 for character in clean):
        raise WebPushConfigurationError("Invalid installation label")
    return clean


def validate_key_pair(public_key: str, private_key: str) -> None:
    expected_public = _decode_public_key(public_key)
    try:
        from py_vapid import Vapid

        clean_private = private_key.strip()
        if clean_private.startswith("-----BEGIN PRIVATE KEY-----"):
            loaded = serialization.load_pem_private_key(
                clean_private.encode("ascii"), None
            )
            vapid = Vapid.from_pem(clean_private.encode("ascii"))
        elif Path(clean_private).is_file():
            vapid = Vapid.from_file(clean_private)
            loaded = vapid.private_key
        else:
            raw = base64.urlsafe_b64decode(
                clean_private + "=" * (-len(clean_private) % 4)
            )
            if len(raw) != 32:
                raise ValueError("invalid raw private key length")
            loaded = ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())
            vapid = Vapid.from_string(clean_private)
    # Parser and library exception types vary by supported key representation and
    # dependency version. Convert every rejection to one safe, redacted error.
    except Exception as exc:
        raise WebPushConfigurationError("Invalid VAPID private key") from exc
    if not isinstance(loaded, ec.EllipticCurvePrivateKey) or not isinstance(
        loaded.curve, ec.SECP256R1
    ):
        raise WebPushConfigurationError("VAPID private key must use P-256")
    derived_public = loaded.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    if derived_public != expected_public:
        raise WebPushConfigurationError("VAPID key pair does not match")
    library_public = vapid.public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    if library_public != expected_public:
        raise WebPushConfigurationError("Web Push library rejected the VAPID key pair")


def generate_key_pair() -> tuple[str, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    private_value = private.private_numbers().private_value.to_bytes(32, "big")
    private_encoded = _b64url(private_value)
    public = _b64url(
        private.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    validate_key_pair(public, private_encoded)
    return public, private_encoded


def _deployment_values() -> tuple[str, str, str] | None:
    settings = get_settings()
    public = settings.vapid_public_key.strip()
    private = settings.vapid_private_key.strip()
    if not public and not private:
        return None
    if not public or not private:
        raise WebPushConfigurationError("Deployment VAPID configuration is incomplete")
    subject = settings.vapid_subject.strip()
    if not subject:
        raise WebPushConfigurationError("Deployment VAPID subject is missing")
    if subject.startswith("mailto:"):
        normalise_subject(subject[7:], None)
    else:
        normalise_subject(None, subject)
    validate_key_pair(public, private)
    return public, private, subject


def ui_configuration(db: Session) -> WebPushConfiguration | None:
    return db.get(WebPushConfiguration, 1)


def effective_credentials(db: Session) -> VapidCredentials | None:
    deployment = _deployment_values()
    if deployment:
        return VapidCredentials(*deployment, source="deployment")
    row = ui_configuration(db)
    if not row:
        return None
    private = decrypt_secret(row.encrypted_private_key)
    if not private or private == "[decryption failed]":
        raise WebPushConfigurationError("Stored Web Push configuration cannot be decrypted")
    validate_key_pair(row.public_key, private)
    return VapidCredentials(row.public_key, private, row.subject, "kaya")


def configuration_status(db: Session) -> dict[str, object]:
    row = ui_configuration(db)
    source = "none"
    state = "not_configured"
    fingerprint = None
    subject = None
    label = None
    generated_at = None
    loaded_at = None
    valid = False
    try:
        deployment = _deployment_values()
        if deployment:
            source = "deployment"
            state = "managed_by_deployment"
            fingerprint = public_key_fingerprint(deployment[0])
            subject = deployment[2]
            loaded_at = datetime.utcnow().isoformat() + "Z"
            valid = True
        elif row:
            credentials = effective_credentials(db)
            source = "kaya"
            state = "configured" if row.enabled else "disabled"
            fingerprint = public_key_fingerprint(row.public_key)
            subject = row.subject
            label = row.installation_label
            generated_at = row.generated_at.isoformat() + "Z"
            valid = credentials is not None
    except WebPushConfigurationError:
        source = "deployment" if get_settings().vapid_public_key or get_settings().vapid_private_key else "kaya"
        state = "invalid_configuration" if source == "deployment" else "configuration_error"
    active_devices = (
        db.query(PushSubscription)
        .filter_by(status="active", revoked_at=None)
        .count()
    )
    last_success = db.query(PushSubscription.last_success_at).filter(
        PushSubscription.last_success_at.is_not(None)
    ).order_by(PushSubscription.last_success_at.desc()).first()
    last_failure = db.query(PushSubscription.last_failure_at).filter(
        PushSubscription.last_failure_at.is_not(None)
    ).order_by(PushSubscription.last_failure_at.desc()).first()
    push_enabled = get_site_setting(db, "notifications_push_enabled") == "1"
    registration_enabled = (
        get_site_setting(db, "notifications_allow_push_registration") == "1"
    )
    return {
        "state": state,
        "status_label": state.replace("_", " ").title(),
        "source": source,
        "source_label": {"deployment": "Managed by deployment", "kaya": "Kaya managed", "none": "None"}[source],
        "valid": valid,
        "enabled": valid and push_enabled and state not in {"disabled"},
        "public_key_fingerprint": fingerprint,
        "subject": subject,
        "installation_label": label,
        "generated_at": generated_at,
        "loaded_at": loaded_at,
        "active_devices": active_devices,
        "last_successful_push": last_success[0].isoformat() + "Z" if last_success else None,
        "last_push_failure": last_failure[0].isoformat() + "Z" if last_failure else None,
        "browser_registration_available": valid and push_enabled and registration_enabled,
        "can_manage": source != "deployment",
    }


def create_ui_configuration(
    db: Session,
    *,
    subject: str,
    installation_label: str | None,
    rotate: bool,
) -> WebPushConfiguration:
    if _deployment_values():
        raise WebPushConfigurationError("Deployment-managed keys cannot be changed here")
    existing = ui_configuration(db)
    if existing and not rotate:
        raise WebPushConfigurationError("Web Push keys are already configured")
    if rotate and not existing:
        raise WebPushConfigurationError("No UI-managed Web Push keys exist to rotate")
    public, private = generate_key_pair()
    now = datetime.utcnow()
    row = existing or WebPushConfiguration(id=1, encrypted_private_key="")
    row.encrypted_private_key = encrypt_secret(private)
    row.public_key = public
    row.public_key_fingerprint = public_key_fingerprint(public)
    row.subject = subject
    row.installation_label = _normalise_label(installation_label)
    row.enabled = True
    if not existing:
        row.generated_at = now
    else:
        row.rotated_at = now
    row.updated_at = now
    db.add(row)
    db.flush()
    # Prove ciphertext can be recovered and accepted before any caller commits.
    recovered = decrypt_secret(row.encrypted_private_key)
    validate_key_pair(row.public_key, recovered)
    return row


def revoke_all_subscriptions(db: Session, reason: str) -> int:
    now = datetime.utcnow()
    rows = db.query(PushSubscription).filter(
        PushSubscription.status == "active", PushSubscription.revoked_at.is_(None)
    ).all()
    ids = [row.id for row in rows]
    for row in rows:
        row.status = "revoked"
        row.revoked_at = now
    if ids:
        db.query(NotificationDeliveryAttempt).filter(
            NotificationDeliveryAttempt.push_subscription_id.in_(ids),
            NotificationDeliveryAttempt.status.in_(["queued", "retry"]),
        ).update(
            {
                NotificationDeliveryAttempt.status: "cancelled",
                NotificationDeliveryAttempt.failure_reason_code: reason[:80],
                NotificationDeliveryAttempt.next_retry_at: None,
            },
            synchronize_session=False,
        )
    return len(rows)
