"""Encryption, lifecycle and recipient-session primitives for Secure Send."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import secrets
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from app.core.security import decrypt_secret, encrypt_secret, hash_password, verify_password
from app.models.models import (
    SecureSendActivity, SecureSendFile, SecureSendPackage, SecureSendRecipientSession, User,
)
from app.services.secret_vault import application_kek, derive_wrapping_key, unwrap_key, wrap_key

STORAGE = Path(os.getenv("KAYA_SECURE_SEND_STORAGE_DIR", "/app/data/secure-send"))
if not Path("/app/data").exists():
    STORAGE = Path("data/secure-send")
SESSION_COOKIE = "kaya_secure_send"
SESSION_MINUTES = 15
PASSPHRASE_WORDS = tuple((
    "amber anchor apple atlas autumn bamboo beacon birch blue breeze brook canyon cedar circle cloud coral copper creek crystal dawn delta dune eagle ember fern field flame forest frost garden globe granite harbor hazel hill island ivory jade juniper lake lantern leaf lemon maple meadow mist moon moss mountain night north ocean olive orchid pebble pine planet quartz rain raven reef river robin silver sky slate snow solar south spring star stone storm summit sun tide timber trail valley violet wave west willow wind winter wood"
).split())


class SecureSendError(ValueError):
    pass


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _aad(package_id: int, purpose: str) -> bytes:
    return f"kaya-secure-send:{package_id}:{purpose}:v1".encode()


def encrypt_value(key: bytes, package_id: int, purpose: str, value: Any) -> str:
    nonce = secrets.token_bytes(12)
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return _b64(nonce + AESGCM(key).encrypt(nonce, raw, _aad(package_id, purpose)))


def decrypt_value(key: bytes, package_id: int, purpose: str, value: str) -> Any:
    try:
        packed = _unb64(value)
        return json.loads(AESGCM(key).decrypt(packed[:12], packed[12:], _aad(package_id, purpose)))
    except (InvalidTag, ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SecureSendError("Secure package integrity validation failed") from exc


def encrypt_file(key: bytes, package_id: int, storage_id: str, content: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, content, _aad(package_id, f"file:{storage_id}"))


def decrypt_file(key: bytes, package_id: int, storage_id: str, content: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(content[:12], content[12:], _aad(package_id, f"file:{storage_id}"))
    except (InvalidTag, ValueError) as exc:
        raise SecureSendError("Secure file integrity validation failed") from exc


def ensure_storage() -> Path:
    STORAGE.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        STORAGE.chmod(0o700)
    except OSError:
        pass
    return STORAGE


def generate_passphrase() -> str:
    return "-".join(secrets.choice(PASSPHRASE_WORDS) for _ in range(10))


def normalise_pin(value: str) -> str:
    return "".join(value.split())


def credential_material(access_token: str, pin: str, passphrase: str) -> str:
    return f"{access_token}\0{normalise_pin(pin)}\0{passphrase.strip()}"


def validate_pin(pin: str) -> str | None:
    clean = normalise_pin(pin)
    if len(clean) < 6 or len(clean) > 32:
        return "Use a PIN between 6 and 32 characters."
    if clean.isdigit() and (len(set(clean)) == 1 or clean in "01234567890123456789" or clean in "98765432109876543210"):
        return "Choose a less predictable PIN."
    return None


def create_package(
    db: Session, sender: User, *, recipient_type: str, internal_recipient_id: int | None,
    summary: dict, note: str, pin: str, expires_at: datetime, one_download_only: bool,
    allow_vault_save: bool, notify_when_opened: bool, files: list[tuple[str, str, bytes]],
) -> tuple[SecureSendPackage, str, str]:
    access_token = secrets.token_urlsafe(48)
    passphrase = generate_passphrase()
    key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    material = credential_material(access_token, pin, passphrase)
    row = SecureSendPackage(
        sender_id=sender.id, internal_recipient_id=internal_recipient_id,
        recipient_type=recipient_type, access_token_hash=hashlib.sha256(access_token.encode()).hexdigest(),
        encrypted_access_token=encrypt_secret(access_token), credential_hash=hash_password(material),
        credential_salt=_b64(salt), credential_wrapped_key=wrap_key(key, derive_wrapping_key(material, salt), "secure-send-credentials"),
        app_wrapped_key=wrap_key(key, application_kek(), "secure-send-application"), encrypted_summary="pending",
        encrypted_note=None, expires_at=expires_at, one_download_only=one_download_only,
        allow_vault_save=allow_vault_save, notify_when_opened=notify_when_opened,
    )
    db.add(row); db.flush()
    row.encrypted_summary = encrypt_value(key, row.id, "summary", summary)
    row.encrypted_note = encrypt_value(key, row.id, "note", note) if note else None
    created_paths: list[Path] = []
    try:
        for name, content_type, content in files:
            storage_id = secrets.token_hex(24)
            encrypted = encrypt_file(key, row.id, storage_id, content)
            path = ensure_storage() / storage_id
            path.write_bytes(encrypted); created_paths.append(path)
            db.add(SecureSendFile(
                package_id=row.id, storage_id=storage_id,
                encrypted_metadata=encrypt_value(key, row.id, f"file-meta:{storage_id}", {"name": name, "content_type": content_type}),
                size_bytes=len(content), ciphertext_size=len(encrypted), integrity_hash=hashlib.sha256(encrypted).hexdigest(),
            ))
        record_activity(db, row, "created", actor_user_id=sender.id, commit=False)
        db.commit(); db.refresh(row)
    except Exception:
        db.rollback()
        for path in created_paths:
            try: path.unlink(missing_ok=True)
            except OSError: pass
        raise
    return row, access_token, passphrase


def package_key_from_application(row: SecureSendPackage) -> bytes:
    return unwrap_key(row.app_wrapped_key, application_kek(), "secure-send-application")


def package_for_token(db: Session, access_token: str) -> SecureSendPackage | None:
    if not access_token or len(access_token) > 200:
        return None
    return db.query(SecureSendPackage).filter_by(access_token_hash=hashlib.sha256(access_token.encode()).hexdigest()).first()


def package_accessible(row: SecureSendPackage, now: datetime | None = None) -> bool:
    now = now or datetime.utcnow()
    return bool(row.status not in {"expired", "revoked", "deleted"} and not row.revoked_at and not row.deleted_at and row.expires_at > now and not row.cleaned_at)


def authenticate_package(row: SecureSendPackage, access_token: str, pin: str, passphrase: str) -> bytes:
    material = credential_material(access_token, pin, passphrase)
    if not verify_password(material, row.credential_hash):
        raise SecureSendError("Authentication failed")
    return unwrap_key(row.credential_wrapped_key, derive_wrapping_key(material, _unb64(row.credential_salt)), "secure-send-credentials")


def decode_summary(row: SecureSendPackage, key: bytes | None = None) -> dict:
    value = decrypt_value(key or package_key_from_application(row), row.id, "summary", row.encrypted_summary)
    return value if isinstance(value, dict) else {}


def decode_note(row: SecureSendPackage, key: bytes) -> str:
    return str(decrypt_value(key, row.id, "note", row.encrypted_note)) if row.encrypted_note else ""


def decoded_files(db: Session, row: SecureSendPackage, key: bytes) -> list[dict]:
    result = []
    for item in db.query(SecureSendFile).filter_by(package_id=row.id).order_by(SecureSendFile.id).all():
        metadata = decrypt_value(key, row.id, f"file-meta:{item.storage_id}", item.encrypted_metadata)
        result.append({"row": item, "name": str(metadata.get("name") or "secure-file"), "content_type": str(metadata.get("content_type") or "application/octet-stream")})
    return result


def read_file(row: SecureSendPackage, item: SecureSendFile, key: bytes) -> bytes:
    encrypted = (ensure_storage() / item.storage_id).read_bytes()
    if not secrets.compare_digest(hashlib.sha256(encrypted).hexdigest(), item.integrity_hash):
        raise SecureSendError("Secure file integrity validation failed")
    return decrypt_file(key, row.id, item.storage_id, encrypted)


def build_zip(db: Session, row: SecureSendPackage, key: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        used: set[str] = set()
        for index, item in enumerate(decoded_files(db, row, key), 1):
            name = Path(item["name"]).name or f"secure-file-{index}"
            if name in used: name = f"{index}-{name}"
            used.add(name); archive.writestr(name, read_file(row, item["row"], key))
        note = decode_note(row, key)
        if note: archive.writestr("secure-note.txt", note)
    return output.getvalue()


def record_activity(db: Session, row: SecureSendPackage, event_type: str, *, actor_user_id: int | None = None, detail: dict | None = None, commit: bool = True) -> SecureSendActivity:
    activity = SecureSendActivity(package_id=row.id, event_type=event_type, actor_user_id=actor_user_id, encrypted_detail=None)
    db.add(activity); db.flush()
    if detail:
        activity.encrypted_detail = encrypt_value(package_key_from_application(row), row.id, f"activity:{activity.id}", detail)
    if commit: db.commit()
    return activity


def start_recipient_session(db: Session, row: SecureSendPackage) -> tuple[str, str, SecureSendRecipientSession]:
    revoke_recipient_sessions(db, row.id, commit=False)
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    now = datetime.utcnow()
    session = SecureSendRecipientSession(
        package_id=row.id, token_hash=hashlib.sha256(token.encode()).hexdigest(), csrf_hash=hashlib.sha256(csrf.encode()).hexdigest(),
        created_at=now, last_activity_at=now, expires_at=min(row.expires_at, now + timedelta(minutes=SESSION_MINUTES)),
    )
    db.add(session); db.commit()
    return token, csrf, session


def active_recipient_session(db: Session, row: SecureSendPackage, token: str | None) -> SecureSendRecipientSession | None:
    if not token or not package_accessible(row): return None
    now = datetime.utcnow()
    session = db.query(SecureSendRecipientSession).filter_by(package_id=row.id, token_hash=hashlib.sha256(token.encode()).hexdigest()).first()
    if not session or session.revoked_at or session.expires_at <= now: return None
    session.last_activity_at = now; session.expires_at = min(row.expires_at, now + timedelta(minutes=SESSION_MINUTES)); db.commit()
    return session


def verify_session_csrf(session: SecureSendRecipientSession, value: str) -> bool:
    return bool(value and secrets.compare_digest(session.csrf_hash, hashlib.sha256(value.encode()).hexdigest()))


def revoke_recipient_sessions(db: Session, package_id: int, *, commit: bool = True) -> None:
    db.query(SecureSendRecipientSession).filter_by(package_id=package_id, revoked_at=None).update({SecureSendRecipientSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
    if commit: db.commit()


def clean_package_content(db: Session, row: SecureSendPackage, *, status: str) -> None:
    now = datetime.utcnow()
    for item in db.query(SecureSendFile).filter_by(package_id=row.id).all():
        try: (ensure_storage() / item.storage_id).unlink(missing_ok=True)
        except OSError: pass
        db.delete(item)
    row.encrypted_note = None; row.cleaned_at = now; row.status = status
    if status == "expired": row.expired_at = row.expired_at or now
    if status == "deleted": row.deleted_at = row.deleted_at or now
    revoke_recipient_sessions(db, row.id, commit=False)
    db.commit()


def expire_and_cleanup(db: Session) -> int:
    now = datetime.utcnow(); count = 0
    rows = db.query(SecureSendPackage).filter(SecureSendPackage.expires_at <= now, SecureSendPackage.cleaned_at.is_(None)).all()
    for row in rows:
        record_activity(db, row, "expired", commit=False)
        clean_package_content(db, row, status="expired"); count += 1
    return count


def decrypted_access_token(row: SecureSendPackage) -> str:
    value = decrypt_secret(row.encrypted_access_token)
    return "" if value == "[decryption failed]" else value
