"""Cryptographic and session primitives for Secret Vault.

No plaintext vault value is persisted by this module. AES-GCM associated data
binds every ciphertext to its owning vault and record purpose.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from fastapi import HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.kayavault import KayaVaultError, decrypt_package, encrypt_package
from app.core.security import hash_password, verify_password
from app.core.totp import decrypted_totp_secret, hotp
from app.models.models import User, Vault, VaultSession, VaultTotpUse

FORMAT_VERSION = 1
ABSOLUTE_SESSION_HOURS = 8
SESSION_KEY = "vault_session_token"
VAULT_STORAGE = Path(os.getenv("KAYA_VAULT_STORAGE_DIR", "/app/data/secret-vault"))
if not Path("/app/data").exists():
    VAULT_STORAGE = Path("data/secret-vault")


class VaultCryptoError(ValueError):
    pass


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def application_kek() -> bytes:
    raw = base64.urlsafe_b64decode(get_settings().encryption_key.encode("ascii"))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"kaya-secret-vault-kek-v1").derive(raw)


def derive_wrapping_key(secret: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(secret.encode("utf-8"))


def seal(key: bytes, plaintext: bytes, associated_data: bytes) -> str:
    nonce = secrets.token_bytes(12)
    return _b64(nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data))


def open_sealed(key: bytes, value: str, associated_data: bytes) -> bytes:
    try:
        packed = _unb64(value)
        if len(packed) < 29:
            raise VaultCryptoError("Ciphertext is malformed")
        return AESGCM(key).decrypt(packed[:12], packed[12:], associated_data)
    except (InvalidTag, ValueError, TypeError) as exc:
        raise VaultCryptoError("Vault integrity validation failed") from exc


def wrap_key(master_key: bytes, wrapping_key: bytes, purpose: str) -> str:
    return seal(wrapping_key, master_key, f"kaya-vault-wrap:{purpose}:v1".encode())


def unwrap_key(value: str, wrapping_key: bytes, purpose: str) -> bytes:
    key = open_sealed(wrapping_key, value, f"kaya-vault-wrap:{purpose}:v1".encode())
    if len(key) != 32:
        raise VaultCryptoError("Wrapped key has an invalid length")
    return key


def encrypt_payload(master_key: bytes, vault_id: int, purpose: str, payload: dict[str, Any]) -> str:
    plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return seal(master_key, plain, f"vault:{vault_id}:{purpose}:v1".encode())


def decrypt_payload(master_key: bytes, vault_id: int, purpose: str, value: str) -> dict[str, Any]:
    try:
        payload = json.loads(open_sealed(master_key, value, f"vault:{vault_id}:{purpose}:v1".encode()))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultCryptoError("Vault payload is invalid") from exc
    if not isinstance(payload, dict):
        raise VaultCryptoError("Vault payload has an invalid shape")
    return payload


def generate_recovery_key() -> str:
    encoded = base64.b32encode(secrets.token_bytes(25)).decode("ascii").rstrip("=")
    return "-".join(encoded[index:index + 5] for index in range(0, len(encoded), 5))


def normalise_recovery_key(value: str) -> str:
    return re.sub(r"[^A-Z2-7]", "", value.upper())


def validate_pin(value: str, minimum: int = 8) -> str | None:
    if len(value) < minimum:
        return f"Use at least {minimum} characters."
    if value.isdigit():
        if len(set(value)) == 1:
            return "Repeated digits are not allowed."
        ascending = "01234567890123456789"
        descending = ascending[::-1]
        if value in ascending or value in descending:
            return "Sequential digits are not allowed."
        if value in {"12345678", "87654321", "11223344", "12121212", "00000000"}:
            return "Choose a less predictable PIN."
    elif len(value) < 12:
        return "Passphrases must contain at least 12 characters."
    return None


def create_vault(db: Session, user: User, pin: str) -> tuple[Vault, str]:
    master_key = secrets.token_bytes(32)
    recovery_key = generate_recovery_key()
    pin_salt = secrets.token_bytes(16)
    recovery_salt = secrets.token_bytes(16)
    vault = Vault(
        owner_id=user.id,
        pin_hash=hash_password(pin),
        pin_salt=_b64(pin_salt),
        pin_wrapped_key=wrap_key(master_key, derive_wrapping_key(pin, pin_salt), "pin"),
        recovery_hash=hash_password(normalise_recovery_key(recovery_key)),
        recovery_salt=_b64(recovery_salt),
        recovery_wrapped_key=wrap_key(master_key, derive_wrapping_key(normalise_recovery_key(recovery_key), recovery_salt), "recovery"),
        app_wrapped_key=wrap_key(master_key, application_kek(), "application"),
    )
    db.add(vault)
    db.commit()
    db.refresh(vault)
    return vault, recovery_key


def master_key_from_pin(vault: Vault, pin: str) -> bytes:
    if not verify_password(pin, vault.pin_hash):
        raise VaultCryptoError("Authentication failed")
    return unwrap_key(vault.pin_wrapped_key, derive_wrapping_key(pin, _unb64(vault.pin_salt)), "pin")


def master_key_from_recovery(vault: Vault, recovery_key: str) -> bytes:
    clean = normalise_recovery_key(recovery_key)
    if not verify_password(clean, vault.recovery_hash):
        raise VaultCryptoError("Authentication failed")
    return unwrap_key(vault.recovery_wrapped_key, derive_wrapping_key(clean, _unb64(vault.recovery_salt)), "recovery")


def master_key_from_application(vault: Vault) -> bytes:
    return unwrap_key(vault.app_wrapped_key, application_kek(), "application")


def reset_pin(db: Session, vault: Vault, master_key: bytes, new_pin: str) -> None:
    salt = secrets.token_bytes(16)
    vault.pin_hash = hash_password(new_pin)
    vault.pin_salt = _b64(salt)
    vault.pin_wrapped_key = wrap_key(master_key, derive_wrapping_key(new_pin, salt), "pin")
    vault.updated_at = datetime.utcnow()
    revoke_sessions(db, vault.id)
    db.commit()


def rotate_recovery_key(db: Session, vault: Vault, master_key: bytes) -> str:
    """Replace a recovery key after use so captured recovery material cannot be replayed."""
    recovery_key = generate_recovery_key()
    clean = normalise_recovery_key(recovery_key)
    salt = secrets.token_bytes(16)
    vault.recovery_hash = hash_password(clean)
    vault.recovery_salt = _b64(salt)
    vault.recovery_wrapped_key = wrap_key(master_key, derive_wrapping_key(clean, salt), "recovery")
    vault.recovery_confirmed_at = None
    vault.updated_at = datetime.utcnow()
    revoke_sessions(db, vault.id)
    db.commit()
    return recovery_key


def verify_fresh_totp(db: Session, user: User, code: str) -> bool:
    if not user.totp_enabled or not user.totp_secret or not code.strip().isdigit():
        return False
    secret = decrypted_totp_secret(user.totp_secret)
    if not secret or secret == "[decryption failed]":
        return False
    counter = int(time.time() // 30)
    for offset in (-1, 0, 1):
        candidate = counter + offset
        if secrets.compare_digest(hotp(secret, candidate), code.strip()):
            if db.query(VaultTotpUse).filter_by(user_id=user.id, counter=candidate).first():
                return False
            db.add(VaultTotpUse(user_id=user.id, counter=candidate))
            db.query(VaultTotpUse).filter(VaultTotpUse.used_at < datetime.utcnow() - timedelta(days=1)).delete()
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                return False
            return True
    return False


def start_vault_session(db: Session, request: Request, vault: Vault, user: User, method: str = "pin_totp") -> VaultSession:
    revoke_sessions(db, vault.id, user.id)
    token = secrets.token_urlsafe(48)
    now = datetime.utcnow()
    minutes = max(5, min(60, vault.auto_lock_minutes or 10))
    row = VaultSession(
        vault_id=vault.id,
        user_id=user.id,
        app_session_id=str(request.session.get("session_id") or ""),
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        nonce=secrets.token_urlsafe(24),
        authentication_method=method,
        unlocked_at=now,
        last_activity_at=now,
        expires_at=now + timedelta(minutes=minutes),
        absolute_expires_at=now + timedelta(hours=ABSOLUTE_SESSION_HOURS),
    )
    db.add(row)
    db.commit()
    request.session[SESSION_KEY] = token
    return row


def active_vault_session(db: Session, request: Request, user: User, touch: bool = True) -> VaultSession | None:
    token = request.session.get(SESSION_KEY)
    app_session = request.session.get("session_id")
    if not token or not app_session:
        return None
    now = datetime.utcnow()
    row = db.query(VaultSession).filter_by(
        token_hash=hashlib.sha256(token.encode()).hexdigest(), user_id=user.id, app_session_id=app_session
    ).first()
    if not row or row.revoked_at or row.expires_at <= now or row.absolute_expires_at <= now:
        request.session.pop(SESSION_KEY, None)
        if row and not row.revoked_at:
            row.revoked_at = now
            db.commit()
        return None
    if touch:
        vault = db.get(Vault, row.vault_id)
        row.last_activity_at = now
        row.expires_at = min(row.absolute_expires_at, now + timedelta(minutes=max(5, min(60, vault.auto_lock_minutes))))
        db.commit()
    return row


def require_unlocked(db: Session, request: Request, user: User) -> tuple[Vault, bytes]:
    session = active_vault_session(db, request, user)
    if not session:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Vault is locked")
    vault = db.get(Vault, session.vault_id)
    if not vault or vault.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Vault access denied")
    return vault, master_key_from_application(vault)


def revoke_sessions(db: Session, vault_id: int, user_id: int | None = None) -> None:
    query = db.query(VaultSession).filter(VaultSession.vault_id == vault_id, VaultSession.revoked_at.is_(None))
    if user_id is not None:
        query = query.filter(VaultSession.user_id == user_id)
    query.update({VaultSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
    db.commit()


def lock_vault(db: Session, request: Request, user: User) -> None:
    row = active_vault_session(db, request, user, touch=False)
    if row:
        row.revoked_at = datetime.utcnow()
        db.commit()
    request.session.pop(SESSION_KEY, None)


def record_failed_unlock(db: Session, vault: Vault) -> None:
    vault.failed_attempts = (vault.failed_attempts or 0) + 1
    if vault.failed_attempts >= 10:
        vault.locked_until = datetime.utcnow() + timedelta(minutes=30)
    elif vault.failed_attempts >= 5:
        vault.locked_until = datetime.utcnow() + timedelta(minutes=5)
    db.commit()


def clear_failed_unlock(db: Session, vault: Vault) -> None:
    vault.failed_attempts = 0
    vault.locked_until = None
    db.commit()


def ensure_storage() -> Path:
    VAULT_STORAGE.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        VAULT_STORAGE.chmod(0o700)
    except OSError:
        pass
    return VAULT_STORAGE


def encrypt_file(master_key: bytes, vault_id: int, storage_id: str, content: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(master_key).encrypt(nonce, content, f"vault:{vault_id}:attachment:{storage_id}:v1".encode())


def decrypt_file(master_key: bytes, vault_id: int, storage_id: str, content: bytes) -> bytes:
    try:
        return AESGCM(master_key).decrypt(content[:12], content[12:], f"vault:{vault_id}:attachment:{storage_id}:v1".encode())
    except (InvalidTag, ValueError) as exc:
        raise VaultCryptoError("Attachment integrity validation failed") from exc


def safe_reference() -> str:
    return f"SV-{datetime.utcnow():%Y%m%d}-{secrets.token_hex(3).upper()}"


def encrypt_portable_package(payload: dict[str, Any], passphrase: str) -> bytes:
    try:
        return encrypt_package(payload, passphrase)
    except KayaVaultError as exc:
        raise VaultCryptoError(str(exc)) from exc


def decrypt_portable_package(package_bytes: bytes, passphrase: str) -> dict[str, Any]:
    try:
        return decrypt_package(package_bytes, passphrase)
    except KayaVaultError as exc:
        raise VaultCryptoError(str(exc)) from exc
