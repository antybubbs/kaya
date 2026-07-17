import base64
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import User, VaultSession
import app.services.secret_vault as vault_service


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def app_key(monkeypatch, tmp_path):
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    monkeypatch.setattr(vault_service, "get_settings", lambda: type("Settings", (), {"encryption_key": key})())
    monkeypatch.setattr(vault_service, "VAULT_STORAGE", tmp_path / "vault")


def account(db):
    user = User(email="vault@example.test", password_hash="unused", role="viewer", is_active=True, totp_enabled=True)
    db.add(user); db.commit(); return user


def test_pin_and_recovery_wrap_the_same_random_master_key(db):
    user = account(db)
    vault, recovery = vault_service.create_vault(db, user, "correct horse battery staple")
    pin_key = vault_service.master_key_from_pin(vault, "correct horse battery staple")
    recovery_key = vault_service.master_key_from_recovery(vault, recovery)
    app_key = vault_service.master_key_from_application(vault)
    assert pin_key == recovery_key == app_key
    with pytest.raises(vault_service.VaultCryptoError):
        vault_service.master_key_from_pin(vault, "incorrect passphrase")


def test_used_recovery_key_is_rotated_and_cannot_be_replayed(db):
    user = account(db)
    vault, original = vault_service.create_vault(db, user, "correct horse battery staple")
    master_key = vault_service.master_key_from_recovery(vault, original)
    replacement = vault_service.rotate_recovery_key(db, vault, master_key)
    assert replacement != original
    with pytest.raises(vault_service.VaultCryptoError):
        vault_service.master_key_from_recovery(vault, original)
    assert vault_service.master_key_from_recovery(vault, replacement) == master_key
    assert vault.recovery_confirmed_at is None


def test_payload_encryption_rejects_tampering_and_wrong_associated_data():
    key = b"m" * 32
    encrypted = vault_service.encrypt_payload(key, 17, "item:2", {"title": "Recovery", "secret": "value"})
    assert "Recovery" not in encrypted and "value" not in encrypted
    assert vault_service.decrypt_payload(key, 17, "item:2", encrypted)["secret"] == "value"
    with pytest.raises(vault_service.VaultCryptoError):
        vault_service.decrypt_payload(key, 18, "item:2", encrypted)
    raw = bytearray(base64.urlsafe_b64decode(encrypted)); raw[-1] ^= 1
    with pytest.raises(vault_service.VaultCryptoError):
        vault_service.decrypt_payload(key, 17, "item:2", base64.urlsafe_b64encode(raw).decode())


def test_encrypted_files_reject_modified_ciphertext():
    key = b"f" * 32
    encrypted = vault_service.encrypt_file(key, 3, "storage-id", b"private document")
    assert b"private document" not in encrypted
    assert vault_service.decrypt_file(key, 3, "storage-id", encrypted) == b"private document"
    modified = bytearray(encrypted); modified[-2] ^= 4
    with pytest.raises(vault_service.VaultCryptoError):
        vault_service.decrypt_file(key, 3, "storage-id", bytes(modified))


def test_portable_export_is_independent_authenticated_and_versioned():
    payload = {"format": "kayavault", "version": 1, "items": [{"payload": {"title": "DC01"}}], "collections": []}
    package = vault_service.encrypt_portable_package(payload, "a sufficiently long export passphrase")
    assert b"DC01" not in package
    assert vault_service.decrypt_portable_package(package, "a sufficiently long export passphrase") == payload
    with pytest.raises(vault_service.VaultCryptoError):
        vault_service.decrypt_portable_package(package, "wrong but sufficiently long password")
    outer = json.loads(package); ciphertext = bytearray(base64.urlsafe_b64decode(outer["ciphertext"])); ciphertext[-1] ^= 1; outer["ciphertext"] = base64.urlsafe_b64encode(ciphertext).decode()
    with pytest.raises(vault_service.VaultCryptoError):
        vault_service.decrypt_portable_package(json.dumps(outer).encode(), "a sufficiently long export passphrase")


@pytest.mark.parametrize("weak", ["11111111", "12345678", "87654321", "12121212", "short"])
def test_weak_pin_patterns_are_rejected(weak):
    assert vault_service.validate_pin(weak)


def test_vault_session_is_bound_to_kaya_session_and_expires(db):
    user = account(db); vault, _ = vault_service.create_vault(db, user, "correct horse battery staple")
    request = type("Request", (), {"session": {"session_id": "kaya-session"}})()
    row = vault_service.start_vault_session(db, request, vault, user)
    assert vault_service.active_vault_session(db, request, user, touch=False).id == row.id
    request.session["session_id"] = "different-session"
    assert vault_service.active_vault_session(db, request, user, touch=False) is None
    request.session["session_id"] = "kaya-session"
    row.expires_at = datetime.utcnow() - timedelta(seconds=1); db.commit()
    assert vault_service.active_vault_session(db, request, user, touch=False) is None


def test_totp_replay_is_rejected(db, monkeypatch):
    user = account(db); user.totp_secret = "encrypted"; db.commit()
    secret = vault_service.base64.b32encode(b"s" * 20).decode().rstrip("=")
    monkeypatch.setattr(vault_service, "decrypted_totp_secret", lambda _: secret)
    monkeypatch.setattr(vault_service.time, "time", lambda: 1_800_000_000)
    code = vault_service.hotp(secret, int(1_800_000_000 // 30))
    assert vault_service.verify_fresh_totp(db, user, code)
    assert not vault_service.verify_fresh_totp(db, user, code)


def test_audit_and_router_sources_do_not_log_submitted_secret_values():
    source = (vault_service.Path(__file__).parents[1] / "app" / "routers" / "secret_vault.py").read_text(encoding="utf-8")
    assert "detail=pin" not in source
    assert "detail=totp_code" not in source
    assert "detail=recovery_key" not in source
