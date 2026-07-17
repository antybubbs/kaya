import base64
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import SecureSendFile, SecureSendRecipientSession, User
import app.services.secret_vault as vault_service
import app.services.secure_send as send_service


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def keys_and_storage(monkeypatch, tmp_path):
    key = base64.urlsafe_b64encode(b"s" * 32).decode()
    monkeypatch.setattr(vault_service, "get_settings", lambda: type("Settings", (), {"encryption_key": key})())
    monkeypatch.setattr(send_service, "STORAGE", tmp_path / "secure-send")


def sender(db):
    row = User(email="sender@example.test", password_hash="unused", role="editor", is_active=True)
    db.add(row); db.commit(); return row


def package(db, *, expires_at=None, one_download=False):
    return send_service.create_package(
        db, sender(db), recipient_type="external", internal_recipient_id=None,
        summary={"title": "Private handoff", "recipient_name": "Recipient", "recipient_email": "recipient@example.test"},
        note="highly confidential note", pin="740196", expires_at=expires_at or datetime.utcnow() + timedelta(hours=1),
        one_download_only=one_download, allow_vault_save=False, notify_when_opened=True,
        files=[("private.txt", "text/plain", b"private file body")],
    )


def test_package_content_and_recipient_metadata_are_encrypted_at_rest(db):
    row, token, passphrase = package(db)
    file_row = db.query(SecureSendFile).filter_by(package_id=row.id).one()
    assert "Private handoff" not in row.encrypted_summary
    assert "recipient@example.test" not in row.encrypted_summary
    assert "highly confidential note" not in row.encrypted_note
    assert token not in row.access_token_hash and passphrase not in row.credential_hash
    ciphertext = (send_service.ensure_storage() / file_row.storage_id).read_bytes()
    assert b"private file body" not in ciphertext
    key = send_service.authenticate_package(row, token, "740196", passphrase)
    assert send_service.decode_note(row, key) == "highly confidential note"
    assert send_service.read_file(row, file_row, key) == b"private file body"


def test_all_three_credentials_are_required(db):
    row, token, passphrase = package(db)
    assert send_service.authenticate_package(row, token, "740196", passphrase)
    for candidate in [("wrong", "740196", passphrase), (token, "000000", passphrase), (token, "740196", "wrong-words")]:
        with pytest.raises(send_service.SecureSendError):
            send_service.authenticate_package(row, *candidate)


def test_ciphertext_tampering_is_rejected(db):
    row, token, passphrase = package(db)
    key = send_service.authenticate_package(row, token, "740196", passphrase)
    file_row = db.query(SecureSendFile).filter_by(package_id=row.id).one()
    path = send_service.ensure_storage() / file_row.storage_id
    content = bytearray(path.read_bytes()); content[-1] ^= 1; path.write_bytes(content)
    with pytest.raises(send_service.SecureSendError):
        send_service.read_file(row, file_row, key)


def test_recipient_session_is_opaque_csrf_bound_and_revocable(db):
    row, _, _ = package(db)
    token, csrf, session = send_service.start_recipient_session(db, row)
    assert token not in session.token_hash and csrf not in session.csrf_hash
    assert send_service.active_recipient_session(db, row, token).id == session.id
    assert send_service.verify_session_csrf(session, csrf)
    assert not send_service.verify_session_csrf(session, "wrong")
    send_service.revoke_recipient_sessions(db, row.id)
    assert send_service.active_recipient_session(db, row, token) is None


def test_expiry_destroys_payload_and_revokes_sessions(db):
    row, _, _ = package(db, expires_at=datetime.utcnow() - timedelta(seconds=1))
    file_row = db.query(SecureSendFile).filter_by(package_id=row.id).one()
    path = send_service.ensure_storage() / file_row.storage_id
    _, _, session = send_service.start_recipient_session(db, row)
    assert path.exists()
    assert send_service.expire_and_cleanup(db) == 1
    db.refresh(row); db.refresh(session)
    assert row.status == "expired" and row.cleaned_at and row.encrypted_note is None
    assert not path.exists() and not db.query(SecureSendFile).filter_by(package_id=row.id).count()
    assert session.revoked_at is not None


def test_public_gateway_and_router_sources_do_not_log_credentials():
    source = (send_service.Path(__file__).parents[1] / "app" / "security_gateway.py").read_text(encoding="utf-8")
    assert "metadata={\"pin\"" not in source
    assert "metadata={\"passphrase\"" not in source
    assert "detail=pin" not in source and "detail=passphrase" not in source


def test_wizard_and_copy_script_use_the_base_template_script_block():
    root = send_service.Path(__file__).parents[1]
    base = (root / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    wizard = (root / "app" / "templates" / "secure_send_new.html").read_text(encoding="utf-8")
    created = (root / "app" / "templates" / "secure_send_created.html").read_text(encoding="utf-8")
    assert "{% block extra_scripts %}" in base
    assert "{% block extra_scripts %}" in wizard and "secure_send.js" in wizard
    assert "{% block extra_scripts %}" in created and "secure_send.js" in created
