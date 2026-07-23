import base64
import hashlib
import io
import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.datastructures import UploadFile
from fastapi import HTTPException

from app.db.session import Base
from app.main import app
from app.models.models import AppSession, User
from app.routers import auth, remote_manager
from app.routers.admin import test_backup_storage_target as check_backup_storage_target
from app.services.sessions import active_user_session, revoke_user_sessions, touch_user_session


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def request(session=None):
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "path": "/setup",
            "raw_path": b"/setup",
            "query_string": b"",
            "headers": [],
            "client": ("198.51.100.2", 1234),
            "server": ("kaya.example.com", 443),
            "session": session or {"csrf_token": "csrf"},
            "app": app,
        }
    )


def user(db, email="user@example.com"):
    row = User(email=email, password_hash="hash", role="admin", is_active=True)
    db.add(row)
    db.flush()
    return row


def test_authoritative_session_rejects_missing_ended_mismatched_and_expired_rows():
    with database() as db:
        first = user(db)
        second = user(db, "other@example.com")
        current = AppSession(session_id="current", user_id=first.id)
        ended = AppSession(session_id="ended", user_id=first.id, ended_at=datetime.utcnow())
        expired = AppSession(
            session_id="expired",
            user_id=first.id,
            created_at=datetime.utcnow() - timedelta(hours=9),
        )
        db.add_all([current, ended, expired])
        db.commit()

        assert active_user_session(db, "current", first.id) is current
        assert active_user_session(db, "current", second.id) is None
        assert active_user_session(db, "ended", first.id) is None
        assert active_user_session(db, "expired", first.id) is None
        assert active_user_session(db, "missing", first.id) is None

        missing_request = request({"csrf_token": "csrf", "session_id": "missing"})
        assert touch_user_session(db, missing_request, first) is False
        assert db.query(AppSession).filter_by(session_id="missing").first() is None


def test_session_revocation_can_preserve_only_the_current_session():
    with database() as db:
        account = user(db)
        current = AppSession(session_id="current", user_id=account.id)
        other = AppSession(session_id="other", user_id=account.id, encrypted_oidc_id_token="encrypted")
        db.add_all([current, other])
        db.commit()

        assert revoke_user_sessions(db, account.id, except_session_id="current") == 1
        db.commit()
        assert current.ended_at is None
        assert other.ended_at is not None
        assert other.encrypted_oidc_id_token is None


def test_first_run_setup_requires_the_deployment_token(monkeypatch):
    monkeypatch.setattr(auth, "settings", SimpleNamespace(setup_token="one-time-token", demo_mode=False))
    with database() as db:
        response = auth.setup_submit(
            request(),
            first_name="Kaya",
            last_name="Admin",
            email="admin@example.com",
            password="correct horse battery staple",
            confirm_password="correct horse battery staple",
            setup_token="wrong-token",
            csrf_token="csrf",
            db=db,
        )
        assert response.status_code == 403
        assert db.query(User).count() == 0

        response = auth.setup_submit(
            request(),
            first_name="Kaya",
            last_name="Admin",
            email="admin@example.com",
            password="correct horse battery staple",
            confirm_password="correct horse battery staple",
            setup_token="one-time-token",
            csrf_token="csrf",
            db=db,
        )
        assert response.status_code == 303
        assert db.query(User).filter_by(email="admin@example.com", role="admin").count() == 1


def test_ssh_host_key_scan_returns_a_verifiable_sha256_fingerprint(monkeypatch):
    raw_key = b"release-test-ed25519-key"
    encoded_key = base64.b64encode(raw_key).decode("ascii")
    completed = SimpleNamespace(stdout=f"host.example ssh-ed25519 {encoded_key}\n")
    calls = []

    monkeypatch.setattr(remote_manager.shutil, "which", lambda name: "/usr/bin/ssh-keyscan")

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return completed

    monkeypatch.setattr(remote_manager.subprocess, "run", run)
    row = SimpleNamespace(
        protocol="ssh",
        port=2222,
        ip_address=SimpleNamespace(address="192.0.2.10"),
    )
    expected = base64.b64encode(hashlib.sha256(raw_key).digest()).decode("ascii").rstrip("=")

    assert remote_manager.scan_ssh_host_key(row) == f"ssh-ed25519 SHA256:{expected}"
    assert calls[0][0] == ["/usr/bin/ssh-keyscan", "-T", "5", "-p", "2222", "192.0.2.10"]
    assert calls[0][1]["timeout"] == 10


def test_plaintext_ftp_is_blocked_even_when_its_legacy_path_is_writable(tmp_path):
    with database() as db:
        ok, detail = check_backup_storage_target(
            db,
            storage_type="ftp",
            storage_path=str(tmp_path),
            remote_host="ftp.example.com",
            remote_share="",
            remote_username="legacy",
            remote_password="legacy",
        )
    assert ok is False
    assert "Plaintext FTP is disabled" in detail


def test_recording_upload_streams_in_bounded_chunks_and_removes_oversize_partial_file(monkeypatch, tmp_path):
    monkeypatch.setattr(
        remote_manager,
        "get_settings",
        lambda: SimpleNamespace(max_recording_upload_mb=1, min_recording_free_mb=0),
    )
    monkeypatch.setattr(remote_manager, "RECORDING_ROOT", tmp_path)
    path = tmp_path / "recording.webm"
    upload = UploadFile(filename="recording.webm", file=io.BytesIO(b"x" * (1024 * 1024 + 1)))

    try:
        asyncio.run(remote_manager.stream_recording_upload(upload, path))
        assert False, "Oversized upload should fail"
    except HTTPException as exc:
        assert exc.status_code == 413

    assert path.exists() is False
    assert path.with_suffix(".webm.part").exists() is False
