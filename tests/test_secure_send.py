import base64
import json
import logging
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import SecureSendFile, SecureSendRecipientSession, User
import app.services.secret_vault as vault_service
import app.services.secure_send as send_service
import app.routers.secure_send as send_router
import app.security_gateway as gateway


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


def test_gateway_health_reports_running_and_caches(monkeypatch):
    calls = []

    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self, _limit): return b'{"status":"ok"}'

    monkeypatch.setattr(send_service, "urlopen", lambda request, timeout: calls.append((request.full_url, timeout)) or Response())
    send_service._GATEWAY_HEALTH_CACHE.update({"expires": 0.0, "result": None})
    assert send_service.gateway_health(force=True)["state"] == "running"
    assert send_service.gateway_health()["state"] == "running"
    assert calls == [("http://secure-send-gateway:8999/healthz", 0.8)]


def test_gateway_health_failure_is_safe_and_visible(monkeypatch):
    monkeypatch.setattr(send_service, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")))
    send_service._GATEWAY_HEALTH_CACHE.update({"expires": 0.0, "result": None})
    result = send_service.gateway_health(force=True)
    assert result["state"] == "unavailable"
    assert "secure-send-gateway" in result["detail"]


def test_authenticated_gateway_status_endpoint_is_live_and_not_cached(db, monkeypatch):
    user = sender(db)
    checks = []
    monkeypatch.setattr(send_router, "gateway_health", lambda: checks.append(True) or {
        "state": "running", "label": "Gateway running", "detail": "Healthy", "checked_at": "12:00:00 UTC",
    })
    response = send_router.gateway_status(db=db, user=user)
    assert response.headers["cache-control"] == "no-store"
    assert json.loads(response.body) == {
        "state": "running", "label": "Gateway running", "detail": "Healthy", "checked_at": "12:00:00 UTC",
    }
    assert checks == [True]


def test_secure_send_dashboard_polls_gateway_status_live():
    root = send_service.Path(__file__).parents[1]
    template = (root / "app" / "templates" / "secure_send.html").read_text(encoding="utf-8")
    script = (root / "app" / "static" / "js" / "secure_send.js").read_text(encoding="utf-8")
    assert "data-gateway-status" in template and "aria-live=\"polite\"" in template
    assert "/security/secure-send/gateway-status" in script
    assert "setInterval(checkGateway, 3000)" in script
    assert "cache: 'no-store'" in script


def test_gateway_denies_malformed_unknown_and_unrecognised_paths_without_branding(db):
    gateway.app.dependency_overrides[gateway.get_db] = lambda: db
    gateway.PUBLIC_REQUESTS.clear()
    try:
        with TestClient(gateway.app) as client:
            gateway.GATEWAY_HOST_CACHE.update({"expires": float("inf"), "hostname": "localhost"})
            for path in ["/dededsfsfa", "/", "/anything/else", "/static/css/app.css", "/bad?token=value", f"/{'a' * 64}"]:
                response = client.get(path, headers={"Host": "localhost"})
                assert response.status_code == 403
                assert response.text == "Forbidden"
                assert "Kaya" not in response.text and "package" not in response.text.lower()
                assert response.headers["cache-control"] == "no-store, max-age=0"
                assert response.headers["x-frame-options"] == "DENY"
            assert client.put(f"/{'a' * 64}", headers={"Host": "localhost"}).status_code == 403
    finally:
        gateway.app.dependency_overrides.clear()


def test_gateway_health_requires_internal_proof():
    gateway.PUBLIC_REQUESTS.clear()
    with TestClient(gateway.app) as client:
        denied = client.get("/healthz")
        allowed = client.get("/healthz", headers={"X-Kaya-Health": send_service.gateway_health_token()})
    assert denied.status_code == 403 and denied.text == "Forbidden"
    assert allowed.status_code == 200 and allowed.json() == {"status": "ok"}


def test_gateway_exposes_only_dedicated_static_assets():
    gateway.PUBLIC_REQUESTS.clear()
    gateway.GATEWAY_HOST_CACHE.update({"expires": float("inf"), "hostname": "localhost"})
    with TestClient(gateway.app) as client:
        headers = {"Host": "localhost"}
        assert client.get("/assets/gateway.css", headers=headers).status_code == 200
        assert client.get("/assets/logo.png", headers=headers).status_code == 200
        assert client.get("/favicon.svg", headers=headers).status_code == 200
        assert client.get("/static/js/login.js", headers=headers).status_code == 403
        assert client.get("/assets/gateway.css", headers={"Host": "attacker.example"}).status_code == 403


def test_gateway_rejection_logging_explains_guard_without_sensitive_request_data(caplog):
    gateway.PUBLIC_REQUESTS.clear()
    gateway.GATEWAY_HOST_CACHE.update({"expires": float("inf"), "hostname": "localhost"})
    access_token = "a" * 64
    with caplog.at_level(logging.WARNING, logger="kaya.secure_send.gateway"):
        with TestClient(gateway.app) as client:
            response = client.post(
                f"/{access_token}/unlock",
                headers={"Host": "localhost", "Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
                data={"pin": "740196", "passphrase": "secret-passphrase"},
            )
    assert response.status_code == 403
    assert "method=POST reason=origin" in caplog.text
    for sensitive in (access_token, "740196", "secret-passphrase", "attacker.example"):
        assert sensitive not in caplog.text


def test_valid_package_flow_survives_host_origin_and_method_enforcement(db, monkeypatch):
    row, access_token, passphrase = package(db)
    gateway.app.dependency_overrides[gateway.get_db] = lambda: db
    gateway.PUBLIC_REQUESTS.clear()
    gateway.GATEWAY_HOST_CACHE.update({"expires": float("inf"), "hostname": "localhost"})
    monkeypatch.setattr(gateway, "notify_sender", lambda *_args, **_kwargs: None)
    headers = {"Host": "localhost"}
    try:
        with TestClient(gateway.app) as client:
            landing = client.get(f"/{access_token}", headers=headers)
            assert landing.status_code == 200 and "Open secure package" in landing.text
            unlocked = client.post(
                f"/{access_token}/unlock", headers={**headers, "Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"},
                data={"pin": "740196", "passphrase": passphrase}, follow_redirects=False,
            )
            assert unlocked.status_code == 303
            content = client.get(unlocked.headers["location"], headers=headers)
            assert content.status_code == 200 and "highly confidential note" in content.text
    finally:
        gateway.app.dependency_overrides.clear()


def test_gateway_runtime_disables_bearer_url_access_logging():
    compose = (send_service.Path(__file__).parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    assert "--no-access-log" in compose
    assert "--no-server-header" in compose
