"""UI wiring for the protocol-v2 server signing key prerequisite.

The provisioning endpoint (app/routers/backup_agent_v2.py::provision_agent_server_key)
and its underlying service (create_server_signing_key) already existed and were
fully gated (admin-only, CSRF, idempotent). Nothing in the frontend ever called it,
so /api/agent/v2/register failed closed with a 503 on every fresh install with no
way for an administrator to discover why. These tests cover the missing wiring:
readiness state on the Compute Host detail page, and the guided provisioning action.
"""

import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.db.session import Base
from app.main import app as fastapi_app
from app.models.models import AuditLog, BackupAgentServerKey, ComputeHost, User
from app.routers import backup_agent_v2, compute_manager
from app.services.backup_agent_protocol import b64u, issue_bootstrap


def database():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return Session(engine)


def actor(db, *, role="admin"):
    row = User(email=f"{role}-{uuid.uuid4()}@example.invalid", password_hash="hash", role=role, is_active=True)
    db.add(row)
    db.flush()
    return row


def docker_host(db, *, name="Synthetic Docker Host"):
    host = ComputeHost(name=name, platform="docker_agent", base_url="agent://synthetic", is_enabled=True)
    db.add(host)
    db.flush()
    return host


def get_request(*, query_string: bytes = b"", session=None):
    return Request(
        {
            "type": "http", "method": "GET", "path": "/", "raw_path": b"/",
            "query_string": query_string, "headers": [], "client": ("198.51.100.2", 1234),
            "session": session or {"csrf_token": "csrf"}, "app": fastapi_app,
        }
    )


def post_request(*, session=None):
    return Request(
        {
            "type": "http", "method": "POST", "path": "/", "raw_path": b"/",
            "query_string": b"", "headers": [], "client": ("198.51.100.2", 1234),
            "session": session or {"csrf_token": "csrf"}, "app": fastapi_app,
        }
    )


# ---------------------------------------------------------------------------
# Host detail page rendering (readiness state).
# ---------------------------------------------------------------------------


def test_no_active_key_shows_initialise_panel_and_hides_bootstrap():
    with database() as db:
        admin = actor(db)
        host = docker_host(db)
        db.commit()

        response = compute_manager.host_detail(get_request(), host.id, db=db, user=admin)

        body = response.body.decode()
        assert "Agent security is not initialised" in body
        assert "Initialise Agent Security" in body
        # No active key: bootstrap issuance and the compose file must not be offered yet.
        assert "Issue one-time bootstrap" not in body
        assert "docker-compose.yml file" not in body


def test_non_administrator_does_not_see_initialise_button():
    with database() as db:
        editor = actor(db, role="editor")
        host = docker_host(db)
        db.commit()

        response = compute_manager.host_detail(get_request(), host.id, db=db, user=editor)

        body = response.body.decode()
        assert "Agent security is not initialised" in body
        assert "Initialise Agent Security" not in body
        assert "Ask an administrator to initialise agent security" in body


def test_active_key_hides_initialise_panel_and_shows_bootstrap_and_safe_metadata():
    with database() as db:
        admin = actor(db)
        host = docker_host(db)
        key = BackupAgentServerKey(
            key_id="ssk_visible", public_key="not-a-secret-public-key", wrapped_private_key="wrapped-blob", status="active",
        )
        db.add(key)
        db.commit()

        response = compute_manager.host_detail(get_request(), host.id, db=db, user=admin)

        body = response.body.decode()
        assert "Agent security is not initialised" not in body
        assert "Initialise Agent Security" not in body
        assert "Issue one-time bootstrap" in body
        # Safe metadata (key id, status via presence, creation date) may be shown...
        assert "ssk_visible" in body
        # ...but never private key material.
        assert "wrapped-blob" not in body


def test_key_material_is_never_rendered_regardless_of_state():
    with database() as db:
        admin = actor(db)
        host = docker_host(db)
        key = BackupAgentServerKey(
            key_id="ssk_secret_check", public_key="public-key-bytes-b64", wrapped_private_key="TOP-SECRET-WRAPPED-PRIVATE-KEY", status="active",
        )
        db.add(key)
        db.commit()

        response = compute_manager.host_detail(get_request(), host.id, db=db, user=admin)
        body = response.body.decode()
        assert "TOP-SECRET-WRAPPED-PRIVATE-KEY" not in body
        assert "public-key-bytes-b64" not in body


# ---------------------------------------------------------------------------
# Provisioning route.
# ---------------------------------------------------------------------------


def test_provision_route_requires_admin_dependency():
    route = next(
        route for route in fastapi_app.routes
        if getattr(route, "path", "") == "/infrastructure/vm-docker-manager/agent-v2/server-key"
    )
    assert "require_admin" in {dependency.call.__name__ for dependency in route.dependant.dependencies}


def test_administrator_can_provision_the_key_and_redirect_enables_bootstrap():
    with database() as db:
        admin = actor(db)
        host = docker_host(db)
        db.commit()

        response = backup_agent_v2.provision_agent_server_key(
            post_request(), host_id=host.id, csrf_token="csrf", db=db, user=admin,
        )

        assert response.status_code == 303
        assert response.headers["location"] == f"/infrastructure/vm-docker-manager/hosts/{host.id}?agent_security_status=initialised"
        row = db.query(BackupAgentServerKey).filter_by(status="active").one()
        assert row.key_id

        # Re-render the host page as if following the redirect: bootstrap is now offered.
        rendered = compute_manager.host_detail(
            get_request(query_string=b"agent_security_status=initialised"), host.id, db=db, user=admin,
        )
        body = rendered.body.decode()
        assert "Agent security initialised" in body
        assert "Issue one-time bootstrap" in body
        assert "Agent security is not initialised" not in body


def test_csrf_failure_is_rejected_and_does_not_provision():
    with database() as db:
        admin = actor(db)
        host = docker_host(db)
        db.commit()

        with pytest.raises(HTTPException) as excinfo:
            backup_agent_v2.provision_agent_server_key(
                post_request(), host_id=host.id, csrf_token="wrong-token", db=db, user=admin,
            )
        assert excinfo.value.status_code == 400
        assert db.query(BackupAgentServerKey).count() == 0


def test_repeated_provisioning_is_handled_safely_without_duplicate_active_keys():
    with database() as db:
        admin = actor(db)
        host = docker_host(db)
        db.commit()

        first = backup_agent_v2.provision_agent_server_key(
            post_request(), host_id=host.id, csrf_token="csrf", db=db, user=admin,
        )
        second = backup_agent_v2.provision_agent_server_key(
            post_request(), host_id=host.id, csrf_token="csrf", db=db, user=admin,
        )

        assert first.status_code == 303
        assert first.headers["location"].endswith("agent_security_status=initialised")
        assert second.status_code == 303
        assert second.headers["location"].endswith("agent_security_status=already_initialised")
        assert db.query(BackupAgentServerKey).filter_by(status="active").count() == 1


def test_audit_logging_records_provisioning_once_without_key_material():
    with database() as db:
        admin = actor(db)
        host = docker_host(db)
        db.commit()

        backup_agent_v2.provision_agent_server_key(post_request(), host_id=host.id, csrf_token="csrf", db=db, user=admin)
        backup_agent_v2.provision_agent_server_key(post_request(), host_id=host.id, csrf_token="csrf", db=db, user=admin)

        audits = db.query(AuditLog).filter_by(action="provision_protocol_v2_server_key").all()
        assert len(audits) == 1  # the safe no-op retry does not write a second, misleading event
        assert audits[0].user_id == admin.id
        row = db.query(BackupAgentServerKey).filter_by(status="active").one()
        assert row.public_key not in (audits[0].detail or "")
        assert row.wrapped_private_key not in (audits[0].detail or "") + (audits[0].metadata_json or "")


def test_provisioning_rejects_missing_or_non_docker_agent_host():
    with database() as db:
        admin = actor(db)
        proxmox_host = ComputeHost(name="Proxmox", platform="proxmox", base_url="https://pve.example.invalid", is_enabled=True)
        db.add(proxmox_host)
        db.commit()

        with pytest.raises(HTTPException) as missing:
            backup_agent_v2.provision_agent_server_key(post_request(), host_id=999999, csrf_token="csrf", db=db, user=admin)
        assert missing.value.status_code == 404

        with pytest.raises(HTTPException) as wrong_platform:
            backup_agent_v2.provision_agent_server_key(post_request(), host_id=proxmox_host.id, csrf_token="csrf", db=db, user=admin)
        assert wrong_platform.value.status_code == 404
        assert db.query(BackupAgentServerKey).count() == 0


# ---------------------------------------------------------------------------
# End-to-end: registration succeeds once the prerequisite is met.
# ---------------------------------------------------------------------------


def _json_request(payload: dict, *, path="/api/agent/v2/register"):
    import json as json_module

    body = json_module.dumps(payload).encode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http", "method": "POST", "path": path, "raw_path": path.encode(),
            "query_string": b"", "headers": [(b"content-type", b"application/json")],
            "client": ("198.51.100.2", 1234),
        },
        receive,
    )


def test_protocol_v2_registration_succeeds_after_provisioning():
    import asyncio

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    with database() as db:
        admin = actor(db)
        host = docker_host(db)
        db.commit()

        # Before provisioning, registration must still fail closed with 503.
        token_before = issue_bootstrap(db, host.id, admin.id)
        db.commit()
        signing = Ed25519PrivateKey.generate()
        envelope = X25519PrivateKey.generate()
        signing_public = b64u(signing.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        envelope_public = b64u(envelope.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        with pytest.raises(HTTPException) as before:
            asyncio.run(backup_agent_v2.register(
                _json_request({
                    "bootstrap_token": token_before,
                    "signing_public_key": signing_public,
                    "envelope_public_key": envelope_public,
                }),
                db,
            ))
        assert before.value.status_code == 503

        # Provision the prerequisite via the newly-wired admin action.
        backup_agent_v2.provision_agent_server_key(post_request(), host_id=host.id, csrf_token="csrf", db=db, user=admin)

        # A fresh bootstrap (the earlier one was not consumed by the 503) now registers successfully.
        token_after = issue_bootstrap(db, host.id, admin.id)
        db.commit()
        result = asyncio.run(backup_agent_v2.register(
            _json_request({
                "bootstrap_token": token_after,
                "signing_public_key": signing_public,
                "envelope_public_key": envelope_public,
            }),
            db,
        ))
        assert "agent_id" in result
        assert result["server_signing_keys"][0]["key_id"]
