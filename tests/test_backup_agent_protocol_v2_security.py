import asyncio
import json
import time
import uuid
import sys
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.db.session import Base
from app.core.security import encrypt_secret
from app.models.models import BackupAgentBootstrap, BackupAgentIdentity, BackupAgentKey, BackupAgentMigrationWindow, BackupJob, ComputeHost, ComputeWorkload, RemoteManagerSetting
from app.routers.backup_agent_v2 import claim, offers
from app.services.backup_agent_protocol import (
    authenticate_request,
    allow_legacy_inventory,
    b64u,
    canonical_json,
    canonical_request,
    issue_bootstrap,
    register_identity,
    create_server_signing_key,
)

AGENT_ROOT = Path(__file__).parents[1] / "external/Kaya-Docker-Agent"
if AGENT_ROOT.exists():
    sys.path.insert(0, str(AGENT_ROOT))
    from protocol_v2 import ProtocolV2Client  # noqa: E402
else:
    ProtocolV2Client = None


@contextmanager
def database():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def public(key) -> str:
    return b64u(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def signed_request(private, identity_id, key_id, *, method="POST", body=None, path="/api/agent/v2/checkin", timestamp=None, request_id=None, signed_path=None, signed_body=None):
    payload = canonical_json(body) if body is not None else b""
    signed_payload = canonical_json(signed_body) if signed_body is not None else payload
    timestamp = int(time.time()) if timestamp is None else timestamp
    request_id = request_id or str(uuid.uuid4())
    signature = b64u(private.sign(canonical_request(method, signed_path or path, "", identity_id, key_id, request_id, timestamp, signed_payload)))
    headers = [(b"content-type", b"application/json"), (b"x-kaya-agent-protocol", b"2"), (b"x-kaya-agent-id", identity_id.encode()), (b"x-kaya-agent-key-id", key_id.encode()), (b"x-kaya-agent-timestamp", str(timestamp).encode()), (b"x-kaya-agent-request-id", request_id.encode()), (b"x-kaya-agent-signature", signature.encode())]
    sent = False
    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": payload, "more_body": False}
    return Request({"type": "http", "method": method, "path": path, "raw_path": path.encode(), "query_string": b"", "headers": headers, "client": ("127.0.0.1", 1)}, receive)


def enrolled(db, *, state="active", enabled=True, scopes=None):
    signing = Ed25519PrivateKey.generate()
    envelope = X25519PrivateKey.generate()
    host = ComputeHost(name=f"Synthetic {uuid.uuid4()}", platform="docker_agent", base_url="agent://synthetic", is_enabled=enabled)
    db.add(host)
    db.flush()
    identity = BackupAgentIdentity(host_id=host.id, state=state, scopes_json=json.dumps(scopes or ["inventory:write"]), envelope_public_key=public(envelope), activated_at=datetime.utcnow())
    db.add(identity)
    db.flush()
    key = BackupAgentKey(identity_id=identity.id, key_id=str(uuid.uuid4()), signing_public_key=public(signing), status="active")
    db.add(key)
    db.commit()
    return host, identity, key, signing


def test_enrolment_is_host_bound_single_use_and_rejects_expired_or_duplicate_keys():
    with database() as db:
        host = ComputeHost(name="Enrollment host", platform="docker_agent", base_url="agent://enrollment")
        other = ComputeHost(name="Other host", platform="docker_agent", base_url="agent://other")
        db.add_all([host, other])
        db.flush()
        signing, envelope = Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
        token = issue_bootstrap(db, host.id, None)
        identity, _ = register_identity(db, token, public(signing), public(envelope))
        assert identity.host_id == host.id
        with pytest.raises(HTTPException) as reused:
            register_identity(db, token, public(Ed25519PrivateKey.generate()), public(X25519PrivateKey.generate()))
        assert reused.value.status_code == 401
        expired = issue_bootstrap(db, other.id, None)
        db.query(BackupAgentBootstrap).filter_by(host_id=other.id).update({"expires_at": datetime.utcnow() - timedelta(seconds=1)})
        with pytest.raises(HTTPException) as rejected:
            register_identity(db, expired, public(Ed25519PrivateKey.generate()), public(X25519PrivateKey.generate()))
        assert rejected.value.status_code == 401


def test_signed_authentication_is_durable_replay_protected_and_body_bound():
    with database() as db:
        _, identity, key, private = enrolled(db)
        request_id = str(uuid.uuid4())
        request = signed_request(private, identity.id, key.key_id, body={"value": 1}, request_id=request_id)
        authenticated, _ = asyncio.run(authenticate_request(request, db, "inventory:write"))
        assert authenticated.identity.id == identity.id
        db.commit()
        with pytest.raises(HTTPException) as replayed:
            asyncio.run(authenticate_request(signed_request(private, identity.id, key.key_id, body={"value": 1}, request_id=request_id), db, "inventory:write"))
        assert replayed.value.status_code == 409
        with pytest.raises(HTTPException) as changed:
            asyncio.run(authenticate_request(signed_request(private, identity.id, key.key_id, body={"value": 2}, signed_body={"value": 1}), db, "inventory:write"))
        assert changed.value.status_code == 401


@pytest.mark.parametrize("offset", [-301, 301])
def test_stale_and_future_requests_are_rejected(offset):
    with database() as db:
        _, identity, key, private = enrolled(db)
        with pytest.raises(HTTPException) as rejected:
            asyncio.run(authenticate_request(signed_request(private, identity.id, key.key_id, timestamp=int(time.time()) + offset), db, "inventory:write"))
        assert rejected.value.status_code == 401


def test_wrong_path_scope_revoked_decommissioned_and_disabled_agents_fail_closed():
    with database() as db:
        host, identity, key, private = enrolled(db)
        with pytest.raises(HTTPException) as path_rejected:
            asyncio.run(authenticate_request(signed_request(private, identity.id, key.key_id, signed_path="/api/agent/v2/other"), db, "inventory:write"))
        assert path_rejected.value.status_code == 401
        with pytest.raises(HTTPException) as scope_rejected:
            asyncio.run(authenticate_request(signed_request(private, identity.id, key.key_id), db, "backup:claim"))
        assert scope_rejected.value.status_code == 403
        for state in ("revoked", "decommissioned"):
            identity.state = state
            db.commit()
            with pytest.raises(HTTPException) as state_rejected:
                asyncio.run(authenticate_request(signed_request(private, identity.id, key.key_id), db, "inventory:write"))
            assert state_rejected.value.status_code == 401
        identity.state = "active"
        host.is_enabled = False
        db.commit()
        with pytest.raises(HTTPException) as disabled:
            asyncio.run(authenticate_request(signed_request(private, identity.id, key.key_id), db, "inventory:write"))
        assert disabled.value.status_code == 403


@pytest.mark.skipif(ProtocolV2Client is None, reason="genuine Kaya-Docker-Agent checkout is not present")
def test_server_agent_offer_claim_interoperability_and_idempotent_retry():
    with database() as db:
        signing, envelope_private = Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
        host = ComputeHost(name="Integrated agent", platform="docker_agent", base_url="agent://integrated", is_enabled=True)
        db.add(host)
        db.flush()
        workload = ComputeWorkload(host_id=host.id, external_id="synthetic-container", name="synthetic-container", kind="container")
        db.add(workload)
        db.flush()
        target = [{"name": "Synthetic", "type": "smb", "remote_host": "backup.example.invalid", "remote_share": "fake-share", "remote_username": "fake-user", "remote_password_enc": encrypt_secret("fake-password"), "path": ""}]
        db.add(RemoteManagerSetting(key="backup_targets_json", value=json.dumps(target)))
        job = BackupJob(host_id=host.id, workload_id=workload.id, operation="backup", status="queued", encrypted_backup_key=encrypt_secret("fake-data-key"), metadata_json=json.dumps({"target_name": "Synthetic", "policy": "full"}))
        db.add(job)
        identity = BackupAgentIdentity(host_id=host.id, state="active", scopes_json=json.dumps(["inventory:write", "backup:poll", "backup:claim", "backup:status"]), envelope_public_key=public(envelope_private), activated_at=datetime.utcnow())
        db.add(identity)
        db.flush()
        key = BackupAgentKey(identity_id=identity.id, key_id=str(uuid.uuid4()), signing_public_key=public(signing), status="active")
        db.add(key)
        server_key = create_server_signing_key(db)
        db.commit()
        offered = asyncio.run(offers(signed_request(signing, identity.id, key.key_id, method="GET", path="/api/agent/v2/backup/offers"), db))
        assert list(offered["offers"][0]) == ["dispatch_id", "manifest"]
        assert "fake-password" not in json.dumps(offered)
        dispatch_id = offered["offers"][0]["dispatch_id"]
        claim_id = str(uuid.uuid4())
        path = f"/api/agent/v2/backup/dispatches/{dispatch_id}/claim"
        envelope = asyncio.run(claim(dispatch_id, signed_request(signing, identity.id, key.key_id, body={"claim_id": claim_id}, path=path), db))
        encoded = json.dumps(envelope)
        assert "fake-password" not in encoded and "fake-data-key" not in encoded
        client = ProtocolV2Client.__new__(ProtocolV2Client)
        client.state = {"agent_id": identity.id, "envelope_private_key": b64u(envelope_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())), "server_signing_keys": {server_key.key_id: server_key.public_key}}
        secret = client.open_envelope(envelope, dispatch_id, claim_id)
        assert secret["target"]["remote_password"] == "fake-password"
        assert secret["encryption"]["data_key"] == "fake-data-key"
        retried = asyncio.run(claim(dispatch_id, signed_request(signing, identity.id, key.key_id, body={"claim_id": claim_id}, path=path), db))
        assert retried == envelope
        with pytest.raises(HTTPException) as conflict:
            asyncio.run(claim(dispatch_id, signed_request(signing, identity.id, key.key_id, body={"claim_id": str(uuid.uuid4())}, path=path), db))
        assert conflict.value.status_code == 409


def test_protocol_v1_window_is_fixed_and_cutoff_clears_legacy_hashes():
    with database() as db:
        host = ComputeHost(name="Legacy agent", platform="docker_agent", base_url="agent://legacy", agent_token_hash="0" * 64)
        db.add(host)
        db.flush()
        assert allow_legacy_inventory(db) is True
        window = db.get(BackupAgentMigrationWindow, 1)
        original_start = window.started_at
        window.cutoff_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
        assert allow_legacy_inventory(db) is False
        db.refresh(host)
        assert host.agent_token_hash is None
        assert window.started_at == original_start
