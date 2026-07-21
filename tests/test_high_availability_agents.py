import asyncio
import base64
import hashlib
import json
import time
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.db.session import Base
from app.models.models import HAAgentCredential, HAAgentRequest, HACluster, HAEvent, HANode
from app.schemas.high_availability import HAAgentEventItem, HAAgentHeartbeat, HAAgentRegister
from app.services.ha_agents import HAAgentError, authenticate_agent_request, create_bootstrap_token, desired_state, ingest_events, record_heartbeat, register_agent, revoke_agent
from app.services.ha_clusters import soft_delete_cluster
from ha_agent.kaya_ha_agent import State, reconcile_desired


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def cluster_with_nodes(db: Session):
    cluster = HACluster(name="DNS HA", provider_key="pihole", virtual_ip="192.0.2.30", prefix_length=24)
    db.add(cluster)
    db.flush()
    primary = HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="https://one.invalid", role="ACTIVE", desired_role="ACTIVE")
    standby = HANode(cluster_id=cluster.id, display_name="Standby", api_base_url="https://two.invalid", role="STANDBY", desired_role="STANDBY")
    db.add_all([primary, standby])
    db.commit()
    return cluster, primary, standby


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def registration_payload(cluster, node, token, key, version="0.1.0"):
    public_key = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return HAAgentRegister(cluster_id=cluster.public_id, node_id=node.public_id, bootstrap_token=token, public_key=encoded(public_key), agent_version=version)


def signed_request(agent_id, key, path, payload, request_id="request-0001", timestamp=None):
    body = json.dumps(payload, separators=(",", ":")).encode()
    timestamp = str(timestamp if timestamp is not None else int(time.time()))
    canonical = "\n".join(("POST", path, request_id, timestamp, hashlib.sha256(body).hexdigest())).encode()
    headers = {
        "content-type": "application/json",
        "x-kaya-agent-id": agent_id,
        "x-kaya-agent-timestamp": timestamp,
        "x-kaya-agent-request-id": request_id,
        "x-kaya-agent-signature": encoded(key.sign(canonical)),
        "x-kaya-agent-protocol": "1",
    }
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({"type": "http", "method": "POST", "scheme": "https", "path": path, "raw_path": path.encode(), "query_string": b"", "headers": [(key.encode(), value.encode()) for key, value in headers.items()], "client": ("192.0.2.10", 1000), "server": ("kaya.invalid", 443)}, receive)


def test_one_time_bootstrap_is_node_bound_hashed_and_supports_rotation():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        credential, token = create_bootstrap_token(db, primary)
        assert credential.bootstrap_token_hash != token
        assert token not in credential.bootstrap_token_hash
        key = Ed25519PrivateKey.generate()
        registered, node = register_agent(db, registration_payload(cluster, primary, token, key))
        assert registered.agent_id == primary.public_id == node.agent_id
        assert registered.bootstrap_token_hash is None
        with pytest.raises(HAAgentError):
            register_agent(db, registration_payload(cluster, primary, token, key))

        credential, rotation_token = create_bootstrap_token(db, primary)
        replacement_key = Ed25519PrivateKey.generate()
        rotated, _ = register_agent(db, registration_payload(cluster, primary, rotation_token, replacement_key, "0.2.0"))
        assert rotated.agent_id == primary.public_id
        assert rotated.last_rotated_at is not None
        assert primary.agent_version == "0.2.0"

        _, standby_token = create_bootstrap_token(db, standby)
        with pytest.raises(HAAgentError):
            register_agent(db, registration_payload(cluster, primary, standby_token, key))
        with pytest.raises(HAAgentError, match="already bound"):
            register_agent(db, registration_payload(cluster, standby, standby_token, replacement_key))


def test_signed_requests_expire_reject_replay_and_stop_after_revocation():
    with database() as db:
        cluster, primary, _ = cluster_with_nodes(db)
        credential, token = create_bootstrap_token(db, primary)
        key = Ed25519PrivateKey.generate()
        register_agent(db, registration_payload(cluster, primary, token, key))
        payload = {"observed_role": "ACTIVE"}
        accepted = asyncio.run(authenticate_agent_request(signed_request(credential.agent_id, key, "/api/ha/agent/v1/heartbeat", payload), db))
        assert accepted.node.id == primary.id
        assert db.query(HAAgentRequest).count() == 1

        with pytest.raises(HTTPException) as replay:
            asyncio.run(authenticate_agent_request(signed_request(credential.agent_id, key, "/api/ha/agent/v1/heartbeat", payload), db))
        assert replay.value.status_code == 409
        with pytest.raises(HTTPException) as expired:
            asyncio.run(authenticate_agent_request(signed_request(credential.agent_id, key, "/api/ha/agent/v1/heartbeat", payload, "request-old", int(time.time()) - 600), db))
        assert expired.value.status_code == 401
        wrong_key = Ed25519PrivateKey.generate()
        with pytest.raises(HTTPException) as forged:
            asyncio.run(authenticate_agent_request(signed_request(credential.agent_id, wrong_key, "/api/ha/agent/v1/heartbeat", payload, "request-forged"), db))
        assert forged.value.status_code == 401
        revoke_agent(db, primary)
        with pytest.raises(HTTPException) as revoked:
            asyncio.run(authenticate_agent_request(signed_request(credential.agent_id, key, "/api/ha/agent/v1/heartbeat", payload, "request-revoked"), db))
        assert revoked.value.status_code == 401


def test_heartbeat_tracks_divergence_and_desired_state_has_no_commands():
    with database() as db:
        cluster, _, standby = cluster_with_nodes(db)
        cluster.cluster_generation = 7
        cluster.role_generation = 3
        db.commit()
        heartbeat = HAAgentHeartbeat(observed_role="ACTIVE", observed_generation=5, vip_owned=True, dhcp_running=False, dns_healthy=True, peer_reachable=True, lease_generation=9, config_generation=4, agent_version="0.1.0")
        record_heartbeat(db, standby, heartbeat)
        state = desired_state(standby)
        assert standby.observed_role == "ACTIVE"
        assert standby.observed_generation != state["cluster_generation"]
        assert state["desired_role"] == "STANDBY"
        assert state["automatic_failover"] is False
        assert state["allowed_actions"] == []


def test_desired_state_supplies_offline_failover_safety_context():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.automatic_failover_enabled = True
        cluster.maintenance_mode = False
        primary.management_host = "192.0.2.20"
        standby.management_host = "192.0.2.21"
        standby.network_interface = "eth0"
        db.commit()
        state = desired_state(standby)
        assert state["automatic_failover"] is True
        assert state["automatic_failback"] is False
        assert state["peer_host"] == "192.0.2.20"
        assert state["network_interface"] == "eth0"
        assert state["automatic_hold_down_seconds"] >= 5


def test_agent_events_are_deduplicated_and_sensitive_details_are_removed():
    with database() as db:
        _, primary, _ = cluster_with_nodes(db)
        item = HAAgentEventItem(event_id="event-123456", event_type="kaya_reconnected", severity="info", message="Connection restored", occurred_at=datetime.utcnow(), details={"attempt": 3, "api_token": "must-not-persist"})
        assert ingest_events(db, primary, [item]) == (1, 0)
        assert ingest_events(db, primary, [item]) == (0, 1)
        row = db.query(HAEvent).one()
        assert "must-not-persist" not in (row.details_json_redacted or "")
        assert json.loads(row.details_json_redacted) == {"attempt": 3}


def test_local_event_queue_survives_restart_and_rejects_stale_desired_state(tmp_path):
    first = State(tmp_path)
    event_id = first.queue_event("offline_event", "warning", "Kaya was unavailable")
    first.set("last_valid_cluster_generation", 8)
    first.db.close()
    second = State(tmp_path)
    assert second.queued_events()[0]["event_id"] == event_id
    reconcile_desired(second, {"cluster_generation": 7, "desired_role": "ACTIVE"})
    assert second.get("last_valid_cluster_generation") == 8
    assert any(item["event_type"] == "stale_generation_rejected" for item in second.queued_events())
    second.db.close()


def test_agent_routes_expose_only_fixed_protocol_operations():
    from app.routers.ha_agent_api import router

    paths = {route.path for route in router.routes}
    assert paths == {"/api/ha/agent/v1/install.sh", "/api/ha/agent/v1/files/{name}", "/api/ha/agent/v1/register", "/api/ha/agent/v1/heartbeat", "/api/ha/agent/v1/events", "/api/ha/agent/v1/desired-state", "/api/ha/agent/v1/lease-snapshot/{generation}", "/api/ha/agent/v1/action-result"}
    assert not any("command" in path or "shell" in path for path in paths)
    template = open("app/templates/high_availability_cluster_agents.html", encoding="utf-8").read()
    assert "one-time token" in template
    assert "Copy command" in template
    assert "input is hidden" in template
    assert "Revoke Agent" in template


def test_guided_installer_is_fixed_checksum_verified_and_keeps_token_off_command_line():
    from fastapi import HTTPException

    from app.routers.ha_agent_api import install_file, install_script
    from app.services.ha_agent_installer import agent_file, installer_checksum

    installer = agent_file("install.sh").decode()
    service = agent_file("kaya-ha-agent.service").decode()
    assert len(installer_checksum()) == 64
    assert "--token-stdin" in installer
    assert 'read -r REGISTRATION_TOKEN </dev/tty' in installer
    assert "apt-get install -y --no-install-recommends" in installer
    assert "visudo -cf" in installer
    assert "curl -k" not in installer and "--insecure" not in installer
    assert "NoNewPrivileges=true" not in service
    assert "ReadWritePaths=/var/lib/kaya-ha-agent /etc/keepalived" in service
    assert b"apt-get install" in install_script().body
    assert b"Ed25519PrivateKey" in install_file("kaya_ha_agent.py").body
    with pytest.raises(HTTPException) as missing:
        install_file("../../etc/passwd")
    assert missing.value.status_code == 404
    with pytest.raises(FileNotFoundError):
        agent_file("../../etc/passwd")


def test_soft_deleted_cluster_preserves_and_revokes_agent_identity():
    with database() as db:
        cluster, primary, _ = cluster_with_nodes(db)
        credential, token = create_bootstrap_token(db, primary)
        key = Ed25519PrivateKey.generate()
        register_agent(db, registration_payload(cluster, primary, token, key))
        credential_id = credential.id
        soft_delete_cluster(db, cluster, cluster.name, True)
        preserved = db.get(HAAgentCredential, credential_id)
        assert preserved is not None
        assert preserved.revoked_at is not None
        assert preserved.public_key is not None
