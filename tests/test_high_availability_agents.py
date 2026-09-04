import asyncio
import base64
import hashlib
import json
from types import SimpleNamespace
import time
from datetime import datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request

from app.db.session import Base
from app.models.models import HAAgentCredential, HAAgentRequest, HACluster, HAEvent, HALeaseReplicationState, HANode, NotificationEvent
from app.schemas.high_availability import HAAgentActionResult, HAAgentEventItem, HAAgentHeartbeat, HAAgentRegister
from app.services.ha_agents import HAAgentError, authenticate_agent_request, create_bootstrap_token, desired_state, ingest_events, prune_agent_request_history, reconcile_vip_ownership, record_action_result, record_heartbeat, register_agent, revoke_agent
import app.services.ha_agents as ha_agents
from app.services.ha_clusters import soft_delete_cluster
from app.services.notification_outbox import process_outbox
from app.services.ha_topology import reconcile_topology
from ha_agent.kaya_ha_agent import AgentRequestError, ICMP_AVAILABLE, ICMP_NO_REPLY, ICMP_UNAVAILABLE, State, probe_icmp, reconcile_desired


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


def test_agent_replay_retention_is_explicit_maintenance():
    with database() as db:
        cluster, primary, _ = cluster_with_nodes(db)
        credential, token = create_bootstrap_token(db, primary)
        key = Ed25519PrivateKey.generate()
        register_agent(db, registration_payload(cluster, primary, token, key))
        old = HAAgentRequest(
            credential_id=credential.id,
            request_id="synthetic-expired-request",
            request_timestamp=datetime.utcnow() - timedelta(days=2),
            received_at=datetime.utcnow() - timedelta(days=2),
        )
        db.add(old)
        db.commit()

        assert prune_agent_request_history(db) == 1
        db.commit()
        assert db.query(HAAgentRequest).count() == 0


def test_rejected_agent_report_logs_reason_without_signature_or_payload(caplog):
    with database() as db:
        cluster, primary, _ = cluster_with_nodes(db)
        credential, token = create_bootstrap_token(db, primary)
        registered_key = Ed25519PrivateKey.generate()
        register_agent(db, registration_payload(cluster, primary, token, registered_key))
        forged_key = Ed25519PrivateKey.generate()
        payload = {"observed_role": "ACTIVE", "sensitive_marker": "must-not-appear-in-log"}
        caplog.set_level("WARNING", logger="app.services.ha_agents")

        with pytest.raises(HTTPException) as rejected:
            asyncio.run(authenticate_agent_request(signed_request(credential.agent_id, forged_key, "/api/ha/agent/v1/heartbeat", payload, "request-safe-log"), db))

        assert rejected.value.status_code == 401
        assert "reason=signature_invalid" in caplog.text
        assert "must-not-appear-in-log" not in caplog.text
        assert "x-kaya-agent-signature" not in caplog.text.lower()


def test_heartbeat_tracks_divergence_and_desired_state_has_no_commands():
    with database() as db:
        cluster, _, standby = cluster_with_nodes(db)
        cluster.cluster_generation = 7
        cluster.role_generation = 3
        db.commit()
        heartbeat = HAAgentHeartbeat(observed_role="ACTIVE", observed_generation=5, vip_owned=True, dhcp_running=False, dns_healthy=True, peer_reachable=False, peer_dns_reachable=True, lease_generation=9, config_generation=4, agent_version="0.2.4")
        record_heartbeat(db, standby, heartbeat)
        state = desired_state(standby)
        assert standby.observed_role == "ACTIVE"
        assert standby.observed_generation != state["cluster_generation"]
        assert standby.peer_reachable is False
        assert standby.peer_dns_reachable is True
        assert standby.last_peer_attempt_at is not None
        assert standby.last_peer_dns_success_at is not None
        assert state["desired_role"] == "STANDBY"
        assert state["automatic_failover"] is False
        assert state["allowed_actions"] == []


def test_steady_state_heartbeat_skips_full_reconciliation(monkeypatch):
    with database() as db:
        cluster, _, node = cluster_with_nodes(db)
        now = datetime.utcnow()
        cluster.status = "HEALTHY"
        node.last_heartbeat_at = now
        node.agent_version = "0.2.7"
        node.observed_role = "STANDBY"
        node.observed_generation = 1
        node.vip_owned = False
        node.dhcp_running = False
        node.dhcp_configured = False
        node.dhcp_listener_active = False
        node.ftl_active = True
        node.dhcp_observation_status = "FRESH"
        node.dhcp_runtime_state = "STOPPED"
        node.dns_healthy = True
        node.peer_reachable = True
        node.peer_icmp_probe_status = "AVAILABLE"
        node.peer_dns_reachable = True
        node.lease_generation = 0
        node.config_generation = 1
        node.keepalived_runtime_state = "RUNNING"
        db.commit()
        heartbeat = HAAgentHeartbeat(
            observed_role="STANDBY", observed_generation=1, vip_owned=False,
            dhcp_running=False, dhcp_configured=False, dhcp_listener_active=False,
            ftl_active=True, dhcp_observation_status="FRESH", dhcp_runtime_state="STOPPED",
            dns_healthy=True, peer_reachable=True, peer_icmp_probe_status="AVAILABLE",
            peer_dns_reachable=True, lease_generation=0, config_generation=1,
            agent_version="0.2.7", keepalived_runtime_state="RUNNING",
        )
        monkeypatch.setattr(ha_agents, "reconcile_vip_ownership", lambda *args, **kwargs: pytest.fail("steady heartbeat reconciled"))
        record_heartbeat(db, node, heartbeat)


def test_peer_dependent_host_resolver_is_reported_and_repair_is_generation_bound():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        primary.management_host = "192.0.2.10"
        standby.management_host = "192.0.2.11"
        standby.network_interface = "eth0"
        db.commit()
        heartbeat = HAAgentHeartbeat(
            report_sequence=1,
            observed_role="STANDBY",
            observed_generation=1,
            vip_owned=False,
            dhcp_running=False,
            dns_healthy=True,
            resolver_manager="SYSTEMD_RESOLVED",
            resolver_nameservers=["192.0.2.10"],
            resolver_observation_status="FRESH",
            agent_version="0.2.12",
        )
        record_heartbeat(db, standby, heartbeat)
        event = db.query(HAEvent).filter(HAEvent.event_type == "host_resolver_peer_dependent").one()
        assert event.severity == "critical"
        assert "Host resolver depends on peer node" in event.message
        assert "192.0.2.10" not in event.details_json_redacted

        standby.resolver_repair_generation = 1
        standby.resolver_repair_status = "PENDING"
        db.commit()
        action = desired_state(standby)["resolver_repair"]
        assert action["action_type"] == "RESOLVER_REPAIR"
        assert action["virtual_ip"] == cluster.virtual_ip
        assert action["network_interface"] == "eth0"
        assert "RESOLVER_REPAIR" in desired_state(standby)["allowed_actions"]

        record_action_result(db, standby, HAAgentActionResult(
            action_id=action["action_id"],
            action_type="RESOLVER_REPAIR",
            generation=1,
            status="APPLIED",
            checksum=action["checksum"],
            backup_reference="a" * 24,
            message="Host resolver verified.",
        ))
        assert standby.resolver_repair_status == "APPLIED"
        assert desired_state(standby)["resolver_repair"] is None


def test_unavailable_dhcp_observation_does_not_become_stopped():
    with database() as db:
        _, primary, _ = cluster_with_nodes(db)
        primary.dhcp_running = True
        primary.dhcp_configured = True
        primary.dhcp_listener_active = True
        primary.ftl_active = True
        primary.dhcp_runtime_state = "RUNNING"
        primary.dhcp_observation_status = "FRESH"
        db.commit()

        record_heartbeat(
            db,
            primary,
            HAAgentHeartbeat(
                    report_sequence=1,
                    observed_role="ACTIVE",
                    observed_generation=0,
                vip_owned=True,
                dhcp_running=False,
                dhcp_runtime_state="UNKNOWN",
                dhcp_observation_status="UNAVAILABLE",
                dns_healthy=True,
                agent_version="0.2.7",
            ),
        )

        assert primary.dhcp_running is True
        assert primary.dhcp_runtime_state == "UNKNOWN"
        assert primary.dhcp_observation_status == "UNAVAILABLE"
        assert primary.dhcp_configured is None
        assert primary.dhcp_listener_active is None


def test_out_of_order_heartbeat_cannot_replace_newer_runtime_truth():
    with database() as db:
        _, primary, _ = cluster_with_nodes(db)
        current = HAAgentHeartbeat(
            report_sequence=2,
            observed_role="ACTIVE",
            observed_generation=0,
            vip_owned=True,
            dhcp_running=True,
            dhcp_configured=True,
            dhcp_listener_active=True,
            ftl_active=True,
            dhcp_runtime_state="RUNNING",
            dhcp_observation_status="FRESH",
            dns_healthy=True,
            agent_version="0.2.7",
        )
        stale = HAAgentHeartbeat(
            report_sequence=1,
            observed_role="STANDBY",
            observed_generation=0,
            vip_owned=False,
            dhcp_running=False,
            dhcp_configured=False,
            dhcp_listener_active=False,
            ftl_active=True,
            dhcp_runtime_state="STOPPED",
            dhcp_observation_status="FRESH",
            dns_healthy=False,
            agent_version="0.2.7",
        )

        record_heartbeat(db, primary, current)
        accepted_at = primary.last_heartbeat_at
        _, accepted, reason = record_heartbeat(db, primary, stale, return_status=True)

        assert accepted is False
        assert reason == "out_of_order"
        assert primary.last_report_sequence == 2
        assert primary.last_heartbeat_at == accepted_at
        assert primary.vip_owned is True
        assert primary.dhcp_runtime_state == "RUNNING"
        assert primary.dns_healthy is True


def test_stale_signed_identity_can_safely_rebase_a_lost_local_report_sequence():
    with database() as db:
        _, primary, _ = cluster_with_nodes(db)
        primary.last_report_sequence = 900
        primary.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=2)
        primary.last_agent_reported_at = datetime.utcnow() - timedelta(minutes=2)
        db.commit()

        heartbeat = HAAgentHeartbeat(
            report_sequence=1,
            reported_at=datetime.utcnow(),
            observed_role="ACTIVE",
            observed_generation=4,
            vip_owned=True,
            dhcp_running=True,
            dhcp_configured=True,
            dhcp_listener_active=True,
            ftl_active=True,
            dhcp_runtime_state="RUNNING",
            dhcp_observation_status="FRESH",
            dns_healthy=True,
            agent_version="0.2.9",
        )
        node, accepted, reason = record_heartbeat(db, primary, heartbeat, return_status=True)

        assert accepted is True
        assert reason == "sequence_rebased"
        assert node.last_report_sequence == 1
        assert node.last_heartbeat_at >= datetime.utcnow() - timedelta(seconds=2)
        assert node.vip_owned is True
        assert node.dns_healthy is True


def test_hard_peer_failure_keeps_service_health_separate_from_redundancy():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.deployment_mode = "DNS_DHCP"
        now = datetime.utcnow()
        primary.last_heartbeat_at = primary.dhcp_observed_at = now
        primary.vip_owned = True
        primary.dns_healthy = True
        primary.dhcp_running = primary.dhcp_configured = primary.dhcp_listener_active = primary.ftl_active = True
        primary.dhcp_runtime_state = "RUNNING"
        primary.dhcp_observation_status = "FRESH"
        standby.last_heartbeat_at = standby.dhcp_observed_at = now - timedelta(minutes=2)
        standby.vip_owned = False
        db.commit()

        topology = reconcile_topology(cluster, now=now)

        assert topology.service_availability == "HEALTHY"
        assert topology.redundancy_state == "REDUCED"
        assert topology.telemetry_state == "DEGRADED"


def test_icmp_transition_is_informational_and_does_not_degrade_cluster():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.status = "HEALTHY"
        cluster.deployment_mode = "DNS_ONLY"
        for node in (primary, standby):
            node.last_heartbeat_at = datetime.utcnow()
            node.dns_healthy = True
            node.keepalived_status = "DEPLOYED"
            node.keepalived_runtime_state = "RUNNING"
            node.agent_version = "0.2.4"
        primary.vip_owned = True
        primary.observed_role = "ACTIVE"
        standby.vip_owned = False
        standby.observed_role = "STANDBY"
        db.commit()

        common = dict(
            observed_role="ACTIVE",
            observed_generation=0,
            vip_owned=True,
            dhcp_running=False,
            dns_healthy=True,
            lease_generation=0,
            config_generation=0,
            agent_version="0.2.4",
            keepalived_runtime_state="RUNNING",
        )
        record_heartbeat(db, primary, HAAgentHeartbeat(**common, peer_reachable=True, peer_dns_reachable=True))
        record_heartbeat(db, primary, HAAgentHeartbeat(**common, peer_reachable=False, peer_dns_reachable=True))

        event_row = db.query(HAEvent).filter_by(event_type="peer_network_reachability_unavailable").one()
        assert event_row.severity == "info"
        assert cluster.status == "HEALTHY"

        record_heartbeat(
            db,
            primary,
            HAAgentHeartbeat(
                **common,
                peer_reachable=None,
                peer_icmp_probe_status="UNAVAILABLE",
                peer_dns_reachable=True,
            ),
        )
        assert primary.peer_reachable is None
        assert primary.peer_icmp_probe_status == "UNAVAILABLE"
        assert cluster.status == "HEALTHY"


def test_desired_state_supplies_offline_failover_safety_context():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.automatic_failover_enabled = True
        cluster.maintenance_mode = False
        primary.management_host = "192.0.2.20"
        standby.management_host = "192.0.2.21"
        standby.network_interface = "eth0"
        primary.agent_version = standby.agent_version = "0.2.7"
        db.commit()
        state = desired_state(standby)
        assert state["automatic_failover"] is True
        assert state["automatic_failback"] is False
        assert state["peer_host"] == "192.0.2.20"
        assert state["network_interface"] == "eth0"
        assert state["automatic_hold_down_seconds"] >= 5


def test_desired_state_disables_automatic_failover_for_unverified_agent_runtime():
    with database() as db:
        cluster, _, standby = cluster_with_nodes(db)
        cluster.automatic_failover_enabled = True
        standby.agent_version = "0.2.0"
        db.commit()

        assert desired_state(standby)["automatic_failover"] is False


def test_desired_state_keeps_automatic_failover_off_during_rolling_agent_update():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.automatic_failover_enabled = True
        primary.agent_version = "0.2.7"
        standby.agent_version = "0.2.6"
        db.commit()

        assert desired_state(primary)["automatic_failover"] is False
        assert desired_state(standby)["automatic_failover"] is False


def test_non_safety_agent_update_does_not_disable_automatic_failover():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.automatic_failover_enabled = True
        primary.agent_version = "0.2.7"
        standby.agent_version = "0.2.8"
        db.commit()

        assert desired_state(primary)["automatic_failover"] is True
        assert desired_state(standby)["automatic_failover"] is True


def test_agent_events_are_deduplicated_and_sensitive_details_are_removed():
    with database() as db:
        _, primary, _ = cluster_with_nodes(db)
        item = HAAgentEventItem(event_id="event-123456", event_type="kaya_reconnected", severity="info", message="Connection restored", occurred_at=datetime.utcnow(), details={"attempt": 3, "api_token": "must-not-persist"})
        assert ingest_events(db, primary, [item]) == (1, 0)
        assert ingest_events(db, primary, [item]) == (0, 1)
        row = db.query(HAEvent).one()
        assert "must-not-persist" not in (row.details_json_redacted or "")
        assert json.loads(row.details_json_redacted) == {"attempt": 3}


def test_verified_automatic_failover_event_immediately_adopts_the_surviving_owner():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.keepalived_status = "DEPLOYED"
        cluster.keepalived_generation = 8
        cluster.automatic_failover_enabled = True
        cluster.current_active_node_id = primary.id
        cluster.authoritative_node_id = primary.id
        cluster.status = "HEALTHY"
        for node in (primary, standby):
            node.keepalived_status = "DEPLOYED"
            node.keepalived_runtime_state = "RUNNING"
            node.config_generation = 8
            node.last_heartbeat_at = datetime.utcnow()
            node.dns_healthy = True
        primary.vip_owned = True
        db.commit()

        record_heartbeat(db, standby, HAAgentHeartbeat(observed_role="ACTIVE", observed_generation=8, vip_owned=True, dhcp_running=True, dhcp_configured=True, dhcp_listener_active=True, ftl_active=True, dhcp_runtime_state="RUNNING", dhcp_observation_status="FRESH", dns_healthy=True, peer_reachable=False, lease_generation=0, config_generation=8, agent_version="0.2.7", keepalived_runtime_state="RUNNING"))
        assert cluster.status == "DEGRADED"
        assert db.query(HAEvent).filter_by(event_type="ownership_transition_pending", severity="warning").one()
        assert db.query(HAEvent).filter_by(event_type="split_brain_detected").count() == 0

        completed = HAAgentEventItem(event_id="automatic-completed-001", event_type="automatic_failover_completed", severity="warning", message="Local failover completed without requiring Kaya.", occurred_at=datetime.utcnow(), details={"generation": 8, "automatic": True})
        assert ingest_events(db, standby, [completed]) == (1, 0)
        db.refresh(cluster)
        db.refresh(primary)
        db.refresh(standby)
        assert cluster.status == "DEGRADED"
        assert cluster.current_active_node_id == standby.id
        assert cluster.authoritative_node_id == standby.id
        assert standby.vip_owned is True and primary.vip_owned is False
        assert standby.role == standby.desired_role == "ACTIVE"
        assert primary.role == primary.desired_role == "STANDBY"
        reconciled = db.query(HAEvent).filter_by(event_type="ownership_reconciled").one()
        assert reconciled.severity == "info"
        assert db.query(HAEvent).filter_by(event_type="automatic_failover_completed").one()


def test_both_nodes_reporting_vip_confirms_split_brain_after_transition_window():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.keepalived_status = "DEPLOYED"
        cluster.keepalived_generation = 8
        cluster.automatic_failover_enabled = True
        cluster.current_active_node_id = primary.id
        cluster.status = "HEALTHY"
        for node in (primary, standby):
            node.keepalived_status = "DEPLOYED"
            node.keepalived_runtime_state = "RUNNING"
            node.config_generation = 8
            node.last_heartbeat_at = datetime.utcnow()
            node.dns_healthy = True
            node.vip_owned = True
        db.commit()

        record_heartbeat(db, standby, HAAgentHeartbeat(observed_role="ACTIVE", observed_generation=8, vip_owned=True, dhcp_running=False, dns_healthy=True, peer_reachable=False, lease_generation=0, config_generation=8, agent_version="0.2.3", keepalived_runtime_state="RUNNING"))
        record_heartbeat(db, primary, HAAgentHeartbeat(observed_role="ACTIVE", observed_generation=8, vip_owned=True, dhcp_running=True, dns_healthy=True, peer_reachable=True, lease_generation=0, config_generation=8, agent_version="0.2.3", keepalived_runtime_state="RUNNING"))

        assert cluster.status == "ERROR"
        assert db.query(HAEvent).filter_by(event_type="split_brain_detected", severity="critical").one()


def test_stale_cached_owner_recovers_on_the_next_surviving_heartbeat():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.keepalived_status = "DEPLOYED"
        cluster.keepalived_generation = 4
        cluster.automatic_failover_enabled = True
        cluster.status = "ERROR"
        cluster.current_active_node_id = None
        for node in (primary, standby):
            node.keepalived_status = "DEPLOYED"
            node.keepalived_runtime_state = "RUNNING"
            node.config_generation = 4
            node.dns_healthy = True
            node.vip_owned = True
        primary.last_heartbeat_at = datetime.utcnow() - timedelta(seconds=60)
        standby.last_heartbeat_at = datetime.utcnow()
        standby.observed_role = "ACTIVE"
        db.add(HAEvent(cluster_id=cluster.id, node_id=standby.id, event_type="automatic_failover_completed", severity="warning", source="agent", message="Local failover completed without requiring Kaya.", details_json_redacted='{"generation":4}', agent_event_id="historic-auto-001", occurred_at=datetime.utcnow()))
        db.add(HAEvent(cluster_id=cluster.id, event_type="split_brain_detected", severity="critical", source="kaya", message="Cached owners conflicted.", details_json_redacted="{}", occurred_at=datetime.utcnow()))
        db.commit()

        reconcile_vip_ownership(db, cluster)
        db.refresh(cluster)
        db.refresh(primary)
        assert cluster.status == "DEGRADED"
        assert cluster.current_active_node_id == standby.id
        assert primary.vip_owned is False
        assert db.query(HAEvent).filter_by(event_type="ownership_reconciled", severity="info").one()


def test_cluster_degraded_and_recovered_notifications_follow_verified_topology():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        now = datetime.utcnow()
        cluster.deployment_mode = "DNS_ONLY"
        cluster.status = "HEALTHY"
        cluster.keepalived_status = "DEPLOYED"
        cluster.keepalived_generation = 4
        cluster.current_active_node_id = cluster.authoritative_node_id = primary.id
        for node in (primary, standby):
            node.keepalived_status = "DEPLOYED"
            node.keepalived_runtime_state = "RUNNING"
            node.config_generation = 4
            node.dns_healthy = True
            node.vip_owned = node.id == primary.id
        primary.last_heartbeat_at = now
        standby.last_heartbeat_at = now - timedelta(minutes=5)
        db.commit()

        reconcile_vip_ownership(db, cluster)
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()
        degraded = db.query(NotificationEvent).filter_by(event_type="pihole.cluster.degraded").one()
        assert cluster.status == "DEGRADED"
        assert degraded.resolved_at is None

        standby.last_heartbeat_at = datetime.utcnow()
        db.commit()
        reconcile_vip_ownership(db, cluster)
        process_outbox(session_factory=sessionmaker(bind=db.bind))
        db.expire_all()
        db.refresh(degraded)
        assert cluster.status == "HEALTHY"
        assert degraded.resolved_at is not None
        assert db.query(NotificationEvent).filter_by(event_type="pihole.cluster.recovered").one()


def test_completed_managed_failover_adopts_active_node_despite_stale_peer_dhcp_cache():
    with database() as db:
        cluster, primary, standby = cluster_with_nodes(db)
        cluster.keepalived_status = "DEPLOYED"
        cluster.keepalived_generation = 6
        cluster.automatic_failover_enabled = True
        cluster.status = "DEGRADED"
        cluster.current_active_node_id = standby.id
        cluster.authoritative_node_id = primary.id
        db.add(HALeaseReplicationState(cluster_id=cluster.id, source_node_id=primary.id, target_node_id=standby.id, status="CURRENT"))
        for node in (primary, standby):
            node.keepalived_status = "DEPLOYED"
            node.keepalived_runtime_state = "RUNNING"
            node.config_generation = 6
            node.dns_healthy = True
            node.vip_owned = True
            node.dhcp_running = True
            node.dhcp_configured = True
            node.dhcp_listener_active = True
            node.ftl_active = True
            node.dhcp_runtime_state = "RUNNING"
            node.dhcp_observation_status = "FRESH"
            node.dhcp_observed_at = datetime.utcnow()
        primary.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=6)
        standby.last_heartbeat_at = datetime.utcnow()
        standby.observed_role = "ACTIVE"
        db.add(HAEvent(cluster_id=cluster.id, node_id=standby.id, event_type="automatic_failover_completed", severity="warning", source="agent", message="Local failover completed without requiring Kaya.", details_json_redacted='{"automatic":true,"generation":6}', agent_event_id="managed-auto-001", occurred_at=datetime.utcnow()))
        db.commit()

        reconcile_vip_ownership(db, cluster)
        db.refresh(cluster)
        db.refresh(primary)
        db.refresh(standby)
        assert cluster.status == "DEGRADED"
        assert cluster.current_active_node_id == standby.id
        assert cluster.authoritative_node_id == standby.id
        assert standby.role == standby.desired_role == "ACTIVE"
        assert primary.role == primary.desired_role == "STANDBY"
        assert standby.vip_owned is True and primary.vip_owned is False


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


def test_desired_state_acknowledges_role_generation_without_regressing_markers(tmp_path):
    state = State(tmp_path)
    state.set("last_valid_cluster_generation", 8)
    state.set("observed_generation", 8)
    state.set("role_generation", 8)

    reconcile_desired(
        state,
        {"cluster_generation": 8, "role_generation": 9, "desired_role": "STANDBY"},
    )

    assert state.get("last_valid_cluster_generation") == 8
    assert state.get("observed_generation") == 9
    assert state.get("role_generation") == 9

    reconcile_desired(
        state,
        {"cluster_generation": 8, "role_generation": 8, "desired_role": "STANDBY"},
    )

    assert state.get("observed_generation") == 9
    assert state.get("role_generation") == 9
    state.db.close()


def test_identical_dhcp_repair_desired_state_executes_once_until_result_is_delivered(tmp_path):
    state = State(tmp_path)
    state.set("vip_owned", True)
    state.set("observed_role", "ACTIVE")
    calls = []
    desired = {
        "cluster_generation": 4,
        "desired_role": "ACTIVE",
        "role_generation": 2,
        "automatic_failover": False,
        "maintenance_mode": True,
        "dhcp_managed": True,
        "automatic_hold_down_seconds": 10,
        "keepalived": None,
        "lease_snapshot": None,
        "failover": {
            "action_id": "maintenance:fake:dhcp_promote:node",
            "action_type": "DHCP_PROMOTE",
            "generation": 2,
            "checksum": "a" * 64,
            "automatic": False,
            "lease_generation": 7,
            "restore_original": False,
            "configuration_only": True,
        },
    }

    def runner(command):
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "status": "applied",
                "configured": True,
                "service_active": True,
                "listening": True,
                "runtime_state": "RUNNING",
                "observation_status": "FRESH",
                "dhcp_running": True,
            }),
            stderr="",
        )

    reconcile_desired(state, desired, helper_runner=runner)
    reconcile_desired(state, desired, helper_runner=runner)

    assert len(calls) == 1
    assert state.get("failover_configuration_only") is True
    assert state.get("pending_failover_action_result")["status"] == "APPLIED"
    state.db.close()


def test_rejected_old_action_result_cannot_starve_failover_proof_or_heartbeats(tmp_path, monkeypatch):
    from ha_agent import failover_runtime, kaya_ha_agent as transport, keepalived_runtime

    state = State(tmp_path)
    state.config_path.write_text('{"agent_id":"fake-agent","kaya_url":"https://kaya.invalid"}', encoding="utf-8")
    state.set("pending_action_result", {"action_id": "obsolete", "action_type": "KEEPALIVED_APPLY", "generation": 1, "status": "FAILED", "message": "fake"})
    event_id = state.queue_event("automatic_failover_completed", "warning", "Local failover completed without requiring Kaya.")
    monkeypatch.setattr(keepalived_runtime, "refresh_vip_state", lambda value: None)
    monkeypatch.setattr(failover_runtime, "refresh_dhcp_state", lambda value: None)
    monkeypatch.setattr(
        transport.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    calls = []
    desired = {
        "cluster_generation": 4,
        "desired_role": "ACTIVE",
        "role_generation": 2,
        "automatic_failover": True,
        "maintenance_mode": False,
        "dhcp_managed": True,
        "automatic_hold_down_seconds": 10,
        "keepalived": None,
        "lease_snapshot": None,
        "failover": None,
    }

    def signed_request(_state, method, path, payload=None):
        calls.append(path)
        if path == "/api/ha/agent/v1/heartbeat":
            return {"accepted": True, "desired": desired}
        if path == "/api/ha/agent/v1/action-result":
            raise AgentRequestError("request_conflict", "Synthetic stale result.", status=409)
        return {"accepted": 1}

    monkeypatch.setattr(transport, "signed_request", signed_request)
    transport.run_once(state)

    assert calls[:3] == [
        "/api/ha/agent/v1/heartbeat",
        "/api/ha/agent/v1/events",
        "/api/ha/agent/v1/action-result",
    ]
    assert state.queued_events() == []
    assert state.get("pending_action_result")["action_id"] == "obsolete"
    assert state.get("last_error")["reason"] == "request_conflict"

    calls.clear()
    transport.run_once(state)
    assert calls[0] == "/api/ha/agent/v1/heartbeat"
    assert "/api/ha/agent/v1/events" not in calls
    assert state.get("report_sequence") == 2
    assert event_id not in {item["event_id"] for item in state.queued_events()}
    state.db.close()


def test_agent_icmp_probe_distinguishes_no_reply_from_local_probe_unavailability():
    calls = []

    def result(returncode):
        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=returncode, stdout=b"", stderr=b"")
        return runner

    assert probe_icmp("192.0.2.20", runner=result(0)) == (True, ICMP_AVAILABLE)
    assert probe_icmp("192.0.2.20", runner=result(1)) == (False, ICMP_NO_REPLY)
    assert probe_icmp("192.0.2.20", runner=result(2)) == (None, ICMP_UNAVAILABLE)

    def denied(command, **kwargs):
        raise PermissionError("synthetic operation not permitted")

    assert probe_icmp("192.0.2.20", runner=denied) == (None, ICMP_UNAVAILABLE)
    assert all(command == ["/usr/bin/ping", "-c", "1", "-W", "1", "192.0.2.20"] for command, _ in calls)


def test_agent_routes_expose_only_fixed_protocol_operations():
    from app.routers.ha_agent_api import router

    paths = {route.path for route in router.routes}
    assert paths == {"/api/ha/agent/v1/install.sh", "/api/ha/agent/v1/files/{name}", "/api/ha/agent/v1/register", "/api/ha/agent/v1/heartbeat", "/api/ha/agent/v1/events", "/api/ha/agent/v1/desired-state", "/api/ha/agent/v1/lease-snapshot/{generation}", "/api/ha/agent/v1/action-result"}
    assert not any("command" in path or "shell" in path for path in paths)
    template = open("app/templates/high_availability_cluster_agents.html", encoding="utf-8").read()
    assert "one-time token" in template
    assert "Copy command" in template
    assert "input is hidden" in template
    assert "Revoke identity in Kaya" in template
    assert "Completely remove the Kaya HA agents" in template
    assert "standby node first" in template
    assert 'data-ha-command-origin="{{ agent_command_origin }}"' in template
    overview = open("app/templates/high_availability_cluster_detail.html", encoding="utf-8").read()
    live_script = open("app/static/js/ha_live.js", encoding="utf-8").read()
    assert "Service remains available" in overview
    assert 'data-ha-node-field="service_state"' in overview
    assert "single_node_service" in live_script
    assert 'node.service_state === "OFFLINE"' in live_script


def test_agent_commands_use_the_browser_origin_without_trusting_forwarded_headers():
    script = open("app/static/js/ha_agents.js", encoding="utf-8").read()
    assert "window.location.origin" in script
    assert "document.body.dataset.appRoot" in script
    assert "data-ha-command-origin" in open("app/templates/high_availability_cluster_agents.html", encoding="utf-8").read()


def test_guided_installer_is_fixed_checksum_verified_and_keeps_token_off_command_line():
    from fastapi import HTTPException

    from app.routers.ha_agent_api import install_file, install_script
    from app.services.ha_agent_installer import CURRENT_AGENT_VERSION, agent_file, agent_version_status, installer_checksum, uninstaller_checksum, updater_checksum

    installer = agent_file("install.sh").decode()
    updater = agent_file("update.sh").decode()
    uninstaller = agent_file("uninstall.sh").decode()
    service = agent_file("kaya-ha-agent.service").decode()
    assert len(installer_checksum()) == 64
    assert len(updater_checksum()) == 64
    assert len(uninstaller_checksum()) == 64
    assert "--token-stdin" in installer
    assert 'read -r REGISTRATION_TOKEN </dev/tty' in installer
    assert "apt-get install -y --no-install-recommends" in installer
    assert "visudo -cf" in installer
    assert "curl -k" not in installer and "--insecure" not in installer
    assert "registration token" not in updater.lower()
    assert "/var/lib/kaya-ha-agent/config.json" in updater
    assert "existing node identity and Kaya link were preserved" in updater
    assert "validate_service_unit" in installer and "validate_service_unit" in updater
    assert "verify_running_service" in installer and "verify_running_service" in updater
    assert 'install -m 0644 -o root -g root "$TEMP_DIR/kaya-ha-agent.service"' in updater
    assert "--remove-kaya-ha-config" in uninstaller
    assert "rm -rf /usr/lib/kaya-ha-agent /var/lib/kaya-ha-agent" in uninstaller
    assert "Keepalived package were not uninstalled" in uninstaller
    assert agent_version_status(CURRENT_AGENT_VERSION) == "Up to date"
    assert agent_version_status("0.1.9") == "Update available"
    assert agent_version_status(None) == "Not reported"
    assert f'AGENT_VERSION = "{CURRENT_AGENT_VERSION}"' in agent_file("kaya_ha_agent.py").decode()
    assert "Generate a new command from the HTTPS Kaya page" in agent_file("kaya_ha_agent.py").decode()
    assert "NoNewPrivileges=true" not in service
    assert "User=kaya-ha" in service
    assert "User=root" not in service
    assert "AmbientCapabilities=CAP_NET_RAW" in service
    assert "CapabilityBoundingSet=" not in service
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
