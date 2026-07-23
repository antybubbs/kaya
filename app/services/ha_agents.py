import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.models import HAAgentActionResult as HAAgentActionResultRow, HAAgentCredential, HAAgentRequest, HACluster, HAEvent, HANode
from app.schemas.high_availability import HAAgentActionResult, HAAgentEventItem, HAAgentHeartbeat, HAAgentRegister
from app.services.ha_keepalived import desired_keepalived_action
from app.services.ha_leases import HALeaseError, desired_lease_action, record_lease_stage_result
from app.services.ha_failover import HAFailoverError, advance_failover, desired_failover_action, record_failover_action_result
from app.services.ha_agent_installer import CURRENT_AGENT_VERSION, version_tuple
from app.services.ha_topology import pihole_manages_dhcp


AGENT_PROTOCOL_VERSION = 1
REQUEST_WINDOW_SECONDS = 300
REQUESTS_PER_MINUTE = 120
BOOTSTRAP_LIFETIME_MINUTES = 15
MAX_AGENT_BODY_BYTES = 256 * 1024
SENSITIVE_DETAIL_PARTS = {"auth", "cookie", "credential", "key", "password", "secret", "session", "token"}


class HAAgentError(ValueError):
    pass


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _decode_urlsafe(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise HAAgentError("Invalid encoded agent credential.") from exc


def create_bootstrap_token(db: Session, node: HANode) -> tuple[HAAgentCredential, str]:
    now = datetime.utcnow()
    raw_token = secrets.token_urlsafe(32)
    credential = node.agent_credential
    if credential is None:
        credential = HAAgentCredential(node_id=node.id, agent_id=node.public_id)
        db.add(credential)
    credential.bootstrap_token_hash = _token_hash(raw_token)
    credential.bootstrap_expires_at = now + timedelta(minutes=BOOTSTRAP_LIFETIME_MINUTES)
    db.commit()
    db.refresh(credential)
    return credential, raw_token


def revoke_agent(db: Session, node: HANode) -> HAAgentCredential:
    credential = node.agent_credential
    if credential is None:
        raise HAAgentError("This node does not have an agent identity.")
    credential.revoked_at = datetime.utcnow()
    credential.bootstrap_token_hash = None
    credential.bootstrap_expires_at = None
    db.commit()
    db.refresh(credential)
    return credential


def register_agent(db: Session, payload: HAAgentRegister) -> tuple[HAAgentCredential, HANode]:
    now = datetime.utcnow()
    credential = db.query(HAAgentCredential).filter(HAAgentCredential.bootstrap_token_hash == _token_hash(payload.bootstrap_token)).first()
    if credential is None or credential.bootstrap_expires_at is None or credential.bootstrap_expires_at < now:
        raise HAAgentError("The bootstrap token is invalid, expired, or has already been used.")
    node = credential.node
    if node.public_id != payload.node_id or node.cluster.public_id != payload.cluster_id or node.cluster.deleted_at is not None:
        raise HAAgentError("The bootstrap token is not valid for this cluster and node.")
    public_key = _decode_urlsafe(payload.public_key)
    if len(public_key) != 32:
        raise HAAgentError("The agent public key must be an Ed25519 public key.")
    try:
        Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError as exc:
        raise HAAgentError("The agent public key must be an Ed25519 public key.") from exc
    reused_identity = db.query(HAAgentCredential.id).filter(HAAgentCredential.public_key == payload.public_key, HAAgentCredential.id != credential.id).first()
    if reused_identity:
        raise HAAgentError("This agent identity is already bound to another node.")
    rotating = credential.registered_at is not None
    credential.public_key = payload.public_key
    credential.bootstrap_token_hash = None
    credential.bootstrap_expires_at = None
    credential.registered_at = now
    credential.last_rotated_at = now if rotating else None
    credential.revoked_at = None
    node.agent_id = credential.agent_id
    node.agent_version = payload.agent_version
    node.last_heartbeat_at = now
    db.commit()
    db.refresh(credential)
    return credential, node


@dataclass(frozen=True)
class AuthenticatedAgent:
    credential: HAAgentCredential
    node: HANode


async def authenticate_agent_request(request: Request, db: Session) -> AuthenticatedAgent:
    agent_id = request.headers.get("x-kaya-agent-id", "").strip()
    timestamp_text = request.headers.get("x-kaya-agent-timestamp", "").strip()
    request_id = request.headers.get("x-kaya-agent-request-id", "").strip()
    signature_text = request.headers.get("x-kaya-agent-signature", "").strip()
    protocol = request.headers.get("x-kaya-agent-protocol", "").strip()
    if not agent_id or not timestamp_text or not request_id or not signature_text:
        raise HTTPException(401, "Missing agent authentication headers")
    if protocol != str(AGENT_PROTOCOL_VERSION):
        raise HTTPException(426, "Unsupported agent protocol version")
    if len(request_id) > 80 or not all(character.isalnum() or character in "-_.:" for character in request_id):
        raise HTTPException(400, "Invalid agent request ID")
    credential = db.query(HAAgentCredential).filter(HAAgentCredential.agent_id == agent_id).first()
    if credential is None or credential.revoked_at is not None or not credential.public_key or credential.registered_at is None or credential.node.cluster.deleted_at is not None:
        raise HTTPException(401, "Invalid or revoked agent identity")
    try:
        request_time = datetime.fromtimestamp(int(timestamp_text), timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        raise HTTPException(400, "Invalid agent request timestamp")
    now = datetime.utcnow()
    db.query(HAAgentRequest).filter(HAAgentRequest.received_at < now - timedelta(days=1)).delete(synchronize_session=False)
    if abs((now - request_time).total_seconds()) > REQUEST_WINDOW_SECONDS:
        raise HTTPException(401, "Expired agent request")
    if db.query(HAAgentRequest.id).filter(HAAgentRequest.credential_id == credential.id, HAAgentRequest.request_id == request_id).first():
        raise HTTPException(409, "Replayed agent request")
    recent = db.query(HAAgentRequest.id).filter(HAAgentRequest.credential_id == credential.id, HAAgentRequest.received_at >= now - timedelta(minutes=1)).count()
    if recent >= REQUESTS_PER_MINUTE:
        raise HTTPException(429, "Agent request rate limit exceeded")
    body = await request.body()
    if len(body) > MAX_AGENT_BODY_BYTES:
        raise HTTPException(413, "Agent payload is too large")
    canonical = "\n".join((request.method.upper(), request.url.path, request_id, timestamp_text, hashlib.sha256(body).hexdigest())).encode()
    try:
        Ed25519PublicKey.from_public_bytes(_decode_urlsafe(credential.public_key)).verify(_decode_urlsafe(signature_text), canonical)
    except (InvalidSignature, ValueError, HAAgentError):
        raise HTTPException(401, "Invalid agent request signature")
    db.add(HAAgentRequest(credential_id=credential.id, request_id=request_id, request_timestamp=request_time))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Replayed agent request")
    return AuthenticatedAgent(credential, credential.node)


def record_heartbeat(db: Session, node: HANode, heartbeat: HAAgentHeartbeat) -> HANode:
    node.agent_version = heartbeat.agent_version
    node.last_heartbeat_at = datetime.utcnow()
    node.observed_role = heartbeat.observed_role
    node.observed_generation = heartbeat.observed_generation
    node.vip_owned = heartbeat.vip_owned
    node.dhcp_running = heartbeat.dhcp_running
    node.dns_healthy = heartbeat.dns_healthy
    node.peer_reachable = heartbeat.peer_reachable
    node.lease_generation = heartbeat.lease_generation
    node.config_generation = heartbeat.config_generation
    node.keepalived_runtime_state = heartbeat.keepalived_runtime_state
    node.keepalived_reported_at = datetime.utcnow()
    db.commit()
    db.refresh(node)
    reconcile_vip_ownership(db, node.cluster)
    advance_failover(db, node.cluster)
    return node


HEARTBEAT_FRESH_SECONDS = 45


def _heartbeat_is_fresh(node: HANode, now: datetime) -> bool:
    return bool(node.last_heartbeat_at and node.last_heartbeat_at >= now - timedelta(seconds=HEARTBEAT_FRESH_SECONDS))


def _automatic_completion_for_generation(db: Session, cluster: HACluster, node: HANode) -> HAEvent | None:
    events = (
        db.query(HAEvent)
        .filter(
            HAEvent.cluster_id == cluster.id,
            HAEvent.node_id == node.id,
            HAEvent.event_type == "automatic_failover_completed",
        )
        .order_by(HAEvent.received_at.desc())
        .limit(50)
        .all()
    )
    for event in events:
        try:
            details = json.loads(event.details_json_redacted or "{}")
            if int(details.get("generation", -1)) == cluster.keepalived_generation:
                return event
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    return None


def reconcile_vip_ownership(db: Session, cluster: HACluster) -> None:
    if cluster.keepalived_status != "DEPLOYED" or any(node.keepalived_status != "DEPLOYED" for node in cluster.nodes):
        return
    now = datetime.utcnow()
    previous_active_id = cluster.current_active_node_id
    previous_status = cluster.status
    current_nodes = [node for node in cluster.nodes if _heartbeat_is_fresh(node, now)]
    owners = [node for node in current_nodes if node.vip_owned]
    current = owners[0] if len(owners) == 1 else None
    completed = _automatic_completion_for_generation(db, cluster, current) if current else None
    cluster.current_active_node_id = current.id if current else None
    fully_healthy = (
        len(current_nodes) == len(cluster.nodes)
        and all(node.dns_healthy is True for node in current_nodes)
        and all(node.keepalived_runtime_state == "RUNNING" for node in current_nodes)
        and all(node.config_generation >= cluster.keepalived_generation for node in cluster.nodes)
    )
    if len(owners) == 1 and fully_healthy:
        cluster.status = "HEALTHY"
    elif len(owners) > 1:
        cluster.status = "ERROR"
    else:
        cluster.status = "DEGRADED"
    if len(owners) > 1 and previous_status != "ERROR":
        db.add(HAEvent(cluster_id=cluster.id, node_id=None, event_type="split_brain_detected", severity="critical", source="kaya", message="Multiple virtual-IP owners were reported. Automatic DHCP activation remains blocked.", details_json_redacted="{}", occurred_at=datetime.utcnow()))
    needs_adoption = bool(
        current
        and (
            previous_active_id != current.id
            or cluster.authoritative_node_id != current.id
            or current.role != "ACTIVE"
            or current.desired_role != "ACTIVE"
        )
    )
    if cluster.automatic_failover_enabled and current and needs_adoption:
        peers = [node for node in cluster.nodes if node.id != current.id]
        dhcp_managed = pihole_manages_dhcp(cluster)
        current_peers = [peer for peer in peers if _heartbeat_is_fresh(peer, now)]
        safe_dhcp = not dhcp_managed or (
            current.dhcp_running
            and all(not peer.dhcp_running for peer in current_peers)
            and (len(current_peers) == len(peers) or completed is not None)
        )
        if current.dns_healthy and safe_dhcp:
            for node in cluster.nodes:
                node.desired_role = "ACTIVE" if node.id == current.id else "STANDBY"
                node.role = node.desired_role
                node.vrrp_priority = 150 if node.id == current.id else 100
            cluster.authoritative_node_id = current.id
            cluster.role_generation += 1
            cluster.last_failover_at = completed.occurred_at if completed else datetime.utcnow()
            db.add(HAEvent(cluster_id=cluster.id, node_id=current.id, event_type="automatic_failover_reconciled", severity="warning", source="kaya", message=f"Kaya reconciled the local failover and adopted {current.display_name} as active. Automatic failback remains disabled.", details_json_redacted=json.dumps({"automatic": True}, sort_keys=True), occurred_at=datetime.utcnow()))
    if current and completed:
        # The other node has stopped reporting and the surviving agent has
        # already completed its local ownership safety checks. Retire the
        # offline node's cached owner bit so every live API response uses
        # the verified current owner instead of stale telemetry.
        for peer in cluster.nodes:
            if peer.id != current.id and not _heartbeat_is_fresh(peer, now):
                peer.vip_owned = False
        transient = (
            db.query(HAEvent)
            .filter(
                HAEvent.cluster_id == cluster.id,
                HAEvent.event_type == "split_brain_detected",
                HAEvent.source == "kaya",
                HAEvent.received_at >= completed.received_at - timedelta(minutes=1),
                HAEvent.received_at <= completed.received_at + timedelta(minutes=1),
            )
            .order_by(HAEvent.received_at.desc())
            .first()
        )
        if transient is not None:
            transient.event_type = "ownership_reconciled"
            transient.severity = "info"
            transient.message = f"Kaya reconciled cached ownership after verified automatic failover. {current.display_name} is the exclusive virtual-IP owner."
    db.commit()


def _adopt_verified_automatic_owner(db: Session, node: HANode, event: HAAgentEventItem) -> None:
    cluster = node.cluster
    try:
        generation = int(event.details.get("generation", -1))
    except (TypeError, ValueError):
        return
    if (
        event.event_type != "automatic_failover_completed"
        or not cluster.automatic_failover_enabled
        or generation != cluster.keepalived_generation
        or node.observed_role != "ACTIVE"
        or node.vip_owned is not True
        or node.dns_healthy is not True
    ):
        return
    dhcp_managed = pihole_manages_dhcp(cluster)
    if dhcp_managed and node.dhcp_running is not True:
        return
    previous_active_id = cluster.current_active_node_id
    for peer in cluster.nodes:
        active = peer.id == node.id
        peer.vip_owned = active
        peer.role = peer.desired_role = "ACTIVE" if active else "STANDBY"
        peer.vrrp_priority = 150 if active else 100
    cluster.current_active_node_id = node.id
    cluster.authoritative_node_id = node.id
    cluster.status = "DEGRADED"
    cluster.last_failover_at = event.occurred_at.replace(tzinfo=None)
    if previous_active_id != node.id:
        cluster.role_generation += 1

    # A heartbeat arriving immediately before the completion event can compare
    # the new owner with the powered-off node's cached owner bit. Preserve that
    # audit row, but reclassify it once the signed agent event proves exclusive
    # ownership through its hold-down and duplicate-address checks.
    transient = (
        db.query(HAEvent)
        .filter(
            HAEvent.cluster_id == cluster.id,
            HAEvent.event_type == "split_brain_detected",
            HAEvent.source == "kaya",
            HAEvent.received_at >= datetime.utcnow() - timedelta(minutes=1),
        )
        .order_by(HAEvent.received_at.desc())
        .first()
    )
    if transient is not None:
        transient.event_type = "ownership_reconciled"
        transient.severity = "info"
        transient.message = f"Kaya reconciled cached ownership after verified automatic failover. {node.display_name} is the exclusive virtual-IP owner."


def record_action_result(db: Session, node: HANode, result: HAAgentActionResult) -> HAAgentActionResultRow:
    existing = db.query(HAAgentActionResultRow).filter(HAAgentActionResultRow.action_id == result.action_id).first()
    if existing:
        if existing.node_id != node.id:
            raise HAAgentError("The action result belongs to a different node.")
        return existing
    if result.action_type == "KEEPALIVED_APPLY":
        expected = desired_keepalived_action(node.cluster, node)
    elif result.action_type == "LEASE_SNAPSHOT_STAGE":
        expected = desired_lease_action(node.cluster, node)
    else:
        expected = desired_failover_action(node.cluster, node)
    if not expected or result.action_id != expected["action_id"] or result.generation != expected["generation"]:
        raise HAAgentError("The action result does not match the node's current desired generation.")
    if result.status == "APPLIED" and result.checksum != expected["checksum"]:
        raise HAAgentError("The applied checksum does not match the desired action.")
    row = HAAgentActionResultRow(action_id=result.action_id, cluster_id=node.cluster_id, node_id=node.id, action_type=result.action_type, generation=result.generation, status=result.status, checksum=result.checksum, backup_reference=result.backup_reference, message_redacted=result.message)
    db.add(row)
    cluster = node.cluster
    if result.action_type == "LEASE_SNAPSHOT_STAGE":
        try:
            record_lease_stage_result(db, node, generation=result.generation, checksum=result.checksum, status=result.status, message=result.message)
        except HALeaseError as exc:
            raise HAAgentError(str(exc)) from exc
    elif result.action_type in {"DHCP_DEMOTE", "DHCP_PROMOTE"}:
        try:
            record_failover_action_result(db, node, action_type=result.action_type, generation=result.generation, checksum=result.checksum, status=result.status, message=result.message)
        except HAFailoverError as exc:
            raise HAAgentError(str(exc)) from exc
    else:
        node.keepalived_status = "DEPLOYED" if result.status == "APPLIED" else "ERROR"
        node.keepalived_config_checksum = result.checksum if result.status == "APPLIED" else None
        node.keepalived_backup_reference = result.backup_reference
        node.keepalived_last_error = None if result.status == "APPLIED" else result.message
        node.keepalived_reported_at = datetime.utcnow()
        if result.status == "APPLIED":
            node.config_generation = result.generation
        if result.status == "FAILED":
            cluster.keepalived_status = "ERROR"
            cluster.status = "ERROR"
        elif all(peer.keepalived_status == "DEPLOYED" for peer in cluster.nodes):
            cluster.keepalived_status = "DEPLOYED"
            cluster.keepalived_deployed_at = datetime.utcnow()
            cluster.status = "READY_TO_DEPLOY"
    db.commit()
    db.refresh(row)
    reconcile_vip_ownership(db, cluster)
    advance_failover(db, cluster)
    return row


def _redacted_details(details: dict) -> str:
    safe: dict[str, str | int | float | bool | None] = {}
    for key, value in list(details.items())[:50]:
        normalised = str(key).strip().lower()
        if not normalised or any(part in normalised for part in SENSITIVE_DETAIL_PARTS):
            continue
        safe[normalised[:80]] = value[:500] if isinstance(value, str) else value
    return json.dumps(safe, sort_keys=True, separators=(",", ":"))


def ingest_events(db: Session, node: HANode, events: list[HAAgentEventItem]) -> tuple[int, int]:
    accepted = 0
    duplicates = 0
    for event in events:
        if db.query(HAEvent.id).filter(HAEvent.agent_event_id == event.event_id).first():
            duplicates += 1
            continue
        db.add(HAEvent(cluster_id=node.cluster_id, node_id=node.id, event_type=event.event_type, severity=event.severity, source="agent", message=event.message, details_json_redacted=_redacted_details(event.details), agent_event_id=event.event_id, occurred_at=event.occurred_at.replace(tzinfo=None)))
        _adopt_verified_automatic_owner(db, node, event)
        accepted += 1
    db.commit()
    return accepted, duplicates


def desired_state(node: HANode) -> dict:
    cluster: HACluster = node.cluster
    keepalived = desired_keepalived_action(cluster, node)
    leases = desired_lease_action(cluster, node)
    failover = desired_failover_action(cluster, node)
    peer = next((item for item in cluster.nodes if item.id != node.id), None)
    dhcp_managed = pihole_manages_dhcp(cluster)
    return {
        "protocol_version": AGENT_PROTOCOL_VERSION,
        "cluster_id": cluster.public_id,
        "node_id": node.public_id,
        "cluster_generation": cluster.cluster_generation,
        "role_generation": cluster.role_generation,
        "desired_role": node.desired_role,
        "desired_sync_generation": cluster.desired_sync_generation,
        "desired_agent_version": CURRENT_AGENT_VERSION,
        "virtual_ip": f"{cluster.virtual_ip}/{cluster.prefix_length}" if cluster.virtual_ip else None,
        "maintenance_mode": cluster.maintenance_mode,
        # Old agents only checked the Pi-hole configuration flag and could
        # mistake a failed DHCP listener for a successful promotion.
        "automatic_failover": bool(
            cluster.automatic_failover_enabled
            and all(
                version_tuple(peer.agent_version) >= version_tuple(CURRENT_AGENT_VERSION)
                for peer in cluster.nodes
            )
        ),
        "automatic_failback": False,
        "automatic_hold_down_seconds": 10,
        "dhcp_managed": dhcp_managed,
        "peer_host": peer.management_host if peer else None,
        "network_interface": node.network_interface,
        "allowed_actions": (["KEEPALIVED_APPLY"] if keepalived else []) + (["LEASE_SNAPSHOT_STAGE"] if leases else []) + ([failover["action_type"]] if failover else []),
        "keepalived": keepalived,
        "lease_snapshot": leases,
        "failover": failover,
    }
