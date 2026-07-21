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
    return node


def reconcile_vip_ownership(db: Session, cluster: HACluster) -> None:
    if cluster.keepalived_status != "DEPLOYED" or any(node.keepalived_status != "DEPLOYED" for node in cluster.nodes):
        return
    owners = [node for node in cluster.nodes if node.vip_owned]
    current = owners[0] if len(owners) == 1 else None
    cluster.current_active_node_id = current.id if current else None
    if len(owners) == 1 and all(node.config_generation >= cluster.keepalived_generation for node in cluster.nodes):
        cluster.status = "HEALTHY"
    elif len(owners) > 1:
        cluster.status = "ERROR"
    else:
        cluster.status = "DEGRADED"
    db.commit()


def record_action_result(db: Session, node: HANode, result: HAAgentActionResult) -> HAAgentActionResultRow:
    existing = db.query(HAAgentActionResultRow).filter(HAAgentActionResultRow.action_id == result.action_id).first()
    if existing:
        if existing.node_id != node.id:
            raise HAAgentError("The action result belongs to a different node.")
        return existing
    expected = desired_keepalived_action(node.cluster, node)
    if not expected or result.action_id != expected["action_id"] or result.generation != expected["generation"]:
        raise HAAgentError("The action result does not match the node's current desired generation.")
    if result.status == "APPLIED" and result.checksum != expected["checksum"]:
        raise HAAgentError("The applied Keepalived checksum does not match the desired configuration.")
    row = HAAgentActionResultRow(action_id=result.action_id, cluster_id=node.cluster_id, node_id=node.id, action_type=result.action_type, generation=result.generation, status=result.status, checksum=result.checksum, backup_reference=result.backup_reference, message_redacted=result.message)
    db.add(row)
    node.keepalived_status = "DEPLOYED" if result.status == "APPLIED" else "ERROR"
    node.keepalived_config_checksum = result.checksum if result.status == "APPLIED" else None
    node.keepalived_backup_reference = result.backup_reference
    node.keepalived_last_error = None if result.status == "APPLIED" else result.message
    node.keepalived_reported_at = datetime.utcnow()
    if result.status == "APPLIED":
        node.config_generation = result.generation
    cluster = node.cluster
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
        accepted += 1
    db.commit()
    return accepted, duplicates


def desired_state(node: HANode) -> dict:
    cluster: HACluster = node.cluster
    keepalived = desired_keepalived_action(cluster, node)
    return {
        "protocol_version": AGENT_PROTOCOL_VERSION,
        "cluster_id": cluster.public_id,
        "node_id": node.public_id,
        "cluster_generation": cluster.cluster_generation,
        "role_generation": cluster.role_generation,
        "desired_role": node.desired_role,
        "desired_sync_generation": cluster.desired_sync_generation,
        "desired_agent_version": None,
        "virtual_ip": f"{cluster.virtual_ip}/{cluster.prefix_length}" if cluster.virtual_ip else None,
        "maintenance_mode": cluster.maintenance_mode,
        "automatic_failover": False,
        "allowed_actions": ["KEEPALIVED_APPLY"] if keepalived else [],
        "keepalived": keepalived,
    }
