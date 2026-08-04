from __future__ import annotations

import hashlib
import json
import secrets
import uuid
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.csrf import validate_csrf_token
from app.core.security import decrypt_secret
from app.db.session import get_db
from app.models.models import (
    BackupAgentDispatch,
    BackupAgentKey,
    BackupAgentRequest,
    BackupAgentServerKey,
    BackupJob,
    ComputeHost,
    ComputeInventoryItem,
    ComputeWorkload,
)
from app.routers.auth import require_admin, require_module_access
from app.routers.backup_manager import backup_target_by_name, backup_target_payload, metadata
from app.routers.compute_manager import reconcile_workload, workload_identity
from app.services.audit import write_audit
from app.services.backup_agent_protocol import (
    GRANT_TTL,
    authenticate_request,
    canonical_json,
    create_server_signing_key,
    consume_rotation_bootstrap,
    issue_bootstrap,
    register_identity,
    seal_dispatch,
    b64u_decode,
)

router = APIRouter()
compute_module_gate = Depends(require_module_access("compute_manager"))


def _json_object(body: bytes) -> dict:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result
    try:
        if body.startswith(b"\xef\xbb\xbf"):
            raise ValueError("JSON BOM is forbidden")
        value = json.loads(body.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(400, "A valid JSON object is required") from exc
    if not isinstance(value, dict):
        raise HTTPException(400, "A JSON object is required")
    return value


@router.post("/infrastructure/vm-docker-manager/hosts/{host_id}/agent-v2/bootstrap")
def create_agent_bootstrap(
    request: Request,
    host_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _module=compute_module_gate,
):
    validate_csrf_token(request, csrf_token)
    host = db.get(ComputeHost, host_id)
    if not host or host.platform != "docker_agent":
        raise HTTPException(404, "Docker agent host not found")
    token = issue_bootstrap(db, host.id, user.id)
    db.commit()
    write_audit(db, user, "issue_protocol_v2_bootstrap", "compute_host", str(host.id), request.client.host if request.client else None, detail=host.name)
    return {"bootstrap_token": token, "expires_in_seconds": 900}


@router.post("/infrastructure/vm-docker-manager/agent-v2/server-key")
def provision_agent_server_key(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _module=compute_module_gate,
):
    validate_csrf_token(request, csrf_token)
    try:
        row = create_server_signing_key(db)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    write_audit(db, user, "provision_protocol_v2_server_key", "backup_agent_server_key", str(row.id), request.client.host if request.client else None, detail=row.key_id)
    return {"key_id": row.key_id, "public_key": row.public_key}


@router.post("/infrastructure/vm-docker-manager/hosts/{host_id}/agent-v2/{action}")
def change_agent_lifecycle(
    request: Request,
    host_id: int,
    action: str,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
    _module=compute_module_gate,
):
    validate_csrf_token(request, csrf_token)
    if action not in {"revoke", "decommission"}:
        raise HTTPException(404, "Unknown lifecycle action")
    from app.models.models import BackupAgentIdentity
    identity = db.query(BackupAgentIdentity).filter_by(host_id=host_id).first()
    if not identity:
        raise HTTPException(404, "Agent identity not found")
    now = datetime.utcnow()
    identity.state = "revoked" if action == "revoke" else "decommissioned"
    identity.revoked_at = now
    db.query(BackupAgentKey).filter_by(identity_id=identity.id, status="active").update({"status": "retired", "retired_at": now})
    db.query(BackupAgentDispatch).filter_by(identity_id=identity.id).filter(BackupAgentDispatch.state.not_in(("successful", "failed"))).update({"state": "revoked", "grant_hash": None, "grant_expires_at": None}, synchronize_session=False)
    db.commit()
    write_audit(db, user, f"protocol_v2_{action}", "backup_agent_identity", identity.id, request.client.host if request.client else None, detail=f"Agent identity {action}d", metadata={"host_id": host_id})
    return {"state": identity.state}


@router.post("/api/agent/v2/register")
async def register(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    if len(body) > 16 * 1024:
        raise HTTPException(413, "Registration body too large")
    payload = _json_object(body)
    required = ("bootstrap_token", "signing_public_key", "envelope_public_key")
    if any(not isinstance(payload.get(field), str) or len(payload[field]) > 256 for field in required):
        raise HTTPException(400, "Invalid registration fields")
    server_key = db.query(BackupAgentServerKey).filter_by(status="active").first()
    if not server_key:
        raise HTTPException(503, "Protocol-v2 server signing key is not provisioned")
    identity, key = register_identity(db, payload["bootstrap_token"], payload["signing_public_key"], payload["envelope_public_key"])
    db.commit()
    write_audit(db, None, "protocol_v2_register", "backup_agent_identity", identity.id, request.client.host if request.client else None, detail="Agent identity activated", metadata={"host_id": identity.host_id, "key_id": key.key_id})
    return {"agent_id": identity.id, "key_id": key.key_id, "server_signing_keys": [{"key_id": server_key.key_id, "public_key": server_key.public_key}]}


@router.post("/api/agent/v2/checkin")
async def checkin(request: Request, db: Session = Depends(get_db)):
    auth, body = await authenticate_request(request, db, "inventory:write")
    payload = _json_object(body)
    workloads = payload.get("workloads") or []
    items = payload.get("items") or []
    if not isinstance(workloads, list) or not isinstance(items, list) or len(workloads) > 5000 or len(items) > 10000:
        raise HTTPException(400, "Invalid inventory")
    host = db.get(ComputeHost, auth.identity.host_id)
    if not host or host.platform != "docker_agent" or not host.is_enabled:
        raise HTTPException(403, "Agent host is disabled")
    now = datetime.utcnow()
    host_data = payload.get("host") if isinstance(payload.get("host"), dict) else {}
    host.status = "online"
    host.agent_last_seen_at = host.last_synced_at = now
    host.version = str(payload.get("version") or host.version or "")[:120] or None
    for field in ("cpu_percent", "memory_used", "memory_total", "storage_used", "storage_total"):
        value = host_data.get(field)
        if value is not None and not isinstance(value, (int, float)):
            raise HTTPException(400, f"Invalid {field}")
        setattr(host, field, value)
    seen: set[tuple[str, str]] = set()
    for data in workloads:
        if not isinstance(data, dict):
            raise HTTPException(400, "Invalid workload")
        kind = str(data.get("kind") or "container")[:30]
        reported = str(data.get("external_id") or data.get("name") or "")[:255]
        name = str(data.get("name") or reported)[:255]
        if not reported or not name:
            raise HTTPException(400, "Workload identity is required")
        external_id = workload_identity(kind, reported, name)
        row, _ = reconcile_workload(db, host.id, kind, external_id, name)
        row.name, row.status, row.last_seen_at, row.updated_at = name, str(data.get("status") or "unknown")[:30], now, now
        row.metadata_json = json.dumps(data.get("metadata") if isinstance(data.get("metadata"), dict) else {})
        seen.add((kind, external_id))
    for row in db.query(ComputeWorkload).filter_by(host_id=host.id).all():
        if (row.kind, row.external_id) not in seen:
            row.status = "missing"
    db.query(ComputeInventoryItem).filter_by(host_id=host.id).delete(synchronize_session=False)
    inventory_seen: set[tuple[str, str]] = set()
    for data in items:
        if not isinstance(data, dict):
            raise HTTPException(400, "Invalid inventory item")
        kind = str(data.get("kind") or "item")[:30]
        external_id = str(data.get("external_id") or data.get("name") or "")[:500]
        if not external_id or (kind, external_id) in inventory_seen:
            continue
        inventory_seen.add((kind, external_id))
        db.add(ComputeInventoryItem(host_id=host.id, external_id=external_id, name=str(data.get("name") or external_id)[:500], kind=kind, status=str(data.get("status"))[:30] if data.get("status") is not None else None, size_bytes=data.get("size_bytes") if isinstance(data.get("size_bytes"), int) else None, metadata_json=json.dumps(data.get("metadata") if isinstance(data.get("metadata"), dict) else {}), last_seen_at=now))
    db.commit()
    return {"ok": True, "server_time": int(now.timestamp())}


@router.post("/api/agent/v2/rotate")
async def rotate(request: Request, db: Session = Depends(get_db)):
    auth, body = await authenticate_request(request, db, "inventory:write")
    payload = _json_object(body)
    signing_public_key = payload.get("signing_public_key")
    envelope_public_key = payload.get("envelope_public_key")
    bootstrap_token = payload.get("bootstrap_token")
    try:
        if not isinstance(signing_public_key, str) or not isinstance(envelope_public_key, str) or len(b64u_decode(signing_public_key)) != 32 or len(b64u_decode(envelope_public_key)) != 32:
            raise ValueError
    except ValueError as exc:
        raise HTTPException(400, "Invalid rotation public keys") from exc
    if not isinstance(bootstrap_token, str) or len(bootstrap_token) > 256:
        raise HTTPException(400, "Rotation bootstrap is required")
    consume_rotation_bootstrap(db, auth.identity.host_id, bootstrap_token)
    if db.query(BackupAgentKey).filter_by(signing_public_key=signing_public_key).first():
        raise HTTPException(409, "Signing key has already been used")
    active_dispatch = db.query(BackupAgentDispatch).filter(BackupAgentDispatch.identity_id == auth.identity.id, BackupAgentDispatch.state.in_(("claimed", "running"))).first()
    if active_dispatch:
        raise HTTPException(409, "Key rotation is blocked while a dispatch is active")
    auth.identity.state = "rotation_pending"
    auth.key.status = "retired"
    auth.key.retired_at = datetime.utcnow()
    new_key = BackupAgentKey(identity_id=auth.identity.id, key_id=str(uuid.uuid4()), signing_public_key=signing_public_key, status="active")
    db.add(new_key)
    auth.identity.envelope_public_key = envelope_public_key
    auth.identity.state = "active"
    db.commit()
    write_audit(db, None, "protocol_v2_rotate", "backup_agent_identity", auth.identity.id, request.client.host if request.client else None, detail="Agent keys rotated", metadata={"new_key_id": new_key.key_id})
    return {"key_id": new_key.key_id}


def _manifest(db: Session, job: BackupJob) -> dict:
    info = metadata(job.metadata_json)
    target_type = backup_target_by_name(db, info.get("target_name")).get("type")
    if target_type not in {"local", "smb", "sftp"}:
        raise HTTPException(409, "Unsupported backup target type")
    return {
        "job_id": str(job.id), "operation": job.operation, "policy": str(info.get("policy") or "full"),
        "target_type": target_type,
        "workload_ref": job.workload.external_id if job.workload else str(info.get("external_id") or ""),
    }


def _minimal_target(target: dict) -> dict:
    target_type = target.get("type")
    fields = {
        "local": ("type", "path"),
        "smb": ("type", "path", "remote_host", "remote_share", "remote_username", "remote_password"),
        "sftp": ("type", "path", "remote_host", "remote_username", "remote_password"),
    }.get(target_type)
    if not fields:
        raise HTTPException(409, "Unsupported backup target type")
    return {field: target.get(field) for field in fields if target.get(field) not in (None, "")}


def _safe_artifact_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")[:120] or "container"


def _expected_artifact_path(target: dict, container_name: str, filename: str) -> str:
    container = _safe_artifact_component(container_name)
    if target["type"] == "local":
        return "/".join((str(target.get("path") or "/mnt/backups").rstrip("/"), "docker", container, filename))
    if target["type"] == "smb":
        parts = [part for part in str(target.get("remote_share") or "").replace("\\", "/").split("/") if part]
        if not parts or not target.get("remote_host"):
            raise HTTPException(409, "SMB target is incomplete")
        return "\\\\" + str(target["remote_host"]).strip("\\/") + "\\" + "\\".join((*parts, "docker", container, filename))
    raise HTTPException(409, "This agent version cannot execute the configured target type")


@router.get("/api/agent/v2/backup/offers")
async def offers(request: Request, db: Session = Depends(get_db)):
    auth, _ = await authenticate_request(request, db, "backup:poll", read_only=True)
    jobs = db.query(BackupJob).filter_by(host_id=auth.identity.host_id, status="queued").order_by(BackupJob.created_at.asc()).limit(5).all()
    result = []
    for job in jobs:
        dispatch = db.query(BackupAgentDispatch).filter_by(backup_job_id=job.id).first()
        if not dispatch:
            dispatch = BackupAgentDispatch(backup_job_id=job.id, state="offered")
            db.add(dispatch)
            db.flush()
        result.append({"dispatch_id": dispatch.id, "manifest": _manifest(db, job)})
    db.commit()
    return {"offers": result}


@router.post("/api/agent/v2/backup/dispatches/{dispatch_id}/claim")
async def claim(dispatch_id: str, request: Request, db: Session = Depends(get_db)):
    auth, body = await authenticate_request(request, db, "backup:claim")
    payload = _json_object(body)
    claim_id = payload.get("claim_id")
    try:
        if str(uuid.UUID(str(claim_id))) != claim_id or uuid.UUID(claim_id).version != 4:
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, "A canonical UUIDv4 claim_id is required") from exc
    dispatch = db.query(BackupAgentDispatch).filter_by(id=dispatch_id).first()
    if not dispatch or dispatch.job.host_id != auth.identity.host_id:
        raise HTTPException(404, "Dispatch not found")
    if dispatch.identity_id:
        if dispatch.identity_id != auth.identity.id or dispatch.claim_id != claim_id:
            raise HTTPException(409, "Dispatch already claimed")
        if dispatch.grant_expires_at and dispatch.grant_expires_at < datetime.utcnow():
            dispatch.identity_id = dispatch.claim_id = dispatch.grant_hash = dispatch.grant_expires_at = dispatch.envelope_json = None
            dispatch.state = "offered"
            dispatch.job.status = "queued"
            db.commit()
            raise HTTPException(409, "Dispatch claim expired and was requeued")
        if not dispatch.envelope_json:
            raise HTTPException(409, "Dispatch claim is incomplete")
        db.commit()
        return json.loads(dispatch.envelope_json)
    now = datetime.utcnow()
    expires = now + GRANT_TTL
    grant = secrets.token_urlsafe(32)
    manifest = _manifest(db, dispatch.job)
    manifest_hash = hashlib.sha256(canonical_json(manifest)).hexdigest()
    aad = {"agent_encryption_key_id": auth.identity.id, "agent_id": auth.identity.id, "claim_id": claim_id, "dispatch_id": dispatch.id, "expires_at": expires.replace(tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), "host_id": str(auth.identity.host_id), "job_id": str(dispatch.job.id), "manifest_sha256": manifest_hash, "operation": dispatch.job.operation, "protocol_version": 2}
    info = metadata(dispatch.job.metadata_json)
    target = _minimal_target(backup_target_payload(db, info.get("target_name")))
    plaintext = {"dispatch_grant": grant, "encryption": {"data_key": decrypt_secret(dispatch.job.encrypted_backup_key) if dispatch.job.encrypted_backup_key else "", "mode": "agent-aes-256-gcm"}, "manifest": manifest, "target": target}
    if dispatch.job.operation == "backup":
        artifact_name = f"job-{dispatch.job.id}.kaya-backup"
        plaintext["artifact_name"] = artifact_name
        container_name = dispatch.job.workload.name if dispatch.job.workload else manifest["workload_ref"]
        dispatch.job.artifact_path = _expected_artifact_path(target, container_name, artifact_name)
    if dispatch.job.operation == "restore":
        plaintext["restore"] = {"source_artifact": info.get("source_artifact"), "source_size_bytes": info.get("source_size_bytes")}
    server_key = db.query(BackupAgentServerKey).filter_by(status="active").first()
    if not server_key:
        raise HTTPException(503, "Dispatch signing key unavailable")
    envelope = seal_dispatch(identity=auth.identity, server_key=server_key, aad=aad, plaintext=plaintext)
    envelope_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    updated = db.query(BackupAgentDispatch).filter(
        BackupAgentDispatch.id == dispatch.id,
        BackupAgentDispatch.identity_id.is_(None),
        BackupAgentDispatch.state == "offered",
    ).update(
        {
            "identity_id": auth.identity.id,
            "claim_id": claim_id,
            "state": "claimed",
            "grant_hash": hashlib.sha256(grant.encode()).hexdigest(),
            "grant_expires_at": expires,
            "claimed_at": now,
            "envelope_json": envelope_json,
        },
        synchronize_session=False,
    )
    if updated != 1:
        db.rollback()
        existing = db.get(BackupAgentDispatch, dispatch_id)
        db.add(BackupAgentRequest(identity_id=auth.identity.id, request_id=auth.request_id))
        db.commit()
        if existing and existing.identity_id == auth.identity.id and existing.claim_id == claim_id and existing.envelope_json:
            return json.loads(existing.envelope_json)
        raise HTTPException(409, "Dispatch already claimed")
    dispatch.job.status, dispatch.job.dispatched_at = "dispatched", now
    db.commit()
    write_audit(db, None, "protocol_v2_claim", "backup_agent_dispatch", dispatch.id, request.client.host if request.client else None, detail="Backup dispatch claimed", metadata={"host_id": auth.identity.host_id, "job_id": dispatch.job.id})
    return envelope


@router.post("/api/agent/v2/backup/dispatches/{dispatch_id}/status")
async def status(dispatch_id: str, request: Request, db: Session = Depends(get_db)):
    auth, body = await authenticate_request(request, db, "backup:status")
    payload = _json_object(body)
    dispatch = db.query(BackupAgentDispatch).filter_by(id=dispatch_id, identity_id=auth.identity.id).first()
    if not dispatch:
        raise HTTPException(404, "Dispatch not found")
    grant = payload.get("dispatch_grant")
    if not isinstance(grant, str) or not secrets.compare_digest(hashlib.sha256(grant.encode()).hexdigest(), dispatch.grant_hash or "") or not dispatch.grant_expires_at or dispatch.grant_expires_at < datetime.utcnow():
        raise HTTPException(401, "Invalid or expired dispatch grant")
    allowed_fields = {"state", "dispatch_grant", "progress_percent", "result_code", "result_digest", "bytes_processed", "agent_finished_at"}
    if set(payload) - allowed_fields:
        raise HTTPException(400, "Unknown status field")
    new_status = payload.get("state")
    allowed = {"claimed": {"running", "failed"}, "running": {"successful", "failed"}}
    if new_status not in allowed.get(dispatch.state, set()):
        raise HTTPException(409, "Invalid dispatch state transition")
    dispatch.state = new_status
    dispatch.job.status = new_status
    dispatch.job.updated_at = datetime.utcnow()
    if new_status in {"successful", "failed"}:
        dispatch.finished_at = dispatch.job.finished_at = datetime.utcnow()
        dispatch.grant_hash = None
        dispatch.grant_expires_at = None
    if new_status == "failed":
        from app.services.notification_outbox import enqueue_notification
        enqueue_notification(
            db,
            event_type_id="backup.job.failed",
            title="Backup failed",
            message="A Kaya-managed backup job failed. Open Backup Manager to review it.",
            target_route="/infrastructure/backup-manager",
            source_entity_type="backup_job",
            source_entity_id=dispatch.job.id,
            deduplication_key=f"backup:job:{dispatch.job.id}:failed",
            recipient_ids=[dispatch.job.requested_by_id] if dispatch.job.requested_by_id else None,
        )
    progress = payload.get("progress_percent")
    if progress is not None and (not isinstance(progress, int) or not 0 <= progress <= 100):
        raise HTTPException(400, "Invalid progress_percent")
    bytes_processed = payload.get("bytes_processed")
    if bytes_processed is not None and (not isinstance(bytes_processed, int) or bytes_processed < 0 or bytes_processed > 2**63 - 1):
        raise HTTPException(400, "Invalid bytes_processed")
    digest = payload.get("result_digest")
    if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise HTTPException(400, "Invalid result_digest")
    if bytes_processed is not None:
        dispatch.job.size_bytes = bytes_processed
    if isinstance(payload.get("result_code"), str):
        dispatch.job.error = payload["result_code"][:120] if new_status == "failed" else None
    db.commit()
    return {"ok": True, "state": new_status}
