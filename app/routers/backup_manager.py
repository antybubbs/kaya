import json
import hashlib
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import decrypt_secret, encrypt_secret
from app.db.session import get_db
from app.models.models import BackupJob, BackupRecord, ComputeHost, ComputeInventoryItem, ComputeWorkload
from app.routers.auth import require_editor, require_user
from app.services.audit import write_audit
from app.services.site_settings import get_site_setting

router = APIRouter(prefix="/infrastructure/backup-manager")
templates = Jinja2Templates(directory="app/templates")


def metadata(value: str | None) -> dict:
    try:
        data = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def host_metadata(host: ComputeHost | None) -> dict:
    return metadata(host.metadata_json if host else None)


def agent_capabilities(host: ComputeHost | None) -> dict:
    data = host_metadata(host)
    capabilities = data.get("agent_capabilities")
    return capabilities if isinstance(capabilities, dict) else {}


def agent_supports_docker_backups(host: ComputeHost | None) -> bool:
    return bool(agent_capabilities(host).get("docker_backups"))


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_agent_host(request: Request, db: Session) -> ComputeHost:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing agent token")
    token_hash = hash_agent_token(auth.split(" ", 1)[1].strip())
    host = (
        db.query(ComputeHost)
        .filter(ComputeHost.platform == "docker_agent", ComputeHost.agent_token_hash == token_hash)
        .first()
    )
    if not host:
        raise HTTPException(401, "Invalid agent token")
    now = datetime.utcnow()
    host.status = "online"
    host.agent_last_seen_at = now
    host.updated_at = now
    return host


def backup_target_summary(db: Session) -> str:
    target_type = get_site_setting(db, "backup_storage_type") or "local"
    if target_type == "local":
        return get_site_setting(db, "backup_storage_path") or "/mnt/backups"
    host = get_site_setting(db, "backup_remote_host")
    share = get_site_setting(db, "backup_remote_share")
    return f"{target_type.upper()} {host}{('/' + share) if share else ''}".strip()


def backup_target_payload(db: Session) -> dict:
    return {
        "type": get_site_setting(db, "backup_storage_type") or "local",
        "path": get_site_setting(db, "backup_storage_path") or "/mnt/backups",
        "remote_host": get_site_setting(db, "backup_remote_host"),
        "remote_share": get_site_setting(db, "backup_remote_share"),
        "remote_username": get_site_setting(db, "backup_remote_username"),
        "remote_password": decrypt_secret(get_site_setting(db, "backup_remote_password")),
    }


def bytes_label(value: int | None) -> str:
    if value is None:
        return "-"
    number = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(number) < 1024:
            return f"{number:.1f} {unit}" if unit != "B" else f"{int(number)} B"
        number /= 1024
    return f"{number:.1f} PB"


def latest_successful_backup(db: Session, workload_id: int) -> BackupJob | None:
    return (
        db.query(BackupJob)
        .filter(
            BackupJob.workload_id == workload_id,
            BackupJob.operation == "backup",
            BackupJob.status == "successful",
            BackupJob.artifact_path.is_not(None),
        )
        .order_by(BackupJob.finished_at.desc(), BackupJob.created_at.desc())
        .first()
    )


def create_docker_job(db: Session, workload: ComputeWorkload, operation: str, user_id: int | None, source_job: BackupJob | None = None) -> BackupJob:
    backup_key = secrets.token_urlsafe(32) if operation == "backup" else None
    payload = {
        "container": workload.name,
        "external_id": workload.external_id,
        "policy": workload.backup_policy,
        "source_job_id": source_job.id if source_job else None,
        "source_artifact": source_job.artifact_path if source_job else None,
        "source_size_bytes": source_job.size_bytes if source_job else None,
    }
    job = BackupJob(
        host_id=workload.host_id,
        workload_id=workload.id,
        operation=operation,
        status="queued",
        encryption_enabled=True,
        encrypted_backup_key=source_job.encrypted_backup_key if source_job else encrypt_secret(backup_key),
        metadata_json=json.dumps(payload),
        requested_by_id=user_id,
    )
    db.add(job)
    return job


def proxmox_backup_jobs(db: Session) -> list[dict]:
    rows = (
        db.query(ComputeInventoryItem, ComputeHost)
        .join(ComputeHost, ComputeHost.id == ComputeInventoryItem.host_id)
        .filter(ComputeInventoryItem.kind == "backup")
        .order_by(ComputeHost.name, ComputeInventoryItem.name)
        .all()
    )
    jobs = []
    for item, host in rows:
        data = metadata(item.metadata_json)
        last_task = data.get("last_task") if isinstance(data.get("last_task"), dict) else {}
        last_run_at = None
        if last_task.get("starttime"):
            try:
                last_run_at = datetime.fromtimestamp(int(last_task["starttime"]))
            except (TypeError, ValueError, OSError):
                last_run_at = None
        jobs.append(
            {
                "host": host,
                "name": item.name,
                "status": item.status or "unknown",
                "last_status": data.get("last_status") or "unknown",
                "last_run_at": last_run_at,
                "schedule": data.get("schedule") or "-",
                "storage": data.get("storage") or "-",
                "vmids": data.get("vmid") or data.get("all") or "all",
                "last_seen_at": item.last_seen_at,
            }
        )
    return jobs


@router.get("")
def backup_home(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    manual_backups = db.query(BackupRecord).order_by(BackupRecord.name.asc()).all()
    docker_workloads = (
        db.query(ComputeWorkload)
        .join(ComputeHost, ComputeHost.id == ComputeWorkload.host_id)
        .filter(ComputeWorkload.kind == "container", ComputeWorkload.status != "missing")
        .order_by(ComputeHost.name, ComputeWorkload.name)
        .all()
    )
    latest_by_workload = {
        row.id: latest_successful_backup(db, row.id)
        for row in docker_workloads
    }
    recent_jobs = (
        db.query(BackupJob)
        .order_by(BackupJob.created_at.desc())
        .limit(20)
        .all()
    )
    return templates.TemplateResponse(
        request,
        "backup_manager.html",
        {
            "user": user,
            "manual_backups": manual_backups,
            "docker_workloads": docker_workloads,
            "latest_by_workload": latest_by_workload,
            "recent_jobs": recent_jobs,
            "proxmox_jobs": proxmox_backup_jobs(db),
            "backup_target": backup_target_summary(db),
            "bytes_label": bytes_label,
            "agent_supports_docker_backups": agent_supports_docker_backups,
            **csrf_context(request),
        },
    )


@router.post("/manual")
def create_manual_backup(
    request: Request,
    name: str = Form(..., max_length=255),
    target: str = Form("", max_length=500),
    schedule: str = Form("", max_length=255),
    owner: str = Form("", max_length=255),
    last_status: str = Form("", max_length=40),
    last_run_at: str = Form(""),
    notes: str = Form("", max_length=5000),
    is_enabled: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(400, "Name is required")
    parsed_last_run = None
    if last_run_at.strip():
        try:
            parsed_last_run = datetime.fromisoformat(last_run_at.strip())
        except ValueError:
            raise HTTPException(400, "Last run must be a valid date and time")
    row = BackupRecord(
        name=clean_name,
        source_type="manual",
        target=target.strip() or None,
        schedule=schedule.strip() or None,
        owner=owner.strip() or None,
        last_status=last_status.strip().lower() or None,
        last_run_at=parsed_last_run,
        notes=notes.strip() or None,
        is_enabled=bool(is_enabled),
    )
    db.add(row)
    db.commit()
    write_audit(db, user, "create", "backup_record", str(row.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse("/infrastructure/backup-manager", status_code=303)


@router.post("/docker/{workload_id}")
def update_docker_backup_policy(
    request: Request,
    workload_id: int,
    backup_policy: str = Form("", max_length=255),
    owner: str = Form("", max_length=255),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    row = db.get(ComputeWorkload, workload_id)
    if not row or row.kind != "container":
        raise HTTPException(404, "Docker container not found")
    row.backup_policy = backup_policy.strip() or None
    row.owner = owner.strip() or None
    db.commit()
    write_audit(db, user, "update", "docker_backup_policy", str(row.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse("/infrastructure/backup-manager", status_code=303)


@router.post("/docker/{workload_id}/backup")
def queue_docker_backup(
    request: Request,
    workload_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    row = db.get(ComputeWorkload, workload_id)
    if not row or row.kind != "container" or not row.host or row.host.platform != "docker_agent":
        raise HTTPException(404, "Docker Agent container not found")
    if not agent_supports_docker_backups(row.host):
        raise HTTPException(400, "Docker Agent must be updated before it can run backups")
    job = create_docker_job(db, row, "backup", user.id)
    db.commit()
    write_audit(db, user, "queue_backup", "backup_job", str(job.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse("/infrastructure/backup-manager", status_code=303)


@router.post("/docker/{workload_id}/restore")
def queue_docker_restore(
    request: Request,
    workload_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    row = db.get(ComputeWorkload, workload_id)
    if not row or row.kind != "container" or not row.host or row.host.platform != "docker_agent":
        raise HTTPException(404, "Docker Agent container not found")
    if not agent_supports_docker_backups(row.host):
        raise HTTPException(400, "Docker Agent must be updated before it can run restores")
    source_job = latest_successful_backup(db, row.id)
    if not source_job:
        raise HTTPException(400, "No successful encrypted backup is available to restore")
    job = create_docker_job(db, row, "restore", user.id, source_job=source_job)
    db.commit()
    write_audit(db, user, "queue_restore", "backup_job", str(job.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse("/infrastructure/backup-manager", status_code=303)


@router.get("/api/agent/jobs")
def agent_jobs(request: Request, db: Session = Depends(get_db)):
    host = require_agent_host(request, db)
    jobs = (
        db.query(BackupJob)
        .filter(BackupJob.host_id == host.id, BackupJob.status == "queued")
        .order_by(BackupJob.created_at.asc())
        .limit(5)
        .all()
    )
    now = datetime.utcnow()
    response = []
    for job in jobs:
        job.status = "dispatched"
        job.dispatched_at = now
        job.updated_at = now
        job_metadata = metadata(job.metadata_json)
        response.append(
            {
                "id": job.id,
                "operation": job.operation,
                "container": job.workload.name if job.workload else job_metadata.get("container"),
                "external_id": job.workload.external_id if job.workload else job_metadata.get("external_id"),
                "policy": job_metadata.get("policy"),
                "target": backup_target_payload(db),
                "encryption": {
                    "enabled": job.encryption_enabled,
                    "mode": "agent-aes-256-gcm",
                    "key": decrypt_secret(job.encrypted_backup_key) if job.encrypted_backup_key else "",
                },
                "source_artifact": job_metadata.get("source_artifact"),
                "source_size_bytes": job_metadata.get("source_size_bytes"),
            }
        )
    db.commit()
    return {"ok": True, "jobs": response}


@router.post("/api/agent/jobs/{job_id}/status")
async def agent_job_status(job_id: int, request: Request, db: Session = Depends(get_db)):
    host = require_agent_host(request, db)
    job = db.get(BackupJob, job_id)
    if not job or job.host_id != host.id:
        raise HTTPException(404, "Backup job not found")
    payload = await request.json()
    status = str(payload.get("status") or "").strip().lower()
    if status not in {"queued", "dispatched", "running", "successful", "failed"}:
        raise HTTPException(400, "Invalid backup job status")
    now = datetime.utcnow()
    job.status = status
    job.updated_at = now
    if status == "running" and not job.started_at:
        job.started_at = now
    if status in {"successful", "failed"}:
        job.finished_at = now
    if payload.get("artifact_path"):
        job.artifact_path = str(payload["artifact_path"])[:1000]
    if payload.get("size_bytes") is not None:
        try:
            job.size_bytes = int(payload["size_bytes"])
        except (TypeError, ValueError):
            job.size_bytes = None
    if payload.get("error"):
        job.error = str(payload["error"])[:2000]
    if payload.get("log"):
        job.log = str(payload["log"])[:10000]
    if isinstance(payload.get("metadata"), dict):
        existing = metadata(job.metadata_json)
        existing.update(payload["metadata"])
        job.metadata_json = json.dumps(existing)
    db.commit()
    return JSONResponse({"ok": True, "job": job.id, "status": job.status})
