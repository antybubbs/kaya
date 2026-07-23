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
from app.models.models import BackupJob, BackupRecord, ComputeHost, ComputeInventoryItem, ComputeWorkload, RemoteManagerSetting
from app.routers.auth import require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.site_settings import get_site_setting

router = APIRouter(prefix="/infrastructure/backup-manager", dependencies=[Depends(require_module_access("backup_manager"))])
templates = Jinja2Templates(directory="app/templates")


def require_backup_user(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    if get_site_setting(db, "backup_manager_enabled") != "1":
        raise HTTPException(status_code=404, detail="Not found")
    return user


def require_backup_editor(request: Request, db: Session = Depends(get_db), user=Depends(require_editor)):
    if get_site_setting(db, "backup_manager_enabled") != "1":
        raise HTTPException(status_code=404, detail="Not found")
    return user


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
    target = default_backup_target(db)
    if target["type"] == "local":
        return target["path"] or "/mnt/backups"
    host = target.get("remote_host") or ""
    share = target.get("remote_share") or ""
    return f"{target['type'].upper()} {host}{('/' + share) if share else ''}".strip()


def configured_backup_targets(db: Session) -> list[dict[str, str]]:
    raw = get_site_setting(db, "backup_targets_json")
    try:
        data = json.loads(raw or "[]")
    except (TypeError, ValueError):
        data = []
    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            key = name.casefold()
            if key in seen:
                continue
            seen.add(key)
            target_type = str(item.get("type") or "local").strip().lower()
            if target_type not in {"local", "smb", "ftp", "sftp"}:
                target_type = "local"
            targets.append(
                {
                    "name": name,
                    "type": target_type,
                    "path": str(item.get("path") or "").strip(),
                    "remote_host": str(item.get("remote_host") or "").strip(),
                    "remote_share": str(item.get("remote_share") or "").strip(),
                    "remote_username": str(item.get("remote_username") or "").strip(),
                    "remote_password_enc": str(item.get("remote_password_enc") or "").strip(),
                }
            )

    if targets:
        return targets

    # Backward-compatible fallback to the single-target settings.
    return [
        {
            "name": "Default",
            "type": (get_site_setting(db, "backup_storage_type") or "local").strip().lower(),
            "path": get_site_setting(db, "backup_storage_path") or "/mnt/backups",
            "remote_host": get_site_setting(db, "backup_remote_host") or "",
            "remote_share": get_site_setting(db, "backup_remote_share") or "",
            "remote_username": get_site_setting(db, "backup_remote_username") or "",
            "remote_password_enc": get_site_setting(db, "backup_remote_password") or "",
        }
    ]


def default_backup_target_name(db: Session, targets: list[dict[str, str]] | None = None) -> str:
    all_targets = targets if targets is not None else configured_backup_targets(db)
    preferred = (get_site_setting(db, "backup_default_target_name") or "").strip()
    if preferred and any(target["name"].casefold() == preferred.casefold() for target in all_targets):
        return preferred
    return all_targets[0]["name"] if all_targets else ""


def backup_target_by_name(db: Session, target_name: str | None) -> dict[str, str]:
    targets = configured_backup_targets(db)
    chosen = (target_name or "").strip()
    if chosen:
        for target in targets:
            if target["name"].casefold() == chosen.casefold():
                return target
    default_name = default_backup_target_name(db, targets)
    for target in targets:
        if target["name"].casefold() == default_name.casefold():
            return target
    return targets[0]


def default_backup_target(db: Session) -> dict[str, str]:
    return backup_target_by_name(db, None)


def backup_target_payload(db: Session, target_name: str | None = None) -> dict:
    target = backup_target_by_name(db, target_name)
    if target["type"] == "ftp":
        raise ValueError("Plaintext FTP backup targets are disabled. Migrate this retained target before running a backup.")
    remote_password = decrypt_secret(target.get("remote_password_enc") or "").strip()
    if not remote_password:
        # Backward-compatible fallback for older single-target installs.
        remote_password = decrypt_secret(get_site_setting(db, "backup_remote_password")).strip()
    return {
        "type": target["type"],
        "path": target["path"] or "/mnt/backups",
        "remote_host": target["remote_host"],
        "remote_share": target["remote_share"],
        "remote_username": target["remote_username"],
        "remote_password": remote_password,
    }


def workload_target_setting_key(workload_id: int) -> str:
    return f"backup_workload_target_{workload_id}"


def load_workload_target_map(db: Session, workload_ids: list[int]) -> dict[int, str]:
    keys = [workload_target_setting_key(workload_id) for workload_id in workload_ids]
    if not keys:
        return {}
    rows = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key.in_(keys)).all()
    mapping: dict[int, str] = {}
    for row in rows:
        if not row.value:
            continue
        try:
            workload_id = int(row.key.rsplit("_", 1)[1])
        except (ValueError, IndexError):
            continue
        mapping[workload_id] = row.value
    return mapping


def set_workload_target(db: Session, workload_id: int, target_name: str) -> None:
    key = workload_target_setting_key(workload_id)
    row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == key).first()
    clean = target_name.strip()
    if not clean:
        if row:
            db.delete(row)
        return
    if not row:
        row = RemoteManagerSetting(key=key)
        db.add(row)
    row.value = clean


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



def backup_contains_restorable_paths(job: BackupJob | None) -> bool:
    if not job:
        return False
    data = metadata(job.metadata_json)
    path_count = data.get("path_count")
    if isinstance(path_count, int):
        return path_count > 0
    paths = data.get("paths")
    if isinstance(paths, list):
        return len(paths) > 0
    # Older jobs may not include path metadata; allow restore attempts.
    return True



def bind_mount_paths(workload: ComputeWorkload) -> list[str]:
    data = metadata(workload.metadata_json)
    mounts = data.get("mounts") if isinstance(data, dict) else None
    if not isinstance(mounts, list):
        return []
    found: set[str] = set()
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        if str(mount.get("Type") or "").strip().lower() != "bind":
            continue
        destination = str(mount.get("Destination") or "").strip().rstrip("/")
        if destination.startswith("/"):
            found.add(destination or "/")
    return sorted(found)


def effective_backup_policy(workload: ComputeWorkload) -> tuple[str | None, list[str], str]:
    raw_policy = (workload.backup_policy or "").strip()
    mode = "explicit"
    if not raw_policy:
        mode = "auto"
    elif raw_policy.lower() in {"full", "auto", "all", "default"}:
        mode = raw_policy.lower()
    else:
        return raw_policy, [], mode

    binds = bind_mount_paths(workload)
    if not binds:
        return None, [], mode
    return f"paths={','.join(binds)}", binds, mode


def backup_policy_mode(value: str | None) -> str:
    clean = (value or "").strip().lower()
    if clean in {"", "auto", "all", "full", "default"}:
        return "full"
    if clean in {"volumes", "volumes-only", "named-volumes"}:
        return "volumes"
    if clean.startswith("paths="):
        return "custom"
    return "custom"


def backup_policy_paths(value: str | None) -> str:
    clean = (value or "").strip()
    if clean.lower().startswith("paths="):
        return clean.split("=", 1)[1]
    return ""


def create_docker_job(db: Session, workload: ComputeWorkload, operation: str, user_id: int | None, source_job: BackupJob | None = None) -> BackupJob:
    backup_key = secrets.token_urlsafe(32) if operation == "backup" else None
    policy, auto_bind_paths, policy_mode = effective_backup_policy(workload)
    target_name = load_workload_target_map(db, [workload.id]).get(workload.id) or default_backup_target_name(db)
    payload = {
        "container": workload.name,
        "external_id": workload.external_id,
        "policy": policy,
        "requested_policy": workload.backup_policy,
        "policy_mode": policy_mode,
        "auto_bind_paths": auto_bind_paths,
        "target_name": target_name,
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
        raw_comment = data.get("comment")
        comment = " ".join(raw_comment.split())[:255] if isinstance(raw_comment, str) else ""
        job_id = str(data.get("id") or item.external_id or item.name)[:500]
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
                "name": comment or item.name,
                "job_id": job_id if comment else None,
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
    user=Depends(require_backup_user),
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
    workload_target_map = load_workload_target_map(db, [row.id for row in docker_workloads])
    backup_targets = configured_backup_targets(db)
    default_target_name = default_backup_target_name(db, backup_targets)
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
            "backup_targets": backup_targets,
            "default_target_name": default_target_name,
            "workload_target_map": workload_target_map,
            "backup_policy_mode": backup_policy_mode,
            "backup_policy_paths": backup_policy_paths,
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
    user=Depends(require_backup_editor),
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


@router.post("/manual/{record_id}/delete")
def delete_manual_backup(request: Request, record_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_backup_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(BackupRecord, record_id)
    if not row or row.source_type != "manual":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Manual backup record not found")
    name = row.name
    db.delete(row)
    db.commit()
    write_audit(db, user, "delete", "backup_record", str(record_id), request.client.host if request.client else None, detail=name)
    return RedirectResponse("/infrastructure/backup-manager", status_code=303)


@router.post("/docker/{workload_id}")
def update_docker_backup_policy(
    request: Request,
    workload_id: int,
    backup_policy_mode: str = Form(""),
    backup_policy_paths: str = Form("", max_length=4000),
    backup_policy: str = Form("", max_length=255),
    backup_target_name: str = Form("", max_length=255),
    owner: str = Form("", max_length=255),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_backup_editor),
):
    validate_csrf_token(request, csrf_token)
    row = db.get(ComputeWorkload, workload_id)
    if not row or row.kind != "container":
        raise HTTPException(404, "Docker container not found")
    mode = backup_policy_mode.strip().lower()
    if mode in {"", "full", "auto", "all", "default"}:
        row.backup_policy = "auto"
    elif mode in {"volumes", "volumes-only", "named-volumes"}:
        row.backup_policy = "volumes-only"
    elif mode == "custom":
        raw_paths = backup_policy_paths.replace("\r", "\n").replace(";", ",").replace("\n", ",")
        path_tokens = [token.strip().rstrip("/") or "/" for token in raw_paths.split(",") if token.strip().startswith("/")]
        row.backup_policy = f"paths={','.join(dict.fromkeys(path_tokens))}" if path_tokens else "auto"
    else:
        row.backup_policy = backup_policy.strip() or None
    row.owner = owner.strip() or None
    set_workload_target(db, workload_id, backup_target_name)
    db.commit()
    write_audit(db, user, "update", "docker_backup_policy", str(row.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse("/infrastructure/backup-manager", status_code=303)


@router.post("/docker/{workload_id}/backup")
def queue_docker_backup(
    request: Request,
    workload_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_backup_editor),
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
    user=Depends(require_backup_editor),
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
    if not backup_contains_restorable_paths(source_job):
        raise HTTPException(
            400,
            "Latest backup contains metadata only and no restorable data paths. Run a new backup with blank/full/auto policy.",
        )
    job = create_docker_job(db, row, "restore", user.id, source_job=source_job)
    db.commit()
    write_audit(db, user, "queue_restore", "backup_job", str(job.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse("/infrastructure/backup-manager", status_code=303)


@router.get("/api/agent/jobs")
def agent_jobs(request: Request, db: Session = Depends(get_db)):
    host = require_agent_host(request, db)
    if get_site_setting(db, "backup_manager_enabled") != "1":
        db.commit()
        return {"ok": True, "jobs": []}
    jobs = (
        db.query(BackupJob)
        .filter(BackupJob.host_id == host.id, BackupJob.status == "queued")
        .order_by(BackupJob.created_at.asc())
        .limit(5)
        .all()
    )
    now = datetime.utcnow()
    response = []
    audit_events = []
    for job in jobs:
        job_metadata = metadata(job.metadata_json)
        try:
            target_payload = backup_target_payload(db, job_metadata.get("target_name"))
        except ValueError as exc:
            job.status = "failed"
            job.error = str(exc)
            job.finished_at = now
            job.updated_at = now
            audit_events.append(
                {
                    "action": "dispatch_blocked",
                    "job_id": str(job.id),
                    "detail": "Blocked dispatch to an insecure plaintext FTP backup target",
                    "metadata": {"host_id": host.id, "operation": job.operation, "target_name": job_metadata.get("target_name")},
                }
            )
            continue
        job.status = "dispatched"
        job.dispatched_at = now
        job.updated_at = now
        response.append(
            {
                "id": job.id,
                "operation": job.operation,
                "container": job.workload.name if job.workload else job_metadata.get("container"),
                "external_id": job.workload.external_id if job.workload else job_metadata.get("external_id"),
                "policy": job_metadata.get("policy"),
                "target": target_payload,
                "encryption": {
                    "enabled": job.encryption_enabled,
                    "mode": "agent-aes-256-gcm",
                    "key": decrypt_secret(job.encrypted_backup_key) if job.encrypted_backup_key else "",
                },
                "source_artifact": job_metadata.get("source_artifact"),
                "source_size_bytes": job_metadata.get("source_size_bytes"),
            }
        )
        audit_events.append(
            {
                "action": "dispatch",
                "job_id": str(job.id),
                "detail": f"Dispatched {job.operation} job to agent host {host.name}",
                "metadata": {
                    "host_id": host.id,
                    "host": host.name,
                    "operation": job.operation,
                    "target_name": job_metadata.get("target_name"),
                },
            }
        )
    db.commit()
    for event in audit_events:
        write_audit(
            db,
            None,
            event["action"],
            "backup_job",
            event["job_id"],
            request.client.host if request.client else None,
            detail=event["detail"],
            metadata=event["metadata"],
        )
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
    write_audit(
        db,
        None,
        "agent_status",
        "backup_job",
        str(job.id),
        request.client.host if request.client else None,
        detail=f"Agent host {host.name} reported backup job {job.id} as {job.status}",
        severity="warning" if job.status == "failed" else "info",
        metadata={
            "host_id": host.id,
            "host": host.name,
            "status": job.status,
            "operation": job.operation,
            "artifact_reported": bool(job.artifact_path),
            "size_bytes": job.size_bytes,
        },
    )
    return JSONResponse({"ok": True, "job": job.id, "status": job.status})
