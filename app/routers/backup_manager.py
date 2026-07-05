import json
from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import BackupRecord, ComputeHost, ComputeInventoryItem, ComputeWorkload
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


def backup_target_summary(db: Session) -> str:
    target_type = get_site_setting(db, "backup_storage_type") or "local"
    if target_type == "local":
        return get_site_setting(db, "backup_storage_path") or "/mnt/backups"
    host = get_site_setting(db, "backup_remote_host")
    share = get_site_setting(db, "backup_remote_share")
    return f"{target_type.upper()} {host}{('/' + share) if share else ''}".strip()


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
    return templates.TemplateResponse(
        request,
        "backup_manager.html",
        {
            "user": user,
            "manual_backups": manual_backups,
            "docker_workloads": docker_workloads,
            "proxmox_jobs": proxmox_backup_jobs(db),
            "backup_target": backup_target_summary(db),
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
