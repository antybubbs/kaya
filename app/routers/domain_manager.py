import json
from datetime import datetime, time

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from app.core.config import get_settings
from sqlalchemy.orm import Session
from starlette import status

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import DomainRecord, DomainRecordHistory
from app.routers.auth import require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.domain_lookup import lookup_domain, normalize_domain
from app.services.domain_polling import (
    get_poll_cadence,
    poll_domain,
    set_poll_cadence,
)

router = APIRouter(prefix="/networking/domain-manager", dependencies=[Depends(require_module_access("domain_manager"))])
templates = Jinja2Templates(directory="app/templates")


def json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def json_dict(value: str | None) -> dict[str, list[str]]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def history_changes(value: str | None) -> list[dict]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def clean_lines(value: str) -> list[str]:
    lines = []
    for line in value.replace(",", "\n").splitlines():
        clean = line.strip().lower().rstrip(".")
        if clean and clean not in lines:
            lines.append(clean)
    return lines


def parse_expiry(value: str) -> datetime | None:
    if not value:
        return None
    return datetime.combine(datetime.strptime(value, "%Y-%m-%d").date(), time.min)


def expiry_state(record: DomainRecord) -> str:
    expires_at = display_expires_at(record)
    if not expires_at:
        return "unknown"
    days = (expires_at.date() - datetime.utcnow().date()).days
    if days < 0:
        return "expired"
    if days <= 30:
        return "soon"
    return "healthy"


def save_lookup(record: DomainRecord, data: dict) -> None:
    record.lookup_registrar = data.get("registrar")
    record.lookup_dns_provider = data.get("dns_provider")
    record.lookup_status = data.get("status")
    record.lookup_expires_at = data.get("expires_at")
    record.lookup_nameservers = json.dumps(data.get("nameservers") or [])
    record.dns_records = json.dumps(data.get("dns_records") or {})
    record.lookup_error = data.get("lookup_error")
    record.last_lookup_at = data.get("last_lookup_at")


def display_registrar(record: DomainRecord) -> str | None:
    return record.registrar or record.lookup_registrar


def display_dns_provider(record: DomainRecord) -> str | None:
    return record.dns_provider or record.lookup_dns_provider


def display_status(record: DomainRecord) -> str | None:
    return record.status or record.lookup_status


def display_expires_at(record: DomainRecord) -> datetime | None:
    return record.expires_at or record.lookup_expires_at


def display_nameservers(record: DomainRecord) -> list[str]:
    return json_list(record.nameservers) or json_list(record.lookup_nameservers)


def context(**extra):
    return {
        **extra,
        "json_list": json_list,
        "json_dict": json_dict,
        "history_changes": history_changes,
        "expiry_state": expiry_state,
        "display_registrar": display_registrar,
        "display_dns_provider": display_dns_provider,
        "display_status": display_status,
        "display_expires_at": display_expires_at,
        "display_nameservers": display_nameservers,
    }


@router.get("")
def list_domains(request: Request, q: str = Query("", max_length=200), db: Session = Depends(get_db), user=Depends(require_user)):
    query = db.query(DomainRecord)
    clean_q = q.strip()
    if clean_q:
        like = f"%{clean_q}%"
        query = query.filter(
            or_(
                DomainRecord.name.ilike(like),
                DomainRecord.registrar.ilike(like),
                DomainRecord.dns_provider.ilike(like),
                DomainRecord.status.ilike(like),
                DomainRecord.notes.ilike(like),
            )
        )
    rows = query.order_by(DomainRecord.expires_at.is_(None), DomainRecord.expires_at.asc(), DomainRecord.name.asc()).limit(500).all()
    poll_cadence = get_poll_cadence(db)
    return templates.TemplateResponse(
        request,
        "domain_manager.html",
        context(user=user, rows=rows, total=db.query(DomainRecord).count(), q=clean_q, poll_cadence=poll_cadence, **csrf_context(request)),
    )


@router.post("/poll-cadence")
def update_poll_cadence(
    request: Request,
    cadence: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    try:
        set_poll_cadence(db, cadence)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    write_audit(db, user, "update", "domain_poll_cadence", None, request.client.host if request.client else None, detail=cadence)
    return RedirectResponse("/networking/domain-manager", status_code=303)


@router.get("/new")
def new_domain(request: Request, user=Depends(require_editor)):
    return templates.TemplateResponse(request, "domain_form.html", context(user=user, record=None, error=None, **csrf_context(request)))


@router.post("/new")
def create_domain(
    request: Request,
    name: str = Form(..., max_length=255),
    registrar: str = Form("", max_length=255),
    dns_provider: str = Form("", max_length=255),
    status_value: str = Form("", max_length=120),
    expires_at: str = Form(""),
    auto_renew: str = Form(""),
    nameservers: str = Form("", max_length=5000),
    notes: str = Form("", max_length=10000),
    lookup_now: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    try:
        clean_name = normalize_domain(name)
    except ValueError as exc:
        return templates.TemplateResponse(request, "domain_form.html", context(user=user, record=None, error=str(exc), **csrf_context(request)), status_code=400)
    if db.query(DomainRecord).filter(DomainRecord.name == clean_name).first():
        return templates.TemplateResponse(request, "domain_form.html", context(user=user, record=None, error="That domain already exists.", **csrf_context(request)), status_code=400)
    record = DomainRecord(
        name=clean_name,
        registrar=registrar.strip() or None,
        dns_provider=dns_provider.strip() or None,
        status=status_value.strip() or None,
        expires_at=parse_expiry(expires_at),
        auto_renew=bool(auto_renew),
        nameservers=json.dumps(clean_lines(nameservers)),
        notes=notes.strip() or None,
    )
    if lookup_now and not get_settings().demo_mode:
        save_lookup(record, lookup_domain(clean_name))
    db.add(record)
    db.commit()
    write_audit(db, user, "create", "domain", str(record.id), request.client.host if request.client else None, detail=record.name)
    return RedirectResponse(f"/networking/domain-manager/{record.id}", status_code=303)


@router.get("/{record_id}")
def detail_domain(request: Request, record_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    record = db.get(DomainRecord, record_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
    history = db.query(DomainRecordHistory).filter(
        DomainRecordHistory.domain_id == record.id
    ).order_by(DomainRecordHistory.checked_at.desc()).limit(100).all()
    return templates.TemplateResponse(request, "domain_detail.html", context(user=user, record=record, history=history, **csrf_context(request)))


@router.get("/{record_id}/edit")
def edit_domain(request: Request, record_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    record = db.get(DomainRecord, record_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
    return templates.TemplateResponse(request, "domain_form.html", context(user=user, record=record, error=None, **csrf_context(request)))


@router.post("/{record_id}/edit")
def update_domain(
    request: Request,
    record_id: int,
    name: str = Form(..., max_length=255),
    registrar: str = Form("", max_length=255),
    dns_provider: str = Form("", max_length=255),
    status_value: str = Form("", max_length=120),
    expires_at: str = Form(""),
    auto_renew: str = Form(""),
    nameservers: str = Form("", max_length=5000),
    notes: str = Form("", max_length=10000),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    record = db.get(DomainRecord, record_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
    try:
        clean_name = normalize_domain(name)
    except ValueError as exc:
        return templates.TemplateResponse(request, "domain_form.html", context(user=user, record=record, error=str(exc), **csrf_context(request)), status_code=400)
    existing = db.query(DomainRecord).filter(DomainRecord.name == clean_name, DomainRecord.id != record.id).first()
    if existing:
        return templates.TemplateResponse(request, "domain_form.html", context(user=user, record=record, error="That domain already exists.", **csrf_context(request)), status_code=400)
    record.name = clean_name
    record.registrar = registrar.strip() or None
    record.dns_provider = dns_provider.strip() or None
    record.status = status_value.strip() or None
    record.expires_at = parse_expiry(expires_at)
    record.auto_renew = bool(auto_renew)
    record.nameservers = json.dumps(clean_lines(nameservers))
    record.notes = notes.strip() or None
    record.updated_at = datetime.utcnow()
    db.commit()
    write_audit(db, user, "update", "domain", str(record.id), request.client.host if request.client else None, detail=record.name)
    return RedirectResponse(f"/networking/domain-manager/{record.id}", status_code=303)


@router.post("/{record_id}/lookup")
def refresh_domain(request: Request, record_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    record = db.get(DomainRecord, record_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
    poll_domain(db, record, source="manual")
    write_audit(db, user, "lookup", "domain", str(record.id), request.client.host if request.client else None, detail=record.name)
    return RedirectResponse(f"/networking/domain-manager/{record.id}", status_code=303)


@router.post("/{record_id}/delete")
def delete_domain(request: Request, record_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    record = db.get(DomainRecord, record_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")
    name = record.name
    db.query(DomainRecordHistory).filter(
        DomainRecordHistory.domain_id == record.id
    ).update({DomainRecordHistory.domain_id: None}, synchronize_session=False)
    db.delete(record)
    db.commit()
    write_audit(db, user, "delete", "domain", None, request.client.host if request.client else None, detail=name)
    return RedirectResponse("/networking/domain-manager", status_code=303)
