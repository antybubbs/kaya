"""Administrator-only Data Integrity workspace: audits, findings and remediation.

Every route requires the Administrator role (``require_admin``) and every
mutation validates the CSRF header. A finding is visible only when the
administrator can open every module it describes; others return 404. Data
changes additionally require the ``data_integrity.repair`` capability, which
is never sufficient without the Administrator role.
"""
from __future__ import annotations

from datetime import datetime
import json
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.csrf import csrf_context, validate_csrf_token
from app.core.templating import templates
from app.db.session import get_db
from app.models.models import DataIntegrityFindingEvent, DataIntegrityRun, User
from app.routers.auth import require_admin
from app.services.audit import write_audit
from app.services.client_ip import client_ip as trusted_client_ip
from app.services.data_integrity import (
    ACTIVE_STATUSES,
    EXPORT_COLUMNS,
    PAGE_SIZES,
    SCHEDULE_CHOICES,
    STATUS_LABELS,
    AuditAlreadyRunning,
    FindingFilters,
    _run_payload,
    export_findings,
    export_record,
    finding_evidence,
    finding_row,
    finding_subject,
    history,
    ignore_finding,
    list_findings,
    queue_audit,
    reopen_finding,
    revalidate_finding,
    schedule_settings,
    summary,
    update_schedule,
    visible_finding,
    visible_types,
)
from app.services.data_integrity_checks import CATEGORY_LABELS, FINDING_TYPES, detect_subject
from app.services.data_integrity_repairs import (
    ACKNOWLEDGEMENTS,
    ACTIONS,
    MAX_BULK,
    RepairRefused,
    StaleRepair,
    acknowledge_finding,
    can_repair,
    execute_bulk,
    execute_repair,
    preview_bulk,
    preview_repair,
)
from app.services.modules import has_module_access
from app.services.table_export import table_export_response

PAGE_PATH = "/data/data-integrity"
page_router = APIRouter()
router = APIRouter(prefix="/api/data-integrity")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepairParams(_Strict):
    owner_asset_id: int | None = Field(None, ge=1)
    keep_assignment_id: int | None = Field(None, ge=1)
    hostname: str | None = Field(None, min_length=1, max_length=255)


class PreviewPayload(_Strict):
    action: str = Field(..., min_length=1, max_length=40)
    params: RepairParams = Field(default_factory=RepairParams)


class RepairPayload(PreviewPayload):
    preview_token: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    confirmation: str | None = Field(None, max_length=120)


class IgnorePayload(_Strict):
    reason: str = Field(..., min_length=1, max_length=500)


class AcknowledgePayload(_Strict):
    acknowledgement: str = Field(..., min_length=1, max_length=40)
    note: str | None = Field(None, max_length=300)


class BulkPreviewPayload(_Strict):
    finding_ids: list[int] = Field(..., min_length=1, max_length=MAX_BULK)


class BulkItem(_Strict):
    finding_id: int = Field(..., ge=1)
    preview_token: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class BulkRepairPayload(_Strict):
    items: list[BulkItem] = Field(..., min_length=1, max_length=MAX_BULK)
    confirmation: str | None = Field(None, max_length=40)


class SchedulePayload(_Strict):
    schedule_hours: str = Field(..., max_length=4)
    notify_critical: bool


def _csrf(request: Request) -> None:
    validate_csrf_token(request, request.headers.get("x-csrf-token"))


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def _jsonable(value):
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return _iso(value)


def _finding_or_404(db: Session, user: User, finding_id: int):
    finding = visible_finding(db, user, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding


def _links(db: Session, user: User, evidence: dict) -> list[dict]:
    links = []
    assets = {}
    for key in ("asset", "linked_asset"):
        if (evidence.get(key) or {}).get("asset_id"):
            assets[evidence[key]["asset_id"]] = evidence[key]
    for row in evidence.get("owners", []) + evidence.get("mac_owners", []) + evidence.get("assignments", []):
        if row.get("asset_id"):
            assets.setdefault(row["asset_id"], row)
    if has_module_access(db, user, "asset_manager"):
        for asset_id, info in list(assets.items())[:6]:
            links.append({"label": f"Asset {info.get('asset_tag') or info.get('asset_name') or asset_id}", "href": f"/infrastructure/asset-manager/{int(asset_id)}"})
    record = evidence.get("record") or {}
    if record.get("ip_address_id") and has_module_access(db, user, "vlan_ip_manager"):
        links.append({"label": f"IP record {record.get('address')}", "href": f"/networking/vlan-ip-manager/{int(record['ip_address_id'])}"})
    client = evidence.get("dns_client") or {}
    if client.get("dns_client_id") and has_module_access(db, user, "dns_manager"):
        links.append({"label": "DNS client", "href": f"/networking/dns-manager/clients/{int(client['dns_client_id'])}"})
    return links


def _detail(db: Session, user: User, finding) -> dict:
    definition = FINDING_TYPES[finding.finding_type]
    current = detect_subject(db, finding.finding_type, finding_subject(finding))
    events = db.query(DataIntegrityFindingEvent).filter(DataIntegrityFindingEvent.finding_id == finding.id).order_by(
        DataIntegrityFindingEvent.id.desc()
    ).limit(25).all()
    actors = {row.id: row for row in db.query(User).filter(User.id.in_({event.actor_id for event in events if event.actor_id} or {-1}))}
    evidence = finding_evidence(finding)
    repair_allowed = can_repair(db, user)
    db.rollback()
    return _jsonable({
        **finding_row(finding),
        "why": definition.why,
        "recommendation": definition.recommendation,
        "consequence": definition.consequence,
        "evidence": evidence,
        "mac": finding.mac, "ip_address": finding.ip_address, "hostname": finding.hostname,
        "ignore_reason": finding.ignore_reason, "ignored_at": finding.ignored_at, "resolution": finding.resolution,
        "live": {
            "detected": current is not None,
            "changed_since_audit": bool(current and current.fingerprint != finding.evidence_fingerprint),
            "evidence": current.evidence if current else None,
        },
        "actions": [
            {"key": key, "label": ACTIONS[key].label, "description": ACTIONS[key].description, "high_risk": ACTIONS[key].high_risk}
            for key in definition.actions if finding.repairable and finding.status in ACTIVE_STATUSES
        ],
        "acknowledgements": [{"key": key, "label": ACKNOWLEDGEMENTS[key][1]} for key in definition.acknowledgements if finding.status in ACTIVE_STATUSES],
        "can_repair": repair_allowed,
        "events": [{
            "event": event.event, "created_at": event.created_at,
            "actor": (actors[event.actor_id].email if event.actor_id in actors else None),
            "detail": json.loads(event.detail_json or "{}"),
        } for event in events],
        "links": _links(db, user, evidence),
    })


def _page_url(filters: FindingFilters, page: int, per_page: int) -> str:
    return f"{PAGE_PATH}?" + urlencode({**filters.query_values(), "page": page, "per_page": per_page})


# ------------------------------------------------------------- page


@page_router.get(PAGE_PATH)
def data_integrity_page(request: Request, page: int = Query(1, ge=1, le=100000), per_page: int = Query(25), db: Session = Depends(get_db), user=Depends(require_admin)):
    filters = FindingFilters.from_values(request.query_params)
    listing = list_findings(db, user, filters, page=page, per_page=per_page)
    types = visible_types(db, user)
    context = {
        "user": user,
        "title": "Data Integrity",
        "summary": summary(db, user),
        "listing": listing,
        "filters": filters,
        "type_options": [(key, FINDING_TYPES[key].label) for key in types],
        "category_options": sorted({FINDING_TYPES[key].category for key in types}),
        "category_labels": CATEGORY_LABELS,
        "status_labels": STATUS_LABELS,
        "page_sizes": PAGE_SIZES,
        "schedule": schedule_settings(db),
        "schedule_choices": SCHEDULE_CHOICES,
        "can_repair": can_repair(db, user),
        "max_bulk": MAX_BULK,
        "previous_url": _page_url(filters, listing["page"] - 1, listing["per_page"]) if listing["page"] > 1 else None,
        "next_url": _page_url(filters, listing["page"] + 1, listing["per_page"]) if listing["page"] < listing["pages"] else None,
        "export_query": urlencode(filters.query_values()),
        "sort_url": lambda key: f"{PAGE_PATH}?" + urlencode({**filters.query_values(), "sort": key, "direction": "asc" if filters.sort == key and filters.direction == "desc" else "desc", "per_page": listing["per_page"]}),
        **csrf_context(request),
    }
    return templates.TemplateResponse(request, "data_integrity.html", context)


# ------------------------------------------------------------- read API


@router.get("/summary")
def api_summary(db: Session = Depends(get_db), user=Depends(require_admin)):
    return _jsonable(summary(db, user))


@router.get("/findings")
def api_findings(request: Request, page: int = Query(1, ge=1, le=100000), per_page: int = Query(25), db: Session = Depends(get_db), user=Depends(require_admin)):
    return _jsonable(list_findings(db, user, FindingFilters.from_values(request.query_params), page=page, per_page=per_page))


@router.get("/findings/{finding_id}")
def api_finding(finding_id: int = Path(..., ge=1), db: Session = Depends(get_db), user=Depends(require_admin)):
    return _detail(db, user, _finding_or_404(db, user, finding_id))


@router.get("/audits/current")
def api_current_audit(db: Session = Depends(get_db), user=Depends(require_admin)):
    state = summary(db, user)
    return _jsonable({"active": state["active"], "latest": state["latest"], "last_finished": state["last_finished"], "freshness": state["freshness"]})


@router.get("/history")
def api_history(limit: int = Query(30, ge=1, le=100), db: Session = Depends(get_db), user=Depends(require_admin)):
    return _jsonable(history(db, user, limit=limit))


@router.get("/export")
def api_export(request: Request, format: str = Query("csv", pattern="^(csv|json)$"), db: Session = Depends(get_db), user=Depends(require_admin)):
    filters = FindingFilters.from_values(request.query_params)
    rows = export_findings(db, user, filters)
    write_audit(db, user, "data_integrity_export", "data_integrity_finding", None, trusted_client_ip(request),
                detail=f"Exported {len(rows)} Data Integrity finding(s) as {format.upper()}",
                metadata={"format": format, "rows": len(rows), "filters": sorted(filters.query_values())}, force=True)
    if format == "csv":
        return table_export_response(
            table_name="data-integrity-findings",
            headers=[label for _key, label in EXPORT_COLUMNS],
            rows=([_iso(finding_row(row)[key]) for key, _label in EXPORT_COLUMNS] for row in rows),
            export_format="csv",
        )
    body = json.dumps({"generated_at": datetime.utcnow().isoformat(), "findings": [export_record(row) for row in rows]}, default=str, indent=2)  # noqa: DTZ003
    return Response(body, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="kaya-data-integrity-findings-{datetime.utcnow():%Y-%m-%d}.json"',  # noqa: DTZ003
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    })


# ------------------------------------------------------------- mutations


@router.post("/audits")
def api_run_audit(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    try:
        run = queue_audit(db, user)
    except AuditAlreadyRunning:
        active = db.query(DataIntegrityRun).filter(DataIntegrityRun.active_slot.isnot(None)).first()
        return JSONResponse({"detail": "An audit is already queued or running.", "active": _jsonable(_run_payload(active))}, status_code=409)
    return JSONResponse(_jsonable({"queued": _run_payload(run)}), status_code=202)


@router.post("/findings/{finding_id}/revalidate")
def api_revalidate(request: Request, finding_id: int = Path(..., ge=1), db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    finding = _finding_or_404(db, user, finding_id)
    state = revalidate_finding(db, finding, actor=user)
    write_audit(db, user, "data_integrity_revalidate", "data_integrity_finding", str(finding.id), trusted_client_ip(request),
                detail="Revalidated Data Integrity finding", metadata={"finding_id": finding.id, "detected": state["detected"]}, force=True, commit=False)
    db.commit()
    return _jsonable({"finding": finding_row(finding), **state})


@router.post("/findings/{finding_id}/ignore")
def api_ignore(request: Request, payload: IgnorePayload, finding_id: int = Path(..., ge=1), db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    finding = _finding_or_404(db, user, finding_id)
    try:
        result = ignore_finding(db, finding, user, payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _jsonable({"finding": finding_row(finding), **result})


@router.post("/findings/{finding_id}/reopen")
def api_reopen(request: Request, finding_id: int = Path(..., ge=1), db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    finding = _finding_or_404(db, user, finding_id)
    try:
        result = reopen_finding(db, finding, user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _jsonable({"finding": finding_row(finding), **result})


@router.post("/findings/{finding_id}/acknowledge")
def api_acknowledge(request: Request, payload: AcknowledgePayload, finding_id: int = Path(..., ge=1), db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    finding = _finding_or_404(db, user, finding_id)
    try:
        result = acknowledge_finding(db, user, finding, payload.acknowledgement, payload.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _jsonable({"finding": finding_row(finding), **result})


@router.post("/findings/{finding_id}/preview")
def api_preview(request: Request, payload: PreviewPayload, finding_id: int = Path(..., ge=1), db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    finding = _finding_or_404(db, user, finding_id)
    try:
        result = preview_repair(db, user, finding, payload.action, payload.params.model_dump(exclude_none=True))
    except RepairRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _jsonable({**result, "can_repair": can_repair(db, user)})


@router.post("/findings/{finding_id}/repair")
def api_repair(request: Request, payload: RepairPayload, finding_id: int = Path(..., ge=1), db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    if not can_repair(db, user):
        raise HTTPException(status_code=403, detail="The Data Integrity repair permission is required.")
    _finding_or_404(db, user, finding_id)
    try:
        result = execute_repair(db, user, finding_id, payload.action, payload.params.model_dump(exclude_none=True), payload.preview_token, confirmation=payload.confirmation)
    except StaleRepair as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RepairRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="The repair could not be completed and was rolled back.") from exc
    finding = visible_finding(db, user, finding_id)
    return _jsonable({**result, "finding": finding_row(finding) if finding else None})


@router.post("/bulk/preview")
def api_bulk_preview(request: Request, payload: BulkPreviewPayload, db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    try:
        result = preview_bulk(db, user, payload.finding_ids)
    except RepairRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _jsonable({**result, "can_repair": can_repair(db, user)})


@router.post("/bulk/repair")
def api_bulk_repair(request: Request, payload: BulkRepairPayload, db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    if not can_repair(db, user):
        raise HTTPException(status_code=403, detail="The Data Integrity repair permission is required.")
    try:
        result = execute_bulk(db, user, [item.model_dump() for item in payload.items], confirmation=payload.confirmation)
    except RepairRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _jsonable(result)


@router.post("/settings")
def api_settings(request: Request, payload: SchedulePayload, db: Session = Depends(get_db), user=Depends(require_admin)):
    _csrf(request)
    try:
        return update_schedule(db, user, schedule_hours=payload.schedule_hours, notify_critical=payload.notify_critical)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
