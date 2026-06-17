from ipaddress import ip_address
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette import status
from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import IPAddress, NetworkMonitor, RemoteAccess, VLAN
from app.routers.auth import require_editor, require_user
from app.routers.remote_manager import RDP_SETTING_KEYS, SETTINGS as REMOTE_MANAGER_DEFAULTS, TERMINAL_SETTING_KEYS, clean_global_setting, decode_settings_blob, encode_settings_blob
from app.services.audit import write_audit
from app.services.custom_fields import active_fields, field_values, option_list, save_custom_values, validate_custom_values
from app.services.managed_lists import list_values
from app.services.network_monitor import clamp_interval, clamp_timeout, ping_ipv4

router = APIRouter(prefix="/ip-addresses")
templates = Jinja2Templates(directory="app/templates")
ASSIGNMENT_TYPES = {"Static", "Dynamic"}
REMOTE_PROTOCOLS = {"ssh", "rdp"}


def clean_ip(value: str) -> str:
    value = value.strip()
    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter a valid IP address.") from exc


def clean_assignment_type(value: str) -> str:
    return value if value in ASSIGNMENT_TYPES else "Static"


def ip_sort_key(row: IPAddress) -> tuple[int, int]:
    parsed = ip_address(row.address)
    return (parsed.version, int(parsed))


def get_default_vlan(db: Session) -> VLAN:
    vlan = db.query(VLAN).filter(VLAN.name == "VLAN 1").first()
    if vlan:
        return vlan
    vlan = VLAN(name="VLAN 1")
    db.add(vlan)
    db.commit()
    db.refresh(vlan)
    return vlan


def clean_category(value: str, allowed: list[str], current: str | None = None) -> str | None:
    clean = value.strip()
    if clean in allowed or (current and clean == current):
        return clean
    return None


def monitor_for(db: Session, record_id: int | None) -> NetworkMonitor | None:
    if not record_id:
        return None
    return db.query(NetworkMonitor).filter(NetworkMonitor.ip_address_id == record_id).first()


def save_monitor_settings(db: Session, record: IPAddress, enabled: bool, display_name: str, interval_seconds: int, timeout_ms: int) -> None:
    monitor = monitor_for(db, record.id)
    if not enabled:
        if monitor:
            monitor.is_enabled = False
        return
    if not monitor:
        monitor = NetworkMonitor(ip_address_id=record.id, check_type="icmp")
        db.add(monitor)
    monitor.display_name = display_name.strip() or None
    monitor.is_enabled = True
    monitor.interval_seconds = clamp_interval(interval_seconds)
    monitor.timeout_ms = clamp_timeout(timeout_ms)


def remote_for(db: Session, record_id: int | None) -> RemoteAccess | None:
    if not record_id:
        return None
    return db.query(RemoteAccess).filter(RemoteAccess.ip_address_id == record_id).first()


def clean_remote_protocol(value: str) -> str:
    value = value.lower().strip()
    return value if value in REMOTE_PROTOCOLS else "ssh"


def clean_remote_port(value: int, protocol: str) -> int:
    if 1 <= value <= 65535:
        return value
    return 3389 if protocol == "rdp" else 22


def remote_override_settings(form, keys: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in keys:
        value = str(form.get(f"override_{key}", ""))
        if value == "":
            continue
        values[key] = clean_global_setting(key, value)
    return values


def save_remote_settings(db: Session, record: IPAddress, enabled: bool, display_name: str, protocol: str, port: int, username: str, terminal_settings: dict[str, str] | None = None, rdp_settings: dict[str, str] | None = None) -> None:
    remote = remote_for(db, record.id)
    if not enabled:
        if remote:
            remote.is_enabled = False
        return
    protocol = clean_remote_protocol(protocol)
    if not remote:
        remote = RemoteAccess(ip_address_id=record.id)
        db.add(remote)
    remote.display_name = display_name.strip() or None
    remote.is_enabled = True
    remote.protocol = protocol
    remote.port = clean_remote_port(port, protocol)
    remote.username = username.strip() or None
    remote.terminal_settings = encode_settings_blob(terminal_settings or {})
    remote.rdp_settings = encode_settings_blob(rdp_settings or {})


def remote_settings_context(remote: RemoteAccess | None) -> dict:
    terminal_overrides = decode_settings_blob(remote.terminal_settings if remote else None)
    rdp_overrides = decode_settings_blob(remote.rdp_settings if remote else None)
    return {
        "remote_terminal_setting_keys": TERMINAL_SETTING_KEYS,
        "remote_rdp_setting_keys": RDP_SETTING_KEYS,
        "remote_defaults": REMOTE_MANAGER_DEFAULTS,
        "remote_terminal_overrides": {key: clean_global_setting(key, value) for key, value in terminal_overrides.items()},
        "remote_rdp_overrides": {key: clean_global_setting(key, value) for key, value in rdp_overrides.items()},
    }


@router.get("")
def list_ip_addresses(request: Request, q: str = Query("", max_length=200), category: str = Query("", max_length=120), db: Session = Depends(get_db), user=Depends(require_user)):
    query = db.query(IPAddress)
    categories = list_values(db, MODULE).get("category", [])
    active_category = category.strip()
    if active_category:
        query = query.filter(IPAddress.category == active_category)
    clean_q = q.strip()
    if clean_q:
        like = f"%{clean_q}%"
        query = query.filter(or_(IPAddress.address.ilike(like), IPAddress.category.ilike(like), IPAddress.name.ilike(like), IPAddress.description.ilike(like), IPAddress.assignment_type.ilike(like), IPAddress.notes.ilike(like)))
    rows = sorted(query.limit(500).all(), key=ip_sort_key)
    total = db.query(IPAddress).count()
    return templates.TemplateResponse(request, "ip_addresses.html", {"user": user, "rows": rows, "total": total, "q": clean_q, "categories": categories, "active_category": active_category, **csrf_context(request)})


MODULE = "ip_addresses"
ENTITY_TYPE = "ip_address"
BULK_NO_CHANGE = "__no_change__"
BULK_CLEAR = "__clear__"


@router.post("/bulk-update")
def bulk_update_ip_addresses(
    request: Request,
    selected_ids: list[int] = Form(...),
    category: str = Form(BULK_NO_CHANGE, max_length=120),
    assignment_type: str = Form(BULK_NO_CHANGE),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    ids = sorted({record_id for record_id in selected_ids if record_id > 0})[:500]
    if not ids:
        return RedirectResponse("/ip-addresses", status_code=303)
    categories = list_values(db, MODULE).get("category", [])
    category_value: str | None = None
    update_category = category != BULK_NO_CHANGE
    if update_category:
        if category == BULK_CLEAR:
            category_value = None
        elif category in categories:
            category_value = category
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a valid category.")
    update_assignment = assignment_type != BULK_NO_CHANGE
    if update_assignment and assignment_type not in ASSIGNMENT_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose Static or Dynamic.")
    if not update_category and not update_assignment:
        return RedirectResponse("/ip-addresses", status_code=303)
    rows = db.query(IPAddress).filter(IPAddress.id.in_(ids)).all()
    for row in rows:
        if update_category:
            row.category = category_value
        if update_assignment:
            row.assignment_type = assignment_type
    db.commit()
    fields = []
    if update_category:
        fields.append(f"category={category_value or 'blank'}")
    if update_assignment:
        fields.append(f"assignment_type={assignment_type}")
    write_audit(
        db,
        user,
        "bulk_update",
        "ip_address",
        ",".join(str(row.id) for row in rows),
        request.client.host if request.client else None,
        detail=f"Updated {len(rows)} IP addresses: {', '.join(fields)}",
    )
    return RedirectResponse("/ip-addresses", status_code=303)


@router.post("/{record_id}/ping")
def ping_ip_address(request: Request, record_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    row = db.get(IPAddress, record_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")
    ok, latency_ms, error = ping_ipv4(row.address, 2000)
    write_audit(
        db,
        user,
        "ping",
        "ip_address",
        str(row.id),
        request.client.host if request.client else None,
        detail=f"{row.address} {'up' if ok else 'down'}{f' {latency_ms}ms' if latency_ms is not None else ''}{f': {error}' if error else ''}",
    )
    return JSONResponse({
        "ok": ok,
        "status": "up" if ok else "down",
        "latency_ms": latency_ms,
        "error": error,
    })


@router.get("/new")
def new_ip_address(request: Request, vlan_id: int | None = Query(None), db: Session = Depends(get_db), user=Depends(require_editor)):
    fields = active_fields(db, MODULE)
    categories = list_values(db, MODULE).get("category", [])
    return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": None, "monitor": None, "remote": None, "categories": categories, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": {}, "option_list": option_list, "error": None, **remote_settings_context(None), **csrf_context(request)})


@router.post("/new")
async def create_ip_address(request: Request, address: str = Form(..., max_length=80), category: str = Form("", max_length=120), name: str = Form("", max_length=255), description: str = Form("", max_length=5000), assignment_type: str = Form("Static"), monitor_enabled: str = Form(""), monitor_display_name: str = Form("", max_length=255), monitor_interval_seconds: int = Form(300), monitor_timeout_ms: int = Form(2000), remote_enabled: str = Form(""), remote_display_name: str = Form("", max_length=255), remote_protocol: str = Form("ssh"), remote_port: int = Form(22), remote_username: str = Form("", max_length=120), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    clean_address = clean_ip(address)
    selected_vlan = get_default_vlan(db)
    fields = active_fields(db, MODULE)
    categories = list_values(db, MODULE).get("category", [])
    form = await request.form()
    custom_error = validate_custom_values(fields, form)
    if custom_error:
        return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": None, "monitor": None, "remote": None, "categories": categories, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": {}, "option_list": option_list, "error": custom_error, **remote_settings_context(None), **csrf_context(request)}, status_code=400)
    if db.query(IPAddress).filter(IPAddress.address == clean_address).first():
        return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": None, "monitor": None, "remote": None, "categories": categories, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": {}, "option_list": option_list, "error": "That IP address already exists.", **remote_settings_context(None), **csrf_context(request)}, status_code=400)
    row = IPAddress(vlan_id=selected_vlan.id, address=clean_address, category=clean_category(category, categories), name=name.strip() or None, description=description.strip() or None, assignment_type=clean_assignment_type(assignment_type), notes=notes.strip() or None)
    db.add(row)
    db.commit()
    save_monitor_settings(db, row, bool(monitor_enabled), monitor_display_name, monitor_interval_seconds, monitor_timeout_ms)
    save_remote_settings(db, row, bool(remote_enabled), remote_display_name, remote_protocol, remote_port, remote_username, remote_override_settings(form, TERMINAL_SETTING_KEYS), remote_override_settings(form, RDP_SETTING_KEYS))
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    db.commit()
    write_audit(db, user, "create", "ip_address", str(row.id), request.client.host if request.client else None, detail=clean_address)
    return RedirectResponse("/ip-addresses", status_code=303)


@router.get("/{record_id}")
def detail_ip_address(request: Request, record_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = db.get(IPAddress, record_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    categories = list_values(db, MODULE).get("category", [])
    return templates.TemplateResponse(request, "ip_address_detail.html", {"user": user, "record": row, "monitor": monitor_for(db, row.id), "remote": remote_for(db, row.id), "categories": categories, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": values, "option_list": option_list, **remote_settings_context(remote_for(db, row.id)), **csrf_context(request)})


@router.get("/{record_id}/edit")
def edit_ip_address(request: Request, record_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    row = db.get(IPAddress, record_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    categories = list_values(db, MODULE).get("category", [])
    remote = remote_for(db, row.id)
    return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": row, "monitor": monitor_for(db, row.id), "remote": remote, "categories": categories, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": values, "option_list": option_list, "error": None, **remote_settings_context(remote), **csrf_context(request)})


@router.post("/{record_id}/edit")
async def update_ip_address(request: Request, record_id: int, address: str = Form(..., max_length=80), category: str = Form("", max_length=120), name: str = Form("", max_length=255), description: str = Form("", max_length=5000), assignment_type: str = Form("Static"), monitor_enabled: str = Form(""), monitor_display_name: str = Form("", max_length=255), monitor_interval_seconds: int = Form(300), monitor_timeout_ms: int = Form(2000), remote_enabled: str = Form(""), remote_display_name: str = Form("", max_length=255), remote_protocol: str = Form("ssh"), remote_port: int = Form(22), remote_username: str = Form("", max_length=120), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(IPAddress, record_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")
    clean_address = clean_ip(address)
    selected_vlan = get_default_vlan(db)
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    categories = list_values(db, MODULE).get("category", [])
    form = await request.form()
    custom_error = validate_custom_values(fields, form)
    if custom_error:
        remote = remote_for(db, row.id)
        return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": row, "monitor": monitor_for(db, row.id), "remote": remote, "categories": categories, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": values, "option_list": option_list, "error": custom_error, **remote_settings_context(remote), **csrf_context(request)}, status_code=400)
    existing = db.query(IPAddress).filter(IPAddress.address == clean_address, IPAddress.id != row.id).first()
    if existing:
        remote = remote_for(db, row.id)
        return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": row, "monitor": monitor_for(db, row.id), "remote": remote, "categories": categories, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": values, "option_list": option_list, "error": "That IP address already exists.", **remote_settings_context(remote), **csrf_context(request)}, status_code=400)
    row.vlan_id = selected_vlan.id
    row.address = clean_address
    row.category = clean_category(category, categories, row.category)
    row.name = name.strip() or None
    row.description = description.strip() or None
    row.assignment_type = clean_assignment_type(assignment_type)
    row.notes = notes.strip() or None
    db.commit()
    save_monitor_settings(db, row, bool(monitor_enabled), monitor_display_name, monitor_interval_seconds, monitor_timeout_ms)
    save_remote_settings(db, row, bool(remote_enabled), remote_display_name, remote_protocol, remote_port, remote_username, remote_override_settings(form, TERMINAL_SETTING_KEYS), remote_override_settings(form, RDP_SETTING_KEYS))
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    db.commit()
    write_audit(db, user, "update", "ip_address", str(row.id), request.client.host if request.client else None, detail=clean_address)
    return RedirectResponse(f"/ip-addresses/{row.id}", status_code=303)
