from datetime import datetime, timedelta
from ipaddress import ip_address
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload
from starlette import status
from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import CustomFieldValue, ComputeWorkload, DHCPLeaseHistory, DHCPRange, DNSClientTrafficEvent, DNSRecognisedDevice, IPAddress, NetworkMonitor, NetworkMonitorCheck, NetworkMonitorEvent, NetworkMonitorOutage, NetworkMonitorStatistic, RemoteAccess, RemoteSessionRecording, VLAN
from app.routers.auth import require_editor, require_user
from app.routers.compute_manager import uptime_label, workload_addresses
from app.routers.remote_manager import RDP_SETTING_KEYS, SETTINGS as REMOTE_MANAGER_DEFAULTS, TERMINAL_SETTING_KEYS, clean_global_setting, decode_settings_blob, encode_settings_blob
from app.services.audit import write_audit
from app.services.custom_fields import active_fields, field_values, option_list, save_custom_values, validate_custom_values
from app.services.managed_lists import list_values
from app.services.network_monitor import clamp_interval, clamp_timeout, ping_ipv4
from app.services.dns_clients import add_event, client_display_name, client_status, dhcp_range_for_ip, normalise_mac
from app.services.site_settings import get_site_setting

router = APIRouter(prefix="/networking/vlan-ip-manager")
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


def clean_vlan_filter(value: str) -> int | None:
    return int(value) if value.isdigit() and int(value) > 0 else None


def dns_link_match(client: DNSRecognisedDevice, record: IPAddress) -> tuple[bool, bool]:
    ip_match = bool(client.current_ip and client.current_ip == record.address)
    managed_mac = normalise_mac(record.mac_address)
    mac_match = bool(managed_mac and client.normalised_mac == managed_mac)
    return ip_match, mac_match


def ip_sort_key(row: IPAddress) -> tuple[int, int]:
    parsed = ip_address(row.address)
    return (parsed.version, int(parsed))


def get_default_vlan(db: Session) -> VLAN:
    vlan = db.query(VLAN).order_by(VLAN.id.asc()).first()
    if vlan:
        return vlan
    vlan = VLAN(name="VLAN 1")
    db.add(vlan)
    db.commit()
    db.refresh(vlan)
    return vlan


def resolve_vlan(db: Session, vlan_id: int | None) -> VLAN:
    vlan = db.get(VLAN, vlan_id) if vlan_id else None
    if vlan_id and not vlan:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a valid VLAN.")
    return vlan or get_default_vlan(db)


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
def list_ip_addresses(request: Request, q: str = Query("", max_length=200), category: str = Query("", max_length=120), vlan_id: str = Query("", max_length=20), view: str = Query("managed", max_length=30), db: Session = Depends(get_db), user=Depends(require_user)):
    active_vlan_id = clean_vlan_filter(vlan_id)
    query = db.query(IPAddress).options(joinedload(IPAddress.vlan))
    categories = list_values(db, MODULE).get("category", [])
    vlans = db.query(VLAN).order_by(VLAN.name.asc()).all()
    active_category = category.strip()
    if active_category:
        query = query.filter(IPAddress.category == active_category)
    if active_vlan_id:
        query = query.filter(IPAddress.vlan_id == active_vlan_id)
    clean_q = q.strip()
    if clean_q:
        like = f"%{clean_q}%"
        query = query.outerjoin(VLAN).filter(or_(IPAddress.address.ilike(like), IPAddress.mac_address.ilike(like), IPAddress.category.ilike(like), IPAddress.name.ilike(like), IPAddress.description.ilike(like), IPAddress.assignment_type.ilike(like), IPAddress.notes.ilike(like), VLAN.name.ilike(like)))
    rows = [] if view in {"observed", "leases"} else sorted(query.limit(500).all(), key=ip_sort_key)
    total = db.query(IPAddress).count()
    enrichment_enabled = get_site_setting(db, "dns_vlan_enrichment_enabled") == "1"
    dns_rows = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.linked_ip_record_id.in_([row.id for row in rows])).all() if enrichment_enabled and rows else []
    dns_by_ip = {row.linked_ip_record_id: row for row in dns_rows}
    observed_query = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.linked_ip_record_id.is_(None), DNSRecognisedDevice.is_ignored == False)  # noqa: E712
    observed_total = observed_query.count()
    if clean_q and view == "observed":
        like = f"%{clean_q}%"
        observed_query = observed_query.filter(or_(DNSRecognisedDevice.friendly_name.ilike(like), DNSRecognisedDevice.hostname.ilike(like), DNSRecognisedDevice.current_ip.ilike(like), DNSRecognisedDevice.mac_address.ilike(like), DNSRecognisedDevice.notes.ilike(like)))
    observed_clients = []
    if view == "observed":
        observed_clients = observed_query.options(joinedload(DNSRecognisedDevice.provider), joinedload(DNSRecognisedDevice.suggested_ip_record)).order_by(DNSRecognisedDevice.last_seen_at.desc()).limit(500).all()
    existing_by_address = {row.address: row for row in db.query(IPAddress).filter(IPAddress.address.in_([client.current_ip for client in observed_clients if client.current_ip])).all()} if observed_clients else {}
    leases = []
    if view == "leases":
        lease_query = db.query(DHCPLeaseHistory).options(joinedload(DHCPLeaseHistory.client), joinedload(DHCPLeaseHistory.dhcp_range).joinedload(DHCPRange.vlan))
        if active_vlan_id:
            lease_query = lease_query.join(DHCPRange, DHCPLeaseHistory.dhcp_range_id == DHCPRange.id).filter(DHCPRange.vlan_id == active_vlan_id)
        if clean_q:
            like = f"%{clean_q}%"
            lease_query = lease_query.filter(or_(DHCPLeaseHistory.ip_address.ilike(like), DHCPLeaseHistory.mac_address.ilike(like), DHCPLeaseHistory.hostname.ilike(like)))
        leases = lease_query.order_by(DHCPLeaseHistory.is_active.desc(), DHCPLeaseHistory.last_seen_at.desc()).limit(500).all()
    active_view = view if view in {"observed", "leases"} else "managed"
    return templates.TemplateResponse(request, "ip_addresses.html", {"user": user, "rows": rows, "total": total, "q": clean_q, "categories": categories, "vlans": vlans, "active_vlan_id": active_vlan_id, "active_category": active_category, "active_view": active_view, "leases": leases, "observed_clients": observed_clients, "observed_total": observed_total, "existing_by_address": existing_by_address, "dns_by_ip": dns_by_ip, "dns_enrichment_enabled": enrichment_enabled, "dns_client_status": client_status, "dns_client_display_name": client_display_name, **csrf_context(request)})


MODULE = "ip_addresses"
ENTITY_TYPE = "ip_address"
BULK_NO_CHANGE = "__no_change__"
BULK_CLEAR = "__clear__"


@router.post("/bulk-update")
def bulk_update_ip_addresses(
    request: Request,
    selected_ids: list[int] = Form(...),
    category: str = Form(BULK_NO_CHANGE, max_length=120),
    vlan_id: str = Form(BULK_NO_CHANGE),
    assignment_type: str = Form(BULK_NO_CHANGE),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    ids = sorted({record_id for record_id in selected_ids if record_id > 0})[:500]
    if not ids:
        return RedirectResponse("/networking/vlan-ip-manager", status_code=303)
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
    update_vlan = vlan_id != BULK_NO_CHANGE
    vlan_value = None
    if update_vlan:
        if not vlan_id.isdigit() or not (vlan_value := db.get(VLAN, int(vlan_id))):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a valid VLAN.")
    if not update_category and not update_assignment and not update_vlan:
        return RedirectResponse("/networking/vlan-ip-manager", status_code=303)
    rows = db.query(IPAddress).filter(IPAddress.id.in_(ids)).all()
    for row in rows:
        if update_category:
            row.category = category_value
        if update_assignment:
            row.assignment_type = assignment_type
        if update_vlan:
            row.vlan_id = vlan_value.id
    db.commit()
    fields = []
    if update_category:
        fields.append(f"category={category_value or 'blank'}")
    if update_assignment:
        fields.append(f"assignment_type={assignment_type}")
    if update_vlan:
        fields.append(f"vlan={vlan_value.name}")
    write_audit(
        db,
        user,
        "bulk_update",
        "ip_address",
        ",".join(str(row.id) for row in rows),
        request.client.host if request.client else None,
        detail=f"Updated {len(rows)} IP addresses: {', '.join(fields)}",
    )
    return RedirectResponse("/networking/vlan-ip-manager", status_code=303)


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
def new_ip_address(request: Request, vlan_id: int | None = Query(None), dns_client_id: int | None = Query(None), db: Session = Depends(get_db), user=Depends(require_editor)):
    fields = active_fields(db, MODULE)
    categories = list_values(db, MODULE).get("category", [])
    dns_client = db.get(DNSRecognisedDevice, dns_client_id) if dns_client_id else None
    if dns_client and dns_client.linked_ip_record_id:
        return RedirectResponse(f"/networking/vlan-ip-manager/{dns_client.linked_ip_record_id}", status_code=303)
    vlans = db.query(VLAN).order_by(VLAN.name.asc()).all()
    scope = dhcp_range_for_ip(db, dns_client.current_ip) if dns_client else None
    inferred_vlan_id = vlan_id or (scope.vlan_id if scope else None)
    return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": None, "dns_client": dns_client, "monitor": None, "remote": None, "categories": categories, "vlans": vlans, "selected_vlan_id": resolve_vlan(db, inferred_vlan_id).id, "selected_assignment_type": "Dynamic" if scope else "Static", "dhcp_range": scope, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": {}, "option_list": option_list, "error": None, **remote_settings_context(None), **csrf_context(request)})


@router.post("/new")
async def create_ip_address(request: Request, address: str = Form(..., max_length=80), vlan_id: int | None = Form(None), mac_address: str = Form("", max_length=40), category: str = Form("", max_length=120), name: str = Form("", max_length=255), description: str = Form("", max_length=5000), assignment_type: str = Form("Static"), dns_client_id: int | None = Form(None), monitor_enabled: str = Form(""), monitor_display_name: str = Form("", max_length=255), monitor_interval_seconds: int = Form(300), monitor_timeout_ms: int = Form(2000), remote_enabled: str = Form(""), remote_display_name: str = Form("", max_length=255), remote_protocol: str = Form("ssh"), remote_port: int = Form(22), remote_username: str = Form("", max_length=120), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    clean_address = clean_ip(address)
    selected_vlan = resolve_vlan(db, vlan_id)
    fields = active_fields(db, MODULE)
    categories = list_values(db, MODULE).get("category", [])
    vlans = db.query(VLAN).order_by(VLAN.name.asc()).all()
    form = await request.form()
    custom_error = validate_custom_values(fields, form)
    if custom_error:
        return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": None, "dns_client": None, "monitor": None, "remote": None, "categories": categories, "vlans": vlans, "selected_vlan_id": selected_vlan.id, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": {}, "option_list": option_list, "error": custom_error, **remote_settings_context(None), **csrf_context(request)}, status_code=400)
    if db.query(IPAddress).filter(IPAddress.vlan_id == selected_vlan.id, IPAddress.address == clean_address).first():
        return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": None, "dns_client": None, "monitor": None, "remote": None, "categories": categories, "vlans": vlans, "selected_vlan_id": selected_vlan.id, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": {}, "option_list": option_list, "error": "That IP address already exists in this VLAN.", **remote_settings_context(None), **csrf_context(request)}, status_code=400)
    clean_mac = normalise_mac(mac_address)
    if mac_address.strip() and not clean_mac:
        raise HTTPException(status_code=400, detail="Enter a valid MAC address.")
    row = IPAddress(vlan_id=selected_vlan.id, address=clean_address, mac_address=clean_mac, category=clean_category(category, categories), name=name.strip() or None, description=description.strip() or None, assignment_type=clean_assignment_type(assignment_type), notes=notes.strip() or None)
    db.add(row)
    db.flush()
    dns_client = db.get(DNSRecognisedDevice, dns_client_id) if dns_client_id else None
    if dns_client:
        if dns_client.linked_ip_record_id:
            db.rollback()
            raise HTTPException(status_code=409, detail="This DNS client is already linked to a managed record.")
        dns_client.linked_ip_record_id = row.id
        dns_client.suggested_ip_record_id = None
        dns_client.is_known = True
        dns_client.match_method = "created_from_dns"
        dns_client.match_confidence = 100
        add_event(db, dns_client, "linked_to_ip_record", "Created and linked VLAN/IP record", new=str(row.id))
    db.commit()
    save_monitor_settings(db, row, bool(monitor_enabled), monitor_display_name, monitor_interval_seconds, monitor_timeout_ms)
    save_remote_settings(db, row, bool(remote_enabled), remote_display_name, remote_protocol, remote_port, remote_username, remote_override_settings(form, TERMINAL_SETTING_KEYS), remote_override_settings(form, RDP_SETTING_KEYS))
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    db.commit()
    write_audit(db, user, "create", "ip_address", str(row.id), request.client.host if request.client else None, detail=clean_address, metadata={"dns_client_id": dns_client.id if dns_client else None})
    return RedirectResponse(f"/networking/vlan-ip-manager/{row.id}", status_code=303)


@router.get("/{record_id}")
def detail_ip_address(request: Request, record_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = db.get(IPAddress, record_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    categories = list_values(db, MODULE).get("category", [])
    vlans = db.query(VLAN).order_by(VLAN.name.asc()).all()
    target_address = str(ip_address(row.address))
    compute_matches = [
        workload
        for workload in db.query(ComputeWorkload).filter(ComputeWorkload.status != "missing").all()
        if any(item["address"] == target_address for item in workload_addresses(workload))
    ]
    compute_matches.sort(key=lambda workload: (workload.host.name.lower(), workload.name.lower()))
    dns_enrichment_enabled = get_site_setting(db, "dns_vlan_enrichment_enabled") == "1"
    dns_clients = db.query(DNSRecognisedDevice).filter_by(linked_ip_record_id=row.id).order_by(DNSRecognisedDevice.last_seen_at.desc()).all() if dns_enrichment_enabled else []
    dns_client_ids = [client.id for client in dns_clients]
    lease_conditions = [DHCPLeaseHistory.ip_address == row.address]
    if dns_client_ids:
        lease_conditions.append(DHCPLeaseHistory.dns_client_id.in_(dns_client_ids))
    lease_history = db.query(DHCPLeaseHistory).options(joinedload(DHCPLeaseHistory.dhcp_range)).filter(or_(*lease_conditions)).order_by(DHCPLeaseHistory.last_seen_at.desc()).limit(100).all() if dns_enrichment_enabled else []
    lease_ids = [lease.id for lease in lease_history]
    traffic_conditions = [DNSClientTrafficEvent.client_ip == row.address]
    if lease_ids:
        traffic_conditions.append(DNSClientTrafficEvent.dhcp_lease_id.in_(lease_ids))
    ip_traffic_history = db.query(DNSClientTrafficEvent).filter(or_(*traffic_conditions)).order_by(DNSClientTrafficEvent.observed_at.desc()).limit(8).all() if dns_enrichment_enabled else []
    dns_link_candidates = []
    if dns_enrichment_enabled:
        match_conditions = [DNSRecognisedDevice.current_ip == row.address]
        managed_mac = normalise_mac(row.mac_address)
        if managed_mac:
            match_conditions.append(DNSRecognisedDevice.normalised_mac == managed_mac)
        candidates = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.linked_ip_record_id.is_(None), DNSRecognisedDevice.is_ignored == False, or_(*match_conditions)).order_by(DNSRecognisedDevice.last_seen_at.desc()).all()  # noqa: E712
        dns_link_candidates = [{"client": candidate, "ip_match": dns_link_match(candidate, row)[0], "mac_match": dns_link_match(candidate, row)[1]} for candidate in candidates]
    monitor = monitor_for(db, row.id)
    monitor_observations = None
    if monitor:
        since = datetime.utcnow() - timedelta(hours=24)
        checks = db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.monitor_id == monitor.id, NetworkMonitorCheck.checked_at >= since).order_by(NetworkMonitorCheck.checked_at.desc()).all()
        up = sum(1 for check in checks if check.status == "up")
        latencies = [check.latency_ms for check in checks if check.latency_ms is not None]
        monitor_observations = {
            "checks": checks[:24], "availability": round((up / len(checks)) * 100, 1) if checks else None,
            "average_latency": round(sum(latencies) / len(latencies)) if latencies else None,
            "events": db.query(NetworkMonitorEvent).filter(NetworkMonitorEvent.monitor_id == monitor.id).order_by(NetworkMonitorEvent.occurred_at.desc()).limit(5).all(),
            "outages": db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.monitor_id == monitor.id, NetworkMonitorOutage.started_at >= since).count(),
        }
    return templates.TemplateResponse(request, "ip_address_detail.html", {"user": user, "record": row, "monitor": monitor, "monitor_observations": monitor_observations, "remote": remote_for(db, row.id), "compute_matches": compute_matches, "dns_clients": dns_clients, "dns_link_candidates": dns_link_candidates, "lease_history": lease_history, "ip_traffic_history": ip_traffic_history, "dns_client_status": client_status, "uptime_label": uptime_label, "categories": categories, "vlans": db.query(VLAN).order_by(VLAN.name.asc()).all(), "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": values, "option_list": option_list, **remote_settings_context(remote_for(db, row.id)), **csrf_context(request)})


@router.post("/{record_id}/link-dns-client")
def link_dns_client_to_ip_record(request: Request, record_id: int, dns_client_id: int = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(IPAddress, record_id)
    client = db.get(DNSRecognisedDevice, dns_client_id)
    if not row or not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Managed record or DNS client not found.")
    if client.linked_ip_record_id and client.linked_ip_record_id != row.id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This DNS client is already linked to another managed record.")
    ip_match, mac_match = dns_link_match(client, row)
    if not ip_match and not mac_match:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The DNS client no longer has an exact IP or MAC match for this record.")
    if ip_match and not mac_match and dhcp_range_for_ip(db, client.current_ip):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An IP-only link cannot be confirmed inside a DHCP range. Add or observe the device MAC address first.")
    old = client.linked_ip_record_id
    client.linked_ip_record_id = row.id
    client.suggested_ip_record_id = None
    client.is_known = True
    client.match_method = "manual"
    client.match_confidence = 100
    reasons = " and ".join(label for label, matched in (("IP", ip_match), ("MAC", mac_match)) if matched)
    add_event(db, client, "linked_to_ip_record", f"Confirmed {reasons} match to managed record {row.name or row.address}", old=str(old or ""), new=str(row.id), source="VLAN/IP Manager")
    db.commit()
    write_audit(db, user, "link", "ip_address", str(row.id), request.client.host if request.client else None, detail=f"Linked DNS client {client_display_name(client)} by exact {reasons} match", metadata={"dns_client_id": client.id, "ip_match": ip_match, "mac_match": mac_match})
    return RedirectResponse(f"/networking/vlan-ip-manager/{row.id}", status_code=303)


@router.get("/{record_id}/edit")
def edit_ip_address(request: Request, record_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    row = db.get(IPAddress, record_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    categories = list_values(db, MODULE).get("category", [])
    remote = remote_for(db, row.id)
    return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": row, "monitor": monitor_for(db, row.id), "remote": remote, "categories": categories, "vlans": db.query(VLAN).order_by(VLAN.name.asc()).all(), "selected_vlan_id": row.vlan_id, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": values, "option_list": option_list, "error": None, **remote_settings_context(remote), **csrf_context(request)})


@router.post("/{record_id}/edit")
async def update_ip_address(request: Request, record_id: int, address: str = Form(..., max_length=80), vlan_id: int | None = Form(None), mac_address: str = Form("", max_length=40), category: str = Form("", max_length=120), name: str = Form("", max_length=255), description: str = Form("", max_length=5000), assignment_type: str = Form("Static"), monitor_enabled: str = Form(""), monitor_display_name: str = Form("", max_length=255), monitor_interval_seconds: int = Form(300), monitor_timeout_ms: int = Form(2000), remote_enabled: str = Form(""), remote_display_name: str = Form("", max_length=255), remote_protocol: str = Form("ssh"), remote_port: int = Form(22), remote_username: str = Form("", max_length=120), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(IPAddress, record_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")
    clean_address = clean_ip(address)
    selected_vlan = resolve_vlan(db, vlan_id or row.vlan_id)
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    categories = list_values(db, MODULE).get("category", [])
    vlans = db.query(VLAN).order_by(VLAN.name.asc()).all()
    form = await request.form()
    custom_error = validate_custom_values(fields, form)
    if custom_error:
        remote = remote_for(db, row.id)
        return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": row, "monitor": monitor_for(db, row.id), "remote": remote, "categories": categories, "vlans": vlans, "selected_vlan_id": selected_vlan.id, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": values, "option_list": option_list, "error": custom_error, **remote_settings_context(remote), **csrf_context(request)}, status_code=400)
    existing = db.query(IPAddress).filter(IPAddress.vlan_id == selected_vlan.id, IPAddress.address == clean_address, IPAddress.id != row.id).first()
    if existing:
        remote = remote_for(db, row.id)
        return templates.TemplateResponse(request, "ip_address_form.html", {"user": user, "record": row, "monitor": monitor_for(db, row.id), "remote": remote, "categories": categories, "vlans": vlans, "selected_vlan_id": selected_vlan.id, "assignment_types": sorted(ASSIGNMENT_TYPES), "remote_protocols": sorted(REMOTE_PROTOCOLS), "custom_fields": fields, "custom_values": values, "option_list": option_list, "error": "That IP address already exists in this VLAN.", **remote_settings_context(remote), **csrf_context(request)}, status_code=400)
    row.vlan_id = selected_vlan.id
    row.address = clean_address
    clean_mac = normalise_mac(mac_address)
    if mac_address.strip() and not clean_mac:
        raise HTTPException(status_code=400, detail="Enter a valid MAC address.")
    row.mac_address = clean_mac
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
    return RedirectResponse(f"/networking/vlan-ip-manager/{row.id}", status_code=303)


@router.post("/{record_id}/delete")
def delete_ip_address(request: Request, record_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(IPAddress, record_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")
    address = row.address
    monitor = monitor_for(db, row.id)
    if monitor:
        db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.monitor_id == monitor.id).delete(synchronize_session=False)
        db.query(NetworkMonitorEvent).filter(NetworkMonitorEvent.monitor_id == monitor.id).delete(synchronize_session=False)
        db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.monitor_id == monitor.id).delete(synchronize_session=False)
        db.query(NetworkMonitorStatistic).filter(NetworkMonitorStatistic.monitor_id == monitor.id).delete(synchronize_session=False)
        db.delete(monitor)
    remote = remote_for(db, row.id)
    if remote:
        db.query(RemoteSessionRecording).filter(RemoteSessionRecording.remote_access_id == remote.id).update(
            {RemoteSessionRecording.remote_access_id: None}, synchronize_session=False
        )
        db.delete(remote)
    db.query(CustomFieldValue).filter(
        CustomFieldValue.entity_type == ENTITY_TYPE,
        CustomFieldValue.entity_id == row.id,
    ).delete(synchronize_session=False)
    db.delete(row)
    db.commit()
    write_audit(db, user, "delete", "ip_address", str(record_id), request.client.host if request.client else None, detail=address)
    return RedirectResponse("/networking/vlan-ip-manager", status_code=303)
