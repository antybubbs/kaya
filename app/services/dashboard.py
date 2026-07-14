"""Database-backed modular dashboard registry, preferences and snapshot builders."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
import json
import logging
from time import perf_counter

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.models import (AppSession, AuditLog, BackupJob, BackupRecord, ComputeEvent,
    ComputeHost, ComputeWorkload, DashboardPreference, DNSInsight, DomainRecord, HardwareAsset,
    IPAddress, Licence, NetworkMonitor, RemoteAccess, RunbookPage, User, VLAN)
from app.services.compute_monitor import compute_summary
from app.services.dns_dashboard_summary import get_dns_dashboard_summary, get_refreshed_dns_dashboard_summary
from app.services.site_settings import get_site_setting

logger = logging.getLogger(__name__)
VALID_SIZES = {"small", "medium", "large", "full"}
VERSION = 1

@dataclass(frozen=True)
class Widget:
    key: str; name: str; module: str; description: str; enabled: bool; position: int
    width: str; minimum_width: str; permission: str; endpoint: str; target_url: str
    refresh: bool = True

WIDGETS = (
    Widget("infrastructure_summary", "Infrastructure at a glance", "Compute Manager", "Host and workload health and capacity.", True, 1, "full", "large", "authenticated", "/api/dashboard/snapshot", "/infrastructure/vm-docker-manager"),
    Widget("attention_required", "Attention Required", "Kaya", "Current actionable warnings across authorised modules.", True, 2, "full", "large", "authenticated", "/api/dashboard/snapshot", "/dashboard"),
    Widget("dns_summary", "DNS Manager", "DNS Manager", "Stored provider health and query activity.", True, 3, "large", "medium", "authenticated", "/api/dashboard/snapshot", "/networking/dns-manager"),
    Widget("backup_health", "Backup Manager", "Backup Manager", "Recent backup results and protected records.", True, 4, "medium", "small", "authenticated", "/api/dashboard/snapshot", "/infrastructure/backup-manager"),
    Widget("networking", "Networking", "VLAN / IP Manager", "Address, VLAN, domain and reachability totals.", True, 5, "medium", "small", "authenticated", "/api/dashboard/snapshot", "/networking/vlan-ip-manager"),
    Widget("remote_manager", "Remote Manager", "Remote Manager", "Configured SSH and RDP targets.", True, 6, "small", "small", "authenticated", "/api/dashboard/snapshot", "/remote-manager"),
    Widget("licences", "Licence Manager", "Licence Manager", "Active and expiring licence records.", True, 7, "medium", "small", "authenticated", "/api/dashboard/snapshot", "/security/license-keys"),
    Widget("documentation", "Documentation and Runbooks", "Runbooks", "Runbook totals and recent changes.", True, 8, "medium", "small", "authenticated", "/api/dashboard/snapshot", "/documentation/runbook-manager"),
    Widget("team_users", "Team and users", "Team", "Account health and recent access.", True, 9, "small", "small", "admin", "/api/dashboard/snapshot", "/team/users"),
    Widget("recent_activity", "Recent activity", "Audit Log", "Latest authorised operational activity.", True, 10, "large", "medium", "admin", "/api/dashboard/snapshot", "/system/audit-logs"),
)

def permitted(widget: Widget, user: User) -> bool:
    return widget.permission == "authenticated" or user.role == "admin"

def availability(db: Session, widget: Widget) -> tuple[bool, str | None]:
    if widget.key == "dns_summary" and get_site_setting(db, "dns_manager_enabled") != "1": return False, "Module disabled"
    if widget.key == "backup_health" and not db.query(BackupRecord.id).first() and not db.query(BackupJob.id).first(): return False, "No backup records configured"
    return True, None

def registry(db: Session, user: User) -> list[dict]:
    disabled = set(filter(None, get_site_setting(db, "dashboard_globally_disabled_widgets").split(",")))
    result = []
    for item in WIDGETS:
        if not permitted(item, user) or item.key in disabled: continue
        available, reason = availability(db, item)
        row = asdict(item); row.update(available=available, availability_reason=reason, required_permission=item.permission,
                                      default_enabled=item.enabled, default_position=item.position, default_width=item.width)
        result.append(row)
    return result

def default_layout(db: Session, user: User) -> dict:
    rows = []
    for item in registry(db, user):
        enabled = item["default_enabled"] and item["available"]
        if item["key"] == "attention_required" and get_site_setting(db, "dashboard_attention_required") == "1": enabled = True
        rows.append({"key": item["key"], "enabled": enabled, "position": item["default_position"], "width": item["default_width"]})
    return {"version": VERSION, "monitor_mode": False, "widgets": rows}

def normalise_layout(db: Session, user: User, value: object) -> dict:
    defaults = default_layout(db, user); allowed = {x["key"]: x for x in registry(db, user)}
    if not isinstance(value, dict) or not isinstance(value.get("widgets"), list): return defaults
    submitted = {}
    for row in value["widgets"]:
        if not isinstance(row, dict) or row.get("key") not in allowed: raise ValueError("Unknown or unavailable widget key")
        key = row["key"]; position = row.get("position"); width = row.get("width")
        if not isinstance(position, int) or position < 0 or position > len(allowed) * 2: raise ValueError("Invalid widget position")
        if width not in VALID_SIZES: raise ValueError("Invalid widget size")
        if not allowed[key]["available"] and row.get("enabled"): raise ValueError("Unavailable widgets cannot be enabled")
        submitted[key] = {"key": key, "enabled": bool(row.get("enabled")), "position": position, "width": width}
    merged = {x["key"]: x for x in defaults["widgets"]}; merged.update(submitted)
    rows = sorted(merged.values(), key=lambda x: (x["position"], x["key"]))
    for index, row in enumerate(rows, 1): row["position"] = index
    attention = merged.get("attention_required")
    if attention and get_site_setting(db, "dashboard_attention_required") == "1": attention["enabled"] = True
    return {"version": VERSION, "monitor_mode": bool(value.get("monitor_mode")) and get_site_setting(db, "dashboard_monitor_mode_enabled") == "1", "widgets": rows}

def preferences(db: Session, user: User) -> dict:
    row = db.query(DashboardPreference).filter_by(user_id=user.id).first()
    if not row: return default_layout(db, user)
    try: return normalise_layout(db, user, json.loads(row.layout_json))
    except (ValueError, TypeError, json.JSONDecodeError): return default_layout(db, user)

def save_preferences(db: Session, user: User, value: object) -> dict:
    canonical = normalise_layout(db, user, value)
    row = db.query(DashboardPreference).filter_by(user_id=user.id).first()
    if not row: row = DashboardPreference(user_id=user.id, preference_version=VERSION, layout_json="{}"); db.add(row)
    row.preference_version = VERSION; row.layout_json = json.dumps(canonical, separators=(",", ":")); db.commit()
    return canonical

def reset_preferences(db: Session, user: User) -> dict:
    row = db.query(DashboardPreference).filter_by(user_id=user.id).first()
    if row: db.delete(row); db.commit()
    return default_layout(db, user)

def _metric(label, value, target=None): return {"label": label, "value": value, "target": target}
def _iso(value): return value.isoformat() + ("Z" if value and value.tzinfo is None else "") if value else None

def _build(db: Session, user: User, key: str) -> dict:
    now = datetime.utcnow()
    if key == "infrastructure_summary":
        s = compute_summary(db); return {"metrics": [_metric("Compute hosts", s["hosts"]), _metric("Online hosts", s["online_hosts"]), _metric("Total workloads", s["workloads"]), _metric("Running", s["running"]), _metric("Stopped", s["stopped"]), _metric("CPU", f'{s["cpu_percent"]:.1f}%' if s["cpu_percent"] is not None else "Unavailable"), _metric("Memory", f'{s["memory_percent"]:.1f}%' if s["memory_percent"] is not None else "Unavailable"), _metric("Storage", f'{s["storage_percent"]:.1f}%' if s["storage_percent"] is not None else "Unavailable")], "source_updated_at": _iso(s["updated_at"]), "severity": "warning" if s["warnings"] else "current"}
    if key == "dns_summary":
        s = get_dns_dashboard_summary(db, user); return {"metrics": [_metric("Total queries", s.queries_today), _metric("Blocked", f"{s.blocked_percentage:.1f}%" if s.blocked_percentage is not None else "Unavailable"), _metric("Active clients", s.active_clients_24h), _metric("Needs attention", s.attention_count)], "source_updated_at": _iso(s.last_updated_at), "severity": "warning" if s.attention_count else "current"}
    if key == "backup_health":
        jobs = db.query(BackupJob); success = jobs.filter(BackupJob.status.in_(["success","completed"])).count(); failed = jobs.filter(BackupJob.status.in_(["failed","error"])).count(); latest = jobs.order_by(BackupJob.finished_at.desc()).first()
        return {"metrics": [_metric("Protected records", db.query(BackupRecord).filter_by(is_enabled=True).count()), _metric("Successful jobs", success), _metric("Failed jobs", failed), _metric("Last result", latest.status if latest else "Unavailable")], "source_updated_at": _iso(latest.finished_at if latest else None), "severity": "critical" if failed else "current"}
    if key == "networking":
        total = db.query(IPAddress).count(); assigned = db.query(IPAddress).filter(IPAddress.name.isnot(None)).count(); monitors = db.query(NetworkMonitor)
        return {"metrics": [_metric("IP addresses", total), _metric("Assigned", assigned), _metric("Available", max(0,total-assigned)), _metric("VLANs", db.query(VLAN).count()), _metric("Domains", db.query(DomainRecord).count()), _metric("Offline targets", monitors.filter(NetworkMonitor.last_status.in_(["offline","down","failed"])).count())], "source_updated_at": _iso(monitors.with_entities(func.max(NetworkMonitor.last_checked_at)).scalar())}
    if key == "remote_manager":
        q=db.query(RemoteAccess).filter_by(is_enabled=True); return {"metrics": [_metric("Configured targets", q.count()), _metric("SSH targets", q.filter_by(protocol="ssh").count()), _metric("RDP targets", q.filter_by(protocol="rdp").count())]}
    if key == "licences":
        today=date.today(); soon=today+timedelta(days=30); q=db.query(Licence); expired=q.filter(Licence.expiry_date < today).count(); expiring=q.filter(Licence.expiry_date >= today, Licence.expiry_date <= soon).count(); nearest=q.filter(Licence.expiry_date >= today).order_by(Licence.expiry_date).first()
        return {"metrics": [_metric("Total licences", q.count()), _metric("Expired", expired), _metric("Expiring in 30 days", expiring), _metric("Nearest expiry", nearest.expiry_date.isoformat() if nearest else "Unavailable")], "severity": "critical" if expired else "warning" if expiring else "current"}
    if key == "documentation":
        q=db.query(RunbookPage); recent=q.filter(RunbookPage.updated_at >= now-timedelta(days=7)).count(); latest=q.order_by(RunbookPage.updated_at.desc()).first(); return {"metrics": [_metric("Total runbooks", q.count()), _metric("Updated in 7 days", recent), _metric("Most recent", latest.title if latest else "Unavailable")], "source_updated_at": _iso(latest.updated_at if latest else None)}
    if key == "team_users":
        active_today=db.query(AppSession.user_id).filter(AppSession.last_seen_at >= now-timedelta(days=1)).distinct().count(); return {"metrics": [_metric("Active users", db.query(User).filter_by(is_active=True).count()), _metric("Active today", active_today), _metric("Administrators", db.query(User).filter_by(role="admin",is_active=True).count()), _metric("Disabled", db.query(User).filter_by(is_active=False).count())]}
    if key == "recent_activity":
        limit=int(get_site_setting(db,"dashboard_recent_activity_limit") or 10)
        rows=db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(max(50,limit*5)).all()
        ignored_paths=("/.well-known", "/favicon.ico", "/api/dashboard/snapshot")
        action_labels={"create":"Created","update":"Updated","delete":"Deleted","login":"Signed in","logout":"Signed out","recognise":"Recognised","recognized":"Recognised"}
        grouped={}
        for event in rows:
            path=(event.request_path or "").lower()
            if any(marker in path for marker in ignored_paths): continue
            if event.entity in {"api","request"} and event.action.lower() in {"get","put","post","request_failed"}: continue
            entity=event.entity.replace("_"," ").strip()
            action=action_labels.get(event.action.lower(),event.action.replace("_"," ").strip().title())
            summary=f"{action} {entity}".strip()
            group_key=(event.severity,summary,event.entity_id)
            item=grouped.setdefault(group_key,{"severity":event.severity,"summary":summary,"object":event.entity_id,"detected_at":_iso(event.created_at),"target":"/system/audit-logs","count":0})
            item["count"] += 1
        return {"items":list(grouped.values())[:limit]}
    if key == "attention_required":
        items=[]
        for h in db.query(ComputeHost).filter(ComputeHost.status != "online").limit(10): items.append({"severity":"critical","module":"Compute Manager","summary":"Host is offline","object":h.name,"detected_at":_iso(h.updated_at),"target":"/infrastructure/vm-docker-manager"})
        for w in db.query(ComputeWorkload).filter(ComputeWorkload.status.in_(["unhealthy","restarting"])).limit(10): items.append({"severity":"warning","module":"Compute Manager","summary":f"Workload is {w.status}","object":w.name,"detected_at":_iso(w.updated_at),"target":"/infrastructure/vm-docker-manager"})
        for x in db.query(DNSInsight).filter(DNSInsight.status=="active", DNSInsight.acknowledged_at.is_(None)).limit(10): items.append({"severity":x.severity,"module":"DNS Manager","summary":x.title,"object":x.entity_identifier,"detected_at":_iso(x.last_detected_at),"target":"/networking/dns-manager?tab=insights"})
        for j in db.query(BackupJob).filter(BackupJob.status.in_(["failed","error"])).order_by(BackupJob.created_at.desc()).limit(5): items.append({"severity":"critical","module":"Backup Manager","summary":"Backup job failed","object":str(j.id),"detected_at":_iso(j.finished_at or j.created_at),"target":"/infrastructure/backup-manager"})
        rank={"critical":0,"warning":1,"information":2,"info":2}
        grouped={}
        for item in items:
            group_key=(item["severity"],item["module"],item["summary"],item["target"])
            group=grouped.setdefault(group_key,{**item,"count":0,"objects":[]})
            group["count"] += 1
            if item.get("object") and item["object"] not in group["objects"] and len(group["objects"]) < 3:
                group["objects"].append(item["object"])
            if (item.get("detected_at") or "") > (group.get("detected_at") or ""):
                group["detected_at"] = item["detected_at"]
        grouped_items=list(grouped.values())
        grouped_items.sort(key=lambda x:(rank.get(x["severity"],2),-(x["count"]),x["detected_at"] or ""))
        counts={level:sum(x["count"] for x in grouped_items if x["severity"] in aliases) for level,aliases in {"critical":{"critical"},"warning":{"warning"},"information":{"information","info"}}.items()}
        return {"items":grouped_items[:12],"counts":counts,"total_count":sum(counts.values()),"severity":"critical" if counts["critical"] else "warning" if counts["warning"] else "information" if counts["information"] else "current"}
    raise KeyError(key)

def snapshot(db: Session, user: User) -> dict:
    started=perf_counter(); config=preferences(db,user); definitions={x["key"]:x for x in registry(db,user)}; output={}
    enabled_keys = {row["key"] for row in config["widgets"] if row["enabled"]}
    if enabled_keys.intersection({"dns_summary", "attention_required"}):
        try:
            # Refresh stale provider data before rendering either DNS metrics or
            # DNS-backed attention items, so every widget uses one fresh view.
            get_refreshed_dns_dashboard_summary(db, user, max_age_seconds=60)
        except Exception:
            logger.exception("Unable to refresh stale DNS dashboard data")
    for row in config["widgets"]:
        if not row["enabled"] or row["key"] not in definitions: continue
        definition=definitions[row["key"]]
        if not definition["available"]: output[row["key"]]={"status":"unavailable","reason":definition["availability_reason"]}; continue
        try: output[row["key"]]={"status":"ok","data":_build(db,user,row["key"]),"last_successful_update":_iso(datetime.utcnow())}
        except Exception: logger.exception("Dashboard widget failed",extra={"widget_key":row["key"]}); output[row["key"]]={"status":"error","reason":"Widget data is temporarily unavailable"}
    generated=datetime.utcnow(); logger.info("Dashboard snapshot generated",extra={"duration_ms":round((perf_counter()-started)*1000,1),"widget_count":len(output),"user_id":user.id})
    return {"generated_at":_iso(generated),"widgets":output}

def config(db: Session, user: User) -> dict:
    try:
        poll_interval = int(get_site_setting(db, "dashboard_poll_interval_seconds") or 10)
    except (TypeError, ValueError):
        poll_interval = 10
    if poll_interval not in {10, 30, 60, 300}:
        poll_interval = 10
    return {"version":VERSION,"poll_interval_seconds":poll_interval,"customisation_enabled":get_site_setting(db,"dashboard_customisation_enabled")=="1","monitor_mode_enabled":get_site_setting(db,"dashboard_monitor_mode_enabled")=="1","show_source_age":get_site_setting(db,"dashboard_show_source_age")=="1","layout":preferences(db,user),"widgets":registry(db,user)}
