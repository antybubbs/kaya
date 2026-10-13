"""Database-backed modular dashboard registry, preferences and snapshot builders."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
import json
import logging
from time import perf_counter

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.models import (
    AppSession,
    AuditLog,
    BackupJob,
    BackupRecord,
    ComputeHost,
    ComputeWorkload,
    DashboardPreference,
    DNSInsight,
    DomainRecord,
    IPAddress,
    Licence,
    NetworkMonitor,
    RemoteAccess,
    RunbookPage,
    User,
    VLAN,
    Vault,
    VaultBackupRecord,
    VaultSession,
)
from app.core.performance import record_dashboard_widget
from app.services.compute_monitor import compute_summary
from app.services.dashboard_panels import (
    OFFLINE_STATES,
    TRAFFIC_RANGES,
    normalise_hidden_monitors,
    traffic_panel,
    uptime_panel,
)
from app.services.dns_dashboard_summary import get_dns_dashboard_summary
from app.services.site_settings import get_site_setting, get_site_settings
from app.services.modules import accessible_module_keys, module_for_path

logger = logging.getLogger(__name__)
VALID_SIZES = {"small", "medium", "large", "full"}
VALID_ZONES = {"main", "rail"}
# Version 2 introduced the Command centre layout (zones and new panel keys).
# Older stored layouts are replaced by the defaults rather than migrated.
VERSION = 2
DEFAULT_TRAFFIC_RANGE = "24h"
DASHBOARD_SETTING_KEYS = {
    "dashboard_attention_required",
    "dashboard_customisation_enabled",
    "dashboard_globally_disabled_widgets",
    "dashboard_monitor_mode_enabled",
    "dashboard_poll_interval_seconds",
    "dashboard_recent_activity_limit",
    "dashboard_show_source_age",
    "dns_manager_enabled",
}


def _prime_settings(db: Session) -> None:
    get_site_settings(db, DASHBOARD_SETTING_KEYS)


@dataclass(frozen=True)
class Widget:
    key: str
    name: str
    module: str
    description: str
    enabled: bool
    position: int
    width: str
    minimum_width: str
    permission: str
    endpoint: str
    target_url: str
    refresh: bool = True
    zone: str = "main"


WIDGETS = (
    Widget(
        "network_traffic",
        "Network traffic",
        "Uptime",
        "Gateway throughput, history and per-VLAN usage.",
        True,
        1,
        "full",
        "large",
        "authenticated",
        "/api/dashboard/snapshot",
        "/networking/ip-wan-monitor/traffic",
    ),
    Widget(
        "uptime",
        "Uptime",
        "Uptime",
        "Thirty-day availability for the hosts you choose.",
        True,
        2,
        "full",
        "large",
        "authenticated",
        "/api/dashboard/snapshot",
        "/networking/ip-wan-monitor",
    ),
    Widget(
        "module_overview",
        "Modules",
        "Kaya",
        "Headline figures for each module you can access.",
        True,
        3,
        "full",
        "large",
        "authenticated",
        "/api/dashboard/snapshot",
        "/dashboard",
    ),
    Widget(
        "attention_required",
        "Attention required",
        "Kaya",
        "Current actionable warnings across authorised modules.",
        True,
        4,
        "full",
        "small",
        "authenticated",
        "/api/dashboard/snapshot",
        "/dashboard",
        zone="rail",
    ),
    Widget(
        "infrastructure_summary",
        "Infrastructure",
        "Compute Manager",
        "Host and workload health and capacity.",
        True,
        5,
        "full",
        "small",
        "authenticated",
        "/api/dashboard/snapshot",
        "/infrastructure/vm-docker-manager",
        zone="rail",
    ),
    Widget(
        "backup_health",
        "Backup Manager",
        "Backup Manager",
        "Recent backup results and protected records.",
        False,
        6,
        "medium",
        "small",
        "authenticated",
        "/api/dashboard/snapshot",
        "/infrastructure/backup-manager",
    ),
    Widget(
        "recent_activity",
        "Recent activity",
        "Audit Log",
        "Latest authorised operational activity.",
        False,
        7,
        "medium",
        "medium",
        "admin",
        "/api/dashboard/snapshot",
        "/system/audit-logs",
    ),
)

WIDGET_MODULE_KEYS = {
    "network_traffic": ("network_monitor",),
    "uptime": ("network_monitor",),
    "infrastructure_summary": ("compute_manager",),
    "attention_required": ("dashboard",),
    "backup_health": ("backup_manager",),
}


def permitted(db: Session, widget: Widget, user: User) -> bool:
    if widget.permission != "authenticated" and user.role != "admin":
        return False
    required = WIDGET_MODULE_KEYS.get(widget.key)
    return not required or bool(set(required) & set(accessible_module_keys(db, user)))


def availability(db: Session, widget: Widget) -> tuple[bool, str | None]:
    if (
        widget.key == "backup_health"
        and not db.query(BackupRecord.id).first()
        and not db.query(BackupJob.id).first()
    ):
        return False, "No backup records configured"
    return True, None


def registry(db: Session, user: User) -> list[dict]:
    disabled = set(
        filter(
            None, get_site_setting(db, "dashboard_globally_disabled_widgets").split(",")
        )
    )
    result = []
    for item in WIDGETS:
        if not permitted(db, item, user) or item.key in disabled:
            continue
        available, reason = availability(db, item)
        row = asdict(item)
        row.update(
            available=available,
            availability_reason=reason,
            required_permission=item.permission,
            default_enabled=item.enabled,
            default_position=item.position,
            default_width=item.width,
            default_zone=item.zone,
        )
        result.append(row)
    return result


def default_layout(db: Session, user: User) -> dict:
    rows = []
    for item in registry(db, user):
        enabled = item["default_enabled"] and item["available"]
        if (
            item["key"] == "attention_required"
            and get_site_setting(db, "dashboard_attention_required") == "1"
        ):
            enabled = True
        rows.append(
            {
                "key": item["key"],
                "enabled": enabled,
                "position": item["default_position"],
                "width": item["default_width"],
                "zone": item["default_zone"],
            }
        )
    return {
        "version": VERSION,
        "monitor_mode": False,
        "widgets": rows,
        "uptime_hidden": [],
    }


def normalise_layout(db: Session, user: User, value: object) -> dict:
    defaults = default_layout(db, user)
    allowed = {x["key"]: x for x in registry(db, user)}
    if not isinstance(value, dict) or not isinstance(value.get("widgets"), list):
        return defaults
    if len(value["widgets"]) > len(allowed) * 2:
        raise ValueError("Too many widgets")
    submitted = {}
    for row in value["widgets"]:
        if not isinstance(row, dict) or row.get("key") not in allowed:
            raise ValueError("Unknown or unavailable widget key")
        key = row["key"]
        position = row.get("position")
        width = row.get("width")
        zone = row.get("zone", allowed[key]["default_zone"])
        if (
            isinstance(position, bool)
            or not isinstance(position, int)
            or position < 0
            or position > len(allowed) * 2
        ):
            raise ValueError("Invalid widget position")
        if width not in VALID_SIZES:
            raise ValueError("Invalid widget size")
        if zone not in VALID_ZONES:
            raise ValueError("Invalid widget zone")
        if not allowed[key]["available"] and row.get("enabled"):
            raise ValueError("Unavailable widgets cannot be enabled")
        submitted[key] = {
            "key": key,
            "enabled": bool(row.get("enabled")),
            "position": position,
            "width": width,
            "zone": zone,
        }
    merged = {x["key"]: x for x in defaults["widgets"]}
    merged.update(submitted)
    rows = sorted(merged.values(), key=lambda x: (x["position"], x["key"]))
    for index, row in enumerate(rows, 1):
        row["position"] = index
    attention = merged.get("attention_required")
    if attention and get_site_setting(db, "dashboard_attention_required") == "1":
        attention["enabled"] = True
    return {
        "version": VERSION,
        "monitor_mode": bool(value.get("monitor_mode"))
        and get_site_setting(db, "dashboard_monitor_mode_enabled") == "1",
        "widgets": rows,
        "uptime_hidden": normalise_hidden_monitors(value.get("uptime_hidden")),
    }


def preferences(db: Session, user: User) -> dict:
    row = db.query(DashboardPreference).filter_by(user_id=user.id).first()
    if not row:
        return default_layout(db, user)
    try:
        stored = json.loads(row.layout_json)
        if not isinstance(stored, dict) or stored.get("version") != VERSION:
            return default_layout(db, user)
        return normalise_layout(db, user, stored)
    except (ValueError, TypeError, json.JSONDecodeError):
        return default_layout(db, user)


def save_preferences(db: Session, user: User, value: object) -> dict:
    canonical = normalise_layout(db, user, value)
    row = db.query(DashboardPreference).filter_by(user_id=user.id).first()
    if not row:
        row = DashboardPreference(
            user_id=user.id, preference_version=VERSION, layout_json="{}"
        )
        db.add(row)
    try:
        existing = json.loads(row.layout_json or "{}")
    except (TypeError, json.JSONDecodeError):
        existing = {}
    extensions = (
        {key: item for key, item in existing.items() if key not in canonical}
        if isinstance(existing, dict)
        else {}
    )
    row.preference_version = VERSION
    row.layout_json = json.dumps({**canonical, **extensions}, separators=(",", ":"))
    db.commit()
    return canonical


def reset_preferences(db: Session, user: User) -> dict:
    row = db.query(DashboardPreference).filter_by(user_id=user.id).first()
    if row:
        try:
            existing = json.loads(row.layout_json or "{}")
        except (TypeError, json.JSONDecodeError):
            existing = {}
        extensions = (
            {
                key: item
                for key, item in existing.items()
                if key not in {"version", "monitor_mode", "widgets", "uptime_hidden"}
            }
            if isinstance(existing, dict)
            else {}
        )
        if extensions:
            row.layout_json = json.dumps(extensions, separators=(",", ":"))
        else:
            db.delete(row)
        db.commit()
    return default_layout(db, user)


def _metric(label, value, target=None):
    return {"label": label, "value": value, "target": target}


def _iso(value):
    return (
        value.isoformat() + ("Z" if value and value.tzinfo is None else "")
        if value
        else None
    )


def _row(label, value, tone=None):
    """One "label … value" line on a module card. ``None`` renders as Unavailable."""
    return {"label": label, "value": value, "tone": tone}


def _dns_summary(db: Session, user: User, context: dict):
    memo = context.setdefault("memo", {})
    if "dns" not in memo:
        memo["dns"] = (
            get_dns_dashboard_summary(db, user)
            if "dns_manager" in accessible_module_keys(db, user)
            and get_site_setting(db, "dns_manager_enabled") == "1"
            else None
        )
    return memo["dns"]


def _dns_card(db: Session, user: User, context: dict) -> dict:
    s = _dns_summary(db, user, context)
    configured = bool(s and s.configured and not s.error)
    attention = s.attention_count if configured else None
    return {
        "key": "dns_manager",
        "title": "DNS Manager",
        "target": "/networking/dns-manager",
        "state": ("warn" if attention else "ok") if configured else "none",
        "rows": [
            _row("Queries", s.queries_today if configured else None),
            _row(
                "Blocked",
                f"{s.blocked_percentage:.1f}%"
                if configured and s.blocked_percentage is not None
                else None,
            ),
            _row("Clients", s.active_clients_24h if configured else None),
            _row("Needs attention", attention, "warn" if attention else None),
        ],
        "source_updated_at": _iso(s.last_updated_at) if s else None,
    }


def _networking_card(db: Session, allowed: frozenset[str]) -> dict:
    total = assigned = vlans = domains = offline = None
    if "vlan_ip_manager" in allowed:
        total = db.query(IPAddress).count()
        assigned = db.query(IPAddress).filter(IPAddress.name.isnot(None)).count()
        vlans = db.query(VLAN).count()
    if "domain_manager" in allowed:
        domains = db.query(DomainRecord).count()
    if "network_monitor" in allowed:
        offline = (
            db.query(NetworkMonitor)
            .filter(NetworkMonitor.is_enabled.is_(True), NetworkMonitor.last_status.in_(OFFLINE_STATES))
            .count()
        )
    target = next(
        (
            path
            for key, path in (
                ("vlan_ip_manager", "/networking/vlan-ip-manager"),
                ("domain_manager", "/networking/domain-manager"),
                ("network_monitor", "/networking/ip-wan-monitor"),
            )
            if key in allowed
        ),
        "/dashboard",
    )
    return {
        "key": "networking",
        "title": "Networking",
        "target": target,
        "state": "warn" if offline else "ok",
        "rows": [
            _row("IP addresses", total),
            _row(
                "Assigned / free",
                f"{assigned:,} / {max(0, total - assigned):,}" if total is not None else None,
            ),
            _row("VLANs", vlans),
            _row("Domains", domains),
        ],
    }


def _remote_card(db: Session, allowed: frozenset[str]) -> dict:
    q = db.query(RemoteAccess).filter_by(is_enabled=True)
    offline = None
    if "network_monitor" in allowed:
        # Remote Manager has no reachability probe of its own. A target counts as
        # offline when the Uptime monitor for the same IP record is currently down.
        offline = (
            q.join(NetworkMonitor, NetworkMonitor.ip_address_id == RemoteAccess.ip_address_id)
            .filter(NetworkMonitor.is_enabled.is_(True), NetworkMonitor.last_status.in_(OFFLINE_STATES))
            .count()
        )
    return {
        "key": "remote_manager",
        "title": "Remote Manager",
        "target": "/remote-manager",
        "state": "warn" if offline else "ok",
        "rows": [
            _row("Targets", q.count()),
            _row("SSH", q.filter_by(protocol="ssh").count()),
            _row("RDP", q.filter_by(protocol="rdp").count()),
            _row("Offline", offline, "warn" if offline else None),
        ],
    }


def _vault_card(db: Session, user: User, now: datetime) -> dict:
    vault = db.query(Vault).filter_by(owner_id=user.id).first()
    latest = (
        db.query(VaultBackupRecord)
        .filter_by(vault_id=vault.id, status="verified")
        .order_by(VaultBackupRecord.verified_at.desc())
        .first()
        if vault
        else None
    )
    unlocked = bool(
        vault
        and db.query(VaultSession.id)
        .filter(
            VaultSession.vault_id == vault.id,
            VaultSession.user_id == user.id,
            VaultSession.revoked_at.is_(None),
            VaultSession.expires_at > now,
            VaultSession.absolute_expires_at > now,
        )
        .first()
    )
    enrolled = bool(vault and vault.recovery_confirmed_at)
    return {
        "key": "secret_vault",
        "title": "Secret Vault",
        "target": "/security/secret-vault",
        "state": "ok" if latest and enrolled else "warn",
        "rows": [
            _row("Status", ("Unlocked" if unlocked else "Locked") if vault else "Not set up"),
            _row("Enrolment", "Complete" if enrolled else "Required", None if enrolled else "warn"),
            _row("Backup", "Verified" if latest else "Not verified", None if latest else "warn"),
            _row(
                "Last verified",
                latest.verified_at.date().isoformat() if latest and latest.verified_at else None,
            ),
        ],
        "source_updated_at": _iso(latest.verified_at if latest else None),
    }


def _licence_card(db: Session) -> dict:
    today = date.today()
    soon = today + timedelta(days=30)
    q = db.query(Licence)
    expired = q.filter(Licence.expiry_date < today).count()
    expiring = q.filter(Licence.expiry_date >= today, Licence.expiry_date <= soon).count()
    nearest = q.filter(Licence.expiry_date >= today).order_by(Licence.expiry_date).first()
    return {
        "key": "licence_manager",
        "title": "Licence Manager",
        "target": "/security/license-keys",
        "state": "warn" if expired or expiring else "ok",
        "rows": [
            _row("Licences", q.count()),
            _row("Expired", expired, "warn" if expired else None),
            _row("Expiring 30d", expiring, "warn" if expiring else None),
            _row("Nearest expiry", nearest.expiry_date.isoformat() if nearest else None),
        ],
    }


def _team_card(db: Session, now: datetime) -> dict:
    active_today = (
        db.query(AppSession.user_id)
        .filter(AppSession.last_seen_at >= now - timedelta(days=1))
        .distinct()
        .count()
    )
    return {
        "key": "team_users",
        "title": "Team and users",
        "target": "/team/users",
        "state": "ok",
        "rows": [
            _row("Active users", db.query(User).filter_by(is_active=True).count()),
            _row("Active today", active_today),
            _row("Admins", db.query(User).filter_by(role="admin", is_active=True).count()),
            _row("Disabled", db.query(User).filter_by(is_active=False).count()),
        ],
    }


def _runbook_card(db: Session, now: datetime) -> dict:
    q = db.query(RunbookPage)
    latest = q.order_by(RunbookPage.updated_at.desc()).first()
    return {
        "key": "runbooks",
        "title": "Runbooks",
        "target": "/documentation/runbook-manager",
        "state": "ok",
        "rows": [
            _row("Total", q.count()),
            _row("Updated 7d", q.filter(RunbookPage.updated_at >= now - timedelta(days=7)).count()),
            _row("Most recent", latest.title if latest else None),
            # Runbooks have no external sync job; "Synced" is the latest page update.
            _row("Synced", {"relative": _iso(latest.updated_at)} if latest and latest.updated_at else None),
        ],
        "source_updated_at": _iso(latest.updated_at if latest else None),
    }


def _compute_card(summary: dict) -> dict:
    return {
        "key": "compute_manager",
        "title": "Compute",
        "target": "/infrastructure/vm-docker-manager",
        "state": "warn" if summary["warnings"] else "ok",
        "rows": [
            _row("Hosts", summary["hosts"]),
            _row("Workloads", summary["workloads"]),
            _row("Running", summary["running"]),
            _row("Stopped", summary["stopped"], "warn" if summary["stopped"] else None),
        ],
        "source_updated_at": _iso(summary["updated_at"]),
    }


def _compute_summary(db: Session, context: dict) -> dict:
    memo = context.setdefault("memo", {})
    if "compute" not in memo:
        memo["compute"] = compute_summary(db)
    return memo["compute"]


def _build(db: Session, user: User, key: str, context: dict | None = None) -> dict:
    context = context if context is not None else {}
    now = datetime.utcnow()
    allowed_modules = accessible_module_keys(db, user)
    if key == "network_traffic":
        dns = _dns_summary(db, user, context)
        return traffic_panel(
            db,
            report_range=context.get("traffic_range", DEFAULT_TRAFFIC_RANGE),
            allowed_modules=allowed_modules,
            dns_blocked_percentage=dns.blocked_percentage if dns and dns.configured and not dns.error else None,
        )
    if key == "uptime":
        layout = context.get("layout") or {}
        return uptime_panel(db, hidden_ids=layout.get("uptime_hidden") or [])
    if key == "module_overview":
        cards = []
        if "dns_manager" in allowed_modules:
            cards.append(_dns_card(db, user, context))
        if {"vlan_ip_manager", "domain_manager", "network_monitor"} & allowed_modules:
            cards.append(_networking_card(db, allowed_modules))
        if "remote_manager" in allowed_modules:
            cards.append(_remote_card(db, allowed_modules))
        if "secret_vault" in allowed_modules:
            cards.append(_vault_card(db, user, now))
        if "licence_manager" in allowed_modules:
            cards.append(_licence_card(db))
        if user.role == "admin":
            cards.append(_team_card(db, now))
        if "runbooks" in allowed_modules:
            cards.append(_runbook_card(db, now))
        if "compute_manager" in allowed_modules:
            cards.append(_compute_card(_compute_summary(db, context)))
        return {"cards": cards}
    if key == "infrastructure_summary":
        s = _compute_summary(db, context)
        return {
            "cpu_percent": s["cpu_percent"],
            "memory_percent": s["memory_percent"],
            "storage_percent": s["storage_percent"],
            "hosts": s["hosts"],
            "online_hosts": s["online_hosts"],
            "workloads": s["workloads"],
            "running": s["running"],
            "source_updated_at": _iso(s["updated_at"]),
            "severity": "warning" if s["warnings"] else "current",
        }
    if key == "backup_health":
        jobs = db.query(BackupJob)
        success = jobs.filter(BackupJob.status.in_(["success", "completed"])).count()
        failed = jobs.filter(BackupJob.status.in_(["failed", "error"])).count()
        latest = jobs.order_by(BackupJob.finished_at.desc()).first()
        return {
            "metrics": [
                _metric(
                    "Protected records",
                    db.query(BackupRecord).filter_by(is_enabled=True).count(),
                ),
                _metric("Successful jobs", success),
                _metric("Failed jobs", failed),
                _metric("Last result", latest.status if latest else "Unavailable"),
            ],
            "source_updated_at": _iso(latest.finished_at if latest else None),
            "severity": "critical" if failed else "current",
        }
    if key == "recent_activity":
        limit = int(get_site_setting(db, "dashboard_recent_activity_limit") or 10)
        rows = (
            db.query(AuditLog)
            .order_by(AuditLog.created_at.desc())
            .limit(max(50, limit * 5))
            .all()
        )
        ignored_paths = ("/.well-known", "/favicon.ico", "/api/dashboard/snapshot")
        action_labels = {
            "create": "Created",
            "update": "Updated",
            "delete": "Deleted",
            "login": "Signed in",
            "logout": "Signed out",
            "recognise": "Recognised",
            "recognized": "Recognised",
        }
        grouped = {}
        for event in rows:
            path = (event.request_path or "").lower()
            if any(marker in path for marker in ignored_paths):
                continue
            event_module = module_for_path(path) if path else None
            if event_module and event_module.key not in allowed_modules:
                continue
            if event.entity in {"api", "request"} and event.action.lower() in {
                "get",
                "put",
                "post",
                "request_failed",
            }:
                continue
            entity = event.entity.replace("_", " ").strip()
            action = action_labels.get(
                event.action.lower(), event.action.replace("_", " ").strip().title()
            )
            summary = f"{action} {entity}".strip()
            group_key = (event.severity, summary, event.entity_id)
            item = grouped.setdefault(
                group_key,
                {
                    "severity": event.severity,
                    "summary": summary,
                    "object": event.entity_id,
                    "detected_at": _iso(event.created_at),
                    "target": "/system/audit-logs",
                    "count": 0,
                },
            )
            item["count"] += 1
        return {"items": list(grouped.values())[:limit]}
    if key == "attention_required":
        items = []
        if "compute_manager" in allowed_modules:
            for h in (
                db.query(ComputeHost).filter(ComputeHost.status != "online").limit(10)
            ):
                items.append(
                    {
                        "severity": "critical",
                        "module": "Compute Manager",
                        "summary": "Host is offline",
                        "object": h.name,
                        "detected_at": _iso(h.updated_at),
                        "target": "/infrastructure/vm-docker-manager",
                    }
                )
            for w in (
                db.query(ComputeWorkload)
                .filter(ComputeWorkload.status.in_(["unhealthy", "restarting"]))
                .limit(10)
            ):
                items.append(
                    {
                        "severity": "warning",
                        "module": "Compute Manager",
                        "summary": f"Workload is {w.status}",
                        "object": w.name,
                        "detected_at": _iso(w.updated_at),
                        "target": "/infrastructure/vm-docker-manager",
                    }
                )
        if "dns_manager" in allowed_modules:
            for x in (
                db.query(DNSInsight)
                .filter(
                    DNSInsight.status == "active", DNSInsight.acknowledged_at.is_(None)
                )
                .limit(10)
            ):
                items.append(
                    {
                        "severity": x.severity,
                        "module": "DNS Manager",
                        "summary": x.title,
                        "object": x.entity_identifier,
                        "detected_at": _iso(x.last_detected_at),
                        "target": "/networking/dns-manager?tab=insights",
                    }
                )
        if "backup_manager" in allowed_modules:
            for j in (
                db.query(BackupJob)
                .filter(BackupJob.status.in_(["failed", "error"]))
                .order_by(BackupJob.created_at.desc())
                .limit(5)
            ):
                items.append(
                    {
                        "severity": "critical",
                        "module": "Backup Manager",
                        "summary": "Backup job failed",
                        "object": str(j.id),
                        "detected_at": _iso(j.finished_at or j.created_at),
                        "target": "/infrastructure/backup-manager",
                    }
                )
        rank = {"critical": 0, "warning": 1, "information": 2, "info": 2}
        grouped = {}
        for item in items:
            group_key = (
                item["severity"],
                item["module"],
                item["summary"],
                item["target"],
            )
            group = grouped.setdefault(group_key, {**item, "count": 0, "objects": []})
            group["count"] += 1
            if (
                item.get("object")
                and item["object"] not in group["objects"]
                and len(group["objects"]) < 3
            ):
                group["objects"].append(item["object"])
            if (item.get("detected_at") or "") > (group.get("detected_at") or ""):
                group["detected_at"] = item["detected_at"]
        grouped_items = list(grouped.values())
        grouped_items.sort(
            key=lambda x: (
                rank.get(x["severity"], 2),
                -(x["count"]),
                x["detected_at"] or "",
            )
        )
        counts = {
            level: sum(x["count"] for x in grouped_items if x["severity"] in aliases)
            for level, aliases in {
                "critical": {"critical"},
                "warning": {"warning"},
                "information": {"information", "info"},
            }.items()
        }
        return {
            "items": grouped_items[:12],
            "counts": counts,
            "total_count": sum(counts.values()),
            "severity": (
                "critical"
                if counts["critical"]
                else (
                    "warning"
                    if counts["warning"]
                    else "information" if counts["information"] else "current"
                )
            ),
        }
    raise KeyError(key)


def snapshot(db: Session, user: User, traffic_range: str = DEFAULT_TRAFFIC_RANGE) -> dict:
    if traffic_range not in TRAFFIC_RANGES:
        raise ValueError("Unsupported traffic range")
    started = perf_counter()
    _prime_settings(db)
    config = preferences(db, user)
    definitions = {x["key"]: x for x in registry(db, user)}
    context = {"traffic_range": traffic_range, "layout": config, "memo": {}}
    output = {}
    for row in config["widgets"]:
        if not row["enabled"] or row["key"] not in definitions:
            continue
        definition = definitions[row["key"]]
        if not definition["available"]:
            output[row["key"]] = {
                "status": "unavailable",
                "reason": definition["availability_reason"],
            }
            continue
        widget_started = perf_counter()
        try:
            output[row["key"]] = {
                "status": "ok",
                "data": _build(db, user, row["key"], context),
                "last_successful_update": _iso(datetime.utcnow()),
            }
            record_dashboard_widget(row["key"], (perf_counter() - widget_started) * 1000)
        except Exception:
            record_dashboard_widget(row["key"], (perf_counter() - widget_started) * 1000)
            logger.exception(
                "Dashboard widget failed", extra={"widget_key": row["key"]}
            )
            output[row["key"]] = {
                "status": "error",
                "reason": "Widget data is temporarily unavailable",
            }
    generated = datetime.utcnow()
    logger.info(
        "Dashboard snapshot generated",
        extra={
            "duration_ms": round((perf_counter() - started) * 1000, 1),
            "widget_count": len(output),
            "user_id": user.id,
        },
    )
    return {"generated_at": _iso(generated), "widgets": output}


def config(db: Session, user: User) -> dict:
    _prime_settings(db)
    try:
        poll_interval = int(
            get_site_setting(db, "dashboard_poll_interval_seconds") or 10
        )
    except (TypeError, ValueError):
        poll_interval = 10
    if poll_interval not in {10, 30, 60, 300}:
        poll_interval = 10
    return {
        "version": VERSION,
        "poll_interval_seconds": poll_interval,
        "customisation_enabled": get_site_setting(db, "dashboard_customisation_enabled") == "1",
        "monitor_mode_enabled": get_site_setting(db, "dashboard_monitor_mode_enabled") == "1",
        "show_source_age": get_site_setting(db, "dashboard_show_source_age") == "1",
        "traffic_ranges": list(TRAFFIC_RANGES),
        "default_traffic_range": DEFAULT_TRAFFIC_RANGE,
        "layout": preferences(db, user),
        "widgets": registry(db, user),
    }
