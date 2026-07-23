from __future__ import annotations

from datetime import datetime, timedelta
import json
from typing import Any
from urllib.parse import urlencode, urlparse

from starlette.datastructures import URL

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import DNSClientEvent, DNSClientHostnameHistory, DNSClientIPHistory, DNSClientTrafficEvent, DNSInsight, DNSInvestigation, DNSProviderConfig, DNSRecognisedDevice, DNSStatisticsSnapshot, IPAddress, RemoteManagerSetting, VLAN
from app.routers.auth import require_admin, require_editor, require_module_access, require_user
from app.services.dns_providers import DNSProvider, DNSProviderResult, provider_for
from app.services.audit import write_audit
from app.services.site_settings import get_site_setting
from app.services.dns_insights import (
    CATEGORY_LABELS,
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    AnalysisAlreadyRunning,
    analyse_provider,
    calculate_health_score,
    insight_action_target,
)
from app.services.dns_clients import add_event, client_display_name, client_status, dhcp_range_for_ip, list_clients, normalise_mac

router = APIRouter(prefix="/networking/dns-manager", dependencies=[Depends(require_module_access("dns_manager"))])
templates = Jinja2Templates(directory="app/templates")

DNS_TABS = ["dashboard", "insights", "reports", "query-log", "clients", "local-dns", "dhcp", "blocklists"]


def dns_manager_enabled(db: Session) -> bool:
    return get_site_setting(db, "dns_manager_enabled") == "1"


def configured_providers(db: Session) -> list[DNSProviderConfig]:
    return (
        db.query(DNSProviderConfig)
        .filter(DNSProviderConfig.is_enabled == True)  # noqa: E712
        .order_by(DNSProviderConfig.name.asc())
        .all()
    )


def selected_provider(db: Session) -> DNSProviderConfig | None:
    providers = configured_providers(db)
    preferred = (get_site_setting(db, "dns_default_provider_id") or "").strip()
    if preferred.isdigit():
        for provider in providers:
            if provider.id == int(preferred):
                return provider
    return providers[0] if providers else None


def list_from_payload(payload: Any, *keys: str) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = list_from_payload(value, *keys)
            if nested:
                return nested
    return []


def stat_value(stats: dict[str, Any] | None, *keys: str) -> Any:
    if not isinstance(stats, dict):
        return "-"
    for key in keys:
        current: Any = stats
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, ""):
            return current
    return "-"


def display_number(value: Any, suffix: str = "") -> str:
    if value in (None, "") or value == "-":
        return "-"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    if suffix:
        return f"{numeric:.1f}{suffix}"
    return f"{int(numeric):,}" if numeric.is_integer() else f"{numeric:,.1f}"


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value or default))
    except (TypeError, ValueError):
        return default


def timestamp_sort_value(value: Any) -> float:
    if value in (None, ""):
        return 0
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OSError):
        return 0


def timestamp_display(value: Any) -> str:
    stamp = timestamp_sort_value(value)
    if not stamp:
        return str(value or "-")
    try:
        return datetime.fromtimestamp(stamp).strftime("%d/%m/%Y %H:%M")
    except (ValueError, OSError):
        return str(value or "-")


def payload_value(payload: Any, *keys: str) -> Any:
    if not isinstance(payload, dict):
        return None
    for key in keys:
        if key in payload and payload[key] not in (None, ""):
            return payload[key]
    return None


def query_log_time(row: Any) -> str:
    value = payload_value(row, "time", "timestamp", "date")
    if value in (None, ""):
        return "-"
    try:
        numeric = float(value)
        return datetime.fromtimestamp(numeric).strftime("%d/%m/%Y %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return str(value)


def query_client_name(row: Any) -> str:
    client = payload_value(row, "client")
    if isinstance(client, dict):
        return str(payload_value(client, "name", "hostname", "host") or "-")
    return str(payload_value(row, "client_name", "hostname", "name") or "-")


def query_client_ip(row: Any) -> str:
    client = payload_value(row, "client")
    if isinstance(client, dict):
        return str(payload_value(client, "ip", "address", "ip_address") or "-")
    value = payload_value(row, "client_ip", "ip", "ip_address", "client")
    return str(value or "-")


def query_reply_type(row: Any) -> str:
    reply = payload_value(row, "reply")
    if isinstance(reply, dict):
        return str(payload_value(reply, "type", "reply_type", "status") or "-")
    return str(payload_value(row, "reply_type", "reply") or "-")


def query_reply_time(row: Any) -> str:
    reply = payload_value(row, "reply")
    value = payload_value(reply, "time", "duration", "response_time") if isinstance(reply, dict) else payload_value(row, "reply_time", "response_time", "duration")
    if value in (None, ""):
        return "-"
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return str(value)
    if seconds < 0.001:
        return f"{seconds * 1000:.3f} ms"
    if seconds < 1:
        return f"{seconds * 1000:.2f} ms"
    return f"{seconds:.2f} s"


def query_domain(row: Any) -> str:
    return str(payload_value(row, "domain", "query") or "-")


def query_type(row: Any) -> str:
    return str(payload_value(row, "type", "query_type") or "-")


def query_status(row: Any) -> str:
    return str(payload_value(row, "status", "reply_status", "reply_type") or "-")


def query_upstream(row: Any) -> str:
    return str(payload_value(row, "upstream", "forwarded_to", "server") or "-")


def filtered_query_rows(
    payload: Any,
    domain_filter: str = "",
    client_filter: str = "",
) -> list[dict[str, Any]]:
    rows = list_from_payload(payload, "queries", "data") if isinstance(payload, dict) else []

    clean_domain = domain_filter.strip().lower() if isinstance(domain_filter, str) else ""
    clean_client = client_filter.strip().lower() if isinstance(client_filter, str) else ""

    if clean_domain:
        rows = [
            row
            for row in rows
            if query_domain(row).strip().rstrip(".").lower() == clean_domain
        ]

    if clean_client:
        rows = [
            row
            for row in rows
            if clean_client
            in {
                query_client_name(row).strip().lower(),
                query_client_ip(row).strip().lower(),
            }
        ]

    return rows


def domain_root(domain: str) -> str:
    clean = (domain or "").strip(".").lower()
    if not clean or clean == "-":
        return "-"
    parts = [part for part in clean.split(".") if part]
    if len(parts) <= 2:
        return clean
    return ".".join(parts[-2:])


def domain_kind(domain: str) -> str:
    clean = (domain or "").strip(".").lower()
    if not clean or clean == "-":
        return "Unknown"
    if clean.endswith(".local") or clean.endswith(".lan") or clean.endswith(".home.arpa"):
        return "Local network"
    if clean.endswith(".in-addr.arpa") or clean.endswith(".ip6.arpa"):
        return "Reverse lookup"
    if clean.startswith("_"):
        return "Service discovery"
    return "External domain"


def open_investigation_domains(db: Session, provider: DNSProviderConfig | None) -> set[str]:
    if not provider:
        return set()
    rows = (
        db.query(DNSInvestigation.domain)
        .filter(DNSInvestigation.provider_id == provider.id, DNSInvestigation.status == "open")
        .all()
    )
    return {str(domain).lower() for domain, in rows if domain}


def _timestamp_label(value: Any) -> str:
    try:
        stamp = int(float(value))
        return datetime.fromtimestamp(stamp).strftime("%H:%M")
    except (TypeError, ValueError, OSError):
        return str(value)


def query_chart_points(history_payload: Any) -> list[dict[str, Any]]:
    payload = history_payload if isinstance(history_payload, dict) else {}
    queries = payload.get("queries") if isinstance(payload.get("queries"), dict) else payload
    domains = queries.get("domains_over_time") if isinstance(queries.get("domains_over_time"), dict) else {}
    blocked = queries.get("ads_over_time") if isinstance(queries.get("ads_over_time"), dict) else {}
    points: list[dict[str, Any]] = []

    def to_int(value: Any) -> int:
        try:
            return int(float(value or 0))
        except (TypeError, ValueError):
            return 0

    history_rows = list_from_payload(queries, "history", "data", "queries")
    if history_rows:
        for index, row in enumerate(history_rows):
            if not isinstance(row, dict):
                continue
            label = row.get("timestamp") or row.get("time") or row.get("date") or index
            blocked_count = to_int(row.get("blocked") or row.get("ads") or row.get("ads_count"))
            allowed = to_int(row.get("allowed") or row.get("permitted"))
            total = to_int(row.get("total") or row.get("queries") or row.get("count"))
            if not total and allowed:
                total = allowed + blocked_count
            points.append(
                {
                    "label": _timestamp_label(label),
                    "total": total,
                    "blocked": blocked_count,
                    "allowed": max(total - blocked_count, 0),
                }
            )
        return points[-144:]

    for key in sorted(set(domains) | set(blocked), key=lambda item: str(item)):
        total = to_int(domains.get(key))
        blocked_count = to_int(blocked.get(key))
        points.append(
            {
                "label": _timestamp_label(key),
                "total": total,
                "blocked": blocked_count,
                "allowed": max(total - blocked_count, 0),
            }
        )
    return points[-144:]


def client_activity_rows(stats_payload: Any, clients_payload: Any, query_payload: Any | None = None) -> list[dict[str, Any]]:
    clients = list_from_payload(clients_payload, "clients", "top_sources", "top_clients", "data")
    if not clients and isinstance(stats_payload, dict):
        clients = list_from_payload(stats_payload, "top_sources", "top_clients", "clients", "data")
    if not clients and isinstance(clients_payload, dict):
        for key in ("top_sources", "top_clients", "clients", "data"):
            value = clients_payload.get(key)
            if isinstance(value, dict):
                clients = list(value.items())
                break
    if not clients and isinstance(stats_payload, dict):
        for key in ("top_sources", "top_clients", "clients", "data"):
            value = stats_payload.get(key)
            if isinstance(value, dict):
                clients = list(value.items())
                break
    rows: list[dict[str, Any]] = []
    if isinstance(clients, list):
        for item in clients[:8]:
            if isinstance(item, dict):
                name = item.get("name") or item.get("client") or item.get("ip") or item.get("ip_address") or "-"
                count = item.get("count") or item.get("queries") or item.get("total") or 0
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                name, count = item[0], item[1]
            else:
                continue
            name = str(name)
            if name.strip().lower() in {"active", "total"}:
                continue
            try:
                count_value = int(float(count))
            except (TypeError, ValueError):
                count_value = 0
            if count_value:
                rows.append({"name": name, "count": count_value})
    if rows:
        return sorted(rows, key=lambda row: row["count"], reverse=True)[:8]

    recent_clients: dict[str, dict[str, Any]] = {}
    for item in list_from_payload(query_payload or {}, "queries", "data")[:300]:
        if not isinstance(item, dict):
            continue
        ip = query_client_ip(item)
        name = query_client_name(item)
        key = ip if ip != "-" else name
        if key == "-":
            continue
        row = recent_clients.setdefault(key, {"name": name if name != "-" else ip, "ip": ip, "count": 0})
        if row["name"] == "-" and name != "-":
            row["name"] = name
        row["count"] += 1
    return sorted(recent_clients.values(), key=lambda row: row["count"], reverse=True)[:8]


def _rows_from_any(payload: Any, *keys: str) -> list[Any]:
    rows = list_from_payload(payload, *keys)
    if rows:
        return rows
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, dict):
                return list(value.values())
    return []


def dhcp_lease_rows(dhcp_payload: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in _rows_from_any(dhcp_payload, "leases", "data"):
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "name": str(payload_value(item, "name", "hostname", "host") or "-"),
                "ip": str(payload_value(item, "ip", "address", "ip_address") or "-"),
                "mac": str(payload_value(item, "mac", "hwaddr", "mac_address") or "-"),
                "expires": payload_value(item, "expires", "expiry", "expires_at", "valid_until"),
                "static": payload_value(item, "static", "reserved", "reservation"),
            }
        )
    return rows


def normalise_hostname(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def known_hostnames(db: Session) -> set[str]:
    raw = get_site_setting(db, "dns_known_hostnames") or "[]"
    try:
        values = json.loads(raw)
    except (TypeError, ValueError):
        values = []
    return {normalise_hostname(value) for value in values if normalise_hostname(value)} if isinstance(values, list) else set()


def save_known_hostnames(db: Session, values: set[str]) -> None:
    row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == "dns_known_hostnames").first()
    if not row:
        row = RemoteManagerSetting(key="dns_known_hostnames")
        db.add(row)
    row.value = json.dumps(sorted(values))


def network_client_inventory(clients_payload: Any, dhcp_payload: Any, query_payload: Any, recognised_hostnames: set[str] | None = None) -> list[dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}

    def merge(row: dict[str, Any], source: str) -> None:
        ip = str(row.get("ip") or "-")
        mac = str(row.get("mac") or "-")
        key = mac if mac != "-" else ip
        if key == "-":
            return
        existing = inventory.setdefault(
            key,
            {
                "name": "-",
                "ip": "-",
                "mac": "-",
                "first_seen": None,
                "last_seen": None,
                "queries": 0,
                "blocked_queries": 0,
                "sources": set(),
            },
        )
        for field in ("name", "ip", "mac"):
            value = str(row.get(field) or "-").strip()
            if value and value != "-" and existing[field] == "-":
                existing[field] = value
        for field in ("first_seen", "last_seen"):
            value = row.get(field)
            if value and timestamp_sort_value(value) > timestamp_sort_value(existing.get(field)):
                existing[field] = value
        existing["queries"] += to_int(row.get("queries"))
        existing["blocked_queries"] += to_int(row.get("blocked_queries"))
        existing["sources"].add(source)

    def merge_client_item(item: dict[str, Any], source: str) -> None:
        merge(
            {
                "name": payload_value(item, "name", "hostname", "host", "client"),
                "ip": payload_value(item, "ip", "address", "ip_address"),
                "mac": payload_value(item, "mac", "hwaddr", "mac_address"),
                "first_seen": payload_value(item, "first_seen", "firstSeen", "firstSeenAt", "created_at"),
                "last_seen": payload_value(item, "last_seen", "lastSeen", "lastQuery", "last_query", "updated_at"),
                "queries": payload_value(item, "queries", "count", "total"),
                "blocked_queries": payload_value(item, "blocked_queries", "blocked", "ads"),
            },
            source,
        )

    for item in _rows_from_any(clients_payload, "devices", "clients", "data"):
        if not isinstance(item, dict):
            continue
        merge_client_item(item, "Pi-hole network")
        for nested_key in ("ips", "addresses", "ip_addresses"):
            nested_rows = item.get(nested_key)
            if isinstance(nested_rows, list):
                for nested in nested_rows:
                    if not isinstance(nested, dict):
                        continue
                    nested.setdefault("mac", payload_value(item, "mac", "hwaddr", "mac_address"))
                    merge_client_item(nested, "Pi-hole network")

    if isinstance(clients_payload, dict):
        for key in ("top_sources", "top_clients", "clients", "data"):
            value = clients_payload.get(key)
            if not isinstance(value, dict):
                continue
            for name, count in value.items():
                merge({"name": name, "ip": name, "queries": count}, "Pi-hole activity")

    for lease in dhcp_lease_rows(dhcp_payload):
        merge(
            {
                "name": lease["name"],
                "ip": lease["ip"],
                "mac": lease["mac"],
                "last_seen": lease["expires"],
            },
            "DHCP lease",
        )

    for item in list_from_payload(query_payload, "queries", "data")[:200]:
        if not isinstance(item, dict):
            continue
        status_text = f"{query_status(item)} {query_reply_type(item)}".lower()
        merge(
            {
                "name": query_client_name(item),
                "ip": query_client_ip(item),
                "last_seen": payload_value(item, "time", "timestamp", "date"),
                "queries": 1,
                "blocked_queries": 1 if any(term in status_text for term in ("block", "gravity", "deny", "regex")) else 0,
            },
            "Recent query",
        )

    rows = []
    recognised_hostnames = recognised_hostnames or set()
    now = datetime.now().timestamp()
    for row in inventory.values():
        first_seen_stamp = timestamp_sort_value(row.get("first_seen"))
        recent_first_seen = bool(first_seen_stamp and now - first_seen_stamp <= 24 * 60 * 60)
        hostname_key = normalise_hostname(row["name"])
        unknown_name = row["name"] in {"-", "", row["ip"]}
        row["is_new"] = recent_first_seen
        row["is_known"] = bool(hostname_key and not unknown_name and hostname_key in recognised_hostnames)
        row["is_unknown"] = not row["is_known"]
        row["hostname_key"] = hostname_key
        row["source_label"] = ", ".join(sorted(row["sources"]))
        row["first_seen_label"] = timestamp_display(row.get("first_seen"))
        row["last_seen_label"] = timestamp_display(row.get("last_seen"))
        rows.append(row)
    return sorted(rows, key=lambda item: (not item["is_new"], not item["is_unknown"], -timestamp_sort_value(item.get("last_seen"))))


def attention_client_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("is_new") or row.get("is_unknown")]


RISKY_DOMAIN_TERMS: dict[str, tuple[str, ...]] = {
    "Adult content": ("porn", "xxx", "adult", "sex", "camgirl", "onlyfans"),
    "Gambling": ("casino", "betting", "bet365", "poker", "gambling"),
    "Malware/phishing": ("malware", "phish", "trojan", "botnet", "cryptominer"),
    "Piracy/torrents": ("torrent", "pirate", "warez"),
}


def risky_blocked_queries(query_payload: Any) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for item in list_from_payload(query_payload, "queries", "data")[:300]:
        if not isinstance(item, dict):
            continue
        status_text = f"{query_status(item)} {query_reply_type(item)}".lower()
        if not any(term in status_text for term in ("block", "gravity", "deny", "regex")):
            continue
        domain = query_domain(item).strip().strip(".").lower()
        if not domain or domain == "-":
            continue
        category = ""
        for label, terms in RISKY_DOMAIN_TERMS.items():
            if any(term in domain for term in terms):
                category = label
                break
        if not category:
            continue
        key = f"{domain}|{query_client_ip(item)}"
        row = rows.setdefault(
            key,
            {
                "domain": domain,
                "category": category,
                "client": query_client_name(item),
                "client_ip": query_client_ip(item),
                "status": query_status(item),
                "count": 0,
                "last_seen": payload_value(item, "time", "timestamp", "date"),
            },
        )
        row["count"] += 1
        if timestamp_sort_value(payload_value(item, "time", "timestamp", "date")) > timestamp_sort_value(row.get("last_seen")):
            row["last_seen"] = payload_value(item, "time", "timestamp", "date")
    result = list(rows.values())
    for row in result:
        row["last_seen_label"] = timestamp_display(row.get("last_seen"))
    return sorted(result, key=lambda item: (-item["count"], -timestamp_sort_value(item.get("last_seen"))))[:8]


def chart_max(rows: list[dict[str, Any]], key: str) -> int:
    values: list[int] = []
    for row in rows:
        try:
            values.append(int(float(row.get(key) or 0)))
        except (AttributeError, TypeError, ValueError):
            continue
    return max(values) if values else 1


def call_provider(provider: DNSProviderConfig | None, method: str, client: DNSProvider | None = None):
    if not provider:
        return None
    dns_client = client or provider_for(provider)
    result = getattr(dns_client, method)()
    provider.last_status = "online" if result.ok else "error"
    provider.last_error = "" if result.ok else result.message
    provider.last_checked_at = datetime.utcnow()
    return result


def demo_dns_payloads() -> dict[str, DNSProviderResult]:
    now = datetime.now()
    queries = [
        {
            "time": (now.timestamp() - index * 184),
            "domain": domain,
            "client": {"name": client, "ip": ip},
            "type": qtype,
            "status": status,
            "reply": {"type": reply, "time": duration},
            "upstream": upstream,
        }
        for index, (domain, client, ip, qtype, status, reply, duration, upstream) in enumerate(
            [
                ("grafana.lab.home.arpa", "admin-laptop", "10.20.1.54", "A", "allowed", "IP", 0.0021, "local"),
                ("updates.ubuntu.com", "docker-01", "10.20.10.31", "AAAA", "allowed", "CNAME", 0.014, "1.1.1.1"),
                ("telemetry.example.invalid", "living-room-display", "10.20.30.42", "A", "blocked", "gravity", 0.0004, "-"),
                ("nas-01.lab.home.arpa", "backup-runner", "10.20.10.44", "A", "allowed", "IP", 0.0016, "local"),
                ("phish-demo.example.invalid", "unknown-android", "10.20.30.88", "A", "blocked", "gravity", 0.0003, "-"),
                ("registry-1.docker.io", "docker-01", "10.20.10.31", "A", "allowed", "IP", 0.021, "9.9.9.9"),
                ("_ldap._tcp.lab.home.arpa", "admin-laptop", "10.20.1.54", "SRV", "allowed", "NODATA", 0.0032, "local"),
                ("casino-demo.example.invalid", "guest-tablet", "10.20.40.23", "A", "blocked", "regex", 0.0005, "-"),
            ]
        )
    ]
    history_rows = [
        {"timestamp": (now.timestamp() - (11 - index) * 600), "total": 780 + index * 42, "blocked": 92 + (index % 4) * 18}
        for index in range(12)
    ]
    return {
        "status": DNSProviderResult(
            True,
            "Demo DNS status loaded.",
            {"version": {"core": {"local": {"version": "v6.0-demo"}}}, "status": "enabled"},
        ),
        "stats": DNSProviderResult(
            True,
            "Demo DNS statistics loaded.",
            {
                "queries": {"total": 18342, "blocked": 2418, "percent_blocked": 13.2},
                "clients": {"active": 12},
                "gravity": {"domains_being_blocked": 148923},
                "status": "enabled",
            },
        ),
        "history": DNSProviderResult(True, "Demo DNS history loaded.", {"queries": {"history": history_rows}}),
        "queries": DNSProviderResult(True, "Demo DNS query log loaded.", {"queries": queries}),
        "clients": DNSProviderResult(
            True,
            "Demo DNS clients loaded.",
            {
                "clients": [
                    {"name": "admin-laptop", "ip": "10.20.1.54", "mac": "02:00:5e:10:01:54", "queries": 842, "blocked_queries": 12, "last_seen": "2026-07-07 09:48"},
                    {"name": "docker-01", "ip": "10.20.10.31", "mac": "02:00:5e:10:10:31", "queries": 1488, "blocked_queries": 96, "last_seen": "2026-07-07 09:50"},
                    {"name": "living-room-display", "ip": "10.20.30.42", "mac": "02:00:5e:10:30:42", "queries": 332, "blocked_queries": 44, "last_seen": "2026-07-07 09:44"},
                    {"name": "unknown-android", "ip": "10.20.30.88", "mac": "-", "queries": 74, "blocked_queries": 18, "last_seen": "2026-07-07 09:39"},
                ]
            },
        ),
        "local_dns": DNSProviderResult(
            True,
            "Demo local DNS records loaded.",
            {
                "hosts": [
                    {"name": "router.lab.home.arpa", "ip": "10.20.1.1", "description": "Core gateway"},
                    {"name": "pve-01.lab.home.arpa", "ip": "10.20.10.11", "description": "Primary Proxmox node"},
                    {"name": "nas-01.lab.home.arpa", "ip": "10.20.10.21", "description": "Shared backup storage"},
                    {"name": "grafana.lab.home.arpa", "ip": "10.20.10.40", "description": "Observability dashboard"},
                ]
            },
        ),
        "dhcp": DNSProviderResult(
            True,
            "Demo DHCP leases loaded.",
            {
                "leases": [
                    {"name": "living-room-display", "ip": "10.20.30.42", "mac": "02:00:5e:10:30:42", "expires": "2026-07-07 14:22", "static": True},
                    {"name": "guest-tablet", "ip": "10.20.40.23", "mac": "02:00:5e:10:40:23", "expires": "2026-07-07 11:10", "static": False},
                    {"name": "unknown-android", "ip": "10.20.30.88", "mac": "-", "expires": "2026-07-07 12:05", "static": False},
                ]
            },
        ),
        "blocklists": DNSProviderResult(
            True,
            "Demo blocklists loaded.",
            {
                "lists": [
                    {"name": "StevenBlack unified hosts", "address": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "enabled": True, "date_updated": "2026-07-07"},
                    {"name": "OISD small", "address": "https://small.oisd.nl/", "enabled": True, "date_updated": "2026-07-06"},
                    {"name": "Kaya demo policy", "address": "local:demo-policy", "enabled": True, "date_updated": "2026-07-07"},
                ]
            },
        ),
    }


@router.post("/investigations")
def flag_dns_investigation(
    request: Request,
    domain: str = Form(..., max_length=500),
    client_name: str = Form("", max_length=255),
    client_ip: str = Form("", max_length=80),
    query_type_value: str = Form("", alias="query_type", max_length=40),
    reply_status: str = Form("", max_length=40),
    reply_type: str = Form("", max_length=120),
    reply_time: str = Form("", max_length=80),
    upstream: str = Form("", max_length=255),
    observed_at: str = Form("", max_length=80),
    notes: str = Form("", max_length=2000),
    return_to: str = Form("", max_length=1000),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    validate_csrf_token(request, csrf_token)
    clean_domain = domain.strip().strip(".").lower()
    if clean_domain and clean_domain != "-":
        provider = selected_provider(db) if dns_manager_enabled(db) else None
        row = DNSInvestigation(
            provider_id=provider.id if provider else None,
            domain=clean_domain,
            client_name=client_name.strip() or None,
            client_ip=client_ip.strip() or None,
            query_type=query_type_value.strip() or None,
            status="open",
            reply_type=reply_type.strip() or reply_status.strip() or None,
            reply_time=reply_time.strip() or None,
            upstream=upstream.strip() or None,
            observed_at=observed_at.strip() or None,
            notes=notes.strip() or None,
            created_by_id=user.id,
        )
        db.add(row)
        db.commit()
        write_audit(
            db,
            user,
            "flag",
            "dns_investigation",
            str(row.id),
            request.client.host if request.client else None,
            detail=f"Flagged DNS query for {clean_domain}",
            severity="warning",
            metadata={
                "domain": clean_domain,
                "client_name": client_name,
                "client_ip": client_ip,
                "query_type": query_type_value,
                "reply_type": reply_type,
                "upstream": upstream,
            },
        )
    redirect_target = "/networking/dns-manager?tab=query-log"
    candidate_return_to = return_to.strip()
    if (
        candidate_return_to.startswith("/networking/dns-manager/clients/")
        and "\\" not in candidate_return_to
        and URL(candidate_return_to).is_relative_url
    ):
        redirect_target = candidate_return_to
    return RedirectResponse(redirect_target, status_code=303)


@router.post("/investigations/{investigation_id}/delete")
def delete_dns_investigation(request: Request, investigation_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(DNSInvestigation, investigation_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DNS investigation not found")
    domain = row.domain
    db.delete(row)
    db.commit()
    write_audit(db, user, "delete", "dns_investigation", str(investigation_id), request.client.host if request.client else None, detail=domain)
    return RedirectResponse("/networking/dns-manager?tab=query-log", status_code=303)


@router.post("/known-hostnames")
def mark_known_hostname(
    request: Request,
    hostname: str = Form(..., max_length=255),
    return_tab: str = Form("clients"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    validate_csrf_token(request, csrf_token)
    if user.role not in {"admin", "editor"}:
        raise HTTPException(status_code=403, detail="Editor access is required.")
    clean = normalise_hostname(hostname)
    if not clean or clean == "-":
        raise HTTPException(status_code=400, detail="A hostname is required.")
    values = known_hostnames(db)
    values.add(clean)
    save_known_hostnames(db, values)
    db.commit()
    write_audit(
        db, user, "recognise", "dns_device", clean, request.client.host if request.client else None,
        detail="Marked DNS hostname as known", metadata={"hostname": clean},
    )
    return RedirectResponse(f"/networking/dns-manager?tab={return_tab if return_tab in DNS_TABS else 'clients'}", status_code=303)


def _dns_client(db: Session, client_id: int) -> DNSRecognisedDevice:
    row = db.query(DNSRecognisedDevice).options(joinedload(DNSRecognisedDevice.linked_ip_record), joinedload(DNSRecognisedDevice.suggested_ip_record)).filter(DNSRecognisedDevice.id == client_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="DNS client not found.")
    return row


def _client_audit(request: Request, db: Session, user, client: DNSRecognisedDevice, action: str, detail: str, **metadata) -> None:
    write_audit(db, user, action, "dns_client", str(client.id), request.client.host if request.client else None, detail=detail, metadata={"provider_id": client.provider_id, "linked_ip_record_id": client.linked_ip_record_id, **metadata})


@router.get("/clients")
def dns_clients_legacy_redirect(
    q: str = Query("", max_length=200),
    client_q: str = Query("", max_length=200),
    user=Depends(require_user),
):
    """Keep old/generated client-list URLs working and route them to the tab."""
    search = client_q or q
    params = {"tab": "clients"}
    if search:
        params["client_q"] = search
    return RedirectResponse(f"/networking/dns-manager?{urlencode(params)}", status_code=307)


@router.get("/clients/{client_id}")
def dns_client_detail(
    request: Request,
    client_id: int,
    q: str = Query("", max_length=200),
    traffic_q: str = Query("", max_length=500),
    traffic_status: str = Query("all", max_length=20),
    traffic_period: str = Query("7d", max_length=20),
    traffic_page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    client = _dns_client(db, client_id)
    like = f"%{q.strip()}%"
    records_query = db.query(IPAddress).options(joinedload(IPAddress.vlan))
    if q.strip():
        records_query = records_query.outerjoin(VLAN).filter(or_(IPAddress.address.ilike(like), IPAddress.mac_address.ilike(like), IPAddress.name.ilike(like), IPAddress.category.ilike(like), VLAN.name.ilike(like)))
    records = records_query.order_by(IPAddress.name.asc(), IPAddress.address.asc()).limit(100).all()
    priority_conditions = []
    if client.current_ip:
        priority_conditions.append(IPAddress.address == client.current_ip)
    priority_ids = {client.suggested_ip_record_id} if client.suggested_ip_record_id else set()
    priority_records = db.query(IPAddress).filter(or_(*priority_conditions)).all() if priority_conditions else []
    if client.normalised_mac:
        priority_records.extend(record for record in db.query(IPAddress).filter(IPAddress.mac_address.is_not(None)).all() if normalise_mac(record.mac_address) == client.normalised_mac)
    if priority_ids:
        priority_records.extend(db.query(IPAddress).filter(IPAddress.id.in_(priority_ids)).all())
    priority_record_ids = {record.id for record in priority_records}
    preferred_ip_record_id = client.suggested_ip_record_id or (next(iter(priority_record_ids)) if len(priority_record_ids) == 1 else None)
    records_by_id = {record.id: record for record in [*priority_records, *records]}
    records = list(records_by_id.values())
    records.sort(key=lambda row: (0 if row.id in priority_ids else 1, 0 if normalise_mac(row.mac_address) and normalise_mac(row.mac_address) == client.normalised_mac else 1, 0 if row.address == client.current_ip else 1, row.name or row.address))
    stale_raw = get_site_setting(db, "dns_stale_client_days")
    try:
        stale_days = int(stale_raw or "30")
    except ValueError:
        stale_days = 30
    try:
        client_history_days = int(get_site_setting(db, "dns_client_history_days") or "365")
    except ValueError:
        client_history_days = 365
    try:
        traffic_history_days = int(get_site_setting(db, "dns_traffic_history_days") or "30")
    except ValueError:
        traffic_history_days = 30
    period_days = {"24h": 1, "7d": 7, "30d": 30, "all": None}
    if traffic_period not in period_days:
        traffic_period = "7d"
    if traffic_status not in {"all", "allowed", "blocked"}:
        traffic_status = "all"
    traffic_base = db.query(DNSClientTrafficEvent).filter(DNSClientTrafficEvent.dns_client_id == client.id)
    cutoff_days = period_days[traffic_period]
    if cutoff_days:
        traffic_base = traffic_base.filter(DNSClientTrafficEvent.observed_at >= datetime.utcnow() - timedelta(days=cutoff_days))
    top_requested = traffic_base.with_entities(DNSClientTrafficEvent.domain.label("domain"), func.count(DNSClientTrafficEvent.id).label("count")).group_by(DNSClientTrafficEvent.domain).order_by(func.count(DNSClientTrafficEvent.id).desc(), DNSClientTrafficEvent.domain.asc()).limit(10).all()
    top_blocked = traffic_base.filter(DNSClientTrafficEvent.is_blocked == True).with_entities(DNSClientTrafficEvent.domain.label("domain"), func.count(DNSClientTrafficEvent.id).label("count")).group_by(DNSClientTrafficEvent.domain).order_by(func.count(DNSClientTrafficEvent.id).desc(), DNSClientTrafficEvent.domain.asc()).limit(10).all()  # noqa: E712
    traffic_query = traffic_base
    clean_traffic_q = traffic_q.strip().rstrip(".").lower()
    if clean_traffic_q:
        traffic_query = traffic_query.filter(DNSClientTrafficEvent.domain.ilike(f"%{clean_traffic_q}%"))
    if traffic_status == "blocked":
        traffic_query = traffic_query.filter(DNSClientTrafficEvent.is_blocked == True)  # noqa: E712
    elif traffic_status == "allowed":
        traffic_query = traffic_query.filter(DNSClientTrafficEvent.is_blocked == False)  # noqa: E712
    traffic_total = traffic_query.count()
    traffic_page_size = 8
    traffic_pages = max(1, (traffic_total + traffic_page_size - 1) // traffic_page_size)
    traffic_page = min(traffic_page, traffic_pages)
    traffic_rows = traffic_query.order_by(DNSClientTrafficEvent.observed_at.desc(), DNSClientTrafficEvent.id.desc()).offset((traffic_page - 1) * traffic_page_size).limit(traffic_page_size).all()
    return templates.TemplateResponse(request, "dns_client_detail.html", {
        "user": user, "client": client, "display_name": client_display_name(client), "status": client_status(client, stale_days),
        "ip_history": db.query(DNSClientIPHistory).filter_by(dns_client_id=client.id).order_by(DNSClientIPHistory.last_seen_at.desc()).all(),
        "hostname_history": db.query(DNSClientHostnameHistory).filter_by(dns_client_id=client.id).order_by(DNSClientHostnameHistory.last_seen_at.desc()).all(),
        "events": db.query(DNSClientEvent).filter_by(dns_client_id=client.id).order_by(DNSClientEvent.created_at.desc()).limit(250).all(),
        "traffic_rows": traffic_rows, "traffic_total": traffic_total, "traffic_page": traffic_page, "traffic_pages": traffic_pages,
        "traffic_filters": {"q": clean_traffic_q, "status": traffic_status, "period": traffic_period},
        "client_history_days": client_history_days, "traffic_history_days": traffic_history_days,
        "top_requested": top_requested, "top_blocked": top_blocked,
        "flagged_traffic_domains": open_investigation_domains(db, client.provider), "domain_root": domain_root, "domain_kind": domain_kind,
        "ip_records": records, "preferred_ip_record_id": preferred_ip_record_id, "priority_ip_record_ids": priority_record_ids, "q": q.strip(), **csrf_context(request),
    })


@router.post("/clients/{client_id}/update")
def update_dns_client(request: Request, client_id: int, friendly_name: str = Form("", max_length=255), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    client = _dns_client(db, client_id)
    old = f"friendly_name={client.friendly_name or ''}; notes={client.notes or ''}"
    client.friendly_name = friendly_name.strip() or None
    client.notes = notes.strip() or None
    add_event(db, client, "client_updated", "Friendly name or notes updated", old=old, new=f"friendly_name={client.friendly_name or ''}; notes={client.notes or ''}")
    db.commit()
    _client_audit(request, db, user, client, "update", "Updated DNS client friendly name or notes", old=old)
    return RedirectResponse(f"/networking/dns-manager/clients/{client.id}", status_code=303)


@router.post("/clients/{client_id}/state")
def set_dns_client_state(request: Request, client_id: int, action: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    client = _dns_client(db, client_id)
    allowed = {"known", "unknown", "ignore", "unignore"}
    if action not in allowed:
        raise HTTPException(status_code=400, detail="Unsupported client action.")
    old = {"is_known": client.is_known, "is_ignored": client.is_ignored, "linked_ip_record_id": client.linked_ip_record_id}
    event_type = ""
    if action == "known":
        client.is_known, event_type = True, "client_marked_known"
    elif action == "unknown":
        client.is_known, event_type = False, "client_marked_unknown"
    elif action == "ignore":
        client.is_ignored, event_type = True, "ignored"
    else:
        client.is_ignored, event_type = False, "restored"
    add_event(db, client, event_type, event_type.replace("_", " ").capitalize(), old=str(old), new=action)
    db.commit()
    _client_audit(request, db, user, client, event_type, f"DNS client {action}", old=old, new=action)
    return RedirectResponse(f"/networking/dns-manager/clients/{client.id}", status_code=303)


@router.post("/clients/{client_id}/link")
def link_dns_client(request: Request, client_id: int, ip_record_id: int = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    client = _dns_client(db, client_id)
    record = db.get(IPAddress, ip_record_id)
    if not record:
        raise HTTPException(status_code=404, detail="VLAN/IP record not found.")
    ip_match = bool(client.current_ip and client.current_ip == record.address)
    mac_match = bool(client.normalised_mac and normalise_mac(record.mac_address) == client.normalised_mac)
    if not ip_match and not mac_match:
        raise HTTPException(status_code=400, detail="Confirm links require an exact current IP or MAC match.")
    if ip_match and not mac_match and dhcp_range_for_ip(db, client.current_ip):
        raise HTTPException(status_code=409, detail="An IP-only link cannot be confirmed inside a DHCP range. Add or observe the device MAC address first.")
    old = client.linked_ip_record_id
    client.linked_ip_record_id, client.is_known = record.id, True
    client.suggested_ip_record_id = None
    client.match_method, client.match_confidence = "manual", 100
    add_event(db, client, "linked_to_ip_record", f"Linked to managed record {record.name or record.address}", old=str(old or ""), new=str(record.id))
    db.commit()
    _client_audit(request, db, user, client, "link", f"Linked DNS client to {record.name or record.address}", old=old, new=record.id)
    return RedirectResponse(f"/networking/dns-manager/clients/{client.id}", status_code=303)


@router.post("/clients/{client_id}/unlink")
def unlink_dns_client(request: Request, client_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    client = _dns_client(db, client_id)
    old = client.linked_ip_record_id
    client.linked_ip_record_id = None
    client.suggested_ip_record_id = None
    client.match_confidence = None
    client.match_method = None
    add_event(db, client, "unlinked_from_ip_record", "Unlinked from managed IP record", old=str(old or ""))
    db.commit()
    _client_audit(request, db, user, client, "unlink", "Unlinked DNS client from managed IP record", old=old)
    return RedirectResponse(f"/networking/dns-manager/clients/{client.id}", status_code=303)


@router.post("/clients/{client_id}/create-ip-record")
def create_ip_record_from_dns(request: Request, client_id: int, address: str = Form(..., max_length=80), name: str = Form("", max_length=255), assignment_type: str = Form("Dynamic"), vlan_id: int | None = Form(None), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    client = _dns_client(db, client_id)
    try:
        from ipaddress import ip_address
        address = str(ip_address(address.strip()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Enter a valid IP address.") from exc
    scope = dhcp_range_for_ip(db, address)
    vlan = db.get(VLAN, vlan_id) if vlan_id else db.get(VLAN, scope.vlan_id) if scope and scope.vlan_id else db.query(VLAN).order_by(VLAN.id.asc()).first()
    if db.query(IPAddress).filter_by(vlan_id=vlan.id if vlan else None, address=address).first():
        raise HTTPException(status_code=409, detail="That IP address already has a managed record in this VLAN. Link it instead.")
    record = IPAddress(vlan_id=vlan.id if vlan else None, address=address, name=name.strip() or client.hostname or None, mac_address=client.normalised_mac, assignment_type="Static" if assignment_type == "Static" else "Dynamic", description=f"Created from DNS observation for {client_display_name(client)}")
    db.add(record)
    db.flush()
    client.linked_ip_record_id, client.is_known = record.id, True
    client.match_method, client.match_confidence = "created_from_dns", 100
    add_event(db, client, "linked_to_ip_record", "Created and linked VLAN/IP record", new=str(record.id))
    db.commit()
    _client_audit(request, db, user, client, "create", f"Created VLAN/IP record {record.address} from DNS client", new=record.id)
    return RedirectResponse(f"/networking/vlan-ip-manager/{record.id}", status_code=303)


@router.post("/clients/{client_id}/delete")
def delete_dns_client(request: Request, client_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    client = _dns_client(db, client_id)
    label, linked = client_display_name(client), client.linked_ip_record_id
    db.delete(client)
    db.commit()
    write_audit(db, user, "delete", "dns_client", str(client_id), request.client.host if request.client else None, detail=f"Deleted retained DNS client {label}; managed record was not deleted", metadata={"linked_ip_record_id": linked})
    return RedirectResponse("/networking/dns-manager?tab=clients", status_code=303)


@router.post("/clients/{client_id}/update-managed-ip")
def update_managed_ip_from_dns(request: Request, client_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    client = _dns_client(db, client_id)
    record = client.linked_ip_record
    if not record or not client.current_ip:
        raise HTTPException(status_code=400, detail="This client has no linked record or observed IP address.")
    if dhcp_range_for_ip(db, client.current_ip) and not (client.normalised_mac or client.provider_client_id):
        raise HTTPException(status_code=409, detail="A managed address inside a DHCP range can only move with a stable MAC or provider client ID.")
    collision = db.query(IPAddress).filter(IPAddress.vlan_id == record.vlan_id, IPAddress.address == client.current_ip, IPAddress.id != record.id).first()
    if collision:
        raise HTTPException(status_code=409, detail="That address is already allocated to another record in this VLAN.")
    old = record.address
    record.address = client.current_ip
    add_event(db, client, "managed_record_updated", "Managed IP explicitly updated", old=old, new=record.address)
    db.commit()
    _client_audit(request, db, user, client, "update", "Updated linked managed IP from DNS observation", old=old, new=record.address)
    return RedirectResponse(f"/networking/dns-manager/clients/{client.id}", status_code=303)


@router.post("/clients/{client_id}/merge")
def merge_dns_clients(request: Request, client_id: int, duplicate_id: int = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    primary, duplicate = _dns_client(db, client_id), _dns_client(db, duplicate_id)
    if primary.id == duplicate.id:
        raise HTTPException(status_code=400, detail="Choose a different duplicate client.")
    if primary.linked_ip_record_id and duplicate.linked_ip_record_id and primary.linked_ip_record_id != duplicate.linked_ip_record_id:
        raise HTTPException(status_code=409, detail="Both clients have different managed links. Unlink one before merging.")
    for history_model, value_field in [(DNSClientIPHistory, "ip_address"), (DNSClientHostnameHistory, "normalised_hostname")]:
        for item in db.query(history_model).filter_by(dns_client_id=duplicate.id).all():
            existing = db.query(history_model).filter(getattr(history_model, "dns_client_id") == primary.id, getattr(history_model, value_field) == getattr(item, value_field)).first()
            if existing:
                existing.first_seen_at = min(existing.first_seen_at, item.first_seen_at)
                existing.last_seen_at = max(existing.last_seen_at, item.last_seen_at)
                existing.observation_count += item.observation_count
                db.delete(item)
            else:
                item.dns_client_id = primary.id
    db.query(DNSClientEvent).filter_by(dns_client_id=duplicate.id).update({DNSClientEvent.dns_client_id: primary.id}, synchronize_session=False)
    primary.is_known = primary.is_known or duplicate.is_known
    primary.is_ignored = primary.is_ignored or duplicate.is_ignored
    primary.linked_ip_record_id = primary.linked_ip_record_id or duplicate.linked_ip_record_id
    primary.friendly_name = primary.friendly_name or duplicate.friendly_name
    if duplicate.notes and duplicate.notes not in (primary.notes or ""):
        primary.notes = "\n\n".join(value for value in [primary.notes, duplicate.notes] if value)
    primary.first_seen_at = min(primary.first_seen_at, duplicate.first_seen_at)
    primary.last_seen_at = max(primary.last_seen_at, duplicate.last_seen_at)
    add_event(db, primary, "clients_merged", f"Merged retained DNS client {duplicate.id}", old=str(duplicate.id), new=str(primary.id))
    db.delete(duplicate)
    db.commit()
    _client_audit(request, db, user, primary, "merge", f"Merged DNS client {duplicate_id} into {primary.id}", old=duplicate_id, new=primary.id)
    return RedirectResponse(f"/networking/dns-manager/clients/{primary.id}", status_code=303)


@router.get("/connection-status")
def dns_connection_status(provider_id: int | None = Query(None), db: Session = Depends(get_db), user=Depends(require_user)):
    provider = selected_provider(db) if dns_manager_enabled(db) else None
    if provider_id is not None and dns_manager_enabled(db):
        provider = (
            db.query(DNSProviderConfig)
            .filter(DNSProviderConfig.id == provider_id, DNSProviderConfig.is_enabled == True)  # noqa: E712
            .first()
        )
    if not provider:
        return JSONResponse({"connected": False, "message": "No enabled provider is configured."})
    if get_settings().demo_mode:
        return JSONResponse({"connected": True, "message": "Demo Pi-hole connected."})
    result = call_provider(provider, "test_connection", provider_for(provider))
    db.commit()
    return JSONResponse({"connected": result.ok, "message": result.message})


@router.post("/blocklists/update")
def update_dns_blocklists(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    validate_csrf_token(request, csrf_token)
    if user.role not in {"admin", "editor"}:
        raise HTTPException(status_code=403, detail="Editor access is required.")
    provider = selected_provider(db) if dns_manager_enabled(db) else None
    if not provider:
        result = DNSProviderResult(False, "No enabled provider is configured.")
    elif get_settings().demo_mode:
        result = DNSProviderResult(True, "Demo Pi-hole blocklists updated successfully.")
    else:
        result = provider_for(provider).update_blocklists()
    write_audit(
        db, user, "refresh", "dns_blocklists", str(provider.id) if provider else None,
        request.client.host if request.client else None,
        detail="DNS provider blocklist refresh succeeded" if result.ok else "DNS provider blocklist refresh failed",
        severity="info" if result.ok else "warning",
        metadata={"provider_id": provider.id if provider else None, "outcome": "success" if result.ok else "failed"},
    )
    params = urlencode({"tab": "blocklists", "notice": result.message, "notice_kind": "success" if result.ok else "error"})
    return RedirectResponse(f"/networking/dns-manager?{params}", status_code=303)


@router.post("/insights/analyse")
def analyse_dns_insights(
    request: Request,
    provider_id: int = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    validate_csrf_token(request, csrf_token)
    if user.role not in {"admin", "editor"}:
        raise HTTPException(status_code=403, detail="Editor access is required.")
    provider = (
        db.query(DNSProviderConfig)
        .filter(DNSProviderConfig.id == provider_id, DNSProviderConfig.is_enabled == True)  # noqa: E712
        .first()
    )
    if not provider:
        raise HTTPException(status_code=404, detail="DNS provider not found.")
    try:
        result = analyse_provider(db, provider, known_hostnames_raw=get_site_setting(db, "dns_known_hostnames"))
    except AnalysisAlreadyRunning as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=409)
    except Exception:
        write_audit(
            db, user, "analyse", "dns_insights", str(provider.id), request.client.host if request.client else None,
            detail=f"DNS insight analysis failed for {provider.name}", severity="warning",
            metadata={"provider_id": provider.id, "outcome": "failed"},
        )
        return JSONResponse({"ok": False, "message": "Unable to update DNS insights. Previous successful results have been preserved."}, status_code=502)
    write_audit(
        db, user, "analyse", "dns_insights", str(provider.id), request.client.host if request.client else None,
        detail=f"DNS insight analysis completed for {provider.name}",
        metadata={"provider_id": provider.id, "created": result.created, "updated": result.updated, "resolved": result.resolved},
    )
    return JSONResponse({"ok": True, "message": "DNS insights updated.", "active": result.active, "analysed_at": result.generated_at.isoformat()})


@router.post("/insights/{insight_id}/acknowledge")
def acknowledge_dns_insight(
    insight_id: int,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    validate_csrf_token(request, csrf_token)
    if user.role not in {"admin", "editor"}:
        raise HTTPException(status_code=403, detail="Editor access is required.")
    insight = db.get(DNSInsight, insight_id)
    if not insight:
        raise HTTPException(status_code=404, detail="DNS insight not found.")
    insight.acknowledged_at = datetime.utcnow()
    insight.acknowledged_by_id = user.id
    db.commit()
    write_audit(
        db, user, "acknowledge", "dns_insight", str(insight.id), request.client.host if request.client else None,
        detail=f"Acknowledged DNS insight {insight.rule_key}", metadata={"provider_id": insight.provider_id, "insight_id": insight.id},
    )
    return JSONResponse({"ok": True, "message": "Insight acknowledged."})


@router.get("")
def dns_manager(
    request: Request,
    tab: str = Query("dashboard"),
    notice: str = Query("", max_length=500),
    notice_kind: str = Query("", max_length=20),
    provider_id: int | None = Query(None),
    insight_status: str = Query("active", max_length=20),
    insight_severity: str = Query("all", max_length=20),
    insight_category: str = Query("all", max_length=40),
    insight_period: str = Query("30d", max_length=20),
    dns_domain: str = Query("", max_length=500),
    dns_client: str = Query("", max_length=255),
    client_q: str = Query("", max_length=200),
    client_status_filter: str = Query("", alias="client_status", max_length=40),
    client_page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    active_tab = tab if tab in DNS_TABS else "dashboard"
    enabled = dns_manager_enabled(db)
    provider = selected_provider(db) if enabled else None
    if active_tab == "insights" and enabled and provider_id is not None:
        requested_provider = (
            db.query(DNSProviderConfig)
            .filter(DNSProviderConfig.id == provider_id, DNSProviderConfig.is_enabled == True)  # noqa: E712
            .first()
        )
        if requested_provider:
            provider = requested_provider
    status = stats = history = queries = clients = local_dns = dhcp = blocklists = None
    error = None
    flagged_domains: set[str] = set()
    investigations: list[DNSInvestigation] = []
    retained_client_rows: list[DNSRecognisedDevice] = []
    retained_client_total = 0

    if enabled and provider:
        if get_settings().demo_mode:
            demo_payloads = demo_dns_payloads()
            if active_tab == "dashboard":
                status = demo_payloads["status"]
                stats = demo_payloads["stats"]
                history = demo_payloads["history"]
                clients = demo_payloads["clients"]
                dhcp = demo_payloads["dhcp"]
                queries = demo_payloads["queries"]
                blocklists = demo_payloads["blocklists"]
            elif active_tab == "query-log":
                queries = demo_payloads["queries"]
            elif active_tab == "clients":
                clients = demo_payloads["clients"]
                dhcp = demo_payloads["dhcp"]
                queries = demo_payloads["queries"]
            elif active_tab == "local-dns":
                local_dns = demo_payloads["local_dns"]
            elif active_tab == "dhcp":
                dhcp = demo_payloads["dhcp"]
            elif active_tab == "blocklists":
                blocklists = demo_payloads["blocklists"]
        else:
            provider_client = provider_for(provider)
            if active_tab == "dashboard":
                status = call_provider(provider, "get_status", provider_client)
                stats = call_provider(provider, "get_statistics", provider_client)
                history = call_provider(provider, "get_history", provider_client)
                clients = call_provider(provider, "get_clients", provider_client)
                dhcp = call_provider(provider, "get_dhcp_leases", provider_client)
                queries = provider_client.get_query_log(limit=300)
                blocklists = call_provider(provider, "get_blocklists", provider_client)
            elif active_tab == "query-log":
                queries = provider_client.get_query_log(limit=200)
            elif active_tab == "clients":
                # Client inventory is populated by the background collector.
                # Normal page rendering never waits for Pi-hole.
                pass
            elif active_tab == "local-dns":
                local_dns = call_provider(provider, "get_local_dns_records", provider_client)
            elif active_tab == "dhcp":
                dhcp = call_provider(provider, "get_dhcp_leases", provider_client)
            elif active_tab == "blocklists":
                blocklists = call_provider(provider, "get_blocklists", provider_client)

            db.commit()
        active_result = next((item for item in [status, stats, history, queries, clients, local_dns, dhcp, blocklists] if item and not item.ok), None)
        error = active_result.message if active_result else None
        flagged_domains = open_investigation_domains(db, provider)
        investigations = (
            db.query(DNSInvestigation)
            .filter(DNSInvestigation.provider_id == provider.id, DNSInvestigation.status == "open")
            .order_by(DNSInvestigation.created_at.desc())
            .limit(100)
            .all()
        )

    recognised_hostnames = known_hostnames(db)
    if active_tab == "clients" and not get_settings().demo_mode:
        retained_client_rows, retained_client_total = list_clients(
            db, provider_id=provider.id if provider else None, search=client_q,
            status=client_status_filter, offset=(client_page - 1) * 100, limit=100,
        )
    insight_rows: list[DNSInsight] = []
    last_analysis_at = None
    health_score = None
    insight_summary = {"active": 0, "warnings": 0, "critical": 0, "acknowledged": 0}
    analysis_coverage = None
    if active_tab == "insights" and provider:
        query = db.query(DNSInsight).filter(DNSInsight.provider_id == provider.id)
        if insight_status == "active":
            query = query.filter(DNSInsight.status == "active", DNSInsight.acknowledged_at.is_(None))
        elif insight_status == "acknowledged":
            query = query.filter(DNSInsight.status == "active", DNSInsight.acknowledged_at.is_not(None))
        elif insight_status == "resolved":
            query = query.filter(DNSInsight.status == "resolved")
        if insight_severity == "attention":
            query = query.filter(DNSInsight.severity.in_(["critical", "warning"]))
        elif insight_severity in SEVERITY_LABELS:
            query = query.filter(DNSInsight.severity == insight_severity)
        if insight_category in CATEGORY_LABELS:
            query = query.filter(DNSInsight.category == insight_category)
        period_days = {"today": 1, "24h": 1, "7d": 7, "30d": 30}.get(insight_period, 30)
        query = query.filter(DNSInsight.last_detected_at >= datetime.utcnow() - timedelta(days=period_days))
        insight_rows = query.all()
        insight_rows.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), -item.last_detected_at.timestamp()))
        last_snapshot = (
            db.query(DNSStatisticsSnapshot)
            .filter(DNSStatisticsSnapshot.provider_id == provider.id, DNSStatisticsSnapshot.provider_connected == True)  # noqa: E712
            .order_by(DNSStatisticsSnapshot.period_end.desc())
            .first()
        )
        last_analysis_at = last_snapshot.period_end if last_snapshot else None
        if last_snapshot:
            try:
                capabilities = json.loads(last_snapshot.capabilities_json or "[]")
            except (TypeError, ValueError):
                capabilities = []
            try:
                summary_data = json.loads(last_snapshot.analysis_summary_json or "{}")
            except (TypeError, ValueError):
                summary_data = {}
            try:
                domain_data = json.loads(last_snapshot.domain_aggregates_json or "{}")
            except (TypeError, ValueError):
                domain_data = {}
            analysis_coverage = {
                "capabilities": capabilities if isinstance(capabilities, list) else [],
                "query_sample_count": summary_data.get("query_sample_count"),
                "clients_analysed": summary_data.get("clients_analysed"),
                "recognised_clients": summary_data.get("recognised_clients"),
                "unrecognised_clients": summary_data.get("unrecognised_clients"),
                "rules_evaluated": summary_data.get("rules_evaluated"),
                "rules_skipped": summary_data.get("rules_skipped"),
                "insights_generated": summary_data.get("insights_generated"),
                "baseline_available": summary_data.get("baseline_available", False),
                "total_queries": last_snapshot.total_queries,
                "blocked_queries": last_snapshot.blocked_queries,
                "failed_queries": last_snapshot.failed_queries,
                "active_clients": last_snapshot.active_clients,
                "blocking_enabled": last_snapshot.blocking_enabled,
                "top_blocked_domains": domain_data.get("top_blocked_domains", []) if isinstance(domain_data, dict) else [],
                "top_client_domain_pairs": domain_data.get("top_client_domain_pairs", []) if isinstance(domain_data, dict) else [],
            }
        all_provider_insights = db.query(DNSInsight).filter(DNSInsight.provider_id == provider.id).all()
        health_score = calculate_health_score(provider, all_provider_insights, last_analysis_at)
        insight_summary = {
            "active": sum(1 for item in all_provider_insights if item.status == "active"),
            "warnings": sum(1 for item in all_provider_insights if item.status == "active" and item.severity == "warning"),
            "critical": sum(1 for item in all_provider_insights if item.status == "active" and item.severity == "critical"),
            "acknowledged": sum(1 for item in all_provider_insights if item.status == "active" and item.acknowledged_at),
        }
    return templates.TemplateResponse(
        request,
        "dns_manager.html",
        {
            "user": user,
            "demo_mode": get_settings().demo_mode,
            "enabled": enabled,
            "provider": provider,
            "providers": configured_providers(db) if enabled else [],
            "active_tab": active_tab,
            "tabs": DNS_TABS,
            "status": status,
            "stats": stats,
            "history": history,
            "queries": queries,
            "clients": clients,
            "local_dns": local_dns,
            "dhcp": dhcp,
            "blocklists": blocklists,
            "error": error,
            "notice": notice,
            "notice_kind": notice_kind,
            "recognised_hostnames": recognised_hostnames,
            "retained_client_rows": retained_client_rows,
            "retained_client_total": retained_client_total,
            "client_filters": {"q": client_q, "status": client_status_filter, "page": client_page},
            "client_display_name": client_display_name,
            "client_status": client_status,
            "flagged_domains": flagged_domains,
            "investigations": investigations,
            "insight_rows": insight_rows,
            "last_analysis_at": last_analysis_at,
            "health_score": health_score,
            "insight_summary": insight_summary,
            "analysis_coverage": analysis_coverage,
            "category_labels": CATEGORY_LABELS,
            "severity_labels": SEVERITY_LABELS,
            "insight_action_target": insight_action_target,
            "insight_filters": {"status": insight_status, "severity": insight_severity, "category": insight_category, "period": insight_period},
            "list_from_payload": list_from_payload,
            "stat_value": stat_value,
            "display_number": display_number,
            "timestamp_display": timestamp_display,
            "query_domain": query_domain,
            "query_type": query_type,
            "query_status": query_status,
            "query_upstream": query_upstream,
            "filtered_query_rows": filtered_query_rows,
            "dns_query_filters": {"domain": dns_domain, "client": dns_client},
            "query_log_time": query_log_time,
            "query_client_name": query_client_name,
            "query_client_ip": query_client_ip,
            "query_reply_type": query_reply_type,
            "query_reply_time": query_reply_time,
            "domain_root": domain_root,
            "domain_kind": domain_kind,
            "query_chart_points": query_chart_points,
            "client_activity_rows": client_activity_rows,
            "dhcp_lease_rows": dhcp_lease_rows,
            "network_client_inventory": network_client_inventory,
            "attention_client_rows": attention_client_rows,
            "risky_blocked_queries": risky_blocked_queries,
            "chart_max": chart_max,
            **csrf_context(request),
        },
    )
