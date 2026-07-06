from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import DNSInvestigation, DNSProviderConfig
from app.routers.auth import require_user
from app.services.dns_providers import DNSProvider, provider_for
from app.services.audit import write_audit
from app.services.site_settings import get_site_setting

router = APIRouter(prefix="/networking/dns-manager")
templates = Jinja2Templates(directory="app/templates")

DNS_TABS = ["dashboard", "query-log", "clients", "local-dns", "dhcp", "blocklists", "reports"]


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
        return datetime.fromtimestamp(numeric).strftime("%Y-%m-%d %H:%M:%S")
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
    for key in sorted(set(domains) | set(blocked), key=lambda item: str(item)):
        total = int(float(domains.get(key) or 0))
        blocked_count = int(float(blocked.get(key) or 0))
        points.append(
            {
                "label": _timestamp_label(key),
                "total": total,
                "blocked": blocked_count,
                "allowed": max(total - blocked_count, 0),
            }
        )
    return points[-144:]


def client_activity_rows(stats_payload: Any, clients_payload: Any) -> list[dict[str, Any]]:
    clients = list_from_payload(clients_payload, "clients", "top_sources", "top_clients", "data")
    if not clients and isinstance(stats_payload, dict):
        clients = list_from_payload(stats_payload, "top_sources", "top_clients", "clients", "data")
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
            try:
                count_value = int(float(count))
            except (TypeError, ValueError):
                count_value = 0
            rows.append({"name": str(name), "count": count_value})
    return rows


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
    return RedirectResponse("/networking/dns-manager?tab=query-log", status_code=303)


@router.get("")
def dns_manager(
    request: Request,
    tab: str = Query("dashboard"),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    active_tab = tab if tab in DNS_TABS else "dashboard"
    enabled = dns_manager_enabled(db)
    provider = selected_provider(db) if enabled else None
    status = stats = history = queries = clients = local_dns = dhcp = blocklists = None
    error = None
    flagged_domains: set[str] = set()
    investigations: list[DNSInvestigation] = []

    if enabled and provider:
        dns_client = provider_for(provider)
        if active_tab == "dashboard":
            status = call_provider(provider, "get_status", dns_client)
            stats = call_provider(provider, "get_statistics", dns_client)
            history = call_provider(provider, "get_history", dns_client)
        elif active_tab == "query-log":
            queries = dns_client.get_query_log(limit=200)
        elif active_tab == "clients":
            clients = call_provider(provider, "get_clients", dns_client)
        elif active_tab == "local-dns":
            local_dns = call_provider(provider, "get_local_dns_records", dns_client)
        elif active_tab == "dhcp":
            dhcp = call_provider(provider, "get_dhcp_leases", dns_client)
        elif active_tab == "blocklists":
            blocklists = call_provider(provider, "get_blocklists", dns_client)

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

    return templates.TemplateResponse(
        request,
        "dns_manager.html",
        {
            "user": user,
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
            "flagged_domains": flagged_domains,
            "investigations": investigations,
            "list_from_payload": list_from_payload,
            "stat_value": stat_value,
            "display_number": display_number,
            "query_domain": query_domain,
            "query_type": query_type,
            "query_status": query_status,
            "query_upstream": query_upstream,
            "query_log_time": query_log_time,
            "query_client_name": query_client_name,
            "query_client_ip": query_client_ip,
            "query_reply_type": query_reply_type,
            "query_reply_time": query_reply_time,
            "domain_root": domain_root,
            "domain_kind": domain_kind,
            "query_chart_points": query_chart_points,
            "client_activity_rows": client_activity_rows,
            "chart_max": chart_max,
            **csrf_context(request),
        },
    )
