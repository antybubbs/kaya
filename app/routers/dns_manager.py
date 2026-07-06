from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.csrf import csrf_context
from app.db.session import get_db
from app.models.models import DNSProviderConfig
from app.routers.auth import require_user
from app.services.dns_providers import DNSProvider, provider_for
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
            "list_from_payload": list_from_payload,
            "stat_value": stat_value,
            "display_number": display_number,
            "query_chart_points": query_chart_points,
            "client_activity_rows": client_activity_rows,
            "chart_max": chart_max,
            **csrf_context(request),
        },
    )
