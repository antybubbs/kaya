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
from app.services.dns_providers import provider_for
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


def call_provider(provider: DNSProviderConfig | None, method: str):
    if not provider:
        return None
    result = getattr(provider_for(provider), method)()
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
    status = stats = queries = clients = local_dns = dhcp = blocklists = None
    error = None

    if enabled and provider:
        if active_tab == "dashboard":
            status = call_provider(provider, "get_status")
            stats = call_provider(provider, "get_statistics")
        elif active_tab == "query-log":
            queries = provider_for(provider).get_query_log(limit=200)
        elif active_tab == "clients":
            clients = call_provider(provider, "get_clients")
        elif active_tab == "local-dns":
            local_dns = call_provider(provider, "get_local_dns_records")
        elif active_tab == "dhcp":
            dhcp = call_provider(provider, "get_dhcp_leases")
        elif active_tab == "blocklists":
            blocklists = call_provider(provider, "get_blocklists")

        db.commit()
        active_result = next((item for item in [status, stats, queries, clients, local_dns, dhcp, blocklists] if item and not item.ok), None)
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
            "queries": queries,
            "clients": clients,
            "local_dns": local_dns,
            "dhcp": dhcp,
            "blocklists": blocklists,
            "error": error,
            "list_from_payload": list_from_payload,
            "stat_value": stat_value,
            **csrf_context(request),
        },
    )
