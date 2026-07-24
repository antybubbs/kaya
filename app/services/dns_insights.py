from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from ipaddress import ip_address
import json
import logging
import threading
import time
from typing import Any
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from app.models.models import DHCPLeaseHistory, DHCPRange, DNSClientTrafficEvent, DNSInsight, DNSProviderConfig, DNSRecognisedDevice, DNSStatisticsSnapshot
from app.services.dns_providers import DNSProvider, DNSProviderResult, provider_for, provider_snapshot_for_io
from app.services.dns_clients import normalise_mac, observe_client
from app.services.site_settings import get_site_settings


logger = logging.getLogger(__name__)


class InsightCategory:
    SYSTEM = "system"
    NETWORK = "network_activity"
    SECURITY = "security"
    DEVICES = "devices"
    TREND = "usage_trend"
    RECOMMENDATION = "recommendation"


class InsightSeverity:
    HEALTHY = "healthy"
    INFORMATION = "information"
    WARNING = "warning"
    CRITICAL = "critical"


CATEGORY_LABELS = {
    InsightCategory.SYSTEM: "System",
    InsightCategory.NETWORK: "Network Activity",
    InsightCategory.SECURITY: "Security",
    InsightCategory.DEVICES: "Devices",
    InsightCategory.TREND: "Usage Trend",
    InsightCategory.RECOMMENDATION: "Recommendation",
}
SEVERITY_LABELS = {
    InsightSeverity.HEALTHY: "Healthy",
    InsightSeverity.INFORMATION: "Information",
    InsightSeverity.WARNING: "Warning",
    InsightSeverity.CRITICAL: "Critical",
}
SEVERITY_ORDER = {
    InsightSeverity.CRITICAL: 0,
    InsightSeverity.WARNING: 1,
    InsightSeverity.INFORMATION: 2,
    InsightSeverity.HEALTHY: 3,
}


@dataclass(frozen=True)
class DNSInsightThresholds:
    provider_stale_hours: int = 1
    blocklist_info_days: int = 7
    blocklist_warning_days: int = 14
    client_query_increase_percent: float = 100.0
    network_query_change_percent: float = 40.0
    minimum_client_queries: int = 50
    minimum_network_queries: int = 500
    blocked_query_warning_percent: float = 35.0
    nxdomain_warning_percent: float = 25.0
    repeated_blocked_domain_attempts: int = 5
    frequent_client_domain_attempts: int = 10
    inactive_recognised_device_days: int = 7
    snapshot_retention_days: int = 30


DEFAULT_THRESHOLDS = DNSInsightThresholds()


@dataclass
class NormalisedClient:
    identity_type: str
    identity_value: str
    hostname: str
    ip: str
    mac: str
    queries: int = 0
    blocked_queries: int = 0
    nxdomain_queries: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    recognised: bool = False
    device_id: int | None = None
    previous_ip: str | None = None
    provider_client_id: str | None = None
    source: str = "Pi-hole sync"


@dataclass
class DNSInsightContext:
    provider: DNSProviderConfig
    generated_at: datetime
    connected: bool
    connection_message: str
    blocking_enabled: bool | None
    total_queries: int | None
    blocked_queries: int | None
    failed_queries: int | None
    active_clients: int | None
    clients: list[NormalisedClient]
    query_rows: list[dict[str, Any]]
    blocklist_updated_at: datetime | None
    previous_snapshot: DNSStatisticsSnapshot | None
    last_successful_snapshot_at: datetime | None
    capabilities: set[str] = field(default_factory=set)


@dataclass
class GeneratedInsight:
    key: str
    rule_key: str
    category: str
    severity: str
    title: str
    summary: str
    detail: str = ""
    entity_type: str | None = None
    entity_identifier: str | None = None
    current_value: str | None = None
    comparison_value: str | None = None
    percentage_change: float | None = None
    action_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleEvaluation:
    supported: bool
    insights: list[GeneratedInsight] = field(default_factory=list)


@dataclass
class AnalysisResult:
    provider_id: int
    generated_at: datetime
    created: int
    updated: int
    resolved: int
    active: int
    rules_evaluated: int
    rules_skipped: int


@dataclass
class HealthFactor:
    label: str
    state: str
    deduction: int | None


@dataclass
class HealthScore:
    score: int
    status: str
    factors: list[HealthFactor]


class AnalysisAlreadyRunning(RuntimeError):
    pass


_ANALYSIS_LOCKS: dict[int, threading.Lock] = {}
_ANALYSIS_LOCKS_GUARD = threading.Lock()


def _provider_lock(provider_id: int) -> threading.Lock:
    with _ANALYSIS_LOCKS_GUARD:
        return _ANALYSIS_LOCKS.setdefault(provider_id, threading.Lock())


def _int(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _timestamp(value: Any) -> datetime | None:
    if value in (None, "", "-"):
        return None
    try:
        numeric = float(value)
        return datetime.utcfromtimestamp(numeric)
    except (TypeError, ValueError, OSError):
        pass
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
    except (TypeError, ValueError):
        return None


def _value(payload: Any, *paths: str) -> Any:
    if not isinstance(payload, dict):
        return None
    for path in paths:
        current: Any = payload
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, ""):
            return current
    return None


def _rows(payload: Any, *keys: str) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = _rows(value, *keys)
            if nested:
                return nested
    return []


def _normalise_hostname(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _normalise_mac(value: Any) -> str:
    return normalise_mac(value) or ""


def _query_client(row: dict[str, Any]) -> tuple[str, str]:
    client = row.get("client")
    if isinstance(client, dict):
        return str(client.get("name") or client.get("hostname") or "-"), str(client.get("ip") or client.get("address") or "-")
    return str(row.get("client_name") or row.get("hostname") or "-"), str(row.get("client_ip") or row.get("ip") or client or "-")


def _query_status(row: dict[str, Any]) -> str:
    reply = row.get("reply")
    reply_type = reply.get("type") if isinstance(reply, dict) else row.get("reply_type")
    return f"{row.get('status') or ''} {reply_type or ''}".strip().lower()


def _query_domain(row: dict[str, Any]) -> str:
    return str(row.get("domain") or row.get("query") or "-").strip().rstrip(".").lower()


def _client_label(client: NormalisedClient) -> str:
    return client.hostname if client.hostname not in {"", "-", "*"} else client.ip


def _identity(hostname: str, ip: str, mac: str, provider_client_id: str = "") -> tuple[str, str]:
    if provider_client_id:
        return "provider_client", provider_client_id
    if mac and mac != "-":
        return "mac", mac
    if hostname and hostname not in {"-", ip}:
        return "hostname", _normalise_hostname(hostname)
    return "ip", ip


def _safe_result(method, label: str) -> DNSProviderResult:
    try:
        return method()
    except Exception as exc:
        logger.warning("DNS insight provider call failed", extra={"dns_operation": label, "error_type": type(exc).__name__})
        return DNSProviderResult(False, f"{label} could not be retrieved.")


def _collect_provider_data(client: DNSProvider) -> dict[str, DNSProviderResult]:
    return {
        "status": _safe_result(client.get_status, "Provider status"),
        "stats": _safe_result(client.get_statistics, "Provider statistics"),
        "history": _safe_result(client.get_history, "Provider history"),
        "clients": _safe_result(client.get_clients, "Provider clients"),
        "queries": _safe_result(lambda: client.get_query_log(limit=500), "Provider query log"),
        "dhcp": _safe_result(client.get_dhcp_leases, "Provider DHCP data"),
        "blocklists": _safe_result(client.get_blocklists, "Provider blocklist data"),
    }


def _known_hostname_set(raw: str) -> set[str]:
    try:
        values = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return set()
    return {_normalise_hostname(value) for value in values if _normalise_hostname(value)} if isinstance(values, list) else set()


def _normalise_clients(
    db: Session,
    provider: DNSProviderConfig,
    payloads: dict[str, DNSProviderResult],
    known_hostnames_raw: str,
    generated_at: datetime,
) -> list[NormalisedClient]:
    inventory: dict[tuple[str, str], NormalisedClient] = {}

    def merge(hostname: Any, ip: Any, mac: Any, *, queries: Any = 0, blocked: Any = 0, nxdomain: Any = 0, first_seen: Any = None, last_seen: Any = None, provider_client_id: Any = "", source: str = "Pi-hole sync") -> None:
        name = str(hostname or "-").strip()
        address = str(ip or "-").strip()
        mac_value = _normalise_mac(mac) or "-"
        provider_id_value = str(provider_client_id or "").strip()
        identity_type, identity_value = _identity(name, address, mac_value, provider_id_value)
        if not identity_value or identity_value == "-":
            return
        key = (identity_type, identity_value)
        if address != "-":
            existing_key = next((candidate for candidate, value in inventory.items() if value.ip == address and (mac_value == "-" or value.mac in {"-", mac_value})), None)
            if existing_key:
                key = existing_key
        row = inventory.get(key)
        if not row:
            row = NormalisedClient(identity_type, identity_value, name, address, mac_value)
            inventory[key] = row
        if row.hostname in {"", "-", row.ip} and name not in {"", "-", address}:
            row.hostname = name
        if address != "-":
            row.ip = address
        if mac_value != "-":
            row.mac = mac_value
        row.queries += _int(queries) or 0
        row.blocked_queries += _int(blocked) or 0
        row.nxdomain_queries += _int(nxdomain) or 0
        row.first_seen = _timestamp(first_seen) or row.first_seen
        row.last_seen = _timestamp(last_seen) or row.last_seen
        row.provider_client_id = provider_id_value or row.provider_client_id
        if source not in row.source:
            row.source = f"{row.source}, {source}"

    client_data = payloads["clients"].data if payloads["clients"].ok else {}
    for item in _rows(client_data, "devices", "clients", "data"):
        if not isinstance(item, dict):
            continue
        merge(
            item.get("name") or item.get("hostname") or item.get("host"),
            item.get("ip") or item.get("address") or item.get("ip_address"),
            item.get("mac") or item.get("hwaddr") or item.get("mac_address"),
            queries=item.get("queries") or item.get("count"),
            blocked=item.get("blocked_queries") or item.get("blocked"),
            first_seen=item.get("first_seen") or item.get("firstSeen"),
            last_seen=item.get("last_seen") or item.get("lastSeen"),
            provider_client_id=item.get("id") or item.get("client_id"),
            source="Pi-hole network",
        )

    dhcp_data = payloads["dhcp"].data if payloads["dhcp"].ok else {}
    for item in _rows(dhcp_data, "leases", "data"):
        if isinstance(item, dict):
            merge(item.get("name") or item.get("hostname"), item.get("ip") or item.get("address"), item.get("mac") or item.get("hwaddr"), last_seen=item.get("last_seen"), source="DHCP lease")

    query_data = payloads["queries"].data if payloads["queries"].ok else {}
    for item in _rows(query_data, "queries", "data"):
        if not isinstance(item, dict):
            continue
        name, ip = _query_client(item)
        status = _query_status(item)
        merge(
            name,
            ip,
            "-",
            queries=1,
            blocked=1 if any(term in status for term in ("block", "gravity", "deny", "regex")) else 0,
            nxdomain=1 if "nxdomain" in status else 0,
            last_seen=item.get("time") or item.get("timestamp") or item.get("date"),
            source="Recent query",
        )

    known_hostnames = _known_hostname_set(known_hostnames_raw)
    for row in inventory.values():
        hostname_key = _normalise_hostname(row.hostname)
        device = observe_client(db, provider, row, generated_at)
        if hostname_key in known_hostnames:
            device.is_known = True
        row.recognised = device.is_known or bool(device.linked_ip_record_id)
        row.device_id = device.id
        row.previous_ip = device.previous_ip
    return list(inventory.values())


def _dhcp_range_for(ranges: list[tuple[DHCPRange, Any, Any]], value: str) -> DHCPRange | None:
    try:
        parsed = ip_address(value)
    except ValueError:
        return None
    return next((row for row, start, end in ranges if start.version == parsed.version and start <= parsed <= end), None)


def _persist_dhcp_leases(
    db: Session,
    provider: DNSProviderConfig,
    dhcp_data: Any,
    clients: list[NormalisedClient],
    generated_at: datetime,
) -> None:
    """Retain lease intervals so an address reused later does not inherit another client's history."""
    lease_rows = [row for row in _rows(dhcp_data, "leases", "data") if isinstance(row, dict)]
    by_ip = {row.ip: row.device_id for row in clients if row.device_id and row.ip not in {"", "-"}}
    by_mac = {normalise_mac(row.mac): row.device_id for row in clients if row.device_id and normalise_mac(row.mac)}
    configured_ranges = []
    for scope in db.query(DHCPRange).filter(DHCPRange.is_enabled == True).all():  # noqa: E712
        try:
            configured_ranges.append((scope, ip_address(scope.start_address), ip_address(scope.end_address)))
        except ValueError:
            continue
    seen_ids: set[int] = set()
    for item in lease_rows:
        address = str(item.get("ip") or item.get("address") or item.get("ip_address") or "").strip()
        if not address:
            continue
        mac = normalise_mac(item.get("mac") or item.get("hwaddr") or item.get("mac_address"))
        hostname = str(item.get("name") or item.get("hostname") or "").strip() or None
        client_id = by_mac.get(mac) if mac else None
        client_id = client_id or by_ip.get(address)
        provider_lease_id = str(item.get("id") or item.get("lease_id") or "").strip() or None
        expires_at = _timestamp(item.get("expires_at") or item.get("expires") or item.get("expiry") or item.get("valid_until"))
        started_at = _timestamp(item.get("starts_at") or item.get("start") or item.get("leased_at")) or generated_at
        active = (
            db.query(DHCPLeaseHistory)
            .filter_by(provider_id=provider.id, ip_address=address, is_active=True)
            .order_by(DHCPLeaseHistory.last_seen_at.desc())
            .first()
        )
        same_identity = bool(active and ((mac and active.mac_address == mac) or (client_id and active.dns_client_id == client_id)))
        if active and not same_identity:
            active.is_active = False
            active.ended_at = generated_at
            active = None
        scope = _dhcp_range_for(configured_ranges, address)
        if not active:
            active = DHCPLeaseHistory(
                provider_id=provider.id,
                dns_client_id=client_id,
                dhcp_range_id=scope.id if scope else None,
                ip_address=address,
                mac_address=mac,
                hostname=hostname,
                provider_lease_id=provider_lease_id,
                lease_started_at=started_at,
                first_seen_at=generated_at,
                last_seen_at=generated_at,
                expires_at=expires_at,
                is_active=True,
                source="Pi-hole DHCP lease",
            )
            db.add(active)
            db.flush()
        else:
            active.dns_client_id = active.dns_client_id or client_id
            active.mac_address = mac or active.mac_address
            active.hostname = hostname or active.hostname
            active.provider_lease_id = provider_lease_id or active.provider_lease_id
            active.dhcp_range_id = active.dhcp_range_id or (scope.id if scope else None)
            active.last_seen_at = generated_at
            active.expires_at = expires_at or active.expires_at
        seen_ids.add(active.id)
    stale = db.query(DHCPLeaseHistory).filter_by(provider_id=provider.id, is_active=True)
    if seen_ids:
        stale = stale.filter(~DHCPLeaseHistory.id.in_(seen_ids))
    for row in stale.all():
        row.is_active = False
        row.ended_at = generated_at


def _persist_client_traffic(
    db: Session,
    provider: DNSProviderConfig,
    query_rows: list[dict[str, Any]],
    clients: list[NormalisedClient],
    generated_at: datetime,
) -> int:
    """Persist the bounded provider query sample without duplicating overlapping polls."""
    values = get_site_settings(db, {"dns_retain_client_history", "dns_traffic_history_days"})
    if values["dns_retain_client_history"] != "1":
        return 0
    by_ip = {row.ip: row.device_id for row in clients if row.device_id and row.ip not in {"", "-"}}
    by_hostname = {
        _normalise_hostname(row.hostname): row.device_id
        for row in clients
        if row.device_id and _normalise_hostname(row.hostname)
    }
    pending: list[tuple[str, int, str | None, dict[str, Any], datetime, str, bool]] = []
    for row in query_rows:
        client_name, client_ip = _query_client(row)
        client_id = by_ip.get(client_ip) or by_hostname.get(_normalise_hostname(client_name))
        domain = _query_domain(row)
        if not client_id or domain in {"", "-"}:
            continue
        observed_at = _timestamp(row.get("time") or row.get("timestamp") or row.get("date")) or generated_at
        status_text = _query_status(row)
        blocked = any(term in status_text for term in ("block", "gravity", "deny", "regex"))
        provider_event_id = row.get("id") or row.get("query_id")
        signature = {
            "provider_event_id": str(provider_event_id or ""),
            "ha_source_node_id": str(row.get("_kaya_ha_node_id") or ""),
            "client": client_ip if client_ip != "-" else _normalise_hostname(client_name),
            "domain": domain,
            "query_type": str(row.get("type") or row.get("query_type") or ""),
            "status": status_text,
            "observed_at": observed_at.isoformat(timespec="microseconds"),
        }
        event_key = hashlib.sha256(json.dumps(signature, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        pending.append((event_key, client_id, client_ip if client_ip != "-" else None, row, observed_at, domain, blocked))
    if not pending:
        return 0
    keys = list({item[0] for item in pending})
    existing = {
        key for (key,) in db.query(DNSClientTrafficEvent.event_key)
        .filter(DNSClientTrafficEvent.provider_id == provider.id, DNSClientTrafficEvent.event_key.in_(keys))
        .all()
    }
    added = 0
    for event_key, client_id, client_ip, row, observed_at, domain, blocked in pending:
        if event_key in existing:
            continue
        existing.add(event_key)
        reply = row.get("reply") if isinstance(row.get("reply"), dict) else {}
        reply_time = reply.get("time") or reply.get("duration") or row.get("reply_time") or row.get("response_time")
        try:
            reply_time_ms = float(reply_time) * 1000 if reply_time not in (None, "", "-") else None
        except (TypeError, ValueError):
            reply_time_ms = None
        upstream = row.get("upstream") or row.get("forwarded_to") or row.get("server")
        if isinstance(upstream, dict):
            upstream = upstream.get("name") or upstream.get("ip") or upstream.get("address")
        lease = None
        if client_ip:
            lease = (
                db.query(DHCPLeaseHistory)
                .filter(
                    DHCPLeaseHistory.provider_id == provider.id,
                    DHCPLeaseHistory.ip_address == client_ip,
                    DHCPLeaseHistory.dns_client_id == client_id,
                    DHCPLeaseHistory.is_active == True,  # noqa: E712
                )
                .order_by(DHCPLeaseHistory.first_seen_at.desc())
                .first()
            )
        db.add(DNSClientTrafficEvent(
            dns_client_id=client_id,
            provider_id=provider.id,
            dhcp_lease_id=lease.id if lease else None,
            event_key=event_key,
            client_ip=client_ip,
            domain=domain,
            query_type=str(row.get("type") or row.get("query_type") or "") or None,
            status=str(row.get("status") or "") or None,
            reply_type=str(reply.get("type") or row.get("reply_type") or "") or None,
            reply_time_ms=reply_time_ms,
            upstream=str(upstream) if upstream not in (None, "", "-") else None,
            is_blocked=blocked,
            observed_at=observed_at,
        ))
        added += 1
    try:
        retention_days = max(1, min(int(values["dns_traffic_history_days"] or "30"), 3650))
    except (TypeError, ValueError):
        retention_days = 30
    db.query(DNSClientTrafficEvent).filter(DNSClientTrafficEvent.observed_at < generated_at - timedelta(days=retention_days)).delete(synchronize_session=False)
    return added


def _blocklist_updated_at(payload: Any) -> datetime | None:
    stamps: list[datetime] = []
    for row in _rows(payload, "lists", "blocklists", "data"):
        if not isinstance(row, dict):
            continue
        stamp = _timestamp(row.get("date_updated") or row.get("updated_at") or row.get("last_updated"))
        if stamp:
            stamps.append(stamp)
    return max(stamps) if stamps else None


def build_context(
    db: Session,
    provider: DNSProviderConfig,
    known_hostnames_raw: str = "[]",
    *,
    payloads: dict[str, DNSProviderResult] | None = None,
) -> DNSInsightContext:
    generated_at = datetime.utcnow()
    if payloads is None:
        payloads = _collect_provider_data(provider_for(provider))
    connected = payloads["stats"].ok or payloads["status"].ok
    provider.last_status = "online" if connected else "error"
    provider.last_checked_at = generated_at
    provider.last_error = "" if connected else next((result.message for result in payloads.values() if not result.ok), "Provider data could not be retrieved.")
    stats_data = payloads["stats"].data if payloads["stats"].ok and isinstance(payloads["stats"].data, dict) else {}
    status_data = payloads["status"].data if payloads["status"].ok and isinstance(payloads["status"].data, dict) else {}
    blocking_raw = _value(stats_data, "blocking", "status", "dns.blocking") or _value(status_data, "blocking", "status")
    blocking_enabled: bool | None = None
    if isinstance(blocking_raw, bool):
        blocking_enabled = blocking_raw
    elif str(blocking_raw).lower() in {"enabled", "true", "1", "on"}:
        blocking_enabled = True
    elif str(blocking_raw).lower() in {"disabled", "false", "0", "off"}:
        blocking_enabled = False
    query_data = payloads["queries"].data if payloads["queries"].ok else {}
    query_rows = [row for row in _rows(query_data, "queries", "data") if isinstance(row, dict)]
    clients = _normalise_clients(db, provider, payloads, known_hostnames_raw, generated_at)
    if payloads["dhcp"].ok:
        _persist_dhcp_leases(db, provider, payloads["dhcp"].data, clients, generated_at)
    _persist_client_traffic(db, provider, query_rows, clients, generated_at)
    previous_snapshot = (
        db.query(DNSStatisticsSnapshot)
        .filter(DNSStatisticsSnapshot.provider_id == provider.id)
        .order_by(DNSStatisticsSnapshot.period_start.desc())
        .first()
    )
    capabilities = {key for key, result in payloads.items() if result.ok}
    return DNSInsightContext(
        provider=provider,
        generated_at=generated_at,
        connected=connected,
        connection_message="Provider connected." if connected else provider.last_error or "Provider disconnected.",
        blocking_enabled=blocking_enabled,
        total_queries=_int(_value(stats_data, "queries.total", "dns_queries_today", "queries_today")),
        blocked_queries=_int(_value(stats_data, "queries.blocked", "ads_blocked_today", "blocked_queries")),
        failed_queries=sum(1 for row in query_rows if any(term in _query_status(row) for term in ("servfail", "refused", "timeout", "dnssec"))),
        active_clients=_int(_value(stats_data, "clients.active", "unique_clients")) or len(clients),
        clients=clients,
        query_rows=query_rows,
        blocklist_updated_at=_blocklist_updated_at(payloads["blocklists"].data if payloads["blocklists"].ok else {}),
        previous_snapshot=previous_snapshot,
        last_successful_snapshot_at=previous_snapshot.period_end if previous_snapshot and previous_snapshot.provider_connected else None,
        capabilities=capabilities,
    )


class DNSInsightRule:
    key = "base"

    def evaluate(self, context: DNSInsightContext, thresholds: DNSInsightThresholds) -> RuleEvaluation:
        raise NotImplementedError


class ProviderDisconnectedRule(DNSInsightRule):
    key = "provider_disconnected"

    def evaluate(self, context, thresholds):
        if context.connected:
            return RuleEvaluation(True)
        return RuleEvaluation(True, [GeneratedInsight(
            key=self.key,
            rule_key=self.key,
            category=InsightCategory.SYSTEM,
            severity=InsightSeverity.CRITICAL,
            title="DNS provider disconnected",
            summary=f"Kaya could not retrieve current DNS data from {context.provider.name}.",
            detail="The provider may be unavailable, unreachable, or rejecting the configured credentials. Existing insight results have been preserved.",
            entity_type="provider",
            entity_identifier=str(context.provider.id),
            action_type="provider_settings",
        )])


class ProviderStaleRule(DNSInsightRule):
    key = "provider_data_stale"

    def evaluate(self, context, thresholds):
        if context.connected:
            return RuleEvaluation(True)
        if not context.last_successful_snapshot_at:
            return RuleEvaluation(False)
        age = context.generated_at - context.last_successful_snapshot_at
        if age <= timedelta(hours=thresholds.provider_stale_hours):
            return RuleEvaluation(True)
        return RuleEvaluation(True, [GeneratedInsight(
            key=self.key,
            rule_key=self.key,
            category=InsightCategory.SYSTEM,
            severity=InsightSeverity.WARNING,
            title="DNS data is stale",
            summary=f"The last successful DNS analysis was {int(age.total_seconds() // 3600)} hours ago.",
            detail=f"Kaya expects current provider data within {thresholds.provider_stale_hours} hour. Several explanations are possible, including connectivity or collection issues.",
            entity_type="provider",
            entity_identifier=str(context.provider.id),
            action_type="analyse_now",
        )])


class BlockingDisabledRule(DNSInsightRule):
    key = "blocking_disabled"

    def evaluate(self, context, thresholds):
        if context.blocking_enabled is None:
            return RuleEvaluation(False)
        if context.blocking_enabled:
            return RuleEvaluation(True)
        return RuleEvaluation(True, [GeneratedInsight(
            key=self.key,
            rule_key=self.key,
            category=InsightCategory.SYSTEM,
            severity=InsightSeverity.WARNING,
            title="DNS blocking is disabled",
            summary=f"{context.provider.name} currently reports that DNS blocking is disabled.",
            detail="Review the provider configuration before making changes. Kaya will not enable blocking automatically.",
            entity_type="provider",
            entity_identifier=str(context.provider.id),
            action_type="provider_settings",
        )])


class OutdatedBlocklistRule(DNSInsightRule):
    key = "blocklist_outdated"

    def evaluate(self, context, thresholds):
        if context.blocklist_updated_at is None:
            return RuleEvaluation(False)
        age_days = max(0, (context.generated_at - context.blocklist_updated_at).days)
        if age_days < thresholds.blocklist_info_days:
            return RuleEvaluation(True)
        severity = InsightSeverity.WARNING if age_days >= thresholds.blocklist_warning_days else InsightSeverity.INFORMATION
        return RuleEvaluation(True, [GeneratedInsight(
            key=self.key,
            rule_key=self.key,
            category=InsightCategory.SYSTEM,
            severity=severity,
            title="Blocklist data may be outdated",
            summary=f"The newest supported blocklist timestamp is {age_days} days old.",
            detail="Review or refresh the provider's blocklist data. Kaya only evaluates timestamps explicitly supplied by the provider.",
            entity_type="provider",
            entity_identifier=str(context.provider.id),
            current_value=f"{age_days} days",
            action_type="blocklists",
        )])


class NewDeviceRule(DNSInsightRule):
    key = "new_unrecognised_device"

    def evaluate(self, context, thresholds):
        if "clients" not in context.capabilities and "queries" not in context.capabilities:
            return RuleEvaluation(False)
        insights = []
        for client in context.clients:
            if client.recognised:
                continue
            insights.append(GeneratedInsight(
                key=f"{self.key}:{client.identity_type}:{client.identity_value}",
                rule_key=self.key,
                category=InsightCategory.DEVICES,
                severity=InsightSeverity.INFORMATION,
                title="New unrecognised device",
                summary=f"{_client_label(client)} is present in current DNS activity and has not been recognised in Kaya.",
                detail="Review the hostname and stable identity before marking this device as known. An IP address alone may change through DHCP.",
                entity_type="client",
                entity_identifier=client.identity_value,
                current_value=client.ip,
                action_type="review_clients",
                metadata={"hostname": client.hostname, "ip": client.ip, "mac": client.mac, "identity_type": client.identity_type},
            ))
        return RuleEvaluation(True, insights[:25])


class RecognisedDeviceIPChangeRule(DNSInsightRule):
    key = "recognised_device_ip_change"

    def evaluate(self, context, thresholds):
        insights = []
        for client in context.clients:
            if not client.recognised or not client.previous_ip:
                continue
            insights.append(GeneratedInsight(
                key=f"{self.key}:{client.device_id}",
                rule_key=self.key,
                category=InsightCategory.DEVICES,
                severity=InsightSeverity.INFORMATION,
                title="Recognised device changed IP address",
                summary=f"{client.hostname} moved from {client.previous_ip} to {client.ip}.",
                detail="The device was matched using a stable recognised identity rather than its IP address.",
                entity_type="recognised_device",
                entity_identifier=str(client.device_id),
                current_value=client.ip,
                comparison_value=client.previous_ip,
                action_type="review_clients",
            ))
        return RuleEvaluation(True, insights)


def _previous_client_counts(snapshot: DNSStatisticsSnapshot | None) -> dict[str, dict[str, Any]]:
    if not snapshot or not snapshot.client_aggregates_json:
        return {}
    try:
        value = json.loads(snapshot.client_aggregates_json)
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


class HighClientVolumeRule(DNSInsightRule):
    key = "high_client_query_volume"

    def evaluate(self, context, thresholds):
        baseline = _previous_client_counts(context.previous_snapshot)
        if not baseline:
            return RuleEvaluation(False)
        insights = []
        for client in context.clients:
            previous = _int((baseline.get(client.identity_value) or {}).get("queries")) or 0
            if previous < thresholds.minimum_client_queries or client.queries < thresholds.minimum_client_queries:
                continue
            change = ((client.queries - previous) / previous) * 100
            if change < thresholds.client_query_increase_percent:
                continue
            insights.append(GeneratedInsight(
                key=f"{self.key}:{client.identity_type}:{client.identity_value}",
                rule_key=self.key,
                category=InsightCategory.NETWORK,
                severity=InsightSeverity.WARNING,
                title="Unusually high client query volume",
                summary=f"{_client_label(client)} generated {client.queries:,} recent queries, {change:.0f}% above the previous comparable snapshot.",
                detail="This observation is based on the available aggregate baseline and does not by itself indicate a fault or security incident.",
                entity_type="client",
                entity_identifier=client.identity_value,
                current_value=f"{client.queries:,}",
                comparison_value=f"{previous:,}",
                percentage_change=change,
                action_type="review_clients",
            ))
        return RuleEvaluation(True, insights[:10])


class HighBlockedRateRule(DNSInsightRule):
    key = "high_blocked_query_rate"

    def evaluate(self, context, thresholds):
        if "queries" not in context.capabilities:
            return RuleEvaluation(False)
        insights = []
        for client in context.clients:
            if client.queries < thresholds.minimum_client_queries:
                continue
            rate = client.blocked_queries / client.queries * 100
            if rate < thresholds.blocked_query_warning_percent:
                continue
            insights.append(GeneratedInsight(
                key=f"{self.key}:{client.identity_type}:{client.identity_value}",
                rule_key=self.key,
                category=InsightCategory.SECURITY,
                severity=InsightSeverity.WARNING,
                title="High blocked-query volume",
                summary=f"{_client_label(client)} had {client.blocked_queries:,} blocked requests out of {client.queries:,} recent queries ({rate:.1f}%).",
                detail="An unusually high blocked proportion may be caused by software, telemetry, filtering policy, or other automated activity and may require investigation.",
                entity_type="client",
                entity_identifier=client.identity_value,
                current_value=f"{rate:.1f}%",
                action_type="query_log",
            ))
        return RuleEvaluation(True, insights[:10])


class NXDomainSpikeRule(DNSInsightRule):
    key = "nxdomain_spike"

    def evaluate(self, context, thresholds):
        if "queries" not in context.capabilities:
            return RuleEvaluation(False)
        insights = []
        for client in context.clients:
            if client.queries < thresholds.minimum_client_queries:
                continue
            rate = client.nxdomain_queries / client.queries * 100
            if rate < thresholds.nxdomain_warning_percent:
                continue
            insights.append(GeneratedInsight(
                key=f"{self.key}:{client.identity_type}:{client.identity_value}",
                rule_key=self.key,
                category=InsightCategory.SECURITY,
                severity=InsightSeverity.WARNING,
                title="Excessive NXDOMAIN responses",
                summary=f"{_client_label(client)} received NXDOMAIN for {rate:.1f}% of its recent DNS requests.",
                detail="Possible causes include misconfigured software, broken applications, tracking or telemetry, incorrect names, or other automated request patterns. This is not proof of compromise.",
                entity_type="client",
                entity_identifier=client.identity_value,
                current_value=f"{rate:.1f}%",
                action_type="query_log",
            ))
        return RuleEvaluation(True, insights[:10])


class RepeatedBlockedDomainRule(DNSInsightRule):
    key = "repeated_blocked_domain"

    def evaluate(self, context, thresholds):
        if "queries" not in context.capabilities:
            return RuleEvaluation(False)
        pairs: dict[tuple[str, str, str], dict[str, Any]] = {}
        for row in context.query_rows:
            status = _query_status(row)
            if not any(term in status for term in ("block", "gravity", "deny", "regex")):
                continue
            domain = _query_domain(row)
            client_name, client_ip = _query_client(row)
            client_label = client_name if client_name not in {"", "-", "*"} else client_ip
            if domain == "-" or client_label == "-":
                continue
            key = (client_label.lower(), client_ip, domain)
            item = pairs.setdefault(key, {"client": client_label, "client_ip": client_ip, "domain": domain, "count": 0, "first": None, "last": None})
            item["count"] += 1
            observed = _timestamp(row.get("time") or row.get("timestamp") or row.get("date"))
            if observed:
                item["first"] = min(item["first"], observed) if item["first"] else observed
                item["last"] = max(item["last"], observed) if item["last"] else observed
        candidates = sorted(pairs.values(), key=lambda item: item["count"], reverse=True)
        insights = []
        for item in candidates:
            if item["count"] < thresholds.repeated_blocked_domain_attempts:
                continue
            timing = ""
            if item["first"] and item["last"]:
                timing = f" The first observed attempt was {item['first'].strftime('%d/%m/%Y %H:%M')} and the most recent was {item['last'].strftime('%d/%m/%Y %H:%M')}."
            insights.append(GeneratedInsight(
                key=f"{self.key}:{item['client'].lower()}:{item['domain']}",
                rule_key=self.key,
                category=InsightCategory.SECURITY,
                severity=InsightSeverity.WARNING,
                title="Repeated requests for a blocked domain",
                summary=f"{item['client']} requested {item['domain']} {item['count']:,} times in the latest provider query sample.",
                detail="Repeated blocked requests may be caused by an application, telemetry, advertising, filtering policy, or other automated activity and may require investigation." + timing,
                entity_type="domain",
                entity_identifier=item["domain"],
                current_value=f"{item['count']:,} blocked attempts",
                action_type="query_log_client_domain",
                metadata={"domain": item["domain"], "client": item["client"], "client_ip": item["client_ip"], "attempts": item["count"]},
            ))
        return RuleEvaluation(True, insights[:15])


class NetworkVolumeTrendRule(DNSInsightRule):
    key = "network_query_volume_change"

    def evaluate(self, context, thresholds):
        previous = context.previous_snapshot.total_queries if context.previous_snapshot else None
        current = context.total_queries
        if not previous or current is None or previous < thresholds.minimum_network_queries or current < thresholds.minimum_network_queries:
            return RuleEvaluation(False)
        change = ((current - previous) / previous) * 100
        if abs(change) < thresholds.network_query_change_percent:
            return RuleEvaluation(True)
        direction = "increased" if change > 0 else "decreased"
        return RuleEvaluation(True, [GeneratedInsight(
            key=self.key,
            rule_key=self.key,
            category=InsightCategory.TREND,
            severity=InsightSeverity.INFORMATION,
            title=f"Network DNS traffic {direction}",
            summary=f"Total DNS queries {direction} by {abs(change):.0f}% compared with the previous available snapshot.",
            detail="Several explanations are possible, including normal usage changes, devices becoming active or inactive, resolver changes, or provider collection differences.",
            current_value=f"{current:,}",
            comparison_value=f"{previous:,}",
            percentage_change=change,
            action_type="reports",
        )])


RULES: tuple[DNSInsightRule, ...] = (
    ProviderDisconnectedRule(),
    ProviderStaleRule(),
    BlockingDisabledRule(),
    OutdatedBlocklistRule(),
    NewDeviceRule(),
    RecognisedDeviceIPChangeRule(),
    HighClientVolumeRule(),
    HighBlockedRateRule(),
    NXDomainSpikeRule(),
    RepeatedBlockedDomainRule(),
    NetworkVolumeTrendRule(),
)


def _recommendations(insights: list[GeneratedInsight]) -> list[GeneratedInsight]:
    recommendations = []
    active_rules = {item.rule_key for item in insights}
    if "new_unrecognised_device" in active_rules:
        recommendations.append(GeneratedInsight(
            key="recommendation:review_unrecognised_devices", rule_key="recommendation", category=InsightCategory.RECOMMENDATION,
            severity=InsightSeverity.INFORMATION, title="Review unrecognised devices",
            summary="One or more current DNS clients have not been recognised in Kaya.",
            detail="Review their stable identity and mark trusted devices as known.", action_type="review_clients",
        ))
    if "provider_data_stale" in active_rules:
        recommendations.append(GeneratedInsight(
            key="recommendation:refresh_provider_data", rule_key="recommendation", category=InsightCategory.RECOMMENDATION,
            severity=InsightSeverity.INFORMATION, title="Refresh provider data",
            summary="Run a new provider analysis to refresh stale DNS observations.", action_type="analyse_now",
        ))
    if "blocklist_outdated" in active_rules:
        recommendations.append(GeneratedInsight(
            key="recommendation:review_blocklists", rule_key="recommendation", category=InsightCategory.RECOMMENDATION,
            severity=InsightSeverity.INFORMATION, title="Review outdated blocklist data",
            summary="Review the provider's blocklist status and refresh it if appropriate.", action_type="blocklists",
        ))
    if active_rules & {"high_client_query_volume", "high_blocked_query_rate", "nxdomain_spike"}:
        recommendations.append(GeneratedInsight(
            key="recommendation:review_noisy_clients", rule_key="recommendation", category=InsightCategory.RECOMMENDATION,
            severity=InsightSeverity.INFORMATION, title="Review unusual client activity",
            summary="At least one client has a material query-volume, blocked-rate, or NXDOMAIN observation.", action_type="review_clients",
        ))
    return recommendations


def _snapshot(
    db: Session,
    context: DNSInsightContext,
    *,
    rules_evaluated: int,
    rules_skipped: int,
    insights_generated: int,
) -> DNSStatisticsSnapshot:
    period_start = context.generated_at.replace(minute=0, second=0, microsecond=0)
    row = (
        db.query(DNSStatisticsSnapshot)
        .filter(DNSStatisticsSnapshot.provider_id == context.provider.id, DNSStatisticsSnapshot.period_start == period_start)
        .first()
    )
    if not row:
        row = DNSStatisticsSnapshot(provider_id=context.provider.id, period_start=period_start, period_end=context.generated_at)
        db.add(row)
    row.period_end = context.generated_at
    row.total_queries = context.total_queries
    row.blocked_queries = context.blocked_queries
    row.failed_queries = context.failed_queries
    row.active_clients = context.active_clients
    row.blocking_enabled = context.blocking_enabled
    row.provider_connected = context.connected
    row.client_aggregates_json = json.dumps({client.identity_value: {"queries": client.queries, "blocked": client.blocked_queries, "nxdomain": client.nxdomain_queries} for client in context.clients[:200]})
    response_counts = Counter(_query_status(item) for item in context.query_rows)
    row.response_aggregates_json = json.dumps(dict(response_counts.most_common(50)))
    blocked_domains: dict[str, dict[str, Any]] = {}
    client_domain_pairs: Counter[tuple[str, str, str]] = Counter()
    for item in context.query_rows:
        domain = _query_domain(item)
        client_name, client_ip = _query_client(item)
        client_label = client_name if client_name not in {"", "-", "*"} else client_ip
        if domain == "-" or client_label == "-":
            continue
        status = _query_status(item)
        blocked = any(term in status for term in ("block", "gravity", "deny", "regex"))
        client_domain_pairs[(client_label, client_ip, domain)] += 1
        if blocked:
            entry = blocked_domains.setdefault(domain, {"count": 0, "clients": Counter()})
            entry["count"] += 1
            entry["clients"][client_label] += 1
    top_blocked = [
        {"domain": domain, "count": data["count"], "clients": [{"name": name, "count": count} for name, count in data["clients"].most_common(5)]}
        for domain, data in sorted(blocked_domains.items(), key=lambda pair: pair[1]["count"], reverse=True)[:15]
    ]
    top_pairs = [
        {"client": client, "client_ip": client_ip, "domain": domain, "count": count}
        for (client, client_ip, domain), count in client_domain_pairs.most_common(15)
    ]
    row.domain_aggregates_json = json.dumps({"top_blocked_domains": top_blocked, "top_client_domain_pairs": top_pairs})
    row.capabilities_json = json.dumps(sorted(context.capabilities))
    row.analysis_summary_json = json.dumps(
        {
            "query_sample_count": len(context.query_rows),
            "clients_analysed": len(context.clients),
            "recognised_clients": sum(1 for client in context.clients if client.recognised),
            "unrecognised_clients": sum(1 for client in context.clients if not client.recognised),
            "rules_evaluated": rules_evaluated,
            "rules_skipped": rules_skipped,
            "insights_generated": insights_generated,
            "baseline_available": context.previous_snapshot is not None,
        }
    )
    return row


def _persist_insights(db: Session, context: DNSInsightContext, generated: list[GeneratedInsight], evaluated_rules: set[str]) -> tuple[int, int, int]:
    existing = db.query(DNSInsight).filter(DNSInsight.provider_id == context.provider.id).all()
    by_key = {row.insight_key: row for row in existing}
    unique_generated = {item.key: item for item in generated}
    generated_keys = set(unique_generated)
    created = updated = resolved = 0
    for item in unique_generated.values():
        row = by_key.get(item.key)
        if not row:
            row = DNSInsight(
                provider_id=context.provider.id,
                insight_key=item.key,
                rule_key=item.rule_key,
                category=item.category,
                severity=item.severity,
                status="active",
                title=item.title,
                summary=item.summary,
                first_detected_at=context.generated_at,
                last_detected_at=context.generated_at,
            )
            db.add(row)
            by_key[item.key] = row
            created += 1
        else:
            updated += 1
            row.status = "active"
            row.resolved_at = None
            row.last_detected_at = context.generated_at
        row.rule_key = item.rule_key
        row.category = item.category
        row.severity = item.severity
        row.title = item.title
        row.summary = item.summary
        row.detail = item.detail or None
        row.entity_type = item.entity_type
        row.entity_identifier = item.entity_identifier
        row.current_value = item.current_value
        row.comparison_value = item.comparison_value
        row.percentage_change = item.percentage_change
        row.action_type = item.action_type
        row.metadata_json = json.dumps(item.metadata) if item.metadata else None
    for row in existing:
        if row.status == "active" and row.rule_key in evaluated_rules and row.insight_key not in generated_keys:
            row.status = "resolved"
            row.resolved_at = context.generated_at
            resolved += 1
    return created, updated, resolved


def analyse_provider(
    db: Session,
    provider: DNSProviderConfig,
    *,
    known_hostnames_raw: str = "[]",
    thresholds: DNSInsightThresholds = DEFAULT_THRESHOLDS,
) -> AnalysisResult:
    provider_id = provider.id
    lock = _provider_lock(provider_id)
    if not lock.acquire(blocking=False):
        raise AnalysisAlreadyRunning("An insight analysis is already running for this provider.")
    started = time.monotonic()
    try:
        logger.info("DNS insight analysis started", extra={"provider_id": provider.id})
        network_client = provider_snapshot_for_io(provider)
        # End the read transaction before bounded provider I/O so an offline
        # integration cannot retain an SQLite reader for its timeout duration.
        db.rollback()
        payloads = _collect_provider_data(network_client)
        provider = db.get(DNSProviderConfig, provider_id)
        if not provider or not provider.is_enabled:
            raise LookupError("DNS provider is no longer enabled.")
        context = build_context(db, provider, known_hostnames_raw, payloads=payloads)
        generated: list[GeneratedInsight] = []
        evaluated_rules: set[str] = set()
        skipped = 0
        for rule in RULES:
            try:
                evaluation = rule.evaluate(context, thresholds)
            except Exception:
                logger.exception("DNS insight rule failed", extra={"provider_id": provider.id, "rule_key": rule.key})
                skipped += 1
                continue
            if evaluation.supported:
                evaluated_rules.add(rule.key)
                generated.extend(evaluation.insights)
            else:
                skipped += 1
                logger.info("DNS insight rule skipped because data is unavailable", extra={"provider_id": provider.id, "rule_key": rule.key})
        generated.extend(_recommendations(generated))
        evaluated_rules.add("recommendation")
        created, updated, resolved = _persist_insights(db, context, generated, evaluated_rules)
        if context.connected:
            _snapshot(
                db,
                context,
                rules_evaluated=len(evaluated_rules),
                rules_skipped=skipped,
                insights_generated=len(generated),
            )
            cutoff = context.generated_at - timedelta(days=thresholds.snapshot_retention_days)
            db.query(DNSStatisticsSnapshot).filter(DNSStatisticsSnapshot.provider_id == provider.id, DNSStatisticsSnapshot.period_start < cutoff).delete(synchronize_session=False)
        db.commit()
        active = db.query(DNSInsight).filter(DNSInsight.provider_id == provider.id, DNSInsight.status == "active").count()
        logger.info(
            "DNS insight analysis completed",
            extra={"provider_id": provider.id, "duration_ms": int((time.monotonic() - started) * 1000), "created": created, "updated": updated, "resolved": resolved},
        )
        return AnalysisResult(provider.id, context.generated_at, created, updated, resolved, active, len(evaluated_rules), skipped)
    except Exception:
        db.rollback()
        logger.exception("DNS insight analysis failed", extra={"provider_id": provider_id})
        raise
    finally:
        lock.release()


def calculate_health_score(provider: DNSProviderConfig, insights: list[DNSInsight], last_analysis_at: datetime | None) -> HealthScore:
    factors: list[HealthFactor] = []
    score = 100
    if provider.last_status:
        connected = provider.last_status == "online"
        deduction = 0 if connected else 40
        score -= deduction
        factors.append(HealthFactor("Provider connection", "Connected" if connected else "Disconnected", deduction))
    else:
        factors.append(HealthFactor("Provider connection", "Unavailable", None))
    blocking = next((item for item in insights if item.rule_key == "blocking_disabled" and item.status == "active"), None)
    if blocking:
        score -= 15
        factors.append(HealthFactor("DNS blocking", "Disabled", 15))
    else:
        factors.append(HealthFactor("DNS blocking", "No active issue", 0))
    if last_analysis_at:
        age_hours = max(0, int((datetime.utcnow() - last_analysis_at).total_seconds() // 3600))
        deduction = 10 if age_hours > DEFAULT_THRESHOLDS.provider_stale_hours else 0
        score -= deduction
        factors.append(HealthFactor("Analysis freshness", f"{age_hours} hours old", deduction))
    else:
        factors.append(HealthFactor("Analysis freshness", "Unavailable", None))
    critical = sum(1 for item in insights if item.status == "active" and item.severity == InsightSeverity.CRITICAL and item.rule_key != "provider_disconnected")
    warnings = sum(1 for item in insights if item.status == "active" and item.severity == InsightSeverity.WARNING and item.rule_key != "blocking_disabled")
    severity_deduction = min(30, critical * 15 + warnings * 4)
    score -= severity_deduction
    factors.append(HealthFactor("Active operational insights", f"{critical} critical, {warnings} warning", severity_deduction))
    score = max(0, min(100, score))
    status = "Excellent" if score >= 90 else "Healthy" if score >= 75 else "Attention Required" if score >= 50 else "Poor" if score >= 25 else "Critical"
    return HealthScore(score, status, factors)


ACTION_TARGETS = {
    "provider_settings": "/system/site-administration?tab=module-dns-manager",
    "review_clients": "/networking/dns-manager?tab=clients",
    "query_log": "/networking/dns-manager?tab=query-log",
    "blocklists": "/networking/dns-manager?tab=blocklists",
    "reports": "/networking/dns-manager?tab=reports",
}


def insight_action_target(insight: DNSInsight) -> str | None:
    action_type = insight.action_type or ""
    if action_type == "query_log_client_domain":
        try:
            metadata = json.loads(insight.metadata_json or "{}")
        except (TypeError, ValueError):
            metadata = {}
        params = {"tab": "query-log"}
        if metadata.get("domain"):
            params["dns_domain"] = str(metadata["domain"])
        if metadata.get("client"):
            params["dns_client"] = str(metadata["client"])
        return f"/networking/dns-manager?{urlencode(params)}"
    return ACTION_TARGETS.get(action_type)
