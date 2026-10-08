"""Stage 1 contracts and safe configuration helpers for Network Traffic.

This module deliberately contains no polling, socket listener, flow decoder or
background task. It defines the stable boundary later providers will implement.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Protocol

from app.core.security import encrypt_secret
from app.models.models import TrafficSource

PROVIDER_CATEGORIES = {"interface_polling", "flow_export", "vendor_api"}
PROVIDER_KEYS = {"snmpv3", "netflow_v9", "cisco_nsel", "vendor_api"}
SOURCE_CONFIGURATION_STATES = {"enabled", "disabled", "unconfigured"}
SOURCE_HEALTH_STATES = {"healthy", "degraded", "stale", "error", "unconfigured"}
VALID_AUTH_PROTOCOLS = {"SHA", "SHA-256", "SHA-384", "SHA-512"}
VALID_PRIVACY_PROTOCOLS = {"AES128", "AES192", "AES256"}
MAX_EXPORTERS = 128


@dataclass(frozen=True)
class ProviderCapabilities:
    key: str
    category: str
    capabilities: frozenset[str]


@dataclass(frozen=True)
class TrafficObservation:
    source_id: int
    interface_id: int
    observed_at: datetime
    inbound_bytes: int | None
    outbound_bytes: int | None
    counter_bits: int = 64
    exporter_epoch: str | None = None


class TrafficProvider(Protocol):
    key: str
    category: str

    def capabilities(self) -> ProviderCapabilities: ...

    def validate_configuration(self, source: TrafficSource) -> None: ...


PROVIDERS = {
    "snmpv3": ProviderCapabilities("snmpv3", "interface_polling", frozenset({"interface_counters", "wan_interfaces"})),
    "netflow_v9": ProviderCapabilities("netflow_v9", "flow_export", frozenset({"flow_records", "exporter_allowlist"})),
    "cisco_nsel": ProviderCapabilities("cisco_nsel", "flow_export", frozenset({"flow_records", "exporter_allowlist", "vendor_extensions"})),
    "vendor_api": ProviderCapabilities("vendor_api", "vendor_api", frozenset()),
}


def validate_destination(value: str | None) -> str | None:
    """Accept only literal private/ULA addresses; no DNS or public SSRF targets."""
    if value is None or not value.strip():
        return None
    candidate = value.strip()
    try:
        address = ip_address(candidate)
    except ValueError as exc:
        raise ValueError("SNMP destination must be a literal private IP address.") from exc
    if not address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        raise ValueError("SNMP destination must be a usable private network address.")
    return str(address)


def validate_local_network(value: str) -> str:
    try:
        network = ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Local network must be a valid IPv4 or IPv6 CIDR.") from exc
    return str(network)


def validate_exporters(values: list[str] | None) -> list[str]:
    values = values or []
    if len(values) > MAX_EXPORTERS:
        raise ValueError("Exporter allowlist is too large.")
    result = []
    for value in values:
        try:
            address = ip_address(str(value).strip())
        except ValueError as exc:
            raise ValueError("Exporter allowlist entries must be literal IP addresses.") from exc
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError("Exporter address is not usable.")
        result.append(str(address))
    return list(dict.fromkeys(result))


def validate_source_input(data: dict, *, existing: TrafficSource | None = None) -> dict:
    name = str(data.get("name", existing.name if existing else "")).strip()
    if not 1 <= len(name) <= 120:
        raise ValueError("Source name must be between 1 and 120 characters.")
    provider_key = str(data.get("provider_key", existing.provider_key if existing else "")).strip()
    if provider_key not in PROVIDERS:
        raise ValueError("Unsupported traffic provider.")
    category = PROVIDERS[provider_key].category
    supplied_category = data.get("source_category") or (existing.source_category if existing else category)
    if supplied_category != category:
        raise ValueError("Provider and source category do not match.")
    destination = validate_destination(data.get("destination_ip", existing.destination_ip if existing else None))
    port = int(data.get("destination_port", existing.destination_port if existing else 161))
    if not 1 <= port <= 65535:
        raise ValueError("Destination port must be between 1 and 65535.")
    interval = int(data.get("polling_interval_seconds", existing.polling_interval_seconds if existing else 60))
    if not 5 <= interval <= 86400:
        raise ValueError("Polling interval must be between 5 and 86400 seconds.")
    collector_port = data.get("collector_port", existing.collector_port if existing else None)
    if collector_port is not None:
        collector_port = int(collector_port)
        if not 1024 <= collector_port <= 65535:
            raise ValueError("Collector port must be between 1024 and 65535.")
    exporters = validate_exporters(data.get("exporter_allowlist", None))
    if provider_key in {"netflow_v9", "cisco_nsel"} and not exporters:
        raise ValueError("Flow providers require at least one authorised exporter IP.")
    security_name = data.get("security_name", existing.security_name if existing else None)
    if security_name is not None:
        security_name = str(security_name).strip()
        if not 1 <= len(security_name) <= 128:
            raise ValueError("SNMP security name must be between 1 and 128 characters.")
    auth_protocol = data.get("snmp_auth_protocol", existing.snmp_auth_protocol if existing else None)
    privacy_protocol = data.get("snmp_privacy_protocol", existing.snmp_privacy_protocol if existing else None)
    if auth_protocol and auth_protocol not in VALID_AUTH_PROTOCOLS:
        raise ValueError("Unsupported SNMP authentication protocol.")
    if privacy_protocol and privacy_protocol not in VALID_PRIVACY_PROTOCOLS:
        raise ValueError("Unsupported SNMP privacy protocol.")
    is_enabled = bool(data.get("is_enabled", existing.is_enabled if existing else False))
    if provider_key == "snmpv3" and is_enabled and (not destination or not security_name):
        raise ValueError("Enabled SNMPv3 sources require a private destination and security name.")
    return {
        "name": name, "provider_key": provider_key, "source_category": category,
        "is_enabled": is_enabled, "configuration_state": "enabled" if is_enabled else "disabled",
        "destination_ip": destination, "destination_port": port, "polling_interval_seconds": interval,
        "collector_port": collector_port, "security_name": security_name,
        "snmp_auth_protocol": auth_protocol, "snmp_privacy_protocol": privacy_protocol,
        "exporter_allowlist_json": json.dumps(exporters, separators=(",", ":")),
    }


def source_public_dict(source: TrafficSource) -> dict:
    return {
        "id": source.id, "name": source.name, "provider_key": source.provider_key,
        "source_category": source.source_category, "is_enabled": source.is_enabled,
        "configuration_state": source.configuration_state, "health_state": source.health_state,
        "health_reason": source.health_reason, "destination_ip": source.destination_ip,
        "destination_port": source.destination_port, "security_name": source.security_name,
        "snmp_auth_protocol": source.snmp_auth_protocol,
        "snmp_privacy_protocol": source.snmp_privacy_protocol,
        "has_snmp_authentication": bool(source.encrypted_snmp_authentication),
        "has_snmp_privacy": bool(source.encrypted_snmp_privacy),
        "exporter_allowlist": json.loads(source.exporter_allowlist_json or "[]"),
        "collector_port": source.collector_port, "polling_interval_seconds": source.polling_interval_seconds,
        "last_success_at": source.last_success_at.isoformat() + "Z" if source.last_success_at else None,
        "last_received_at": source.last_received_at.isoformat() + "Z" if source.last_received_at else None,
    }


def apply_source_secrets(source: TrafficSource, data: dict, *, creating: bool = False) -> None:
    for field, attribute in (("snmp_authentication", "encrypted_snmp_authentication"), ("snmp_privacy", "encrypted_snmp_privacy")):
        if field in data and data[field] is not None:
            value = str(data[field])
            if value and not 8 <= len(value.encode("utf-8")) <= 32:
                raise ValueError("SNMP credentials must be between 8 and 32 bytes.")
            setattr(source, attribute, encrypt_secret(value) if value else None)
        elif creating:
            setattr(source, attribute, None)
