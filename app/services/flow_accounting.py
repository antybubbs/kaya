"""Conservative topology-aware accounting and device-attribution contracts."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address, ip_network

from sqlalchemy.orm import Session

from app.models.models import DHCPLeaseHistory, DNSClientIPHistory, DNSRecognisedDevice, IPAddress
from app.services.flow_protocol import NormalizedFlowRecord

ACCOUNTING_CLASSES = {
    "wan_inbound", "wan_outbound", "internet_download", "internet_upload",
    "internal_lan", "vpn_tunnel", "unknown",
}


@dataclass(frozen=True)
class FlowClassification:
    traffic_class: str
    confidence: str
    reason: str | None = None


@dataclass(frozen=True)
class FlowAttribution:
    state: str
    confidence: str
    method: str | None = None
    ip_record_id: int | None = None
    dhcp_lease_id: int | None = None
    dns_client_id: int | None = None
    unresolved_reason: str | None = None


def _in_network(value: str | None, networks: list) -> bool:
    if not value:
        return False
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in networks)


def classify_flow(record: NormalizedFlowRecord, *, interfaces=(), local_networks=()) -> FlowClassification:
    """Classify only when configured topology supports the conclusion."""
    networks = []
    for value in local_networks:
        try:
            networks.append(ip_network(value, strict=False) if isinstance(value, str) else value)
        except ValueError:
            continue
    wan_indexes = {item.interface_index for item in interfaces if getattr(item, "is_enabled", True) and getattr(item, "is_wan", False) and item.interface_index is not None}
    input_wan = record.input_interface in wan_indexes
    output_wan = record.output_interface in wan_indexes
    if input_wan and not output_wan:
        return FlowClassification("wan_inbound", "high")
    if output_wan and not input_wan:
        return FlowClassification("wan_outbound", "high")
    source_local = _in_network(record.source_ip, networks)
    destination_local = _in_network(record.destination_ip, networks)
    translated_source_local = _in_network(record.translated_source_ip, networks)
    translated_destination_local = _in_network(record.translated_destination_ip, networks)
    source_local = source_local or translated_source_local
    destination_local = destination_local or translated_destination_local
    if source_local and destination_local:
        return FlowClassification("internal_lan", "high")
    if source_local != destination_local:
        return FlowClassification("internet_upload" if source_local else "internet_download", "medium")
    if record.translated_source_ip or record.translated_destination_ip:
        return FlowClassification("vpn_tunnel", "low", "translated_endpoints_without_local_topology")
    return FlowClassification("unknown", "unknown", "topology_incomplete")


def resolve_flow_attribution(db: Session, record: NormalizedFlowRecord, *, address: str | None = None, local_networks=()) -> FlowAttribution:
    """Resolve through time-bounded existing identity records only.

    No new device record or per-device traffic history is created here.
    """
    observed = record.observed_at
    address = address or record.source_ip
    if not address:
        return FlowAttribution("unresolved", "none", unresolved_reason="missing_endpoint")
    candidates = db.query(DHCPLeaseHistory).filter(
        DHCPLeaseHistory.ip_address == address,
        DHCPLeaseHistory.lease_started_at <= observed,
        (DHCPLeaseHistory.expires_at.is_(None) | (DHCPLeaseHistory.expires_at >= observed)),
    ).all()
    if len(candidates) == 1:
        lease = candidates[0]
        client = db.get(DNSRecognisedDevice, lease.dns_client_id) if lease.dns_client_id else None
        return FlowAttribution("resolved", "high", "dhcp_lease", ip_record_id=client.linked_ip_record_id if client else None, dhcp_lease_id=lease.id, dns_client_id=lease.dns_client_id)
    if len(candidates) > 1:
        return FlowAttribution("unresolved", "none", unresolved_reason="ambiguous_dhcp_history")
    managed = db.query(IPAddress).filter(IPAddress.address == address).all()
    if len(managed) == 1 and managed[0].assignment_type.lower() != "dynamic":
        return FlowAttribution("resolved", "medium", "managed_ip", ip_record_id=managed[0].id)
    history = db.query(DNSClientIPHistory).filter(
        DNSClientIPHistory.ip_address == address,
        DNSClientIPHistory.first_seen_at <= observed,
        DNSClientIPHistory.last_seen_at >= observed,
    ).all() if record.source_ip else []
    if len(history) == 1:
        client = db.get(DNSRecognisedDevice, history[0].dns_client_id)
        return FlowAttribution("resolved", "low", "ip_history", ip_record_id=client.linked_ip_record_id if client else None, dns_client_id=history[0].dns_client_id)
    if len(history) > 1:
        return FlowAttribution("unresolved", "none", unresolved_reason="ambiguous_ip_history")
    return FlowAttribution("unresolved", "none", unresolved_reason="no_time_bounded_identity")


def retention_cutoffs(now: datetime, *, short_days: int, hourly_days: int, daily_days: int) -> dict[int, datetime]:
    from datetime import timedelta
    return {300: now - timedelta(days=short_days), 3600: now - timedelta(days=hourly_days), 86400: now - timedelta(days=daily_days)}
