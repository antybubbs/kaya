"""Persistent DNS client identity and VLAN/IP record integration."""

from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import ip_address
import re
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.models.models import (
    DNSClientEvent,
    DNSClientHostnameHistory,
    DNSClientIPHistory,
    DNSProviderConfig,
    DNSRecognisedDevice,
    DHCPLeaseHistory,
    DHCPRange,
    IPAddress,
)
from app.services.site_settings import get_site_settings


PLACEHOLDER_HOSTNAMES = {"", "-", "unknown", "localhost", "none", "null"}
INVALID_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def dhcp_range_for_ip(db: Session, value: str | None) -> DHCPRange | None:
    if not value:
        return None
    try:
        parsed = ip_address(value)
    except ValueError:
        return None
    for row in db.query(DHCPRange).filter(DHCPRange.is_enabled == True).all():  # noqa: E712
        try:
            start, end = ip_address(row.start_address), ip_address(row.end_address)
        except ValueError:
            continue
        if start.version == parsed.version and start <= parsed <= end:
            return row
    return None


def normalise_mac(value: Any) -> str | None:
    compact = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(compact) != 12 or not re.fullmatch(r"[0-9a-f]{12}", compact):
        return None
    result = ":".join(compact[index:index + 2] for index in range(0, 12, 2))
    return None if result in INVALID_MACS else result


def normalise_hostname(value: Any, ip: str | None = None) -> str | None:
    clean = str(value or "").strip().rstrip(".").lower()
    if clean in PLACEHOLDER_HOSTNAMES or clean == str(ip or "").lower():
        return None
    return clean


def _event(db: Session, client: DNSRecognisedDevice, event_type: str, summary: str, *, old: str | None = None, new: str | None = None, source: str | None = None) -> None:
    db.add(DNSClientEvent(
        dns_client_id=client.id,
        event_type=event_type,
        event_summary=summary,
        old_value=old,
        new_value=new,
        source=source,
        provider_id=client.provider_id,
    ))


def _history(db: Session, client: DNSRecognisedDevice, *, ip: str | None, hostname: str | None, observed_at: datetime, source: str) -> None:
    if get_site_settings(db, {"dns_retain_client_history"})["dns_retain_client_history"] != "1":
        return
    if ip and ip != "-":
        row = db.query(DNSClientIPHistory).filter_by(dns_client_id=client.id, ip_address=ip).first()
        if row:
            row.last_seen_at = max(row.last_seen_at, observed_at)
            row.observation_count += 1
            row.source = source
        else:
            db.add(DNSClientIPHistory(dns_client_id=client.id, ip_address=ip, first_seen_at=observed_at, last_seen_at=observed_at, provider_id=client.provider_id, source=source))
    hostname_key = normalise_hostname(hostname, ip)
    if hostname_key:
        row = db.query(DNSClientHostnameHistory).filter_by(dns_client_id=client.id, normalised_hostname=hostname_key).first()
        if row:
            row.last_seen_at = max(row.last_seen_at, observed_at)
            row.observation_count += 1
            row.hostname = str(hostname).strip()
            row.source = source
        else:
            db.add(DNSClientHostnameHistory(dns_client_id=client.id, hostname=str(hostname).strip(), normalised_hostname=hostname_key, first_seen_at=observed_at, last_seen_at=observed_at, provider_id=client.provider_id, source=source))


def _compatible_mac(client: DNSRecognisedDevice, mac: str | None) -> bool:
    existing = client.normalised_mac or normalise_mac(client.mac_address)
    return not (mac and existing and mac != existing)


def match_client(db: Session, provider_id: int, *, provider_client_id: str | None, mac: str | None, ip: str | None, hostname: str | None) -> tuple[DNSRecognisedDevice | None, str | None]:
    hostname_key = normalise_hostname(hostname, ip)
    if provider_client_id:
        row = db.query(DNSRecognisedDevice).filter_by(provider_id=provider_id, provider_client_id=provider_client_id).first()
        if row:
            return row, "provider_client_identifier"
    if mac:
        row = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.normalised_mac == mac).order_by(DNSRecognisedDevice.last_seen_at.desc()).first()
        if row:
            return row, "mac_address"
    # Inside a configured DHCP range, an address is temporary evidence rather
    # than identity. Only provider IDs and MAC addresses may reunite a client.
    if dhcp_range_for_ip(db, ip):
        active_lease = (
            db.query(DHCPLeaseHistory)
            .filter_by(provider_id=provider_id, ip_address=ip, is_active=True)
            .order_by(DHCPLeaseHistory.last_seen_at.desc())
            .first()
        )
        if active_lease and active_lease.dns_client_id:
            leased_client = db.get(DNSRecognisedDevice, active_lease.dns_client_id)
            if leased_client and _compatible_mac(leased_client, mac):
                return leased_client, "active_dhcp_lease"
        if hostname_key:
            recent = datetime.utcnow() - timedelta(days=1)
            rows = db.query(DNSRecognisedDevice).filter(
                DNSRecognisedDevice.provider_id == provider_id,
                DNSRecognisedDevice.current_ip == ip,
                DNSRecognisedDevice.normalised_hostname == hostname_key,
                DNSRecognisedDevice.last_seen_at >= recent,
            ).all()
            if len(rows) == 1:
                return rows[0], "recent_dhcp_ip_hostname"
        return None, None
    if ip and hostname_key:
        rows = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.current_ip == ip, DNSRecognisedDevice.normalised_hostname == hostname_key).all()
        rows = [row for row in rows if _compatible_mac(row, mac)]
        if len(rows) == 1:
            return rows[0], "ip_and_hostname"
    if ip:
        rows = [row for row in db.query(DNSRecognisedDevice).filter_by(current_ip=ip).all() if _compatible_mac(row, mac)]
        if len(rows) == 1:
            return rows[0], "ip_address"
    if hostname_key and not mac:
        rows = db.query(DNSRecognisedDevice).filter_by(normalised_hostname=hostname_key).all()
        if len(rows) == 1 and not rows[0].normalised_mac:
            return rows[0], "hostname"
    return None, None


def _suggest_managed_record(db: Session, client: DNSRecognisedDevice) -> None:
    settings = get_site_settings(db, {"dns_vlan_integration_enabled", "dns_match_suggestions_enabled", "dns_auto_link_exact_mac", "dns_auto_update_dynamic_ip", "dns_update_empty_managed_hostname"})
    if settings["dns_vlan_integration_enabled"] != "1":
        return
    mac = client.normalised_mac
    candidates = []
    method = None
    confidence = None
    if mac:
        candidates = [row for row in db.query(IPAddress).filter(IPAddress.mac_address.is_not(None)).all() if normalise_mac(row.mac_address) == mac]
        method, confidence = "managed_mac", 100
    if not candidates and client.current_ip and not dhcp_range_for_ip(db, client.current_ip):
        candidates = db.query(IPAddress).filter(IPAddress.address == client.current_ip).all()
        method, confidence = "managed_ip", 70
        if client.normalised_hostname:
            exact = [row for row in candidates if normalise_hostname(row.name) == client.normalised_hostname]
            if exact:
                candidates, method, confidence = exact, "managed_ip_hostname", 75
    if not client.linked_ip_record_id:
        if len(candidates) == 1 and settings["dns_match_suggestions_enabled"] == "1":
            client.suggested_ip_record_id = candidates[0].id
            client.match_method = method
            client.match_confidence = confidence
            if method == "managed_mac" and settings["dns_auto_link_exact_mac"] == "1":
                client.linked_ip_record_id = candidates[0].id
                client.suggested_ip_record_id = None
                client.is_known = True
                _event(db, client, "linked_to_ip_record", "Automatically linked exact MAC match", new=str(candidates[0].id), source="automatic exact MAC match")
        else:
            client.suggested_ip_record_id = None
            client.match_confidence = None
            if client.match_method and client.match_method.startswith("managed_"):
                client.match_method = None
    managed = client.linked_ip_record or (db.get(IPAddress, client.linked_ip_record_id) if client.linked_ip_record_id else None)
    if managed:
        if managed.assignment_type == "Dynamic" and client.current_ip and managed.address != client.current_ip and settings["dns_auto_update_dynamic_ip"] == "1" and (client.normalised_mac or client.provider_client_id):
            collision = db.query(IPAddress).filter(IPAddress.vlan_id == managed.vlan_id, IPAddress.address == client.current_ip, IPAddress.id != managed.id).first()
            if collision:
                _event(db, client, "managed_record_update_blocked", "Dynamic managed IP update blocked because the address is already allocated", old=managed.address, new=client.current_ip, source="automatic dynamic IP update")
            else:
                old = managed.address
                managed.address = client.current_ip
                _event(db, client, "managed_record_updated", "Dynamic managed IP updated from stable client identity", old=old, new=managed.address, source="automatic dynamic IP update")
        if not managed.name and client.hostname and settings["dns_update_empty_managed_hostname"] == "1":
            managed.name = client.hostname
            _event(db, client, "managed_record_updated", "Empty managed hostname populated from observation", new=managed.name, source="automatic empty hostname update")


def observe_client(db: Session, provider: DNSProviderConfig, observation: Any, generated_at: datetime) -> DNSRecognisedDevice:
    ip = str(getattr(observation, "ip", "") or "").strip()
    ip = None if ip in {"", "-"} else ip
    hostname = str(getattr(observation, "hostname", "") or "").strip()
    hostname_key = normalise_hostname(hostname, ip)
    hostname = hostname if hostname_key else None
    mac = normalise_mac(getattr(observation, "mac", None))
    provider_client_id = str(getattr(observation, "provider_client_id", "") or "").strip() or None
    source = str(getattr(observation, "source", "") or "Pi-hole sync")
    observed_at = getattr(observation, "last_seen", None) or generated_at
    first_seen = getattr(observation, "first_seen", None) or observed_at
    client, match_method = match_client(db, provider.id, provider_client_id=provider_client_id, mac=mac, ip=ip, hostname=hostname)
    if not client:
        in_dhcp_range = bool(dhcp_range_for_ip(db, ip))
        identity_type = "provider_client" if provider_client_id else "mac" if mac else "dhcp_observation" if in_dhcp_range else "ip" if ip else "hostname"
        identity_value = provider_client_id or mac or (f"{provider.id}:{ip}:{hostname_key or '-'}:{int(generated_at.timestamp())}" if in_dhcp_range else ip) or hostname_key
        client = DNSRecognisedDevice(
            provider_id=provider.id,
            provider_type=provider.provider_type,
            identity_type=identity_type,
            identity_value=str(identity_value),
            provider_client_id=provider_client_id,
            hostname=hostname,
            normalised_hostname=hostname_key,
            current_ip=ip,
            mac_address=mac,
            normalised_mac=mac,
            first_seen_at=first_seen,
            last_seen_at=observed_at,
            last_synced_at=generated_at,
            observation_source=source,
        )
        db.add(client)
        db.flush()
        _event(db, client, "client_discovered", "DNS client discovered", new=hostname or ip or mac, source=source)
    else:
        if ip and client.current_ip and client.current_ip != ip:
            old = client.current_ip
            client.previous_ip = old
            client.current_ip = ip
            _event(db, client, "ip_changed", "Observed IP address changed", old=old, new=ip, source=source)
        elif ip:
            client.current_ip = ip
        if hostname_key and client.normalised_hostname and client.normalised_hostname != hostname_key:
            old = client.hostname
            client.previous_hostname = old
            client.hostname = hostname
            client.normalised_hostname = hostname_key
            _event(db, client, "hostname_changed", "Reported hostname changed", old=old, new=hostname, source=source)
        elif hostname_key:
            client.hostname = hostname
            client.normalised_hostname = hostname_key
        if mac:
            client.mac_address = mac
            client.normalised_mac = mac
        if provider_client_id:
            client.provider_client_id = provider_client_id
        client.provider_id = provider.id
        client.provider_type = provider.provider_type
        client.last_seen_at = max(client.last_seen_at, observed_at)
        client.last_synced_at = generated_at
        client.observation_source = source
    client.query_count = int(getattr(observation, "queries", 0) or 0)
    client.blocked_query_count = int(getattr(observation, "blocked_queries", 0) or 0)
    client.match_method = client.match_method or match_method
    _history(db, client, ip=ip, hostname=hostname, observed_at=observed_at, source=source)
    _suggest_managed_record(db, client)
    return client


def client_display_name(client: DNSRecognisedDevice) -> str:
    managed = client.linked_ip_record
    return client.friendly_name or (managed.name if managed else None) or client.hostname or client.current_ip or client.mac_address or "Unnamed client"


def client_status(client: DNSRecognisedDevice, stale_days: int = 30) -> str:
    if client.is_ignored:
        return "Ignored"
    if client.last_seen_at and client.last_seen_at < datetime.utcnow() - timedelta(days=stale_days):
        return "Stale"
    managed = client.linked_ip_record
    if managed:
        mac_conflict = managed.mac_address and client.normalised_mac and normalise_mac(managed.mac_address) != client.normalised_mac
        static_ip_conflict = managed.assignment_type != "Dynamic" and client.current_ip and managed.address != client.current_ip
        return "Conflict" if mac_conflict or static_ip_conflict else "Linked"
    if client.match_confidence:
        return "Suggested match"
    return "Known" if client.is_known else "Unmanaged"


def list_clients(db: Session, *, provider_id: int | None = None, search: str = "", status: str = "", offset: int = 0, limit: int = 100) -> tuple[list[DNSRecognisedDevice], int]:
    query = db.query(DNSRecognisedDevice).options(joinedload(DNSRecognisedDevice.linked_ip_record), joinedload(DNSRecognisedDevice.suggested_ip_record))
    if provider_id:
        query = query.filter(DNSRecognisedDevice.provider_id == provider_id)
    clean = search.strip()
    if clean:
        like = f"%{clean}%"
        history_ids = db.query(DNSClientIPHistory.dns_client_id).filter(DNSClientIPHistory.ip_address.ilike(like)).union(db.query(DNSClientHostnameHistory.dns_client_id).filter(DNSClientHostnameHistory.hostname.ilike(like)))
        query = query.outerjoin(IPAddress, DNSRecognisedDevice.linked_ip_record_id == IPAddress.id).filter(or_(DNSRecognisedDevice.friendly_name.ilike(like), DNSRecognisedDevice.hostname.ilike(like), DNSRecognisedDevice.current_ip.ilike(like), DNSRecognisedDevice.mac_address.ilike(like), DNSRecognisedDevice.notes.ilike(like), IPAddress.name.ilike(like), DNSRecognisedDevice.id.in_(history_ids)))
    ordered = query.order_by(DNSRecognisedDevice.last_seen_at.desc())
    if not status:
        total = query.count()
        return ordered.offset(offset).limit(limit).all(), total
    rows = ordered.all()
    settings = get_site_settings(db, {"dns_stale_client_days"})
    try:
        stale_days = int(settings["dns_stale_client_days"] or "30")
    except ValueError:
        stale_days = 30
    if status:
        rows = [row for row in rows if client_status(row, stale_days).lower().replace(" ", "-") == status]
    return rows[offset:offset + limit], len(rows)


def add_event(db: Session, client: DNSRecognisedDevice, event_type: str, summary: str, *, old: str | None = None, new: str | None = None, source: str = "user") -> None:
    _event(db, client, event_type, summary, old=old, new=new, source=source)


def reconcile_managed_matches(db: Session) -> int:
    """Re-evaluate retained clients after managed inventory changes, even if a provider omits them."""
    changed = 0
    for client in db.query(DNSRecognisedDevice).options(joinedload(DNSRecognisedDevice.linked_ip_record)).all():
        before = (client.linked_ip_record_id, client.suggested_ip_record_id, client.match_method, client.match_confidence)
        _suggest_managed_record(db, client)
        after = (client.linked_ip_record_id, client.suggested_ip_record_id, client.match_method, client.match_confidence)
        if before != after:
            changed += 1
    db.commit()
    return changed


def prune_client_history(db: Session) -> None:
    settings = get_site_settings(db, {"dns_retain_client_history", "dns_client_history_days"})
    if settings["dns_retain_client_history"] != "1":
        return
    try:
        days = max(1, min(int(settings["dns_client_history_days"] or "365"), 3650))
    except ValueError:
        days = 365
    cutoff = datetime.utcnow() - timedelta(days=days)
    db.query(DNSClientIPHistory).filter(DNSClientIPHistory.last_seen_at < cutoff).delete(synchronize_session=False)
    db.query(DNSClientHostnameHistory).filter(DNSClientHostnameHistory.last_seen_at < cutoff).delete(synchronize_session=False)
    db.query(DNSClientEvent).filter(DNSClientEvent.created_at < cutoff).delete(synchronize_session=False)
    db.commit()
