"""Persistent DNS client identity and VLAN/IP record integration."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
from ipaddress import ip_address
import json
import re
from typing import Any

from sqlalchemy import and_, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.models.models import (
    DNSClientEvent,
    DNSClientHostnameHistory,
    DNSClientIPHistory,
    DNSClientObservation,
    DNSClientTrafficEvent,
    DNSProviderConfig,
    DNSRecognisedDevice,
    DHCPLeaseHistory,
    DHCPRange,
    IPAddress,
)
from app.services.audit import write_audit
from app.services.site_settings import get_site_settings


PLACEHOLDER_HOSTNAMES = {"", "-", "unknown", "localhost", "none", "null"}
INVALID_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
RETENTION_FOREVER = "forever"


def logical_provider_key(provider: DNSProviderConfig) -> str:
    """Return the stable service boundary used for client identity matching."""
    return f"ha-cluster:{provider.ha_cluster_id}" if provider.ha_cluster_id else f"provider:{provider.id}"


def _provider_scope_ids(db: Session, provider: DNSProviderConfig) -> list[int]:
    if provider.ha_cluster_id:
        return [row.id for row in db.query(DNSProviderConfig.id).filter(DNSProviderConfig.ha_cluster_id == provider.ha_cluster_id)]
    return [provider.id]


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


def match_client(db: Session, provider: DNSProviderConfig, *, provider_client_id: str | None, mac: str | None, ip: str | None, hostname: str | None, observed_at: datetime | None = None) -> tuple[DNSRecognisedDevice | None, str | None]:
    provider_ids = _provider_scope_ids(db, provider)
    hostname_key = normalise_hostname(hostname, ip)
    if mac:
        row = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.provider_id.in_(provider_ids), DNSRecognisedDevice.normalised_mac == mac).order_by(DNSRecognisedDevice.last_seen_at.desc()).first()
        if row:
            return row, "mac_address"
    if provider_client_id:
        row = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.provider_id.in_(provider_ids), DNSRecognisedDevice.provider_client_id == provider_client_id).first()
        if row:
            return row, "provider_client_identifier"
    # Inside a configured DHCP range, an address is temporary evidence rather
    # than identity. Only provider IDs and MAC addresses may reunite a client.
    if dhcp_range_for_ip(db, ip):
        active_lease = (
            db.query(DHCPLeaseHistory)
            .filter(DHCPLeaseHistory.provider_id.in_(provider_ids), DHCPLeaseHistory.ip_address == ip, DHCPLeaseHistory.is_active == True)  # noqa: E712
            .order_by(DHCPLeaseHistory.last_seen_at.desc())
            .first()
        )
        if active_lease and active_lease.dns_client_id:
            leased_client = db.get(DNSRecognisedDevice, active_lease.dns_client_id)
            if leased_client and _compatible_mac(leased_client, mac):
                return leased_client, "active_dhcp_lease"
        if hostname_key:
            recent = (observed_at or datetime.utcnow()) - timedelta(days=1)
            rows = db.query(DNSRecognisedDevice).filter(
                DNSRecognisedDevice.provider_id.in_(provider_ids),
                DNSRecognisedDevice.current_ip == ip,
                DNSRecognisedDevice.normalised_hostname == hostname_key,
                DNSRecognisedDevice.last_seen_at >= recent,
            ).all()
            if len(rows) == 1:
                return rows[0], "recent_dhcp_ip_hostname"
        return None, None
    if ip and hostname_key:
        rows = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.provider_id.in_(provider_ids), DNSRecognisedDevice.current_ip == ip, DNSRecognisedDevice.normalised_hostname == hostname_key).all()
        rows = [row for row in rows if _compatible_mac(row, mac)]
        if len(rows) == 1:
            return rows[0], "ip_and_hostname"
    if ip:
        rows = [row for row in db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.provider_id.in_(provider_ids), DNSRecognisedDevice.current_ip == ip).all() if _compatible_mac(row, mac)]
        if len(rows) == 1:
            return rows[0], "ip_address"
    if hostname_key and not mac:
        rows = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.provider_id.in_(provider_ids), DNSRecognisedDevice.normalised_hostname == hostname_key).all()
        if len(rows) == 1 and not rows[0].normalised_mac:
            return rows[0], "hostname"
    return None, None


def stable_identity_key(*, mac: str | None, provider_client_id: str | None, ip: str | None, hostname: str | None, observed_at: datetime) -> str:
    """Build a constrained logical identity without treating an IP as permanent."""
    if mac:
        return f"mac:{mac}"
    if provider_client_id:
        digest = hashlib.sha256(provider_client_id.encode("utf-8")).hexdigest()[:32]
        return f"provider-client:{digest}"
    weak = f"{normalise_hostname(hostname, ip) or '-'}|{ip or '-'}"
    digest = hashlib.sha256(weak.encode("utf-8")).hexdigest()[:32]
    return f"weak:{digest}:{observed_at.date().isoformat()}"


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
    provider_key = logical_provider_key(provider)
    in_dhcp_range = bool(dhcp_range_for_ip(db, ip))
    identity_type = "mac" if mac else "provider_client" if provider_client_id else "hostname_ip" if hostname_key and ip else "ip" if ip else "hostname"
    weak_identity = f"{hostname_key or '-'}|{ip or '-'}"
    identity_value = mac or provider_client_id or (f"{weak_identity}|{observed_at.date().isoformat()}" if in_dhcp_range else ip) or hostname_key
    identity_key = stable_identity_key(mac=mac, provider_client_id=provider_client_id, ip=ip, hostname=hostname, observed_at=observed_at)
    if not mac and not provider_client_id:
        identity_value = identity_key
    client = db.query(DNSRecognisedDevice).filter(
        DNSRecognisedDevice.logical_provider_key == provider_key,
        DNSRecognisedDevice.identity_key == identity_key,
    ).first()
    if not client and (mac or provider_client_id):
        client = db.query(DNSRecognisedDevice).filter(
            DNSRecognisedDevice.provider_id.in_(_provider_scope_ids(db, provider)),
            DNSRecognisedDevice.identity_type == identity_type,
            DNSRecognisedDevice.identity_value == str(identity_value),
        ).first()
    match_method = "provider_identity" if client else None
    if not client:
        client, match_method = match_client(db, provider, provider_client_id=provider_client_id, mac=mac, ip=ip, hostname=hostname, observed_at=observed_at)
        if client and client.identity_key:
            identity_key = client.identity_key
    created = False
    if not client:
        candidate = DNSRecognisedDevice(
            provider_id=provider.id,
            logical_provider_key=provider_key,
            identity_key=identity_key,
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
        try:
            with db.begin_nested():
                db.add(candidate)
                db.flush()
            client = candidate
            created = True
        except IntegrityError:
            client = db.query(DNSRecognisedDevice).filter_by(logical_provider_key=provider_key, identity_key=identity_key).first()
            if client is None:
                raise
            match_method = "provider_identity_race"
    if created:
        _event(db, client, "client_discovered", "DNS client discovered", new=hostname or ip or mac, source=source)
    else:
        client.logical_provider_key = provider_key
        # Promote a weak identity when a stable identifier becomes available.
        if mac or provider_client_id or not client.identity_key:
            client.identity_key = stable_identity_key(mac=mac or client.normalised_mac, provider_client_id=provider_client_id or client.provider_client_id, ip=ip or client.current_ip, hostname=hostname or client.hostname, observed_at=observed_at)
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
        client.provider_type = provider.provider_type
        client.first_seen_at = min(client.first_seen_at or first_seen, first_seen)
        client.last_seen_at = max(client.last_seen_at or observed_at, observed_at)
        client.last_synced_at = generated_at
        client.observation_source = source
    client.query_count = int(getattr(observation, "queries", 0) or 0)
    client.blocked_query_count = int(getattr(observation, "blocked_queries", 0) or 0)
    client.match_method = client.match_method or match_method
    _history(db, client, ip=ip, hostname=hostname, observed_at=observed_at, source=source)
    observation_key = hashlib.sha256(json.dumps({
        "client": client.id,
        "provider": provider.id,
        "ip": ip,
        "mac": mac,
        "hostname": hostname_key,
        "observed_at": observed_at.isoformat(timespec="microseconds"),
        "source": source,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    existing_observation = db.query(DNSClientObservation.id).filter_by(provider_id=provider.id, observation_key=observation_key).first()
    if not existing_observation:
        client.observation_count = int(client.observation_count or 0) + 1
        db.add(DNSClientObservation(
            dns_client_id=client.id,
            provider_id=provider.id,
            observation_key=observation_key,
            ip_address=ip,
            mac_address=mac,
            hostname=hostname,
            logical_provider_key=provider_key,
            source=source[:255],
            source_member=str(getattr(observation, "source_member", "") or "")[:120] or None,
            observed_at=observed_at,
        ))
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


def list_clients(db: Session, *, provider_id: int | None = None, search: str = "", status: str = "", offset: int = 0, limit: int = 50) -> tuple[list[DNSRecognisedDevice], int]:
    query = db.query(DNSRecognisedDevice).options(joinedload(DNSRecognisedDevice.provider), joinedload(DNSRecognisedDevice.linked_ip_record), joinedload(DNSRecognisedDevice.suggested_ip_record))
    if provider_id:
        query = query.filter(DNSRecognisedDevice.provider_id == provider_id)
    clean = search.strip()
    if clean:
        like = f"%{clean}%"
        history_ids = db.query(DNSClientIPHistory.dns_client_id).filter(DNSClientIPHistory.ip_address.ilike(like)).union(db.query(DNSClientHostnameHistory.dns_client_id).filter(DNSClientHostnameHistory.hostname.ilike(like)))
        query = query.outerjoin(IPAddress, DNSRecognisedDevice.linked_ip_record_id == IPAddress.id).filter(or_(DNSRecognisedDevice.friendly_name.ilike(like), DNSRecognisedDevice.hostname.ilike(like), DNSRecognisedDevice.current_ip.ilike(like), DNSRecognisedDevice.mac_address.ilike(like), DNSRecognisedDevice.notes.ilike(like), IPAddress.name.ilike(like), DNSRecognisedDevice.id.in_(history_ids)))
    settings = get_site_settings(db, {"dns_stale_client_days"})
    try:
        stale_days = int(settings["dns_stale_client_days"] or "30")
    except ValueError:
        stale_days = 30
    stale_cutoff = datetime.utcnow() - timedelta(days=stale_days)
    recent = DNSRecognisedDevice.last_seen_at >= stale_cutoff
    not_ignored = DNSRecognisedDevice.is_ignored == False  # noqa: E712
    mac_conflict = and_(IPAddress.mac_address.is_not(None), DNSRecognisedDevice.normalised_mac.is_not(None), func.lower(func.replace(IPAddress.mac_address, "-", ":")) != DNSRecognisedDevice.normalised_mac)
    static_ip_conflict = and_(IPAddress.assignment_type != "Dynamic", DNSRecognisedDevice.current_ip.is_not(None), IPAddress.address != DNSRecognisedDevice.current_ip)
    if status == "ignored":
        query = query.filter(DNSRecognisedDevice.is_ignored == True)  # noqa: E712
    elif status == "stale":
        query = query.filter(not_ignored, DNSRecognisedDevice.last_seen_at < stale_cutoff)
    elif status == "suggested-match":
        query = query.filter(not_ignored, recent, DNSRecognisedDevice.linked_ip_record_id.is_(None), DNSRecognisedDevice.match_confidence.is_not(None))
    elif status == "known":
        query = query.filter(not_ignored, recent, DNSRecognisedDevice.linked_ip_record_id.is_(None), DNSRecognisedDevice.match_confidence.is_(None), DNSRecognisedDevice.is_known == True)  # noqa: E712
    elif status == "unmanaged":
        query = query.filter(not_ignored, recent, DNSRecognisedDevice.linked_ip_record_id.is_(None), DNSRecognisedDevice.match_confidence.is_(None), DNSRecognisedDevice.is_known == False)  # noqa: E712
    elif status == "conflict":
        query = query.join(IPAddress, DNSRecognisedDevice.linked_ip_record_id == IPAddress.id).filter(
            not_ignored, recent, or_(mac_conflict, static_ip_conflict),
        )
    elif status == "linked":
        query = query.join(IPAddress, DNSRecognisedDevice.linked_ip_record_id == IPAddress.id).filter(not_ignored, recent, ~or_(mac_conflict, static_ip_conflict))
    total = query.count()
    rows = query.order_by(DNSRecognisedDevice.last_seen_at.desc(), DNSRecognisedDevice.id.desc()).offset(offset).limit(limit).all()
    return rows, total


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


def list_dhcp_leases(db: Session, *, provider_id: int | None, status: str = "current", offset: int = 0, limit: int = 50, now: datetime | None = None) -> tuple[list[DHCPLeaseHistory], int]:
    """Return a bounded retained-lease view; no provider call is made here."""
    now = now or datetime.utcnow()
    recent_cutoff = now - timedelta(hours=24)
    query = db.query(DHCPLeaseHistory).options(
        joinedload(DHCPLeaseHistory.client), joinedload(DHCPLeaseHistory.dhcp_range).joinedload(DHCPRange.vlan), joinedload(DHCPLeaseHistory.provider)
    )
    if provider_id:
        query = query.filter(DHCPLeaseHistory.provider_id == provider_id)
    if status == "active":
        query = query.filter(DHCPLeaseHistory.is_active == True)  # noqa: E712
    elif status == "recent":
        query = query.filter(DHCPLeaseHistory.is_active == False, DHCPLeaseHistory.ended_at >= recent_cutoff)  # noqa: E712
    elif status == "history":
        query = query.filter(DHCPLeaseHistory.is_active == False, DHCPLeaseHistory.ended_at < recent_cutoff)  # noqa: E712
    elif status != "all":
        query = query.filter(or_(DHCPLeaseHistory.is_active == True, DHCPLeaseHistory.ended_at >= recent_cutoff))  # noqa: E712
    total = query.count()
    rows = query.order_by(DHCPLeaseHistory.is_active.desc(), DHCPLeaseHistory.last_seen_at.desc(), DHCPLeaseHistory.id.desc()).offset(offset).limit(limit).all()
    return rows, total


def _retention_days(value: str, default: int) -> int | None:
    if str(value or "").strip().lower() == RETENTION_FOREVER:
        return None
    try:
        return max(1, min(int(value), 3650))
    except (TypeError, ValueError):
        return default


def cleanup_dns_history(db: Session, *, now: datetime | None = None) -> dict[str, int]:
    """Transactionally prune only raw observations and ended lease intervals."""
    now = now or datetime.utcnow()
    values = get_site_settings(db, {"dns_observation_history_days", "dns_dhcp_history_days"})
    observation_days = _retention_days(values["dns_observation_history_days"], 30)
    lease_days = _retention_days(values["dns_dhcp_history_days"], 90)
    observations_deleted = 0
    leases_deleted = 0
    try:
        if observation_days is not None:
            observations_deleted = db.query(DNSClientObservation).filter(DNSClientObservation.observed_at < now - timedelta(days=observation_days)).delete(synchronize_session=False)
        if lease_days is not None:
            leases_deleted = db.query(DHCPLeaseHistory).filter(
                DHCPLeaseHistory.is_active == False,  # noqa: E712
                DHCPLeaseHistory.ended_at.is_not(None),
                DHCPLeaseHistory.ended_at < now - timedelta(days=lease_days),
            ).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
        raise
    if observations_deleted or leases_deleted:
        write_audit(
            db, None, "retention_cleanup", "dns_history",
            detail="Expired DNS observation and ended DHCP lease history was removed by policy.",
            category="data",
            metadata={"observations_deleted": observations_deleted, "ended_leases_deleted": leases_deleted},
        )
    return {"observations": observations_deleted, "dhcp_leases": leases_deleted}


def consolidate_strong_identity_duplicates(db: Session) -> int:
    """Merge only unambiguous same-MAC rows within one logical provider boundary."""
    rows = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.normalised_mac.is_not(None)).order_by(DNSRecognisedDevice.id.asc()).all()
    groups: dict[tuple[str, str], list[DNSRecognisedDevice]] = {}
    for row in rows:
        key = row.logical_provider_key or f"provider:{row.provider_id}"
        groups.setdefault((key, row.normalised_mac), []).append(row)
    merged = 0
    for candidates in groups.values():
        if len(candidates) < 2:
            continue
        linked_ids = {row.linked_ip_record_id for row in candidates if row.linked_ip_record_id}
        if len(linked_ids) > 1:
            continue
        survivor = sorted(candidates, key=lambda row: (not bool(row.linked_ip_record_id), not row.is_known, row.id))[0]
        for duplicate in candidates:
            if duplicate.id == survivor.id:
                continue
            for history_model, key_field in ((DNSClientIPHistory, "ip_address"), (DNSClientHostnameHistory, "normalised_hostname")):
                for history in db.query(history_model).filter_by(dns_client_id=duplicate.id).all():
                    existing = db.query(history_model).filter(
                        history_model.dns_client_id == survivor.id,
                        getattr(history_model, key_field) == getattr(history, key_field),
                    ).first()
                    if existing:
                        existing.first_seen_at = min(existing.first_seen_at, history.first_seen_at)
                        existing.last_seen_at = max(existing.last_seen_at, history.last_seen_at)
                        existing.observation_count += history.observation_count
                        db.delete(history)
                    else:
                        history.dns_client_id = survivor.id
            for model in (DNSClientObservation, DNSClientEvent, DNSClientTrafficEvent, DHCPLeaseHistory):
                db.query(model).filter(model.dns_client_id == duplicate.id).update({"dns_client_id": survivor.id}, synchronize_session=False)
            if duplicate.last_seen_at >= survivor.last_seen_at:
                survivor.current_ip = duplicate.current_ip or survivor.current_ip
                survivor.hostname = duplicate.hostname or survivor.hostname
                survivor.normalised_hostname = duplicate.normalised_hostname or survivor.normalised_hostname
                survivor.observation_source = duplicate.observation_source or survivor.observation_source
            survivor.first_seen_at = min(survivor.first_seen_at or duplicate.first_seen_at, duplicate.first_seen_at or survivor.first_seen_at)
            survivor.last_seen_at = max(survivor.last_seen_at or duplicate.last_seen_at, duplicate.last_seen_at or survivor.last_seen_at)
            survivor.observation_count = int(survivor.observation_count or 0) + int(duplicate.observation_count or 0)
            survivor.linked_ip_record_id = survivor.linked_ip_record_id or duplicate.linked_ip_record_id
            survivor.suggested_ip_record_id = survivor.suggested_ip_record_id or duplicate.suggested_ip_record_id
            survivor.friendly_name = survivor.friendly_name or duplicate.friendly_name
            survivor.notes = survivor.notes or duplicate.notes
            survivor.is_known = survivor.is_known or duplicate.is_known
            survivor.is_ignored = survivor.is_ignored or duplicate.is_ignored
            db.delete(duplicate)
            merged += 1
    db.commit()
    return merged
