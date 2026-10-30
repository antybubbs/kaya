"""Bounded, read-only composition and atomic adoption of discovered devices."""
from __future__ import annotations

from datetime import datetime
import ipaddress

from sqlalchemy import text
from sqlalchemy.orm import Session, joinedload

from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    TrafficDiscoveryObservation,
    TrafficSource,
)
from app.services.audit import write_audit
from app.services.asset_identity import (
    MANAGED_HOSTNAME_SOURCE,
    MANAGED_STATIC_PROVENANCE,
    _assignment_lock_key,
    _lock_asset_dhcp,
    _normalise_evidence,
    confirmed_mac_owned_elsewhere,
    dhcp_address_lock_key,
    dhcp_identity_conflict,
    lock_identity_scope,
    managed_static_record_mac,
    superseded_dhcp_assignments,
)
from app.services.asset_tags import allocate_asset_tag

MAX_CANDIDATES = 5000
MAX_SOURCE_ROWS = 5000


def _discovery_lock_key(value: str) -> int:
    """Derive the same stable signed key shape used by identity locking."""
    return _assignment_lock_key(f"discovered:{value}", 0, None, None, None)


def _lock_adoption_keys(db: Session, keys: list[int]) -> None:
    """Serialize one adoption transaction on PostgreSQL; remain a no-op on SQLite."""
    if db.get_bind().dialect.name != "postgresql":
        return
    for key in sorted(set(keys)):
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": key})


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _candidate_key(kind: str, value: object) -> str:
    return f"{kind}:{value}"


def _dhcp_identity_scope(provider_id: int | None, dhcp_range_id: int | None) -> str | None:
    if provider_id is None:
        return None
    range_part = str(dhcp_range_id) if dhcp_range_id is not None else "unscoped"
    return f"provider:{provider_id}:range:{range_part}"


def _candidate(store: dict[str, dict], key: str, *, kind: str, name: str | None, ip: str | None, first: datetime | None, last: datetime | None) -> dict:
    row = store.setdefault(key, {
        "id": key, "kind": kind, "name": name or ip or "Unidentified device", "ip_addresses": [],
        "mac_addresses": [], "dhcp_client_ids": [], "sources": [], "vlan_context": [],
        "first_seen_at": _iso(first), "last_seen_at": _iso(last), "review_state": "review",
        "asset_id": None, "asset_name": None, "evidence": [], "traffic": [], "dns_client_id": None,
        "provider_name": None,
        "dhcp_identity_scope": None,
        "dhcp_lease_ids": [], "traffic_observation": None,
        "historical_assignments": [], "identity_conflict": False,
        "stale_reason": None,
    })
    if name and row["name"] in {"Unidentified device", ip}:
        row["name"] = name
    if ip and ip not in row["ip_addresses"]:
        row["ip_addresses"].append(ip)
    if first and (not row["first_seen_at"] or first.isoformat() < row["first_seen_at"]):
        row["first_seen_at"] = first.isoformat()
    if last and (not row["last_seen_at"] or last.isoformat() > row["last_seen_at"]):
        row["last_seen_at"] = last.isoformat()
    return row


def compose_discovered_devices(db: Session, *, query: str = "", source: str = "", state: str = "", page: int = 1, page_size: int = 50) -> dict:
    """Compose source-owned observations without creating a competing identity store."""
    page_size = max(1, min(int(page_size), MAX_CANDIDATES))
    page = max(1, int(page))
    candidates: dict[str, dict] = {}
    dns_rows = db.query(DNSRecognisedDevice).order_by(DNSRecognisedDevice.last_seen_at.desc()).limit(MAX_SOURCE_ROWS).all()
    hardware_asset_ids = {row.hardware_asset_id for row in dns_rows if row.hardware_asset_id is not None}
    hardware_assets = {
        row.id: row
        for row in db.query(HardwareAsset).filter(HardwareAsset.id.in_(hardware_asset_ids or {-1})).all()
    }
    dns_by_id: dict[int, dict] = {}
    for row in dns_rows:
        key = _candidate_key("dns", row.id)
        item = _candidate(candidates, key, kind="dns", name=row.friendly_name or row.hostname, ip=row.current_ip, first=row.first_seen_at, last=row.last_seen_at)
        item["dns_client_id"] = row.id
        item["sources"] = sorted(set(item["sources"]) | {"DNS Manager"})
        item["provider_name"] = row.provider.name if row.provider else row.provider_type
        item["dhcp_identity_scope"] = _dhcp_identity_scope(row.provider_id, None)
        item["evidence"] = [value for value in (row.hostname, row.mac_address, row.provider_client_id) if value]
        item["asset_id"] = row.hardware_asset_id
        if row.hardware_asset_id:
            asset = hardware_assets.get(row.hardware_asset_id)
            item["asset_name"] = asset.name if asset else None
        mac_address = row.normalised_mac or row.mac_address
        if mac_address:
            item["mac_addresses"] = [mac_address]
        if row.provider_client_id:
            item["dhcp_client_ids"] = [row.provider_client_id]
        if row.is_ignored:
            item["review_state"] = "dismissed"
        dns_by_id[row.id] = item

    lease_rows = db.query(DHCPLeaseHistory).order_by(DHCPLeaseHistory.last_seen_at.desc()).limit(MAX_SOURCE_ROWS).all()
    for row in lease_rows:
        item = dns_by_id.get(row.dns_client_id) if row.dns_client_id else None
        if item is None:
            key = _candidate_key("dhcp", row.id)
            item = _candidate(candidates, key, kind="dhcp", name=row.hostname, ip=row.ip_address, first=row.first_seen_at, last=row.last_seen_at)
        item["sources"] = sorted(set(item["sources"]) | {"DHCP"})
        if row.mac_address and row.mac_address not in item["mac_addresses"]:
            item["mac_addresses"].append(row.mac_address)
        item["dhcp_lease_ids"].append(row.id)
        item["dhcp_identity_scope"] = _dhcp_identity_scope(row.provider_id, row.dhcp_range_id) or item["dhcp_identity_scope"]

    observations = db.query(TrafficDiscoveryObservation).order_by(TrafficDiscoveryObservation.last_seen_at.desc()).limit(MAX_SOURCE_ROWS).all()
    source_rows = {row.id: row for row in db.query(TrafficSource).filter(TrafficSource.id.in_({row.source_id for row in observations} or {-1})).all()}
    for row in observations:
        key = _candidate_key("traffic", f"{row.source_id}:{row.exporter_identity}:{row.endpoint_ip}:{row.endpoint_role}")
        source_row = source_rows.get(row.source_id)
        item = _candidate(candidates, key, kind="traffic", name=None, ip=row.endpoint_ip, first=row.first_seen_at, last=row.last_seen_at)
        item["sources"] = sorted(set(item["sources"]) | {source_row.name if source_row else "Network Traffic"})
        item["traffic"].append({"source_id": row.source_id, "source_name": source_row.name if source_row else None, "exporter_identity": row.exporter_identity, "endpoint_role": row.endpoint_role, "classification": row.classification, "confidence": row.confidence, "observation_count": row.observation_count, "first_seen_at": _iso(row.first_seen_at), "last_seen_at": _iso(row.last_seen_at)})
        item["traffic_observation"] = {"source_id": row.source_id, "exporter_identity": row.exporter_identity, "endpoint_ip": row.endpoint_ip, "endpoint_role": row.endpoint_role}

    addresses = {ip for item in candidates.values() for ip in item["ip_addresses"]}
    ip_rows = {row.address: row for row in db.query(IPAddress).options(joinedload(IPAddress.vlan)).filter(IPAddress.address.in_(addresses or {"0.0.0.0"})).limit(MAX_SOURCE_ROWS).all()}
    ip_ids = [row.id for row in ip_rows.values()]
    assignments = db.query(AssetNetworkAssignment).options(joinedload(AssetNetworkAssignment.asset)).filter(
        AssetNetworkAssignment.ip_address_id.in_(ip_ids or [-1]),
        AssetNetworkAssignment.status == "confirmed",
    ).order_by(AssetNetworkAssignment.started_at.desc()).limit(MAX_SOURCE_ROWS).all()
    assignment_by_ip: dict[int, AssetNetworkAssignment] = {}
    assignments_by_ip: dict[int, list[AssetNetworkAssignment]] = {}
    for assignment in assignments:
        assignments_by_ip.setdefault(assignment.ip_address_id, []).append(assignment)
        # An address is an assignment at a point in time, not a permanent
        # identity. Only an open assignment can be current evidence. Closed
        # rows remain available below as historical context.
        if assignment.ended_at is None:
            assignment_by_ip.setdefault(assignment.ip_address_id, assignment)

    evidence_values = {
        ("mac", mac)
        for item in candidates.values()
        for mac in item["mac_addresses"]
        if mac
    }
    evidence_values.update(
        ("dhcp_client_id", client_id)
        for item in candidates.values()
        for client_id in item["dhcp_client_ids"]
        if client_id
    )
    confirmed_identity_assets: dict[tuple[str, str], set[int]] = {}
    if evidence_values:
        evidence_rows = db.query(AssetIdentityEvidence).filter(
            AssetIdentityEvidence.status == "confirmed",
            AssetIdentityEvidence.revoked_at.is_(None),
            AssetIdentityEvidence.evidence_type.in_({kind for kind, _value in evidence_values}),
            AssetIdentityEvidence.normalised_value.in_({value.casefold() for _kind, value in evidence_values}),
        ).limit(MAX_SOURCE_ROWS).all()
        for row in evidence_rows:
            if row.asset_id is not None:
                confirmed_identity_assets.setdefault((row.evidence_type, row.normalised_value), set()).add(row.asset_id)

    for item in candidates.values():
        strong_assets = set()
        for evidence_type, values in (("mac", item["mac_addresses"]), ("dhcp_client_id", item["dhcp_client_ids"])):
            for value in values:
                strong_assets.update(confirmed_identity_assets.get((evidence_type, value.casefold()), set()))
        if item["asset_id"] is not None and (item["mac_addresses"] or item["dhcp_client_ids"]) and item["asset_id"] not in strong_assets:
            # A source-owned link that contradicts confirmed strong identity
            # evidence is not allowed to block review/adoption. Preserve it as
            # historical context instead of altering the source record.
            item["historical_asset_id"] = item["asset_id"]
            item["historical_asset_name"] = item["asset_name"]
            item["asset_id"] = None
            item["asset_name"] = None
            item["identity_conflict"] = True
        for address in item["ip_addresses"]:
            ip_row = ip_rows.get(address)
            if not ip_row:
                continue
            if ip_row.vlan and ip_row.vlan.name not in item["vlan_context"]:
                item["vlan_context"].append(ip_row.vlan.name)
            assignment = assignment_by_ip.get(ip_row.id)
            if assignment and assignment.asset_id and assignment.asset_id not in strong_assets:
                item["historical_assignments"].append({
                    "asset_id": assignment.asset_id,
                    "asset_name": assignment.asset.name if assignment.asset else None,
                    "address": assignment.address,
                    "started_at": _iso(assignment.started_at),
                    "ended_at": _iso(assignment.ended_at),
                })
            if item["asset_id"] is None and assignment and assignment.asset_id and assignment.asset_id in strong_assets:
                item["asset_id"] = assignment.asset_id
                item["asset_name"] = assignment.asset.name if assignment.asset else None
            for historical in assignments_by_ip.get(ip_row.id, []):
                if historical.ip_address_id == ip_row.id and historical.ended_at is not None and historical.asset_id:
                    item["historical_assignments"].append({
                        "asset_id": historical.asset_id,
                        "asset_name": historical.asset.name if historical.asset else None,
                        "address": historical.address,
                        "started_at": _iso(historical.started_at),
                        "ended_at": _iso(historical.ended_at),
                    })
        if item["historical_assignments"]:
            seen = set()
            item["historical_assignments"] = [row for row in item["historical_assignments"] if not ((row["asset_id"], row["started_at"], row["ended_at"]) in seen or seen.add((row["asset_id"], row["started_at"], row["ended_at"])))]

    clean_query = query.strip().casefold()[:120]
    rows = list(candidates.values())
    if clean_query:
        rows = [row for row in rows if clean_query in " ".join([row["name"], *row["ip_addresses"], *row["mac_addresses"], *row["sources"]]).casefold()]
    if source:
        rows = [row for row in rows if source in row["sources"]]
    if state in {"review", "dismissed", "adopted"}:
        rows = [row for row in rows if ("adopted" if row["asset_id"] else row["review_state"]) == state]
    rows.sort(key=lambda row: (row["last_seen_at"] or "", row["name"].casefold()), reverse=True)
    total = len(rows)
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    selected = rows[(page - 1) * page_size: page * page_size]
    return {"rows": selected, "total": total, "page": page, "page_size": page_size, "pages": pages, "sources": sorted({source for row in candidates.values() for source in row["sources"]})}


def get_discovered_device(db: Session, candidate_id: str) -> dict | None:
    """Resolve a candidate through its explicit source namespace."""
    clean_id = candidate_id.strip()
    if clean_id.startswith("dhcp:"):
        raw_id = clean_id[5:]
        if not raw_id.isdigit() or int(raw_id) <= 0:
            return None
        lease = db.get(DHCPLeaseHistory, int(raw_id))
        if not lease:
            return None
        item = _candidate(
            {}, clean_id, kind="dhcp", name=lease.hostname, ip=lease.ip_address,
            first=lease.first_seen_at, last=lease.last_seen_at,
        )
        item["sources"] = ["DHCP"]
        item["provider_name"] = lease.provider.name if lease.provider else None
        item["dhcp_identity_scope"] = _dhcp_identity_scope(lease.provider_id, lease.dhcp_range_id)
        item["mac_addresses"] = [lease.mac_address] if lease.mac_address else []
        item["dhcp_client_ids"] = [lease.provider_lease_id] if lease.provider_lease_id else []
        item["dhcp_lease_ids"] = [lease.id]
        item["dns_client_id"] = lease.dns_client_id
        if lease.dhcp_range and lease.dhcp_range.vlan:
            item["vlan_context"] = [lease.dhcp_range.vlan.name]
        if lease.dns_client_id:
            dns_client = db.get(DNSRecognisedDevice, lease.dns_client_id)
            if dns_client:
                item["evidence"] = [value for value in (dns_client.hostname, dns_client.normalised_mac, dns_client.provider_client_id) if value]
                item["asset_id"] = dns_client.hardware_asset_id
        assignment = db.query(AssetNetworkAssignment).filter(
            AssetNetworkAssignment.dhcp_lease_id == lease.id,
            AssetNetworkAssignment.status == "confirmed",
        ).order_by(AssetNetworkAssignment.started_at.desc()).first()
        if assignment:
            item["asset_id"] = assignment.asset_id
            item["asset_name"] = assignment.asset.name if assignment.asset else None
        elif dhcp_identity_conflict(db, lease):
            # Conflicting confirmed identifiers: never present the lease as
            # associated through a MAC-linked DNS client; it needs review.
            item["asset_id"] = None
            item["identity_conflict"] = True
        if lease.expires_at and lease.expires_at < datetime.utcnow():
            item["review_state"] = "stale"
            item["stale_reason"] = "DHCP lease expired."
        elif not lease.is_active:
            item["review_state"] = "stale"
            item["stale_reason"] = "DHCP lease is inactive or superseded."
        return item
    result = compose_discovered_devices(db, page=1, page_size=MAX_CANDIDATES)
    return next((row for row in result["rows"] if row["id"] == candidate_id), None)


def _normalise_ip(value: str) -> tuple[str, int]:
    parsed = ipaddress.ip_address(value)
    return parsed.compressed, parsed.version


def _add_evidence(db: Session, user, asset_id: int, evidence_type: str, value: str, source: str, source_scope: str | None, now: datetime) -> None:
    normalised = _normalise_evidence(evidence_type, value)
    # MAC ownership is global across discovery sources; the caller already
    # holds the per-MAC adoption lock. Other identifiers stay source-scoped.
    if evidence_type == "mac" and confirmed_mac_owned_elsewhere(db, normalised, asset_id):
        raise ValueError("The selected evidence is already confirmed for another asset.")
    conflict = db.query(AssetIdentityEvidence).filter(
        AssetIdentityEvidence.evidence_type == evidence_type,
        AssetIdentityEvidence.normalised_value == normalised,
        AssetIdentityEvidence.source == source,
        AssetIdentityEvidence.source_scope == source_scope,
        AssetIdentityEvidence.status == "confirmed",
        AssetIdentityEvidence.asset_id != asset_id,
    ).first()
    if conflict:
        raise ValueError("The selected evidence is already confirmed for another asset in this source scope.")
    row = db.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id == asset_id, AssetIdentityEvidence.evidence_type == evidence_type, AssetIdentityEvidence.normalised_value == normalised, AssetIdentityEvidence.source == source, AssetIdentityEvidence.source_scope == source_scope, AssetIdentityEvidence.status != "revoked").first()
    if row is None:
        row = AssetIdentityEvidence(asset_id=asset_id, evidence_type=evidence_type, normalised_value=normalised, source=source, source_scope=source_scope, first_observed_at=now)
    row.status, row.confirmed_by, row.confirmed_at = "confirmed", user.id, now
    row.last_observed_at = now
    row.conflict_reason = None
    db.add(row)


def _managed_static_record(db: Session, address: str, mac: str | None) -> IPAddress | None:
    """Return the single administrator-managed static record for this address and MAC."""
    if not mac:
        return None
    rows = db.query(IPAddress).filter(
        IPAddress.address == address,
        IPAddress.mac_address.isnot(None),
    ).order_by(IPAddress.id.asc()).limit(20).all()
    matches = [row for row in rows if managed_static_record_mac(row) == mac]
    return matches[0] if len(matches) == 1 else None


def _revalidate_source_candidate(db: Session, candidate: dict) -> None:
    """Reload source-owned state after locking and reject stale candidate payloads."""
    kind = candidate.get("kind")
    if kind == "dns":
        raw_id = str(candidate.get("id") or "")
        try:
            source_id = int(raw_id.split(":", 1)[1])
        except (IndexError, ValueError):
            raise ValueError("The discovery source record is invalid.")
        row = db.get(DNSRecognisedDevice, source_id)
        if not row:
            raise ValueError("The discovery source record no longer exists.")
        if row.is_ignored:
            raise ValueError("This discovery is not available for adoption.")
        if row.hardware_asset_id and not (
            candidate.get("identity_conflict")
            and candidate.get("historical_asset_id") == row.hardware_asset_id
        ):
            raise ValueError("This discovery is already associated with an asset.")
    elif kind == "dhcp":
        raw_id = str(candidate.get("id") or "")
        try:
            source_id = int(raw_id.split(":", 1)[1])
        except (IndexError, ValueError):
            raise ValueError("The discovery source record is invalid.")
        row = db.get(DHCPLeaseHistory, source_id)
        if not row:
            raise ValueError("The discovery source record no longer exists.")
        # Lease freshness controls whether the address may be assigned as
        # current evidence; it must not prevent adoption of a valid MAC.
        # Confirmed MAC uniqueness is enforced separately by _add_evidence.
    elif kind == "traffic":
        observation = candidate.get("traffic_observation") or {}
        row = db.query(TrafficDiscoveryObservation).filter(
            TrafficDiscoveryObservation.source_id == observation.get("source_id"),
            TrafficDiscoveryObservation.exporter_identity == observation.get("exporter_identity"),
            TrafficDiscoveryObservation.endpoint_ip == observation.get("endpoint_ip"),
            TrafficDiscoveryObservation.endpoint_role == observation.get("endpoint_role"),
        ).order_by(TrafficDiscoveryObservation.last_seen_at.desc()).first()
        if not row:
            raise ValueError("The Network Traffic observation is no longer available for adoption; it remains review-only.")
        if row.classification != "internal" or not str(row.endpoint_role).startswith("original"):
            raise ValueError("This observation is ambiguous or translated and requires review.")
    else:
        raise ValueError("This discovery source cannot be adopted.")


def adopt_discovered_device(db: Session, user, candidate: dict, *, asset_id: int | None = None, new_name: str | None = None, category: str | None = None) -> HardwareAsset:
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    if not candidate or candidate.get("review_state") == "dismissed":
        raise ValueError("This discovery is not available for adoption.")
    if candidate.get("asset_id"):
        raise ValueError("This discovery is already associated with an asset.")
    if candidate.get("kind") != "traffic" and not candidate.get("mac_addresses") and not candidate.get("dhcp_client_ids"):
        raise ValueError("A stable MAC or DHCP client identifier is required before adoption.")
    lock_keys = [_discovery_lock_key(str(candidate.get("id") or ""))]
    lock_macs: list[str] = []
    address_keys: list[int] = []
    evidence_values = []
    if candidate.get("mac_addresses"):
        evidence_values.append(("mac", candidate["mac_addresses"][0], "discovery", "dns" if candidate["kind"] == "dns" else "dhcp"))
    if candidate.get("dhcp_client_ids"):
        evidence_values.append(("dhcp_client_id", candidate["dhcp_client_ids"][0], "dhcp", candidate.get("dhcp_identity_scope")))
    if candidate.get("kind") != "traffic" and candidate.get("name") and candidate["name"] != "Unidentified device":
        evidence_values.append(("hostname", candidate["name"], "dns" if candidate["kind"] == "dns" else "dhcp", None))
    # An administrator-managed static IP/VLAN Manager record for the candidate's
    # MAC is explicit current intent, outranking DHCP-derived network state.
    managed_static = None
    if candidate.get("kind") in {"dns", "dhcp"} and candidate.get("mac_addresses") and candidate.get("ip_addresses"):
        try:
            candidate_mac = _normalise_evidence("mac", candidate["mac_addresses"][0])
        except ValueError:
            candidate_mac = None
        managed_static = _managed_static_record(db, _normalise_ip(candidate["ip_addresses"][0])[0], candidate_mac)
    if managed_static and managed_static.name and managed_static.name.strip():
        evidence_values.append(("hostname", managed_static.name.strip(), MANAGED_HOSTNAME_SOURCE, None))
    for evidence_type, value, source, scope in evidence_values:
        normalised = _normalise_evidence(evidence_type, value)
        lock_keys.append(_discovery_lock_key(f"evidence:{evidence_type}:{normalised}:{source}:{scope or '<null>'}"))
        if evidence_type == "mac":
            # Serialises every confirmation of this MAC, whatever its source.
            lock_macs.append(normalised)
    if candidate.get("ip_addresses"):
        normalised, family = _normalise_ip(candidate["ip_addresses"][0])
        ip_row = managed_static or db.query(IPAddress).filter(IPAddress.address == normalised).order_by(IPAddress.id.asc()).first()
        if ip_row:
            address_keys.append(_assignment_lock_key(normalised, family, ip_row.vlan_id, None, None))
            # DHCP reconciliation serialises on this key for the same address.
            address_keys.append(dhcp_address_lock_key(normalised, family))
    if candidate.get("kind") == "traffic" and candidate.get("traffic_observation"):
        observation = candidate["traffic_observation"]
        lock_keys.append(_discovery_lock_key(
            f"traffic:{observation.get('source_id')}:{observation.get('exporter_identity')}:{observation.get('endpoint_ip')}:{observation.get('endpoint_role')}"
        ))
    # Adoption-only discovery keys first, then the shared MAC, asset and
    # address tiers in the global order used by DHCP reconciliation and repair.
    _lock_adoption_keys(db, lock_keys)
    lock_identity_scope(db, macs=lock_macs, asset_ids=[asset_id] if asset_id else [], assignment_keys=address_keys)
    _revalidate_source_candidate(db, candidate)
    now = datetime.utcnow()
    asset = db.get(HardwareAsset, asset_id) if asset_id else HardwareAsset(
        asset_tag=allocate_asset_tag(db, None),
        name=(new_name or candidate["name"]).strip()[:255],
        category=(category or "").strip()[:120] or None,
        status="In use",
    )
    if asset_id and not asset:
        raise ValueError("Hardware asset not found.")
    if not asset_id:
        db.add(asset)
        db.flush()
    if candidate["kind"] in {"dns", "dhcp"}:
        for evidence_type, value, source, scope in evidence_values:
            _add_evidence(db, user, asset.id, evidence_type, value, source, scope, now)
        if candidate.get("dns_client_id"):
            dns_row = db.get(DNSRecognisedDevice, candidate["dns_client_id"])
            if dns_row:
                dns_row.hardware_asset_id = asset.id
    traffic_observation = candidate.get("traffic_observation") if candidate.get("kind") == "traffic" else None
    if traffic_observation:
        normalised, family = _normalise_ip(traffic_observation["endpoint_ip"])
        source_id = int(traffic_observation["source_id"])
        exporter_identity = str(traffic_observation["exporter_identity"]).strip()[:255]
        conflict = db.query(AssetNetworkAssignment).filter(
            AssetNetworkAssignment.address == normalised,
            AssetNetworkAssignment.address_family == family,
            AssetNetworkAssignment.source_id == source_id,
            AssetNetworkAssignment.exporter_identity == exporter_identity,
            AssetNetworkAssignment.status == "confirmed",
            AssetNetworkAssignment.ended_at.is_(None),
            AssetNetworkAssignment.asset_id != asset.id,
        ).first()
        if conflict:
            raise ValueError("The observed Network Traffic endpoint is already assigned to another asset.")
        db.add(AssetNetworkAssignment(
            asset_id=asset.id, address=normalised, address_family=family,
            source_id=source_id, exporter_identity=exporter_identity,
            started_at=now, provenance="network_traffic_adoption", status="confirmed",
            confirmed_by=user.id, confirmed_at=now,
        ))
    current_dhcp_evidence = True
    if candidate["kind"] == "dhcp":
        lease = db.get(DHCPLeaseHistory, candidate["dhcp_lease_ids"][0]) if candidate.get("dhcp_lease_ids") else None
        current_dhcp_evidence = bool(lease and lease.is_active and (not lease.expires_at or lease.expires_at >= now))
    elif candidate.get("dhcp_lease_ids"):
        current_dhcp_evidence = db.query(DHCPLeaseHistory).filter(
            DHCPLeaseHistory.id.in_(candidate["dhcp_lease_ids"]),
            DHCPLeaseHistory.is_active.is_(True),
        ).filter(
            (DHCPLeaseHistory.expires_at.is_(None)) | (DHCPLeaseHistory.expires_at >= now)
        ).first() is not None
    closed_assignment_ids: list[int] = []
    for address in candidate["ip_addresses"][:1] if not traffic_observation else []:
        normalised, family = _normalise_ip(address)
        if candidate.get("dhcp_lease_ids") and not current_dhcp_evidence and managed_static is None:
            # Preserve the lease history without promoting expired/inactive
            # DHCP evidence into a current asset assignment. A managed static
            # record is not DHCP evidence, so stale leases never suppress it.
            continue
        ip_row = managed_static or db.query(IPAddress).filter(IPAddress.address == normalised).order_by(IPAddress.id.asc()).first()
        if not ip_row:
            continue
        existing = db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.asset_id == asset.id, AssetNetworkAssignment.address == normalised, AssetNetworkAssignment.status == "confirmed", AssetNetworkAssignment.ended_at.is_(None)).first()
        if not existing:
            conflict = db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.address == normalised, AssetNetworkAssignment.address_family == family, AssetNetworkAssignment.status == "confirmed", AssetNetworkAssignment.ended_at.is_(None), AssetNetworkAssignment.asset_id != asset.id).first()
            if conflict:
                if candidate.get("mac_addresses"):
                    # IP ownership is temporal. A verified new MAC may be adopted
                    # while the previous open assignment remains intact; current
                    # address reassignment is a separate reviewed action.
                    continue
                raise ValueError("The observed address is already assigned to another asset.")
            provenance = MANAGED_STATIC_PROVENANCE if managed_static else "discovered_device_adoption"
            db.add(AssetNetworkAssignment(asset_id=asset.id, address=normalised, address_family=family, vlan_id=ip_row.vlan_id, network_cidr=ip_row.vlan.subnet_cidr if ip_row.vlan else None, ip_address_id=ip_row.id, started_at=now, provenance=provenance, status="confirmed", confirmed_by=user.id, confirmed_at=now))
        if managed_static:
            # The asset now holds its managed static address: earlier DHCP
            # addresses of the same MAC stop being current but stay as history.
            # Serialise with concurrent DHCP reconciliation of this asset. An
            # existing asset is already locked above, in order; a new asset is
            # invisible to other transactions until commit, so nothing waits on it.
            _lock_asset_dhcp(db, asset.id)
            superseded = superseded_dhcp_assignments(
                db, asset.id, keep_address=normalised, family=family,
                macs=candidate.get("mac_addresses") or [], lease_ids=candidate.get("dhcp_lease_ids") or [],
            )
            for row in superseded:
                row.ended_at = max(row.started_at, now)
            closed_assignment_ids = [row.id for row in superseded]
    audit = write_audit(
        db,
        user,
        "adopt",
        "discovered_device",
        candidate["id"],
        detail="Adopted a reviewed discovery into Asset Manager",
        metadata={"asset_id": asset.id, "managed_static_ip_address_id": managed_static.id, "closed_assignment_ids": closed_assignment_ids} if managed_static else None,
        force=True,
        commit=False,
    )
    if audit is None:
        db.rollback()
        raise RuntimeError("The adoption could not be audited.")
    db.commit()
    db.refresh(asset)
    return asset
