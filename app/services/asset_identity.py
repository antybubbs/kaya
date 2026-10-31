"""Administrator-reviewed stable asset identity and network assignment operations."""

from collections.abc import Iterable
from datetime import datetime
import hashlib
import ipaddress
import re

from sqlalchemy import and_, or_, text
from sqlalchemy.orm import Session

from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    HardwareAsset,
    IPAddress,
    TrafficDiscoveryNetworkMapping,
    TrafficSource,
    User,
    VLAN,
)
from app.services.audit import write_audit
from app.services.modules import MODULE_BY_KEY, module_is_enabled


EVIDENCE_TYPES = {"mac", "dhcp_client_id", "provider_client_id", "hostname", "serial_number"}
STATUSES = {"pending", "confirmed", "revoked", "conflict", "unresolved"}
# Explicit administrator-managed IP/VLAN Manager static intent. It outranks
# DHCP-derived network state and observed DHCP/DNS hostnames for the same MAC.
MANAGED_STATIC_PROVENANCE = "managed_static_adoption"
MANAGED_STATIC_REPAIR_PROVENANCE = "managed_static_repair"
MANAGED_HOSTNAME_SOURCE = "vlan_ip_manager"
ADMINISTRATOR_HOSTNAME_SOURCE = "administrator"
_MAC = re.compile(r"^[0-9a-f]{12}$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def eligible_traffic_contexts(db: Session, address: str) -> list[dict]:
    """Return current, unambiguous source/exporter/VLAN contexts for an address."""
    normalised, family = _normalise_ip(address)
    parsed = ipaddress.ip_address(normalised)
    rows = (
        db.query(TrafficDiscoveryNetworkMapping, TrafficSource, VLAN)
        .join(TrafficSource, TrafficSource.id == TrafficDiscoveryNetworkMapping.source_id)
        .join(VLAN, VLAN.id == TrafficDiscoveryNetworkMapping.vlan_id)
        .filter(
            TrafficDiscoveryNetworkMapping.is_enabled.is_(True),
            TrafficSource.is_enabled.is_(True),
            TrafficSource.is_deleted.is_(False),
            TrafficSource.provider_key.in_(("netflow_v9", "cisco_nsel")),
            VLAN.subnet_cidr.isnot(None),
        )
        .limit(256)
        .all()
    )
    candidates = []
    for mapping, source, vlan in rows:
        try:
            network = ipaddress.ip_network(vlan.subnet_cidr, strict=False)
        except ValueError:
            continue
        if network.version == family and parsed in network:
            candidates.append((mapping, source, vlan, str(network)))
    counts = {}
    for mapping, source, _vlan, _cidr in candidates:
        key = (source.id, mapping.exporter_identity)
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "mapping_id": mapping.id,
            "source_id": source.id,
            "source_name": source.name,
            "provider_key": source.provider_key,
            "exporter_identity": mapping.exporter_identity,
            "vlan_id": vlan.id,
            "vlan_name": vlan.name,
            "network_cidr": cidr,
            "address": normalised,
        }
        for mapping, source, vlan, cidr in candidates
        if counts[(source.id, mapping.exporter_identity)] == 1
    ]


def _assignment_lock_key(address: str, family: int, vlan_id: int | None, source_id: int | None, exporter_identity: str | None) -> int:
    """Return a stable signed PostgreSQL advisory-lock key for one context."""
    parts = (
        address,
        str(family),
        str(vlan_id) if vlan_id is not None else "<null-vlan>",
        str(source_id) if source_id is not None else "<null-source>",
        exporter_identity if exporter_identity is not None else "<null-exporter>",
    )
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).digest()[:8]
    return int.from_bytes(digest, byteorder="big", signed=True)


def _lock_assignment_context(db: Session, *, address: str, family: int, vlan_id: int | None, source_id: int | None, exporter_identity: str | None) -> None:
    """Serialize competing assignment confirmations on PostgreSQL only."""
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": _assignment_lock_key(address, family, vlan_id, source_id, exporter_identity)},
        )


def _normalise_evidence(evidence_type: str, value: str) -> str:
    kind = str(evidence_type or "").strip().lower()
    value = str(value or "").strip()
    if kind not in EVIDENCE_TYPES:
        raise ValueError("Unsupported identity evidence type.")
    if not value or len(value) > 255:
        raise ValueError("Identity evidence must contain 1 to 255 characters.")
    if kind == "mac":
        compact = re.sub(r"[^0-9A-Fa-f]", "", value).lower()
        if not _MAC.fullmatch(compact):
            raise ValueError("MAC evidence must be a valid 48-bit address.")
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    if kind in {"hostname", "dhcp_client_id", "provider_client_id", "serial_number"}:
        return value.casefold()
    return value


def normalise_hostname_value(value: str | None, *, allow_empty: bool = False) -> str | None:
    """Validate the hostname form Kaya accepts for administrator identity."""
    clean = " ".join(str(value or "").split()).strip().rstrip(".").casefold()
    if not clean:
        if allow_empty:
            return None
        raise ValueError("Hostname is required.")
    if len(clean) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in clean.split(".")):
        raise ValueError("Enter a valid hostname or FQDN using letters, numbers and hyphens.")
    return clean


def mac_identity_lock_key(normalised_mac: str) -> int:
    """Advisory-lock key for one physical MAC, independent of evidence source."""
    digest = hashlib.sha256(f"asset-identity-mac\x1f{normalised_mac}".encode("utf-8")).digest()[:8]
    return int.from_bytes(digest, byteorder="big", signed=True)


def confirmed_mac_owned_elsewhere(db: Session, normalised_mac: str, asset_id: int) -> bool:
    """Whether another asset holds this MAC as confirmed, unrevoked evidence.

    A MAC names one physical interface, so ownership is global: the evidence
    source and scope (DHCP, DNS discovery, manual) do not partition it. One
    asset may still hold many MACs, and suggestions or revoked rows never count.
    """
    return db.query(AssetIdentityEvidence.id).filter(
        AssetIdentityEvidence.evidence_type == "mac",
        AssetIdentityEvidence.normalised_value == normalised_mac,
        AssetIdentityEvidence.status == "confirmed",
        AssetIdentityEvidence.revoked_at.is_(None),
        AssetIdentityEvidence.asset_id.isnot(None),
        AssetIdentityEvidence.asset_id != asset_id,
    ).first() is not None


def managed_static_record_mac(record: IPAddress | None) -> str | None:
    """Normalised MAC of a static (non-Dynamic) managed IP record, else ``None``."""
    if record is None or not record.mac_address or record.assignment_type == "Dynamic":
        return None
    try:
        return _normalise_evidence("mac", record.mac_address)
    except ValueError:
        return None


def _normalise_ip(address: str) -> tuple[str, int]:
    try:
        parsed = ipaddress.ip_address(str(address).strip())
    except ValueError as exc:
        raise ValueError("Network assignment address must be a valid IPv4 or IPv6 address.") from exc
    return parsed.compressed, parsed.version


def _audit_commit(db: Session, user: User, action: str, entity: str, entity_id: int, detail: str) -> None:
    # Identity mutations are security-relevant and must remain auditable even
    # when the configured audit level is reduced to essential events.
    event = write_audit(db, user, action, entity, str(entity_id), detail=detail, force=True, commit=False)
    if event is None:
        db.rollback()
        raise RuntimeError("The identity change could not be audited.")
    db.commit()


def confirm_identity_evidence(
    db: Session,
    user: User,
    *,
    asset_id: int,
    evidence_type: str,
    value: str,
    source: str,
    source_scope: str | None = None,
    observed_at: datetime | None = None,
) -> AssetIdentityEvidence:
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    asset = db.get(HardwareAsset, asset_id)
    if not asset:
        raise ValueError("Hardware asset not found.")
    source = str(source or "").strip()
    if not 1 <= len(source) <= 80:
        raise ValueError("Evidence source must contain 1 to 80 characters.")
    if source_scope is not None:
        source_scope = str(source_scope).strip()
        if not source_scope or len(source_scope) > 255:
            raise ValueError("Evidence source scope must contain 1 to 255 characters.")
    normalised = _normalise_evidence(evidence_type, value)
    evidence_kind = evidence_type.strip().lower()
    if evidence_kind == "mac":
        lock_identity_scope(db, macs=[normalised])
        if confirmed_mac_owned_elsewhere(db, normalised, asset_id):
            raise ValueError("Strong identity evidence is already confirmed for another asset.")
    elif evidence_kind in {"dhcp_client_id", "provider_client_id"}:
        conflicting = db.query(AssetIdentityEvidence).filter(
            AssetIdentityEvidence.evidence_type == evidence_kind,
            AssetIdentityEvidence.normalised_value == normalised,
            AssetIdentityEvidence.source == source,
            AssetIdentityEvidence.source_scope == source_scope,
            AssetIdentityEvidence.status == "confirmed",
            AssetIdentityEvidence.asset_id != asset_id,
        ).first()
        if conflicting:
            raise ValueError("Strong identity evidence is already confirmed for another asset in this source scope.")
    now = observed_at or datetime.utcnow()
    existing = db.query(AssetIdentityEvidence).filter(
        AssetIdentityEvidence.asset_id == asset_id,
        AssetIdentityEvidence.evidence_type == evidence_kind,
        AssetIdentityEvidence.normalised_value == normalised,
        AssetIdentityEvidence.source == source,
        AssetIdentityEvidence.source_scope == source_scope,
        AssetIdentityEvidence.status != "revoked",
    ).first()
    row = existing or AssetIdentityEvidence(
        asset_id=asset_id,
        evidence_type=evidence_kind,
        normalised_value=normalised,
        source=source,
        source_scope=source_scope,
        first_observed_at=now,
    )
    row.last_observed_at = now
    row.status = "confirmed"
    row.confirmed_by = user.id
    row.confirmed_at = now
    row.revoked_at = None
    row.conflict_reason = None
    db.add(row)
    db.flush()
    _audit_commit(db, user, "confirm", "asset_identity_evidence", row.id, "Confirmed asset identity evidence")
    return row


def revoke_identity_evidence(db: Session, user: User, evidence_id: int, *, revoked_at: datetime | None = None) -> AssetIdentityEvidence:
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    row = db.get(AssetIdentityEvidence, evidence_id)
    if not row:
        raise ValueError("Identity evidence not found.")
    row.status = "revoked"
    row.revoked_at = revoked_at or datetime.utcnow()
    db.flush()
    _audit_commit(db, user, "revoke", "asset_identity_evidence", row.id, "Revoked asset identity evidence")
    return row


def confirm_existing_identity_evidence(db: Session, user: User, evidence_id: int, *, confirmed_at: datetime | None = None) -> AssetIdentityEvidence:
    """Confirm an existing suggestion after reloading it inside the mutation transaction."""
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    row = db.get(AssetIdentityEvidence, evidence_id)
    if not row or row.asset_id is None:
        raise ValueError("Identity evidence not found.")
    return confirm_identity_evidence(
        db,
        user,
        asset_id=row.asset_id,
        evidence_type=row.evidence_type,
        value=row.normalised_value,
        source=row.source,
        source_scope=row.source_scope,
        observed_at=confirmed_at or row.last_observed_at or datetime.utcnow(),
    )


def set_administrator_hostname(
    db: Session,
    user: User,
    *,
    asset_id: int,
    hostname: str | None,
    managed_ip_address_id: int | None = None,
    update_managed_hostname: bool = False,
    commit: bool = True,
) -> dict:
    """Set or explicitly clear the administrator-preferred hostname.

    Revoked evidence is never changed. A non-empty correction creates or updates
    only the administrator source row; observations and leases remain history.
    """
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    asset = db.get(HardwareAsset, asset_id)
    if not asset:
        raise ValueError("Hardware asset not found.")
    clean = normalise_hostname_value(hostname, allow_empty=True)
    now = datetime.utcnow()
    current = db.query(AssetIdentityEvidence).filter(
        AssetIdentityEvidence.asset_id == asset_id,
        AssetIdentityEvidence.evidence_type == "hostname",
        AssetIdentityEvidence.source == ADMINISTRATOR_HOSTNAME_SOURCE,
        AssetIdentityEvidence.status == "confirmed",
    ).order_by(AssetIdentityEvidence.id.desc()).first()
    previous = current.normalised_value if current else None
    managed_record = None
    if update_managed_hostname:
        if managed_ip_address_id is None:
            raise ValueError("Select an associated Static IP/VLAN Manager record.")
        managed_record = db.get(IPAddress, managed_ip_address_id)
        if not managed_record or managed_record.assignment_type == "Dynamic":
            raise ValueError("The selected managed record is not a valid Static record.")
        linked = db.query(AssetNetworkAssignment).filter(
            AssetNetworkAssignment.asset_id == asset_id,
            AssetNetworkAssignment.ip_address_id == managed_ip_address_id,
        ).first()
        if linked is None:
            raise ValueError("The managed record is not associated with this asset.")
        macs = {row.normalised_value for row in db.query(AssetIdentityEvidence).filter(
            AssetIdentityEvidence.asset_id == asset_id,
            AssetIdentityEvidence.evidence_type == "mac",
            AssetIdentityEvidence.status == "confirmed",
            AssetIdentityEvidence.revoked_at.is_(None),
        ).all()}
        record_mac = managed_static_record_mac(managed_record)
        if not record_mac or record_mac not in macs:
            raise ValueError("The managed record MAC is not confirmed for this asset.")
    if clean:
        row = db.query(AssetIdentityEvidence).filter(
            AssetIdentityEvidence.asset_id == asset_id,
            AssetIdentityEvidence.evidence_type == "hostname",
            AssetIdentityEvidence.normalised_value == clean,
            AssetIdentityEvidence.source == ADMINISTRATOR_HOSTNAME_SOURCE,
            AssetIdentityEvidence.status != "revoked",
        ).first()
        for previous_row in db.query(AssetIdentityEvidence).filter(
            AssetIdentityEvidence.asset_id == asset_id,
            AssetIdentityEvidence.evidence_type == "hostname",
            AssetIdentityEvidence.source == ADMINISTRATOR_HOSTNAME_SOURCE,
            AssetIdentityEvidence.status == "confirmed",
            AssetIdentityEvidence.normalised_value != clean,
        ).all():
            previous_row.status = "revoked"
            previous_row.revoked_at = now
        if row is None:
            row = AssetIdentityEvidence(
                asset_id=asset_id, evidence_type="hostname", normalised_value=clean,
                source=ADMINISTRATOR_HOSTNAME_SOURCE, first_observed_at=now,
            )
        row.last_observed_at = now
        row.status = "confirmed"
        row.confirmed_by = user.id
        row.confirmed_at = now
        row.revoked_at = None
        row.conflict_reason = None
        db.add(row)
    else:
        for row in db.query(AssetIdentityEvidence).filter(
            AssetIdentityEvidence.asset_id == asset_id,
            AssetIdentityEvidence.evidence_type == "hostname",
            AssetIdentityEvidence.source == ADMINISTRATOR_HOSTNAME_SOURCE,
            AssetIdentityEvidence.status == "confirmed",
        ).all():
            row.status = "revoked"
            row.revoked_at = now
    if managed_record is not None:
        managed_record.name = clean
    db.flush()
    detail = f"Administrator hostname correction: {previous or '(none)'} -> {clean or '(cleared)'}"
    if managed_record is not None:
        detail += f"; updated managed IP record {managed_record.id}"
    event = write_audit(db, user, "set_hostname", "hardware_asset", str(asset_id), detail=detail, force=True, commit=False)
    if event is None:
        db.rollback()
        raise RuntimeError("The hostname change could not be audited.")
    if commit:
        db.commit()
    return {"asset_id": asset_id, "previous_hostname": previous, "hostname": clean, "managed_ip_address_id": managed_record.id if managed_record else None}


def assign_network_identity(
    db: Session,
    user: User,
    *,
    asset_id: int,
    address: str,
    started_at: datetime,
    ended_at: datetime | None = None,
    vlan_id: int | None = None,
    ip_address_id: int | None = None,
    dhcp_lease_id: int | None = None,
    source_id: int | None = None,
    exporter_identity: str | None = None,
    provenance: str,
) -> AssetNetworkAssignment:
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    if not isinstance(started_at, datetime) or (ended_at is not None and ended_at <= started_at):
        raise ValueError("Assignment interval is invalid.")
    if not str(provenance or "").strip() or len(str(provenance)) > 80:
        raise ValueError("Assignment provenance is required and bounded.")
    normalised, family = _normalise_ip(address)
    if not db.get(HardwareAsset, asset_id):
        raise ValueError("Hardware asset not found.")
    vlan = db.get(VLAN, vlan_id) if vlan_id is not None else None
    if vlan_id is not None and not vlan:
        raise ValueError("VLAN not found.")
    ip_record = db.get(IPAddress, ip_address_id) if ip_address_id is not None else None
    if ip_address_id is not None and (not ip_record or ip_record.address != normalised):
        raise ValueError("Managed IP record does not match the assignment address.")
    if ip_record and vlan_id is not None and ip_record.vlan_id != vlan_id:
        raise ValueError("Managed IP record does not belong to the selected VLAN.")
    scoped_exporter = str(exporter_identity).strip()[:255] if exporter_identity else None
    _lock_assignment_context(
        db,
        address=normalised,
        family=family,
        vlan_id=vlan_id,
        source_id=source_id,
        exporter_identity=scoped_exporter,
    )
    query = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.address == normalised,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.vlan_id == vlan_id,
        AssetNetworkAssignment.source_id == source_id,
        AssetNetworkAssignment.exporter_identity == scoped_exporter,
        AssetNetworkAssignment.status == "confirmed",
    )
    candidates = query.all()
    for candidate in candidates:
        overlaps = candidate.ended_at is None or started_at < candidate.ended_at
        if ended_at is not None and candidate.started_at >= ended_at:
            overlaps = False
        if overlaps and candidate.asset_id != asset_id:
            raise ValueError("A conflicting confirmed assignment already exists.")
    row = AssetNetworkAssignment(
        asset_id=asset_id, address=normalised, address_family=family, vlan_id=vlan_id,
        network_cidr=(vlan.subnet_cidr.strip() if vlan and vlan.subnet_cidr else None),
        ip_address_id=ip_address_id, dhcp_lease_id=dhcp_lease_id, source_id=source_id,
        exporter_identity=scoped_exporter,
        started_at=started_at, ended_at=ended_at, provenance=str(provenance).strip(),
        status="confirmed", confirmed_by=user.id, confirmed_at=datetime.utcnow(),
    )
    db.add(row)
    db.flush()
    _audit_commit(db, user, "confirm", "asset_network_assignment", row.id, "Confirmed asset network assignment")
    return row


def close_network_assignment(db: Session, user: User, assignment_id: int, ended_at: datetime) -> AssetNetworkAssignment:
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    row = db.get(AssetNetworkAssignment, assignment_id)
    if not row:
        raise ValueError("Network assignment not found.")
    if ended_at <= row.started_at:
        raise ValueError("Assignment end must be after its start.")
    if row.ended_at is not None and ended_at > row.ended_at:
        raise ValueError("Assignment cannot be extended after it was closed.")
    row.ended_at = ended_at
    db.flush()
    _audit_commit(db, user, "close", "asset_network_assignment", row.id, "Closed asset network assignment")
    return row


def confirm_existing_network_assignment(db: Session, user: User, assignment_id: int, *, confirmed_at: datetime | None = None) -> AssetNetworkAssignment:
    """Approve a pending assignment without creating or relinking any records."""
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    row = db.get(AssetNetworkAssignment, assignment_id)
    if not row or row.asset_id is None:
        raise ValueError("Network assignment not found.")
    if row.status == "confirmed":
        return row
    if row.status in {"revoked", "conflict", "unresolved"}:
        raise ValueError("This network assignment is not eligible for confirmation.")
    if row.vlan_id is not None:
        vlan = db.get(VLAN, row.vlan_id)
        if not vlan or not vlan.subnet_cidr:
            raise ValueError("The VLAN network context is no longer valid.")
        row.network_cidr = vlan.subnet_cidr.strip()
    row.status = "confirmed"
    row.confirmed_by = user.id
    row.confirmed_at = confirmed_at or datetime.utcnow()
    row.conflict_reason = None
    db.flush()
    _audit_commit(db, user, "confirm", "asset_network_assignment", row.id, "Confirmed existing asset network assignment")
    return row


def asset_identity_summary(db: Session, asset_id: int) -> dict[str, list]:
    if not db.get(HardwareAsset, asset_id):
        raise ValueError("Hardware asset not found.")
    return {
        "identities": db.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id == asset_id).order_by(AssetIdentityEvidence.id).all(),
        "assignments": db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.asset_id == asset_id).order_by(AssetNetworkAssignment.started_at).all(),
    }


def _dhcp_lease_identifiers(lease: DHCPLeaseHistory) -> tuple[str | None, set[str]]:
    """Strong identifiers carried by a lease: its MAC and DHCP client identifier.

    The client identifier is the value adoption records as ``dhcp_client_id``
    evidence. The lease's DNS client link is deliberately not used: ingestion
    may derive it from the IP address, and an address is never an identifier.
    """
    mac = None
    if lease.mac_address:
        try:
            mac = _normalise_evidence("mac", lease.mac_address)
        except ValueError:
            mac = None
    client_ids = set()
    if lease.provider_lease_id:
        client_ids.add(str(lease.provider_lease_id).strip().casefold())
    client_ids.discard("")
    return mac, client_ids


def _dhcp_evidence_owner(db: Session, mac: str | None, client_ids: set[str]) -> tuple[int | None, bool]:
    """Return ``(asset_id, conflict)`` from confirmed MAC / DHCP client-id evidence.

    Every matching confirmed identifier must belong to the same single asset; a
    MAC confirmed for one asset and a client id confirmed for another conflict.
    """
    filters = []
    if mac:
        filters.append(and_(AssetIdentityEvidence.evidence_type == "mac", AssetIdentityEvidence.normalised_value == mac))
    if client_ids:
        filters.append(and_(AssetIdentityEvidence.evidence_type == "dhcp_client_id", AssetIdentityEvidence.normalised_value.in_(sorted(client_ids))))
    if not filters:
        return None, False
    rows = db.query(AssetIdentityEvidence.asset_id).filter(
        AssetIdentityEvidence.status == "confirmed",
        AssetIdentityEvidence.revoked_at.is_(None),
        AssetIdentityEvidence.asset_id.isnot(None),
        or_(*filters),
    ).limit(50).all()
    owners = {row[0] for row in rows}
    if len(owners) > 1:
        return None, True
    return (next(iter(owners)) if owners else None), False


def _dhcp_assignment_continuity_owner(db: Session, lease: DHCPLeaseHistory, client_ids: set[str]) -> int | None:
    """Fallback: the single asset whose confirmed assignment came from an earlier
    lease of the same provider with the same MAC or DHCP client identifier."""
    identity_filters = _identity_lease_filters(lease, client_ids)
    if not identity_filters:
        return None
    rows = db.query(AssetNetworkAssignment.asset_id).join(
        DHCPLeaseHistory, DHCPLeaseHistory.id == AssetNetworkAssignment.dhcp_lease_id
    ).filter(
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.dhcp_lease_id != lease.id,
        DHCPLeaseHistory.provider_id == lease.provider_id,
    ).filter(or_(*identity_filters)).limit(20).all()
    owners = {row[0] for row in rows if row[0] is not None}
    return next(iter(owners)) if len(owners) == 1 else None


def _identity_lease_filters(lease: DHCPLeaseHistory, client_ids: set[str]) -> list:
    filters = []
    if lease.mac_address:
        filters.append(DHCPLeaseHistory.mac_address == lease.mac_address)
    if client_ids:
        filters.append(DHCPLeaseHistory.provider_lease_id.in_(sorted(client_ids)))
    return filters


def superseded_dhcp_assignments(db: Session, asset_id: int, *, keep_address: str, family: int, macs: list[str], lease_ids: list[int] | None = None) -> list[AssetNetworkAssignment]:
    """This asset's open assignments for other addresses DHCP leased to the same MAC.

    These stop being current once an explicit managed static assignment for that
    MAC is current. Static, traffic-only and unrelated assignments never match.
    The caller closes them (at the current time, so attributed history stays).
    """
    filters = []
    if macs:
        filters.append(DHCPLeaseHistory.mac_address.in_(sorted(set(macs))))
    if lease_ids:
        filters.append(DHCPLeaseHistory.id.in_(sorted(set(lease_ids))))
    if not filters:
        return []
    dhcp_addresses = set()
    for (address,) in db.query(DHCPLeaseHistory.ip_address).filter(or_(*filters)).limit(5000).all():
        try:
            dhcp_addresses.add(_normalise_ip(address)[0])
        except ValueError:
            continue
    rows = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.asset_id == asset_id,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.address != keep_address,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
    ).order_by(AssetNetworkAssignment.id.asc()).limit(50).all()
    return [row for row in rows if row.address in dhcp_addresses]


def _managed_static_record_for(db: Session, normalised: str, normalised_mac: str, ip_address_id: int | None) -> IPAddress:
    records = db.query(IPAddress).filter(IPAddress.address == normalised).order_by(IPAddress.id.asc()).limit(20).all()
    records = [row for row in records if managed_static_record_mac(row) == normalised_mac and (ip_address_id is None or row.id == ip_address_id)]
    if len(records) != 1:
        raise ValueError("Exactly one Static IP/VLAN Manager record for this address must carry this MAC.")
    return records[0]


def _managed_static_owner_checks(db: Session, asset: HardwareAsset, normalised_mac: str) -> None:
    owns_mac = db.query(AssetIdentityEvidence.id).filter(
        AssetIdentityEvidence.asset_id == asset.id,
        AssetIdentityEvidence.evidence_type == "mac",
        AssetIdentityEvidence.normalised_value == normalised_mac,
        AssetIdentityEvidence.status == "confirmed",
        AssetIdentityEvidence.revoked_at.is_(None),
    ).first()
    if owns_mac is None:
        raise ValueError("The asset does not hold this MAC as confirmed identity evidence.")
    if confirmed_mac_owned_elsewhere(db, normalised_mac, asset.id):
        raise ValueError("This MAC is also confirmed for another asset; resolve that conflict first.")


def _managed_static_state(
    db: Session, asset: HardwareAsset, normalised_mac: str, record: IPAddress, normalised: str, family: int, now: datetime
) -> tuple[dict, AssetNetworkAssignment | None, list[AssetNetworkAssignment]]:
    held_elsewhere = db.query(AssetNetworkAssignment.id, AssetNetworkAssignment.asset_id).filter(
        AssetNetworkAssignment.address == normalised,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
        AssetNetworkAssignment.asset_id != asset.id,
    ).first()
    if held_elsewhere is not None:
        raise ValueError("The managed static address is currently assigned to another asset.")
    current = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.asset_id == asset.id,
        AssetNetworkAssignment.address == normalised,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
    ).first()
    superseded = superseded_dhcp_assignments(db, asset.id, keep_address=normalised, family=family, macs=[normalised_mac])
    plan = {
        "asset_id": asset.id,
        "asset_tag": asset.asset_tag,
        "mac": normalised_mac,
        "ip_address_id": record.id,
        "address": normalised,
        "vlan_id": record.vlan_id,
        "existing_assignment_id": current.id if current else None,
        "create_assignment": current is None,
        "close_assignments": [
            {"assignment_id": row.id, "address": row.address, "started_at": row.started_at.isoformat(), "provenance": row.provenance}
            for row in superseded
        ],
        "repair_time": now.isoformat(),
        "executed": False,
    }
    plan["changes_required"] = bool(plan["create_assignment"] or superseded)
    return plan, current, superseded


def plan_managed_static_assignment(
    db: Session, *, asset: HardwareAsset, mac: str, address: str, ip_address_id: int | None = None, now: datetime | None = None
) -> dict:
    """The managed static repair plan without locks or changes (for audits and previews).

    Applies exactly the validation of ``repair_managed_static_assignment`` and
    raises ``ValueError`` where it would refuse. Execution always re-plans
    under locks, so this result never authorises a change by itself.
    """
    normalised_mac = _normalise_evidence("mac", mac)
    normalised, family = _normalise_ip(address)
    _managed_static_owner_checks(db, asset, normalised_mac)
    record = _managed_static_record_for(db, normalised, normalised_mac, ip_address_id)
    return _managed_static_state(db, asset, normalised_mac, record, normalised, family, now or datetime.utcnow())[0]


def repair_managed_static_assignment(
    db: Session,
    *,
    asset_id: int,
    asset_tag: str,
    mac: str,
    address: str,
    ip_address_id: int | None = None,
    actor: User | None = None,
    execute: bool = False,
    now: datetime | None = None,
    audit_context: dict | None = None,
    on_plan=None,
    before_commit=None,
) -> dict:
    """Idempotently make a managed static record the asset's current address.

    For assets adopted before managed static precedence existed. Every target is
    verified before any change: the asset by id and tag, its confirmed MAC, a
    single Static IP/VLAN Manager record for that address carrying the MAC, and
    no other asset holding the address. It then creates the missing managed
    static assignment and closes superseded DHCP-derived assignments at repair
    time. DHCP history, identity evidence and traffic rows are never modified.
    A dry run (the default) reports the plan and rolls back; ``execute`` commits
    the change with one forced audit record, or nothing at all.

    ``on_plan(plan)`` runs under the locks before any change and may raise to
    refuse (for example a stale preview); ``before_commit(plan)`` runs in the
    same transaction after the audit record. ``audit_context`` adds bounded
    caller identifiers to the audit metadata.
    """
    if actor is not None and (actor.role != "admin" or not actor.is_active):
        raise PermissionError("An active administrator is required to attribute the repair.")
    normalised_mac = _normalise_evidence("mac", mac)
    normalised, family = _normalise_ip(address)
    clean_tag = str(asset_tag or "").strip()
    if not clean_tag or len(clean_tag) > 120:
        raise ValueError("The asset tag must contain 1 to 120 characters.")
    now = now or datetime.utcnow()
    try:
        lock_identity_scope(db, macs=[normalised_mac], asset_ids=[asset_id])
        asset = db.get(HardwareAsset, asset_id)
        if not asset or (asset.asset_tag or "").strip() != clean_tag:
            raise ValueError("The asset id and asset tag do not identify the same asset.")
        _managed_static_owner_checks(db, asset, normalised_mac)
        record = _managed_static_record_for(db, normalised, normalised_mac, ip_address_id)
        # Also the DHCP reconciliation key, so the two exclude each other here.
        lock_identity_scope(db, assignment_keys=[
            _assignment_lock_key(normalised, family, record.vlan_id, None, None),
            dhcp_address_lock_key(normalised, family),
        ])
        plan, current, superseded = _managed_static_state(db, asset, normalised_mac, record, normalised, family, now)
        if on_plan is not None:
            on_plan(plan)
        if not execute or not plan["changes_required"]:
            db.rollback()
            return plan
        created = None
        if current is None:
            created = AssetNetworkAssignment(
                asset_id=asset.id, address=normalised, address_family=family,
                vlan_id=record.vlan_id, network_cidr=record.vlan.subnet_cidr.strip() if record.vlan and record.vlan.subnet_cidr else None,
                ip_address_id=record.id, started_at=now, provenance=MANAGED_STATIC_REPAIR_PROVENANCE,
                status="confirmed", confirmed_by=actor.id if actor else None, confirmed_at=now,
            )
            db.add(created)
        for row in superseded:
            row.ended_at = max(row.started_at, now)
        db.flush()
        context = {key: value for key, value in (audit_context or {}).items() if isinstance(value, (int, str)) and len(str(value)) <= 80}
        audit = write_audit(
            db, actor, "repair", "asset_network_assignment", str(created.id if created else current.id),
            detail="Repaired managed static network assignment",
            metadata={
                **context,
                "asset_id": asset.id,
                "ip_address_id": record.id,
                "created_assignment_id": created.id if created else None,
                "closed_assignment_ids": [row.id for row in superseded],
                "address_family": family,
            },
            force=True, commit=False,
        )
        if audit is None:
            raise RuntimeError("The repair could not be audited.")
        plan["executed"] = True
        plan["created_assignment_id"] = created.id if created else None
        if before_commit is not None:
            before_commit(plan)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return plan


def _managed_static_outranks_lease(db: Session, asset_id: int, lease: DHCPLeaseHistory, mac: str | None, family: int) -> bool:
    """Whether a newer managed static assignment for this MAC outranks the lease.

    The asset must hold an open confirmed assignment whose managed IP record is
    still Static and still carries the lease's MAC, started after this lease was
    first seen. A lease first seen later (the device genuinely back on DHCP), or
    a record since made Dynamic, removed or re-MACed, reconciles as before.
    """
    if not mac:
        return False
    lease_seen = lease.first_seen_at or lease.lease_started_at
    rows = db.query(AssetNetworkAssignment, IPAddress).join(
        IPAddress, IPAddress.id == AssetNetworkAssignment.ip_address_id
    ).filter(
        AssetNetworkAssignment.asset_id == asset_id,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
    ).limit(50).all()
    return any(
        record.address == assignment.address
        and managed_static_record_mac(record) == mac
        and (lease_seen is None or assignment.started_at >= lease_seen)
        for assignment, record in rows
    )


def _asset_dhcp_lock_key(asset_id: int) -> int:
    digest = hashlib.sha256(f"asset-dhcp-reconciliation\x1f{asset_id}".encode("utf-8")).digest()[:8]
    return int.from_bytes(digest, byteorder="big", signed=True)


def _lock_asset_dhcp(db: Session, asset_id: int) -> None:
    """Serialise DHCP reconciliation per asset on PostgreSQL."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": _asset_dhcp_lock_key(asset_id)})


def dhcp_address_lock_key(address: str, family: int) -> int:
    """The VLAN-independent address key DHCP reconciliation serialises on."""
    return _assignment_lock_key(address, family, None, None, None)


def lock_identity_scope(
    db: Session,
    *,
    macs: Iterable[str] = (),
    asset_ids: Iterable[int] = (),
    assignment_keys: Iterable[int] = (),
) -> None:
    """Take identity locks in the one global order: MAC, then asset, then address.

    Adoption, DHCP reconciliation, evidence confirmation and the managed static
    repair all acquire these tiers in this order, each tier sorted, so no two
    of them wait on each other in opposite orders. A caller may skip tiers or
    call again for a later tier, but never for an earlier one. Advisory locks
    are transaction-scoped and re-entrant; this is a no-op on SQLite.
    """
    if db.get_bind().dialect.name != "postgresql":
        return
    tiers = (
        sorted({mac_identity_lock_key(mac) for mac in macs}),
        sorted({_asset_dhcp_lock_key(asset_id) for asset_id in asset_ids}),
        sorted(set(assignment_keys)),
    )
    for keys in tiers:
        for key in keys:
            db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": key})


def close_ended_dhcp_assignments(
    db: Session,
    *,
    provider_id: int,
    observed_at: datetime,
    lease_ids: list[int] | None = None,
    expired_only: bool = False,
) -> int:
    """Close open confirmed assignments whose DHCP lease no longer supports them.

    Only assignments linked to a lease of this provider are considered, so
    static and manually entered assignments are never closed here. A lease no
    longer supports its assignment once a successful collection has ended it
    (absent from the snapshot, or the address observed with another identity).
    During a provider outage (``expired_only``) only a provider-reported expiry
    that has passed counts; an expiry not after the lease start (for example an
    infinite lease reported as 0) is not evidence. The assignment ends at the
    lease's last observation, the last supported evidence of ownership, so the
    uncertain interval is never attributed. Identity evidence is untouched.
    """
    if not module_is_enabled(db, MODULE_BY_KEY["asset_manager"]):
        return 0
    lease_state = (
        and_(
            DHCPLeaseHistory.is_active.is_(True),
            DHCPLeaseHistory.expires_at.isnot(None),
            DHCPLeaseHistory.expires_at > DHCPLeaseHistory.lease_started_at,
            DHCPLeaseHistory.expires_at <= observed_at,
        )
        if expired_only
        else DHCPLeaseHistory.is_active.is_(False)
    )
    query = db.query(AssetNetworkAssignment, DHCPLeaseHistory).join(
        DHCPLeaseHistory, DHCPLeaseHistory.id == AssetNetworkAssignment.dhcp_lease_id
    ).filter(
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
        DHCPLeaseHistory.provider_id == provider_id,
        lease_state,
    )
    if lease_ids is not None:
        if not lease_ids:
            return 0
        query = query.filter(DHCPLeaseHistory.id.in_(lease_ids))
    candidates = query.order_by(AssetNetworkAssignment.asset_id, AssetNetworkAssignment.id).limit(500).all()
    closed = 0
    postgresql = db.get_bind().dialect.name == "postgresql"
    for row, lease in candidates:
        _lock_asset_dhcp(db, row.asset_id)
        if postgresql:
            # Another collection may have closed it while this one waited.
            db.refresh(row)
        if row.ended_at is not None or row.status != "confirmed":
            continue
        last_seen = lease.last_seen_at or lease.first_seen_at or row.started_at
        row.ended_at = max(row.started_at, min(last_seen, observed_at))
        db.flush()
        audit = write_audit(
            db, None, "update", "asset_network_assignment", str(row.id),
            detail="Closed DHCP network assignment after its lease ended",
            metadata={"asset_id": row.asset_id, "lease_id": lease.id, "reason": "lease_expired" if expired_only else "lease_ended", "address_family": row.address_family},
            force=True, commit=False,
        )
        if audit is None:
            raise RuntimeError("The DHCP assignment closure could not be audited.")
        closed += 1
    return closed


def dhcp_identity_conflict(db: Session, lease: DHCPLeaseHistory) -> bool:
    """Whether the lease's confirmed MAC and DHCP client identifiers name different assets."""
    mac, client_ids = _dhcp_lease_identifiers(lease)
    return _dhcp_evidence_owner(db, mac, client_ids)[1]


def reconcile_dhcp_assignment(db: Session, lease: DHCPLeaseHistory, *, observed_at: datetime) -> str:
    """Carry a confirmed asset's network assignment across a DHCP address change.

    Runs from DHCP lease ingestion. The asset is identified only by confirmed
    strong evidence: a confirmed MAC or DHCP client identifier resolving to
    exactly one asset, or (as before) a confirmed assignment made from an earlier
    lease of the same identity. Hostnames, IP addresses, VLANs and exporters
    never identify an asset, and no asset or managed IP is ever created. The
    replacement assignment is source-less, so no exporter scope is invented.

    Returns ``renewed`` (already current), ``reassigned`` (new assignment
    created, earlier DHCP addresses of the same identity closed), ``superseded``
    (a newer active lease of the same identity, or a newer managed static
    assignment for the same MAC, exists), or ``review_required``
    (no single safe owner, conflicting identifiers, or address held elsewhere).
    """
    if not lease or not isinstance(observed_at, datetime):
        return "review_required"
    if not module_is_enabled(db, MODULE_BY_KEY["asset_manager"]):
        return "review_required"
    try:
        normalised, family = _normalise_ip(lease.ip_address)
    except ValueError:
        return "review_required"
    mac, client_ids = _dhcp_lease_identifiers(lease)
    asset_id, conflict = _dhcp_evidence_owner(db, mac, client_ids)
    if conflict:
        return "review_required"
    basis = "confirmed_identity_evidence"
    if asset_id is None:
        asset_id = _dhcp_assignment_continuity_owner(db, lease, client_ids)
        basis = "confirmed_dhcp_assignment"
        if asset_id is None:
            return "review_required"
    # Routine renewal: the asset already holds this address. A read-only early
    # return, so it needs no lock; any change below is re-checked under locks.
    current = db.query(AssetNetworkAssignment.id).filter(
        AssetNetworkAssignment.asset_id == asset_id,
        AssetNetworkAssignment.address == normalised,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
    ).first()
    if current is not None:
        return "renewed"
    identity_filters = _identity_lease_filters(lease, client_ids)
    # Act only on the newest active lease of this identity, so an older lease
    # that has not yet expired never pulls the asset back to its old address.
    if identity_filters and lease.lease_started_at is not None:
        newer = db.query(DHCPLeaseHistory.id).filter(
            DHCPLeaseHistory.id != lease.id,
            DHCPLeaseHistory.is_active.is_(True),
            or_(*identity_filters),
            or_(
                DHCPLeaseHistory.lease_started_at > lease.lease_started_at,
                and_(DHCPLeaseHistory.lease_started_at == lease.lease_started_at, DHCPLeaseHistory.id > lease.id),
            ),
        ).first()
        if newer is not None:
            return "superseded"
    # Explicit managed static intent for this MAC is newer than this lease, so
    # an older lease that has not yet expired never pulls the asset back.
    if _managed_static_outranks_lease(db, asset_id, lease, mac, family):
        return "superseded"
    lock_identity_scope(db, asset_ids=[asset_id], assignment_keys=[dhcp_address_lock_key(normalised, family)])
    open_rows = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.asset_id == asset_id,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
    ).limit(50).all()
    if any(row.address == normalised for row in open_rows):
        return "renewed"
    held_elsewhere = db.query(AssetNetworkAssignment.id).filter(
        AssetNetworkAssignment.address == normalised,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
        AssetNetworkAssignment.asset_id != asset_id,
    ).first()
    if held_elsewhere is not None:
        return "review_required"
    # Close only open assignments for addresses DHCP previously leased to this
    # same identity; static or unrelated assignments are left untouched. The
    # earlier lease's last observation is the last supported evidence that the
    # identity held that address: ownership after it is uncertain, so the old
    # interval ends there (fail closed), never after this lease was first seen.
    last_seen_by_address: dict[str, datetime | None] = {}
    if identity_filters:
        for address, last_seen_at in db.query(DHCPLeaseHistory.ip_address, DHCPLeaseHistory.last_seen_at).filter(
            DHCPLeaseHistory.id != lease.id, or_(*identity_filters)
        ).limit(500).all():
            try:
                key = _normalise_ip(address)[0]
            except ValueError:
                continue
            previous = last_seen_by_address.get(key)
            last_seen_by_address[key] = last_seen_at if previous is None else max(previous, last_seen_at or previous)
    superseded_rows = [row for row in open_rows if row.address in last_seen_by_address]
    started_at = min(observed_at, lease.first_seen_at or observed_at)
    if superseded_rows:
        started_at = max(started_at, max(row.started_at for row in superseded_rows))
    # Never backfill over a closed interval of this address. A lease whose own
    # assignment was closed (for example on confirmed expiry during a provider
    # outage) is followed again only from this observation.
    prior = db.query(AssetNetworkAssignment.ended_at, AssetNetworkAssignment.dhcp_lease_id).filter(
        AssetNetworkAssignment.asset_id == asset_id,
        AssetNetworkAssignment.address == normalised,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.isnot(None),
    ).order_by(AssetNetworkAssignment.ended_at.desc()).limit(20).all()
    if any(lease_id == lease.id for _ended, lease_id in prior):
        started_at = max(started_at, observed_at)
    elif prior:
        started_at = max(started_at, prior[0][0])
    vlan = None
    parsed = ipaddress.ip_address(normalised)
    for candidate in [*(row.vlan for row in superseded_rows), lease.dhcp_range.vlan if lease.dhcp_range else None]:
        if not candidate or not candidate.subnet_cidr:
            continue
        try:
            if parsed in ipaddress.ip_network(candidate.subnet_cidr.strip(), strict=False):
                vlan = candidate
                break
        except ValueError:
            continue
    for row in superseded_rows:
        last_seen = last_seen_by_address[row.address]
        row.ended_at = started_at if last_seen is None else max(row.started_at, min(started_at, last_seen))
    replacement = AssetNetworkAssignment(
        asset_id=asset_id,
        address=normalised,
        address_family=family,
        vlan_id=vlan.id if vlan else None,
        network_cidr=vlan.subnet_cidr.strip() if vlan else None,
        dhcp_lease_id=lease.id,
        started_at=started_at,
        provenance="dhcp_reconciliation",
        status="confirmed",
        confirmed_by=None,
        confirmed_at=observed_at,
    )
    db.add(replacement)
    db.flush()
    audit = write_audit(
        db, None, "update", "asset_network_assignment", str(replacement.id),
        detail="Reconciled confirmed DHCP network assignment",
        metadata={
            "asset_id": asset_id,
            "previous_assignment_ids": [row.id for row in superseded_rows],
            "lease_id": lease.id,
            "basis": basis,
            "address_family": family,
        },
        force=True, commit=False,
    )
    if audit is None:
        raise RuntimeError("The DHCP assignment reconciliation could not be audited.")
    return "reassigned"
