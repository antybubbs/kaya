"""Administrator-reviewed stable asset identity and network assignment operations."""

from datetime import datetime
import hashlib
import ipaddress
import re

from sqlalchemy import or_, text
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


EVIDENCE_TYPES = {"mac", "dhcp_client_id", "provider_client_id", "hostname", "serial_number"}
STATUSES = {"pending", "confirmed", "revoked", "conflict", "unresolved"}
_MAC = re.compile(r"^[0-9a-f]{12}$")


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
        compact = re.sub(r"[^0-9A-Fa-f]", "", value)
        if not _MAC.fullmatch(compact):
            raise ValueError("MAC evidence must be a valid 48-bit address.")
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2)).lower()
    if kind in {"hostname", "dhcp_client_id", "provider_client_id", "serial_number"}:
        return value.casefold()
    return value


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
    if evidence_kind in {"mac", "dhcp_client_id", "provider_client_id"}:
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


def reconcile_dhcp_assignment(db: Session, lease: DHCPLeaseHistory, *, observed_at: datetime) -> str:
    """Safely carry a confirmed asset assignment across a DHCP address change.

    This is intentionally conservative: a current lease must share a confirmed
    MAC or DHCP client identifier with exactly one prior assignment.  A hostname
    or reused address is never sufficient.  The replacement assignment is
    source-less until an administrator confirms the applicable traffic source.
    """
    if not lease or not isinstance(observed_at, datetime) or not (lease.mac_address or lease.dns_client_id):
        return "review_required"
    identity_filters = []
    if lease.mac_address:
        identity_filters.append(DHCPLeaseHistory.mac_address == lease.mac_address)
    if lease.dns_client_id:
        identity_filters.append(DHCPLeaseHistory.dns_client_id == lease.dns_client_id)
    candidates = db.query(AssetNetworkAssignment).join(
        DHCPLeaseHistory, DHCPLeaseHistory.id == AssetNetworkAssignment.dhcp_lease_id
    ).filter(
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.dhcp_lease_id != lease.id,
        DHCPLeaseHistory.provider_id == lease.provider_id,
    ).filter(or_(*identity_filters)).order_by(AssetNetworkAssignment.started_at.desc()).limit(20).all()
    asset_ids = {row.asset_id for row in candidates if row.asset_id is not None}
    if len(asset_ids) != 1:
        return "review_required"
    current = next((row for row in candidates if row.ended_at is None), None)
    if current is None:
        return "review_required"
    try:
        normalised, family = _normalise_ip(lease.ip_address)
    except ValueError:
        return "review_required"
    if current.address == normalised and current.address_family == family:
        return "renewed"
    _lock_assignment_context(
        db,
        address=normalised,
        family=family,
        vlan_id=current.vlan_id,
        source_id=None,
        exporter_identity=None,
    )
    conflict = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.address == normalised,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
        AssetNetworkAssignment.asset_id != current.asset_id,
    ).first()
    if conflict:
        return "review_required"
    current.ended_at = observed_at
    vlan = current.vlan
    replacement = AssetNetworkAssignment(
        asset_id=current.asset_id,
        address=normalised,
        address_family=family,
        vlan_id=current.vlan_id,
        network_cidr=vlan.subnet_cidr.strip() if vlan and vlan.subnet_cidr else current.network_cidr,
        dhcp_lease_id=lease.id,
        started_at=observed_at,
        provenance="dhcp_reconciliation",
        status="confirmed",
        confirmed_by=current.confirmed_by,
        confirmed_at=observed_at,
    )
    db.add(replacement)
    db.flush()
    audit = write_audit(
        db, None, "update", "asset_network_assignment", str(replacement.id),
        detail="Reconciled confirmed DHCP network assignment",
        metadata={"previous_assignment_id": current.id, "lease_id": lease.id, "address_family": family},
        force=True, commit=False,
    )
    if audit is None:
        raise RuntimeError("The DHCP assignment reconciliation could not be audited.")
    return "reassigned"
