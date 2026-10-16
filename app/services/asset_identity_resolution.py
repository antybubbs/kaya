"""Read-only, bounded correlation of network evidence to hardware assets.

This module deliberately performs no writes. Callers remain responsible for
module permissions and may use the results to present an administrator review
workflow in a later phase.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import ipaddress
import re
from typing import Iterable

from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSClientObservation,
    DNSRecognisedDevice,
    HardwareAsset,
    TrafficDiscoveryObservation,
)
from app.services.network_discovery_matching import match_endpoint
from app.services.network_discovery_mapping import mapped_network_contexts


MAX_CANDIDATES = 100
MATCH_STATES = {"confirmed_match", "suggested_match", "ambiguous", "unresolved", "stale"}
ORIGINAL_ENDPOINT_ROLES = {"original", "initiator", "responder"}
_MAC = re.compile(r"^[0-9a-f]{12}$")


@dataclass(frozen=True)
class EvidenceCandidate:
    asset_id: int | None
    match_state: str
    evidence_source: str
    evidence_type: str
    normalised_reference: str | None
    source_scope: str | None
    vlan_id: int | None
    exporter_identity: str | None
    interval_start: datetime | None
    interval_end: datetime | None
    reason: str
    review_required: bool


@dataclass(frozen=True)
class ResolutionResult:
    state: str
    candidates: tuple[EvidenceCandidate, ...]
    reasons: tuple[str, ...]


def _limit(value: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Candidate limit must be an integer.") from exc
    if not 1 <= value <= MAX_CANDIDATES:
        raise ValueError(f"Candidate limit must be between 1 and {MAX_CANDIDATES}.")
    return value


def _ip(value: str) -> tuple[str, int]:
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError("Observed address must be a valid IPv4 or IPv6 address.") from exc
    return parsed.compressed, parsed.version


def _mac(value: str | None) -> str | None:
    if not value:
        return None
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2)).lower() if _MAC.fullmatch(compact) else None


def _contains(start: datetime | None, end: datetime | None, observed_at: datetime) -> bool:
    return start is not None and start <= observed_at and (end is None or observed_at < end)


def _same_context(row: AssetNetworkAssignment, *, vlan_id: int | None, source_id: int | None, exporter_identity: str | None) -> bool:
    if vlan_id is not None and row.vlan_id != vlan_id:
        return False
    if source_id is not None and row.source_id != source_id:
        return False
    if exporter_identity is not None and row.exporter_identity != exporter_identity:
        return False
    return True


def _candidate(
    *, asset_id: int | None, state: str, source: str, kind: str, reference: str | None,
    scope: str | None, vlan_id: int | None, exporter: str | None,
    start: datetime | None, end: datetime | None, reason: str,
) -> EvidenceCandidate:
    if state not in MATCH_STATES:
        raise ValueError("Invalid resolver match state.")
    return EvidenceCandidate(
        asset_id=asset_id, match_state=state, evidence_source=source,
        evidence_type=kind, normalised_reference=reference, source_scope=scope,
        vlan_id=vlan_id, exporter_identity=exporter, interval_start=start,
        interval_end=end, reason=reason, review_required=state != "confirmed_match",
    )


def _finish(candidates: Iterable[EvidenceCandidate], reasons: Iterable[str], limit: int) -> ResolutionResult:
    rows = list(candidates)[:limit]
    asset_ids = {row.asset_id for row in rows if row.asset_id is not None}
    if len(asset_ids) > 1:
        rows = [EvidenceCandidate(**{**row.__dict__, "match_state": "ambiguous", "review_required": True}) for row in rows]
        state = "ambiguous"
    elif not rows:
        state = "unresolved"
    elif any(row.match_state == "confirmed_match" for row in rows):
        state = "confirmed_match"
    elif any(row.match_state == "stale" for row in rows):
        state = "stale"
    else:
        state = "suggested_match"
    return ResolutionResult(state=state, candidates=tuple(rows), reasons=tuple(dict.fromkeys(reasons)))


def _evidence_candidates(
    db: Session,
    *,
    observed_at: datetime,
    mac_address: str | None,
    dhcp_client_id: str | None,
    provider_client_id: str | None,
    hostname: str | None,
    source_scope: str | None,
    limit: int,
) -> list[EvidenceCandidate]:
    values = {
        "mac": _mac(mac_address),
        "dhcp_client_id": str(dhcp_client_id).strip().casefold() if dhcp_client_id else None,
        "provider_client_id": str(provider_client_id).strip().casefold() if provider_client_id else None,
        "hostname": str(hostname).strip().casefold() if hostname else None,
    }
    clauses = [
        (kind, value) for kind, value in values.items() if value and len(value) <= 255
    ]
    if not clauses:
        return []
    conditions = [
        (AssetIdentityEvidence.evidence_type == kind)
        & (AssetIdentityEvidence.normalised_value == value)
        for kind, value in clauses
    ]
    query = db.query(AssetIdentityEvidence).filter(
        or_(*conditions), AssetIdentityEvidence.status == "confirmed",
    )
    if source_scope:
        query = query.filter(or_(AssetIdentityEvidence.source_scope == source_scope, AssetIdentityEvidence.source_scope.is_(None)))
    rows = query.order_by(AssetIdentityEvidence.id.asc()).limit(limit).all()
    result = []
    for row in rows:
        if row.asset_id is None:
            continue
        result.append(_candidate(
            asset_id=row.asset_id, state="confirmed_match", source=row.source,
            kind=row.evidence_type, reference=row.normalised_value,
            scope=row.source_scope, vlan_id=None, exporter=None,
            start=row.first_observed_at, end=row.last_observed_at,
            reason="confirmed identity evidence matches the supplied observation; administrator review is required",
        ))
    return result


def _assignment_candidates(
    db: Session,
    *,
    address: str,
    family: int,
    observed_at: datetime,
    vlan_id: int | None,
    source_id: int | None,
    exporter_identity: str | None,
    limit: int,
) -> list[EvidenceCandidate]:
    rows = db.query(AssetNetworkAssignment).options(joinedload(AssetNetworkAssignment.vlan)).filter(
        AssetNetworkAssignment.address == address,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.asset_id.isnot(None),
    ).order_by(AssetNetworkAssignment.started_at.desc()).limit(limit).all()
    result = []
    for row in rows:
        if not _same_context(row, vlan_id=vlan_id, source_id=source_id, exporter_identity=exporter_identity):
            continue
        if not _contains(row.started_at, row.ended_at, observed_at):
            continue
        if row.vlan_id is not None:
            current_cidr = row.vlan.subnet_cidr if row.vlan else None
            if not row.network_cidr or not current_cidr or row.network_cidr.strip() != current_cidr.strip():
                continue
        result.append(_candidate(
            asset_id=row.asset_id, state="confirmed_match", source=row.provenance,
            kind="network_assignment", reference=row.address, scope=None,
            vlan_id=row.vlan_id, exporter=row.exporter_identity,
            start=row.started_at, end=row.ended_at,
            reason="administrator-confirmed network assignment matches address, time and context",
        ))
    return result


def _dhcp_candidates(db: Session, *, address: str, observed_at: datetime, limit: int) -> list[EvidenceCandidate]:
    leases = db.query(DHCPLeaseHistory).options(joinedload(DHCPLeaseHistory.dhcp_range)).filter(
        DHCPLeaseHistory.ip_address == address,
        DHCPLeaseHistory.lease_started_at <= observed_at,
    ).order_by(DHCPLeaseHistory.last_seen_at.desc()).limit(limit).all()
    result = []
    for lease in leases:
        end = lease.ended_at or lease.expires_at
        if end is not None and observed_at >= end:
            continue
        client = db.get(DNSRecognisedDevice, lease.dns_client_id) if lease.dns_client_id else None
        asset_id = client.hardware_asset_id if client else None
        if asset_id is None:
            continue
        result.append(_candidate(
            asset_id=asset_id, state="confirmed_match" if client and client.is_known else "suggested_match",
            source="dhcp", kind="dhcp_lease", reference=_mac(lease.mac_address) or lease.provider_lease_id,
            scope=lease.source, vlan_id=lease.dhcp_range.vlan_id if lease.dhcp_range else None,
            exporter=None, start=lease.lease_started_at, end=end,
            reason="time-valid DHCP lease is associated with an existing DNS-recognised asset" if client and client.is_known else "DHCP lease provides a reviewable asset hint",
        ))
    return result


def _dns_candidates(db: Session, *, address: str, observed_at: datetime, limit: int) -> list[EvidenceCandidate]:
    rows = db.query(DNSClientObservation, DNSRecognisedDevice).join(
        DNSRecognisedDevice, DNSRecognisedDevice.id == DNSClientObservation.dns_client_id,
    ).filter(
        DNSClientObservation.ip_address == address,
        DNSClientObservation.observed_at <= observed_at,
    ).order_by(DNSClientObservation.observed_at.desc()).limit(limit).all()
    result = []
    for observation, client in rows:
        if client.hardware_asset_id is None:
            continue
        result.append(_candidate(
            asset_id=client.hardware_asset_id,
            state="confirmed_match" if client.is_known else "suggested_match",
            source="dns", kind="dns_client", reference=client.provider_client_id or client.normalised_mac or client.normalised_hostname,
            scope=client.logical_provider_key, vlan_id=None, exporter=None,
            start=observation.observed_at, end=None,
            reason="DNS-recognised client is linked to an existing asset in the observed time context" if client.is_known else "DNS client link is a reviewable hint",
        ))
    return result


def resolve_observed_ip(
    db: Session,
    address: str,
    observed_at: datetime,
    *,
    vlan_id: int | None = None,
    source_id: int | None = None,
    exporter_identity: str | None = None,
    endpoint_role: str | None = None,
    mac_address: str | None = None,
    dhcp_client_id: str | None = None,
    provider_client_id: str | None = None,
    hostname: str | None = None,
    source_scope: str | None = None,
    limit: int = 25,
) -> ResolutionResult:
    """Resolve an observed address without mutating any module's tables."""
    if not isinstance(observed_at, datetime):
        raise ValueError("Observation time is required.")
    limit = _limit(limit)
    address, family = _ip(address)
    if endpoint_role and endpoint_role not in ORIGINAL_ENDPOINT_ROLES:
        return _finish([], ["translated_or_unsupported_endpoint_role_is_review_only"], limit)
    if source_id is not None and not exporter_identity:
        return _finish([], ["source_scoped_observations_require_exporter_identity"], limit)
    candidates = _assignment_candidates(
        db, address=address, family=family, observed_at=observed_at,
        vlan_id=vlan_id, source_id=source_id, exporter_identity=exporter_identity,
        limit=limit,
    )
    candidates.extend(_evidence_candidates(
        db, observed_at=observed_at, mac_address=mac_address,
        dhcp_client_id=dhcp_client_id, provider_client_id=provider_client_id,
        hostname=hostname, source_scope=source_scope or exporter_identity, limit=limit,
    ))
    candidates.extend(_dhcp_candidates(db, address=address, observed_at=observed_at, limit=limit))
    candidates.extend(_dns_candidates(db, address=address, observed_at=observed_at, limit=limit))
    reasons = []
    if not candidates:
        reasons.append("no time-valid confirmed or reviewable evidence matched")
    return _finish(candidates, reasons, limit)


def resolve_dhcp_lease(db: Session, lease_id: int, *, observed_at: datetime | None = None, limit: int = 25) -> ResolutionResult:
    lease = db.get(DHCPLeaseHistory, lease_id)
    if lease is None:
        raise ValueError("DHCP lease not found.")
    return resolve_observed_ip(
        db, lease.ip_address, observed_at or lease.last_seen_at,
        vlan_id=lease.dhcp_range.vlan_id if lease.dhcp_range else None,
        mac_address=lease.mac_address,
        hostname=lease.hostname,
        limit=limit,
    )


def resolve_dns_client(db: Session, client_id: int, *, observed_at: datetime | None = None, limit: int = 25) -> ResolutionResult:
    client = db.get(DNSRecognisedDevice, client_id)
    if client is None:
        raise ValueError("DNS client not found.")
    observed = observed_at or client.last_seen_at
    if not client.current_ip:
        return _finish([], ["DNS client has no current IP address"], _limit(limit))
    return resolve_observed_ip(
        db, client.current_ip, observed,
        mac_address=client.normalised_mac or client.mac_address,
        provider_client_id=client.provider_client_id,
        hostname=client.normalised_hostname or client.hostname,
        source_scope=client.logical_provider_key,
        limit=limit,
    )


def resolve_discovery_observation(db: Session, observation_id: int, *, limit: int = 25) -> ResolutionResult:
    observation = db.get(TrafficDiscoveryObservation, observation_id)
    if observation is None:
        raise ValueError("Discovery observation not found.")
    if observation.endpoint_role not in ORIGINAL_ENDPOINT_ROLES:
        return _finish([], ["translated_or_unsupported_endpoint_role_is_review_only"], _limit(limit))
    match = match_endpoint(
        db, observation.source_id, observation.exporter_identity,
        observation.endpoint_ip, classification=observation.classification,
    )
    result = resolve_observed_ip(
        db, observation.endpoint_ip, observation.last_seen_at,
        vlan_id=None, source_id=observation.source_id,
        exporter_identity=observation.exporter_identity,
        endpoint_role=observation.endpoint_role, limit=limit,
    )
    if match.status == "ambiguous":
        return ResolutionResult("ambiguous", result.candidates, tuple(dict.fromkeys((*result.reasons, match.reason or "ambiguous_discovery_context"))))
    if match.status == "unmatched":
        return ResolutionResult("unresolved", (), tuple(dict.fromkeys((*result.reasons, match.reason or "discovery_does_not_establish_asset_identity"))))
    return result


def evidence_for_asset(db: Session, asset_id: int, *, limit: int = 100) -> dict[str, list[EvidenceCandidate]]:
    """Return current and historical evidence for review; never mutates it."""
    limit = _limit(limit)
    if db.get(HardwareAsset, asset_id) is None:
        raise ValueError("Hardware asset not found.")
    identities = db.query(AssetIdentityEvidence).filter(
        AssetIdentityEvidence.asset_id == asset_id,
    ).order_by(AssetIdentityEvidence.id.desc()).limit(limit).all()
    assignments = db.query(AssetNetworkAssignment).options(joinedload(AssetNetworkAssignment.vlan)).filter(
        AssetNetworkAssignment.asset_id == asset_id,
    ).order_by(AssetNetworkAssignment.started_at.desc()).limit(limit).all()
    now = datetime.utcnow()
    current = []
    stale = []
    for row in identities:
        item = _candidate(
            asset_id=asset_id,
            state="confirmed_match" if row.status == "confirmed" else "stale",
            source=row.source, kind=row.evidence_type, reference=row.normalised_value,
            scope=row.source_scope, vlan_id=None, exporter=None,
            start=row.first_observed_at, end=row.last_observed_at,
            reason="administrator-confirmed evidence" if row.status == "confirmed" else "identity evidence is revoked or unresolved",
        )
        (current if row.status == "confirmed" else stale).append(item)
    for row in assignments:
        active = row.status == "confirmed" and _contains(row.started_at, row.ended_at, now)
        context_current = True
        if row.vlan_id is not None:
            context_current = bool(row.network_cidr and row.vlan and row.vlan.subnet_cidr and row.network_cidr.strip() == row.vlan.subnet_cidr.strip())
        if context_current and row.source_id is not None and row.exporter_identity:
            context_current = any(
                vlan_id == row.vlan_id and cidr == (row.network_cidr or "")
                for vlan_id, cidr, _network in mapped_network_contexts(db, row.source_id, row.exporter_identity)
            )
        active = active and context_current
        item = _candidate(
            asset_id=asset_id,
            state="confirmed_match" if active else "stale",
            source=row.provenance, kind="network_assignment", reference=row.address,
            scope=None, vlan_id=row.vlan_id, exporter=row.exporter_identity,
            start=row.started_at, end=row.ended_at,
            reason="current administrator-confirmed assignment" if active else "assignment is closed or its VLAN/exporter context is no longer current",
        )
        (current if item.match_state == "confirmed_match" else stale).append(item)
    return {"current": current[:limit], "stale": stale[:limit]}
