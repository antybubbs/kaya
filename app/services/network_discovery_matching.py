"""Conservative matching of flow-discovered endpoints to managed IP records."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.models import IPAddress, TrafficDiscoveryLink, TrafficDiscoveryObservation, TrafficLocalNetwork


@dataclass(frozen=True)
class DiscoveryMatch:
    status: str
    confidence: str
    managed_ip_address_id: int | None = None
    reason: str | None = None


def _parse(value: str | None):
    try:
        return ipaddress.ip_address(value or "")
    except ValueError:
        return None


def _local_networks(db: Session) -> list[ipaddress._BaseNetwork]:
    networks = []
    for row in db.query(TrafficLocalNetwork).filter(TrafficLocalNetwork.is_enabled.is_(True)).limit(256):
        try:
            networks.append(ipaddress.ip_network(row.network_cidr, strict=False))
        except ValueError:
            continue
    return networks


def _managed_candidates(db: Session, endpoint: ipaddress._BaseAddress) -> list[IPAddress]:
    candidates = []
    for row in db.query(IPAddress).filter(IPAddress.address == str(endpoint)).limit(64):
        vlan = row.vlan
        if vlan and vlan.subnet_cidr:
            try:
                if endpoint not in ipaddress.ip_network(vlan.subnet_cidr, strict=False):
                    continue
            except ValueError:
                continue
        candidates.append(row)
    return candidates


def match_endpoint(db: Session, source_id: int, endpoint_ip: str, *, classification: str | None = None) -> DiscoveryMatch:
    """Return a non-mutating match; exact address and network context are required."""
    endpoint = _parse(endpoint_ip)
    if endpoint is None:
        return DiscoveryMatch("unmatched", "unknown", reason="invalid_endpoint")
    networks = [network for network in _local_networks(db) if endpoint.version == network.version and endpoint in network]
    if classification == "ambiguous" or len(networks) > 1:
        return DiscoveryMatch("ambiguous", "unknown", reason="overlapping_local_networks")
    if not networks:
        return DiscoveryMatch("unmatched", "unknown", reason="outside_enabled_local_networks")
    candidates = _managed_candidates(db, endpoint)
    if len(candidates) > 1:
        return DiscoveryMatch("ambiguous", "low", reason="multiple_managed_records")
    if not candidates:
        return DiscoveryMatch("unlinked", "unknown", reason="no_exact_managed_record")
    return DiscoveryMatch("unlinked", "high", managed_ip_address_id=candidates[0].id, reason="exact_ip_and_network_match")


def current_link(db: Session, source_id: int, exporter_identity: str, endpoint_ip: str, endpoint_role: str) -> TrafficDiscoveryLink | None:
    return db.query(TrafficDiscoveryLink).filter_by(
        source_id=source_id,
        exporter_identity=exporter_identity,
        endpoint_ip=endpoint_ip,
        endpoint_role=endpoint_role,
    ).first()


def latest_observation(db: Session, source_id: int, exporter_identity: str, endpoint_ip: str, endpoint_role: str) -> TrafficDiscoveryObservation | None:
    return db.query(TrafficDiscoveryObservation).filter_by(
        source_id=source_id,
        exporter_identity=exporter_identity,
        endpoint_ip=endpoint_ip,
        endpoint_role=endpoint_role,
    ).order_by(TrafficDiscoveryObservation.last_seen_at.desc(), TrafficDiscoveryObservation.id.desc()).first()


def observation_keys_query(db: Session, *, source_id: int | None = None, exporter_identity: str | None = None, endpoint_ip: str | None = None):
    query = db.query(
        TrafficDiscoveryObservation.source_id,
        TrafficDiscoveryObservation.exporter_identity,
        TrafficDiscoveryObservation.endpoint_ip,
        TrafficDiscoveryObservation.endpoint_role,
        func.max(TrafficDiscoveryObservation.last_seen_at).label("last_seen_at"),
        func.min(TrafficDiscoveryObservation.first_seen_at).label("first_seen_at"),
        func.sum(TrafficDiscoveryObservation.observation_count).label("observation_count"),
    )
    if source_id is not None:
        query = query.filter(TrafficDiscoveryObservation.source_id == source_id)
    if exporter_identity:
        query = query.filter(TrafficDiscoveryObservation.exporter_identity == exporter_identity)
    if endpoint_ip:
        query = query.filter(TrafficDiscoveryObservation.endpoint_ip == endpoint_ip)
    return query.group_by(
        TrafficDiscoveryObservation.source_id,
        TrafficDiscoveryObservation.exporter_identity,
        TrafficDiscoveryObservation.endpoint_ip,
        TrafficDiscoveryObservation.endpoint_role,
    )
