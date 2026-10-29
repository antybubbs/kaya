"""Conservative matching of flow-discovered endpoints to managed IP records."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.models.models import (
    IPAddress,
    TrafficDiscoveryLink,
    TrafficDiscoveryNetworkMapping,
    TrafficDiscoveryObservation,
    TrafficSource,
    VLAN,
)
from app.services.network_discovery_mapping import mapped_networks


@dataclass(frozen=True)
class DiscoveryMatch:
    status: str
    confidence: str
    managed_ip_address_id: int | None = None
    reason: str | None = None


@dataclass
class DiscoveryPayloadContext:
    """Bulk-loaded, read-only inputs used to render discovery observations."""

    latest: dict[tuple[int, str, str, str], object] = field(default_factory=dict)
    links: dict[tuple[int, str, str, str], TrafficDiscoveryLink] = field(default_factory=dict)
    networks: dict[tuple[int, str], list[ipaddress._BaseNetwork]] = field(default_factory=dict)
    network_contexts: dict[tuple[int, str], list[tuple[int, str, ipaddress._BaseNetwork]]] = field(default_factory=dict)
    managed_ips: dict[str, list[IPAddress]] = field(default_factory=dict)
    sources: dict[int, TrafficSource] = field(default_factory=dict)
    targets: dict[int, IPAddress] = field(default_factory=dict)


def build_discovery_payload_context(db: Session, rows: list) -> DiscoveryPayloadContext:
    """Load all read-side discovery dependencies in bounded bulk queries.

    The endpoint list is already capped by the caller. This avoids turning
    every returned observation key into a sequence of ORM lookups while
    preserving the existing conservative matching rules.
    """
    context = DiscoveryPayloadContext()
    keys = {
        (row.source_id, row.exporter_identity, row.endpoint_ip, row.endpoint_role)
        for row in rows
    }
    if not keys:
        return context
    source_ids = {key[0] for key in keys}
    endpoint_ips = {key[2] for key in keys}
    endpoint_roles = {key[3] for key in keys}
    pairs = {(key[0], key[1]) for key in keys}

    latest_rank = func.row_number().over(
        partition_by=(
            TrafficDiscoveryObservation.source_id,
            TrafficDiscoveryObservation.exporter_identity,
            TrafficDiscoveryObservation.endpoint_ip,
            TrafficDiscoveryObservation.endpoint_role,
        ),
        order_by=(TrafficDiscoveryObservation.last_seen_at.desc(), TrafficDiscoveryObservation.id.desc()),
    ).label("latest_rank")
    latest_rows = db.query(
        TrafficDiscoveryObservation.source_id,
        TrafficDiscoveryObservation.exporter_identity,
        TrafficDiscoveryObservation.endpoint_ip,
        TrafficDiscoveryObservation.endpoint_role,
        TrafficDiscoveryObservation.classification,
        TrafficDiscoveryObservation.confidence,
        latest_rank,
    ).filter(
        TrafficDiscoveryObservation.source_id.in_(source_ids),
        TrafficDiscoveryObservation.endpoint_ip.in_(endpoint_ips),
        TrafficDiscoveryObservation.endpoint_role.in_(endpoint_roles),
    ).subquery()
    for row in db.query(latest_rows).filter(latest_rows.c.latest_rank == 1).all():
        context.latest[(row.source_id, row.exporter_identity, row.endpoint_ip, row.endpoint_role)] = row

    links = db.query(TrafficDiscoveryLink).filter(
        TrafficDiscoveryLink.source_id.in_(source_ids),
        TrafficDiscoveryLink.endpoint_ip.in_(endpoint_ips),
        TrafficDiscoveryLink.endpoint_role.in_(endpoint_roles),
    ).all()
    context.links = {
        (row.source_id, row.exporter_identity, row.endpoint_ip, row.endpoint_role): row
        for row in links
    }
    context.sources = {
        row.id: row
        for row in db.query(TrafficSource).filter(TrafficSource.id.in_(source_ids)).all()
    }
    managed_ip_rows = db.query(IPAddress).options(joinedload(IPAddress.vlan)).filter(IPAddress.address.in_(endpoint_ips)).all()
    for row in managed_ip_rows:
        context.managed_ips.setdefault(row.address, []).append(row)
    target_ids = {row.managed_ip_address_id for row in links if row.managed_ip_address_id}
    if target_ids:
        context.targets = {
            row.id: row
            for row in db.query(IPAddress).options(joinedload(IPAddress.vlan)).filter(IPAddress.id.in_(target_ids)).all()
        }

    mapping_rows = db.query(TrafficDiscoveryNetworkMapping, VLAN).join(
        VLAN, TrafficDiscoveryNetworkMapping.vlan_id == VLAN.id
    ).filter(
        TrafficDiscoveryNetworkMapping.source_id.in_(source_ids),
        TrafficDiscoveryNetworkMapping.is_enabled.is_(True),
        VLAN.subnet_cidr.isnot(None),
    ).all()
    for mapping, vlan in mapping_rows:
        pair = (mapping.source_id, mapping.exporter_identity)
        if pair not in pairs:
            continue
        try:
            network = ipaddress.ip_network(vlan.subnet_cidr, strict=False)
        except ValueError:
            continue
        context.network_contexts.setdefault(pair, []).append((mapping.vlan_id, str(network), network))
        context.networks.setdefault(pair, []).append(network)
    return context


def _parse(value: str | None):
    try:
        return ipaddress.ip_address(value or "")
    except ValueError:
        return None


def _managed_candidates(db: Session, endpoint: ipaddress._BaseAddress, context: DiscoveryPayloadContext | None = None) -> list[IPAddress]:
    if context is not None:
        candidates = context.managed_ips.get(str(endpoint), [])
    else:
        candidates = []
        rows = db.query(IPAddress).filter(IPAddress.address == str(endpoint)).limit(64)
        for row in rows:
            candidates.append(row)
    filtered = []
    for row in candidates[:64]:
        vlan = row.vlan
        if vlan and vlan.subnet_cidr:
            try:
                if endpoint not in ipaddress.ip_network(vlan.subnet_cidr, strict=False):
                    continue
            except ValueError:
                continue
        filtered.append(row)
    return filtered


def match_endpoint(db: Session, source_id: int, exporter_identity: str, endpoint_ip: str, *, classification: str | None = None, context: DiscoveryPayloadContext | None = None) -> DiscoveryMatch:
    """Return a non-mutating match; exact address and network context are required."""
    endpoint = _parse(endpoint_ip)
    if endpoint is None:
        return DiscoveryMatch("unmatched", "unknown", reason="invalid_endpoint")
    networks = [network for network in (context.networks.get((source_id, exporter_identity), []) if context else mapped_networks(db, source_id, exporter_identity)) if endpoint.version == network.version and endpoint in network]
    if classification == "ambiguous" or len(networks) > 1:
        return DiscoveryMatch("ambiguous", "unknown", reason="overlapping_local_networks")
    if not networks:
        return DiscoveryMatch("unmatched", "unknown", reason="outside_enabled_local_networks")
    candidates = _managed_candidates(db, endpoint, context)
    if len(candidates) > 1:
        return DiscoveryMatch("ambiguous", "low", reason="multiple_managed_records")
    if not candidates:
        return DiscoveryMatch("unlinked", "unknown", reason="no_exact_managed_record")
    return DiscoveryMatch("unlinked", "high", managed_ip_address_id=candidates[0].id, reason="exact_ip_and_network_match")


def current_link(db: Session, source_id: int, exporter_identity: str, endpoint_ip: str, endpoint_role: str, *, context: DiscoveryPayloadContext | None = None) -> TrafficDiscoveryLink | None:
    if context is not None:
        return context.links.get((source_id, exporter_identity, endpoint_ip, endpoint_role))
    return db.query(TrafficDiscoveryLink).filter_by(
        source_id=source_id,
        exporter_identity=exporter_identity,
        endpoint_ip=endpoint_ip,
        endpoint_role=endpoint_role,
    ).first()


def latest_observation(db: Session, source_id: int, exporter_identity: str, endpoint_ip: str, endpoint_role: str, *, context: DiscoveryPayloadContext | None = None) -> TrafficDiscoveryObservation | None:
    if context is not None:
        return context.latest.get((source_id, exporter_identity, endpoint_ip, endpoint_role))
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
