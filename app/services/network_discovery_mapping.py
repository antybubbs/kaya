"""Resolve explicit VLAN trust scopes for flow discovery only."""

from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from app.models.models import TrafficDiscoveryNetworkMapping, TrafficSource, VLAN


def mapped_network_contexts(db: Session, source_id: int, exporter_identity: str) -> list[tuple[int, str, ipaddress._BaseNetwork]]:
    """Return current enabled VLAN trust contexts for one source/exporter pair."""
    source = db.get(TrafficSource, source_id)
    if source is None or source.is_deleted or not exporter_identity:
        return []
    result = []
    rows = (
        db.query(TrafficDiscoveryNetworkMapping, VLAN)
        .join(VLAN, TrafficDiscoveryNetworkMapping.vlan_id == VLAN.id)
        .filter(
            TrafficDiscoveryNetworkMapping.source_id == source_id,
            TrafficDiscoveryNetworkMapping.exporter_identity == exporter_identity,
            TrafficDiscoveryNetworkMapping.is_enabled.is_(True),
            VLAN.subnet_cidr.isnot(None),
        )
        .limit(256)
        .all()
    )
    for mapping, vlan in rows:
        try:
            network = ipaddress.ip_network(vlan.subnet_cidr, strict=False)
        except ValueError:
            continue
        result.append((mapping.vlan_id, str(network), network))
    return result


def mapped_networks(db: Session, source_id: int, exporter_identity: str) -> list[ipaddress._BaseNetwork]:
    """Return current enabled VLAN CIDRs for one source/exporter pair.

    Missing, disabled or invalid mappings fail closed. This resolver is not used
    by flow accounting or device-usage classification.
    """
    return [network for _vlan_id, _cidr, network in mapped_network_contexts(db, source_id, exporter_identity)]
