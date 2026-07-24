from __future__ import annotations

from app.models.models import HACluster, HANode


DNS_ONLY = "DNS_ONLY"
DNS_DHCP = "DNS_DHCP"


def deployment_mode(cluster: HACluster) -> str:
    """Use the explicit mode while preserving pre-amendment cluster behaviour."""
    if cluster.deployment_mode in {DNS_ONLY, DNS_DHCP}:
        return cluster.deployment_mode
    # Pre-amendment clusters discovered DHCP dynamically. Until a legacy
    # cluster is explicitly classified, preserve the safer DNS + DHCP
    # boundary. A temporary inactive DHCP flag during handover must never
    # reclassify the cluster as externally managed.
    return DNS_DHCP


def pihole_manages_dhcp(cluster: HACluster) -> bool:
    return deployment_mode(cluster) == DNS_DHCP


def requires_dhcp_validation(cluster: HACluster) -> bool:
    return cluster.deployment_mode != DNS_ONLY


def lease_continuity_enabled(cluster: HACluster) -> bool:
    return cluster.deployment_mode != DNS_ONLY


def peer_for(cluster: HACluster, node: HANode) -> HANode | None:
    return next((candidate for candidate in cluster.nodes if candidate.id != node.id), None)


def advertised_dns_addresses(cluster: HACluster, node: HANode) -> tuple[str, str] | None:
    """Addresses this node should advertise whenever it is DHCP-active."""
    peer = peer_for(cluster, node)
    if not pihole_manages_dhcp(cluster) or not cluster.virtual_ip or peer is None or not peer.management_host:
        return None
    return cluster.virtual_ip, peer.management_host
