from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.models.models import HACluster, HANode
from app.services.ha_topology import dhcp_observation, pihole_manages_dhcp, reconcile_topology

OWNER_PROTECTION_AGENT_VERSION = (0, 2, 13)


@dataclass(frozen=True)
class DHCPDemotionDecision:
    allowed: bool
    owner_handover: bool
    reason: str


def _agent_version(value: str | None) -> tuple[int, int, int]:
    try:
        parts = [int(part) for part in str(value or "0").split(".")[:3]]
    except ValueError:
        return (0, 0, 0)
    return tuple((parts + [0, 0, 0])[:3])


def authorise_dhcp_demotion(
    cluster: HACluster,
    node: HANode,
    *,
    replacement: HANode | None = None,
    owner_handover: bool = False,
    replacement_has_local_authority: bool = False,
    now: datetime | None = None,
    freshness_seconds: int = 120,
) -> DHCPDemotionDecision:
    """Protect the sole DHCP owner from observation and maintenance work.

    Idempotent cleanup is permitted only on a node that is currently proven not
    to be the sole DHCP owner. Removing DHCP from the sole owner additionally
    requires an explicit handover and a replacement that is ready now.
    """
    current = now or datetime.utcnow()
    if _agent_version(node.agent_version) < OWNER_PROTECTION_AGENT_VERSION:
        return DHCPDemotionDecision(False, False, "Update this node to HA Agent 0.2.13 before Kaya may issue a DHCP demotion.")
    topology = reconcile_topology(cluster, now=current, freshness_seconds=freshness_seconds)
    node_observation = dhcp_observation(node, current, freshness_seconds=freshness_seconds)
    sole_dhcp_owner = topology.dhcp_owner_ids == (node.id,)

    if not sole_dhcp_owner:
        if len(topology.dhcp_owner_ids) < 2 and node.vip_owned and node_observation.active:
            return DHCPDemotionDecision(False, False, "Current ownership evidence is inconsistent; DHCP demotion was suppressed.")
        return DHCPDemotionDecision(True, False, "The node is not the sole active DHCP owner.")

    if not owner_handover:
        return DHCPDemotionDecision(False, False, "Routine work cannot disable DHCP on the sole active owner.")
    if replacement is None or replacement.id == node.id:
        return DHCPDemotionDecision(False, False, "The replacement node is not defined for this handover.")

    replacement_observation = dhcp_observation(replacement, current, freshness_seconds=freshness_seconds)
    state = cluster.lease_replication
    checks = (
        (topology.fresh, "both node observations are not fresh"),
        (topology.vip_owner_ids in {(node.id,), (replacement.id,)}, "Virtual IP ownership is not exclusive"),
        (not topology.dhcp_unknown_node_ids, "DHCP ownership is not fully observed"),
        (bool(node.last_heartbeat_at and node.last_heartbeat_at >= current - timedelta(seconds=freshness_seconds)), "the current owner heartbeat is stale"),
        (node.dns_healthy is True and node.ftl_active is True, "the current owner service health is not ready"),
        (node.keepalived_status == "DEPLOYED" and node.keepalived_runtime_state == "RUNNING", "the current owner failover service is not ready"),
        (bool(replacement.last_heartbeat_at and replacement.last_heartbeat_at >= current - timedelta(seconds=freshness_seconds)), "the replacement heartbeat is stale"),
        (replacement.dns_healthy is True and replacement.ftl_active is True, "the replacement service health is not ready"),
        (replacement.keepalived_status == "DEPLOYED" and replacement.keepalived_runtime_state == "RUNNING", "the replacement failover service is not ready"),
        (replacement.config_generation >= cluster.keepalived_generation, "the replacement configuration generation is stale"),
        (topology.vip_owner_ids == (replacement.id,) or not replacement.vip_owned, "the replacement Virtual IP state is unsafe"),
        (replacement_observation.released and replacement_observation.configured is False, "the replacement has not proved DHCP is stopped"),
        (
            not pihole_manages_dhcp(cluster)
            or (
                topology.vip_owner_ids == (replacement.id,)
                and replacement_has_local_authority
            )
            or bool(
                state is not None
                and state.status == "CURRENT"
                and state.applied_generation == state.desired_generation
                and (
                    (state.target_node_id == replacement.id and replacement.lease_generation >= state.desired_generation)
                    or state.source_node_id == replacement.id
                )
            ),
            "the replacement lease generation is not ready",
        ),
    )
    blocker = next((message for passed, message in checks if not passed), None)
    if blocker:
        return DHCPDemotionDecision(False, False, f"The replacement is not ready for atomic handover: {blocker}.")
    return DHCPDemotionDecision(True, True, "The replacement is ready for the explicit atomic handover.")
