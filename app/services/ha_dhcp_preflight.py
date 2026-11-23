"""Read-only preflight for the DHCP protocol rollout runbook (PROPOSAL; changes nothing).

Each step of docs/modules/high-availability-dhcp-rollout.md runs this first.  It answers, from fresh
signed reports only, whether the cluster is in a state where the step is safe, and lists every
blocker in plain words.  It never writes to the database or contacts a node.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.models.models import HACluster
from app.services.ha_dhcp_authority import authority, authority_behind, lease_snapshot_ready, supports_authority
from app.services.ha_topology import FRESH_SECONDS, dhcp_observation, reconcile_topology

STEPS = ("agent_rollout", "agent_rollback", "kaya_rollback")


def preflight(cluster: HACluster, step: str, *, now: datetime | None = None) -> dict[str, Any]:
    if step not in STEPS:
        raise ValueError(f"Unknown step; expected one of {', '.join(STEPS)}.")
    from app.services.ha_failover import active_failover
    from app.services.ha_maintenance import active_maintenance

    current = now or datetime.utcnow()
    topology = reconcile_topology(cluster, now=current, freshness_seconds=FRESH_SECONDS)
    nodes = sorted(cluster.nodes, key=lambda node: node.display_name)
    names = {node.id: node.display_name for node in nodes}
    blockers: list[str] = []
    warnings: list[str] = []
    if len(nodes) != 2 or len(topology.fresh_node_ids) != 2:
        blockers.append("Both nodes must be reporting fresh signed heartbeats.")
    if active_failover(cluster) is not None or active_maintenance(cluster) is not None or cluster.maintenance_mode:
        blockers.append("No failover, maintenance or repair may be running, and maintenance mode must be off.")
    if len(topology.vip_owner_ids) != 1 or topology.dhcp_owner_ids != topology.vip_owner_ids or topology.dhcp_unknown_node_ids:
        blockers.append("Exactly one node must hold the Virtual IP and be the only DHCP server (align ownership first).")
    for node in nodes:
        if node.dhcp_guard_mode == "dns_only":
            blockers.append(f"{node.display_name} runs Pi-hole DNS-only; repair its DHCP setting first.")
    owner = next((node for node in nodes if node.id in topology.vip_owner_ids), None)
    standby = next((node for node in nodes if owner is not None and node.id != owner.id), None)
    if step == "agent_rollout" and standby is not None:
        ready, reason = lease_snapshot_ready(cluster, standby)
        snapshot_ok = ready and cluster.lease_replication is not None and int(cluster.lease_replication.applied_generation or 0) > 0
        if not snapshot_ok:
            blockers.append(f"A verified lease snapshot of {owner.display_name} must be staged on {standby.display_name} ({reason}).")
    if step == "agent_rollback" and authority_behind(cluster):
        blockers.append("Kaya's DHCP authority record is older than the nodes; wait until it is re-established.")
    if step == "kaya_rollback":
        # Agents can only be re-installed from the Kaya version that serves them, so Kaya goes first.
        newer = [node.display_name for node in nodes if supports_authority(node)]
        if newer:
            warnings.append(f"Immediately after the Kaya rollback, run the agent update on {', '.join(newer)}. Until then DHCP keeps "
                            "running, but if the DHCP holder reboots its DHCP stays off until its agent is re-installed.")
    return {
        "step": step,
        "safe": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "nodes": [{
            "name": node.display_name, "agent_version": node.agent_version, "revised_protocol": supports_authority(node),
            "fresh": node.id in topology.fresh_node_ids, "vip": node.id in topology.vip_owner_ids,
            "dhcp": dhcp_observation(node, current, freshness_seconds=FRESH_SECONDS).state,
            "guard_mode": node.dhcp_guard_mode, "authority_epoch_seen": node.dhcp_authority_epoch,
        } for node in nodes],
        "authority": ({"holder": next((n.display_name for n in nodes if n.public_id == authority(cluster)["node_id"]), "?"),
                       "epoch": authority(cluster)["epoch"], "behind": authority_behind(cluster)} if authority(cluster) else None),
        "vip_owner": names.get(topology.active_node_id),
    }
