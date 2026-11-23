"""Explicit, epoch-numbered DHCP authority (DHCP handover PROPOSAL; requires approval before rollout).

Rules (the administrator summary is in docs/modules/high-availability.md, "DHCP authority"):

1. Exactly one node may hold DHCP authority.  Kaya records it on the cluster and moves it only when
   it promotes a node after verified release of the other one (DHCP configured off *and* not
   listening) or with fresh, positive external fencing evidence.  It is never derived from node
   roles, Keepalived state or a node's saved configuration.
2. Every grant has a new, higher epoch.  A node enables DHCP only for a grant newer than anything
   it has seen, and records it durably first.
3. Every Pi-hole FTL start runs the boot guard.  DHCP stays on only for a restart of FTL in the same
   boot on a node that still holds its grant and the Virtual IP; otherwise DHCP is off until a fresh
   grant.  If pihole.toml cannot be made safe, FTL starts DNS-only with DHCP forced off.
4. Each agent cycle releases DHCP if Kaya names another holder (independent of Keepalived hooks).
5. Leases: a grant that keeps authority on the same node keeps its live lease file; a grant that
   moves authority installs the previous holder's verified snapshot; nothing is overwritten in place.
6. If any node reports an epoch newer than Kaya's record (for example after a database restore),
   Kaya stops sending authority instructions and re-establishes authority from a verified topology,
   above the highest epoch reported.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.models.models import HACluster, HANode
from app.services.ha_topology import FRESH_SECONDS, dhcp_observation, pihole_manages_dhcp, reconcile_topology

MAX_EPOCH = 2**31 - 1
EVIDENCE = {"established_verified_topology", "verified_release", "external_fence", "test"}
AUTHORITY_AGENT_VERSION = (0, 2, 16)  # first agent with the boot guard, enforcement and authority records


def supports_authority(node: HANode) -> bool:
    """Only agents of the revised protocol understand authority instructions."""
    from app.services.ha_agent_installer import version_tuple

    return version_tuple(node.agent_version) >= AUTHORITY_AGENT_VERSION


def authority(cluster: HACluster) -> dict[str, Any] | None:
    try:
        value = json.loads(cluster.dhcp_authority_json or "null")
    except (TypeError, ValueError):
        return None  # unreadable: treated as not established (nodes then receive no authority view)
    if not isinstance(value, dict) or not isinstance(value.get("epoch"), int) or not isinstance(value.get("node_id"), str):
        return None
    return value


def holder(cluster: HACluster) -> HANode | None:
    current = authority(cluster)
    if current is None:
        return None
    return next((node for node in cluster.nodes if node.public_id == current["node_id"]), None)


def reported_epoch(cluster: HACluster) -> int:
    """The newest epoch any node reports having seen (0 if none, or from agents that do not report it)."""
    return max((int(node.dhcp_authority_epoch or 0) for node in cluster.nodes), default=0)


def authority_behind(cluster: HACluster) -> bool:
    """A node has seen a newer epoch than Kaya's record: Kaya's database is older than the cluster."""
    current = authority(cluster)
    return current is not None and reported_epoch(cluster) > current["epoch"]


def grant_authority(cluster: HACluster, node: HANode, *, evidence: str, run_id: str | None = None) -> dict[str, Any]:
    """Move authority to ``node`` with a new, higher epoch (no commit; caller holds the cluster lock)."""
    if evidence not in EVIDENCE:
        raise ValueError("Unknown DHCP authority evidence.")
    if node.cluster_id != cluster.id:
        raise ValueError("The node does not belong to this cluster.")
    current = authority(cluster)
    behind = authority_behind(cluster)
    epoch = max(current["epoch"] if current else 0, reported_epoch(cluster)) + 1
    if epoch > MAX_EPOCH:
        raise ValueError("DHCP authority epoch exhausted.")
    # The grant history is only trusted while it is not behind the cluster (rule 6).
    previous = current if current is not None and not behind else None
    same_holder = previous is not None and previous["node_id"] == node.public_id
    # First epoch of this node's current, unbroken run of grants (lease continuity).  Unknown (None)
    # when authority is established from a node that was already serving: its own record decides.
    if same_holder:
        since = previous.get("holder_since")
    else:
        since = None if evidence == "established_verified_topology" else epoch
    record = {"epoch": epoch, "node_id": node.public_id, "evidence": evidence, "run_id": run_id,
              "granted_at": datetime.utcnow().isoformat() + "Z",
              "previous_node_id": previous["node_id"] if previous else None,
              "previous_epoch": previous["epoch"] if previous else None,
              "holder_since": since}
    cluster.dhcp_authority_json = json.dumps(record, sort_keys=True)
    return record


def ensure_authority(cluster: HACluster, node: HANode, *, evidence: str, run_id: str | None) -> dict[str, Any]:
    """Grant authority for one promotion step unless this exact grant already exists (idempotent)."""
    current = authority(cluster)
    if current is not None and current["node_id"] == node.public_id and current.get("run_id") == run_id and not authority_behind(cluster):
        return current
    return grant_authority(cluster, node, evidence=evidence, run_id=run_id)


def authority_for_node(cluster: HACluster, node: HANode) -> dict[str, Any] | None:
    """The per-node view sent in desired state: ``{"epoch", "holder"}``.

    None if authority is not established, or Kaya's record is behind the cluster (rule 6): agents
    then take no authority action and no promotion is offered until Kaya re-establishes it.
    """
    current = authority(cluster)
    if current is None or authority_behind(cluster):
        return None
    return {"epoch": current["epoch"], "holder": current["node_id"] == node.public_id}


def promotion_terms(cluster: HACluster, node: HANode) -> dict[str, Any] | None:
    """What a DHCP_PROMOTE action for ``node`` carries, or None: only the holder is ever promoted.

    ``lease_mode`` "continue" keeps the node's live lease file (authority never left it); "transfer"
    installs the staged snapshot, which the node verifies was captured from ``lease_source``.
    """
    view = authority_for_node(cluster, node)
    if view is None or not view["holder"]:
        return None
    current = authority(cluster)
    previous_node = current.get("previous_node_id")
    terms: dict[str, Any] = {"authority_epoch": current["epoch"], "previous_epoch": current.get("previous_epoch"),
                             "holder_since": current.get("holder_since")}
    if previous_node == node.public_id:
        return {**terms, "lease_mode": "continue", "lease_source": None}
    if previous_node is not None:
        return {**terms, "lease_mode": "transfer", "lease_source": previous_node}
    # First grant (or history discarded): the replicated snapshot comes from the node Kaya last read
    # leases from.  If that is this node, its own live file is newer than any snapshot of it.
    replication = cluster.lease_replication
    source = replication.source_node if replication is not None else None
    if source is None or source.id == node.id:
        return {**terms, "lease_mode": "continue", "lease_source": None}
    return {**terms, "lease_mode": "transfer", "lease_source": source.public_id}


def lease_snapshot_ready(cluster: HACluster, target: HANode) -> tuple[bool, str]:
    """Whether moving DHCP authority to ``target`` has the leases it needs (rule 5).

    Keeping authority on the same node needs nothing.  A transfer needs a snapshot captured from the
    node that holds (or last read as holding) the leases, already staged on ``target``; without it the
    node helper would refuse the promotion, so Kaya does not start one (DHCP stays where it is).
    """
    current = authority(cluster) if not authority_behind(cluster) else None
    replication = cluster.lease_replication
    if current is not None:
        source_public = current["node_id"]
    else:
        source_public = replication.source_node.public_id if replication is not None and replication.source_node is not None else None
    if source_public is None or source_public == target.public_id:
        return True, "DHCP authority stays on this node; its own leases are kept"
    source = next((node for node in cluster.nodes if node.public_id == source_public), None)
    if replication is None or replication.target_node_id != target.id or int(replication.applied_generation or 0) < 1:
        return False, f"no lease snapshot is staged on {target.display_name} yet"
    from app.services.ha_leases import _snapshot_for_generation

    snapshot = _snapshot_for_generation(cluster, int(replication.applied_generation))
    if snapshot is None or source is None or snapshot.source_node_id != source.id:
        return False, f"the lease snapshot staged on {target.display_name} was not captured from {source.display_name if source else 'the DHCP holder'}"
    return True, f"lease snapshot generation {snapshot.generation} from {source.display_name} is staged"


def establish_authority(cluster: HACluster, *, now: datetime | None = None) -> bool:
    """Record authority from a fully verified, aligned topology only (no commit).

    Once for upgraded clusters, and again whenever Kaya's record is behind the cluster (rule 6).
    """
    if (authority(cluster) is not None and not authority_behind(cluster)) or not pihole_manages_dhcp(cluster) or len(cluster.nodes) != 2:
        return False
    current = now or datetime.utcnow()
    topology = reconcile_topology(cluster, now=current, freshness_seconds=FRESH_SECONDS)
    if not topology.fresh or len(topology.vip_owner_ids) != 1 or topology.dhcp_owner_ids != topology.vip_owner_ids:
        return False
    if topology.dhcp_unknown_node_ids:
        return False
    owner = next(node for node in cluster.nodes if node.id == topology.vip_owner_ids[0])
    other = next(node for node in cluster.nodes if node.id != owner.id)
    if not dhcp_observation(other, current, freshness_seconds=FRESH_SECONDS).released:
        return False
    grant_authority(cluster, owner, evidence="established_verified_topology")
    return True


def serving_without_authority(cluster: HACluster, *, now: datetime | None = None) -> list[HANode]:
    """Nodes reported serving DHCP that do not hold authority (only once authority is established)."""
    current = authority(cluster)
    if current is None:
        return []
    at = now or datetime.utcnow()
    return [node for node in cluster.nodes
            if node.public_id != current["node_id"] and dhcp_observation(node, at, freshness_seconds=FRESH_SECONDS).active]
