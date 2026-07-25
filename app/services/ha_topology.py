from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.models.models import HACluster, HANode


DNS_ONLY = "DNS_ONLY"
DNS_DHCP = "DNS_DHCP"
FRESH_SECONDS = 45


@dataclass(frozen=True)
class TopologyIssue:
    code: str
    title: str
    message: str
    severity: str
    requires_service_movement: bool = False


@dataclass(frozen=True)
class DHCPObservation:
    state: str
    status: str
    observed_at: datetime | None
    configured: bool | None = None
    service_active: bool | None = None
    listening: bool | None = None

    @property
    def active(self) -> bool:
        return self.state == "ACTIVE"

    @property
    def released(self) -> bool:
        return self.state == "RELEASED"


@dataclass(frozen=True)
class ReconciledTopology:
    observed_at: datetime
    fresh_node_ids: tuple[int, ...]
    vip_owner_ids: tuple[int, ...]
    dhcp_owner_ids: tuple[int, ...]
    dhcp_unknown_node_ids: tuple[int, ...]
    issues: tuple[TopologyIssue, ...]
    service_availability: str
    redundancy_state: str
    telemetry_state: str
    configuration_state: str
    topology_safe: bool

    @property
    def fresh(self) -> bool:
        return len(self.fresh_node_ids) == 2

    @property
    def active_node_id(self) -> int | None:
        return self.vip_owner_ids[0] if len(self.vip_owner_ids) == 1 else None


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


def heartbeat_is_fresh(
    node: HANode,
    now: datetime,
    *,
    since: datetime | None = None,
    freshness_seconds: int = FRESH_SECONDS,
) -> bool:
    return bool(
        node.last_heartbeat_at
        and node.last_heartbeat_at >= now - timedelta(seconds=freshness_seconds)
        and (since is None or node.last_heartbeat_at >= since)
    )


def dhcp_observation(
    node: HANode,
    now: datetime,
    *,
    since: datetime | None = None,
    freshness_seconds: int = FRESH_SECONDS,
) -> DHCPObservation:
    observed_at = node.dhcp_observed_at or node.last_heartbeat_at
    status = str(node.dhcp_observation_status or "UNKNOWN").upper()
    if (
        not heartbeat_is_fresh(node, now, since=since, freshness_seconds=freshness_seconds)
        or observed_at is None
        or observed_at < now - timedelta(seconds=freshness_seconds)
        or (since is not None and observed_at < since)
    ):
        return DHCPObservation("UNKNOWN", "STALE", observed_at)
    if status != "FRESH":
        # Pre-0.2.7 reports with all three independent observations remain
        # usable during the rolling upgrade. A lone legacy boolean does not.
        if node.dhcp_configured is None or node.dhcp_listener_active is None or node.ftl_active is None:
            return DHCPObservation("UNKNOWN", status, observed_at)
    runtime = str(node.dhcp_runtime_state or "UNKNOWN").upper()
    if runtime == "UNKNOWN" and status != "FRESH":
        runtime = "RUNNING" if node.dhcp_running else "STOPPED"
    evidence = (node.dhcp_configured, node.ftl_active, node.dhcp_listener_active)
    if node.dhcp_listener_active is True and node.ftl_active is True and runtime == "RUNNING":
        return DHCPObservation("ACTIVE", "FRESH", observed_at, *evidence)
    if node.dhcp_listener_active is False and runtime == "STOPPED":
        return DHCPObservation("RELEASED", "FRESH", observed_at, *evidence)
    if None in {node.dhcp_configured, node.dhcp_listener_active, node.ftl_active} or runtime == "UNKNOWN":
        return DHCPObservation("UNKNOWN", status, observed_at, *evidence)
    return DHCPObservation("INACTIVE", "FRESH", observed_at, *evidence)


def reconcile_topology(
    cluster: HACluster,
    *,
    now: datetime | None = None,
    since: datetime | None = None,
    freshness_seconds: int = FRESH_SECONDS,
) -> ReconciledTopology:
    current = now or datetime.utcnow()
    fresh_nodes = [
        node
        for node in cluster.nodes
        if heartbeat_is_fresh(node, current, since=since, freshness_seconds=freshness_seconds)
    ]
    vip_owners = [node for node in fresh_nodes if node.vip_owned]
    observations = {
        node.id: dhcp_observation(node, current, since=since, freshness_seconds=freshness_seconds)
        for node in fresh_nodes
    }
    dhcp_owners = [node for node in fresh_nodes if observations[node.id].active]
    dhcp_unknown = [node for node in fresh_nodes if observations[node.id].state == "UNKNOWN"]
    managed = pihole_manages_dhcp(cluster)
    issues: list[TopologyIssue] = []

    if len(cluster.nodes) != 2:
        issues.append(TopologyIssue("NODE_COUNT", "Cluster node configuration is incomplete", "A Pi-hole HA cluster requires exactly two existing nodes.", "critical"))
    if len(fresh_nodes) != len(cluster.nodes):
        missing = ", ".join(node.display_name for node in cluster.nodes if node not in fresh_nodes)
        issues.append(TopologyIssue("STALE_AGENT_STATE", "Fresh node inspection is incomplete", f"Waiting for a new signed HA Agent report from {missing or 'both nodes'}.", "warning"))
    if len(vip_owners) > 1:
        issues.append(TopologyIssue("DUPLICATE_VIP", "Virtual IP ownership conflict detected", "More than one node reports ownership of the DNS Virtual IP.", "critical", True))
    elif fresh_nodes and not vip_owners:
        issues.append(TopologyIssue("NO_VIP_OWNER", "No Virtual IP owner reported", "No current signed node report confirms ownership of the DNS Virtual IP.", "critical", True))
    if managed and len(dhcp_owners) > 1:
        issues.append(TopologyIssue("MULTIPLE_DHCP", "Multiple DHCP servers detected", "More than one node has fresh configuration, FTL and UDP/67 evidence for DHCP. Kaya will not start another DHCP service.", "critical", True))
    elif managed and not dhcp_owners:
        if dhcp_unknown:
            names = ", ".join(node.display_name for node in dhcp_unknown)
            issues.append(TopologyIssue("DHCP_TELEMETRY_UNKNOWN", "DHCP state needs a fresh observation", f"Kaya could not inspect DHCP completely on {names}. The service is not being reported as stopped.", "warning"))
        elif fresh_nodes:
            issues.append(TopologyIssue("NO_DHCP_OWNER", "No DHCP service owner reported", "Both nodes have fresh observations, but neither has DHCP configured and listening on UDP port 67.", "critical", True))
    if managed and len(vip_owners) == 1 and len(dhcp_owners) == 1 and vip_owners[0].id != dhcp_owners[0].id:
        issues.append(TopologyIssue("OWNERSHIP_MISMATCH", "Cluster ownership mismatch", "The DNS Virtual IP and DHCP service are currently owned by different nodes.", "critical", True))

    owner = vip_owners[0] if len(vip_owners) == 1 else None
    if managed and owner and owner.id in observations:
        active_observation = observations[owner.id]
        if active_observation.configured is False:
            issues.append(TopologyIssue(
                "ACTIVE_DHCP_CONFIGURATION_DISABLED",
                "Active DHCP configuration drift detected",
                f"{owner.display_name} exclusively owns the Virtual IP but Pi-hole DHCP configuration is disabled.",
                "warning" if active_observation.active else "critical",
            ))
        elif active_observation.configured is True and not active_observation.active:
            issues.append(TopologyIssue(
                "ACTIVE_DHCP_ACTIVATION_INCOMPLETE",
                "Active DHCP service has not converged",
                f"{owner.display_name} has DHCP enabled but is not listening on UDP port 67.",
                "critical",
            ))
        for standby in (node for node in fresh_nodes if node.id != owner.id):
            standby_observation = observations[standby.id]
            if standby_observation.configured is True and standby_observation.released:
                issues.append(TopologyIssue(
                    "STANDBY_DHCP_CONFIGURATION_ENABLED",
                    "Standby DHCP configuration drift detected",
                    f"{standby.display_name} is not serving DHCP, but its Pi-hole DHCP configuration remains enabled.",
                    "warning",
                ))

    service_ok = bool(
        owner
        and owner.dns_healthy is True
        and (not managed or (len(dhcp_owners) == 1 and dhcp_owners[0].id == owner.id))
    )
    configuration_consistent = bool(
        not managed
        or (
            owner
            and observations.get(owner.id)
            and observations[owner.id].configured is True
            and all(
                observations[node.id].configured is False
                for node in fresh_nodes
                if node.id != owner.id
            )
        )
    )
    topology_safe = bool(
        service_ok
        and len(vip_owners) == 1
        and (
            not managed
            or (
                len(dhcp_owners) == 1
                and not dhcp_unknown
                and all(
                    observations[node.id].active if node.id == owner.id else observations[node.id].released
                    for node in fresh_nodes
                )
            )
        )
        and configuration_consistent
    )
    return ReconciledTopology(
        observed_at=current,
        fresh_node_ids=tuple(node.id for node in fresh_nodes),
        vip_owner_ids=tuple(node.id for node in vip_owners),
        dhcp_owner_ids=tuple(node.id for node in dhcp_owners),
        dhcp_unknown_node_ids=tuple(node.id for node in dhcp_unknown),
        issues=tuple(issues),
        service_availability="HEALTHY" if service_ok else "DEGRADED",
        redundancy_state="HEALTHY" if len(fresh_nodes) == len(cluster.nodes) and topology_safe else "REDUCED",
        telemetry_state="CURRENT" if len(fresh_nodes) == len(cluster.nodes) and (not managed or not dhcp_unknown) else "DEGRADED",
        configuration_state="CONSISTENT" if configuration_consistent else "INCONSISTENT",
        topology_safe=topology_safe,
    )


def advertised_dns_addresses(cluster: HACluster, node: HANode) -> tuple[str, str] | None:
    """Addresses this node should advertise whenever it is DHCP-active."""
    peer = peer_for(cluster, node)
    if not pihole_manages_dhcp(cluster) or not cluster.virtual_ip or peer is None or not peer.management_host:
        return None
    return cluster.virtual_ip, peer.management_host
