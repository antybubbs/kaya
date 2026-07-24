"""Recovery readiness for HA nodes without changing the proven transition engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAEvent, HAFailoverRun, HANode, HASyncRun
from app.services.audit import write_audit
from app.services.ha_topology import pihole_manages_dhcp


RECOVERY_HEARTBEAT_SECONDS = 45
RECOVERY_STABILITY_SECONDS = 60
RECOVERY_STATES = {
    "OFFLINE",
    "RECOVERING",
    "SYNCHRONISING",
    "VERIFYING",
    "STANDBY_READY",
    "ACTIVE",
    "STANDBY",
}


@dataclass(frozen=True)
class RecoveryCheck:
    key: str
    label: str
    passed: bool
    detail: str
    required: bool = True


@dataclass(frozen=True)
class NodeRecovery:
    node: HANode
    state: str
    checks: tuple[RecoveryCheck, ...]
    stability_seconds: int
    stability_required_seconds: int

    @property
    def ready(self) -> bool:
        return self.state == "STANDBY_READY"


def _fresh(node: HANode, now: datetime) -> bool:
    return bool(node.last_heartbeat_at and node.last_heartbeat_at >= now - timedelta(seconds=RECOVERY_HEARTBEAT_SECONDS))


def preferred_node(cluster: HACluster) -> HANode | None:
    preferred = next((node for node in cluster.nodes if node.id == cluster.preferred_node_id), None)
    if preferred is not None:
        return preferred
    earliest = min(cluster.failover_runs, key=lambda run: run.created_at or datetime.min, default=None)
    if earliest is not None:
        return earliest.source_node
    return next((node for node in cluster.nodes if node.role == "ACTIVE"), None) or (
        min(cluster.nodes, key=lambda node: node.id) if cluster.nodes else None
    )


def current_active_node(cluster: HACluster, now: datetime | None = None) -> HANode | None:
    current = now or datetime.utcnow()
    owners = [node for node in cluster.nodes if node.vip_owned and _fresh(node, current)]
    if len(owners) == 1:
        return owners[0]
    return next((node for node in cluster.nodes if node.id == cluster.current_active_node_id and _fresh(node, current)), None)


def _latest_sync(db: Session, cluster: HACluster, active: HANode, target: HANode) -> HASyncRun | None:
    return (
        db.query(HASyncRun)
        .filter(
            HASyncRun.cluster_id == cluster.id,
            HASyncRun.source_node_id == active.id,
            HASyncRun.target_node_id == target.id,
        )
        .order_by(HASyncRun.created_at.desc())
        .first()
    )


def recovery_checks(db: Session, cluster: HACluster, node: HANode, *, now: datetime | None = None) -> tuple[RecoveryCheck, ...]:
    current = now or datetime.utcnow()
    active = current_active_node(cluster, current)
    heartbeat = _fresh(node, current)
    credential = node.agent_credential
    agent = bool(heartbeat and credential and credential.registered_at and credential.revoked_at is None)
    keepalived = bool(node.keepalived_status == "DEPLOYED" and node.keepalived_runtime_state == "RUNNING")
    generation = bool(
        node.config_generation >= cluster.keepalived_generation
        and node.observed_generation >= cluster.role_generation
    )
    standby_runtime = bool(node.vip_owned is False and node.observed_role == "STANDBY")
    dhcp_safe = not pihole_manages_dhcp(cluster) or node.dhcp_running is False
    latest_sync = _latest_sync(db, cluster, active, node) if active and active.id != node.id else None
    configuration_sync = bool(
        latest_sync
        and latest_sync.status in {"IN_SYNC", "SUCCEEDED"}
        and (
            node.recovery_started_at is None
            or (latest_sync.completed_at or latest_sync.created_at) >= node.recovery_started_at
        )
    )
    lease = cluster.lease_replication
    lease_sync = bool(
        not pihole_manages_dhcp(cluster)
        or (
            lease
            and lease.status == "CURRENT"
            and lease.target_node_id == node.id
            and lease.applied_generation >= lease.desired_generation
            and node.lease_generation >= lease.desired_generation
        )
    )
    peer_label = "Peer Network Reachability (optional)"
    return (
        RecoveryCheck("kaya_heartbeat", "Kaya heartbeat", heartbeat, "The HA Agent has reported to Kaya recently."),
        RecoveryCheck("agent_identity", "HA Agent identity", agent, "The registered, non-revoked agent identity is reporting."),
        RecoveryCheck("dns", "Local DNS and Pi-hole FTL", node.dns_healthy is True, "Pi-hole answered the agent's local DNS probe."),
        RecoveryCheck("network_interface", "Expected network interface", bool(node.network_interface), "The node has the configured HA network interface."),
        RecoveryCheck("keepalived", "Local failover service", keepalived, "Keepalived is deployed and running."),
        RecoveryCheck("cluster_generation", "Cluster generation", generation, "The node recognises the current configuration and role generations."),
        RecoveryCheck("standby_runtime", "Standby ownership", standby_runtime, "The recovered node is not claiming the DNS Virtual IP."),
        RecoveryCheck("dhcp_safe", "DHCP standby state", dhcp_safe, "DHCP is safely stopped on the recovered node.", pihole_manages_dhcp(cluster)),
        RecoveryCheck("configuration_sync", "Pi-hole API, configuration and drift", configuration_sync, "A post-recovery active-to-standby API comparison or synchronisation completed without supported drift."),
        RecoveryCheck("lease_sync", "DHCP generation and lease staging", lease_sync, "The standby has staged the current validated DHCP generation.", pihole_manages_dhcp(cluster)),
        RecoveryCheck(
            "peer_reachability",
            peer_label,
            node.peer_reachable is True,
            "Optional ICMP ping only. An unavailable ping does not affect recovery, failover, failback, DNS health, or Kaya heartbeat status.",
            False,
        ),
    )


def _event_for_transition(db: Session, cluster: HACluster, node: HANode, previous: str, current: str, now: datetime) -> None:
    labels = {
        "OFFLINE": ("node_offline", "warning", f"{node.display_name} stopped reporting to Kaya."),
        "RECOVERING": ("node_recovered", "info", f"{node.display_name} is online and recovery checks have started."),
        "SYNCHRONISING": ("node_recovery_synchronising", "info", f"{node.display_name} is being synchronised from the current active node."),
        "VERIFYING": ("node_recovery_verifying", "info", f"{node.display_name} passed synchronisation checks and entered the stability window."),
        "STANDBY_READY": ("node_standby_ready", "info", f"{node.display_name} is fully recovered and ready for controlled failback."),
        "ACTIVE": ("node_active", "info", f"{node.display_name} is the current active node."),
        "STANDBY": ("node_standby", "info", f"{node.display_name} is operating as standby."),
    }
    event_type, severity, message = labels[current]
    db.add(HAEvent(
        cluster_id=cluster.id,
        node_id=node.id,
        event_type=event_type,
        severity=severity,
        source="kaya",
        message=message,
        details_json_redacted=f'{{"from":"{previous}","to":"{current}"}}',
        occurred_at=now,
    ))


def evaluate_recovery(
    db: Session,
    cluster: HACluster,
    *,
    now: datetime | None = None,
    stability_seconds: int = RECOVERY_STABILITY_SECONDS,
) -> dict[int, NodeRecovery]:
    current = now or datetime.utcnow()
    preferred = preferred_node(cluster)
    if cluster.preferred_node_id is None and preferred is not None:
        cluster.preferred_node_id = preferred.id
    active = current_active_node(cluster, current)
    results: dict[int, NodeRecovery] = {}
    changed: list[tuple[HANode, str, str]] = []

    for node in cluster.nodes:
        previous = node.recovery_state if node.recovery_state in RECOVERY_STATES else "STANDBY"
        checks = recovery_checks(db, cluster, node, now=current)
        required = [check for check in checks if check.required]
        if active and node.id == active.id:
            state = "ACTIVE"
            node.recovery_started_at = None
            node.recovery_stable_since = None
        elif not _fresh(node, current):
            state = "OFFLINE"
            node.recovery_started_at = None
            node.recovery_stable_since = None
        else:
            if previous == "OFFLINE" or node.recovery_started_at is None:
                node.recovery_started_at = current
            basic_keys = {"kaya_heartbeat", "agent_identity", "dns", "network_interface", "keepalived", "cluster_generation", "standby_runtime", "dhcp_safe"}
            basic_ready = all(check.passed for check in required if check.key in basic_keys)
            sync_ready = all(check.passed for check in required if check.key in {"configuration_sync", "lease_sync"})
            if not basic_ready:
                state = "RECOVERING"
                node.recovery_stable_since = None
            elif not sync_ready:
                state = "SYNCHRONISING"
                node.recovery_stable_since = None
            else:
                if node.recovery_stable_since is None:
                    node.recovery_stable_since = current
                stable_for = int((current - node.recovery_stable_since).total_seconds())
                state = "STANDBY_READY" if stable_for >= stability_seconds else "VERIFYING"
        node.recovery_state = state
        stable_for = int((current - node.recovery_stable_since).total_seconds()) if node.recovery_stable_since else 0
        results[node.id] = NodeRecovery(node, state, checks, max(0, stable_for), stability_seconds)
        if previous != state:
            changed.append((node, previous, state))
            _event_for_transition(db, cluster, node, previous, state, current)

    db.commit()
    for node, previous, state in changed:
        write_audit(
            db,
            None,
            f"ha_recovery_{state.lower()}",
            "ha_node",
            entity_id=node.public_id,
            detail=f"{node.display_name} recovery state changed from {previous} to {state}.",
            severity="warning" if state == "OFFLINE" else "info",
            metadata={"cluster_id": cluster.public_id, "from": previous, "to": state},
        )
    return results


def failback_target(db: Session, cluster: HACluster, *, now: datetime | None = None) -> NodeRecovery | None:
    active = current_active_node(cluster, now)
    preferred = preferred_node(cluster)
    if active is None or preferred is None or active.id == preferred.id:
        return None
    return evaluate_recovery(db, cluster, now=now).get(preferred.id)


def recovery_snapshot(db: Session, cluster: HACluster, *, now: datetime | None = None) -> dict[int, NodeRecovery]:
    current = now or datetime.utcnow()
    results: dict[int, NodeRecovery] = {}
    for node in cluster.nodes:
        stable_for = int((current - node.recovery_stable_since).total_seconds()) if node.recovery_stable_since else 0
        results[node.id] = NodeRecovery(
            node,
            node.recovery_state if node.recovery_state in RECOVERY_STATES else "STANDBY",
            recovery_checks(db, cluster, node, now=current),
            max(0, stable_for),
            RECOVERY_STABILITY_SECONDS,
        )
    return results


def peer_diagnostic(node: HANode, peer: HANode | None, *, now: datetime | None = None) -> dict[str, object | None]:
    current = now or datetime.utcnow()
    if peer is None:
        status, display_label = "NOT_CONFIGURED", "Not configured"
        explanation = "No peer node is configured."
    elif node.peer_icmp_probe_status == "UNAVAILABLE":
        status, display_label = "ICMP_PROBE_UNAVAILABLE", "ICMP probe unavailable"
        explanation = "The node could not run its local ICMP probe. Check the installed HA Agent service capability and ping package. This does not mean the peer is unreachable."
    elif not node.last_peer_attempt_at:
        status, display_label = "NOT_TESTED", "Not tested"
        explanation = "No ICMP ping result has been reported yet."
    elif node.peer_icmp_probe_status == "AVAILABLE" or node.peer_reachable is True:
        status, display_label = "PING_AVAILABLE", "Ping available"
        explanation = f"{node.display_name} received an ICMP response from {peer.display_name}."
    else:
        status, display_label = "PING_UNAVAILABLE", "Ping unavailable"
        explanation = "ICMP may be blocked by the host firewall or network. This is informational and does not mean the peer, DNS, or HA Agent is offline."

    if node.peer_dns_reachable is True:
        dns_status, dns_label = "REACHABLE", "DNS port 53 reachable"
        dns_explanation = f"{node.display_name} opened a TCP connection to port 53 on {peer.display_name if peer else 'the peer'}."
    elif node.peer_dns_reachable is False:
        dns_status, dns_label = "UNREACHABLE", "DNS port 53 unavailable"
        dns_explanation = "The peer did not accept a TCP connection on port 53. This service result is separate from ICMP ping."
    else:
        dns_status, dns_label = "NOT_TESTED", "Not tested"
        dns_explanation = "This agent version has not reported the peer DNS port test yet."

    peer_heartbeat_current = bool(
        peer
        and peer.last_heartbeat_at
        and peer.last_heartbeat_at >= current - timedelta(seconds=RECOVERY_HEARTBEAT_SECONDS)
    )
    if peer_heartbeat_current:
        kaya_status, kaya_label = "REPORTING", "Reporting to Kaya"
        kaya_explanation = f"{peer.display_name} has a current, signed Kaya heartbeat."
    elif peer and peer.last_heartbeat_at:
        kaya_status, kaya_label = "DELAYED", "Heartbeat delayed"
        kaya_explanation = f"{peer.display_name} has not sent a current signed heartbeat to Kaya."
    else:
        kaya_status, kaya_label = "NOT_REPORTED", "Not reported"
        kaya_explanation = "The peer has not sent a signed heartbeat to Kaya."

    return {
        "status": status,
        "display_label": display_label,
        "severity": "info",
        "explanation": explanation,
        "probe": "Optional ICMP ping",
        "peer_name": peer.display_name if peer else None,
        "peer_address": peer.management_host if peer else None,
        "last_attempt_at": node.last_peer_attempt_at.isoformat() + "Z" if node.last_peer_attempt_at else None,
        "last_success_at": node.last_peer_success_at.isoformat() + "Z" if node.last_peer_success_at else None,
        "dns_status": dns_status,
        "dns_display_label": dns_label,
        "dns_explanation": dns_explanation,
        "dns_last_attempt_at": node.last_peer_dns_attempt_at.isoformat() + "Z" if node.last_peer_dns_attempt_at else None,
        "dns_last_success_at": node.last_peer_dns_success_at.isoformat() + "Z" if node.last_peer_dns_success_at else None,
        "peer_kaya_status": kaya_status,
        "peer_kaya_display_label": kaya_label,
        "peer_kaya_explanation": kaya_explanation,
        "peer_kaya_last_heartbeat_at": peer.last_heartbeat_at.isoformat() + "Z" if peer and peer.last_heartbeat_at else None,
        "possible_causes": [
            "ICMP echo is blocked by a host or network firewall.",
            "The configured peer address is unreachable from this node.",
            "A routing or Layer 2 connectivity problem exists.",
        ],
    }
