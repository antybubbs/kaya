from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAEvent, HAFailoverRun, HANode, User
from app.services.ha_leases import HALeaseError, reconcile_cluster_leases


ACTIVE_RUN_STATUSES = {"RUNNING", "ROLLING_BACK"}
MIN_AGENT_VERSION = (0, 1, 4)


class HAFailoverError(ValueError):
    pass


@dataclass(frozen=True)
class FailoverReadiness:
    source: HANode | None
    target: HANode | None
    dhcp_managed: bool
    blockers: list[str]
    warnings: list[str]

    @property
    def ready(self) -> bool:
        return not self.blockers


def _version(value: str | None) -> tuple[int, int, int]:
    try:
        parts = [int(part) for part in str(value or "0").split(".")[:3]]
    except ValueError:
        return (0, 0, 0)
    return tuple((parts + [0, 0, 0])[:3])


def latest_failover(cluster: HACluster) -> HAFailoverRun | None:
    return max(cluster.failover_runs, key=lambda item: item.created_at) if cluster.failover_runs else None


def active_failover(cluster: HACluster) -> HAFailoverRun | None:
    return next((run for run in sorted(cluster.failover_runs, key=lambda item: item.created_at, reverse=True) if run.status in ACTIVE_RUN_STATUSES), None)


def failover_readiness(cluster: HACluster, *, now: datetime | None = None) -> FailoverReadiness:
    blockers: list[str] = []
    warnings: list[str] = ["DNS and DHCP may pause briefly while ownership changes."]
    owners = [node for node in cluster.nodes if node.vip_owned]
    source = owners[0] if len(owners) == 1 else None
    target = next((node for node in cluster.nodes if source and node.id != source.id), None)
    if len(cluster.nodes) != 2:
        blockers.append("Controlled failover requires exactly two nodes.")
    if len(owners) != 1:
        blockers.append("Exactly one node must currently own the virtual IP.")
    if cluster.keepalived_status != "DEPLOYED" or any(node.keepalived_status != "DEPLOYED" for node in cluster.nodes):
        blockers.append("Keepalived must be deployed and current on both nodes.")
    current = now or datetime.utcnow()
    for node in cluster.nodes:
        if not node.last_heartbeat_at or node.last_heartbeat_at < current - timedelta(minutes=2):
            blockers.append(f"Wait for a recent heartbeat from {node.display_name}.")
        if _version(node.agent_version) < MIN_AGENT_VERSION:
            blockers.append(f"Update {node.display_name} to agent 0.1.4 before controlled failover.")
        if node.dns_healthy is not True:
            blockers.append(f"Resolve the DNS health warning on {node.display_name}.")
        if node.keepalived_runtime_state != "RUNNING":
            blockers.append(f"Keepalived must be running on {node.display_name}.")
    state = cluster.lease_replication
    if state is None:
        blockers.append("Complete the DHCP continuity check before failover.")
        dhcp_managed = False
    else:
        dhcp_managed = state.status != "NOT_APPLICABLE"
        if dhcp_managed:
            if state.status != "CURRENT" or state.applied_generation != state.desired_generation:
                blockers.append("The standby lease snapshot must be current.")
            if target and target.lease_generation != state.desired_generation:
                blockers.append(f"Wait for {target.display_name} to stage the current lease generation.")
            dhcp_nodes = [node for node in cluster.nodes if node.dhcp_running]
            if len(dhcp_nodes) != 1 or (source and dhcp_nodes[0].id != source.id):
                blockers.append("Exactly the current VIP owner must report DHCP active before handover.")
        elif any(node.dhcp_running for node in cluster.nodes):
            blockers.append("Pi-hole DHCP is configured as external, but an agent reports DHCP active.")
    if active_failover(cluster):
        blockers.append("A controlled transition is already running.")
    return FailoverReadiness(source, target, dhcp_managed, list(dict.fromkeys(blockers)), warnings)


def _action_checksum(run: HAFailoverRun, node: HANode, action_type: str) -> str:
    value = f"{action_type}:{run.public_id}:{run.role_generation}:{node.public_id}"
    return hashlib.sha256(value.encode()).hexdigest()


def _event(db: Session, run: HAFailoverRun, event_type: str, severity: str, message: str) -> None:
    db.add(HAEvent(cluster_id=run.cluster_id, node_id=None, event_type=event_type, severity=severity, source="kaya", message=message, details_json_redacted=json.dumps({"run_id": run.public_id, "phase": run.phase, "role_generation": run.role_generation}, sort_keys=True), occurred_at=datetime.utcnow()))


def _move_vip(db: Session, run: HAFailoverRun, target: HANode) -> None:
    cluster = run.cluster
    for node in cluster.nodes:
        node.desired_role = "ACTIVE" if node.id == target.id else "STANDBY"
        node.vrrp_priority = 150 if node.id == target.id else 100
        node.keepalived_status = "PENDING_AGENT"
        node.keepalived_last_error = None
    cluster.cluster_generation += 1
    cluster.keepalived_generation += 1
    cluster.keepalived_status = "PENDING_AGENT"
    cluster.keepalived_requested_at = datetime.utcnow()
    cluster.status = "DEPLOYING"
    db.flush()


def start_controlled_failover(db: Session, cluster: HACluster, target: HANode, user: User, *, confirmation: str, acknowledged: bool) -> HAFailoverRun:
    if not acknowledged or confirmation.strip() != cluster.name:
        raise HAFailoverError(f"Type {cluster.name} and confirm the expected interruption before starting.")
    readiness = failover_readiness(cluster)
    if not readiness.ready or readiness.source is None or readiness.target is None:
        raise HAFailoverError(" ".join(readiness.blockers) or "The cluster is not ready for controlled failover.")
    if target.id != readiness.target.id:
        raise HAFailoverError("Choose the standby node as the failover target.")
    state = cluster.lease_replication
    if readiness.dhcp_managed:
        try:
            state = reconcile_cluster_leases(db, cluster)
        except HALeaseError as exc:
            raise HAFailoverError(f"Final lease capture failed: {exc}") from exc
    cluster.role_generation += 1
    cluster.cluster_generation += 1
    phase = "WAITING_FOR_LEASES" if readiness.dhcp_managed and state and state.status != "CURRENT" else ("DEMOTING_SOURCE" if readiness.dhcp_managed else "MOVING_VIP")
    run = HAFailoverRun(cluster_id=cluster.id, source_node_id=readiness.source.id, target_node_id=target.id, status="RUNNING", phase=phase, dhcp_managed=readiness.dhcp_managed, lease_generation=state.desired_generation if state else 0, role_generation=cluster.role_generation, requested_by_user_id=user.id, report_json=json.dumps({"starting_vip_owner": readiness.source.public_id, "target": target.public_id, "automatic": False}, sort_keys=True))
    db.add(run)
    db.flush()
    if phase == "MOVING_VIP":
        _move_vip(db, run, target)
    _event(db, run, "controlled_failover_started", "warning", f"Controlled failover started from {readiness.source.display_name} to {target.display_name}.")
    db.commit()
    db.refresh(run)
    return run


def desired_failover_action(cluster: HACluster, node: HANode) -> dict[str, Any] | None:
    run = active_failover(cluster)
    if run is None:
        return None
    action_type = None
    restore_original = False
    if run.phase == "DEMOTING_SOURCE" and node.id == run.source_node_id:
        action_type = "DHCP_DEMOTE"
    elif run.phase == "PROMOTING_TARGET" and node.id == run.target_node_id:
        action_type = "DHCP_PROMOTE"
    elif run.phase == "ROLLBACK_DEMOTING_TARGET" and node.id == run.target_node_id:
        action_type = "DHCP_DEMOTE"
    elif run.phase == "ROLLBACK_PROMOTING_SOURCE" and node.id == run.source_node_id:
        action_type, restore_original = "DHCP_PROMOTE", True
    if action_type is None:
        return None
    checksum = _action_checksum(run, node, action_type)
    return {"action_id": f"failover:{run.public_id}:{action_type.lower()}:{node.public_id}", "action_type": action_type, "generation": run.role_generation, "checksum": checksum, "run_id": run.public_id, "automatic": False, "lease_generation": run.lease_generation, "restore_original": restore_original}


def _safe_failure(db: Session, run: HAFailoverRun, message: str) -> None:
    run.status = "FAILED_SAFE"
    run.phase = "FAILED_SAFE"
    run.error_redacted = message[:1000]
    run.cluster.status = "DEGRADED"
    _event(db, run, "controlled_failover_failed_safe", "critical", message[:1000])


def record_failover_action_result(db: Session, node: HANode, *, action_type: str, generation: int, checksum: str | None, status: str, message: str) -> HAFailoverRun:
    run = active_failover(node.cluster)
    expected = desired_failover_action(node.cluster, node)
    if run is None or expected is None or generation != run.role_generation or checksum != expected["checksum"]:
        raise HAFailoverError("The failover result does not match the current transition generation.")
    if status != "APPLIED":
        _safe_failure(db, run, message or f"{action_type} failed safely.")
        return run
    if run.phase == "DEMOTING_SOURCE":
        node.dhcp_running = False
        run.phase = "MOVING_VIP"
        _move_vip(db, run, run.target_node)
    elif run.phase == "PROMOTING_TARGET":
        node.dhcp_running = True
        run.phase = "VERIFYING_TARGET"
    elif run.phase == "ROLLBACK_DEMOTING_TARGET":
        node.dhcp_running = False
        run.phase = "ROLLBACK_MOVING_VIP"
        _move_vip(db, run, run.source_node)
    elif run.phase == "ROLLBACK_PROMOTING_SOURCE":
        node.dhcp_running = True
        run.phase = "ROLLBACK_VERIFYING_SOURCE"
    return run


def _complete(db: Session, run: HAFailoverRun, *, rolled_back: bool) -> None:
    active = run.source_node if rolled_back else run.target_node
    standby = run.target_node if rolled_back else run.source_node
    active.role = active.desired_role = "ACTIVE"
    standby.role = standby.desired_role = "STANDBY"
    run.cluster.current_active_node_id = active.id
    run.cluster.authoritative_node_id = active.id
    run.cluster.status = "HEALTHY"
    run.cluster.last_failover_at = datetime.utcnow()
    run.status = "ROLLED_BACK" if rolled_back else "SUCCEEDED"
    run.phase = "ROLLED_BACK" if rolled_back else "COMPLETE"
    run.completed_at = datetime.utcnow()
    run.error_redacted = None if not rolled_back else run.error_redacted
    _event(db, run, "controlled_failover_rolled_back" if rolled_back else "controlled_failover_completed", "warning" if rolled_back else "info", f"Controlled transition completed with {active.display_name} active. Automatic failback remains disabled.")


def advance_failover(db: Session, cluster: HACluster) -> HAFailoverRun | None:
    run = active_failover(cluster)
    if run is None:
        return None
    state = cluster.lease_replication
    if run.phase == "WAITING_FOR_LEASES" and state and state.status == "CURRENT" and state.applied_generation >= run.lease_generation:
        run.phase = "DEMOTING_SOURCE"
    elif run.phase in {"MOVING_VIP", "ROLLBACK_MOVING_VIP"}:
        expected = run.target_node if run.phase == "MOVING_VIP" else run.source_node
        other = run.source_node if run.phase == "MOVING_VIP" else run.target_node
        if expected.vip_owned and not other.vip_owned and all(node.keepalived_status == "DEPLOYED" for node in cluster.nodes):
            if run.phase == "MOVING_VIP":
                run.phase = "PROMOTING_TARGET" if run.dhcp_managed else "VERIFYING_TARGET"
            else:
                run.phase = "ROLLBACK_PROMOTING_SOURCE" if run.dhcp_managed else "ROLLBACK_VERIFYING_SOURCE"
    if run.phase == "VERIFYING_TARGET":
        dhcp_ok = (run.target_node.dhcp_running and not run.source_node.dhcp_running) if run.dhcp_managed else not any(node.dhcp_running for node in cluster.nodes)
        if run.target_node.vip_owned and not run.source_node.vip_owned and run.target_node.dns_healthy is True and dhcp_ok:
            _complete(db, run, rolled_back=False)
    elif run.phase == "ROLLBACK_VERIFYING_SOURCE":
        dhcp_ok = (run.source_node.dhcp_running and not run.target_node.dhcp_running) if run.dhcp_managed else not any(node.dhcp_running for node in cluster.nodes)
        if run.source_node.vip_owned and not run.target_node.vip_owned and run.source_node.dns_healthy is True and dhcp_ok:
            _complete(db, run, rolled_back=True)
    db.commit()
    return run


def request_failover_rollback(db: Session, run: HAFailoverRun, *, acknowledged: bool) -> HAFailoverRun:
    if not acknowledged or run.status != "FAILED_SAFE":
        raise HAFailoverError("Confirm rollback of the failed controlled transition.")
    run.status = "ROLLING_BACK"
    run.cluster.cluster_generation += 1
    run.cluster.role_generation += 1
    run.role_generation = run.cluster.role_generation
    if run.source_node.vip_owned and (not run.dhcp_managed or run.source_node.dhcp_running):
        _complete(db, run, rolled_back=True)
    else:
        run.phase = "ROLLBACK_DEMOTING_TARGET"
        run.error_redacted = run.error_redacted or "Operator requested rollback."
        _event(db, run, "controlled_failover_rollback_started", "warning", f"Rollback to {run.source_node.display_name} started.")
    db.commit()
    db.refresh(run)
    return run


def failover_status(run: HAFailoverRun | None) -> dict[str, Any]:
    if run is None:
        return {"running": False, "status": "NOT_STARTED", "phase": "READY", "message": "No controlled failover has been run."}
    labels = {"WAITING_FOR_LEASES": "Capturing the final lease snapshot", "DEMOTING_SOURCE": "Stopping DHCP on the current active node", "MOVING_VIP": "Moving the virtual IP", "PROMOTING_TARGET": "Importing leases and starting DHCP on the target", "VERIFYING_TARGET": "Verifying DNS, DHCP and VIP ownership", "COMPLETE": "Controlled failover completed", "FAILED_SAFE": "Transition stopped safely", "ROLLBACK_DEMOTING_TARGET": "Ensuring DHCP is stopped on the target", "ROLLBACK_MOVING_VIP": "Returning the virtual IP", "ROLLBACK_PROMOTING_SOURCE": "Restoring DHCP on the original node", "ROLLBACK_VERIFYING_SOURCE": "Verifying the restored active node", "ROLLED_BACK": "Original node restored"}
    return {"running": run.status in ACTIVE_RUN_STATUSES, "run_id": run.public_id, "status": run.status, "phase": run.phase, "message": labels.get(run.phase, run.phase.replace("_", " ").title()), "error": run.error_redacted, "source": run.source_node.display_name, "target": run.target_node.display_name, "dhcp_managed": run.dhcp_managed, "started_at": run.started_at.isoformat() if run.started_at else None, "completed_at": run.completed_at.isoformat() if run.completed_at else None}
