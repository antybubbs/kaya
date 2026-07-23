from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAEvent, HAFailoverRun, HANode, User
from app.services.ha_leases import HALeaseError, reconcile_cluster_leases
from app.services.ha_topology import pihole_manages_dhcp


ACTIVE_RUN_STATUSES = {"RUNNING", "ROLLING_BACK"}
MIN_AGENT_VERSION = (0, 1, 5)
AUTOMATIC_AGENT_VERSION = (0, 2, 1)


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
    current = now or datetime.utcnow()
    owners = [node for node in cluster.nodes if node.vip_owned and node.last_heartbeat_at and node.last_heartbeat_at >= current - timedelta(minutes=2)]
    source = owners[0] if len(owners) == 1 else None
    target = next((node for node in cluster.nodes if source and node.id != source.id), None)
    if len(cluster.nodes) != 2:
        blockers.append("Controlled failover requires exactly two nodes.")
    if len(owners) != 1:
        blockers.append("Exactly one node must currently own the virtual IP.")
    if cluster.keepalived_status != "DEPLOYED" or any(node.keepalived_status != "DEPLOYED" for node in cluster.nodes):
        blockers.append("Keepalived must be deployed and current on both nodes.")
    for node in cluster.nodes:
        if not node.last_heartbeat_at or node.last_heartbeat_at < current - timedelta(minutes=2):
            blockers.append(f"Wait for a recent heartbeat from {node.display_name}.")
        if _version(node.agent_version) < MIN_AGENT_VERSION:
            blockers.append(f"Update {node.display_name} to agent 0.1.5 before controlled failover.")
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


def automatic_failover_blockers(cluster: HACluster, *, now: datetime | None = None) -> list[str]:
    blockers = list(failover_readiness(cluster, now=now).blockers)
    if not any(run.status == "SUCCEEDED" for run in cluster.failover_runs):
        blockers.append("Complete one successful controlled failover test first.")
    for node in cluster.nodes:
        if _version(node.agent_version) < AUTOMATIC_AGENT_VERSION:
            blockers.append(f"Update {node.display_name} to agent 0.2.1 for verified offline DHCP failover.")
    if cluster.maintenance_mode:
        blockers.append("Exit maintenance mode before enabling automatic failover.")
    return list(dict.fromkeys(blockers))


def set_automatic_failover(db: Session, cluster: HACluster, *, enabled: bool, confirmation: str, acknowledged: bool) -> HACluster:
    if enabled:
        if confirmation.strip() != cluster.name or not acknowledged:
            raise HAFailoverError(f"Type {cluster.name} and confirm the automatic-failover safety warning.")
        blockers = automatic_failover_blockers(cluster)
        if blockers:
            raise HAFailoverError(" ".join(blockers))
    if cluster.automatic_failover_enabled == enabled:
        return cluster
    cluster.automatic_failover_enabled = enabled
    cluster.automatic_failback_enabled = False
    cluster.cluster_generation += 1
    if enabled:
        cluster.keepalived_generation += 1
        cluster.keepalived_status = "PENDING_AGENT"
        cluster.keepalived_requested_at = datetime.utcnow()
        cluster.status = "DEPLOYING"
        for node in cluster.nodes:
            node.keepalived_status = "PENDING_AGENT"
            node.keepalived_last_error = None
    db.add(HAEvent(cluster_id=cluster.id, node_id=None, event_type="automatic_failover_enabled" if enabled else "automatic_failover_disabled", severity="warning" if enabled else "info", source="kaya", message=("Offline automatic failover was enabled. Automatic failback remains disabled." if enabled else "Offline automatic failover was disabled. Existing DNS and DHCP services were not changed."), details_json_redacted=json.dumps({"automatic_failback": False}, sort_keys=True), occurred_at=datetime.utcnow()))
    db.commit()
    db.refresh(cluster)
    return cluster


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
    try:
        report = json.loads(run.report_json or "{}")
    except json.JSONDecodeError:
        report = {}
    report["vip_move_started_at"] = datetime.utcnow().isoformat()
    run.report_json = json.dumps(report, sort_keys=True)
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
    cluster.maintenance_mode = True
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


def _restore_dhcp_after_failed_vip_move(db: Session, run: HAFailoverRun, message: str) -> None:
    run.status = "ROLLING_BACK"
    run.phase = "ROLLBACK_PROMOTING_SOURCE"
    run.error_redacted = message[:1000]
    run.cluster.status = "DEGRADED"
    run.cluster.maintenance_mode = True
    run.cluster.role_generation += 1
    run.cluster.cluster_generation += 1
    run.role_generation = run.cluster.role_generation
    _event(
        db,
        run,
        "controlled_failover_auto_recovery_started",
        "critical",
        f"The virtual IP did not move. {run.source_node.display_name} retained exclusive ownership, so Kaya is restoring DHCP there automatically.",
    )


def _mark_verification_started(run: HAFailoverRun) -> None:
    try:
        report = json.loads(run.report_json or "{}")
    except json.JSONDecodeError:
        report = {}
    report["verification_started_at"] = datetime.utcnow().isoformat()
    run.report_json = json.dumps(report, sort_keys=True)


def _verification_started_at(run: HAFailoverRun) -> datetime:
    try:
        value = json.loads(run.report_json or "{}").get("verification_started_at")
        return datetime.fromisoformat(value) if value else run.started_at
    except (ValueError, TypeError, json.JSONDecodeError):
        return run.started_at


def _vip_move_started_at(run: HAFailoverRun) -> datetime:
    try:
        value = json.loads(run.report_json or "{}").get("vip_move_started_at")
        return datetime.fromisoformat(value) if value else run.started_at
    except (ValueError, TypeError, json.JSONDecodeError):
        return run.started_at


def _vip_move_failure(run: HAFailoverRun) -> str:
    expected = run.target_node if run.phase == "MOVING_VIP" else run.source_node
    owners = [node.display_name for node in run.cluster.nodes if node.vip_owned]
    deployments = ", ".join(
        f"{node.display_name}: {node.keepalived_status.replace('_', ' ').lower()}"
        for node in run.cluster.nodes
    )
    owner_text = ", ".join(owners) if owners else "none reported"
    return (
        f"Virtual IP handover did not converge within 60 seconds. "
        f"Expected {expected.display_name} to become the only owner; current owner reports: {owner_text}. "
        f"Keepalived deployment reports: {deployments}. Use safe rollback after checking both agents."
    )


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
        _mark_verification_started(run)
    elif run.phase == "ROLLBACK_DEMOTING_TARGET":
        node.dhcp_running = False
        run.phase = "ROLLBACK_MOVING_VIP"
        _move_vip(db, run, run.source_node)
    elif run.phase == "ROLLBACK_PROMOTING_SOURCE":
        node.dhcp_running = True
        run.phase = "ROLLBACK_VERIFYING_SOURCE"
        _mark_verification_started(run)
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
    run.cluster.maintenance_mode = False
    run.status = "ROLLED_BACK" if rolled_back else "SUCCEEDED"
    run.phase = "ROLLED_BACK" if rolled_back else "COMPLETE"
    run.completed_at = datetime.utcnow()
    run.error_redacted = None if not rolled_back else run.error_redacted
    # The destination temporarily receives a preempt-capable configuration so
    # it can take the VIP from a nopreempt MASTER. Once ownership and services
    # are verified, immediately restore nopreempt on both nodes to retain the
    # no-automatic-failback safety boundary.
    run.cluster.cluster_generation += 1
    run.cluster.keepalived_generation += 1
    run.cluster.keepalived_status = "PENDING_AGENT"
    run.cluster.keepalived_requested_at = datetime.utcnow()
    run.cluster.status = "DEPLOYING"
    for node in run.cluster.nodes:
        node.keepalived_status = "PENDING_AGENT"
        node.keepalived_last_error = None
    _event(db, run, "controlled_failover_rolled_back" if rolled_back else "controlled_failover_completed", "warning" if rolled_back else "info", f"Controlled transition completed with {active.display_name} active. Automatic failback remains disabled.")


def advance_failover(db: Session, cluster: HACluster) -> HAFailoverRun | None:
    run = active_failover(cluster)
    if run is None:
        return None
    if not run.dhcp_managed and pihole_manages_dhcp(cluster) and any(node.dhcp_running for node in cluster.nodes):
        # Legacy clusters could previously be misclassified from a temporary
        # inactive flag while DHCP was moving. Stop instead of continuing a
        # DNS-only handover around a live DHCP owner.
        run.dhcp_managed = True
        _safe_failure(
            db,
            run,
            "The handover was stopped because this Pi-hole cluster manages DHCP, "
            "but the transition had been started as DNS-only. No further ownership "
            "change was attempted. Use safe rollback to return to the last owner.",
        )
        db.commit()
        return run
    state = cluster.lease_replication
    if run.phase == "WAITING_FOR_LEASES" and state and state.status == "CURRENT" and state.applied_generation >= run.lease_generation:
        run.phase = "DEMOTING_SOURCE"
    elif (
        run.phase == "ROLLBACK_DEMOTING_TARGET"
        and run.source_node.vip_owned
        and not run.target_node.vip_owned
        and not run.target_node.dhcp_running
    ):
        # The failed forward move never left the original VIP owner. Restore
        # DHCP there directly instead of needlessly redeploying Keepalived.
        run.phase = "ROLLBACK_PROMOTING_SOURCE"
    elif run.phase in {"MOVING_VIP", "ROLLBACK_MOVING_VIP"}:
        expected = run.target_node if run.phase == "MOVING_VIP" else run.source_node
        other = run.source_node if run.phase == "MOVING_VIP" else run.target_node
        if expected.vip_owned and not other.vip_owned and all(node.keepalived_status == "DEPLOYED" for node in cluster.nodes):
            if run.phase == "MOVING_VIP":
                run.phase = "PROMOTING_TARGET" if run.dhcp_managed else "VERIFYING_TARGET"
            else:
                run.phase = "ROLLBACK_PROMOTING_SOURCE" if run.dhcp_managed else "ROLLBACK_VERIFYING_SOURCE"
        elif datetime.utcnow() - _vip_move_started_at(run) > timedelta(seconds=60):
            failure = _vip_move_failure(run)
            if (
                run.phase == "MOVING_VIP"
                and run.dhcp_managed
                and run.source_node.vip_owned
                and not run.target_node.vip_owned
                and not run.target_node.dhcp_running
            ):
                _restore_dhcp_after_failed_vip_move(db, run, failure)
            else:
                _safe_failure(db, run, failure)
    if run.phase == "VERIFYING_TARGET":
        dhcp_ok = (run.target_node.dhcp_running and not run.source_node.dhcp_running) if run.dhcp_managed else not any(node.dhcp_running for node in cluster.nodes)
        if run.target_node.vip_owned and not run.source_node.vip_owned and run.target_node.dns_healthy is True and dhcp_ok:
            _complete(db, run, rolled_back=False)
        elif datetime.utcnow() - _verification_started_at(run) > timedelta(seconds=30):
            _safe_failure(db, run, f"{run.target_node.display_name} did not report healthy DNS within 30 seconds. The transition stopped and can be rolled back safely.")
    elif run.phase == "ROLLBACK_VERIFYING_SOURCE":
        dhcp_ok = (run.source_node.dhcp_running and not run.target_node.dhcp_running) if run.dhcp_managed else not any(node.dhcp_running for node in cluster.nodes)
        if run.source_node.vip_owned and not run.target_node.vip_owned and run.source_node.dns_healthy is True and dhcp_ok:
            _complete(db, run, rolled_back=True)
        elif datetime.utcnow() - _verification_started_at(run) > timedelta(seconds=30):
            _safe_failure(db, run, f"{run.source_node.display_name} did not report healthy DNS within 30 seconds during rollback. Manual recovery is required; Kaya will not enable another DHCP owner.")
    db.commit()
    return run


def request_failover_rollback(db: Session, run: HAFailoverRun, *, acknowledged: bool) -> HAFailoverRun:
    recover_unhealthy_active = (
        run.status == "SUCCEEDED"
        and run.target_node.vip_owned
        and run.target_node.dns_healthy is not True
        and run.source_node.dns_healthy is True
    )
    if not acknowledged or (run.status != "FAILED_SAFE" and not recover_unhealthy_active):
        raise HAFailoverError("Confirm rollback of the failed controlled transition.")
    run.status = "ROLLING_BACK"
    run.cluster.maintenance_mode = True
    run.cluster.cluster_generation += 1
    run.cluster.role_generation += 1
    run.role_generation = run.cluster.role_generation
    source_still_owns_vip = run.source_node.vip_owned and not run.target_node.vip_owned
    if source_still_owns_vip and (not run.dhcp_managed or run.source_node.dhcp_running):
        _complete(db, run, rolled_back=True)
    elif source_still_owns_vip and run.dhcp_managed and not run.target_node.dhcp_running:
        run.phase = "ROLLBACK_PROMOTING_SOURCE"
        run.error_redacted = run.error_redacted or "The original node retained the virtual IP and DHCP is being restored there."
        _event(db, run, "controlled_failover_rollback_started", "warning", f"Direct DHCP recovery on {run.source_node.display_name} started because it retained exclusive virtual-IP ownership.")
    else:
        run.phase = "ROLLBACK_DEMOTING_TARGET"
        run.error_redacted = run.error_redacted or ("The promoted node reported unhealthy DNS after handover." if recover_unhealthy_active else "Operator requested rollback.")
        _event(db, run, "controlled_failover_rollback_started", "warning", f"Rollback to {run.source_node.display_name} started.")
    db.commit()
    db.refresh(run)
    return run


def failover_status(run: HAFailoverRun | None) -> dict[str, Any]:
    if run is None:
        return {"running": False, "status": "NOT_STARTED", "phase": "READY", "message": "No controlled failover has been run."}
    labels = {"WAITING_FOR_LEASES": "Capturing the final lease snapshot", "DEMOTING_SOURCE": "Stopping DHCP on the current active node", "MOVING_VIP": "Moving the virtual IP", "PROMOTING_TARGET": "Importing leases and starting DHCP on the target", "VERIFYING_TARGET": "Verifying DNS, DHCP and VIP ownership", "COMPLETE": "Controlled failover completed", "FAILED_SAFE": "Transition stopped safely", "ROLLBACK_DEMOTING_TARGET": "Ensuring DHCP is stopped on the target", "ROLLBACK_MOVING_VIP": "Returning the virtual IP", "ROLLBACK_PROMOTING_SOURCE": "Restoring DHCP on the original node", "ROLLBACK_VERIFYING_SOURCE": "Verifying the restored active node", "ROLLED_BACK": "Original node restored"}
    return {"running": run.status in ACTIVE_RUN_STATUSES, "run_id": run.public_id, "status": run.status, "phase": run.phase, "message": labels.get(run.phase, run.phase.replace("_", " ").title()), "error": run.error_redacted, "source": run.source_node.display_name, "target": run.target_node.display_name, "dhcp_managed": run.dhcp_managed, "started_at": run.started_at.isoformat() if run.started_at else None, "completed_at": run.completed_at.isoformat() if run.completed_at else None}
