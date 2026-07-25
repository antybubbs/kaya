"""Safe, explicit repair workflows for inconsistent HA cluster state."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.security import encrypt_secret
from app.models.models import (
    HABackup,
    HACluster,
    HAEvent,
    HAMaintenanceRun,
    HANode,
    HASyncRun,
    User,
)
from app.services.ha_leases import HALeaseError, reconcile_cluster_leases
from app.services.ha_recovery import evaluate_recovery
from app.services.ha_sync import (
    HASyncError,
    _live_configuration,
    create_sync_plan,
    execute_sync,
)
from app.services.ha_topology import pihole_manages_dhcp
from app.services.ha_validation import _safe_configuration
from app.services.audit import write_audit


FRESH_SECONDS = 45
PROCESS_STARTED_AT = datetime.utcnow()
ACTIVE_STATUSES = {"RUNNING", "PAUSED"}
TERMINAL_STATUSES = {"SUCCEEDED", "FAILED_SAFE", "CANCELLED"}


class HAMaintenanceError(ValueError):
    pass


@dataclass(frozen=True)
class ConsistencyIssue:
    code: str
    title: str
    message: str
    severity: str
    requires_service_movement: bool = False


@dataclass(frozen=True)
class ClusterInspection:
    observed_at: datetime
    fresh_node_ids: tuple[int, ...]
    vip_owner_ids: tuple[int, ...]
    dhcp_owner_ids: tuple[int, ...]
    issues: tuple[ConsistencyIssue, ...]
    service_availability: str
    configuration_state: str

    @property
    def fresh(self) -> bool:
        return len(self.fresh_node_ids) == 2

    @property
    def consistent(self) -> bool:
        return self.fresh and not self.issues


def _fresh(node: HANode, now: datetime, *, since: datetime | None = None) -> bool:
    return bool(
        node.last_heartbeat_at
        and node.last_heartbeat_at >= now - timedelta(seconds=FRESH_SECONDS)
        and (since is None or node.last_heartbeat_at >= since)
    )


def _registered(node: HANode) -> bool:
    credential = node.agent_credential
    return bool(credential and credential.registered_at and credential.revoked_at is None)


def _dhcp_active(node: HANode) -> bool:
    configured = node.dhcp_configured if node.dhcp_configured is not None else node.dhcp_running
    listening = node.dhcp_listener_active if node.dhcp_listener_active is not None else node.dhcp_running
    ftl_active = node.ftl_active if node.ftl_active is not None else True
    return bool(configured and listening and ftl_active and node.dhcp_running)


def _dhcp_released(node: HANode) -> bool:
    configured = node.dhcp_configured if node.dhcp_configured is not None else node.dhcp_running
    listening = node.dhcp_listener_active if node.dhcp_listener_active is not None else node.dhcp_running
    return configured is False and listening is False and node.dhcp_running is False


def inspect_cluster(cluster: HACluster, *, now: datetime | None = None, since: datetime | None = None) -> ClusterInspection:
    current = now or datetime.utcnow()
    fresh_nodes = [node for node in cluster.nodes if _fresh(node, current, since=since)]
    vip_owners = [node for node in fresh_nodes if node.vip_owned]
    dhcp_owners = [node for node in fresh_nodes if _dhcp_active(node)]
    managed = pihole_manages_dhcp(cluster)
    issues: list[ConsistencyIssue] = []

    if len(cluster.nodes) != 2:
        issues.append(ConsistencyIssue(
            "NODE_COUNT",
            "Cluster node configuration is incomplete",
            "A Pi-hole HA cluster requires exactly two existing nodes.",
            "critical",
        ))
    if len(fresh_nodes) != len(cluster.nodes):
        missing = ", ".join(node.display_name for node in cluster.nodes if node not in fresh_nodes)
        issues.append(ConsistencyIssue(
            "STALE_AGENT_STATE",
            "Fresh node inspection is incomplete",
            f"Waiting for a new signed HA Agent report from {missing or 'both nodes'}.",
            "warning",
        ))
    if len(vip_owners) > 1:
        issues.append(ConsistencyIssue(
            "DUPLICATE_VIP",
            "Virtual IP ownership conflict detected",
            "More than one node reports ownership of the DNS Virtual IP.",
            "critical",
            True,
        ))
    elif fresh_nodes and len(vip_owners) == 0:
        issues.append(ConsistencyIssue(
            "NO_VIP_OWNER",
            "No Virtual IP owner reported",
            "Neither current node report shows ownership of the DNS Virtual IP.",
            "critical",
            True,
        ))
    if managed and len(dhcp_owners) > 1:
        issues.append(ConsistencyIssue(
            "MULTIPLE_DHCP",
            "Multiple DHCP servers detected",
            "More than one Pi-hole reports DHCP running. Kaya will not start another DHCP service.",
            "critical",
            True,
        ))
    if managed and len(vip_owners) == 1 and len(dhcp_owners) == 1 and vip_owners[0].id != dhcp_owners[0].id:
        issues.append(ConsistencyIssue(
            "OWNERSHIP_MISMATCH",
            "Cluster ownership mismatch",
            "The DNS Virtual IP and DHCP service are currently owned by different nodes. This can occur after an interrupted setup or HA transition.",
            "critical",
            True,
        ))
    if managed and fresh_nodes and len(dhcp_owners) == 0:
        issues.append(ConsistencyIssue(
            "NO_DHCP_OWNER",
            "No DHCP service owner reported",
            "This cluster is configured to provide DHCP, but neither node reports DHCP running.",
            "critical",
            True,
        ))

    observed_owner = vip_owners[0] if len(vip_owners) == 1 else None
    if observed_owner and (
        cluster.current_active_node_id != observed_owner.id
        or observed_owner.role != "ACTIVE"
        or observed_owner.desired_role != "ACTIVE"
    ):
        issues.append(ConsistencyIssue(
            "STORED_ROLE_MISMATCH",
            "Stored HA state does not match observed node state",
            f"{observed_owner.display_name} owns the Virtual IP, but Kaya's stored Active/Standby assignment does not match.",
            "warning",
        ))
    for node in fresh_nodes:
        if (
            node.recovery_state in {"RECOVERING", "SYNCHRONISING", "VERIFYING"}
            and node.recovery_started_at
            and node.recovery_started_at < current - timedelta(minutes=5)
            and node.dns_healthy is True
            and node.keepalived_runtime_state == "RUNNING"
            and (
                node.vip_owned
                or (node.observed_role == "STANDBY" and not node.vip_owned and (not managed or not node.dhcp_running))
            )
        ):
            issues.append(ConsistencyIssue(
                "STALE_RECOVERY_STATE",
                "Recovery state appears stale",
                f"{node.display_name} has reported stable runtime health but remains marked {node.recovery_state.replace('_', ' ').title()}.",
                "warning",
            ))

    if observed_owner:
        service_ok = observed_owner.dns_healthy is True and (
            not managed or (len(dhcp_owners) == 1 and dhcp_owners[0].id == observed_owner.id)
        )
        availability = "HEALTHY" if service_ok else "AVAILABLE_WITH_RISK" if observed_owner.dns_healthy is True else "DEGRADED"
    else:
        availability = "DEGRADED"
    configuration = "CONSISTENT" if fresh_nodes and not issues else "INCONSISTENT"
    return ClusterInspection(
        observed_at=current,
        fresh_node_ids=tuple(node.id for node in fresh_nodes),
        vip_owner_ids=tuple(node.id for node in vip_owners),
        dhcp_owner_ids=tuple(node.id for node in dhcp_owners),
        issues=tuple(issues),
        service_availability=availability,
        configuration_state=configuration,
    )


def inspection_json(cluster: HACluster, inspection: ClusterInspection) -> dict[str, Any]:
    node_by_id = {node.id: node for node in cluster.nodes}
    return {
        "observed_at": inspection.observed_at.isoformat() + "Z",
        "fresh": inspection.fresh,
        "consistent": inspection.consistent,
        "service_availability": inspection.service_availability,
        "configuration_state": inspection.configuration_state,
        "vip_owners": [node_by_id[node_id].display_name for node_id in inspection.vip_owner_ids],
        "dhcp_owners": [node_by_id[node_id].display_name for node_id in inspection.dhcp_owner_ids],
        "issues": [asdict(issue) for issue in inspection.issues],
        "nodes": [{
            "id": node.public_id,
            "name": node.display_name,
            "address": node.management_host,
            "agent_connected": node.id in inspection.fresh_node_ids and _registered(node),
            "agent_generation": node.observed_generation,
            "dns_healthy": node.dns_healthy,
            "dhcp_running": node.dhcp_running,
            "dhcp_configured": node.dhcp_configured,
            "dhcp_listener_active": node.dhcp_listener_active,
            "ftl_active": node.ftl_active,
            "vip_owned": node.vip_owned,
            "keepalived_running": node.keepalived_runtime_state == "RUNNING",
            "network_interface": node.network_interface,
            "configuration_generation": node.config_generation,
            "role_generation": node.observed_generation,
            "lease_generation": node.lease_generation,
            "recovery_state": node.recovery_state,
            "last_heartbeat_at": node.last_heartbeat_at.isoformat() + "Z" if node.last_heartbeat_at else None,
        } for node in cluster.nodes],
    }


def latest_maintenance(cluster: HACluster) -> HAMaintenanceRun | None:
    return max(cluster.maintenance_runs, key=lambda item: item.created_at) if cluster.maintenance_runs else None


def active_maintenance(cluster: HACluster) -> HAMaintenanceRun | None:
    return next((
        item for item in sorted(cluster.maintenance_runs, key=lambda value: value.created_at, reverse=True)
        if item.status in ACTIVE_STATUSES
    ), None)


def _event(db: Session, run: HAMaintenanceRun, event_type: str, severity: str, message: str, details: dict[str, Any] | None = None) -> None:
    safe_details = {"maintenance_run_id": run.public_id, "operation": run.operation, "phase": run.phase}
    safe_details.update(details or {})
    db.add(HAEvent(
        cluster_id=run.cluster_id,
        node_id=None,
        event_type=event_type,
        severity=severity,
        source="kaya",
        message=message[:1000],
        details_json_redacted=json.dumps(safe_details, sort_keys=True, separators=(",", ":")),
        occurred_at=datetime.utcnow(),
    ))


def _snapshot_state(cluster: HACluster) -> dict[str, Any]:
    return {
        "automatic_failover_enabled": bool(cluster.automatic_failover_enabled),
        "automatic_sync_enabled": bool(cluster.automatic_sync_enabled),
        "automatic_sync_allow_deletions": bool(cluster.automatic_sync_allow_deletions),
        "authoritative_node_id": cluster.authoritative_node_id,
        "current_active_node_id": cluster.current_active_node_id,
        "status": cluster.status,
        "nodes": [{
            "id": node.id,
            "role": node.role,
            "desired_role": node.desired_role,
            "recovery_state": node.recovery_state,
            "vip_owned": bool(node.vip_owned),
            "dhcp_running": bool(node.dhcp_running),
        } for node in cluster.nodes],
    }


def start_reconciliation(db: Session, cluster: HACluster, user: User) -> HAMaintenanceRun:
    if active_maintenance(cluster):
        raise HAMaintenanceError("Cluster maintenance is already in progress.")
    from app.services.ha_failover import active_failover
    if active_failover(cluster):
        raise HAMaintenanceError("Wait for the current failover or rollback operation to finish.")
    run = HAMaintenanceRun(
        cluster_id=cluster.id,
        operation="RECONCILE",
        status="RUNNING",
        phase="WAITING_FOR_REPORTS",
        previous_state_json=json.dumps(_snapshot_state(cluster), sort_keys=True),
        requested_by_user_id=user.id,
    )
    db.add(run)
    db.flush()
    _event(db, run, "cluster_reconciliation_started", "info", "Cluster reconciliation started. Kaya is waiting for fresh signed reports from both nodes.")
    db.commit()
    db.refresh(run)
    return run


def reconcile_cluster_state(db: Session, run: HAMaintenanceRun) -> HAMaintenanceRun:
    if run.operation != "RECONCILE" or run.status not in ACTIVE_STATUSES:
        return run
    inspection = inspect_cluster(run.cluster, since=run.started_at)
    run.result_json = json.dumps(inspection_json(run.cluster, inspection), sort_keys=True)
    if not inspection.fresh:
        run.phase = "WAITING_FOR_REPORTS"
        db.commit()
        return run

    run.phase = "RECONCILING"
    clean_owner = (
        len(inspection.vip_owner_ids) == 1
        and (
            not pihole_manages_dhcp(run.cluster)
            or (
                len(inspection.dhcp_owner_ids) == 1
                and inspection.dhcp_owner_ids[0] == inspection.vip_owner_ids[0]
            )
        )
    )
    corrected: list[str] = []
    reported_cluster_generations = {node.observed_generation for node in run.cluster.nodes}
    if (
        len(reported_cluster_generations) == 1
        and None not in reported_cluster_generations
        and next(iter(reported_cluster_generations)) > run.cluster.cluster_generation
    ):
        run.cluster.cluster_generation = next(iter(reported_cluster_generations))
        corrected.append("cluster generation")
    reported_config_generations = {node.config_generation for node in run.cluster.nodes}
    if (
        len(reported_config_generations) == 1
        and next(iter(reported_config_generations)) > run.cluster.keepalived_generation
    ):
        run.cluster.keepalived_generation = next(iter(reported_config_generations))
        corrected.append("Keepalived generation")
    if clean_owner:
        owner_id = inspection.vip_owner_ids[0]
        if run.cluster.current_active_node_id != owner_id:
            run.cluster.current_active_node_id = owner_id
            corrected.append("current Active node")
        if run.cluster.authoritative_node_id != owner_id:
            run.cluster.authoritative_node_id = owner_id
            corrected.append("configuration authority")
        for node in run.cluster.nodes:
            role = "ACTIVE" if node.id == owner_id else "STANDBY"
            if node.role != role or node.desired_role != role:
                node.role = node.desired_role = role
                corrected.append(f"{node.display_name} stored role")
    evaluate_recovery(db, run.cluster, stability_seconds=0)
    final = inspect_cluster(run.cluster)
    run.result_json = json.dumps({
        **inspection_json(run.cluster, final),
        "corrected": corrected,
        "service_movement_performed": False,
    }, sort_keys=True)
    run.status = "SUCCEEDED"
    run.phase = "COMPLETE"
    run.completed_at = datetime.utcnow()
    if any(issue.requires_service_movement for issue in final.issues):
        message = f"Reconciliation corrected {len(corrected)} stale state record(s). A service ownership mismatch remains and requires cluster reinitialisation."
    else:
        message = f"Cluster reconciliation completed without moving services. Kaya corrected {len(corrected)} stale state record(s)."
    _event(db, run, "cluster_reconciliation_completed", "warning" if final.issues else "info", message, {"corrected_count": len(corrected), "remaining_issue_codes": [issue.code for issue in final.issues]})
    db.commit()
    write_audit(
        db,
        run.requested_by,
        "complete",
        "ha_cluster_reconciliation",
        run.cluster.public_id,
        detail=message,
        metadata={"maintenance_run_id": run.public_id, "service_movement_performed": False},
    )
    return run


def start_reinitialisation(
    db: Session,
    cluster: HACluster,
    user: User,
    *,
    desired_active: HANode,
    authority: HANode,
    acknowledged: bool,
) -> HAMaintenanceRun:
    if not acknowledged:
        raise HAMaintenanceError("Confirm that Kaya may rebuild HA ownership while preserving Pi-hole data and cluster history.")
    if desired_active not in cluster.nodes or authority not in cluster.nodes:
        raise HAMaintenanceError("The selected nodes do not belong to this cluster.")
    if len(cluster.nodes) != 2:
        raise HAMaintenanceError("Reinitialisation requires exactly two existing nodes.")
    if active_maintenance(cluster):
        raise HAMaintenanceError("Cluster maintenance is already in progress.")
    from app.services.ha_failover import active_failover
    if active_failover(cluster):
        raise HAMaintenanceError("Wait for the current failover or rollback operation to finish.")

    prior_run = latest_maintenance(cluster)
    if prior_run and prior_run.operation == "REINITIALISE" and prior_run.status == "FAILED_SAFE":
        try:
            previous = json.loads(prior_run.previous_state_json or "{}")
        except json.JSONDecodeError:
            previous = _snapshot_state(cluster)
    else:
        previous = _snapshot_state(cluster)
    run = HAMaintenanceRun(
        cluster_id=cluster.id,
        operation="REINITIALISE",
        status="RUNNING",
        phase="WAITING_FOR_REPORTS",
        desired_active_node_id=desired_active.id,
        authoritative_node_id=authority.id,
        previous_state_json=json.dumps(previous, sort_keys=True),
        result_json=json.dumps({"progress": ["Waiting for fresh signed node reports"]}, sort_keys=True),
        requested_by_user_id=user.id,
    )
    cluster.maintenance_mode = True
    cluster.automatic_failover_enabled = False
    cluster.automatic_sync_enabled = False
    db.add(run)
    db.flush()
    _event(
        db,
        run,
        "cluster_reinitialisation_started",
        "warning",
        f"Cluster reinitialisation started with {desired_active.display_name} selected as Active.",
        {"desired_active_node_id": desired_active.public_id, "authoritative_node_id": authority.public_id},
    )
    db.commit()
    db.refresh(run)
    return run


def _set_phase(run: HAMaintenanceRun, phase: str, progress: str) -> None:
    run.phase = phase
    run.phase_started_at = datetime.utcnow()
    try:
        result = json.loads(run.result_json or "{}")
    except json.JSONDecodeError:
        result = {}
    rows = list(result.get("progress") or [])
    if not rows or rows[-1] != progress:
        rows.append(progress)
    result["progress"] = rows[-20:]
    run.result_json = json.dumps(result, sort_keys=True)


def _fail_safe(db: Session, run: HAMaintenanceRun, message: str) -> HAMaintenanceRun:
    run.status = "FAILED_SAFE"
    run.phase = "PAUSED"
    run.error_redacted = message[:1000]
    run.completed_at = datetime.utcnow()
    run.cluster.status = "DEGRADED"
    _event(db, run, "cluster_reinitialisation_failed", "critical", message[:1000])
    db.commit()
    write_audit(
        db,
        run.requested_by,
        "fail_safe",
        "ha_cluster_reinitialisation",
        run.cluster.public_id,
        detail=message[:1000],
        severity="warning",
        metadata={"maintenance_run_id": run.public_id, "phase": run.phase},
    )
    return run


def _create_two_node_backups(db: Session, run: HAMaintenanceRun) -> HASyncRun:
    cluster = run.cluster
    cluster.authoritative_node_id = run.authoritative_node_id
    raw_snapshots: dict[int, dict[str, Any]] = {}
    for node in cluster.nodes:
        _, configuration = _live_configuration(node)
        safe = {key: _safe_configuration(value) for key, value in configuration.items()}
        from app.services.ha_dns_advertisement import preserve_cached_dns_advertisement

        snapshot_text = json.dumps(
            preserve_cached_dns_advertisement(node, safe),
            sort_keys=True,
            separators=(",", ":"),
        )
        node.configuration_snapshot_json = snapshot_text
        node.configuration_checksum = hashlib.sha256(snapshot_text.encode()).hexdigest()
        raw_snapshots[node.id] = safe
    db.commit()
    sync_run = create_sync_plan(db, cluster, run.requested_by)
    for node in cluster.nodes:
        backup_text = json.dumps(raw_snapshots[node.id], sort_keys=True, separators=(",", ":"))
        db.add(HABackup(
            sync_run_id=sync_run.id,
            node_id=node.id,
            encrypted_snapshot=encrypt_secret(backup_text),
            checksum=hashlib.sha256(backup_text.encode()).hexdigest(),
        ))
    run.sync_run_id = sync_run.id
    db.commit()
    return sync_run


def _maintenance_checksum(run: HAMaintenanceRun, node: HANode, action_type: str) -> str:
    return hashlib.sha256(f"{action_type}:{run.public_id}:{run.cluster.role_generation}:{node.public_id}".encode()).hexdigest()


def desired_maintenance_action(cluster: HACluster, node: HANode) -> dict[str, Any] | None:
    run = active_maintenance(cluster)
    if run is None or run.operation != "REINITIALISE" or run.status != "RUNNING":
        return None
    target = run.desired_active_node
    if target is None:
        return None
    action_type = None
    if run.phase == "DEMOTING_STANDBY" and node.id != target.id and node.dhcp_running:
        action_type = "DHCP_DEMOTE"
    elif run.phase == "PROMOTING_ACTIVE" and node.id == target.id and not node.dhcp_running:
        action_type = "DHCP_PROMOTE"
    if action_type is None:
        return None
    checksum = _maintenance_checksum(run, node, action_type)
    return {
        "action_id": f"maintenance:{run.public_id}:{action_type.lower()}:{node.public_id}",
        "action_type": action_type,
        "generation": run.cluster.role_generation,
        "checksum": checksum,
        "maintenance_run_id": run.public_id,
        "automatic": False,
        "lease_generation": run.cluster.lease_replication.desired_generation if run.cluster.lease_replication else 0,
        "restore_original": False,
    }


def record_maintenance_action_result(
    db: Session,
    node: HANode,
    *,
    action_type: str,
    generation: int,
    checksum: str | None,
    status: str,
    message: str,
) -> HAMaintenanceRun:
    run = active_maintenance(node.cluster)
    expected = desired_maintenance_action(node.cluster, node)
    if run is None or expected is None or generation != expected["generation"] or checksum != expected["checksum"]:
        raise HAMaintenanceError("The maintenance result does not match the current repair generation.")
    if status != "APPLIED":
        if run.phase == "DEMOTING_STANDBY":
            _set_phase(run, "VERIFYING_DHCP_RELEASE", f"Unexpected response while stopping DHCP on {node.display_name}; checking its fresh configuration and UDP/67 state")
        elif run.phase == "PROMOTING_ACTIVE":
            _set_phase(run, "VERIFYING_DHCP_ACTIVATION", f"Unexpected response while starting DHCP on {node.display_name}; checking the final two-node topology")
        else:
            return _fail_safe(db, run, message or f"{action_type} failed safely.")
        run.error_redacted = str(message or f"{action_type} returned an unexpected result.")[:1000]
        _event(
            db,
            run,
            "cluster_reinitialisation_dhcp_warning",
            "warning",
            f"{node.display_name} returned an unexpected DHCP result. Kaya is verifying observed state before deciding whether repair failed.",
            {"node_id": node.public_id, "action_type": action_type},
        )
        db.commit()
        return run
    if run.phase == "DEMOTING_STANDBY":
        node.dhcp_running = False
        _set_phase(run, "REBUILDING_HA", f"DHCP stopped and verified on {node.display_name}")
    elif run.phase == "PROMOTING_ACTIVE":
        node.dhcp_running = True
        _set_phase(run, "VERIFYING", f"DHCP started and verified on {node.display_name}")
    db.commit()
    return run


def _request_runtime_rebuild(db: Session, run: HAMaintenanceRun) -> None:
    cluster = run.cluster
    target = run.desired_active_node
    if target is None:
        raise HAMaintenanceError("The selected Active node no longer exists.")
    cluster.role_generation += 1
    cluster.cluster_generation += 1
    cluster.keepalived_generation += 1
    cluster.keepalived_status = "PENDING_AGENT"
    cluster.keepalived_requested_at = datetime.utcnow()
    cluster.status = "DEPLOYING"
    for node in cluster.nodes:
        active = node.id == target.id
        node.desired_role = "ACTIVE" if active else "STANDBY"
        node.vrrp_priority = 150 if active else 100
        node.keepalived_status = "PENDING_AGENT"
        node.keepalived_last_error = None
    _set_phase(run, "WAITING_FOR_VIP", f"HA runtime configuration queued with {target.display_name} selected as Active")
    db.commit()


def validate_cluster_invariants(run: HAMaintenanceRun, *, now: datetime | None = None) -> list[str]:
    cluster = run.cluster
    target = run.desired_active_node
    inspection = inspect_cluster(cluster, now=now, since=run.phase_started_at)
    blockers: list[str] = []
    if not inspection.fresh:
        blockers.append("Waiting for fresh signed reports from both nodes.")
    if target is None:
        blockers.append("The selected Active node no longer exists.")
        return blockers
    if inspection.vip_owner_ids != (target.id,):
        blockers.append(f"{target.display_name} is not yet the only Virtual IP owner.")
    if pihole_manages_dhcp(cluster) and inspection.dhcp_owner_ids != (target.id,):
        blockers.append(f"{target.display_name} is not yet the only DHCP-active node.")
    if any(node.dns_healthy is not True for node in cluster.nodes):
        blockers.append("DNS must be healthy on both nodes.")
    if any(not _registered(node) for node in cluster.nodes):
        blockers.append("Both registered HA Agent identities must be reporting.")
    if any(node.keepalived_status != "DEPLOYED" or node.keepalived_runtime_state != "RUNNING" for node in cluster.nodes):
        blockers.append("Keepalived must be deployed and running on both nodes.")
    if any(node.config_generation < cluster.keepalived_generation for node in cluster.nodes):
        blockers.append("Both nodes must report the current HA configuration generation.")
    if pihole_manages_dhcp(cluster):
        state = cluster.lease_replication
        standby = next(node for node in cluster.nodes if node.id != target.id)
        if not state or state.status != "CURRENT" or state.target_node_id != standby.id or standby.lease_generation < state.desired_generation:
            blockers.append("The standby must stage the current validated DHCP generation.")
    return list(dict.fromkeys(blockers))


def advance_reinitialisation(db: Session, run: HAMaintenanceRun) -> HAMaintenanceRun:
    if run.operation != "REINITIALISE" or run.status != "RUNNING":
        return run
    cluster = run.cluster
    target = run.desired_active_node
    if target is None:
        return _fail_safe(db, run, "The selected Active node no longer exists.")
    standby = next(node for node in cluster.nodes if node.id != target.id)
    try:
        try:
            process_marker = json.loads(run.result_json or "{}").get("resumed_for_process_started_at")
        except json.JSONDecodeError:
            process_marker = None
        current_process_marker = PROCESS_STARTED_AT.isoformat()
        if run.started_at < PROCESS_STARTED_AT and process_marker != current_process_marker:
            _set_phase(
                run,
                "WAITING_FOR_REPORTS",
                "Kaya restarted; the repair sequence is restarting from fresh signed node reports",
            )
            resumed_result = json.loads(run.result_json or "{}")
            resumed_result["resumed_for_process_started_at"] = current_process_marker
            run.result_json = json.dumps(resumed_result, sort_keys=True)
            db.commit()
            return run
        if run.phase == "WAITING_FOR_REPORTS":
            inspection = inspect_cluster(cluster, since=run.phase_started_at)
            run.result_json = json.dumps({**inspection_json(cluster, inspection), "progress": ["Waiting for fresh signed node reports"]}, sort_keys=True)
            if not inspection.fresh:
                db.commit()
                return run
            _set_phase(run, "BACKING_UP", "Fresh signed reports received from both nodes")
        elif run.phase == "BACKING_UP":
            sync_run = _create_two_node_backups(db, run)
            _event(db, run, "cluster_reinitialisation_backups_completed", "info", "Encrypted Pi-hole configuration backups were created for both nodes before any service ownership change.", {"sync_run_id": sync_run.public_id})
            _set_phase(run, "SYNCHRONISING", "Encrypted configuration backups created for both nodes")
        elif run.phase == "SYNCHRONISING":
            sync_run = db.get(HASyncRun, run.sync_run_id)
            if sync_run is None:
                raise HAMaintenanceError("The protected synchronisation plan is missing.")
            if sync_run.status == "PLANNED":
                execute_sync(db, cluster, sync_run, allow_deletions=True, maintenance_authorised=True)
            elif sync_run.status not in {"IN_SYNC", "SUCCEEDED"}:
                raise HAMaintenanceError("The protected configuration synchronisation did not complete.")
            if pihole_manages_dhcp(cluster):
                _set_phase(run, "STAGING_DHCP", "Supported configuration synchronised and verified")
            else:
                _set_phase(run, "NORMALISING_STANDBY", "Supported configuration synchronised and verified")
        elif run.phase == "STAGING_DHCP":
            state = reconcile_cluster_leases(db, cluster)
            if state.conflict_count:
                raise HAMaintenanceError("The DHCP lease snapshot contains conflicts and cannot be staged safely.")
            _set_phase(run, "WAITING_FOR_DHCP_STAGE", "Validated DHCP lease snapshot queued for the selected standby")
        elif run.phase == "WAITING_FOR_DHCP_STAGE":
            state = cluster.lease_replication
            if not state or state.status != "CURRENT" or state.target_node_id != standby.id or standby.lease_generation < state.desired_generation:
                db.commit()
                return run
            _set_phase(run, "NORMALISING_STANDBY", "Current DHCP generation staged on the selected standby")
        elif run.phase == "NORMALISING_STANDBY":
            if pihole_manages_dhcp(cluster) and standby.dhcp_running:
                _set_phase(run, "DEMOTING_STANDBY", f"Stopping DHCP on {standby.display_name} before changing Virtual IP ownership")
            else:
                _set_phase(run, "REBUILDING_HA", f"{standby.display_name} is safe as standby")
        elif run.phase == "DEMOTING_STANDBY":
            db.commit()
            return run
        elif run.phase == "VERIFYING_DHCP_RELEASE":
            if _dhcp_released(standby):
                _set_phase(run, "REBUILDING_HA", f"{standby.display_name} has now confirmed DHCP disabled and UDP/67 released")
                run.error_redacted = None
            elif datetime.utcnow() - run.phase_started_at > timedelta(seconds=45):
                return _fail_safe(db, run, f"{standby.display_name} still reports DHCP configured or UDP port 67 listening after the bounded release window. Reinitialisation stopped before another DHCP owner was enabled.")
        elif run.phase == "REBUILDING_HA":
            _request_runtime_rebuild(db, run)
        elif run.phase == "WAITING_FOR_VIP":
            fresh = inspect_cluster(cluster, since=run.phase_started_at)
            failed_nodes = [node for node in cluster.nodes if node.keepalived_status == "ERROR"]
            if failed_nodes:
                detail = " ".join(
                    f"{node.display_name}: {node.keepalived_last_error or 'Keepalived configuration was rejected.'}"
                    for node in failed_nodes
                )
                return _fail_safe(db, run, "The HA runtime rebuild stopped safely. " + detail)
            if not fresh.fresh or any(node.keepalived_status != "DEPLOYED" for node in cluster.nodes):
                db.commit()
                return run
            if fresh.vip_owner_ids != (target.id,):
                if datetime.utcnow() - run.phase_started_at > timedelta(seconds=90):
                    return _fail_safe(db, run, f"Kaya could not confirm that {target.display_name} became the only Virtual IP owner. No additional DHCP service was started.")
                db.commit()
                return run
            if pihole_manages_dhcp(cluster) and not target.dhcp_running:
                _set_phase(run, "PROMOTING_ACTIVE", f"{target.display_name} exclusively owns the Virtual IP; starting DHCP there")
            else:
                _set_phase(run, "VERIFYING", f"{target.display_name} exclusively owns the Virtual IP")
        elif run.phase == "PROMOTING_ACTIVE":
            db.commit()
            return run
        elif run.phase == "VERIFYING_DHCP_ACTIVATION":
            fresh = inspect_cluster(cluster, since=run.phase_started_at)
            if (
                fresh.fresh
                and fresh.vip_owner_ids == (target.id,)
                and fresh.dhcp_owner_ids == (target.id,)
                and _dhcp_released(standby)
                and target.dns_healthy is True
            ):
                _set_phase(run, "VERIFYING", f"Final inspection confirmed {target.display_name} exclusively owns the Virtual IP and DHCP")
                run.error_redacted = None
            elif datetime.utcnow() - run.phase_started_at > timedelta(seconds=45):
                return _fail_safe(db, run, "Final DHCP activation verification did not converge. Kaya could not confirm exactly one VIP and DHCP owner, so repair stopped without issuing another ownership change.")
        elif run.phase == "VERIFYING":
            blockers = validate_cluster_invariants(run)
            if blockers:
                if datetime.utcnow() - run.phase_started_at > timedelta(seconds=90):
                    return _fail_safe(db, run, "Final HA validation stopped safely: " + " ".join(blockers))
                db.commit()
                return run
            for node in cluster.nodes:
                active = node.id == target.id
                node.role = node.desired_role = "ACTIVE" if active else "STANDBY"
                node.recovery_state = "ACTIVE" if active else "STANDBY_READY"
                node.recovery_started_at = None
                node.recovery_stable_since = datetime.utcnow() if not active else None
            cluster.current_active_node_id = target.id
            cluster.authoritative_node_id = run.authoritative_node_id
            cluster.status = "HEALTHY"
            cluster.maintenance_mode = False
            previous = json.loads(run.previous_state_json or "{}")
            cluster.automatic_failover_enabled = bool(previous.get("automatic_failover_enabled"))
            cluster.automatic_sync_enabled = bool(previous.get("automatic_sync_enabled"))
            cluster.automatic_sync_allow_deletions = bool(previous.get("automatic_sync_allow_deletions"))
            run.status = "SUCCEEDED"
            run.phase = "COMPLETE"
            run.completed_at = datetime.utcnow()
            run.error_redacted = None
            result = inspection_json(cluster, inspect_cluster(cluster))
            result["progress"] = list(json.loads(run.result_json or "{}").get("progress") or []) + ["Final invariants verified; HA automation restored"]
            run.result_json = json.dumps(result, sort_keys=True)
            _event(db, run, "cluster_reinitialisation_completed", "info", f"Cluster reinitialised with {target.display_name} as the exclusive Active node.", {"selected_active_node_id": target.public_id, "selected_standby_node_id": standby.public_id})
        db.commit()
        if run.status == "SUCCEEDED":
            write_audit(
                db,
                run.requested_by,
                "complete",
                "ha_cluster_reinitialisation",
                cluster.public_id,
                detail=f"Cluster reinitialised with {target.display_name} as the exclusive Active node.",
                metadata={
                    "maintenance_run_id": run.public_id,
                    "desired_active_node_id": target.public_id,
                    "authoritative_node_id": run.authoritative_node.public_id if run.authoritative_node else None,
                },
            )
        return run
    except (HASyncError, HALeaseError, HAMaintenanceError, ValueError) as exc:
        db.rollback()
        run = db.get(HAMaintenanceRun, run.id)
        return _fail_safe(db, run, str(exc))
    except Exception:
        db.rollback()
        run = db.get(HAMaintenanceRun, run.id)
        return _fail_safe(
            db,
            run,
            "Cluster repair stopped because an unexpected internal error occurred. No further repair actions were issued.",
        )


def maintenance_status(run: HAMaintenanceRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    try:
        result = json.loads(run.result_json or "{}")
    except json.JSONDecodeError:
        result = {}
    return {
        "id": run.public_id,
        "operation": run.operation,
        "status": run.status,
        "phase": run.phase,
        "error": run.error_redacted,
        "desired_active_node_id": run.desired_active_node.public_id if run.desired_active_node else None,
        "desired_active_name": run.desired_active_node.display_name if run.desired_active_node else None,
        "authoritative_name": run.authoritative_node.display_name if run.authoritative_node else None,
        "progress": list(result.get("progress") or []),
        "inspection": result,
        "started_at": run.started_at.isoformat() + "Z" if run.started_at else None,
        "completed_at": run.completed_at.isoformat() + "Z" if run.completed_at else None,
    }
