"""Safe, explicit repair workflows for inconsistent HA cluster state."""

from __future__ import annotations

import hashlib
import json
import logging
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
from app.services.ha_agent_installer import version_tuple
from app.services.ha_recovery import evaluate_recovery
from app.services.ha_sync import (
    HASyncError,
    _live_configuration,
    create_sync_plan,
    execute_sync,
)
from app.services.ha_topology import (
    dhcp_observation,
    heartbeat_is_fresh,
    pihole_manages_dhcp,
    reconcile_topology,
)
from app.services.ha_validation import _safe_configuration
from app.services.audit import write_audit


logger = logging.getLogger(__name__)


FRESH_SECONDS = 45
PROCESS_STARTED_AT = datetime.utcnow()
ACTIVE_STATUSES = {"RUNNING", "PAUSED"}
TERMINAL_STATUSES = {"SUCCEEDED", "FAILED_SAFE", "CANCELLED"}
REINITIALISATION_PHASES = (
    "WAITING_FOR_REPORTS",
    "BACKING_UP",
    "SYNCHRONISING",
    "STAGING_DHCP",
    "WAITING_FOR_DHCP_STAGE",
    "NORMALISING_STANDBY",
    "DEMOTING_STANDBY",
    "VERIFYING_DHCP_RELEASE",
    "REBUILDING_HA",
    "WAITING_FOR_VIP",
    "PROMOTING_ACTIVE",
    "VERIFYING_DHCP_ACTIVATION",
    "VERIFYING",
    "COMPLETE",
)
DHCP_SELF_HEAL_PHASES = (
    "REPAIRING_DHCP",
    "VERIFYING_DHCP_REPAIR",
    "COMPLETE",
)
# Configuration-only DHCP repair was introduced in 0.2.11. Older agents would
# interpret DHCP_PROMOTE as a lease restore and must not receive this repair.
DHCP_SELF_HEAL_AGENT_VERSION = (0, 2, 11)


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
    return heartbeat_is_fresh(node, now, since=since, freshness_seconds=FRESH_SECONDS)


def _registered(node: HANode) -> bool:
    credential = node.agent_credential
    return bool(credential and credential.registered_at and credential.revoked_at is None)


def _dhcp_active(node: HANode) -> bool:
    return dhcp_observation(node, datetime.utcnow(), freshness_seconds=FRESH_SECONDS).active


def _dhcp_released(node: HANode) -> bool:
    return dhcp_observation(node, datetime.utcnow(), freshness_seconds=FRESH_SECONDS).released


def inspect_cluster(cluster: HACluster, *, now: datetime | None = None, since: datetime | None = None) -> ClusterInspection:
    current = now or datetime.utcnow()
    managed = pihole_manages_dhcp(cluster)
    topology = reconcile_topology(cluster, now=current, since=since, freshness_seconds=FRESH_SECONDS)
    fresh_nodes = [node for node in cluster.nodes if node.id in topology.fresh_node_ids]
    issues = [ConsistencyIssue(issue.code, issue.title, issue.message, issue.severity, issue.requires_service_movement) for issue in topology.issues]
    observed_owner = next((node for node in cluster.nodes if node.id == topology.active_node_id), None)
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
                or (node.observed_role == "STANDBY" and not node.vip_owned and (not managed or _dhcp_released(node)))
            )
        ):
            issues.append(ConsistencyIssue(
                "STALE_RECOVERY_STATE",
                "Recovery state appears stale",
                f"{node.display_name} has reported stable runtime health but remains marked {node.recovery_state.replace('_', ' ').title()}.",
                "warning",
            ))

    return ClusterInspection(
        observed_at=current,
        fresh_node_ids=topology.fresh_node_ids,
        vip_owner_ids=topology.vip_owner_ids,
        dhcp_owner_ids=topology.dhcp_owner_ids,
        issues=tuple(issues),
        service_availability=topology.service_availability,
        configuration_state=topology.configuration_state,
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
            "dhcp_runtime_state": node.dhcp_runtime_state,
            "dhcp_observation_status": node.dhcp_observation_status,
            "dhcp_observed_at": node.dhcp_observed_at.isoformat() + "Z" if node.dhcp_observed_at else None,
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


def _hard_failover_proof(db: Session, cluster: HACluster, owner: HANode, now: datetime) -> bool:
    """Accept the local agent's bounded failover proof when the failed peer is offline."""
    events = (
        db.query(HAEvent)
        .filter(
            HAEvent.cluster_id == cluster.id,
            HAEvent.node_id == owner.id,
            HAEvent.source == "agent",
            HAEvent.event_type == "automatic_failover_completed",
            HAEvent.received_at >= now - timedelta(minutes=10),
        )
        .order_by(HAEvent.received_at.desc())
        .limit(20)
        .all()
    )
    for event in events:
        try:
            if int(json.loads(event.details_json_redacted or "{}").get("generation", -1)) == cluster.keepalived_generation:
                return True
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    return False


def _result_document(run: HAMaintenanceRun) -> dict[str, Any]:
    try:
        result = json.loads(run.result_json or "{}")
    except json.JSONDecodeError:
        return {}
    return result if isinstance(result, dict) else {}


def _dhcp_topology_fingerprint(cluster: HACluster, topology, now: datetime) -> str:
    """Fingerprint meaningful HA evidence, never heartbeat timestamps or counters."""
    nodes = []
    for node in sorted(cluster.nodes, key=lambda item: item.id):
        observation = dhcp_observation(node, now)
        nodes.append({
            "node_id": node.public_id,
            "desired_role": node.desired_role,
            "observed_role": node.observed_role,
            "vip_owned": node.vip_owned if node.id in topology.fresh_node_ids else None,
            "dhcp_state": observation.state,
            "dhcp_configured": observation.configured,
            "ftl_active": observation.service_active,
            "udp67_listening": observation.listening,
            "dns_healthy": node.dns_healthy if node.id in topology.fresh_node_ids else None,
            "config_generation": node.config_generation,
            "agent_version": node.agent_version,
        })
    evidence = {
        "fresh_node_ids": sorted(node.public_id for node in cluster.nodes if node.id in topology.fresh_node_ids),
        "vip_owner_ids": sorted(node.public_id for node in cluster.nodes if node.id in topology.vip_owner_ids),
        "dhcp_owner_ids": sorted(node.public_id for node in cluster.nodes if node.id in topology.dhcp_owner_ids),
        "nodes": nodes,
    }
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _clear_changed_dhcp_failure_latches(db: Session, cluster: HACluster, topology_fingerprint: str) -> None:
    changed = False
    failed_runs = db.query(HAMaintenanceRun).filter(
        HAMaintenanceRun.cluster_id == cluster.id,
        HAMaintenanceRun.operation == "DHCP_SELF_HEAL",
        HAMaintenanceRun.status == "FAILED_SAFE",
    ).all()
    for failed in failed_runs:
        result = _result_document(failed)
        if result.get("latch_active") is True and result.get("topology_fingerprint") != topology_fingerprint:
            result.update({
                "latch_active": False,
                "latch_cleared_at": datetime.utcnow().isoformat() + "Z",
                "latch_cleared_reason": "material_topology_change",
            })
            failed.result_json = json.dumps(result, sort_keys=True)
            changed = True
    if changed:
        db.commit()


def _matching_dhcp_failure_latch(db: Session, cluster: HACluster, drift_signature: str) -> HAMaintenanceRun | None:
    failed_runs = db.query(HAMaintenanceRun).filter(
        HAMaintenanceRun.cluster_id == cluster.id,
        HAMaintenanceRun.operation == "DHCP_SELF_HEAL",
        HAMaintenanceRun.status == "FAILED_SAFE",
    ).order_by(HAMaintenanceRun.created_at.desc()).all()
    return next((
        run for run in failed_runs
        if (result := _result_document(run)).get("latch_active") is True
        and result.get("drift_signature") == drift_signature
    ), None)


def start_dhcp_self_heal(
    db: Session,
    cluster: HACluster,
    *,
    now: datetime | None = None,
    force_retry: bool = False,
    requested_by: User | None = None,
) -> HAMaintenanceRun | None:
    """Queue one narrowly-scoped DHCP configuration repair when ownership is certain."""
    current = now or datetime.utcnow()
    if (
        cluster.provider_key != "pihole"
        or cluster.keepalived_status != "DEPLOYED"
        or len(cluster.nodes) != 2
        or not pihole_manages_dhcp(cluster)
        or active_maintenance(cluster)
        or cluster.maintenance_mode
    ):
        return None
    from app.services.ha_failover import active_failover
    if active_failover(cluster):
        return None
    topology = reconcile_topology(cluster, now=current)
    topology_fingerprint = _dhcp_topology_fingerprint(cluster, topology, current)
    _clear_changed_dhcp_failure_latches(db, cluster, topology_fingerprint)
    if (
        len(topology.vip_owner_ids) != 1
        or topology.dhcp_unknown_node_ids
        or len(topology.dhcp_owner_ids) > 1
    ):
        return None
    owner = next(node for node in cluster.nodes if node.id == topology.vip_owner_ids[0])
    standby = next(node for node in cluster.nodes if node.id != owner.id)
    if any(version_tuple(node.agent_version) < DHCP_SELF_HEAL_AGENT_VERSION for node in cluster.nodes):
        return None
    owner_observation = dhcp_observation(owner, current)
    standby_observation = dhcp_observation(standby, current)
    hard_failure_proven = bool(
        len(topology.fresh_node_ids) == 1
        and topology.fresh_node_ids == (owner.id,)
        and _hard_failover_proof(db, cluster, owner, current)
    )
    if not topology.fresh and not hard_failure_proven:
        return None
    if owner.dns_healthy is not True or owner.ftl_active is not True or (not standby_observation.released and not hard_failure_proven):
        return None

    repair_node = None
    action_type = None
    if topology.fresh and standby_observation.configured is True:
        repair_node, action_type = standby, "DHCP_DEMOTE"
    elif owner_observation.configured is False:
        repair_node, action_type = owner, "DHCP_PROMOTE"
    if repair_node is None:
        return None

    repair_type = "ACTIVE_DHCP_CONFIGURATION_REPAIR" if action_type == "DHCP_PROMOTE" else "STANDBY_DHCP_CONFIGURATION_REPAIR"
    drift_signature = hashlib.sha256(
        f"{repair_type}:{repair_node.public_id}:{topology_fingerprint}".encode()
    ).hexdigest()
    failed_latch = _matching_dhcp_failure_latch(db, cluster, drift_signature)
    if failed_latch and not force_retry:
        return None
    if failed_latch:
        failed_result = _result_document(failed_latch)
        failed_result.update({
            "latch_active": False,
            "latch_cleared_at": current.isoformat() + "Z",
            "latch_cleared_reason": "administrator_retry",
        })
        failed_latch.result_json = json.dumps(failed_result, sort_keys=True)

    # Acquire the existing cluster maintenance lock atomically. This prevents
    # simultaneous signed heartbeats from creating duplicate repair jobs.
    claimed = db.query(HACluster).filter(
        HACluster.id == cluster.id,
        HACluster.maintenance_mode.is_(False),
    ).update({HACluster.maintenance_mode: True}, synchronize_session=False)
    if claimed != 1:
        db.rollback()
        return None
    cluster.maintenance_mode = True

    # This is configuration convergence on the existing active node. It does
    # not change HA roles, Keepalived, or desired cluster topology, so changing
    # either generation would incorrectly invalidate the ready standby.
    run = HAMaintenanceRun(
        cluster_id=cluster.id,
        operation="DHCP_SELF_HEAL",
        status="RUNNING",
        phase="REPAIRING_DHCP",
        desired_active_node_id=owner.id,
        requested_by_user_id=requested_by.id if requested_by else None,
        previous_state_json=json.dumps(_snapshot_state(cluster), sort_keys=True),
        result_json=json.dumps({
            "repair_node_id": repair_node.id,
            "action_type": action_type,
            "attempt": 1,
            "phase_attempts": {"REPAIRING_DHCP": 1},
            "hard_failure_proven": hard_failure_proven,
            "classification": "SAFE_ACTIVE_DHCP_CONFIGURATION_DRIFT" if action_type == "DHCP_PROMOTE" else "SAFE_STANDBY_DHCP_CONFIGURATION_DRIFT",
            "repair_type": repair_type,
            "target_node_id": repair_node.public_id,
            "drift_signature": drift_signature,
            "topology_fingerprint": topology_fingerprint,
            "latch_active": False,
            "automatic": requested_by is None,
            "progress": [
                "Active node confirmed",
                "Sole Virtual IP owner confirmed",
                "DHCP runtime owner confirmed",
                "Standby confirmed safe",
                f"Correcting DHCP configuration on {repair_node.display_name}",
            ],
        }, sort_keys=True),
    )
    db.add(run)
    db.flush()
    logger.info(
        "HA DHCP repair classified cluster=%s run=%s repair_type=%s target=%s action=%s vip_owner=%s service_movement=false",
        cluster.public_id,
        run.public_id,
        repair_type,
        repair_node.public_id,
        action_type,
        owner.public_id,
    )
    drift_message = (
        f"Active DHCP configuration drift detected on {repair_node.display_name}. Kaya safely queued a configuration-only repair."
        if action_type == "DHCP_PROMOTE"
        else f"Standby DHCP configuration drift detected on {repair_node.display_name}. Kaya safely queued an idempotent disable repair."
    )
    _event(
        db,
        run,
        "dhcp_configuration_drift_detected",
        "warning",
        drift_message,
        {"node_id": repair_node.public_id, "action_type": action_type, "automatic": requested_by is None},
    )
    db.commit()
    db.refresh(run)
    write_audit(
        db,
        requested_by,
        "started",
        "ha_dhcp_self_heal",
        cluster.public_id,
        detail=f"Queued a bounded DHCP configuration repair for {cluster.name}.",
        severity="warning",
        metadata={"maintenance_run_id": run.public_id, "node_id": repair_node.public_id, "action_type": action_type, "automatic": requested_by is None},
    )
    return run


def advance_dhcp_self_heal(db: Session, run: HAMaintenanceRun) -> HAMaintenanceRun:
    if run.operation != "DHCP_SELF_HEAL" or run.status != "RUNNING":
        return run
    if run.phase == "REPAIRING_DHCP":
        return run
    try:
        result = json.loads(run.result_json or "{}")
    except json.JSONDecodeError:
        result = {}
    repair_node = db.get(HANode, result.get("repair_node_id"))
    action_type = result.get("action_type")
    owner = run.desired_active_node
    if repair_node is None or owner is None or action_type not in {"DHCP_PROMOTE", "DHCP_DEMOTE"}:
        return _fail_dhcp_self_heal(db, run, "The bounded DHCP repair record is incomplete. No further action was issued.")
    topology = reconcile_topology(run.cluster, since=run.phase_started_at)
    owner_observation = dhcp_observation(owner, datetime.utcnow(), since=run.phase_started_at)
    repair_observation = dhcp_observation(repair_node, datetime.utcnow(), since=run.phase_started_at)
    standby = next(node for node in run.cluster.nodes if node.id != owner.id)
    standby_observation = dhcp_observation(standby, datetime.utcnow(), since=run.phase_started_at)
    hard_failure_proven = bool(result.get("hard_failure_proven") and _hard_failover_proof(db, run.cluster, owner, datetime.utcnow()))
    reports_sufficient = topology.fresh or (
        hard_failure_proven
        and topology.fresh_node_ids == (owner.id,)
    )
    repaired = bool(
        reports_sufficient
        and topology.vip_owner_ids == (owner.id,)
        and owner.dns_healthy is True
        and (
            action_type == "DHCP_PROMOTE"
            and owner_observation.active
            and owner_observation.configured is True
            and ((standby_observation.released and standby_observation.configured is False) or hard_failure_proven)
            or action_type == "DHCP_DEMOTE"
            and repair_observation.released
            and repair_observation.configured is False
        )
    )
    if repaired:
        run.status = "SUCCEEDED"
        run.phase = "COMPLETE"
        run.completed_at = datetime.utcnow()
        run.error_redacted = None
        run.cluster.maintenance_mode = False
        final = reconcile_topology(run.cluster)
        logger.info(
            "HA DHCP repair verified cluster=%s run=%s target=%s configured=%s runtime=%s udp67=%s vip_owner_ids=%s topology_safe=%s",
            run.cluster.public_id,
            run.public_id,
            repair_node.public_id,
            repair_observation.configured,
            repair_observation.state,
            repair_observation.listening,
            list(final.vip_owner_ids),
            final.topology_safe,
        )
        run.cluster.status = "HEALTHY" if final.topology_safe else "DEGRADED"
        progress = list(result.get("progress") or [])
        repair_description = "active DHCP configuration restored" if action_type == "DHCP_PROMOTE" else "standby DHCP configuration safely disabled"
        progress.extend(["Fresh signed HA Agent report received", repair_description.capitalize()])
        result.update({"progress": progress[-20:], "service_movement_performed": False, "final_topology_safe": final.topology_safe})
        result.update({"latch_active": False, "latch_cleared_reason": "repair_succeeded"})
        run.result_json = json.dumps(result, sort_keys=True)
        _event(db, run, "dhcp_configuration_automatically_repaired", "info", f"Configuration repair completed: {repair_description}. Fresh signed reports verified the result.", {"node_id": repair_node.public_id, "action_type": action_type, "automatic": run.requested_by_user_id is None})
        db.commit()
        write_audit(db, run.requested_by, "completed", "ha_dhcp_self_heal", run.cluster.public_id, detail=f"Verified the DHCP configuration repair for {run.cluster.name}.", metadata={"maintenance_run_id": run.public_id, "node_id": repair_node.public_id, "fresh_report_verified": True, "automatic": run.requested_by_user_id is None})
        return run
    if datetime.utcnow() - run.phase_started_at > timedelta(seconds=45):
        action_result = result.get("action_result") if isinstance(result.get("action_result"), dict) else {}
        failure_detail = str(action_result.get("message") or "")[:500] if action_result.get("status") == "FAILED" else ""
        message = "DHCP configuration repair did not converge after one bounded attempt. Kaya stopped without changing VIP ownership."
        if failure_detail:
            message = f"DHCP configuration repair failed: {failure_detail} Kaya stopped without changing VIP ownership."
        return _fail_dhcp_self_heal(db, run, message)
    db.commit()
    return run


def _fail_dhcp_self_heal(db: Session, run: HAMaintenanceRun, message: str) -> HAMaintenanceRun:
    run.status = "FAILED_SAFE"
    run.phase = "PAUSED"
    run.error_redacted = message[:1000]
    run.completed_at = datetime.utcnow()
    run.cluster.maintenance_mode = False
    run.cluster.status = "DEGRADED"
    result = _result_document(run)
    result.update({
        "latch_active": True,
        "attempted_at": datetime.utcnow().isoformat() + "Z",
        "result": "FAILED_SAFE",
        "failure_reason": message[:1000],
    })
    run.result_json = json.dumps(result, sort_keys=True)
    logger.warning(
        "HA DHCP repair failed safely cluster=%s run=%s repair_type=%s target=%s reason=%s",
        run.cluster.public_id,
        run.public_id,
        result.get("repair_type", "unknown"),
        result.get("target_node_id", "unknown"),
        message[:300],
    )
    _event(db, run, "dhcp_self_heal_failed_safe", "warning", message[:1000])
    db.commit()
    write_audit(db, run.requested_by, "fail_safe", "ha_dhcp_self_heal", run.cluster.public_id, detail=message[:1000], severity="warning", metadata={"maintenance_run_id": run.public_id, "failure_latched": True, "drift_signature": result.get("drift_signature", "")[:16]})
    return run


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
    remaining_issues = list(final.issues)
    run.status = "FAILED_SAFE" if remaining_issues else "SUCCEEDED"
    run.phase = "PAUSED" if remaining_issues else "COMPLETE"
    run.completed_at = datetime.utcnow()
    run.error_redacted = " ".join(issue.message for issue in remaining_issues)[:1000] if remaining_issues else None
    if any(issue.requires_service_movement for issue in remaining_issues):
        message = f"Reconciliation corrected {len(corrected)} stale state record(s). A service ownership mismatch remains and requires cluster reinitialisation."
    elif remaining_issues:
        message = f"Reconciliation stopped with {len(remaining_issues)} unresolved configuration issue(s). Fresh topology does not prove convergence."
    else:
        message = f"Cluster reconciliation completed without moving services. Kaya corrected {len(corrected)} stale state record(s)."
    _event(db, run, "cluster_reconciliation_needs_attention" if remaining_issues else "cluster_reconciliation_completed", "warning" if remaining_issues else "info", message, {"corrected_count": len(corrected), "remaining_issue_codes": [issue.code for issue in remaining_issues]})
    db.commit()
    write_audit(
        db,
        run.requested_by,
        "fail_safe" if remaining_issues else "complete",
        "ha_cluster_reconciliation",
        run.cluster.public_id,
        detail=message,
        severity="warning" if remaining_issues else "info",
        metadata={"maintenance_run_id": run.public_id, "service_movement_performed": False, "remaining_issue_codes": [issue.code for issue in remaining_issues]},
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
    if run.operation == "DHCP_SELF_HEAL":
        attempts = dict(result.get("phase_attempts") or {})
        attempts[phase] = int(attempts.get(phase, 0)) + 1
        result["phase_attempts"] = attempts
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
    if run is None or run.operation not in {"REINITIALISE", "DHCP_SELF_HEAL"} or run.status != "RUNNING":
        return None
    if run.operation == "DHCP_SELF_HEAL":
        if run.phase != "REPAIRING_DHCP":
            return None
        try:
            result = json.loads(run.result_json or "{}")
        except json.JSONDecodeError:
            return None
        if node.id != result.get("repair_node_id") or result.get("action_type") not in {"DHCP_PROMOTE", "DHCP_DEMOTE"}:
            return None
        action_type = result["action_type"]
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
            # Repair the persisted Pi-hole setting only. The node already owns
            # the VIP and serves DHCP, so live leases must remain untouched.
            "configuration_only": action_type == "DHCP_PROMOTE",
        }
    target = run.desired_active_node
    if target is None:
        return None
    action_type = None
    if run.phase == "DEMOTING_STANDBY" and node.id != target.id and not _dhcp_released(node):
        action_type = "DHCP_DEMOTE"
    elif run.phase == "PROMOTING_ACTIVE" and node.id == target.id and not _dhcp_active(node):
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
    try:
        result_document = json.loads(run.result_json or "{}")
    except json.JSONDecodeError:
        result_document = {}
    result_document["action_result"] = {
        "action_type": action_type,
        "node_id": node.public_id,
        "status": status,
        "message": str(message or "")[:1000],
        "received_at": datetime.utcnow().isoformat() + "Z",
    }
    run.result_json = json.dumps(result_document, sort_keys=True)
    logger.info(
        "HA DHCP action result received cluster=%s run=%s node=%s action=%s status=%s detail=%s",
        node.cluster.public_id,
        run.public_id,
        node.public_id,
        action_type,
        status,
        str(message or "")[:300],
    )
    if status != "APPLIED":
        if run.operation == "DHCP_SELF_HEAL":
            _set_phase(run, "VERIFYING_DHCP_REPAIR", f"Unexpected repair response from {node.display_name}; verifying the final two-node topology")
            run.error_redacted = str(message or f"{action_type} returned an unexpected result.")[:1000]
            _event(db, run, "dhcp_self_heal_verifying_final_state", "warning", "Kaya received an unexpected repair response and is checking both nodes before deciding the outcome.", {"node_id": node.public_id})
            db.commit()
            return run
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
    if run.operation == "DHCP_SELF_HEAL":
        _set_phase(run, "VERIFYING_DHCP_REPAIR", f"DHCP configuration repair was accepted on {node.display_name}; waiting for a fresh signed report")
    elif run.phase == "DEMOTING_STANDBY":
        _set_phase(run, "VERIFYING_DHCP_RELEASE", f"DHCP disable was accepted on {node.display_name}; waiting for a fresh configuration and UDP/67 observation")
    elif run.phase == "PROMOTING_ACTIVE":
        _set_phase(run, "VERIFYING_DHCP_ACTIVATION", f"DHCP enable was accepted on {node.display_name}; verifying the final two-node topology")
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
        try:
            attempt_result = json.loads(run.result_json or "{}")
        except json.JSONDecodeError:
            attempt_result = {}
        phase_attempts = dict(attempt_result.get("phase_attempts") or {})
        phase_attempts[run.phase] = int(phase_attempts.get(run.phase, 0)) + 1
        attempt_result["phase_attempts"] = phase_attempts
        run.result_json = json.dumps(attempt_result, sort_keys=True)
        if run.phase == "WAITING_FOR_REPORTS":
            inspection = inspect_cluster(cluster, since=run.phase_started_at)
            run.result_json = json.dumps({
                **inspection_json(cluster, inspection),
                "progress": ["Waiting for fresh signed node reports"],
                "phase_attempts": phase_attempts,
            }, sort_keys=True)
            if not inspection.fresh:
                db.commit()
                return run
            already_correct = (
                inspection.vip_owner_ids == (target.id,)
                and (
                    not pihole_manages_dhcp(cluster)
                    or inspection.dhcp_owner_ids == (target.id,)
                )
                and not any(issue.requires_service_movement for issue in inspection.issues)
            )
            if already_correct:
                for node in cluster.nodes:
                    active = node.id == target.id
                    node.role = node.desired_role = "ACTIVE" if active else "STANDBY"
                    node.recovery_state = "ACTIVE" if active else "STANDBY_READY"
                    node.recovery_started_at = None
                    node.recovery_stable_since = datetime.utcnow() if not active else None
                cluster.current_active_node_id = target.id
                cluster.authoritative_node_id = run.authoritative_node_id
                previous = json.loads(run.previous_state_json or "{}")
                cluster.automatic_failover_enabled = bool(previous.get("automatic_failover_enabled"))
                cluster.automatic_sync_enabled = bool(previous.get("automatic_sync_enabled"))
                cluster.automatic_sync_allow_deletions = bool(previous.get("automatic_sync_allow_deletions"))
                cluster.status = "HEALTHY"
                cluster.maintenance_mode = False
                run.status = "SUCCEEDED"
                run.phase = "COMPLETE"
                run.completed_at = datetime.utcnow()
                run.error_redacted = None
                final_inspection = inspect_cluster(cluster)
                run.result_json = json.dumps({
                    **inspection_json(cluster, final_inspection),
                    "progress": [
                        "Fresh signed reports received from both nodes",
                        "Observed topology already matches the requested Active and Standby assignment",
                        "Kaya stored state reconciled without moving DNS, DHCP or the Virtual IP",
                    ],
                    "service_movement_performed": False,
                }, sort_keys=True)
                _event(db, run, "cluster_reinitialisation_reconciled", "info", f"The observed topology already had {target.display_name} as the exclusive service owner. Kaya repaired stored state without moving services.")
                db.commit()
                write_audit(
                    db,
                    run.requested_by,
                    "complete",
                    "ha_cluster_reinitialisation",
                    cluster.public_id,
                    detail=f"Cluster state reconciled with {target.display_name} already active; no service movement was issued.",
                    metadata={
                        "maintenance_run_id": run.public_id,
                        "desired_active_node_id": target.public_id,
                        "authoritative_node_id": run.authoritative_node.public_id if run.authoritative_node else None,
                        "service_movement_performed": False,
                    },
                )
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
            if pihole_manages_dhcp(cluster) and not _dhcp_released(standby):
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
            if pihole_manages_dhcp(cluster) and not _dhcp_active(target):
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
    labels = {
        "WAITING_FOR_REPORTS": "Waiting for fresh signed reports",
        "BACKING_UP": "Creating encrypted configuration backups",
        "SYNCHRONISING": "Synchronising supported configuration",
        "STAGING_DHCP": "Validating the DHCP snapshot",
        "WAITING_FOR_DHCP_STAGE": "Waiting for standby lease staging",
        "NORMALISING_STANDBY": "Confirming the standby is safe",
        "DEMOTING_STANDBY": "Stopping DHCP on the standby",
        "VERIFYING_DHCP_RELEASE": "Verifying UDP port 67 is released",
        "REBUILDING_HA": "Rebuilding HA runtime state",
        "WAITING_FOR_VIP": "Waiting for exclusive Virtual IP ownership",
        "PROMOTING_ACTIVE": "Starting DHCP on the selected active node",
        "VERIFYING_DHCP_ACTIVATION": "Verifying DHCP activation",
        "VERIFYING": "Checking final topology invariants",
        "REPAIRING_DHCP": "Repairing DHCP configuration drift",
        "VERIFYING_DHCP_REPAIR": "Verifying the repaired DHCP topology",
        "COMPLETE": "Maintenance completed",
        "PAUSED": "Maintenance stopped safely",
    }
    phases = REINITIALISATION_PHASES if run.operation == "REINITIALISE" else DHCP_SELF_HEAL_PHASES if run.operation == "DHCP_SELF_HEAL" else ("WAITING_FOR_REPORTS", "RECONCILING", "COMPLETE")
    current_index = phases.index(run.phase) if run.phase in phases else 0
    attempts = dict(result.get("phase_attempts") or {})
    elapsed = max(0, int((datetime.utcnow() - (run.started_at or run.created_at)).total_seconds()))
    repair_node = next((node for node in run.cluster.nodes if node.id == result.get("repair_node_id")), None)
    recently_completed = bool(
        run.status == "SUCCEEDED"
        and run.completed_at
        and datetime.utcnow() - run.completed_at <= timedelta(seconds=15)
    )
    failure_latched = result.get("latch_active") is True
    if run.operation == "DHCP_SELF_HEAL" and run.status == "FAILED_SAFE":
        display_message = "Self-heal paused"
        detail = "Kaya stopped without moving Virtual IP ownership. Automatic retries are paused until the topology changes or an administrator explicitly retries this repair."
    elif run.operation == "DHCP_SELF_HEAL" and run.status == "SUCCEEDED":
        display_message = "HA configuration repaired"
        detail = (
            f"Kaya corrected DHCP configuration drift on {repair_node.display_name}. Network service was not interrupted."
            if repair_node
            else "Kaya corrected DHCP configuration drift. Network service was not interrupted."
        )
    elif run.operation == "DHCP_SELF_HEAL" and repair_node:
        display_message = (
            f"Correcting DHCP configuration on {repair_node.display_name}"
            if run.phase == "REPAIRING_DHCP"
            else "Waiting for a fresh signed report"
            if run.phase == "VERIFYING_DHCP_REPAIR"
            else labels.get(run.phase, run.phase.replace("_", " ").title())
        )
        detail = "Network services remain available. No user action is required."
    else:
        display_message = labels.get(run.phase, run.phase.replace("_", " ").title())
        detail = "Kaya advances only after persisted safety checks and fresh signed node reports."
    return {
        "id": run.public_id,
        "operation": run.operation,
        "status": run.status,
        "phase": run.phase,
        "error": run.error_redacted,
        "failure_latched": failure_latched,
        "desired_active_node_id": run.desired_active_node.public_id if run.desired_active_node else None,
        "desired_active_name": run.desired_active_node.display_name if run.desired_active_node else None,
        "authoritative_name": run.authoritative_node.display_name if run.authoritative_node else None,
        "progress": list(result.get("progress") or []),
        "inspection": result,
        "started_at": run.started_at.isoformat() + "Z" if run.started_at else None,
        "completed_at": run.completed_at.isoformat() + "Z" if run.completed_at else None,
        "message": display_message,
        "detail": detail,
        "visible": run.status == "RUNNING" or (run.status == "FAILED_SAFE" and failure_latched) or recently_completed,
        "elapsed_seconds": elapsed,
        "phase_attempt": int(attempts.get(run.phase, 0)),
        "progress_percent": 100 if run.status == "SUCCEEDED" else round((current_index / max(1, len(phases) - 1)) * 100),
        "steps": [{
            "phase": phase,
            "label": labels.get(phase, phase.replace("_", " ").title()),
            "state": "complete" if index < current_index or run.status == "SUCCEEDED" else "current" if index == current_index else "pending",
        } for index, phase in enumerate(phases)],
    }
