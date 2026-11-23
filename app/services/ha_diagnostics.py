"""Bounded, read-only diagnostics for HA authority and recovery decisions."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HAAgentActionResult, HACluster, HAEvent, HAMaintenanceRun, HASyncRun
from app.services.ha_maintenance import (
    active_maintenance,
    inspect_cluster,
    inspection_json,
    latest_maintenance,
    maintenance_status,
)
from app.services.ha_recovery import recovery_snapshot
from app.services.ha_leases import desired_lease_action, latest_snapshot_summary
from app.services.ha_sync import HASyncError, authority_and_target
from app.services.ha_topology import dhcp_observation, pihole_manages_dhcp, reconcile_topology


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _json_object(value: str | None) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: str | None) -> list[Any]:
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _check(code: str, label: str, passed: bool, observed: Any, expected: Any, action: str) -> dict[str, Any]:
    return {
        "code": code,
        "label": label,
        "passed": bool(passed),
        "observed": observed,
        "expected": expected,
        "next_action": action if not passed else "No action required.",
    }


def build_diagnostic_bundle(
    db: Session,
    cluster: HACluster,
    *,
    event_limit: int = 50,
    severity: str | None = None,
    event_type: str | None = None,
) -> dict[str, Any]:
    """Build a bounded bundle from persisted reports; never performs remote I/O."""
    limit = max(1, min(int(event_limit), 100))
    now = datetime.utcnow()
    topology = reconcile_topology(cluster, now=now)
    inspection = inspect_cluster(cluster, now=now)
    recovery = recovery_snapshot(db, cluster, now=now)
    active = active_maintenance(cluster)
    latest = latest_maintenance(cluster)
    lease = cluster.lease_replication
    try:
        authority_source, _authority_target, authority_verified = authority_and_target(cluster)
    except HASyncError:
        authority_source = None
        authority_verified = False

    observed_vip = next((node for node in cluster.nodes if node.id == topology.active_node_id), None)
    stored_active = next((node for node in cluster.nodes if node.id == cluster.current_active_node_id), None)
    stored_authority = next((node for node in cluster.nodes if node.id == cluster.authoritative_node_id), None)
    observed_dhcp = next((node for node in cluster.nodes if node.id in topology.dhcp_owner_ids), None)
    managed = pihole_manages_dhcp(cluster)
    generation_ok = all(
        node.config_generation >= cluster.keepalived_generation
        and node.observed_generation >= cluster.role_generation
        for node in cluster.nodes
    )
    latest_sync = (
        db.query(HASyncRun)
        .filter(HASyncRun.cluster_id == cluster.id)
        .order_by(HASyncRun.created_at.desc())
        .first()
    )
    sync_plan = _json_object(latest_sync.plan_json if latest_sync else None)
    dhcp_groups = [
        group for group in sync_plan.get("groups", [])
        if isinstance(group, dict) and group.get("key") == "dhcp"
    ]
    sync_execution = sync_plan.get("execution") if isinstance(sync_plan.get("execution"), dict) else None

    lease_snapshot = latest_snapshot_summary(cluster) if lease else None
    lease_action = None
    lease_gate = None
    if lease:
        target = lease.target_node
        expected_action = desired_lease_action(cluster, target) if target else None
        latest_action = (
            db.query(HAAgentActionResult)
            .filter(
                HAAgentActionResult.cluster_id == cluster.id,
                HAAgentActionResult.action_type == "LEASE_SNAPSHOT_STAGE",
                HAAgentActionResult.node_id == (target.id if target else -1),
            )
            .order_by(HAAgentActionResult.received_at.desc())
            .limit(1)
            .first()
        )
        if latest_action:
            lease_action = {
                "status": latest_action.status,
                "generation": latest_action.generation,
                "received_at": _iso(latest_action.received_at),
                "message": latest_action.message_redacted,
            }
        if lease.status != "PENDING" or lease.desired_generation <= lease.applied_generation:
            lease_gate = {"code": "LEASE_CURRENT", "detail": "The desired lease generation is applied."}
        elif not expected_action:
            lease_gate = {"code": "LEASE_ACTION_NOT_AVAILABLE", "detail": "No protected stage action is currently available for the recorded standby target."}
        elif latest_action and latest_action.generation == lease.desired_generation and latest_action.status in {"FAILED", "ERROR"}:
            lease_gate = {"code": "LEASE_STAGE_FAILED", "detail": "The latest protected stage action failed; review its redacted result before retrying."}
        elif latest_action and latest_action.generation == lease.desired_generation and latest_action.status == "APPLIED":
            lease_gate = {"code": "LEASE_ACKNOWLEDGEMENT_PENDING", "detail": "The standby reported staging, but Kaya has not yet persisted the desired generation as current."}
        else:
            lease_gate = {"code": "LEASE_STAGE_ACKNOWLEDGEMENT_PENDING", "detail": "The protected stage action is awaiting a standby acknowledgement."}

    maintenance_state = (
        "ACTIVE_RUN"
        if active is not None
        else "SAFETY_LATCH_NO_ACTIVE_RUN"
        if cluster.maintenance_mode
        else "INACTIVE"
    )
    blockers: list[dict[str, str]] = []
    if maintenance_state == "SAFETY_LATCH_NO_ACTIVE_RUN":
        blockers.append({
            "code": "MAINTENANCE_SAFETY_LATCH",
            "owner": "administrator",
            "state": "blocked",
            "next_action": "Inspect the failed-safe run and verify the live topology before explicitly clearing the latch.",
        })
    elif active is not None:
        blockers.append({
            "code": "MAINTENANCE_ACTIVE",
            "owner": "maintenance workflow",
            "state": active.status,
            "next_action": "Allow the active maintenance workflow to complete or pause safely.",
        })
    if latest_sync and latest_sync.status == "PLANNED" and dhcp_groups:
        blockers.append({
            "code": "CONFIGURATION_SYNC_APPROVAL",
            "owner": "administrator",
            "state": "awaiting approval",
            "next_action": "Review the high-impact DHCP difference; do not apply it automatically.",
        })
    if lease and (lease.status == "PENDING" or lease.desired_generation > lease.applied_generation):
        blockers.append({
            "code": "LEASE_GENERATION_PENDING",
            "owner": lease.target_node.display_name if lease.target_node else "standby agent",
            "state": "pending",
            "next_action": "Verify authority and wait for the protected lease-stage action and acknowledgement.",
        })
    if latest and latest.status == "FAILED_SAFE":
        blockers.append({
            "code": "LAST_MAINTENANCE_FAILED_SAFE",
            "owner": "maintenance workflow",
            "state": "failed-safe",
            "next_action": "Review the redacted failure and repair its prerequisite before retrying.",
        })

    maintenance_rows = (
        db.query(HAMaintenanceRun)
        .filter(HAMaintenanceRun.cluster_id == cluster.id)
        .order_by(HAMaintenanceRun.created_at.desc())
        .limit(20)
        .all()
    )
    events_query = db.query(HAEvent).filter(HAEvent.cluster_id == cluster.id)
    if severity in {"info", "warning", "error", "critical"}:
        events_query = events_query.filter(HAEvent.severity == severity)
    if event_type and len(event_type) <= 80:
        events_query = events_query.filter(HAEvent.event_type == event_type)
    events = events_query.order_by(HAEvent.occurred_at.desc()).limit(limit).all()

    stored_observed_rows = []
    for node in cluster.nodes:
        observation = dhcp_observation(node, now)
        stored_observed_rows.append({
            "node": node.display_name,
            "node_id": node.public_id,
            "stored_role": node.role,
            "desired_role": node.desired_role,
            "observed_role": node.observed_role,
            "recovery_state": node.recovery_state,
            "report_fresh": node.id in topology.fresh_node_ids,
            "last_report_sequence": node.last_report_sequence,
            "last_heartbeat_at": _iso(node.last_heartbeat_at),
            "last_agent_reported_at": _iso(node.last_agent_reported_at),
            "vip_owned": node.vip_owned if node.id in topology.fresh_node_ids else None,
            "dhcp_state": observation.state if node.id in topology.fresh_node_ids else "UNKNOWN",
            "dhcp_configured": node.dhcp_configured if node.id in topology.fresh_node_ids else None,
            "dhcp_listener_active": node.dhcp_listener_active if node.id in topology.fresh_node_ids else None,
            "dns_healthy": node.dns_healthy if node.id in topology.fresh_node_ids else None,
            "observed_generation": node.observed_generation,
            "config_generation": node.config_generation,
            "lease_generation": node.lease_generation,
            "resolver": {
                "manager": node.resolver_manager,
                "status": node.resolver_observation_status,
                "nameservers": [
                    value for value in _json_list(node.resolver_nameservers_json)
                    if isinstance(value, str)
                ][:8],
                "repair_status": node.resolver_repair_status,
                "repair_error": node.resolver_repair_last_error,
            },
        })

    recovery_rows = []
    for node in cluster.nodes:
        result = recovery[node.id]
        recovery_rows.append({
            "node": node.display_name,
            "state": result.state,
            "stable_for_seconds": result.stability_seconds,
            "stability_required_seconds": result.stability_required_seconds,
            "gates": [
                {"code": check.key, "label": check.label, "passed": check.passed, "required": check.required, "detail": check.detail}
                for check in result.checks
            ],
        })

    decision_trace = [
        _check("FRESH_REPORTS", "Fresh signed reports", inspection.fresh, len(inspection.fresh_node_ids), len(cluster.nodes), "Wait for fresh reports from every registered node."),
        _check("EXCLUSIVE_VIP", "Exactly one VIP owner", len(topology.vip_owner_ids) == 1, [node.display_name for node in cluster.nodes if node.id in topology.vip_owner_ids], [node.display_name for node in cluster.nodes if node.id in topology.vip_owner_ids] if len(topology.vip_owner_ids) == 1 else "one owner", "Resolve duplicate or missing VIP ownership through the protected maintenance workflow."),
        _check("DHCP_OWNER", "Exactly one DHCP owner", not managed or len(topology.dhcp_owner_ids) == 1, [node.display_name for node in cluster.nodes if node.id in topology.dhcp_owner_ids], "one owner" if managed else "not applicable", "Wait for fresh DHCP observations; do not start another DHCP service."),
        _check("DHCP_VIP_MATCH", "DHCP owner matches VIP owner", not managed or (observed_vip is not None and observed_dhcp is not None and observed_vip.id == observed_dhcp.id), observed_dhcp.display_name if observed_dhcp else None, observed_vip.display_name if observed_vip else None, "Use the protected DHCP reconciliation workflow after ownership is unambiguous."),
        _check("GENERATION_FENCING", "Generation and fencing", generation_ok, {node.display_name: {"role": node.observed_generation, "config": node.config_generation} for node in cluster.nodes}, {"role_at_least": cluster.role_generation, "config_at_least": cluster.keepalived_generation}, "Wait for reports at the current cluster generations."),
        _check("VERIFIED_AUTHORITY", "Verified sync authority", authority_verified, authority_source.display_name if authority_source else None, observed_vip.display_name if observed_vip else None, "Do not synchronize or replicate leases until one safe authority is verified."),
        _check("MAINTENANCE_COMPATIBLE", "No incompatible maintenance operation", active is None or active.operation in {"RECONCILE"}, maintenance_status(active) if active else None, "none or reconciliation", "Complete or safely pause the active maintenance workflow before another operation."),
    ]

    from app.services.ha_assessment import assess_cluster

    return {
        "assessment": assess_cluster(db, cluster, now=now, recovery=recovery).as_dict(),
        "generated_at": _iso(now),
        "source": "persisted Kaya state and latest signed agent reports; no live remote calls",
        "cluster": {
            "id": cluster.public_id,
            "name": cluster.name,
            "status": cluster.status,
            "deployment_mode": cluster.deployment_mode,
            "maintenance_mode": bool(cluster.maintenance_mode),
            "automatic_sync_hold": bool(cluster.automatic_sync_hold),
            "maintenance_latch_acknowledged_at": _iso(cluster.maintenance_latch_acknowledged_at),
            "maintenance_latch_released_at": _iso(cluster.maintenance_latch_released_at),
            "automatic_failover_enabled": bool(cluster.automatic_failover_enabled),
            "automatic_sync_enabled": bool(cluster.automatic_sync_enabled),
            "generations": {
                "cluster": cluster.cluster_generation,
                "role": cluster.role_generation,
                "keepalived": cluster.keepalived_generation,
                "desired_sync": cluster.desired_sync_generation,
            },
            "stored_active": stored_active.display_name if stored_active else None,
            "stored_authority": stored_authority.display_name if stored_authority else None,
            "observed_vip_owner": observed_vip.display_name if observed_vip else None,
            "observed_dhcp_owner": observed_dhcp.display_name if observed_dhcp else None,
        },
        "decision_trace": decision_trace,
        "nodes": stored_observed_rows,
        "recovery": recovery_rows,
        "maintenance": {
            "state": maintenance_state,
            "active": maintenance_status(active),
            "latest": maintenance_status(latest),
            "recent_runs": [
                {"id": run.public_id, "operation": run.operation, "status": run.status, "phase": run.phase, "started_at": _iso(run.started_at), "completed_at": _iso(run.completed_at), "error": run.error_redacted}
                for run in maintenance_rows
            ],
        },
        "blockers": blockers,
        "sync": {
            "latest_status": latest_sync.status if latest_sync else None,
            "created_at": _iso(latest_sync.created_at) if latest_sync else None,
            "source": latest_sync.source_node.display_name if latest_sync and latest_sync.source_node else None,
            "target": latest_sync.target_node.display_name if latest_sync and latest_sync.target_node else None,
            "required_generation": sync_plan.get("required_sync_generation"),
            "verified_generation": sync_plan.get("verified_sync_generation"),
            "dhcp_differences": dhcp_groups,
            "execution": sync_execution,
        },
        "lease": None if lease is None else {
            "status": lease.status,
            "source": lease.source_node.display_name if lease.source_node else None,
            "target": lease.target_node.display_name if lease.target_node else None,
            "desired_generation": lease.desired_generation,
            "applied_generation": lease.applied_generation,
            "standby_generations": {node.display_name: node.lease_generation for node in cluster.nodes},
            "last_error": lease.last_error_redacted,
            "snapshot": lease_snapshot,
            "last_staging_action": lease_action,
            "recovery_gate": lease_gate,
        },
        "resolver": [
            {"node": node.display_name, "status": node.resolver_repair_status, "error": node.resolver_repair_last_error, "observation": node.resolver_observation_status}
            for node in cluster.nodes
        ],
        "events": [
            {"id": event.id, "type": event.event_type, "severity": event.severity, "source": event.source, "node": event.node.display_name if event.node else "Cluster", "message": event.message, "occurred_at": _iso(event.occurred_at), "acknowledged": event.acknowledged_at is not None}
            for event in events
        ],
        "inspection": inspection_json(cluster, inspection),
    }
