"""Align service ownership: move only the Virtual IP to the verified sole DHCP server.

This is the dedicated, administrator-approved repair for the 4 November 2026
condition: one node holds the Virtual IP while a *different* node is the only
DHCP server.  DHCP and leases are already where they should be, so the repair
moves the Virtual IP alone.  It never starts, stops, promotes or demotes DHCP,
never issues a lease action and never writes a live lease file.  The only agent
actions it causes are generation-fenced ``KEEPALIVED_APPLY`` reloads.

It is a step of the existing HA coordinator (an ``HAMaintenanceRun`` with
operation ``ALIGN_OWNERSHIP``), advanced under the per-cluster coordination lock
like every other operation.  There is no separate scheduler and no automatic
start: an administrator must review the preview and approve each run.

Phases (each bounded; any failed check stops the run in ``FAILED_SAFE`` with
no retry and no attempt to move the Virtual IP back):

``CONFIRMING_GATES``
    Kaya holds maintenance mode for the run and waits until both agents report,
    in fresh signed heartbeats, that their local gates have maintenance on.  A
    transition hook then never touches DHCP while the Virtual IP moves.
``MOVING_VIP``
    One new Keepalived generation: the DHCP owner gets the higher priority and
    a preempt-capable configuration, the current owner keeps ``nopreempt``.
    Both are applied as reloads (agent 0.2.15+ never restarts a running
    Keepalived).  Waits for fresh reports showing the DHCP owner as the only
    Virtual IP owner.
``RESTORING_STANDBY_BASELINE`` / ``RESTORING_OWNER_BASELINE``
    The stable ``nopreempt`` configuration, node without the Virtual IP first,
    then the owner (a reload, which the lab showed keeps the Virtual IP).
``VERIFYING``
    Fresh signed reports from both nodes must show one Virtual IP owner, the
    same single DHCP owner, the other node released, healthy DNS, Keepalived
    running, current generations, and the stable configuration applied (by
    checksum).  Only then is the run recorded as succeeded.

Every phase also stops the run if an agent stops reporting, DHCP ownership
changes, DNS health deteriorates, Keepalived stops or rejects a configuration,
another change moves a generation, or two nodes claim the Virtual IP for longer
than the split-brain confirmation window.

Retained maintenance safety latch: the repair may run while the latch is held,
but only with an explicit extra authorisation for that run, after the failed
operation that set the latch has been acknowledged.  The latch is never
cleared by this repair: maintenance mode stays on during and after the run, so
no unrelated automation resumes.  Without an identifiable, acknowledged failed
operation the repair is blocked (fail closed).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAMaintenanceRun, HANode, User
from app.services.audit import write_audit
from app.services.ha_agent_installer import version_tuple
from app.services.ha_maintenance import (
    PROCESS_STARTED_AT,
    _event,
    _registered,
    _set_phase,
    _snapshot_state,
    active_maintenance,
    inspect_cluster,
    inspection_json,
    latched_failed_run,
    latch_acknowledgement_matches,
)
from app.services.ha_topology import FRESH_SECONDS, dhcp_observation, heartbeat_is_fresh, pihole_manages_dhcp, reconcile_topology

OPERATION = "ALIGN_OWNERSHIP"
ALIGNMENT_AGENT_VERSION = (0, 2, 15)
ALIGNMENT_PHASES = (
    "CONFIRMING_GATES",
    "MOVING_VIP",
    "RESTORING_STANDBY_BASELINE",
    "RESTORING_OWNER_BASELINE",
    "VERIFYING",
    "COMPLETE",
)
PHASE_LABELS = {
    "CONFIRMING_GATES": "Confirming both agents hold DHCP automation off",
    "MOVING_VIP": "Moving the Virtual IP to the DHCP server",
    "RESTORING_STANDBY_BASELINE": "Restoring the stable Keepalived configuration on the standby",
    "RESTORING_OWNER_BASELINE": "Restoring the stable Keepalived configuration on the owner",
    "VERIFYING": "Verifying the final ownership from fresh reports",
    "COMPLETE": "Service ownership aligned",
}
GATE_TIMEOUT_SECONDS = 60
# Apply on both nodes (helper timeout 30 s) + preempt_delay 3 s + VRRP adverts.
# The isolated lab measured about 7 s from apply to the move.
MOVE_TIMEOUT_SECONDS = 90
RESTORE_STEP_TIMEOUT_SECONDS = 120
VERIFY_TIMEOUT_SECONDS = 60
# Matches the confirmed split-brain notification window: brief overlapping
# reports during a clean VRRP handover are tolerated, a lasting one is not.
DUAL_VIP_TOLERANCE_SECONDS = 20
# Heartbeats are asynchronous: the old owner can report "released" before the new
# owner's next report says "taken" (seen in the real-VRRP lab although the handover
# itself had no gap).  An absence is tolerated for one freshness window; a lasting
# absence stops the repair.  The step limits still apply.
NO_VIP_OWNER_TOLERANCE_SECONDS = FRESH_SECONDS


class HAAlignmentError(ValueError):
    pass


class HAAlignmentBusy(HAAlignmentError):
    """Another operation holds the cluster's coordination lock; nothing was started."""


@dataclass(frozen=True)
class AlignmentCheck:
    code: str
    label: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class AlignmentPreview:
    condition: str
    vip_owner: HANode | None
    dhcp_owner: HANode | None
    checks: tuple[AlignmentCheck, ...]
    latch_retained: bool
    latch_failed_run_id: str | None
    fingerprint: str
    impact: tuple[str, ...]
    generated_at: datetime

    @property
    def relevant(self) -> bool:
        """An ownership fault the Health & Repair workspace should explain (aligned or unknown is not)."""
        return self.condition in {"MISMATCH", "DUPLICATE_VIP", "MULTIPLE_DHCP", "NO_VIP_OWNER", "NO_DHCP_OWNER"}

    @property
    def allowed(self) -> bool:
        return self.condition == "MISMATCH" and all(check.passed for check in self.checks)

    @property
    def blockers(self) -> list[str]:
        return [check.detail for check in self.checks if not check.passed]


# --------------------------------------------------------------------------------------
# Preview (read-only)
# --------------------------------------------------------------------------------------


def active_alignment(cluster: HACluster) -> HAMaintenanceRun | None:
    run = active_maintenance(cluster)
    return run if run is not None and run.operation == OPERATION else None


def latest_alignment(cluster: HACluster) -> HAMaintenanceRun | None:
    runs = [run for run in cluster.maintenance_runs if run.operation == OPERATION]
    return max(runs, key=lambda run: (run.created_at or datetime.min, run.id or 0)) if runs else None


def _gates(node: HANode) -> dict[str, Any] | None:
    if not node.agent_automation_gates_json:
        return None
    try:
        value = json.loads(node.agent_automation_gates_json)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _desired_automatic_failover(cluster: HACluster) -> bool:
    from app.services.ha_failover import AUTOMATIC_AGENT_VERSION

    return bool(cluster.automatic_failover_enabled and all(version_tuple(node.agent_version) >= AUTOMATIC_AGENT_VERSION for node in cluster.nodes))


def _condition(cluster: HACluster, topology) -> str:
    vip, dhcp = topology.vip_owner_ids, topology.dhcp_owner_ids
    if len(vip) > 1:
        return "DUPLICATE_VIP"
    if len(dhcp) > 1:
        return "MULTIPLE_DHCP"
    if not topology.fresh or topology.dhcp_unknown_node_ids:
        return "UNKNOWN"
    if not vip:
        return "NO_VIP_OWNER"
    if pihole_manages_dhcp(cluster) and not dhcp:
        return "NO_DHCP_OWNER"
    if pihole_manages_dhcp(cluster) and dhcp != vip:
        return "MISMATCH"
    return "ALIGNED"


def outdated_agents(nodes) -> list[str]:
    """Agents older than 0.2.15 may restart Keepalived when a reload fails and do not report their gates."""
    return [f"{node.display_name} ({node.agent_version or 'unknown'})" for node in nodes if version_tuple(node.agent_version) < ALIGNMENT_AGENT_VERSION]


def gate_problems(cluster: HACluster, nodes) -> list[str]:
    """Nodes whose reported local automation gates do not match the cluster settings."""
    desired_failover = _desired_automatic_failover(cluster)
    problems = []
    for node in nodes:
        gates = _gates(node)
        if gates is None:
            problems.append(f"{node.display_name} has not reported its local automation gates")
        elif (gates.get("dhcp_managed") is not True or gates.get("automatic_failover") is not desired_failover
              or gates.get("maintenance_mode") is not bool(cluster.maintenance_mode)):
            problems.append(f"{node.display_name} has not yet applied the cluster's automation settings")
    return problems


def other_operations(cluster: HACluster) -> list[str]:
    """Operations that must finish before another Keepalived-changing repair may start."""
    from app.services.ha_failover import active_failover
    from app.services.ha_keepalived_baseline import ACTIVE_STATES, outstanding

    running = []
    if active_maintenance(cluster) is not None:
        running.append("a maintenance operation is running")
    if active_failover(cluster) is not None:
        running.append("a controlled failover is running")
    if any(node.resolver_repair_status == "PENDING" for node in cluster.nodes):
        running.append("a resolver repair is pending")
    if (outstanding(cluster) or {}).get("state") in ACTIVE_STATES:
        running.append("a Keepalived baseline restoration is running")
    return running


def latch_authorisation(cluster: HACluster) -> tuple[HAMaintenanceRun | None, bool, str]:
    """(failed run behind the latch, may a repair be authorised under it, explanation).  Fails closed."""
    failed_run = latched_failed_run(cluster) if cluster.maintenance_mode else None
    acknowledged = latch_acknowledgement_matches(cluster, failed_run)
    if cluster.maintenance_mode and failed_run is None:
        detail = ("The maintenance hold is on, but Kaya cannot identify the failed operation that set it, so it cannot "
                  "authorise a repair under it. Resolve the operation shown on the Health & Repair or Failover page first.")
    elif cluster.maintenance_mode and not acknowledged:
        detail = "Acknowledge the failed operation that set the maintenance safety latch first (Health & Repair). The latch stays in place."
    elif cluster.maintenance_mode:
        detail = "The safety latch stays in place. Confirming the repair also requires authorising it under the latch."
    else:
        detail = "No maintenance safety latch is held."
    return failed_run, not cluster.maintenance_mode or (failed_run is not None and acknowledged), detail


CONDITION_DETAILS = {
    "MISMATCH": "One node holds the Virtual IP and a different node is the only DHCP server.",
    "ALIGNED": "One node already holds both the Virtual IP and DHCP; there is nothing to align.",
    "UNKNOWN": "Fresh signed reports, including a fresh DHCP observation, are needed from both nodes before Kaya can tell which node serves what.",
    "DUPLICATE_VIP": (
        "Two nodes report the Virtual IP. This is split-brain, not a misalignment, and Kaya will not move the Virtual IP. "
        "If Keepalived on one node was killed or crashed, that node can keep the address without running VRRP: check the "
        "addresses and the keepalived service on both nodes and stop the stale owner. Kaya never removes Virtual IP addresses itself."
    ),
    "MULTIPLE_DHCP": "Two DHCP servers are running. Disable DHCP in Pi-hole on the node that should not serve it; Kaya will not choose for you.",
    "NO_VIP_OWNER": "No node holds the Virtual IP. This is a separate fault: check Keepalived and the DNS health check on both nodes. Alignment never assigns a missing Virtual IP.",
    "NO_DHCP_OWNER": "No node is serving DHCP. This is a separate fault: check Pi-hole DHCP on the Virtual IP owner. Alignment never starts DHCP.",
}


def alignment_preview(db: Session, cluster: HACluster, *, now: datetime | None = None) -> AlignmentPreview:
    """Decide from stored signed observations only whether alignment may be offered.  Never writes."""
    current = now or datetime.utcnow()
    topology = reconcile_topology(cluster, now=current, freshness_seconds=FRESH_SECONDS)
    condition = _condition(cluster, topology)
    by_id = {node.id: node for node in cluster.nodes}
    vip_owner = by_id.get(topology.vip_owner_ids[0]) if len(topology.vip_owner_ids) == 1 else None
    dhcp_owner = by_id.get(topology.dhcp_owner_ids[0]) if len(topology.dhcp_owner_ids) == 1 else None
    nodes = sorted(cluster.nodes, key=lambda node: (node.display_name, node.id))
    checks: list[AlignmentCheck] = []

    def check(code: str, label: str, passed: bool, detail: str) -> None:
        checks.append(AlignmentCheck(code, label, bool(passed), detail))

    check("CONDITION", "Exactly one Virtual IP owner and a different, single DHCP server", condition == "MISMATCH", CONDITION_DETAILS[condition])
    check("DHCP_MANAGED", "Pi-hole manages DHCP for this cluster", pihole_manages_dhcp(cluster) and len(cluster.nodes) == 2,
          "Alignment applies only to two-node DNS and DHCP clusters.")
    registered = all(_registered(node) for node in cluster.nodes)
    check("AGENTS_REGISTERED", "Both nodes have a registered HA Agent", registered and len(cluster.nodes) == 2,
          "Register an active agent on both nodes.")
    stale = [node.display_name for node in nodes if not heartbeat_is_fresh(node, current, freshness_seconds=FRESH_SECONDS)]
    unknown = [node.display_name for node in nodes if node.id in topology.dhcp_unknown_node_ids]
    check("FRESH_REPORTS", "Fresh signed reports, with a fresh DHCP observation, from both nodes", not stale and not unknown,
          "Waiting for a fresh signed report from " + ", ".join(stale or unknown) + "." if (stale or unknown) else "Both nodes reported recently.")
    if vip_owner is not None and dhcp_owner is not None and vip_owner.id != dhcp_owner.id:
        owner_obs = dhcp_observation(dhcp_owner, current, freshness_seconds=FRESH_SECONDS)
        vip_obs = dhcp_observation(vip_owner, current, freshness_seconds=FRESH_SECONDS)
        check("DHCP_EXCLUSIVE", f"{dhcp_owner.display_name} serves DHCP; {vip_owner.display_name} has DHCP released",
              owner_obs.active and owner_obs.configured is True and owner_obs.service_active is True and owner_obs.listening is True and vip_obs.released,
              f"{dhcp_owner.display_name} must report DHCP enabled, FTL active and UDP port 67 listening, and {vip_owner.display_name} DHCP disabled and not listening.")
        check("TARGET_HEALTHY", f"{dhcp_owner.display_name} can receive the Virtual IP (DNS healthy, FTL active)",
              dhcp_owner.dns_healthy is True and dhcp_owner.ftl_active is True,
              f"Resolve the DNS or FTL health warning on {dhcp_owner.display_name}; Keepalived would refuse it the Virtual IP.")
    unhealthy = [node.display_name for node in nodes if node.dns_healthy is not True]
    check("DNS_HEALTHY", "DNS is healthy on both nodes", not unhealthy,
          "Resolve the DNS health warning on " + ", ".join(unhealthy) + "." if unhealthy else "Both nodes report healthy DNS.")
    pending_request = bool(cluster.keepalived_requested_at and (not cluster.keepalived_deployed_at or cluster.keepalived_requested_at > cluster.keepalived_deployed_at))
    keepalived_problems = [node.display_name for node in nodes if node.keepalived_runtime_state != "RUNNING" or node.keepalived_status != "DEPLOYED"]
    check("KEEPALIVED", "Keepalived is deployed and running on both nodes, with no pending change",
          cluster.keepalived_status == "DEPLOYED" and not keepalived_problems and not pending_request,
          ("Keepalived must be running with the current deployment on " + ", ".join(keepalived_problems) + "." if keepalived_problems
           else "Wait for the pending Keepalived change to be applied by both nodes."))
    behind = [node.display_name for node in nodes if node.config_generation != cluster.keepalived_generation or node.observed_generation < cluster.role_generation]
    check("GENERATIONS", "Both nodes report the current configuration and role generations", not behind,
          "Generation fencing is not current on " + ", ".join(behind) + "." if behind else "Both nodes report the current generations.")
    old = outdated_agents(nodes)
    check("AGENT_VERSION", "Both agents are version 0.2.15 or newer", not old,
          "Update the HA Agent to 0.2.15 or newer on " + ", ".join(old) + ": older agents may restart Keepalived when a reload fails, and do not report their local automation gates." if old
          else "Both agents never restart a running Keepalived and report their gates.")
    gates_differ = gate_problems(cluster, nodes)
    check("AGENT_GATES", "Both agents report local automation gates matching the cluster settings", not gates_differ,
          "; ".join(gates_differ) + "." if gates_differ else "Both agents' gates match.")
    running = other_operations(cluster)
    check("NO_OPERATION", "No other operation is running", not running,
          "Wait until " + " and ".join(running) + "." if running else "No other operation is running.")
    failed_run, latch_passed, latch_detail = latch_authorisation(cluster)
    check("LATCH", "Maintenance safety latch: acknowledged, if held", latch_passed, latch_detail)

    fingerprint = hashlib.sha256(json.dumps({
        "condition": condition,
        "vip_owner": vip_owner.public_id if vip_owner else None,
        "dhcp_owner": dhcp_owner.public_id if dhcp_owner else None,
        "keepalived_generation": cluster.keepalived_generation,
        "role_generation": cluster.role_generation,
        "maintenance_mode": bool(cluster.maintenance_mode),
        "latch_failed_run": failed_run.public_id if failed_run else None,
        "automatic_failover": bool(cluster.automatic_failover_enabled),
        "automatic_sync": bool(cluster.automatic_sync_enabled),
    }, sort_keys=True).encode()).hexdigest()
    impact: tuple[str, ...] = ()
    if vip_owner is not None and dhcp_owner is not None and vip_owner.id != dhcp_owner.id:
        impact = (
            f"The Virtual IP moves once, from {vip_owner.display_name} to {dhcp_owner.display_name}. Clients using the Virtual IP "
            "for DNS may see a brief pause (typically about a second) while VRRP hands over.",
            f"DHCP keeps running on {dhcp_owner.display_name}. Kaya does not start, stop, promote or demote DHCP, and does not write lease files.",
            f"Keepalived is reloaded, never restarted: once to let {dhcp_owner.display_name} take the Virtual IP, then once per node "
            f"to restore the stable no-preemption configuration, {vip_owner.display_name} first.",
            "Automatic failover and automatic synchronisation keep their current settings. Maintenance mode is held while the repair "
            "runs so neither node's transition hook acts on DHCP.",
            "If any check fails, Kaya stops, does not retry and does not move the Virtual IP back. The evidence is kept for review.",
        ) + (("The maintenance safety latch stays in place before, during and after the repair; release it separately afterwards.",)
             if cluster.maintenance_mode else ())
    return AlignmentPreview(condition, vip_owner, dhcp_owner, tuple(checks), bool(cluster.maintenance_mode),
                            failed_run.public_id if failed_run else None, fingerprint, impact, current)


def preview_json(preview: AlignmentPreview) -> dict[str, Any]:
    return {
        "condition": preview.condition,
        "allowed": preview.allowed,
        "vip_owner": preview.vip_owner.display_name if preview.vip_owner else None,
        "dhcp_owner": preview.dhcp_owner.display_name if preview.dhcp_owner else None,
        "checks": [{"code": item.code, "label": item.label, "passed": item.passed, "detail": item.detail} for item in preview.checks],
        "latch_retained": preview.latch_retained,
        "latch_failed_run_id": preview.latch_failed_run_id,
        "generated_at": preview.generated_at.isoformat() + "Z",
    }


# --------------------------------------------------------------------------------------
# Start (administrator approval)
# --------------------------------------------------------------------------------------


def start_alignment(
    db: Session,
    cluster: HACluster,
    user: User,
    *,
    target_public_id: str,
    fingerprint: str,
    confirmation: str,
    acknowledged: bool,
    latch_authorised: bool,
    wait_seconds: float = 5.0,
) -> HAMaintenanceRun:
    """Start one approved alignment under the cluster's coordination lock (worker thread only)."""
    from app.services.ha_coordination import coordinated_waiting

    cluster_id = cluster.id
    with coordinated_waiting(db, cluster_id, operation="start_alignment", wait_seconds=wait_seconds) as acquired:
        if not acquired:
            raise HAAlignmentBusy("Kaya is already updating this cluster. Wait a moment and review the repair again.")
        return _start_alignment(db, cluster_id, user, target_public_id=target_public_id, fingerprint=fingerprint,
                                confirmation=confirmation, acknowledged=acknowledged, latch_authorised=latch_authorised)


def _deny(db: Session, user: User, cluster: HACluster, reason_code: str, message: str, blockers: list[str] | None = None) -> None:
    write_audit(db, user, "denied", "ha_service_alignment", cluster.public_id,
                detail=f"Align service ownership was refused for {cluster.name}: {message}"[:1000], severity="warning",
                metadata={"reason_code": reason_code, "blocked_checks": (blockers or [])[:12], "service_change_issued": False}, force=True)
    raise HAAlignmentError(message)


def _start_alignment(db: Session, cluster_id: int, user: User, *, target_public_id: str, fingerprint: str,
                     confirmation: str, acknowledged: bool, latch_authorised: bool) -> HAMaintenanceRun:
    cluster = db.query(HACluster).populate_existing().filter(HACluster.id == cluster_id).with_for_update().one()
    if not acknowledged or confirmation.strip() != cluster.name:
        _deny(db, user, cluster, "CONFIRMATION_REQUIRED", f"Type {cluster.name} and confirm the expected Virtual IP move before starting.")
    preview = alignment_preview(db, cluster)
    failed = [check.code for check in preview.checks if not check.passed]
    if not preview.allowed:
        _deny(db, user, cluster, "PREREQUISITES_BLOCKED", "The repair is blocked: " + " ".join(preview.blockers), failed)
    target, source = preview.dhcp_owner, preview.vip_owner
    if target is None or source is None or target.public_id != target_public_id or fingerprint != preview.fingerprint:
        _deny(db, user, cluster, "PREVIEW_CHANGED", "The cluster changed since you reviewed the repair. Review the current preview and confirm again.")
    if cluster.maintenance_mode and not latch_authorised:
        _deny(db, user, cluster, "LATCH_AUTHORISATION_REQUIRED",
              "The maintenance safety latch is held. Confirm that this single repair may run while the latch stays in place.")
    previous = _snapshot_state(cluster)
    previous["maintenance_mode"] = bool(cluster.maintenance_mode)
    run = HAMaintenanceRun(
        cluster_id=cluster.id,
        operation=OPERATION,
        status="RUNNING",
        phase="CONFIRMING_GATES",
        desired_active_node_id=target.id,
        authoritative_node_id=cluster.authoritative_node_id,
        previous_state_json=json.dumps(previous, sort_keys=True),
        result_json=json.dumps({
            "progress": [f"Approved: move only the Virtual IP from {source.display_name} to {target.display_name}, the verified sole DHCP server"],
            "source_node_id": source.id,
            "source_public_id": source.public_id,
            "target_public_id": target.public_id,
            "start_checks": preview_json(preview)["checks"],
            "authorised_under_latch": bool(cluster.maintenance_mode),
            "latch_failed_run_id": preview.latch_failed_run_id,
            "role_generation": cluster.role_generation,
            "expected_keepalived_generation": cluster.keepalived_generation,
            "keepalived_change_issued": False,
            "dhcp_actions_issued": 0,
            "lease_actions_issued": 0,
        }, sort_keys=True),
        requested_by_user_id=user.id,
    )
    cluster.maintenance_mode = True  # agents' hooks never touch DHCP while it is on
    db.add(run)
    db.flush()
    run.phase_started_at = datetime.utcnow()
    _event(db, run, "service_alignment_started", "warning",
           f"Align service ownership started: the Virtual IP will move from {source.display_name} to {target.display_name}, "
           "which already serves DHCP. DHCP and leases are not changed.",
           {"source_node_id": source.public_id, "target_node_id": target.public_id, "authorised_under_latch": preview.latch_retained})
    write_audit(db, user, "started", "ha_service_alignment", cluster.public_id,
                detail=f"Approved Align service ownership for {cluster.name}: Virtual IP from {source.display_name} to {target.display_name}; DHCP unchanged.",
                severity="warning",
                metadata={"maintenance_run_id": run.public_id, "source_node_id": source.public_id, "target_node_id": target.public_id,
                          "authorised_under_retained_latch": preview.latch_retained, "latch_failed_run_id": preview.latch_failed_run_id,
                          "latch_released": False, "dhcp_change_authorised": False, "lease_change_authorised": False},
                commit=False)
    db.commit()
    db.refresh(run)
    from app.services import ha_evaluation_queue

    ha_evaluation_queue.request_evaluation(cluster.id)
    return run


# --------------------------------------------------------------------------------------
# Advance (coordinator)
# --------------------------------------------------------------------------------------


def _result(run: HAMaintenanceRun) -> dict[str, Any]:
    try:
        value = json.loads(run.result_json or "{}")
    except (TypeError, ValueError):
        value = {}
    return value if isinstance(value, dict) else {}


def _save_result(run: HAMaintenanceRun, result: dict[str, Any]) -> None:
    run.result_json = json.dumps(result, sort_keys=True)


def _evidence(cluster: HACluster) -> dict[str, Any]:
    inspection = inspection_json(cluster, inspect_cluster(cluster))
    inspection["keepalived"] = [{
        "name": node.display_name,
        "status": node.keepalived_status,
        "runtime": node.keepalived_runtime_state,
        "config_generation": node.config_generation,
        "applied_checksum": (node.keepalived_config_checksum or "")[:16] or None,
        "last_error": (node.keepalived_last_error or "")[:300] or None,
    } for node in cluster.nodes]
    inspection["cluster_keepalived_generation"] = cluster.keepalived_generation
    return inspection


def _stage(cluster: HACluster, nodes: list[HANode]) -> None:
    from app.services.ha_keepalived_baseline import _stage_node

    for node in nodes:
        _stage_node(cluster, node)
    cluster.status = "DEPLOYING"


def _fail(db: Session, run: HAMaintenanceRun, message: str) -> HAMaintenanceRun:
    cluster = run.cluster
    result = _result(run)
    changed = result.get("keepalived_change_issued") is True
    try:
        previous = json.loads(run.previous_state_json or "{}")
    except (TypeError, ValueError):
        previous = {}
    failed_phase = run.phase
    result["failure_evidence"] = _evidence(cluster)
    result["failed_phase"] = failed_phase
    # Once Keepalived was changed, keep the maintenance hold as a safety latch for review;
    # before that nothing changed, so the previous setting is restored.
    result["latch_active"] = changed
    if not changed:
        cluster.maintenance_mode = previous.get("maintenance_mode") is True
    rows = list(result.get("progress") or [])
    rows.append("Stopped safely: " + message[:300])
    result["progress"] = rows[-20:]
    _save_result(run, result)
    run.status = "FAILED_SAFE"
    run.phase = "PAUSED"
    run.error_redacted = message[:1000]
    run.completed_at = datetime.utcnow()
    _event(db, run, "service_alignment_failed_safe", "critical",
           message + (" Kaya did not move the Virtual IP back and will not retry; the maintenance hold stays on for review."
                      if changed else " No Keepalived, DHCP or lease change was made."),
           {"failed_phase": failed_phase, "keepalived_change_issued": changed})
    from app.services.ha_repair_outcomes import queue_repair_stopped

    queue_repair_stopped(db, cluster, repair="Align service ownership", reference=run.public_id,
                         message=message + (" Keepalived had been changed: the maintenance hold stays on and the Virtual IP was not moved back."
                                            if changed else " Nothing was changed."))
    db.commit()  # the outcome and its notification commit together
    write_audit(db, run.requested_by, "fail_safe", "ha_service_alignment", cluster.public_id, detail=message[:1000], severity="warning",
                metadata={"maintenance_run_id": run.public_id, "failed_phase": failed_phase, "keepalived_change_issued": changed,
                          "dhcp_actions_issued": 0, "lease_actions_issued": 0, "latch_active": changed})
    return run


def _complete(db: Session, run: HAMaintenanceRun, target: HANode, source: HANode, *, how: str) -> HAMaintenanceRun:
    cluster = run.cluster
    result = _result(run)
    try:
        previous = json.loads(run.previous_state_json or "{}")
    except (TypeError, ValueError):
        previous = {}
    target.role = target.desired_role = "ACTIVE"
    source.role = source.desired_role = "STANDBY"
    target.recovery_state = "ACTIVE"
    cluster.current_active_node_id = target.id
    authority_changed = cluster.authoritative_node_id == source.id
    if authority_changed:
        cluster.authoritative_node_id = target.id  # the DHCP server's configuration was the one serving clients
    cluster.maintenance_mode = previous.get("maintenance_mode") is True  # a retained latch stays held
    cluster.status = "HEALTHY"
    from app.services.ha_keepalived_baseline import clear_after_verified_operation

    clear_after_verified_operation(cluster)
    result["verification"] = _evidence(cluster)
    result["authority_changed"] = authority_changed
    rows = list(result.get("progress") or [])
    rows.append(how)
    result["progress"] = rows[-20:]
    _save_result(run, result)
    run.status = "SUCCEEDED"
    run.phase = "COMPLETE"
    run.completed_at = datetime.utcnow()
    run.error_redacted = None
    latch = " The maintenance safety latch is still held; release it separately after review." if cluster.maintenance_mode else ""
    _event(db, run, "service_ownership_aligned", "info",
           f"Service ownership aligned: {target.display_name} holds the Virtual IP and serves DHCP; {source.display_name} is standby. "
           f"Verified from fresh signed reports. DHCP was not changed.{latch}",
           {"active_node_id": target.public_id, "standby_node_id": source.public_id, "latch_retained": bool(cluster.maintenance_mode)})
    from app.services.ha_repair_outcomes import queue_repair_completed

    queue_repair_completed(db, cluster, repair="Align service ownership", reference=run.public_id,
                           message=f"{target.display_name} holds the Virtual IP and serves DHCP, verified from fresh signed reports. DHCP was not changed.{latch}")
    db.commit()  # the outcome and its notification commit together
    write_audit(db, run.requested_by, "complete", "ha_service_alignment", cluster.public_id,
                detail=f"Service ownership aligned on {target.display_name} and verified from fresh signed reports; DHCP unchanged.",
                metadata={"maintenance_run_id": run.public_id, "active_node_id": target.public_id, "dhcp_actions_issued": 0,
                          "lease_actions_issued": 0, "latch_retained": bool(cluster.maintenance_mode), "authority_changed": authority_changed})
    return run


def advance_alignment(db: Session, run: HAMaintenanceRun) -> HAMaintenanceRun:
    """Advance one bounded step; concurrent callers skip while another holds the cluster."""
    if run.operation != OPERATION or run.status != "RUNNING":
        return run
    from app.services.ha_coordination import coordinated, refresh_cluster

    with coordinated(db, run.cluster_id, operation="advance_alignment", run=run) as acquired:
        if not acquired:
            return run
        # Always act on the committed state, also when nested in a coordinator evaluation
        # whose session may hold an older copy of this run (lost-update protection).
        refresh_cluster(db, run.cluster_id, run=run)
        if run.status != "RUNNING":
            return run
        try:
            return _advance(db, run)
        except Exception:
            db.rollback()
            run = db.get(HAMaintenanceRun, run.id)
            return _fail(db, run, "Align service ownership stopped because of an unexpected internal error. No further action was issued.")


def _advance(db: Session, run: HAMaintenanceRun, *, now: datetime | None = None) -> HAMaintenanceRun:
    cluster = run.cluster
    current = now or datetime.utcnow()
    result = _result(run)
    target = run.desired_active_node
    source = next((node for node in cluster.nodes if node.id == result.get("source_node_id")), None)
    if target is None or source is None or target.id == source.id or len(cluster.nodes) != 2:
        return _fail(db, run, "A node involved in the repair no longer exists.")
    if run.started_at and run.started_at < PROCESS_STARTED_AT and result.get("resumed_for_process_started_at") != PROCESS_STARTED_AT.isoformat():
        result["resumed_for_process_started_at"] = PROCESS_STARTED_AT.isoformat()
        _save_result(run, result)
        _event(db, run, "service_alignment_resumed", "info",
               "Kaya restarted during Align service ownership; it continues only from fresh signed reports and the recorded step limits.")
    attempts = dict(result.get("phase_attempts") or {})
    attempts[run.phase] = int(attempts.get(run.phase, 0)) + 1
    result["phase_attempts"] = attempts
    _save_result(run, result)
    phase = run.phase
    elapsed = (current - (run.phase_started_at or current)).total_seconds()

    # --- safety checks that apply to every phase -------------------------------------------
    for node in (source, target):
        if not heartbeat_is_fresh(node, current, freshness_seconds=FRESH_SECONDS):
            return _fail(db, run, f"Lost contact with the HA Agent on {node.display_name}: no signed report for over {FRESH_SECONDS} seconds.")
    target_dhcp = dhcp_observation(target, current, freshness_seconds=FRESH_SECONDS)
    source_dhcp = dhcp_observation(source, current, freshness_seconds=FRESH_SECONDS)
    if not target_dhcp.active or not source_dhcp.released:
        return _fail(db, run, f"DHCP ownership changed or could not be confirmed during the repair: {target.display_name} must keep serving DHCP "
                              f"and {source.display_name} must stay released. Kaya did not touch DHCP.")
    unhealthy = [node.display_name for node in (target, source) if node.dns_healthy is not True]
    if unhealthy:
        return _fail(db, run, f"DNS health deteriorated on {', '.join(unhealthy)} during the repair.")
    rejected = [node for node in (target, source) if node.keepalived_status == "ERROR"]
    if rejected:
        detail = "; ".join(f"{node.display_name}: {node.keepalived_last_error or 'the configuration was rejected'}" for node in rejected)
        return _fail(db, run, f"A node did not apply the Keepalived configuration ({detail}). The agent reported its own rollback outcome; "
                              "Kaya has not verified the running configuration and treats it as unconfirmed until fresh reports show it.")
    not_running = [node.display_name for node in (target, source) if node.keepalived_runtime_state != "RUNNING"]
    if not_running:
        return _fail(db, run, f"Keepalived is not running on {', '.join(not_running)}.")
    expected_generation = int(result.get("expected_keepalived_generation") or 0)
    if (cluster.keepalived_generation != expected_generation or cluster.role_generation != int(result.get("role_generation") or 0)
            or any(node.config_generation > expected_generation for node in (target, source))):
        return _fail(db, run, "Another change altered the HA configuration or role generation during the repair.")
    since = reconcile_topology(cluster, now=current, since=run.phase_started_at, freshness_seconds=FRESH_SECONDS)
    if len(since.vip_owner_ids) > 1:
        dual_since = result.get("dual_vip_since")
        if dual_since is None:
            result["dual_vip_since"] = current.isoformat()
            _save_result(run, result)
        elif (current - datetime.fromisoformat(dual_since)).total_seconds() > DUAL_VIP_TOLERANCE_SECONDS:
            return _fail(db, run, f"Both nodes reported the Virtual IP for more than {DUAL_VIP_TOLERANCE_SECONDS} seconds (split-brain).")
    elif result.get("dual_vip_since"):
        result.pop("dual_vip_since", None)
        _save_result(run, result)
    both_reported = all(node.id in since.fresh_node_ids for node in (target, source))
    if both_reported and not since.vip_owner_ids:
        absent_since = result.get("no_vip_owner_since")
        if absent_since is None:
            result["no_vip_owner_since"] = current.isoformat()
            _save_result(run, result)
        elif (current - datetime.fromisoformat(absent_since)).total_seconds() > NO_VIP_OWNER_TOLERANCE_SECONDS:
            return _fail(db, run, f"No node reported the Virtual IP for more than {NO_VIP_OWNER_TOLERANCE_SECONDS} seconds.")
    elif result.get("no_vip_owner_since"):
        result.pop("no_vip_owner_since", None)
        _save_result(run, result)
    # A single owner other than the expected one is never a reporting artefact.
    other_owner = both_reported and len(since.vip_owner_ids) == 1
    vip_on_target = both_reported and since.vip_owner_ids == (target.id,)
    vip_on_source = both_reported and since.vip_owner_ids == (source.id,)

    if phase == "CONFIRMING_GATES":
        gates_on = all(
            node.last_heartbeat_at and node.last_heartbeat_at >= run.phase_started_at
            and (_gates(node) or {}).get("maintenance_mode") is True and (_gates(node) or {}).get("dhcp_managed") is True
            for node in (target, source)
        )
        if gates_on and vip_on_target:
            _set_phase(run, "VERIFYING", f"{target.display_name} already holds the Virtual IP; no Keepalived change is needed")
        elif gates_on and vip_on_source:
            result = _result(run)
            cluster.cluster_generation += 1
            cluster.keepalived_generation += 1
            for node in (target, source):
                node.desired_role = "ACTIVE" if node is target else "STANDBY"
                node.vrrp_priority = 150 if node is target else 100
            _stage(cluster, [source, target])
            from app.services.ha_keepalived_baseline import record_preemption

            record_preemption(cluster, target, reason="service_alignment")  # verified and cleared by this run
            result.update({"expected_keepalived_generation": cluster.keepalived_generation, "move_generation": cluster.keepalived_generation,
                           "keepalived_change_issued": True})
            _save_result(run, result)
            _set_phase(run, "MOVING_VIP", f"Both agents confirmed DHCP automation is held; Keepalived generation {cluster.keepalived_generation} "
                                          f"lets only {target.display_name} take the Virtual IP")
            _event(db, run, "service_alignment_moving_vip", "warning",
                   f"Keepalived reload requested: {target.display_name} may now take the Virtual IP from {source.display_name}. DHCP is not changed.",
                   {"generation": cluster.keepalived_generation})
        elif elapsed > GATE_TIMEOUT_SECONDS:
            return _fail(db, run, f"Both agents did not confirm within {GATE_TIMEOUT_SECONDS} seconds that their local DHCP automation is held "
                                  "(maintenance gate). Nothing was changed.")
        db.commit()
        return run

    if phase == "MOVING_VIP":
        applied = all(node.keepalived_status == "DEPLOYED" and node.config_generation >= expected_generation for node in (target, source))
        if applied and vip_on_target:
            result = _result(run)
            cluster.cluster_generation += 1
            cluster.keepalived_generation += 1
            result.update({"expected_keepalived_generation": cluster.keepalived_generation, "restore_generation": cluster.keepalived_generation,
                           "vip_moved_at": current.isoformat()})
            _save_result(run, result)
            _stage(cluster, [source])  # the node without the Virtual IP first
            _set_phase(run, "RESTORING_STANDBY_BASELINE", f"{target.display_name} holds the Virtual IP and still serves DHCP; restoring the stable "
                                                          f"configuration on {source.display_name} first")
        elif elapsed > MOVE_TIMEOUT_SECONDS:
            owners = ", ".join(node.display_name for node in (target, source) if node.id in since.vip_owner_ids) or "none reported"
            return _fail(db, run, f"The Virtual IP did not move to {target.display_name} within {MOVE_TIMEOUT_SECONDS} seconds "
                                  f"(current owner reports: {owners}). {target.display_name} may still hold the preempt-capable configuration; "
                                  "the Health assessment tracks it.")
        db.commit()
        return run

    if phase in {"RESTORING_STANDBY_BASELINE", "RESTORING_OWNER_BASELINE"}:
        from app.services.ha_keepalived_baseline import _applied_stable

        if other_owner and not vip_on_target:
            return _fail(db, run, "The Virtual IP owner changed while the stable configuration was being restored.")
        node = source if phase == "RESTORING_STANDBY_BASELINE" else target
        if node.keepalived_status == "DEPLOYED" and node.config_generation >= expected_generation and _applied_stable(cluster, node):
            if phase == "RESTORING_STANDBY_BASELINE":
                _stage(cluster, [target])
                _set_phase(run, "RESTORING_OWNER_BASELINE", f"{source.display_name} applied the stable configuration; reloading {target.display_name}")
            else:
                _set_phase(run, "VERIFYING", f"{target.display_name} applied the stable configuration; verifying from fresh reports")
        elif elapsed > RESTORE_STEP_TIMEOUT_SECONDS:
            return _fail(db, run, f"{node.display_name} did not apply the stable Keepalived configuration within {RESTORE_STEP_TIMEOUT_SECONDS} seconds. "
                                  "Services are aligned, but a node may still hold the preempt-capable configuration.")
        db.commit()
        return run

    if phase == "VERIFYING":
        from app.services.ha_keepalived_baseline import _applied_stable

        missing = []
        if not both_reported:
            missing.append("fresh signed reports from both nodes since verification started")
        elif other_owner and not vip_on_target:
            return _fail(db, run, "Final verification found a different Virtual IP owner.")
        elif not vip_on_target:
            missing.append(f"{target.display_name} as the only Virtual IP owner")
        if both_reported and (since.dhcp_owner_ids != (target.id,) or since.dhcp_unknown_node_ids
                              or not dhcp_observation(source, current, since=run.phase_started_at, freshness_seconds=FRESH_SECONDS).released):
            missing.append(f"{target.display_name} as the only DHCP server with {source.display_name} released")
        if both_reported and not since.topology_safe:
            missing.append("a topology with no ownership or DHCP configuration issue")
        unstable = [node.display_name for node in (target, source)
                    if node.keepalived_status != "DEPLOYED" or node.config_generation != cluster.keepalived_generation or not _applied_stable(cluster, node)]
        if unstable or cluster.keepalived_status != "DEPLOYED":
            missing.append("the stable Keepalived configuration applied at the current generation on " + (", ".join(unstable) or "both nodes"))
        if not missing:
            return _complete(db, run, target, source,
                             how=f"Verified from fresh signed reports: {target.display_name} is the only Virtual IP owner and DHCP server, "
                                 f"{source.display_name} has DHCP released, DNS is healthy and both run the stable configuration")
        result = _result(run)
        result["verification_waiting_for"] = missing
        _save_result(run, result)
        if elapsed > VERIFY_TIMEOUT_SECONDS:
            return _fail(db, run, f"Final verification did not succeed within {VERIFY_TIMEOUT_SECONDS} seconds. Not confirmed: " + "; ".join(missing) + ".")
        db.commit()
        return run
    return _fail(db, run, f"Unknown repair step {phase}.")


def alignment_status(run: HAMaintenanceRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    result = _result(run)
    index = ALIGNMENT_PHASES.index(run.phase) if run.phase in ALIGNMENT_PHASES else (
        ALIGNMENT_PHASES.index(result.get("failed_phase")) if result.get("failed_phase") in ALIGNMENT_PHASES else 0)
    steps = []
    for position, phase in enumerate(ALIGNMENT_PHASES):
        if run.status == "SUCCEEDED" or position < index:
            state = "complete"
        elif position == index:
            state = "failed" if run.status == "FAILED_SAFE" else "current"
        else:
            state = "pending"
        steps.append({"phase": phase, "label": PHASE_LABELS[phase], "state": state})
    verification = result.get("verification") or result.get("failure_evidence") or {}
    return {
        "id": run.public_id,
        "status": run.status,
        "phase": run.phase,
        "error": run.error_redacted,
        "progress": list(result.get("progress") or []),
        "steps": steps,
        "authorised_under_latch": result.get("authorised_under_latch") is True,
        "latch_active": result.get("latch_active") is True,
        "keepalived_change_issued": result.get("keepalived_change_issued") is True,
        "verification": verification,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
    }
