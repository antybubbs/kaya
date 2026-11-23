"""Administrator-approved restoration of the stable Keepalived baseline.

When a maintenance step, a controlled failover or Align service ownership gave
one node a preempt-capable Keepalived configuration and then stopped (or
completed without verifying the stable configuration), the preemption grant is
tracked by ``ha_keepalived_baseline``.  Automatic restoration is disabled by
default and stays disabled.  This module lets an administrator approve **one**
restoration attempt for **one** cluster:

* the preview is read-only and built from stored signed agent reports;
* the attempt runs the existing bounded restoration steps of the coordinator
  (node without the Virtual IP first, then the owner, each a reload, then
  verification that the Virtual IP owner did not change);
* it never moves the Virtual IP, never touches DHCP or leases and never
  restarts Keepalived (agents 0.2.15+ never fall back to a restart);
* it stops in ``BLOCKED`` on the first failed check and is never retried
  without a new approval;
* under a retained maintenance safety latch it needs the same explicit,
  audited authorisation as Align service ownership, after the failed operation
  has been acknowledged, and it never releases the latch.  If Kaya cannot
  identify the operation behind the latch the attempt is blocked (fail closed).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import HACluster, HANode, User
from app.services.audit import write_audit
from app.services.ha_alignment import AlignmentCheck, gate_problems, latch_authorisation, other_operations, outdated_agents
from app.services.ha_keepalived_baseline import ACTIVE_STATES, begin_restoration, outstanding
from app.services.ha_maintenance import _registered
from app.services.ha_topology import FRESH_SECONDS, heartbeat_is_fresh, pihole_manages_dhcp, reconcile_topology

APPROVABLE_STATES = {"PENDING_APPROVAL", "BLOCKED"}
STATE_DETAILS = {
    "OUTSTANDING": "The operation that granted preemption has not finished yet, or the nodes have not reported since. Kaya offers restoration once it has.",
    "PENDING_APPROVAL": "A node may still hold a preempt-capable configuration. Automatic restoration is disabled, so it waits for an administrator.",
    "BLOCKED": "The previous restoration attempt stopped safely. An administrator may approve one new attempt once every check passes.",
    "RESTORING_STANDBY": "A restoration attempt is running.",
    "RESTORING_OWNER": "A restoration attempt is running.",
    "VERIFYING": "A restoration attempt is running.",
}


class HABaselineRepairError(ValueError):
    pass


class HABaselineRepairBusy(HABaselineRepairError):
    """Another operation holds the cluster's coordination lock; nothing was started."""


@dataclass(frozen=True)
class RestorationPreview:
    state: str | None
    preempt_node: HANode | None
    owner: HANode | None
    standby: HANode | None
    checks: tuple[AlignmentCheck, ...]
    latch_retained: bool
    latch_failed_run_id: str | None
    fingerprint: str
    impact: tuple[str, ...]
    detail: str | None
    previous_block: str | None
    generated_at: datetime

    @property
    def relevant(self) -> bool:
        return self.state is not None

    @property
    def running(self) -> bool:
        return self.state in ACTIVE_STATES

    @property
    def state_detail(self) -> str:
        return STATE_DETAILS.get(self.state or "", "")

    @property
    def allowed(self) -> bool:
        return self.state in APPROVABLE_STATES and all(check.passed for check in self.checks)

    @property
    def blockers(self) -> list[str]:
        return [check.detail for check in self.checks if not check.passed]


def restoration_preview(db: Session, cluster: HACluster, *, now: datetime | None = None) -> RestorationPreview:
    """Decide from stored signed observations only whether one restoration may be approved.  Never writes."""
    current = now or datetime.utcnow()
    state = outstanding(cluster) or {}
    phase = state.get("state")
    by_id = {node.id: node for node in cluster.nodes}
    nodes = sorted(cluster.nodes, key=lambda node: (node.display_name, node.id))
    topology = reconcile_topology(cluster, now=current, freshness_seconds=FRESH_SECONDS)
    owner = by_id.get(topology.vip_owner_ids[0]) if len(topology.vip_owner_ids) == 1 else None
    standby = next((node for node in nodes if owner is not None and node.id != owner.id), None)
    checks: list[AlignmentCheck] = []

    def check(code: str, label: str, passed: bool, detail: str) -> None:
        checks.append(AlignmentCheck(code, label, bool(passed), detail))

    check("STATE", "A preempt-capable configuration is outstanding and no restoration is running", phase in APPROVABLE_STATES,
          STATE_DETAILS.get(phase, "No preempt-capable configuration is outstanding; nothing needs restoring."))
    check("AGENTS_REGISTERED", "Both nodes have a registered HA Agent", len(cluster.nodes) == 2 and all(_registered(node) for node in cluster.nodes),
          "Register an active agent on both nodes.")
    stale = [node.display_name for node in nodes if not heartbeat_is_fresh(node, current, freshness_seconds=FRESH_SECONDS)]
    check("FRESH_REPORTS", "Fresh signed reports from both nodes", not stale,
          "Waiting for a fresh signed report from " + ", ".join(stale) + "." if stale else "Both nodes reported recently.")
    owners = topology.vip_owner_ids
    check("VIP_OWNER", "Exactly one node holds the Virtual IP", len(owners) == 1,
          ("Two nodes report the Virtual IP (split-brain). Restoration never runs then; resolve the duplicate first." if len(owners) > 1
           else "No node reports the Virtual IP. That is a separate fault; restoration never assigns the Virtual IP." if not owners
           else f"{owner.display_name} holds the Virtual IP and keeps it."))
    managed = pihole_manages_dhcp(cluster)
    dhcp_ok = not managed or (len(topology.dhcp_owner_ids) <= 1 and not topology.dhcp_unknown_node_ids)
    check("DHCP_SAFE", "No second DHCP server and a fresh DHCP observation from both nodes", dhcp_ok,
          ("Two DHCP servers are running; restoration never runs during a DHCP conflict." if len(topology.dhcp_owner_ids) > 1
           else "Waiting for a fresh DHCP observation from both nodes." if not dhcp_ok
           else "Restoration does not change DHCP." if managed else "DHCP is not managed by Pi-hole for this cluster."))
    check("OWNER_DNS", "DNS is healthy on the Virtual IP owner", owner is not None and owner.dns_healthy is True,
          (f"Resolve the DNS health warning on {owner.display_name} first; Keepalived could move the Virtual IP during the reload." if owner is not None
           else "Needs exactly one Virtual IP owner."))
    pending_request = bool(cluster.keepalived_requested_at and (not cluster.keepalived_deployed_at or cluster.keepalived_requested_at > cluster.keepalived_deployed_at))
    rejected = [node for node in nodes if node.keepalived_status == "ERROR"]
    problems = [node.display_name for node in nodes if node.keepalived_runtime_state != "RUNNING" or node.keepalived_status != "DEPLOYED"]
    if rejected:
        keepalived_detail = ("; ".join(f"{node.display_name} reported a failed Keepalived apply ({(node.keepalived_last_error or 'no detail')[:160]})" for node in rejected)
                             + ". Kaya cannot confirm the running configuration there, so it will not stage another change on top of it. "
                               "Check Keepalived on that node, re-run the Safety checks, then redeploy Keepalived (Setup: Shared DNS address).")
    elif problems:
        keepalived_detail = "Keepalived must be running with the current deployment on " + ", ".join(problems) + "."
    else:
        keepalived_detail = "Wait for the pending Keepalived change to be applied by both nodes." if pending_request else "Keepalived is deployed and running on both nodes."
    check("KEEPALIVED", "Keepalived is deployed and running on both nodes, with no pending change",
          cluster.keepalived_status == "DEPLOYED" and not problems and not pending_request, keepalived_detail)
    behind = [node.display_name for node in nodes if node.config_generation != cluster.keepalived_generation]
    check("GENERATIONS", "Both nodes report the current configuration generation", not behind,
          "Generation fencing is not current on " + ", ".join(behind) + "." if behind else "Both nodes report the current generation.")
    old = outdated_agents(nodes)
    check("AGENT_VERSION", "Both agents are version 0.2.15 or newer", not old,
          "Update the HA Agent to 0.2.15 or newer on " + ", ".join(old) + ": older agents may restart Keepalived when a reload fails." if old
          else "Both agents apply Keepalived changes as reloads and never restart a running Keepalived.")
    gates = gate_problems(cluster, nodes)
    check("AGENT_GATES", "Both agents report local automation gates matching the cluster settings", not gates,
          "; ".join(gates) + "." if gates else "Both agents' gates match.")
    running = other_operations(cluster)
    check("NO_OPERATION", "No other operation is running", not running,
          "Wait until " + " and ".join(running) + "." if running else "No other operation is running.")
    failed_run, latch_passed, latch_detail = latch_authorisation(cluster)
    check("LATCH", "Maintenance safety latch: acknowledged, if held", latch_passed, latch_detail)

    preempt_node = by_id.get(state.get("preempt_node_id"))
    fingerprint = hashlib.sha256(json.dumps({
        "state": phase,
        "preempt_node": preempt_node.public_id if preempt_node else None,
        "preempt_generation": state.get("preempt_generation"),
        "restore_generation": state.get("restore_generation"),
        "owner": owner.public_id if owner else None,
        "keepalived_generation": cluster.keepalived_generation,
        "maintenance_mode": bool(cluster.maintenance_mode),
        "latch_failed_run": failed_run.public_id if failed_run else None,
    }, sort_keys=True).encode()).hexdigest()
    impact: tuple[str, ...] = ()
    if owner is not None and standby is not None:
        impact = (
            f"The Virtual IP stays on {owner.display_name}. Kaya pushes the stable no-preemption configuration as a Keepalived reload "
            f"(never a restart): {standby.display_name} first, then {owner.display_name}.",
            "DHCP, leases and Pi-hole settings are not changed.",
            f"Kaya verifies from fresh signed reports that both nodes run the stable configuration and that {owner.display_name} still "
            "holds the Virtual IP. If the owner changes, a node rejects the configuration or a step takes longer than 120 seconds, "
            "it stops, does not retry and keeps the evidence.",
        ) + (("The maintenance safety latch stays in place; release it separately afterwards.",) if cluster.maintenance_mode else ())
    return RestorationPreview(phase, preempt_node, owner, standby, tuple(checks), bool(cluster.maintenance_mode),
                              failed_run.public_id if failed_run else None, fingerprint, impact,
                              state.get("detail"), state.get("previous_block"), current)


def _deny(db: Session, user: User, cluster: HACluster, reason_code: str, message: str, blockers: list[str] | None = None) -> None:
    write_audit(db, user, "denied", "ha_keepalived_baseline", cluster.public_id,
                detail=f"Keepalived baseline restoration was refused for {cluster.name}: {message}"[:1000], severity="warning",
                metadata={"reason_code": reason_code, "blocked_checks": (blockers or [])[:14], "service_change_issued": False}, force=True)
    raise HABaselineRepairError(message)


def approve_restoration(
    db: Session,
    cluster: HACluster,
    user: User,
    *,
    fingerprint: str,
    confirmation: str,
    acknowledged: bool,
    latch_authorised: bool,
    wait_seconds: float = 5.0,
) -> dict:
    """Start one approved restoration attempt under the cluster's coordination lock (worker thread only)."""
    from app.services.ha_coordination import coordinated_waiting

    cluster_id = cluster.id
    with coordinated_waiting(db, cluster_id, operation="approve_baseline_restoration", wait_seconds=wait_seconds) as acquired:
        if not acquired:
            raise HABaselineRepairBusy("Kaya is already updating this cluster. Wait a moment and review the restoration again.")
        cluster = db.query(HACluster).populate_existing().filter(HACluster.id == cluster_id).with_for_update().one()
        if not acknowledged or confirmation.strip() != cluster.name:
            _deny(db, user, cluster, "CONFIRMATION_REQUIRED", f"Type {cluster.name} and confirm the restoration before starting.")
        preview = restoration_preview(db, cluster)
        failed = [check.code for check in preview.checks if not check.passed]
        if not preview.allowed:
            _deny(db, user, cluster, "PREREQUISITES_BLOCKED", "The restoration is blocked: " + " ".join(preview.blockers), failed)
        if fingerprint != preview.fingerprint:
            _deny(db, user, cluster, "PREVIEW_CHANGED", "The cluster changed since you reviewed the restoration. Review the current preview and confirm again.")
        if cluster.maintenance_mode and not latch_authorised:
            _deny(db, user, cluster, "LATCH_AUTHORISATION_REQUIRED",
                  "The maintenance safety latch is held. Confirm that this single restoration may run while the latch stays in place.")
        state = outstanding(cluster) or {}
        previous_state = state.get("state")
        begin_restoration(db, cluster, state, preview.owner, now=datetime.utcnow(), applied_by="administrator", approved_by=f"user:{user.id}")
        write_audit(db, user, "approved", "ha_keepalived_baseline", cluster.public_id,
                    detail=f"Approved one Keepalived baseline restoration for {cluster.name}: stable configuration on "
                           f"{preview.standby.display_name} first, then {preview.owner.display_name}; Virtual IP and DHCP unchanged.",
                    severity="warning",
                    metadata={"restore_generation": cluster.keepalived_generation, "previous_state": previous_state,
                              "owner_node_id": preview.owner.public_id, "preempt_node_id": preview.preempt_node.public_id if preview.preempt_node else None,
                              "authorised_under_retained_latch": preview.latch_retained, "latch_failed_run_id": preview.latch_failed_run_id,
                              "latch_released": False, "vip_move_authorised": False, "dhcp_change_authorised": False},
                    commit=False)
        db.commit()
        from app.services import ha_evaluation_queue

        ha_evaluation_queue.request_evaluation(cluster.id)
        return {"restore_generation": cluster.keepalived_generation, "owner": preview.owner.display_name}


def restoration_status(cluster: HACluster) -> dict | None:
    """Plain-language progress of the current or last restoration attempt."""
    state = outstanding(cluster)
    if state is None:
        return None
    order = ("RESTORING_STANDBY", "RESTORING_OWNER", "VERIFYING")
    labels = {"RESTORING_STANDBY": "Stable configuration on the node without the Virtual IP",
              "RESTORING_OWNER": "Stable configuration on the Virtual IP owner",
              "VERIFYING": "Verifying from fresh reports that the owner did not change"}
    phase = state.get("state")
    steps = []
    if phase in order:
        index = order.index(phase)
        steps = [{"label": labels[item], "state": "complete" if position < index else "current" if position == index else "pending"}
                 for position, item in enumerate(order)]
    by_id = {node.id: node for node in cluster.nodes}
    preempt = by_id.get(state.get("preempt_node_id"))
    return {
        "state": phase,
        "steps": steps,
        "preempt_node": preempt.display_name if preempt else None,
        "preempt_generation": state.get("preempt_generation"),
        "reason": str(state.get("reason") or "").replace("_", " "),
        "detail": state.get("detail"),
        "attempts": int(state.get("attempts") or 0),
        "applied_by": state.get("applied_by"),
    }
