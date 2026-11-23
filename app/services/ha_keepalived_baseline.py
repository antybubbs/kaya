"""Restore Kaya's stable Keepalived baseline after a preempt-capable configuration.

Kaya's stable configuration uses ``nopreempt`` on both nodes, so a recovered
node never takes the Virtual IP back on its own.  To move the VIP on purpose,
a REINITIALISE (``WAITING_FOR_VIP``) or a controlled failover/rollback
(``MOVING_VIP``) temporarily gives the destination ``preempt_delay``.  Until a
later ``nopreempt`` generation is verified on both nodes, that node could
still preempt unexpectedly (Gate A defects D8 and D9).

This module records every such grant and drives one bounded restoration from
the existing HA coordinator (no separate scheduler):

1. Wait until no maintenance or failover operation is running and both nodes
   report Keepalived deployed and running, with exactly one fresh VIP owner.
2. Push a new ``nopreempt`` generation to the node *without* the VIP first.
   That removes any remaining preemption risk without touching the VIP.
3. Then push it to the VIP owner, as a reload, never a restart.
4. Declare success only when fresh signed reports show both nodes on the new
   generation, Keepalived running, and the same exclusive VIP owner as when
   restoration started.

Restoration never touches DHCP, never moves the VIP and never retries
automatically.  A rejected configuration, an uncertain rollback, a timeout or
any change of VIP ownership stops it in ``BLOCKED`` with an explanation for
the Health assessment.  A later Keepalived deployment by an administrator,
which always renders ``nopreempt``, also satisfies the baseline once verified.

Automatic restoration is **off** unless ``ha_keepalived_baseline_restoration``
is enabled in deployment settings.  While off, Kaya only records and reports
the outstanding restoration (``PENDING_APPROVAL``) and changes nothing until an
administrator approves one restoration attempt on the Health & Repair page
(``ha_baseline_repair``).  An approved attempt runs exactly the same bounded
steps; a ``BLOCKED`` attempt is never retried without a new approval.

Behaviour validated in the isolated two-node lab with real VRRP (Keepalived
2.2.8, Kaya-rendered configurations, the real Keepalived helper): reloads of
the MASTER kept the VIP in every run, while a MASTER crash moved it, which is
why the final verification is required.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAEvent, HANode
from app.services.audit import write_audit
from app.services.ha_topology import reconcile_topology

STEP_TIMEOUT_SECONDS = 120
ACTIVE_STATES = {"RESTORING_STANDBY", "RESTORING_OWNER", "VERIFYING"}


def restoration_enabled() -> bool:
    from app.core.config import get_settings

    return bool(get_settings().ha_keepalived_baseline_restoration)


def outstanding(cluster: HACluster) -> dict[str, Any] | None:
    try:
        value = json.loads(cluster.keepalived_restoration_json or "null")
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _save(cluster: HACluster, state: dict[str, Any] | None) -> None:
    cluster.keepalived_restoration_json = json.dumps(state, sort_keys=True) if state else None


def record_preemption(cluster: HACluster, node: HANode, *, reason: str) -> None:
    """Record that ``node`` was given a preempt-capable configuration at the current generation."""
    _save(cluster, {
        "state": "OUTSTANDING",
        "preempt_node_id": node.id,
        "preempt_generation": cluster.keepalived_generation,
        "reason": reason,
        "recorded_at": datetime.utcnow().isoformat(),
    })


def track_completion_restore(cluster: HACluster, owner: HANode) -> None:
    """A controlled failover's completion already pushes nopreempt to both nodes; only verify it."""
    state = outstanding(cluster) or {"preempt_node_id": owner.id, "preempt_generation": cluster.keepalived_generation - 1, "reason": "controlled_failover"}
    now = datetime.utcnow().isoformat()
    state.update({"state": "VERIFYING", "restore_generation": cluster.keepalived_generation, "owner_id": owner.id,
                  "started_at": now, "phase_started_at": now, "detail": None, "applied_by": "operation_completion"})
    _save(cluster, state)


def clear_after_verified_operation(cluster: HACluster) -> None:
    """An approved operation verified the stable configuration on both nodes itself (no commit)."""
    _save(cluster, None)


def _event(db: Session, cluster: HACluster, event_type: str, severity: str, message: str, details: dict | None = None) -> None:
    db.add(HAEvent(cluster_id=cluster.id, node_id=None, event_type=event_type, severity=severity, source="kaya",
                   message=message[:1000], details_json_redacted=json.dumps(details or {}, sort_keys=True), occurred_at=datetime.utcnow()))


def _operation_running(cluster: HACluster) -> bool:
    from app.services.ha_failover import active_failover
    from app.services.ha_maintenance import active_maintenance

    return active_maintenance(cluster) is not None or active_failover(cluster) is not None


def _blocked(db: Session, cluster: HACluster, state: dict[str, Any], reason: str) -> None:
    state.update({"state": "BLOCKED", "detail": reason[:500], "blocked_at": datetime.utcnow().isoformat()})
    _save(cluster, state)
    _event(db, cluster, "keepalived_restoration_blocked", "warning",
           f"Kaya stopped restoring the stable Keepalived configuration: {reason} Kaya will not retry automatically; "
           "review it on the Health & Repair page, where an administrator can approve one new attempt once its safety checks pass.",
           {"state": "BLOCKED", "restore_generation": state.get("restore_generation"), "applied_by": state.get("applied_by")})
    from app.services.ha_repair_outcomes import queue_repair_stopped

    queue_repair_stopped(db, cluster, repair="Keepalived baseline restoration", reference=f"baseline-{state.get('restore_generation')}",
                         message=f"Restoring the stable Keepalived configuration stopped: {reason} The Virtual IP and DHCP were not moved by Kaya.")
    db.commit()  # the outcome and its notification commit together
    write_audit(db, None, "blocked", "ha_keepalived_baseline", cluster.public_id, detail=reason[:500], severity="warning",
                metadata={"cluster_id": cluster.public_id, "vip_moved_by_kaya": False, "dhcp_changed": False,
                          "applied_by": state.get("applied_by"), "restore_generation": state.get("restore_generation")})


def _restored(db: Session, cluster: HACluster, state: dict[str, Any], how: str, *, owner_verified: bool) -> None:
    _save(cluster, None)
    ownership = " The Virtual IP owner did not change." if owner_verified else ""
    _event(db, cluster, "keepalived_baseline_restored", "info",
           f"The stable Keepalived configuration (no automatic preemption) is verified on both nodes {how}.{ownership}",
           {"generation": cluster.keepalived_generation, "how": how, "owner_verified": owner_verified})
    if state.get("applied_by") in {"administrator", "restoration"}:
        from app.services.ha_repair_outcomes import queue_repair_completed

        queue_repair_completed(db, cluster, repair="Keepalived baseline restoration", reference=f"baseline-{cluster.keepalived_generation}",
                               message=f"The stable Keepalived configuration is verified on both nodes {how}.{ownership}")
    db.commit()  # the outcome and its notification commit together
    write_audit(db, None, "restored", "ha_keepalived_baseline", cluster.public_id,
                detail=f"Stable Keepalived configuration verified on both nodes {how}.",
                metadata={"cluster_id": cluster.public_id, "generation": cluster.keepalived_generation,
                          "vip_moved_by_kaya": False, "dhcp_changed": False, "applied_by": state.get("applied_by")})
    if state.get("applied_by") not in {"administrator", "restoration"}:
        # Satisfied by a later deployment: close any open "stopped safely" incident.
        from app.services.ha_notifications import resolve_ha_notification
        from app.services.ha_repair_outcomes import failure_key

        resolve_ha_notification(db, failure_key(cluster))


def _applied_stable(cluster: HACluster, node: HANode) -> bool:
    """The configuration this node reported applying is exactly the stable (nopreempt) rendering."""
    from app.services.ha_keepalived import HAKeepalivedError, render_keepalived_config

    try:
        expected = render_keepalived_config(cluster, node, allow_preemption=False).checksum
    except HAKeepalivedError:
        return False
    return bool(node.keepalived_config_checksum and node.keepalived_config_checksum == expected)


def _baseline_holds(cluster: HACluster, fresh_ids: set[int], *, newer_than: int = 0) -> bool:
    """Both nodes run, and reported applying, the stable rendering of the current generation."""
    return bool(
        cluster.keepalived_status == "DEPLOYED"
        and cluster.keepalived_generation > newer_than
        and all(
            node.keepalived_status == "DEPLOYED"
            and node.keepalived_runtime_state == "RUNNING"
            and node.config_generation >= cluster.keepalived_generation
            and node.id in fresh_ids
            and _applied_stable(cluster, node)
            for node in cluster.nodes
        )
    )


def _stage_node(cluster: HACluster, node: HANode) -> None:
    node.keepalived_status = "PENDING_AGENT"
    node.keepalived_last_error = None
    cluster.keepalived_status = "PENDING_AGENT"
    cluster.keepalived_requested_at = datetime.utcnow()


def begin_restoration(db: Session, cluster: HACluster, state: dict[str, Any], owner: HANode, *, now: datetime,
                      applied_by: str, approved_by: str | None = None) -> None:
    """Stage the first restoration step (no commit).  The caller holds the cluster lock and has
    verified one fresh, exclusive Virtual IP owner and a fully deployed, running Keepalived."""
    standby = next(node for node in cluster.nodes if node.id != owner.id)
    cluster.cluster_generation += 1
    cluster.keepalived_generation += 1
    stamp = now.isoformat()
    previous_detail = state.get("detail") if state.get("state") == "BLOCKED" else None
    state.update({"state": "RESTORING_STANDBY", "restore_generation": cluster.keepalived_generation, "owner_id": owner.id,
                  "standby_id": standby.id, "started_at": stamp, "phase_started_at": stamp, "detail": None, "applied_by": applied_by,
                  "attempts": int(state.get("attempts") or 0) + 1})
    if approved_by:
        state["approved_by"] = approved_by
    if previous_detail:
        state["previous_block"] = previous_detail
    _stage_node(cluster, standby)
    _save(cluster, state)
    who = "approved by an administrator" if applied_by == "administrator" else "automatic"
    _event(db, cluster, "keepalived_restoration_started", "info",
           f"Restoring the stable Keepalived configuration ({who}): {standby.display_name} (no Virtual IP) first, then {owner.display_name}. "
           "DHCP and the Virtual IP are not changed.", {"generation": cluster.keepalived_generation, "applied_by": applied_by})


def advance_keepalived_baseline(db: Session, cluster: HACluster, *, now: datetime | None = None) -> None:
    """One bounded, idempotent step.  Call from the coordinator while holding the cluster's lock."""
    state = outstanding(cluster)
    if state is None or _operation_running(cluster):
        return
    current = now or datetime.utcnow()
    topology = reconcile_topology(cluster, now=current)
    fresh = set(topology.fresh_node_ids)
    owners = topology.vip_owner_ids
    phase = state.get("state")

    if phase in {"OUTSTANDING", "PENDING_APPROVAL", "BLOCKED"}:
        # From BLOCKED only a newer, administrator-requested deployment counts.
        newer_than = int(state.get("restore_generation") or 0) if phase == "BLOCKED" else 0
        if _baseline_holds(cluster, fresh, newer_than=newer_than):
            _restored(db, cluster, state, "after a later Keepalived deployment", owner_verified=False)
            return
        if phase == "BLOCKED":
            return  # explicit administrator action required; never retried automatically
        if not restoration_enabled():
            if phase != "PENDING_APPROVAL":
                state["state"] = "PENDING_APPROVAL"
                _save(cluster, state)
                _event(db, cluster, "keepalived_restoration_pending", "warning",
                       "A node may still hold a preempt-capable Keepalived configuration from a completed or stopped operation. "
                       "Automatic restoration is not enabled; redeploy Keepalived from the Deployment page to restore it.",
                       {"preempt_generation": state.get("preempt_generation")})
                db.commit()
            return
        ready = (
            len(owners) == 1
            and len(fresh) == len(cluster.nodes) == 2
            and cluster.keepalived_status == "DEPLOYED"
            and all(node.keepalived_status == "DEPLOYED" and node.keepalived_runtime_state == "RUNNING"
                    and node.config_generation >= cluster.keepalived_generation for node in cluster.nodes)
        )
        if not ready:
            return  # wait for a stable, fully reported topology; nothing is pushed meanwhile
        owner = next(node for node in cluster.nodes if node.id == owners[0])
        begin_restoration(db, cluster, state, owner, now=current, applied_by="restoration")
        db.commit()
        return

    if phase not in ACTIVE_STATES:
        return
    restore_generation = int(state["restore_generation"])
    owner = next((node for node in cluster.nodes if node.id == state.get("owner_id")), None)
    if owner is None:
        _blocked(db, cluster, state, "The recorded Virtual IP owner no longer exists.")
        return
    standby = next(node for node in cluster.nodes if node.id != owner.id)
    started = datetime.fromisoformat(state["phase_started_at"])
    failed = [node for node in cluster.nodes if node.keepalived_status == "ERROR"]
    if failed:
        detail = "; ".join(f"{node.display_name}: {node.keepalived_last_error or 'configuration rejected'}" for node in failed)
        _blocked(db, cluster, state, f"A node did not apply the stable configuration ({detail}). The agent reported its own rollback outcome; Kaya does not assume it succeeded.")
        return
    if len(owners) > 1 or (len(owners) == 1 and owners[0] != owner.id and owners[0] in fresh):
        _blocked(db, cluster, state, "The Virtual IP owner changed while the stable configuration was being restored.")
        return
    if (current - started).total_seconds() > STEP_TIMEOUT_SECONDS:
        _blocked(db, cluster, state, f"Restoration did not complete within {STEP_TIMEOUT_SECONDS} seconds ({phase.replace('_', ' ').lower()}).")
        return

    if phase == "RESTORING_STANDBY":
        if standby.keepalived_status == "DEPLOYED" and standby.config_generation >= restore_generation:
            state.update({"state": "RESTORING_OWNER", "phase_started_at": current.isoformat()})
            _stage_node(cluster, owner)
            _save(cluster, state)
            db.commit()
        return
    if phase == "RESTORING_OWNER":
        if owner.keepalived_status == "DEPLOYED" and owner.config_generation >= restore_generation:
            state.update({"state": "VERIFYING", "phase_started_at": current.isoformat()})
            _save(cluster, state)
            db.commit()
        return
    # VERIFYING: fresh signed reports after the last apply must show the same exclusive owner.
    verified = (
        owners == (owner.id,)
        and all(node.id in fresh and node.last_heartbeat_at and node.last_heartbeat_at >= started for node in cluster.nodes)
        and all(node.config_generation >= restore_generation for node in cluster.nodes)
        and _baseline_holds(cluster, fresh)
    )
    if verified:
        how = "after the operation completed" if state.get("applied_by") == "operation_completion" else "(non-owner first, then the Virtual IP owner)"
        _restored(db, cluster, state, how, owner_verified=True)
