"""Automatic DHCP handover by verified release (PROPOSAL; requires approval before any rollout).

After an unplanned Virtual IP move (a Keepalived stop, crash, restart or fault on the DHCP owner),
DHCP must follow the Virtual IP without two DHCP servers ever serving clients.  In a two-node
cluster the only proof that the other node is *not* serving DHCP is positive evidence from that
node itself (or an independent fencing authority).  Silence (no VRRP adverts, no ARP reply, no
DHCPOFFER, no heartbeat) is never proof: a hung, partitioned or misconfigured server can still serve.

This module classifies the situation from stored signed reports and, when automatic failover is
enabled, starts one controlled handover run (the existing failover state machine) that:

* demotes the old owner if it still serves DHCP, with the existing atomic-handover authorisation;
* waits for a fresh signed report proving the release (UDP/67 closed, DHCP stopped);
* promotes the Virtual IP owner under the run's generation fence (the node's helper also refuses if
  another DHCP server answers its discovery check; that check is a veto only, never proof);
* never moves the Virtual IP (it already moved) and never retries automatically.

When the old owner is silent, nothing is promoted on Kaya's own judgement or an administrator's
word: the ``DHCP_HANDOVER_BLOCKED`` finding raises a critical alert.  Promotion then requires fresh,
positive evidence from an independent fencing provider (``external_fence_evidence``; none is
configured, so this fails closed).  An administrator may *record* a physical check
(``record_physical_check``); that record is audited and never authorises DHCP.

Every promotion first moves the explicit DHCP authority (``ha_dhcp_authority``) to the target.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAEvent, HAFailoverRun, HANode, User
from app.services.audit import write_audit
from app.services.ha_agent_installer import version_tuple
from app.services.ha_topology import FRESH_SECONDS, dhcp_observation, heartbeat_is_fresh, pihole_manages_dhcp, reconcile_topology

HANDOVER_AGENT_VERSION = (0, 2, 16)
STABILITY_SECONDS = 10
COOLDOWN_SECONDS = 600
FENCE_MAX_AGE_SECONDS = 60
TRANSITION_KIND = "AUTOMATIC_DHCP_HANDOVER"


class HADHCPHandoverError(ValueError):
    pass


@dataclass(frozen=True)
class HandoverState:
    """NOT_APPLICABLE | READY_PROMOTE | READY_DEMOTE_FIRST | BLOCKED_SOURCE_SILENT | BLOCKED | COOLDOWN"""

    state: str
    target: HANode | None = None
    source: HANode | None = None
    detail: str = ""


@dataclass(frozen=True)
class FenceEvidence:
    """Evidence from an independent fencing provider (power controller, managed switch port, hypervisor)."""

    provider: str
    node_public_id: str
    fenced: bool
    method: str
    verified_at: datetime


def external_fence_evidence(cluster: HACluster, node: HANode) -> FenceEvidence | None:
    """No fencing provider is configured in this proposal: always None, so promotion fails closed.

    A provider must query the fencing device itself (never Kaya's own reachability of the node) and
    report when it last verified that ``node`` is powered off or isolated from the client network.
    """
    return None


def _valid_fence(evidence: FenceEvidence | None, node: HANode, now: datetime) -> tuple[bool, str]:
    if evidence is None:
        return False, "no external fencing provider is configured"
    if not isinstance(evidence, FenceEvidence) or evidence.node_public_id != node.public_id or not evidence.provider:
        return False, "the fencing evidence does not identify this node"
    if evidence.fenced is not True:
        return False, f"the fencing provider reports that {node.display_name} is not fenced"
    age = (now - evidence.verified_at).total_seconds()
    if age < -5 or age > FENCE_MAX_AGE_SECONDS:
        return False, "the fencing evidence is not fresh"
    return True, ""


def fence_check(cluster: HACluster, node: HANode, *, now: datetime | None = None,
                provider: Callable[[HACluster, HANode], FenceEvidence | None] | None = None) -> tuple[bool, str, FenceEvidence | None]:
    """Ask the fencing provider; any failure is treated as *not fenced* (fail closed)."""
    current = now or datetime.utcnow()
    try:
        evidence = (provider or external_fence_evidence)(cluster, node)
    except Exception:  # provider or device failure: never evidence of fencing
        return False, "the fencing provider failed", None
    valid, reason = _valid_fence(evidence, node, current)
    return valid, reason, evidence


def _recent_handover_away_from(cluster: HACluster, target: HANode, now: datetime) -> HAFailoverRun | None:
    """Anti-flap: a recent automatic handover that took DHCP *away from* ``target`` (so moving it back would flap).

    Start-up convergence (DHCP re-promoted on the node that already held the Virtual IP) and a first
    genuine failover are not flapping and do not count.
    """
    for run in sorted(cluster.failover_runs, key=lambda item: (item.created_at or datetime.min, item.id or 0), reverse=True):
        try:
            kind = json.loads(run.report_json or "{}").get("transition_kind")
        except (TypeError, ValueError):
            kind = None
        try:
            took_ownership = json.loads(run.report_json or "{}").get("source_was_active") is True
        except (TypeError, ValueError):
            took_ownership = False
        if (kind == TRANSITION_KIND and took_ownership and run.created_at and run.created_at >= now - timedelta(seconds=COOLDOWN_SECONDS)
                and run.source_node_id == target.id):
            return run
    return None


def handover_assessment(cluster: HACluster, *, now: datetime | None = None) -> HandoverState:
    """Classify the DHCP situation after an unplanned Virtual IP move.  Read-only."""
    current = now or datetime.utcnow()
    if not pihole_manages_dhcp(cluster) or len(cluster.nodes) != 2:
        return HandoverState("NOT_APPLICABLE")
    topology = reconcile_topology(cluster, now=current, freshness_seconds=FRESH_SECONDS)
    if len(topology.vip_owner_ids) != 1:
        return HandoverState("NOT_APPLICABLE", detail="No single Virtual IP owner.")
    target = next(node for node in cluster.nodes if node.id == topology.vip_owner_ids[0])
    source = next(node for node in cluster.nodes if node.id != target.id)
    target_dhcp = dhcp_observation(target, current, freshness_seconds=FRESH_SECONDS)
    if target_dhcp.active or target.id not in topology.fresh_node_ids:
        return HandoverState("NOT_APPLICABLE", target, source)  # already serving, or not verifiable
    if not target_dhcp.released:
        # Only a target positively proven stopped is promoted (lab finding: a briefly unknown state
        # must never trigger a promotion that would replace a serving node's live leases).
        return HandoverState("BLOCKED", target, source, f"{target.display_name} DHCP state is not verified ({target_dhcp.state.lower()}).")
    if len(topology.dhcp_owner_ids) > 1:
        return HandoverState("BLOCKED", target, source, "Two DHCP servers are reported.")
    source_fresh = heartbeat_is_fresh(source, current, freshness_seconds=FRESH_SECONDS)
    source_dhcp = dhcp_observation(source, current, freshness_seconds=FRESH_SECONDS)
    if not source_fresh or source_dhcp.state in {"UNKNOWN"}:
        return HandoverState(
            "BLOCKED_SOURCE_SILENT", target, source,
            f"{source.display_name} is not reporting, so Kaya cannot verify that it stopped serving DHCP. A silent node may still "
            "be serving clients (hung, partitioned or misconfigured), so Kaya will not start a second DHCP server.",
        )
    blocked = promotion_blocker(cluster, target, source, current)
    if blocked is not None:
        return blocked
    if source_dhcp.released:
        return HandoverState("READY_PROMOTE", target, source, "Release verified from a fresh signed report.")
    if source_dhcp.active and not source.vip_owned:
        return HandoverState("READY_DEMOTE_FIRST", target, source, f"{source.display_name} still serves DHCP without the Virtual IP.")
    return HandoverState("BLOCKED", target, source, f"{source.display_name} DHCP state is {source_dhcp.state.lower()}.")


def promotion_blocker(cluster: HACluster, target: HANode, source: HANode, current: datetime) -> HandoverState | None:
    """Conditions every automatic promotion needs, whatever the release evidence."""
    from app.services.ha_failover import active_failover
    from app.services.ha_maintenance import active_maintenance

    if active_failover(cluster) is not None or active_maintenance(cluster) is not None:
        return HandoverState("BLOCKED", target, source, "Another operation is running.")
    if _recent_handover_away_from(cluster, target, current) is not None:
        return HandoverState("COOLDOWN", target, source,
                             f"DHCP was handed over away from {target.display_name} in the last {COOLDOWN_SECONDS // 60} minutes; Kaya waits "
                             "until that window has passed before moving it back, so DHCP does not flap.")
    stable = target.vip_stable_since is not None and (current - target.vip_stable_since).total_seconds() >= STABILITY_SECONDS
    if not stable or target.dns_healthy is not True or target.ftl_active is not True:
        return HandoverState("BLOCKED", target, source, "Waiting for a stable, healthy Virtual IP owner.")
    if any(version_tuple(node.agent_version) < HANDOVER_AGENT_VERSION for node in cluster.nodes):
        return HandoverState("BLOCKED", target, source, "Both agents must run the revised protocol version.")
    if target.dhcp_guard_mode == "dns_only":
        return HandoverState("BLOCKED", target, source,
                             f"{target.display_name} runs Pi-hole DNS-only: its DHCP setting could not be made safe when FTL started, "
                             "so it cannot serve DHCP until its configuration is repaired and FTL restarted.")
    from app.services.ha_dhcp_authority import lease_snapshot_ready

    ready, reason = lease_snapshot_ready(cluster, target)
    if not ready:
        return HandoverState("BLOCKED", target, source, f"Waiting for leases: {reason}. DHCP is not moved until it is.")
    return None


def _new_run(db: Session, cluster: HACluster, state: HandoverState, *, phase: str, evidence: str, requested_by: User | None) -> HAFailoverRun:
    lease = cluster.lease_replication
    cluster.role_generation += 1
    cluster.cluster_generation += 1
    cluster.maintenance_mode = True  # node hooks never act on DHCP while the handover runs
    run = HAFailoverRun(
        cluster_id=cluster.id, source_node_id=state.source.id, target_node_id=state.target.id, preferred_node_id=cluster.preferred_node_id,
        status="RUNNING", phase=phase, dhcp_managed=True, lease_generation=int(state.target.lease_generation or 0) if lease is None else int(lease.applied_generation or 0),
        role_generation=cluster.role_generation, requested_by_user_id=requested_by.id if requested_by else None,
        report_json=json.dumps({"automatic": requested_by is None, "transition_kind": TRANSITION_KIND, "vip_already_on_target": True,
                                "source_was_active": cluster.current_active_node_id == state.source.id,
                                "source": state.source.public_id, "target": state.target.public_id, "release_evidence": evidence},
                               sort_keys=True),
    )
    db.add(run)
    db.flush()
    return run


def start_automatic_dhcp_handover(db: Session, cluster: HACluster, *, now: datetime | None = None) -> HAFailoverRun | None:
    """Start one verified handover if, and only if, release is (or can be) verified.  Caller holds the cluster lock."""
    if not cluster.automatic_failover_enabled or cluster.maintenance_mode:
        return None
    current = now or datetime.utcnow()
    state = handover_assessment(cluster, now=current)
    from app.services.ha_failover import _event, sync_promotion_authority

    if state.state == "BLOCKED_SOURCE_SILENT":
        return _start_after_external_fence(db, cluster, state, current)
    if state.state not in {"READY_PROMOTE", "READY_DEMOTE_FIRST"}:
        return None
    phase = "PROMOTING_TARGET" if state.state == "READY_PROMOTE" else "DEMOTING_SOURCE"
    run = _new_run(db, cluster, state, phase=phase, evidence="verified_signed_report", requested_by=None)
    sync_promotion_authority(run)
    _event(db, run, "automatic_dhcp_handover_started", "warning",
           f"Automatic DHCP handover to {state.target.display_name} (the Virtual IP owner): "
           + ("release of " + state.source.display_name + " already verified." if phase == "PROMOTING_TARGET"
              else state.source.display_name + " still serves DHCP; it will be released and verified first."))
    db.commit()
    return run


def _start_after_external_fence(db: Session, cluster: HACluster, state: HandoverState, current: datetime) -> HAFailoverRun | None:
    """A silent source: promote only with fresh, positive evidence from an independent fencing provider."""
    from app.services.ha_failover import _event, sync_promotion_authority

    if promotion_blocker(cluster, state.target, state.source, current) is not None:
        return None
    if not (state.target.vip_owned and state.target.dns_healthy is True and state.target.ftl_active is True):
        return None
    fenced, _reason, evidence = fence_check(cluster, state.source, now=current)
    if not fenced:
        return None  # fail closed; the DHCP_HANDOVER_BLOCKED finding explains the next step
    run = _new_run(db, cluster, state, phase="PROMOTING_TARGET", evidence="external_fence", requested_by=None)
    report = json.loads(run.report_json)
    report["fence"] = {"provider": evidence.provider[:80], "method": evidence.method[:40], "verified_at": evidence.verified_at.isoformat() + "Z"}
    run.report_json = json.dumps(report, sort_keys=True)
    sync_promotion_authority(run)
    _event(db, run, "automatic_dhcp_handover_started", "critical",
           f"{state.source.display_name} is silent; the fencing provider {evidence.provider[:80]} reports it fenced "
           f"({evidence.method[:40]}). DHCP will be promoted on {state.target.display_name} from the last staged lease snapshot.")
    db.commit()
    return run


def record_physical_check(db: Session, cluster: HACluster, user: User, *, checked_node_public_id: str,
                          confirmation: str, acknowledged: bool) -> None:
    """Record an administrator's physical check of a node.  Audited; never authorises DHCP.

    A typed confirmation is not an independently enforced fence: the node may be powered on again,
    reconnected, or may not be the machine the administrator checked.  Promotion still needs verified
    release from the node itself or fresh external fencing evidence.
    """
    node = next((item for item in cluster.nodes if item.public_id == checked_node_public_id), None)
    if node is None:
        raise HADHCPHandoverError("The node does not belong to this cluster.")
    if not acknowledged or confirmation.strip() != cluster.name:
        write_audit(db, user, "denied", "ha_dhcp_handover", cluster.public_id, detail="Physical check not recorded: confirmation missing.",
                    severity="warning", metadata={"reason_code": "CONFIRMATION_REQUIRED", "service_change_issued": False}, force=True)
        raise HADHCPHandoverError(f"Type {cluster.name} and confirm what you physically checked.")
    db.add(HAEvent(cluster_id=cluster.id, node_id=node.id, event_type="dhcp_physical_check_recorded", severity="warning", source="kaya", occurred_at=datetime.utcnow(),
                   message=f"An administrator recorded a physical check of {node.display_name}. This is a record only: Kaya does not "
                           "promote DHCP because of it. Promotion still requires verified release from the node or external fencing evidence."))
    write_audit(db, user, "physical_check_recorded", "ha_dhcp_handover", cluster.public_id, severity="warning",
                detail=f"Physical check of {node.display_name} recorded (record only; no DHCP change).",
                metadata={"checked_node_id": node.public_id, "authorises_dhcp": False, "service_change_issued": False}, commit=False)
    db.commit()
