"""Confirmed, deduplicated notifications for HA ownership problems.

Two conditions, both taken from the same signed-report topology the unified
assessment uses:

* **Ownership mismatch** (``OWNERSHIP_MISMATCH``): one node holds the Virtual
  IP while DHCP is served by the other.  Notified once it has persisted for
  ``MISMATCH_CONFIRM_SECONDS``, longer than a normal local DHCP hand-over
  (hold-down plus checks) and several heartbeats, so transient observations
  during a healthy failover never alert.
* **Split-brain** (``DUPLICATE_VIP`` or ``MULTIPLE_DHCP``): two Virtual IP
  owners or two DHCP servers.  Urgent; confirmed after
  ``SPLIT_BRAIN_CONFIRM_SECONDS`` to filter the brief overlap of a VRRP
  election.

Each condition produces one notification per episode (an active-condition
deduplication key), an ``HAEvent`` audit row when confirmed and when cleared,
and a single "ownership restored" notification when a confirmed episode ends.
Transient episodes that clear before confirmation leave no notification.

Read-only towards nodes: nothing here changes VIP, DHCP or Keepalived state.
Costs no queries while ownership is consistent; one indexed query per
evaluation only while a confirmed condition persists.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAEvent
from app.services.ha_notifications import publish_ha_notification, resolve_ha_notification
from app.services.ha_topology import ReconciledTopology, assigned_active_node, reconcile_topology

MISMATCH_CONFIRM_SECONDS = 60
SPLIT_BRAIN_CONFIRM_SECONDS = 20
MISSING_OWNER_CONFIRM_SECONDS = 60
MISMATCH_CODES = frozenset({"OWNERSHIP_MISMATCH"})
SPLIT_BRAIN_CODES = frozenset({"DUPLICATE_VIP", "MULTIPLE_DHCP"})
MISSING_OWNER_CODES = frozenset({"NO_VIP_OWNER", "NO_DHCP_OWNER"})
# Degradation caused by any of these is notified only once confirmed (above), so a
# brief VRRP election never alerts and one incident never raises a generic and a
# specific alert at once.  Other causes keep their immediate degraded alert.
OWNERSHIP_ALERT_CODES = MISMATCH_CODES | SPLIT_BRAIN_CODES | MISSING_OWNER_CODES


def _names(cluster: HACluster, ids) -> str:
    names = [node.display_name for node in cluster.nodes if node.id in set(ids)]
    return " and ".join(names) or "no node"


def _bounded(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _next_step(db: Session, cluster: HACluster, code: str, now: datetime) -> str:
    """The next safe action, taken from the unified assessment's own finding."""
    from app.services.ha_assessment import assess_cluster

    finding = next((item for item in assess_cluster(db, cluster, now=now).findings if item.code == code), None)
    if finding is None:
        return "Review the Health assessment on the cluster overview."
    if finding.repair is not None:
        return f"Next step: {finding.repair.label} (requires administrator approval)."
    return f"Kaya will not change this automatically: {finding.no_repair_reason}"


def _episode_marker(since: datetime) -> str:
    return f'"since": "{since.isoformat()}"'


def _confirmed_event(db: Session, cluster: HACluster, event_type: str, since: datetime) -> HAEvent | None:
    """The confirmation recorded for exactly this episode (identified by when it began)."""
    return (
        db.query(HAEvent)
        .filter(
            HAEvent.cluster_id == cluster.id,
            HAEvent.event_type == event_type,
            HAEvent.occurred_at >= since,
            HAEvent.details_json_redacted.contains(_episode_marker(since)),
        )
        .order_by(HAEvent.id.desc())
        .first()
    )


def update_ownership_alerts(
    db: Session,
    cluster: HACluster,
    *,
    now: datetime | None = None,
    topology: ReconciledTopology | None = None,
) -> None:
    """Track, confirm, notify and resolve ownership problems.  Idempotent; call under the cluster lock."""
    current = now or datetime.utcnow()
    topology = topology or reconcile_topology(cluster, now=current)
    codes = {issue.code for issue in topology.issues}
    split = bool(codes & SPLIT_BRAIN_CODES)
    mismatch = bool(codes & MISMATCH_CODES) and not split
    # Only fresh reports from every node prove ownership is consistent.  Losing
    # sight of the nodes is not recovery: keep the episode unchanged until the
    # reports return, so an outage never resolves and re-raises an alert.
    evidence_complete = len(topology.fresh_node_ids) == len(cluster.nodes)
    missing = bool(codes & MISSING_OWNER_CODES) and not split and not mismatch and evidence_complete
    _track(db, cluster, "split_brain", split, SPLIT_BRAIN_CONFIRM_SECONDS, topology, current, evidence_complete)
    _track(db, cluster, "ownership_mismatch", mismatch, MISMATCH_CONFIRM_SECONDS, topology, current, evidence_complete)
    _track(db, cluster, "missing_owner", missing, MISSING_OWNER_CONFIRM_SECONDS, topology, current, evidence_complete)


def _track(
    db: Session,
    cluster: HACluster,
    kind: str,
    present: bool,
    confirm_seconds: int,
    topology: ReconciledTopology,
    now: datetime,
    evidence_complete: bool,
) -> None:
    attribute = f"{kind}_since"
    since = getattr(cluster, attribute)
    # A missing owner is the cluster's degraded incident: it shares that key, so the
    # existing "cluster recovered" notification resolves it once the cluster is healthy.
    key = f"pihole:cluster:{cluster.public_id}:" + ("degraded" if kind == "missing_owner" else kind)
    confirmed_type = f"{kind}_confirmed"
    if present:
        if since is None:
            setattr(cluster, attribute, now)
            db.commit()
            return
        if now - since < timedelta(seconds=confirm_seconds):
            return
        if _confirmed_event(db, cluster, confirmed_type, since) is not None:
            return  # already notified for this episode
        _notify(db, cluster, kind, key, since, topology, now)
        return
    if since is None or not evidence_complete:
        return
    episode_confirmed = _confirmed_event(db, cluster, confirmed_type, since) is not None
    setattr(cluster, attribute, None)
    if not episode_confirmed:
        db.commit()  # transient: cleared before confirmation, nothing was notified
        return
    if kind == "missing_owner":
        db.add(HAEvent(
            cluster_id=cluster.id, node_id=None, event_type="missing_owner_resolved", severity="info", source="kaya",
            message=f"A node on {cluster.name} again holds the virtual IP and DHCP is served.",
            details_json_redacted=json.dumps({"since": since.isoformat()}, sort_keys=True), occurred_at=now,
        ))
        db.commit()  # the cluster-recovered notification follows once the cluster is healthy
        return
    label = "Split-brain" if kind == "split_brain" else "The DNS and DHCP ownership mismatch"
    db.add(HAEvent(
        cluster_id=cluster.id, node_id=None, event_type=f"{kind}_resolved", severity="info", source="kaya",
        message=f"{label} on {cluster.name} has cleared. One node holds the virtual IP and serves DHCP.",
        details_json_redacted=json.dumps({"since": since.isoformat()}, sort_keys=True), occurred_at=now,
    ))
    db.commit()
    resolve_ha_notification(db, key)
    publish_ha_notification(
        db,
        cluster,
        event_type_id="pihole.ownership.recovered",
        title="Pi-hole ownership restored",
        message=_bounded(f"{label} on {cluster.name} has cleared. One node again holds the virtual IP and serves DHCP.", 500),
        deduplication_key=f"{key}:recovered:{since.isoformat()}",
        source_entity_type="ha_cluster",
        source_entity_id=cluster.public_id,
        correlation_id=cluster.public_id,
        metadata={"cluster_id": cluster.public_id, "condition": kind},
    )


def _notify(db: Session, cluster: HACluster, kind: str, key: str, since: datetime, topology: ReconciledTopology, now: datetime) -> None:
    vip = _names(cluster, topology.vip_owner_ids)
    dhcp = _names(cluster, topology.dhcp_owner_ids)
    assigned = assigned_active_node(cluster)
    minutes = max(1, int((now - since).total_seconds() // 60))
    if kind == "split_brain":
        code = "DUPLICATE_VIP" if len(topology.vip_owner_ids) > 1 else "MULTIPLE_DHCP"
        problem = (f"Both {vip} report the virtual IP" if code == "DUPLICATE_VIP" else f"DHCP is running on both {dhcp}")
        title = "Pi-hole split-brain detected"
        event_type_id = "pihole.ownership.split_brain"
        severity = "critical"
        impact = "Clients may reach different nodes or receive conflicting addresses. Kaya blocks automatic DHCP activation."
    elif kind == "missing_owner":
        codes = {issue.code for issue in topology.issues}
        code = "NO_VIP_OWNER" if "NO_VIP_OWNER" in codes else "NO_DHCP_OWNER"
        problem = "No node holds the virtual IP" if code == "NO_VIP_OWNER" else "No node is serving DHCP"
        title = "Pi-hole cluster degraded"
        event_type_id = "pihole.cluster.degraded"
        severity = "critical"
        impact = ("Clients using the virtual IP for DNS get no answers." if code == "NO_VIP_OWNER"
                  else "Clients cannot obtain or renew DHCP leases.")
    else:
        code = "OWNERSHIP_MISMATCH"
        problem = f"{vip} holds the virtual IP but DHCP is served by {dhcp}"
        title = "Pi-hole DNS and DHCP on different nodes"
        event_type_id = "pihole.ownership.mismatch"
        severity = "warning"
        impact = "DNS and DHCP are no longer protected as one service."
    assigned_text = f" Assigned Active: {assigned.display_name}." if assigned else ""
    message = _bounded(
        f"{cluster.name}: {problem} (for about {minutes} min).{assigned_text} {impact} {_next_step(db, cluster, code, now)}",
        500,
    )
    db.add(HAEvent(
        cluster_id=cluster.id, node_id=None, event_type=f"{kind}_confirmed", severity=severity, source="kaya",
        message=message,
        details_json_redacted=json.dumps({"since": since.isoformat(), "code": code}, sort_keys=True), occurred_at=now,
    ))
    db.commit()
    publish_ha_notification(
        db,
        cluster,
        event_type_id=event_type_id,
        title=title,
        message=message,
        deduplication_key=key,
        source_entity_type="ha_cluster",
        source_entity_id=cluster.public_id,
        correlation_id=cluster.public_id,
        metadata={"cluster_id": cluster.public_id, "condition": kind, "code": code},
    )
