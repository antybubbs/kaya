"""Read-only view model for the Health & Repair workspace.

Health & Repair is the cluster's existing Maintenance (Reconcile) page,
consolidated: one status line, the observed service ownership and supporting
state, the single recommended repair, the approved repairs themselves (Align
service ownership, Keepalived baseline restoration, maintenance latch review)
and, under Advanced, the low-level tools (Reconcile State, Reinitialise).

Everything here is derived from stored signed agent reports and Kaya's own
records.  It never writes, never contacts a node and introduces no action.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HACluster, HAMaintenanceRun, HASyncRun
from app.services.ha_keepalived_baseline import outstanding
from app.services.ha_recovery import NodeRecovery
from app.services.ha_topology import FRESH_SECONDS, assigned_active_node, pihole_manages_dhcp, reconcile_topology


@dataclass(frozen=True)
class OverviewItem:
    key: str
    label: str
    value: str
    tone: str  # ok | warn | bad | muted
    note: str = ""


def _when(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "never"


def _names(cluster: HACluster, ids) -> str:
    wanted = set(ids)
    return " and ".join(sorted(node.display_name for node in cluster.nodes if node.id in wanted)) or "none"


def service_overview(db: Session, cluster: HACluster, recovery: dict[int, NodeRecovery], *, now: datetime) -> tuple[OverviewItem, ...]:
    topology = reconcile_topology(cluster, now=now, freshness_seconds=FRESH_SECONDS)
    managed = pihole_manages_dhcp(cluster)
    items: list[OverviewItem] = []
    vip = topology.vip_owner_ids
    items.append(OverviewItem("vip_owner", "Virtual IP (DNS) observed on", _names(cluster, vip),
                              "ok" if len(vip) == 1 else "bad",
                              "Two nodes report it (split-brain)" if len(vip) > 1 else "No node reports it" if not vip else ""))
    if managed:
        dhcp = topology.dhcp_owner_ids
        aligned = len(dhcp) == 1 and tuple(dhcp) == tuple(vip)
        items.append(OverviewItem("dhcp_owner", "DHCP observed on", _names(cluster, dhcp) if dhcp else ("unknown" if topology.dhcp_unknown_node_ids else "none"),
                                  "ok" if aligned else "bad",
                                  "" if aligned else "Two DHCP servers" if len(dhcp) > 1 else "Not on the Virtual IP owner" if dhcp else "No confirmed DHCP server"))
    else:
        items.append(OverviewItem("dhcp_owner", "DHCP", "Not managed by Pi-hole", "muted"))
    active = assigned_active_node(cluster)
    standby = next((node for node in cluster.nodes if active is not None and node.id != active.id), None)
    items.append(OverviewItem("roles", "Assigned roles",
                              f"Active: {active.display_name}; Standby: {standby.display_name if standby else 'none'}" if active else "No Active node assigned",
                              "ok" if active and tuple(vip) == (active.id,) else "warn",
                              "" if not active or tuple(vip) == (active.id,) else "Differs from the observed Virtual IP owner"))
    if standby is not None:
        result = recovery.get(standby.id)
        if standby.id in vip:
            readiness, tone, note = "Holds the Virtual IP now", "warn", "Readiness is assessed once the assigned roles and observed ownership agree"
        elif result is None:
            readiness, tone, note = "Unknown", "muted", ""
        elif result.ready or result.state == "STANDBY":
            readiness, tone, note = "Ready to take over", "ok", ""
        else:
            blockers = result.operational_blockers
            readiness, tone, note = result.state.replace("_", " ").title(), "warn", blockers[0] if blockers else ""
        items.append(OverviewItem("standby", f"Standby readiness ({standby.display_name})", readiness, tone, note))
    latest_sync = (db.query(HASyncRun).filter(HASyncRun.cluster_id == cluster.id)
                   .order_by(HASyncRun.created_at.desc(), HASyncRun.id.desc()).first())
    sync_mode = ("automatic" if cluster.automatic_sync_enabled and not cluster.automatic_sync_hold
                 else "automatic, on hold" if cluster.automatic_sync_enabled else "manual")
    if latest_sync is None:
        items.append(OverviewItem("config_sync", "Configuration sync", f"No sync recorded ({sync_mode})", "muted"))
    else:
        status = latest_sync.status
        tone = "ok" if status in {"SUCCEEDED", "RESOLVED", "IN_SYNC"} else "bad" if status in {"FAILED", "ERROR", "ROLLED_BACK"} else "warn"
        items.append(OverviewItem("config_sync", "Configuration sync",
                                  f"{status.replace('_', ' ').title()} at {_when(latest_sync.completed_at or latest_sync.created_at)} ({sync_mode})", tone,
                                  "Differences are waiting for review" if status == "PLANNED" else ""))
    state = cluster.lease_replication
    if managed and state is not None:
        lease_tone = "ok" if state.status == "CURRENT" and state.applied_generation >= state.desired_generation else (
            "bad" if state.status in {"ERROR", "CONFLICT"} else "warn")
        items.append(OverviewItem("lease_sync", "DHCP lease replication",
                                  f"{state.status.replace('_', ' ').title()}: generation {state.applied_generation} of {state.desired_generation}",
                                  lease_tone, (state.last_error_redacted or "")[:200]))
    elif managed:
        items.append(OverviewItem("lease_sync", "DHCP lease replication", "Not started", "muted"))
    restoration = outstanding(cluster)
    if restoration is not None:
        holder = next((node.display_name for node in cluster.nodes if node.id == restoration.get("preempt_node_id")), "a node")
        items.append(OverviewItem("keepalived", "Keepalived configuration",
                                  f"{holder} may still preempt (restoration {str(restoration.get('state')).replace('_', ' ').lower()})", "warn"))
    else:
        deployed = cluster.keepalived_status == "DEPLOYED"
        items.append(OverviewItem("keepalived", "Keepalived configuration",
                                  f"Stable, generation {cluster.keepalived_generation}" if deployed else cluster.keepalived_status.replace("_", " ").title(),
                                  "ok" if deployed else "warn"))
    holds = []
    from app.services.ha_maintenance import active_maintenance

    if cluster.maintenance_mode and active_maintenance(cluster) is not None:
        holds.append("maintenance hold for the running operation (automatic failover and DHCP automation paused)")
    elif cluster.maintenance_mode:
        holds.append("maintenance hold (automatic failover and DHCP automation paused)")
    if cluster.automatic_sync_hold:
        holds.append("automatic configuration sync on hold")
    items.append(OverviewItem("holds", "Maintenance holds", ("; ".join(holds)[:1].upper() + "; ".join(holds)[1:]) if holds else "None", "warn" if holds else "ok"))
    items.append(OverviewItem("automation", "Automation settings",
                              f"Automatic failover {'on' if cluster.automatic_failover_enabled else 'off'}; automatic sync {'on' if cluster.automatic_sync_enabled else 'off'}; "
                              "automatic Keepalived restoration off", "muted"))
    return tuple(items)


def alignment_remaining(cluster: HACluster, run: HAMaintenanceRun | None, *, now: datetime) -> list[dict[str, Any]]:
    """What is still not right after Align service ownership stopped safely, and the next safe step for each."""
    if run is None or run.status != "FAILED_SAFE":
        return []
    from app.services.ha_alignment import _condition, _result

    result = _result(run)
    topology = reconcile_topology(cluster, now=now, freshness_seconds=FRESH_SECONDS)
    condition = _condition(cluster, topology)
    items: list[dict[str, Any]] = []
    vip, dhcp = _names(cluster, topology.vip_owner_ids), _names(cluster, topology.dhcp_owner_ids)
    if condition == "ALIGNED":
        items.append({"open": False, "label": "Service ownership",
                      "detail": f"{vip} now holds the Virtual IP and serves DHCP. The stopped repair did not verify this; the Health assessment confirms it from fresh reports."})
    elif condition == "MISMATCH":
        items.append({"open": True, "label": "Service ownership",
                      "detail": f"Still split: Virtual IP on {vip}, DHCP on {dhcp}. Align service ownership can be approved again once its checks pass.",
                      "anchor": "#align-ownership"})
    else:
        items.append({"open": True, "label": "Service ownership",
                      "detail": f"Virtual IP reported by {vip}; DHCP by {dhcp if topology.dhcp_owner_ids else 'none confirmed'}. See the Health assessment for this fault."})
    restoration = outstanding(cluster)
    if restoration is not None:
        holder = next((node.display_name for node in cluster.nodes if node.id == restoration.get("preempt_node_id")), "A node")
        items.append({"open": True, "label": "Preempt-capable Keepalived configuration",
                      "detail": f"{holder} may still hold the preempt-capable configuration from generation {restoration.get('preempt_generation')}. "
                                "Restore the stable configuration (below) once its checks pass.",
                      "anchor": "#restore-baseline"})
    elif result.get("keepalived_change_issued") is True:
        items.append({"open": False, "label": "Preempt-capable Keepalived configuration", "detail": "None outstanding: the stable configuration is verified on both nodes."})
    for node in sorted(cluster.nodes, key=lambda item: item.display_name):
        if node.keepalived_status == "ERROR":
            items.append({"open": True, "label": f"Keepalived on {node.display_name}",
                          "detail": f"Last apply failed: {(node.keepalived_last_error or 'no detail')[:200]}. Kaya has not verified its running configuration."})
    if cluster.maintenance_mode and result.get("latch_active") is True:
        items.append({"open": True, "label": "Maintenance safety latch",
                      "detail": "Held because Keepalived had been changed. Automatic failover and DHCP automation stay paused until you review and release it.",
                      "anchor": "#latch-review"})
    return items
