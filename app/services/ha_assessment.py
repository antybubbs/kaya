"""Unified, read-only HA health assessment.

One authoritative description of a cluster's health that every HA view shows
the same way.  It reuses the existing checks (topology, inspection, recovery,
failover readiness, maintenance latch, lease and configuration state) rather
than re-deriving them, and turns them into findings that say:

* what is actually wrong, with the observations that show it;
* how severe it is and what it affects;
* whether it is transient, being healed automatically, needs an administrator's
  approval, or is blocked (nothing in Kaya can safely fix it);
* the exact safety prerequisites, each marked met or not;
* the existing repair action that can safely succeed, or why there is none;
* what automatic recovery has already attempted.

Strictly read-only and deterministic: it never writes, never calls a node or
Pi-hole, and the same stored state and ``now`` give the same findings in the
same order.  It introduces no new action; repairs link to existing pages.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HACluster, HANode, HASyncRun
from app.services.ha_agent_installer import CURRENT_AGENT_VERSION, version_tuple
from app.services.ha_failover import AUTOMATIC_AGENT_VERSION, FailoverReadiness, active_failover, failover_readiness
from app.services.ha_maintenance import ClusterInspection, active_maintenance, inspect_cluster, latch_preview
from app.services.ha_recovery import NodeRecovery, recovery_snapshot
from app.services.ha_topology import FRESH_SECONDS, assigned_active_node, pihole_manages_dhcp, reconcile_topology
from app.services.ha_keepalived_baseline import outstanding as keepalived_restoration

TRANSIENT = "TRANSIENT"
SELF_HEALING = "SELF_HEALING"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
BLOCKED = "BLOCKED"
DISPOSITION_LABELS = {
    TRANSIENT: "Temporary: no action needed",
    SELF_HEALING: "Kaya is fixing this automatically",
    APPROVAL_REQUIRED: "Needs an administrator's approval",
    BLOCKED: "Kaya cannot fix this automatically",
}
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
STALE_AGENT_GRACE = timedelta(minutes=2)


@dataclass(frozen=True)
class Prerequisite:
    label: str
    satisfied: bool


@dataclass(frozen=True)
class RepairAction:
    key: str
    label: str
    path: str
    service_impact: str


@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    category: str
    severity: str
    condition: str
    impact: str
    disposition: str
    observations: tuple[tuple[str, str], ...] = ()
    prerequisites: tuple[Prerequisite, ...] = ()
    repair: RepairAction | None = None
    no_repair_reason: str | None = None
    automatic_attempts: tuple[str, ...] = ()
    node: str | None = None

    @property
    def disposition_label(self) -> str:
        return DISPOSITION_LABELS[self.disposition]

    @property
    def sort_key(self) -> tuple:
        return (SEVERITY_ORDER.get(self.severity, 9), self.category, self.code, self.node or "")


@dataclass(frozen=True)
class ClusterAssessment:
    cluster_public_id: str
    assessed_at: datetime
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @property
    def overall(self) -> str:
        severities = {finding.severity for finding in self.findings}
        return "CRITICAL" if "critical" in severities else "ATTENTION" if "warning" in severities else "HEALTHY"

    @property
    def counts(self) -> dict[str, int]:
        result = {"critical": 0, "warning": 0, "info": 0}
        for finding in self.findings:
            result[finding.severity] = result.get(finding.severity, 0) + 1
        return result

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_public_id,
            "assessed_at": self.assessed_at.isoformat() + "Z",
            "overall": self.overall,
            "counts": self.counts,
            "findings": [
                {
                    "code": finding.code,
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity,
                    "node": finding.node,
                    "condition": finding.condition,
                    "impact": finding.impact,
                    "disposition": finding.disposition,
                    "observations": [list(item) for item in finding.observations],
                    "prerequisites": [{"label": item.label, "satisfied": item.satisfied} for item in finding.prerequisites],
                    "repair": None if finding.repair is None else {"key": finding.repair.key, "label": finding.repair.label, "path": finding.repair.path, "service_impact": finding.repair.service_impact},
                    "no_repair_reason": finding.no_repair_reason,
                    "automatic_attempts": list(finding.automatic_attempts),
                }
                for finding in self.findings
            ],
        }


def _when(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "never"


def _yes(value: Any) -> str:
    return "unknown" if value is None else "yes" if value else "no"


def _page(cluster: HACluster, section: str) -> str:
    return f"/high-availability/clusters/{cluster.public_id}/{section}"


class _Builder:
    def __init__(self, db: Session, cluster: HACluster, now: datetime, inspection: ClusterInspection,
                 recovery: dict[int, NodeRecovery], readiness: FailoverReadiness):
        self.db, self.cluster, self.now = db, cluster, now
        self.inspection, self.recovery, self.readiness = inspection, recovery, readiness
        self.topology = reconcile_topology(cluster, now=now, freshness_seconds=FRESH_SECONDS)
        self.nodes = sorted(cluster.nodes, key=lambda node: (node.display_name, node.id))
        self.by_id = {node.id: node for node in self.nodes}
        self.managed = pihole_manages_dhcp(cluster)
        self.active_run = active_maintenance(cluster)
        self.failover_run = active_failover(cluster)
        self.findings: list[Finding] = []

    # --- shared facts --------------------------------------------------------------

    def names(self, ids) -> str:
        return ", ".join(sorted(self.by_id[node_id].display_name for node_id in ids if node_id in self.by_id)) or "none"

    def ownership_observations(self) -> tuple[tuple[str, str], ...]:
        # Assigned by a verified, authorised operation; never copied from an observation.
        stored = assigned_active_node(self.cluster) or self.by_id.get(self.cluster.current_active_node_id)
        authority = self.by_id.get(self.cluster.authoritative_node_id)
        return (
            ("Virtual IP reported by", self.names(self.topology.vip_owner_ids)),
            ("DHCP served by", self.names(self.topology.dhcp_owner_ids) if self.managed else "not managed by Pi-hole"),
            ("Assigned Active node", stored.display_name if stored else "none"),
            ("Configuration authority", authority.display_name if authority else "none"),
            ("Nodes with fresh signed reports", self.names(self.topology.fresh_node_ids)),
        )

    def no_operation_running(self) -> Prerequisite:
        return Prerequisite("No maintenance or failover operation is running", self.active_run is None and self.failover_run is None)

    def fresh_reports(self) -> Prerequisite:
        return Prerequisite("Both nodes have fresh signed reports", len(self.topology.fresh_node_ids) == len(self.nodes) == 2)

    def single_owner(self) -> Prerequisite:
        aligned = len(self.topology.vip_owner_ids) == 1 and (not self.managed or self.topology.dhcp_owner_ids == self.topology.vip_owner_ids)
        return Prerequisite("Exactly one node owns the Virtual IP and DHCP", aligned)

    def self_heal_attempts(self) -> tuple[str, ...]:
        runs = sorted((run for run in self.cluster.maintenance_runs if run.operation == "DHCP_SELF_HEAL"),
                      key=lambda run: (run.created_at or datetime.min, run.id), reverse=True)[:3]
        return tuple(f"DHCP configuration repair {run.status.replace('_', ' ').lower()} at {_when(run.completed_at or run.created_at)}" for run in runs)

    def self_heal_latched(self) -> bool:
        for run in self.cluster.maintenance_runs:
            if run.operation == "DHCP_SELF_HEAL" and run.status in {"FAILED_SAFE", "FAILED"}:
                try:
                    if json.loads(run.result_json or "{}").get("latch_active") is True:
                        return True
                except (TypeError, ValueError):
                    continue
        return False

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def redeploy_route(self) -> RepairAction:
        """Redeploying Keepalived needs a validated cluster; point to the Safety checks first when it is not."""
        from app.services.ha_keepalived import deployment_blockers

        if any(item.startswith("Complete read-only validation") for item in deployment_blockers(self.cluster, now=self.now)):
            return RepairAction("VALIDATE_THEN_REDEPLOY", "Re-run the safety checks, then redeploy Keepalived", _page(self.cluster, "validation"),
                                "Read-only checks first; the redeployment is a Keepalived reload on both nodes")
        return RepairAction("KEEPALIVED_DEPLOY", "Review and redeploy Keepalived", _page(self.cluster, "deployment"), "Keepalived reload on both nodes")

    def failed_failover_holding(self):
        """A failed-safe controlled failover keeps the maintenance hold; its recovery is the Failover page's rollback."""
        runs = sorted(self.cluster.failover_runs, key=lambda run: (run.created_at or datetime.min, run.id or 0), reverse=True)
        latest = runs[0] if runs else None
        return latest if latest is not None and latest.status == "FAILED_SAFE" else None

    # --- ownership and service topology ------------------------------------------

    def ownership(self) -> None:
        codes = {issue.code: issue for issue in self.inspection.issues}
        cluster = self.cluster
        never_automatic = "Kaya never changes service ownership automatically while ownership is ambiguous; it acts only on one verified owner."
        if "DUPLICATE_VIP" in codes:
            self.add(Finding("DUPLICATE_VIP", "Two nodes report the Virtual IP", "OWNERSHIP", "critical",
                             codes["DUPLICATE_VIP"].message, "Clients may reach either node; DHCP activation is blocked to prevent two DHCP servers.",
                             BLOCKED, self.ownership_observations(), (self.fresh_reports(), self.single_owner()),
                             no_repair_reason=never_automatic + " Restore VRRP communication between the nodes (network, firewall or Keepalived) and the duplicate clears by itself."
                             " If Keepalived on one node was killed or crashed, that node can keep the address without running VRRP, so the duplicate"
                             " persists: check the addresses and the keepalived service on both nodes and stop the stale owner. Kaya never removes"
                             " Virtual IP addresses itself."))
        if "NO_VIP_OWNER" in codes:
            self.add(Finding("NO_VIP_OWNER", "No node reports the Virtual IP", "OWNERSHIP", "critical",
                             codes["NO_VIP_OWNER"].message, "Clients using the Virtual IP for DNS may get no answers.",
                             BLOCKED, self.ownership_observations(), (self.fresh_reports(),),
                             no_repair_reason=never_automatic + " Check Keepalived and DNS health on both nodes; Keepalived assigns the Virtual IP itself once a node is healthy."))
        if "MULTIPLE_DHCP" in codes:
            self.add(Finding("MULTIPLE_DHCP", "Two DHCP servers are running", "DHCP", "critical",
                             codes["MULTIPLE_DHCP"].message, "Clients may receive conflicting addresses.",
                             BLOCKED, self.ownership_observations(), (self.fresh_reports(), self.single_owner()),
                             no_repair_reason=never_automatic + " Disable DHCP on the node that does not own the Virtual IP in Pi-hole, then let both agents report."))
        if "NO_DHCP_OWNER" in codes:
            self.add(Finding("NO_DHCP_OWNER", "No node is serving DHCP", "DHCP", "critical",
                             codes["NO_DHCP_OWNER"].message, "Clients cannot obtain or renew addresses.",
                             BLOCKED, self.ownership_observations(), (self.fresh_reports(),),
                             no_repair_reason="Kaya only repairs DHCP configuration on a verified, stable Virtual IP owner. Check Pi-hole DHCP on the Virtual IP owner."))
        if "OWNERSHIP_MISMATCH" in codes:
            from app.services.ha_alignment import active_alignment, alignment_preview

            impact = "DNS and DHCP keep working, but redundancy is reduced, lease replication is paused and controlled failover is unavailable."
            running = active_alignment(cluster)
            if running is not None:
                self.add(Finding("OWNERSHIP_MISMATCH", "DNS and DHCP are on different nodes", "OWNERSHIP", "critical",
                                 codes["OWNERSHIP_MISMATCH"].message, impact, TRANSIENT, self.ownership_observations(), (),
                                 no_repair_reason=f"Align service ownership is running ({running.phase.replace('_', ' ').lower()}); "
                                                  "follow its progress on the Health & Repair page."))
            else:
                preview = alignment_preview(self.db, cluster, now=self.now)
                target = preview.dhcp_owner.display_name if preview.dhcp_owner else "the DHCP server"
                self.add(Finding("OWNERSHIP_MISMATCH", "DNS and DHCP are on different nodes", "OWNERSHIP", "critical",
                                 codes["OWNERSHIP_MISMATCH"].message, impact,
                                 APPROVAL_REQUIRED if preview.allowed else BLOCKED, self.ownership_observations(),
                                 tuple(Prerequisite(check.label, check.passed) for check in preview.checks),
                                 repair=RepairAction("ALIGN_OWNERSHIP", "Review and align service ownership", _page(cluster, "maintenance") + "#align-ownership",
                                                     f"Moves only the Virtual IP to {target} (DNS may pause briefly); DHCP and leases are not changed")
                                 if preview.allowed else None,
                                 no_repair_reason=None if preview.allowed else (
                                     f"Align service ownership would move only the Virtual IP to {target}, but it is blocked: "
                                     + " ".join(preview.blockers)
                                 )))
        if "STORED_ROLE_MISMATCH" in codes and self.topology.topology_safe:
            prerequisites = (self.fresh_reports(), self.single_owner(), self.no_operation_running())
            ready = all(item.satisfied for item in prerequisites)
            self.add(Finding("STORED_ROLE_MISMATCH", "Kaya's record of the active node is out of date", "OWNERSHIP", "warning",
                             codes["STORED_ROLE_MISMATCH"].message, "Views and readiness checks may describe the wrong node as active. Services are unaffected.",
                             SELF_HEALING if cluster.automatic_failover_enabled and ready else APPROVAL_REQUIRED,
                             self.ownership_observations(), prerequisites,
                             repair=RepairAction("RECONCILE", "Reconcile stored state", _page(cluster, "maintenance") + "#reconcile", "None: records only, no service change") if ready else None,
                             no_repair_reason=None if ready else "Reconcile needs fresh reports, one verified owner and no running operation."))
        for code, title, impact in (
            ("ACTIVE_DHCP_CONFIGURATION_DISABLED", "DHCP is disabled in Pi-hole on the active node", "DHCP may stop after the next Pi-hole restart."),
            ("STANDBY_DHCP_CONFIGURATION_ENABLED", "DHCP is still enabled in Pi-hole on the standby", "The standby could start a second DHCP server after a restart."),
        ):
            if code not in codes:
                continue
            latched = self.self_heal_latched()
            prerequisites = (self.fresh_reports(), self.single_owner(), self.no_operation_running(),
                             Prerequisite("Cluster is not in maintenance", not cluster.maintenance_mode),
                             Prerequisite("Previous automatic repair did not fail for this condition", not latched))
            blocked = not all(item.satisfied for item in prerequisites[:4])
            # While the Virtual IP and DHCP are on different nodes (or ownership is otherwise
            # unresolved), this follows from that problem: it is repaired there, not here.
            dependent = blocked and bool(codes.keys() & {"OWNERSHIP_MISMATCH", "DUPLICATE_VIP", "NO_VIP_OWNER", "MULTIPLE_DHCP", "NO_DHCP_OWNER"})
            self.add(Finding(code, title, "DHCP", codes[code].severity, codes[code].message, impact,
                             TRANSIENT if dependent else BLOCKED if blocked else APPROVAL_REQUIRED if latched else SELF_HEALING,
                             self.ownership_observations(), prerequisites,
                             repair=RepairAction("RETRY_DHCP_SELF_HEAL", "Retry DHCP configuration repair", _page(cluster, "maintenance") + "#reconcile",
                                                 "Changes the Pi-hole DHCP setting only; live leases are untouched") if latched and not blocked else None,
                             no_repair_reason=("This follows from the service ownership problem; it clears, or Kaya repairs it automatically, once one node "
                                               "owns both the Virtual IP and DHCP." if dependent
                                               else "Kaya repairs this automatically once its safety prerequisites are met." if blocked else None),
                             automatic_attempts=self.self_heal_attempts()))
        if "ACTIVE_DHCP_ACTIVATION_INCOMPLETE" in codes:
            self.add(Finding("ACTIVE_DHCP_ACTIVATION_INCOMPLETE", "DHCP is enabled but not listening on the active node", "DHCP", "critical",
                             codes["ACTIVE_DHCP_ACTIVATION_INCOMPLETE"].message, "Clients cannot obtain or renew addresses.",
                             BLOCKED, self.ownership_observations(), (self.fresh_reports(),),
                             no_repair_reason="Pi-hole reports DHCP enabled but FTL is not listening on UDP port 67; check Pi-hole FTL on that node."))
        if "STALE_RECOVERY_STATE" in codes:
            self.add(Finding("STALE_RECOVERY_STATE", "Standby readiness looks out of date", "RECOVERY", "warning",
                             codes["STALE_RECOVERY_STATE"].message, "Controlled failback may be offered later than necessary. Services are unaffected.",
                             SELF_HEALING, self.ownership_observations(), (self.fresh_reports(), self.no_operation_running()),
                             repair=RepairAction("RECONCILE", "Reconcile stored state", _page(cluster, "maintenance") + "#reconcile", "None: records only, no service change")))

    # --- nodes, agents and Keepalived ---------------------------------------------

    def nodes_and_agents(self) -> None:
        cluster = self.cluster
        desired_gates = {
            "automatic_failover": bool(cluster.automatic_failover_enabled and all(version_tuple(node.agent_version) >= AUTOMATIC_AGENT_VERSION for node in self.nodes)),
            "maintenance_mode": bool(cluster.maintenance_mode),
            "dhcp_managed": self.managed,
        }
        for node in self.nodes:
            fresh = node.id in self.topology.fresh_node_ids
            credential = node.agent_credential
            observations = (
                ("Last signed report", _when(node.last_heartbeat_at)),
                ("Agent version", node.agent_version or "not reported"),
                ("DNS healthy", _yes(node.dns_healthy)),
                ("Keepalived", node.keepalived_runtime_state or "unknown"),
            )
            if credential is None or credential.registered_at is None or credential.revoked_at is not None:
                self.add(Finding("AGENT_NOT_REGISTERED", "No registered HA Agent", "AGENT", "critical",
                                 f"{node.display_name} has no active, registered agent identity.", "Kaya cannot observe or coordinate this node.",
                                 APPROVAL_REQUIRED, observations, (),
                                 repair=RepairAction("AGENT_BOOTSTRAP", "Register the agent", _page(cluster, "agents"), "None until the agent is installed"),
                                 node=node.display_name))
                continue
            if not fresh:
                silent_long = node.last_heartbeat_at is None or node.last_heartbeat_at < self.now - STALE_AGENT_GRACE
                self.add(Finding("AGENT_NOT_REPORTING", "Node is not reporting", "AGENT", "critical" if silent_long else "warning",
                                 f"No fresh signed report from {node.display_name} since {_when(node.last_heartbeat_at)}.",
                                 "Kaya cannot verify this node; failover readiness and repairs that need it are paused. Keepalived still protects DNS locally.",
                                 BLOCKED if silent_long else TRANSIENT, observations, (),
                                 no_repair_reason="Check the node, its network and the kaya-ha-agent service; reporting resumes automatically." if silent_long else None,
                                 node=node.display_name))
                continue
            if version_tuple(node.agent_version) < version_tuple(CURRENT_AGENT_VERSION):
                self.add(Finding("AGENT_UPDATE_AVAILABLE", "HA Agent update available", "AGENT", "info",
                                 f"{node.display_name} runs agent {node.agent_version}; this Kaya provides {CURRENT_AGENT_VERSION}.",
                                 "Newer safety features (for example gate reporting) are unavailable on this node until it is updated.",
                                 APPROVAL_REQUIRED, observations, (),
                                 repair=RepairAction("AGENT_UPDATE", "Review the agent update", _page(cluster, "agents"), "Agent restart on that node; DNS and DHCP keep running"),
                                 node=node.display_name))
            if node.agent_automation_gates_json:
                try:
                    reported = json.loads(node.agent_automation_gates_json)
                except (TypeError, ValueError):
                    reported = {}
                differing = sorted(key for key, value in desired_gates.items() if reported.get(key) is not value)
                if differing:
                    self.add(Finding("AGENT_GATES_DIFFER", "Agent safety gates differ from Kaya's settings", "AGENT", "warning",
                                     f"{node.display_name} reports {', '.join(f'{key}={reported.get(key)}' for key in differing)}.",
                                     "Local failover behaviour on this node may not match the cluster settings until it applies them.",
                                     TRANSIENT, observations + tuple((key, f"reported {reported.get(key)}, expected {desired_gates[key]}") for key in differing), (),
                                     node=node.display_name))
            if node.dns_healthy is False:
                owner = node.id in self.topology.vip_owner_ids
                self.add(Finding("DNS_UNHEALTHY", "DNS health check failing", "DNS", "critical" if owner else "warning",
                                 f"{node.display_name} reports its local DNS health check failing.",
                                 "Keepalived moves the Virtual IP away from this node by itself." if owner else "This node cannot take over DNS until it recovers.",
                                 BLOCKED, observations, (),
                                 no_repair_reason="Kaya does not repair Pi-hole DNS; check pihole-FTL on this node. Keepalived reacts locally.",
                                 node=node.display_name))
            if node.keepalived_status == "ERROR":
                self.add(Finding("KEEPALIVED_REJECTED", "Keepalived configuration was rejected", "KEEPALIVED", "critical",
                                 f"{node.display_name}: {node.keepalived_last_error or 'the agent reported a failed Keepalived apply'}",
                                 "This node may be running an older or unknown Keepalived configuration.",
                                 APPROVAL_REQUIRED, observations, (self.no_operation_running(),),
                                 repair=self.redeploy_route(),
                                 node=node.display_name))
            elif node.keepalived_runtime_state not in {"RUNNING", None}:
                self.add(Finding("KEEPALIVED_NOT_RUNNING", "Keepalived is not running", "KEEPALIVED", "critical",
                                 f"{node.display_name} reports Keepalived {node.keepalived_runtime_state.lower()}.",
                                 "This node cannot hold or take over the Virtual IP.",
                                 BLOCKED, observations, (),
                                 no_repair_reason="Kaya never starts or restarts Keepalived; check the keepalived service on this node.",
                                 node=node.display_name))
            if node.config_generation < cluster.keepalived_generation:
                pending = cluster.keepalived_status == "PENDING_AGENT"
                self.add(Finding("KEEPALIVED_GENERATION_BEHIND", "Node has not applied the latest Keepalived configuration", "KEEPALIVED", "warning",
                                 f"{node.display_name} reports generation {node.config_generation}; the cluster is at {cluster.keepalived_generation}.",
                                 "Transition hooks from the newer configuration are fenced until the node applies it.",
                                 TRANSIENT if pending else APPROVAL_REQUIRED, observations, (),
                                 repair=None if pending else self.redeploy_route(),
                                 node=node.display_name))

    # --- standby readiness ----------------------------------------------------------

    def standby(self) -> None:
        owner_ids = set(self.topology.vip_owner_ids)
        for node in self.nodes:
            result = self.recovery.get(node.id)
            if result is None or node.id in owner_ids or node.id not in self.topology.fresh_node_ids or result.ready or result.state in {"ACTIVE", "STANDBY"}:
                continue
            failing = [check for check in result.checks if check.required and not check.passed]
            remaining = max(0, result.stability_required_seconds - result.stability_seconds)
            self.add(Finding("STANDBY_NOT_READY", "Standby is not yet ready to take over", "RECOVERY", "warning",
                             f"{node.display_name} is catching up" + (f": {failing[0].detail}" if failing else f"; stability window {remaining}s remaining."),
                             "A controlled switch to this node is unavailable until it is ready. Keepalived can still fail over DNS.",
                             SELF_HEALING if not self.cluster.maintenance_mode else BLOCKED,
                             tuple((check.label, "met" if check.passed else check.detail) for check in result.checks if check.required),
                             tuple(Prerequisite(check.label, check.passed) for check in result.checks if check.required),
                             no_repair_reason="Readiness is evaluated automatically from signed reports and synchronisation; the maintenance hold pauses it." if self.cluster.maintenance_mode else None,
                             automatic_attempts=(f"Recovery checks running since {_when(node.recovery_started_at)}",) if node.recovery_started_at else (),
                             node=node.display_name))

    # --- maintenance, failover, configuration and leases ----------------------------

    def operations(self) -> None:
        cluster = self.cluster
        if self.failover_run is not None:
            self.add(Finding("FAILOVER_IN_PROGRESS", "Controlled failover in progress", "FAILOVER", "info",
                             f"Step: {self.failover_run.phase.replace('_', ' ').lower()}.", "Other repairs wait until it finishes.",
                             TRANSIENT, (("Status", self.failover_run.status.lower()),), ()))
        if self.active_run is not None:
            from app.services.ha_alignment import OPERATION as ALIGN_OPERATION, PHASE_LABELS as ALIGN_PHASES

            aligning = self.active_run.operation == ALIGN_OPERATION
            self.add(Finding("MAINTENANCE_IN_PROGRESS", "Align service ownership in progress" if aligning else "Maintenance operation in progress", "MAINTENANCE", "info",
                             (f"Approved repair, step: {ALIGN_PHASES.get(self.active_run.phase, self.active_run.phase).lower()}. Each step advances only after fresh signed reports confirm it."
                              if aligning else f"{self.active_run.operation.replace('_', ' ').title()}: {self.active_run.phase.replace('_', ' ').lower()}."),
                             "Automatic failover and synchronisation are paused while it runs.",
                             TRANSIENT, (("Status", self.active_run.status.lower()),), ()))
        elif cluster.maintenance_mode:
            preview = latch_preview(self.db, cluster)
            checks = tuple(Prerequisite(item["detail"], bool(item["passed"])) for item in preview["checks"])
            allowed = bool(preview["release_allowed"])
            # Acknowledging the failed operation changes only Kaya's review record (the hold
            # stays on), and it is what lets an approved repair run under the latch.
            acknowledge = (preview.get("failed_run_id") is not None and not preview.get("acknowledged_at") and not allowed)
            failover_hold = self.failed_failover_holding() if preview.get("failed_run_id") is None and not allowed else None
            # Reviewed, services consistent, only Kaya's records lag behind: Reconcile State
            # (records only) is the next step before the release.
            failing = {item.get("code") for item in preview["checks"] if not item["passed"]}
            reconcile_first = (not allowed and not acknowledge and bool(preview.get("acknowledged_at")) and bool(failing)
                               and failing <= {"STORED_ROLES_ALIGNED", "RECONCILIATION_COMPLETE"})
            self.add(Finding("MAINTENANCE_HOLD", "Automation is held after a failed repair", "MAINTENANCE", "warning",
                             "A maintenance operation stopped safely earlier; automatic failover and configuration changes stay paused until an administrator reviews it.",
                             "Kaya will not move services or apply configuration automatically. DNS and DHCP keep running.",
                             APPROVAL_REQUIRED if allowed or acknowledge or reconcile_first or failover_hold else BLOCKED,
                             (("Failed operation", preview.get("failed_run_id") or "none recorded"),
                              ("Acknowledged", _when(preview.get("acknowledged_at")))),
                             checks,
                             repair=(RepairAction("RELEASE_HOLD", "Review and release the hold", _page(cluster, "maintenance") + "#latch-review", "None: releases the hold; automatic failover stays disabled") if allowed
                                     else RepairAction("ACKNOWLEDGE_HOLD", "Review and acknowledge the failed operation", _page(cluster, "maintenance") + "#latch-review",
                                                       "None: records your review; the hold stays on") if acknowledge
                                     else RepairAction("RECONCILE", "Reconcile stored state, then review the hold", _page(cluster, "maintenance") + "#reconcile",
                                                       "None: records only, no service change; the hold stays on") if reconcile_first
                                     else RepairAction("FAILOVER_ROLLBACK", "Review the failed controlled failover and its rollback", _page(cluster, "testing"),
                                                       "Rollback returns services to the original owner and releases the hold") if failover_hold else None),
                             no_repair_reason=None if allowed or acknowledge or reconcile_first or failover_hold else "The hold can be released only when every listed check passes."))
        restoration = keepalived_restoration(cluster)
        if restoration is not None:
            phase = restoration.get("state")
            node = self.by_id.get(restoration.get("preempt_node_id"))
            holder = node.display_name if node else "A node"
            observations = (("Preempt-capable since generation", str(restoration.get("preempt_generation"))),
                            ("Restoration state", str(phase).replace("_", " ").lower()))
            if phase in {"RESTORING_STANDBY", "RESTORING_OWNER", "VERIFYING"}:
                self.add(Finding("KEEPALIVED_BASELINE_RESTORING", "Restoring the stable Keepalived configuration", "KEEPALIVED", "info",
                                 "Kaya is reapplying the no-preemption configuration, node without the Virtual IP first.",
                                 "None expected; the Virtual IP owner must stay the same.", SELF_HEALING, observations, ()))
            else:
                from app.services.ha_baseline_repair import restoration_preview

                blocked = phase == "BLOCKED"
                preview = restoration_preview(self.db, cluster, now=self.now)
                waiting = phase == "OUTSTANDING"
                restore = RepairAction("RESTORE_BASELINE", "Review and restore the stable Keepalived configuration",
                                       _page(cluster, "maintenance") + "#restore-baseline",
                                       "Keepalived reloads only, node without the Virtual IP first; the Virtual IP and DHCP do not move")
                # Agents older than 0.2.15 cannot run the approved restoration; the P5 path
                # (an administrator's Keepalived redeployment, which renders nopreempt) remains.
                failing = {check.code for check in preview.checks if not check.passed}
                legacy = not waiting and bool(failing) and failing <= {"AGENT_VERSION", "AGENT_GATES"}
                redeploy = self.redeploy_route()
                fix = restore if preview.allowed else redeploy if legacy else None
                self.add(Finding("KEEPALIVED_PREEMPT_RETAINED", "A node may still preempt the Virtual IP", "KEEPALIVED", "warning",
                                 f"{holder} received a preempt-capable configuration for a maintenance, failover or repair step that has ended."
                                 + (f" The last restoration attempt stopped: {restoration.get('detail')}" if blocked and restoration.get("detail") else ""),
                                 "That node could take the Virtual IP back on its own instead of only by an approved operation.",
                                 TRANSIENT if waiting else APPROVAL_REQUIRED if fix else BLOCKED, observations,
                                 () if waiting else tuple(Prerequisite(check.label, check.passed) for check in preview.checks),
                                 repair=fix,
                                 no_repair_reason=("Waiting for the operation to finish and both nodes to report." if waiting else None if fix
                                                   else "Restoring the stable configuration needs every safety check to pass: " + " ".join(preview.blockers)
                                                   + " Automatic restoration stays disabled.")))
        if cluster.automatic_sync_hold:
            self.add(Finding("AUTOMATIC_SYNC_HELD", "Automatic configuration sync is on hold", "CONFIGURATION", "info",
                             "Automatic configuration writes were paused when the maintenance hold was released.",
                             "Configuration drift is detected but not applied until approved.",
                             APPROVAL_REQUIRED, (), (),
                             repair=RepairAction("SYNC_SETTINGS", "Review automatic synchronisation", _page(cluster, "synchronisation"), "None until a sync is applied")))
        latest_sync = (self.db.query(HASyncRun).filter(HASyncRun.cluster_id == cluster.id)
                       .order_by(HASyncRun.created_at.desc(), HASyncRun.id.desc()).first())
        if latest_sync is not None and latest_sync.status == "PLANNED":
            try:
                plan = json.loads(latest_sync.plan_json or "{}")
            except (TypeError, ValueError):
                plan = {}
            groups = [item.get("label") or item.get("key") for item in plan.get("groups", []) if isinstance(item, dict)]
            high_impact = any(isinstance(item, dict) and item.get("risk") == "high" for item in plan.get("groups", []))
            automatic = cluster.automatic_sync_enabled and not cluster.automatic_sync_hold and not high_impact and not plan.get("deletion_count")
            self.add(Finding("CONFIGURATION_DRIFT", "Standby configuration differs from the active node", "CONFIGURATION", "warning",
                             "Differences: " + (", ".join(sorted(str(group) for group in groups)) or "unspecified") + ".",
                             "After a failover the standby would serve different settings.",
                             SELF_HEALING if automatic else APPROVAL_REQUIRED,
                             (("Plan created", _when(latest_sync.created_at)), ("High-impact changes", _yes(high_impact)), ("Deletions", str(plan.get("deletion_count") or 0))),
                             (Prerequisite("Kaya can verify one safe configuration authority", bool(plan.get("authority_verified"))),),
                             repair=None if automatic else RepairAction("SYNC_REVIEW", "Review and apply synchronisation", _page(cluster, "synchronisation"), "Writes the listed settings to the standby only")))
        state = cluster.lease_replication
        if self.managed and state is not None and state.status in {"BLOCKED", "ERROR", "CONFLICT"}:
            topology_blocked = not self.single_owner().satisfied
            self.add(Finding("LEASE_REPLICATION_STOPPED", "DHCP lease replication is paused", "LEASES", "warning",
                             state.last_error_redacted or f"Lease replication is {state.status.lower()}.",
                             "A failover now could lose recent DHCP leases on the standby.",
                             BLOCKED if topology_blocked else APPROVAL_REQUIRED if state.conflict_count else SELF_HEALING,
                             (("Status", state.status.lower()), ("Lease generation", f"{state.applied_generation} applied of {state.desired_generation}"), ("Conflicts", str(state.conflict_count or 0))),
                             (self.single_owner(),),
                             repair=RepairAction("LEASE_RECONCILE", "Review DHCP lease replication", _page(cluster, "dhcp"), "Stages leases on the standby only") if state.conflict_count and not topology_blocked else None,
                             no_repair_reason="Replication resumes automatically once one node owns both the Virtual IP and DHCP." if topology_blocked else None,
                             automatic_attempts=(f"Last automatic lease check {_when(state.last_full_reconciliation_at)}",)))


def assess_cluster(
    db: Session,
    cluster: HACluster,
    *,
    now: datetime | None = None,
    inspection: ClusterInspection | None = None,
    recovery: dict[int, NodeRecovery] | None = None,
    readiness: FailoverReadiness | None = None,
) -> ClusterAssessment:
    """Assess one cluster.  Pass the results a view already computed (with the
    same ``now``) to avoid recomputing them; never writes."""
    current = now or datetime.utcnow()
    recovery = recovery if recovery is not None else recovery_snapshot(db, cluster, now=current)
    inspection = inspection if inspection is not None else inspect_cluster(cluster, now=current, recovery=recovery)
    readiness = readiness if readiness is not None else failover_readiness(cluster, now=current)
    builder = _Builder(db, cluster, current, inspection, recovery, readiness)
    builder.ownership()
    builder.nodes_and_agents()
    builder.standby()
    builder.operations()
    findings = sorted(builder.findings, key=lambda finding: finding.sort_key)
    return ClusterAssessment(cluster.public_id, current, tuple(findings))


HEALTHY = "HEALTHY"
RECOVERING = "RECOVERING"
IN_PROGRESS_CODES = ("MAINTENANCE_IN_PROGRESS", "FAILOVER_IN_PROGRESS", "KEEPALIVED_BASELINE_RESTORING")
NEEDS_APPROVAL = "NEEDS_APPROVAL"
STATE_LABELS = {
    HEALTHY: "Healthy",
    RECOVERING: "Recovering automatically",
    NEEDS_APPROVAL: "Needs approval",
    BLOCKED: "Blocked",
}


@dataclass(frozen=True)
class HealthSummary:
    """The one-line answer to "is this cluster fine, and if not, what now?"."""

    state: str
    headline: str
    detail: str
    primary: Finding | None
    action: RepairAction | None
    action_finding: Finding | None
    recovering: tuple[Finding, ...]
    notes: tuple[Finding, ...]

    @property
    def label(self) -> str:
        return STATE_LABELS[self.state]


def health_summary(assessment: ClusterAssessment) -> HealthSummary:
    """Classify an assessment for the Health & Repair workspace.

    * **Healthy**: no warning or critical finding (informational notes, such as
      an available agent update, never change this).
    * **Recovering automatically**: every open problem is transient or being
      healed by Kaya; shows what Kaya is doing.
    * **Needs approval**: a problem has one safe repair an administrator can
      approve; the most severe such repair is the single recommended action.
    * **Blocked**: a critical problem has no safe repair, or no open problem has
      one; shows the exact reason and the next safe step (an approvable repair
      elsewhere in the list, such as an agent update, when one exists).
    """
    findings = assessment.findings
    moving = {TRANSIENT, SELF_HEALING}
    open_items = [item for item in findings if item.severity in {"critical", "warning"} or item.disposition in moving and item.severity == "info"]
    recovering = tuple(item for item in open_items if item.disposition in moving)
    notes = tuple(item for item in findings if item not in open_items)
    if any(item.code in IN_PROGRESS_CODES for item in findings):
        notes = tuple(item for item in notes if item.code not in IN_PROGRESS_CODES)
    approvals = [item for item in open_items if item.disposition == APPROVAL_REQUIRED and item.repair is not None]
    blocked = [item for item in open_items if item.disposition == BLOCKED or (item.disposition == APPROVAL_REQUIRED and item.repair is None)]
    if not open_items:
        return HealthSummary(HEALTHY, "No action required", "Both nodes report healthy, consistent service ownership.", None, None, None, (), notes)
    critical_blocked = [item for item in blocked if item.severity == "critical"]
    if critical_blocked:
        primary = critical_blocked[0]
        follow_up = approvals[0] if approvals else next((item for item in notes if item.disposition == APPROVAL_REQUIRED and item.repair), None)
        return HealthSummary(BLOCKED, primary.title, primary.no_repair_reason or primary.condition, primary,
                             follow_up.repair if follow_up else None, follow_up, recovering, notes)
    # While an approved or automatic operation runs, its own steps explain the state;
    # side effects of the operation (a paused standby check, a pending generation) are
    # not separate problems to act on.  A critical blocked fault still wins (above).
    in_progress = [item for item in findings if item.code in IN_PROGRESS_CODES]
    if in_progress:
        primary = in_progress[0]
        return HealthSummary(RECOVERING, primary.title, primary.condition, primary, None, None,
                             tuple(in_progress) + tuple(item for item in recovering if item not in in_progress), notes)
    if approvals:
        primary = approvals[0]
        return HealthSummary(NEEDS_APPROVAL, primary.title, primary.condition, primary, primary.repair, primary, recovering, notes)
    if blocked:
        primary = blocked[0]
        follow_up = next((item for item in notes if item.disposition == APPROVAL_REQUIRED and item.repair), None)
        return HealthSummary(BLOCKED, primary.title, primary.no_repair_reason or primary.condition, primary,
                             follow_up.repair if follow_up else None, follow_up, recovering, notes)
    primary = recovering[0]
    return HealthSummary(RECOVERING, primary.title, primary.condition, primary, None, None, recovering, notes)


def assessment_node_summary(assessment: ClusterAssessment, node: HANode) -> list[Finding]:
    return [finding for finding in assessment.findings if finding.node == node.display_name]
