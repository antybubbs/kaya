#!/usr/bin/env python3
"""Read-only HA safety-invariant report for Kaya Pi-hole clusters (Gate A).

Evaluates stored and most-recently observed HA state against the safety
invariants agreed for the HAL-Home-DNS hardening programme and prints a
PASS / FAIL / WARN / UNKNOWN line per check.  It never changes anything:

* SQLite is opened with ``mode=ro``; PostgreSQL sessions are forced to
  ``default_transaction_read_only=on`` and every transaction is rolled back.
* No service, agent, Pi-hole or Keepalived endpoint is contacted.
* The database URL is never printed.  Output contains node display names,
  generations and states only: no addresses, keys, secrets or lease data.

Usage (inside the Kaya container or any environment with Kaya's settings):

    KAYA_HA_REPORT_DATABASE_URL=... python scripts/ha_invariant_report.py [--json] [--cluster PUBLIC_ID]

The URL may also be passed with ``--url``; prefer the environment variable so
the credential does not appear in process arguments.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FRESH_SECONDS = 45
ACTIVE_RUN_STATUSES = {"RUNNING", "PAUSED", "ROLLING_BACK"}


@dataclass(frozen=True)
class Check:
    code: str
    status: str  # PASS | FAIL | WARN | UNKNOWN
    detail: str


def read_only_engine(url: str):
    from sqlalchemy import create_engine, event
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    if parsed.get_backend_name() == "sqlite":
        database = parsed.database or ""
        if not database or database == ":memory:":
            raise ValueError("A SQLite report needs an existing database file.")
        path = Path(database).resolve()
        if not path.is_file():
            raise ValueError("The SQLite database file does not exist.")
        engine = create_engine(f"sqlite:///file:{path.as_posix()}?mode=ro&uri=true")
    elif parsed.get_backend_name() == "postgresql":
        engine = create_engine(url, connect_args={"options": "-c default_transaction_read_only=on"}, pool_pre_ping=True)

        @event.listens_for(engine, "connect")
        def enforce(connection, record):
            cursor = connection.cursor()
            cursor.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            cursor.close()
    else:
        raise ValueError("Only SQLite and PostgreSQL databases are supported.")
    return engine


def _names(cluster, ids) -> list[str]:
    lookup = {node.id: node.display_name for node in cluster.nodes}
    return [lookup.get(item, f"node#{item}") for item in ids]


def evaluate_cluster(cluster, *, now: datetime | None = None) -> dict:
    from app.services.ha_topology import pihole_manages_dhcp, reconcile_topology

    current = now or datetime.utcnow()
    topology = reconcile_topology(cluster, now=current)
    dhcp_managed = pihole_manages_dhcp(cluster)
    by_id = {node.id: node for node in cluster.nodes}
    vip = _names(cluster, topology.vip_owner_ids)
    dhcp = _names(cluster, topology.dhcp_owner_ids)
    fresh = set(topology.fresh_node_ids)
    checks: list[Check] = []

    def add(code, ok, detail, *, unknown=False, warn=False):
        status = "UNKNOWN" if unknown else ("PASS" if ok else ("WARN" if warn else "FAIL"))
        checks.append(Check(code, status, detail))

    stale = [node.display_name for node in cluster.nodes if node.id not in fresh]
    add("FRESH_OBSERVATIONS", not stale, "All nodes reported recently." if not stale else f"Stale or missing reports: {', '.join(stale)}.", warn=True)
    add("I1_SINGLE_DHCP_SERVER", len(dhcp) <= 1, f"Observed DHCP servers: {dhcp or 'none'}.", unknown=bool(topology.dhcp_unknown_node_ids) and dhcp_managed)
    add("I2_SINGLE_VIP_OWNER", len(vip) <= 1, f"Observed VIP owners: {vip or 'none'}.")
    add("VIP_OWNER_PRESENT", len(vip) == 1, f"Observed VIP owners: {vip or 'none'}.", warn=True)
    if dhcp_managed:
        aligned = len(vip) == 1 and vip == dhcp
        add("I3_VIP_DHCP_ALIGNED", aligned, "VIP and DHCP are owned by the same node." if aligned else f"VIP owner {vip or 'none'} differs from DHCP owner {dhcp or 'none'}.")
    stored_active = by_id.get(cluster.current_active_node_id)
    authority = by_id.get(cluster.authoritative_node_id)
    dhcp_owner = by_id.get(topology.dhcp_owner_ids[0]) if len(topology.dhcp_owner_ids) == 1 else None
    reference = dhcp_owner if dhcp_managed else (by_id.get(topology.vip_owner_ids[0]) if len(topology.vip_owner_ids) == 1 else None)
    add("STORED_ACTIVE_MATCHES_SERVICE_OWNER", bool(reference and stored_active and reference.id == stored_active.id),
        f"Stored active: {stored_active.display_name if stored_active else 'none'}; service owner: {reference.display_name if reference else 'unknown'}.", unknown=reference is None)
    add("AUTHORITY_MATCHES_SERVICE_OWNER", bool(reference and authority and reference.id == authority.id),
        f"Stored configuration authority: {authority.display_name if authority else 'none'}.", unknown=reference is None)
    active_roles = [node.display_name for node in cluster.nodes if node.role == "ACTIVE"]
    add("STORED_ROLES_ALIGNED", bool(reference and active_roles == [reference.display_name]), f"Nodes with stored role ACTIVE: {active_roles or 'none'}.", unknown=reference is None)
    add("TOPOLOGY_SAFE", topology.topology_safe, f"Topology issues: {sorted(issue.code for issue in topology.issues) or 'none'}.")

    generation_problems = [
        node.display_name for node in cluster.nodes
        if (node.config_generation or 0) != (cluster.keepalived_generation or 0)
        or (node.observed_generation or 0) < (cluster.role_generation or 0)
    ]
    add("I6_GENERATIONS_CONSISTENT", not generation_problems,
        f"Cluster keepalived_generation {cluster.keepalived_generation}, role_generation {cluster.role_generation}; "
        + ("all nodes match." if not generation_problems else f"mismatched: {', '.join(generation_problems)}."))
    undeployed = [node.display_name for node in cluster.nodes if node.keepalived_status != "DEPLOYED"]
    add("KEEPALIVED_DEPLOYED_NO_PENDING_PUSH", cluster.keepalived_status == "DEPLOYED" and not undeployed,
        f"Cluster Keepalived status {cluster.keepalived_status}; " + ("all nodes deployed." if not undeployed else f"pending: {', '.join(undeployed)}."))
    keepalived_down = [node.display_name for node in cluster.nodes if node.keepalived_runtime_state != "RUNNING"]
    add("KEEPALIVED_RUNNING", not keepalived_down, "Keepalived running on all nodes." if not keepalived_down else f"Not running: {', '.join(keepalived_down)}.", warn=True)
    dns_down = [node.display_name for node in cluster.nodes if node.dns_healthy is not True]
    add("DNS_HEALTHY", not dns_down, "All nodes report healthy local DNS." if not dns_down else f"DNS unhealthy: {', '.join(dns_down)}.", warn=True)

    add("I5_AUTOMATIC_FAILOVER_STATE", True, f"automatic_failover_enabled={bool(cluster.automatic_failover_enabled)}, maintenance_mode={bool(cluster.maintenance_mode)}, automatic_sync_hold={bool(getattr(cluster, 'automatic_sync_hold', False))}.")
    if cluster.automatic_failover_enabled and not topology.topology_safe:
        add("I5_AUTOMATIC_FAILOVER_WHILE_UNSAFE", False, "Automatic failover is enabled while the topology is not safe.", warn=True)

    runs = sorted(cluster.maintenance_runs, key=lambda item: item.created_at)
    active_runs = [f"{run.operation}:{run.phase}" for run in runs if run.status in ACTIVE_RUN_STATUSES]
    active_runs += [f"FAILOVER:{run.phase}" for run in cluster.failover_runs if run.status in {"RUNNING", "ROLLING_BACK"}]
    add("NO_ACTIVE_OPERATION", not active_runs, "No maintenance or failover operation is active." if not active_runs else f"Active: {', '.join(active_runs)}.", warn=True)
    latest = runs[-1] if runs else None
    if latest and latest.operation == "REINITIALISE" and latest.status == "FAILED_SAFE":
        try:
            previous = json.loads(latest.previous_state_json or "{}")
        except ValueError:
            previous = {}
        hazard = bool(previous.get("automatic_failover_enabled")) and not cluster.automatic_failover_enabled
        add("D7_STALE_PREVIOUS_STATE_HAZARD", not hazard,
            "A new REINITIALISE would inherit saved state that re-enables automatic failover." if hazard
            else "The latest failed-safe REINITIALISE would not re-enable automatic failover.", warn=True)
        add("MAINTENANCE_LATCH_RETAINED", False, f"Latest REINITIALISE {latest.public_id[:8]} is FAILED_SAFE; release requires the guarded latch workflow.", warn=True)

    lease = cluster.lease_replication
    if dhcp_managed:
        add("LEASE_REPLICATION_CURRENT", bool(lease and lease.status == "CURRENT"),
            f"Lease replication status {lease.status if lease else 'missing'}.", warn=True)
    recovery = {node.display_name: node.recovery_state for node in cluster.nodes}
    standby_ready = any(state == "STANDBY_READY" for state in recovery.values())
    add("STANDBY_READY", standby_ready, f"Recovery states: {recovery}.", warn=True)
    owner_in_recovery = [node.display_name for node in cluster.nodes if dhcp_owner and node.id == dhcp_owner.id and node.recovery_state in {"RECOVERING", "SYNCHRONISING", "VERIFYING"}]
    if owner_in_recovery:
        add("D2_DHCP_OWNER_IN_STANDBY_RECOVERY", False, f"The DHCP owner {owner_in_recovery[0]} is classified as a recovering standby.", warn=True)

    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "cluster": cluster.name,
        "cluster_id": cluster.public_id,
        "stored_status": cluster.status,
        "generated_at": current.isoformat() + "Z",
        "summary": "FAIL" if failed else ("WARN" if any(check.status in {"WARN", "UNKNOWN"} for check in checks) else "PASS"),
        "observed": {"vip_owners": vip, "dhcp_owners": dhcp, "fresh_nodes": _names(cluster, topology.fresh_node_ids)},
        "checks": [asdict(check) for check in checks],
    }


def build_report(session, *, cluster_public_id: str | None = None, now: datetime | None = None) -> list[dict]:
    from app.models.models import HACluster

    query = session.query(HACluster).filter(HACluster.deleted_at.is_(None), HACluster.provider_key == "pihole")
    if cluster_public_id:
        query = query.filter(HACluster.public_id == cluster_public_id)
    try:
        return [evaluate_cluster(cluster, now=now) for cluster in query.order_by(HACluster.name).all()]
    finally:
        session.rollback()


def render_text(reports: list[dict]) -> str:
    lines = []
    for report in reports:
        lines.append(f"Cluster {report['cluster']} ({report['cluster_id']}): stored {report['stored_status']}, invariant summary {report['summary']}")
        lines.append(f"  observed VIP owners: {report['observed']['vip_owners'] or 'none'}; DHCP owners: {report['observed']['dhcp_owners'] or 'none'}")
        for check in report["checks"]:
            lines.append(f"  [{check['status']:<7}] {check['code']}: {check['detail']}")
    return "\n".join(lines) if lines else "No Pi-hole HA clusters found."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Kaya HA invariant report.")
    parser.add_argument("--url", help="Database URL (prefer KAYA_HA_REPORT_DATABASE_URL).")
    parser.add_argument("--cluster", help="Limit to one cluster public ID.", type=lambda value: value[:64])
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    args = parser.parse_args(argv)
    url = args.url or os.environ.get("KAYA_HA_REPORT_DATABASE_URL")
    if not url:
        parser.error("Provide KAYA_HA_REPORT_DATABASE_URL (or --url).")
    from sqlalchemy.orm import Session

    try:
        engine = read_only_engine(url)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        with Session(engine) as session:
            reports = build_report(session, cluster_public_id=args.cluster)
    finally:
        engine.dispose()
    print(json.dumps(reports, indent=2, default=str) if args.json else render_text(reports))
    return 1 if any(report["summary"] == "FAIL" for report in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
