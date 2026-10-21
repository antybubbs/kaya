"""Read-only audit for DHCP/IP identity inconsistencies.

This script requires PostgreSQL and a read-only database role. It never calls
commit, flush, update, delete, or any Kaya mutation service. Results are
bounded JSON containing database identifiers and the minimum network evidence
needed for administrator review.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
import json
import sys

from sqlalchemy import create_engine, distinct, func
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSClientTrafficEvent,
    DNSRecognisedDevice,
)


MAX_LIMIT = 5000


def _limit(value: int) -> int:
    return max(1, min(int(value), MAX_LIMIT))


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _asset_mac_evidence(db: Session) -> dict[int, set[str]]:
    rows = db.query(AssetIdentityEvidence).filter(
        AssetIdentityEvidence.evidence_type == "mac",
        AssetIdentityEvidence.status == "confirmed",
        AssetIdentityEvidence.revoked_at.is_(None),
        AssetIdentityEvidence.asset_id.isnot(None),
    ).limit(MAX_LIMIT * 4).all()
    result: dict[int, set[str]] = defaultdict(set)
    for row in rows:
        result[row.asset_id].add(row.normalised_value.casefold())
    return result


def _dns_link_conflicts(db: Session, limit: int) -> list[dict]:
    evidence = _asset_mac_evidence(db)
    clients = db.query(DNSRecognisedDevice).filter(
        DNSRecognisedDevice.hardware_asset_id.isnot(None),
        DNSRecognisedDevice.normalised_mac.isnot(None),
    ).order_by(DNSRecognisedDevice.id.asc()).limit(limit).all()
    rows = []
    for client in clients:
        observed = (client.normalised_mac or client.mac_address or "").casefold()
        confirmed = evidence.get(client.hardware_asset_id, set())
        if observed in confirmed:
            continue
        other_assets = [asset_id for asset_id, values in evidence.items() if observed in values and asset_id != client.hardware_asset_id]
        rows.append({
            "dns_client_id": client.id,
            "asset_id": client.hardware_asset_id,
            "observed_mac": observed,
            "confirmed_asset_macs": sorted(confirmed),
            "matching_other_asset_ids": sorted(other_assets),
            "classification": "definite_conflict" if other_assets else "suspected_unverified_link",
        })
    return rows


def _expired_open_assignments(db: Session, now: datetime, limit: int) -> list[dict]:
    rows = db.query(AssetNetworkAssignment, DHCPLeaseHistory).join(
        DHCPLeaseHistory, DHCPLeaseHistory.id == AssetNetworkAssignment.dhcp_lease_id,
    ).filter(
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
    ).order_by(AssetNetworkAssignment.id.asc()).limit(limit).all()
    provider_ids = {lease.provider_id for _assignment, lease in rows if lease.provider_id is not None}
    addresses = {lease.ip_address for _assignment, lease in rows}
    active_rows = db.query(DHCPLeaseHistory).filter(
        DHCPLeaseHistory.is_active.is_(True),
        DHCPLeaseHistory.provider_id.in_(provider_ids or {-1}),
        DHCPLeaseHistory.ip_address.in_(addresses or {"0.0.0.0"}),
    ).order_by(DHCPLeaseHistory.last_seen_at.desc()).limit(limit * 2).all()
    newest: dict[tuple[int | None, str], DHCPLeaseHistory] = {}
    for active in active_rows:
        key = (active.provider_id, active.ip_address)
        current = newest.get(key)
        if current is None or (active.lease_started_at, active.id) > (current.lease_started_at, current.id):
            newest[key] = active
    result = []
    for assignment, lease in rows:
        replacement = newest.get((lease.provider_id, lease.ip_address))
        superseded = bool(
            replacement
            and replacement.id != lease.id
            and (replacement.lease_started_at, replacement.id) > (lease.lease_started_at, lease.id)
            and replacement.mac_address != lease.mac_address
        )
        expired = bool(
            not lease.is_active
            or lease.ended_at is not None
            or (lease.expires_at is not None and lease.expires_at < now)
        )
        if not expired and not superseded:
            continue
        result.append({
            "assignment_id": assignment.id,
            "asset_id": assignment.asset_id,
            "lease_id": lease.id,
            "address": assignment.address,
            "dhcp_mac": lease.mac_address,
            "lease_active": bool(lease.is_active),
            "lease_ended_at": _iso(lease.ended_at),
            "lease_expires_at": _iso(lease.expires_at),
            "superseded_by_lease_id": replacement.id if superseded else None,
            "classification": "definite_inconsistency",
        })
    return result


def _active_ip_conflicts(db: Session, limit: int) -> list[dict]:
    grouped = db.query(
        AssetNetworkAssignment.address,
        AssetNetworkAssignment.address_family,
        AssetNetworkAssignment.vlan_id,
        AssetNetworkAssignment.source_id,
        AssetNetworkAssignment.exporter_identity,
        func.count(distinct(AssetNetworkAssignment.asset_id)),
    ).filter(
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
        AssetNetworkAssignment.asset_id.isnot(None),
    ).group_by(
        AssetNetworkAssignment.address,
        AssetNetworkAssignment.address_family,
        AssetNetworkAssignment.vlan_id,
        AssetNetworkAssignment.source_id,
        AssetNetworkAssignment.exporter_identity,
    ).having(func.count(distinct(AssetNetworkAssignment.asset_id)) > 1).limit(limit).all()
    return [{
        "address": address,
        "address_family": family,
        "vlan_id": vlan_id,
        "source_id": source_id,
        "exporter_identity": exporter,
        "distinct_asset_count": count,
        "classification": "definite_inconsistency",
    } for address, family, vlan_id, source_id, exporter, count in grouped]


def _traffic_conflicts(db: Session, limit: int) -> list[dict]:
    evidence = _asset_mac_evidence(db)
    rows = db.query(DNSClientTrafficEvent, DNSRecognisedDevice).join(
        DNSRecognisedDevice, DNSRecognisedDevice.id == DNSClientTrafficEvent.dns_client_id,
    ).filter(
        DNSRecognisedDevice.hardware_asset_id.isnot(None),
        DNSRecognisedDevice.normalised_mac.isnot(None),
    ).order_by(DNSClientTrafficEvent.id.asc()).limit(limit).all()
    result = []
    for event, client in rows:
        observed = (client.normalised_mac or "").casefold()
        asset_id = client.hardware_asset_id
        if observed in evidence.get(asset_id, set()):
            continue
        result.append({
            "traffic_event_id": event.id,
            "dns_client_id": client.id,
            "asset_id": asset_id,
            "dhcp_lease_id": event.dhcp_lease_id,
            "client_ip": event.client_ip,
            "observed_at": _iso(event.observed_at),
            "classification": "definite_conflict" if any(observed in values for other, values in evidence.items() if other != asset_id) else "suspected_unverified_link",
        })
    return result


def run_audit(db: Session, limit: int) -> dict:
    now = datetime.utcnow()
    dns_conflicts = _dns_link_conflicts(db, limit)
    return {
        "generated_at": now.isoformat(),
        "read_only": True,
        "limit_per_category": limit,
        "dns_asset_link_conflicts": dns_conflicts,
        "open_assignments_with_ended_leases": _expired_open_assignments(db, now, limit),
        "active_ip_ownership_conflicts": _active_ip_conflicts(db, limit),
        "legacy_dns_traffic_conflicts": _traffic_conflicts(db, limit),
        "discovery_association_review": [
            {
                "candidate_id": f"dns:{row['dns_client_id']}",
                "classification": row["classification"],
                "asset_id": row["asset_id"],
                "observed_mac": row["observed_mac"],
            }
            for row in dns_conflicts
        ],
        "discovery_note": "Discovery blocking is derived at request time; contradictory DNS links are represented by discovery_association_review and are not mutated by this audit.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a bounded, SELECT-only Kaya DHCP/IP identity audit.")
    parser.add_argument("--limit", type=int, default=1000, help=f"Maximum rows per category (1-{MAX_LIMIT}).")
    args = parser.parse_args()
    limit = _limit(args.limit)
    settings = get_settings()
    database_url = settings.database_url
    if not database_url.startswith("postgresql"):
        raise SystemExit("Refusing to run: DATABASE_URL must be PostgreSQL for the production audit.")
    connect_args = {
        "options": "-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=2000",
    }
    engine = create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        with factory() as db:
            with db.begin():
                db.connection().exec_driver_sql("SET TRANSACTION READ ONLY")
                report = run_audit(db, limit)
            print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)
