"""Read-only audit for DHCP/IP identity inconsistencies.

This script requires PostgreSQL and a read-only database role. It never calls
commit, flush, update, delete, or any Kaya mutation service. Results are
bounded JSON containing database identifiers and the minimum network evidence
needed for administrator review.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.models import DNSClientTrafficEvent, DNSRecognisedDevice
from app.services.data_integrity_checks import (
    MAX_LIMIT,
    asset_confirmed_macs,
    auto_filled_static_hostnames,
    confirmed_mac_duplicates,
    dns_link_conflicts,
    obsolete_dhcp_assignments,
    run_check,
    suspect_dhcp_client_id_evidence,
)


def _limit(value: int) -> int:
    return max(1, min(int(value), MAX_LIMIT))


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _dns_link_conflicts(db: Session, limit: int) -> list[dict]:
    return [{key: value for key, value in row.items() if key != "client"} for row in dns_link_conflicts(db, limit)]


def _expired_open_assignments(db: Session, now: datetime, limit: int) -> list[dict]:
    return [{
        "assignment_id": assignment.id,
        "asset_id": assignment.asset_id,
        "lease_id": lease.id,
        "address": assignment.address,
        "dhcp_mac": lease.mac_address,
        "lease_active": bool(lease.is_active),
        "lease_ended_at": _iso(lease.ended_at),
        "lease_expires_at": _iso(lease.expires_at),
        "superseded_by_lease_id": replacement.id if replacement else None,
        "reason": reason,
        "classification": "definite_inconsistency",
    } for assignment, lease, replacement, reason in obsolete_dhcp_assignments(db, now, limit)]


def _active_ip_conflicts(db: Session, limit: int) -> list[dict]:
    rows = []
    for detection in run_check(db, "duplicate_active_ip", limit=limit).detections:
        source, exporter, vlan = detection.evidence["scope"].split("|")
        rows.append({
            "address": detection.evidence["address"],
            "address_family": detection.evidence["address_family"],
            "vlan_id": None if vlan == "any" else int(vlan),
            "source_id": None if source == "-" else int(source),
            "exporter_identity": None if exporter == "-" else exporter,
            "distinct_asset_count": len({row["asset_id"] for row in detection.evidence["assignments"]}),
            "assignment_ids": [row["assignment_id"] for row in detection.evidence["assignments"]],
            "classification": "definite_inconsistency",
        })
    return rows


def _traffic_conflicts(db: Session, limit: int) -> list[dict]:
    evidence = asset_confirmed_macs(db)
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


def _cross_asset_mac_duplicates(db: Session, limit: int) -> list[dict]:
    """Confirmed MACs owned by more than one asset (recorded under different sources)."""
    return [{
        "mac": mac,
        "distinct_asset_count": len({row.asset_id for row in rows}),
        "evidence": [{"evidence_id": row.id, "asset_id": row.asset_id, "source": row.source, "source_scope": row.source_scope, "confirmed_at": _iso(row.confirmed_at)} for row in rows],
        "classification": "definite_conflict",
    } for mac, rows in confirmed_mac_duplicates(db, limit)]


def _suspect_dhcp_client_id_evidence(db: Session, limit: int) -> list[dict]:
    """Confirmed DHCP client-id evidence that looks like a provider lease record number.

    The former ingestion fallback stored a provider's lease ``id`` as the client
    identifier. Genuine option-61 identifiers and DUIDs are not bare decimals.
    """
    return [{
        "evidence_id": row.id,
        "asset_id": row.asset_id,
        "value": row.normalised_value,
        "source_scope": row.source_scope,
        "classification": "suspected_provider_record_id",
    } for row in suspect_dhcp_client_id_evidence(db, limit)]


def _auto_filled_static_hostnames(db: Session, limit: int) -> list[dict]:
    """Static records whose current name was copied from a DNS observation."""
    return [{
        "ip_address_id": record.id,
        "dns_client_id": client.id,
        "event_id": event.id,
        "filled_at": _iso(event.created_at),
        "name_unchanged_since_fill": record.name == event.new_value,
        "classification": "review_managed_hostname_authority",
    } for event, client, record in auto_filled_static_hostnames(db, limit)]


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
        "cross_asset_confirmed_mac_duplicates": _cross_asset_mac_duplicates(db, limit),
        "suspect_dhcp_client_id_evidence": _suspect_dhcp_client_id_evidence(db, limit),
        "auto_filled_static_hostnames": _auto_filled_static_hostnames(db, limit),
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
