"""Drive the Stage 2B DHCP identity-continuity journey through real ingestion.

``collect`` runs the real DNS Manager collection job (``analyse_provider``)
with a synthetic Pi-hole DHCP payload in place of the network fetch, at a
simulated collection time so lease intervals span whole traffic buckets.
``flows`` sends synthetic NSEL records through the real flow collector.
``inspect`` reports state and side effects without writing. No network
assignment is ever inserted here: assignments come only from DHCP
reconciliation. Disposable acceptance databases only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

import app.services.dns_insights as dns_insights
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    NetworkMonitor,
    TrafficDeviceMonitoring,
)
from app.services.dns_providers import DNSProviderResult
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord
from scripts.kaya_test_migrations import _verify_connected_target, verify_disposable_url

PROVIDER_NAME = "Stage2B DHCP continuity Pi-hole"
SOURCE_ID = 9101


def _mask_mac_address(mac: str | None) -> str | None:
    if mac is None:
        return None
    parts = mac.split(":")
    if len(parts) == 6:
        return "xx:xx:xx:xx:xx:" + parts[-1]
    return "redacted"
EXPORTER = "192.0.2.1"
REMOTE = "198.51.100.31"
ADDRESSES = ("192.0.2.231", "192.0.2.232", "192.0.2.233")


def _aligned(value: datetime, seconds: int = 300) -> datetime:
    epoch = int((value - datetime(1970, 1, 1)).total_seconds())
    return datetime(1970, 1, 1) + timedelta(seconds=epoch - epoch % seconds)


def _provider(db) -> DNSProviderConfig:
    provider = db.query(DNSProviderConfig).filter_by(name=PROVIDER_NAME).first()
    if provider is None:
        provider = DNSProviderConfig(name=PROVIDER_NAME, provider_type="pihole", base_url="https://pihole.stage2b.invalid", is_enabled=True)
        db.add(provider)
        db.commit()
    return provider


def _redact_mac(mac: str | None) -> str:
    if not mac:
        return "REDACTED"
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(["xx", "xx", "xx", parts[3], parts[4], parts[5]])
    return "REDACTED"


def collect(db, leases: list[dict], minutes_ago: int) -> dict:
    """One DNS Manager collection pass, as the scheduler would run it."""
    at = _aligned(datetime.utcnow() - timedelta(minutes=minutes_ago))

    class _CollectionClock(datetime):
        @classmethod
        def utcnow(cls):
            return at

    payloads = {
        "status": DNSProviderResult(True, "Synthetic status", {"blocking": "enabled"}),
        "stats": DNSProviderResult(True, "Synthetic statistics", {}),
        "history": DNSProviderResult(False, "Not provided by the synthetic payload"),
        "clients": DNSProviderResult(False, "Not provided by the synthetic payload"),
        "queries": DNSProviderResult(True, "Synthetic query log", {"queries": []}),
        "dhcp": DNSProviderResult(True, "Synthetic DHCP leases", {"leases": leases}),
        "blocklists": DNSProviderResult(False, "Not provided by the synthetic payload"),
    }
    original_collect, original_clock = dns_insights._collect_provider_data, dns_insights.datetime
    dns_insights._collect_provider_data = lambda _client: payloads
    dns_insights.datetime = _CollectionClock
    try:
        dns_insights.analyse_provider(db, _provider(db))
    finally:
        dns_insights._collect_provider_data, dns_insights.datetime = original_collect, original_clock
    rows = db.query(DHCPLeaseHistory).filter(DHCPLeaseHistory.ip_address.in_(ADDRESSES)).order_by(DHCPLeaseHistory.id).all()
    return {"collected_at": at.isoformat(), "leases": [{"id": row.id, "ip": row.ip_address, "mac": _redact_mac(row.mac_address), "active": row.is_active} for row in rows]}


def flows(db, items: list[dict]) -> dict:
    now = datetime.utcnow()
    records = []
    for index, item in enumerate(items):
        observed = _aligned(now - timedelta(minutes=int(item["minutes_ago"]))) + timedelta(minutes=1)
        records.append(NormalizedFlowRecord(
            exporter_identity=EXPORTER, source_id=SOURCE_ID, sequence=int(item["sequence"]), record_index=0,
            observed_at=observed, flow_start=None, flow_end=None, source_ip=item["ip"], destination_ip=REMOTE,
            source_port=41000 + index, destination_port=443, protocol=6, input_interface=None, output_interface=None,
            translated_source_ip=None, translated_destination_ip=None, translated_source_port=None, translated_destination_port=None,
            bytes_total=int(item["upload"]) + int(item["download"]), packets_total=4, direction="unknown", event_type=None, connection_id=None,
            cumulative_counters=False, data_quality="complete", forward_bytes=int(item["upload"]), reverse_bytes=int(item["download"]),
            forward_packets=2, reverse_packets=2,
        ))
    result = process_records(db, records, source_id=SOURCE_ID)
    db.commit()
    return {"processed": len(records), "result": str(result)}


def inspect(db) -> dict:
    assets = db.query(HardwareAsset).filter(HardwareAsset.name.like("Stage2B DHCP %")).order_by(HardwareAsset.id).all()
    return {
        "assets_total": db.query(func.count(HardwareAsset.id)).scalar(),
        "assets": {
            asset.name: {
                "id": asset.id,
                "assignments": [
                    {"address": row.address, "provenance": row.provenance, "open": row.ended_at is None, "source_id": row.source_id,
                     "exporter_identity": row.exporter_identity, "dhcp_lease_id": row.dhcp_lease_id,
                     "started_at": row.started_at.isoformat(), "ended_at": row.ended_at.isoformat() if row.ended_at else None}
                    for row in db.query(AssetNetworkAssignment).filter_by(asset_id=asset.id).order_by(AssetNetworkAssignment.started_at, AssetNetworkAssignment.id)
                ],
                "evidence": sorted(f"{row.evidence_type}:{row.status}" for row in db.query(AssetIdentityEvidence).filter_by(asset_id=asset.id)),
            }
            for asset in assets
        },
        "leases": [{"id": row.id, "ip": row.ip_address, "mac": _mask_mac_address(row.mac_address), "active": row.is_active, "first_seen_at": row.first_seen_at.isoformat(),
                    "last_seen_at": row.last_seen_at.isoformat(), "ended_at": row.ended_at.isoformat() if row.ended_at else None}
                   for row in db.query(DHCPLeaseHistory).filter(DHCPLeaseHistory.ip_address.in_(ADDRESSES)).order_by(DHCPLeaseHistory.id)],
        "dns_clients": db.query(func.count(DNSRecognisedDevice.id)).scalar(),
        "dns_clients_by_mac": {
            row.normalised_mac: {"count": count, "hardware_asset_id": row.hardware_asset_id}
            for row, count in (
                (db.query(DNSRecognisedDevice).filter_by(normalised_mac=mac).first(), db.query(func.count(DNSRecognisedDevice.id)).filter_by(normalised_mac=mac).scalar())
                for (mac,) in db.query(DHCPLeaseHistory.mac_address).filter(DHCPLeaseHistory.ip_address.in_(ADDRESSES)).distinct()
            ) if row is not None
        },
        "managed_ips": db.query(func.count(IPAddress.id)).filter(IPAddress.address.in_(ADDRESSES)).scalar(),
        "monitoring_records": db.query(func.count(TrafficDeviceMonitoring.id)).scalar(),
        "uptime_monitors": db.query(func.count(NetworkMonitor.id)).scalar(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("collect", "flows", "inspect"))
    parser.add_argument("payload", nargs="?", default="[]", help="JSON list of leases or flows.")
    parser.add_argument("--minutes-ago", type=int, default=0)
    parser.add_argument("--url", default=os.environ.get("KAYA_TEST_POSTGRES_URL"))
    args = parser.parse_args()
    if os.environ.get("KAYA_STAGE2B_TEST_MARKER") != "I_UNDERSTAND_DISPOSABLE_STAGE2B":
        raise SystemExit("Refusing to seed without KAYA_STAGE2B_TEST_MARKER=I_UNDERSTAND_DISPOSABLE_STAGE2B")
    if not args.url:
        raise SystemExit("--url or KAYA_TEST_POSTGRES_URL is required")
    verify_disposable_url(args.url)
    payload = json.loads(args.payload)
    if not isinstance(payload, list) or len(payload) > 20:
        raise SystemExit("payload must be a JSON list of at most 20 items")
    for item in payload:
        if not isinstance(item, dict) or item.get("ip") not in ADDRESSES:
            raise SystemExit("every item must use a Stage 2B DHCP continuity address")
    engine = create_engine(args.url, future=True)
    try:
        _verify_connected_target(engine, args.url)
        with sessionmaker(bind=engine, expire_on_commit=False)() as db:
            if args.command == "collect":
                print(json.dumps(collect(db, payload, args.minutes_ago)))
            elif args.command == "flows":
                print(json.dumps(flows(db, payload)))
            else:
                print(json.dumps(inspect(db)))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
