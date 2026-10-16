"""Seed automatic observed-endpoint usage for the Stage 2B browser journeys.

Flows go through the real collector path relative to now. Identity evidence is
created as pending (unconfirmed) assignments so the browser confirms it
explicitly. Disposable acceptance databases only.
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

from app.models.models import AssetNetworkAssignment, HardwareAsset, IPAddress, TrafficDeviceMonitoring, TrafficEndpointAggregate
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord
from scripts.kaya_test_migrations import _verify_connected_target, verify_disposable_url

SOURCE_ID = 9101
EXPORTER = "192.0.2.1"
REMOTE = "198.51.100.30"
UNKNOWN = "192.0.2.120"   # never adopted
ADOPT = "192.0.2.121"     # adopted in the browser
OLD_IP = "192.0.2.122"    # DHCP device's previous address, later reused
NEW_IP = "192.0.2.123"    # DHCP device's new address
ADDRESSES = (UNKNOWN, ADOPT, OLD_IP, NEW_IP)


def _flow(observed_at, sequence, address, forward, reverse):
    return NormalizedFlowRecord(
        exporter_identity=EXPORTER, source_id=SOURCE_ID, sequence=900000 + sequence, record_index=0,
        observed_at=observed_at, flow_start=None, flow_end=None, source_ip=address, destination_ip=REMOTE,
        source_port=40000 + sequence, destination_port=443, protocol=6, input_interface=None, output_interface=None,
        translated_source_ip=None, translated_destination_ip=None, translated_source_port=None, translated_destination_port=None,
        bytes_total=forward + reverse, packets_total=4, direction="unknown", event_type=None, connection_id=None,
        cumulative_counters=False, data_quality="complete", forward_bytes=forward, reverse_bytes=reverse, forward_packets=2, reverse_packets=2,
    )


def _aligned(value: datetime, seconds: int = 300) -> datetime:
    epoch = int((value - datetime(1970, 1, 1)).total_seconds())
    return datetime(1970, 1, 1) + timedelta(seconds=epoch - epoch % seconds)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("KAYA_TEST_POSTGRES_URL"))
    parser.add_argument("--inspect", action="store_true", help="Report side effects without writing.")
    args = parser.parse_args()
    if os.environ.get("KAYA_STAGE2B_TEST_MARKER") != "I_UNDERSTAND_DISPOSABLE_STAGE2B":
        raise SystemExit("Refusing to seed without KAYA_STAGE2B_TEST_MARKER=I_UNDERSTAND_DISPOSABLE_STAGE2B")
    if not args.url:
        raise SystemExit("--url or KAYA_TEST_POSTGRES_URL is required")
    verify_disposable_url(args.url)
    engine = create_engine(args.url, future=True)
    try:
        _verify_connected_target(engine, args.url)
        with sessionmaker(bind=engine, expire_on_commit=False)() as db:
            if args.inspect:
                print(json.dumps({
                    "managed_ips": db.query(func.count(IPAddress.id)).filter(IPAddress.address.in_(ADDRESSES)).scalar(),
                    "monitoring_records": db.query(func.count(TrafficDeviceMonitoring.id)).filter(TrafficDeviceMonitoring.asset_id.in_(db.query(HardwareAsset.id).filter(HardwareAsset.asset_tag.like("STAGE2B-AUTO-%")))).scalar(),
                    "observed_rows": db.query(func.count()).select_from(TrafficEndpointAggregate).filter(TrafficEndpointAggregate.endpoint_ip.in_(ADDRESSES)).scalar(),
                }))
                return 0
            now = datetime.utcnow()
            # Boundaries on 5-minute bucket edges so ownership intervals are exact.
            adopted_from = _aligned(now - timedelta(hours=2))
            handover = _aligned(now - timedelta(hours=3))
            adopt = HardwareAsset(asset_tag="STAGE2B-AUTO-ADOPT", name="Stage2B Adopted Camera", status="In use")
            mover = HardwareAsset(asset_tag="STAGE2B-AUTO-DHCP", name="Stage2B DHCP Mover", status="In use")
            reuser = HardwareAsset(asset_tag="STAGE2B-AUTO-REUSE", name="Stage2B Address Reuser", status="In use")
            db.add_all([adopt, mover, reuser])
            db.flush()
            pending_adopt = AssetNetworkAssignment(asset_id=adopt.id, address=ADOPT, address_family=4, started_at=adopted_from, provenance="stage2b adoption proposal", status="pending")
            pending_new = AssetNetworkAssignment(asset_id=mover.id, address=NEW_IP, address_family=4, started_at=handover, provenance="stage2b dhcp renewal proposal", status="pending")
            db.add_all([
                pending_adopt, pending_new,
                AssetNetworkAssignment(asset_id=mover.id, address=OLD_IP, address_family=4, started_at=now - timedelta(days=2), ended_at=handover, provenance="stage2b dhcp original", status="confirmed"),
                AssetNetworkAssignment(asset_id=reuser.id, address=OLD_IP, address_family=4, started_at=handover, provenance="stage2b dhcp reuse", status="confirmed"),
            ])
            db.commit()
            records = [
                _flow(now - timedelta(hours=1), 1, UNKNOWN, 1000, 4000),
                _flow(now - timedelta(hours=4), 2, ADOPT, 5555, 7777),          # before the adoption interval
                _flow(now - timedelta(minutes=30), 3, ADOPT, 100, 200),         # inside it
                _flow(now - timedelta(hours=5), 4, OLD_IP, 11, 22),             # mover on its original address
                _flow(now - timedelta(hours=1), 5, OLD_IP, 33, 44),             # reuser on the same address
                _flow(now - timedelta(minutes=20), 6, NEW_IP, 55, 66),          # mover on its new address
            ]
            process_records(db, records, source_id=SOURCE_ID)
            db.commit()
            print(json.dumps({
                "assets": {"adopt": adopt.id, "mover": mover.id, "reuser": reuser.id},
                "pending": {"adopt": pending_adopt.id, "renewal": pending_new.id},
                "addresses": {"unknown": UNKNOWN, "adopt": ADOPT, "old": OLD_IP, "new": NEW_IP},
                "expected": {
                    "unknown": {"download": 4000, "upload": 1000},
                    "adopt_usage": {"download": 7977, "upload": 5655},
                    "adopt_profile": {"download": 200, "upload": 100},
                    "old_usage": {"download": 66, "upload": 44},
                    "mover_profile": {"download": 22 + 66, "upload": 11 + 55},
                    "reuser_profile": {"download": 44, "upload": 33},
                },
            }))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
