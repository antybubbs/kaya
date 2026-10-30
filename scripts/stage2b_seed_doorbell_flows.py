"""Send synthetic NSEL-shaped flows for the Stage 2B doorbell through the real
device attribution path. Disposable acceptance databases only."""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from app.models.models import TrafficDeviceAggregate, TrafficDeviceMonitoringPeriod, TrafficEndpointAggregate
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord
from scripts.kaya_test_migrations import _verify_connected_target, verify_disposable_url
from tests.fixtures.stage2b_acceptance import DOORBELL_ADDRESS

SOURCE_ID = 9101
EXPORTER = "192.0.2.1"
OTHER_SOURCE_ID = 9102
OTHER_EXPORTER = "192.0.2.2"
REMOTE = "198.51.100.20"
DOORBELL_ASSET_ID = 9460


def _flow(observed_at, sequence, *, source_ip, destination_ip, forward, reverse, source_id=SOURCE_ID, exporter=EXPORTER):
    return NormalizedFlowRecord(
        exporter_identity=exporter, source_id=source_id, sequence=sequence, record_index=0,
        observed_at=observed_at, flow_start=None, flow_end=None, source_ip=source_ip,
        destination_ip=destination_ip, source_port=50000 + sequence, destination_port=443, protocol=6,
        input_interface=None, output_interface=None, translated_source_ip=None,
        translated_destination_ip=None, translated_source_port=None, translated_destination_port=None,
        bytes_total=forward + reverse, packets_total=4, direction="unknown", event_type=None,
        connection_id=None, cumulative_counters=False, data_quality="complete",
        forward_bytes=forward, reverse_bytes=reverse, forward_packets=2, reverse_packets=2,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("KAYA_TEST_POSTGRES_URL"))
    parser.add_argument("--inspect", action="store_true", help="Report the doorbell's monitoring periods and aggregates without writing.")
    args = parser.parse_args()
    if os.environ.get("KAYA_STAGE2B_TEST_MARKER") != "I_UNDERSTAND_DISPOSABLE_STAGE2B":
        raise SystemExit("Refusing to seed without KAYA_STAGE2B_TEST_MARKER=I_UNDERSTAND_DISPOSABLE_STAGE2B")
    if not args.url:
        raise SystemExit("--url or KAYA_TEST_POSTGRES_URL is required")
    verify_disposable_url(args.url)
    engine = create_engine(args.url, future=True)
    try:
        _verify_connected_target(engine, args.url)
        if args.inspect:
            with sessionmaker(bind=engine)() as db:
                periods = db.query(TrafficDeviceMonitoringPeriod).filter_by(asset_id=DOORBELL_ASSET_ID).order_by(TrafficDeviceMonitoringPeriod.id).all()
                aggregates = db.query(TrafficDeviceAggregate).filter_by(asset_id=DOORBELL_ASSET_ID, bucket_seconds=300).all()
                print(json.dumps({
                    "periods": [{"id": row.id, "assignment_id": row.assignment_id, "closed": row.ended_at is not None} for row in periods],
                    "aggregates_300s": len(aggregates),
                    "aggregate_period_ids": sorted({row.period_id for row in aggregates}),
                    "aggregate_source_ids": sorted({row.source_id for row in aggregates}),
                }))
            return 0
        now = datetime.utcnow()
        records = [
            # Doorbell as initiator: forward bytes are its upload, reverse its download.
            _flow(now, 1, source_ip=DOORBELL_ADDRESS, destination_ip=REMOTE, forward=1200, reverse=48000),
            # Doorbell as responder: reverse bytes are its upload, forward its download.
            _flow(now, 2, source_ip=REMOTE, destination_ip=DOORBELL_ADDRESS, forward=900, reverse=300),
            # The same endpoint seen by a different source: its own observed
            # context, never added to the Cisco context or to tracked usage.
            _flow(now, 3, source_ip=DOORBELL_ADDRESS, destination_ip=REMOTE, forward=7777, reverse=7777, source_id=OTHER_SOURCE_ID, exporter=OTHER_EXPORTER),
        ]
        with sessionmaker(bind=engine, expire_on_commit=False)() as db:
            # The real collector path: replay protection, tracked-device
            # attribution and automatic observed-endpoint usage.
            for record in records:
                process_records(db, [record], source_id=record.source_id)
            db.commit()
            totals = {}
            for model, key in ((TrafficDeviceAggregate, "tracked"), (TrafficEndpointAggregate, "observed")):
                query = db.query(model.source_id, model.direction, func.sum(model.bytes_total)).filter(model.bucket_seconds == 300)
                query = query.filter(model.asset_id == DOORBELL_ASSET_ID) if model is TrafficDeviceAggregate else query.filter(model.endpoint_ip == DOORBELL_ADDRESS)
                totals[key] = {f"{source}:{direction}": int(value) for source, direction, value in query.group_by(model.source_id, model.direction).all()}
        print(json.dumps({**totals, "expected_download": 48900, "expected_upload": 1500, "other_source": 7777}))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
