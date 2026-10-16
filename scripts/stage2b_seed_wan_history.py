"""Seed synthetic SNMP WAN interface history relative to now and print the
expected selected-period totals. Disposable acceptance databases only."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.models import TrafficAggregate, TrafficCounterObservation, TrafficInterface, TrafficSource
from scripts.kaya_test_migrations import _verify_connected_target, verify_disposable_url

# Per-bucket bytes per interface and resolution: (download, upload).
VALUES = {
    "a0": {300: (1_000_000, 100_000), 3600: (10_000_000, 1_000_000), 86400: (100_000_000, 10_000_000)},
    "a1": {300: (500_000, 50_000), 3600: (5_000_000, 500_000), 86400: (50_000_000, 5_000_000)},
    "b0": {300: (7_000, 700), 3600: (70_000, 7_000), 86400: (700_000, 70_000)},
}
# Seeded spans stay clear of the moving window edges for the acceptance run.
SPANS = {300: (timedelta(hours=23), timedelta(minutes=10)), 3600: (timedelta(days=6, hours=12), timedelta(hours=2)), 86400: (timedelta(days=88), timedelta(days=1))}
MISSING_300 = 12  # the first twelve 5-minute buckets of interface a0 are absent (no counter delta)


def _aligned(value: datetime, seconds: int) -> datetime:
    epoch = int((value - datetime(1970, 1, 1)).total_seconds())
    return datetime(1970, 1, 1) + timedelta(seconds=epoch - epoch % seconds)


def _buckets(now: datetime, seconds: int) -> list[datetime]:
    oldest, newest = SPANS[seconds]
    cursor = _aligned(now - oldest, seconds) + timedelta(seconds=seconds)
    result = []
    while cursor <= now - newest:
        result.append(cursor)
        cursor += timedelta(seconds=seconds)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("KAYA_TEST_POSTGRES_URL"))
    args = parser.parse_args()
    if os.environ.get("KAYA_STAGE2B_TEST_MARKER") != "I_UNDERSTAND_DISPOSABLE_STAGE2B":
        raise SystemExit("Refusing to seed without KAYA_STAGE2B_TEST_MARKER=I_UNDERSTAND_DISPOSABLE_STAGE2B")
    if not args.url:
        raise SystemExit("--url or KAYA_TEST_POSTGRES_URL is required")
    verify_disposable_url(args.url)
    engine = create_engine(args.url, future=True)
    try:
        _verify_connected_target(engine, args.url)
        now = datetime.utcnow()
        expected: dict = {"sources": {}, "ranges": {}}
        with sessionmaker(bind=engine)() as db:
            sources = {
                "a": TrafficSource(name="Stage2B WAN primary", provider_key="snmpv3", source_category="interface_polling", is_enabled=True, is_deleted=False),
                "b": TrafficSource(name="Stage2B WAN backup", provider_key="snmpv3", source_category="interface_polling", is_enabled=True, is_deleted=False),
            }
            db.add_all(sources.values())
            db.flush()
            interfaces = {
                "a0": TrafficInterface(source_id=sources["a"].id, interface_key="stage2b-wan-a0", interface_index=1, display_name="WAN A0", is_enabled=True, is_wan=True, inbound_direction="download", outbound_direction="upload"),
                "a1": TrafficInterface(source_id=sources["a"].id, interface_key="stage2b-wan-a1", interface_index=2, display_name="WAN A1", is_enabled=True, is_wan=True, inbound_direction="download", outbound_direction="upload"),
                "b0": TrafficInterface(source_id=sources["b"].id, interface_key="stage2b-wan-b0", interface_index=1, display_name="WAN B0", is_enabled=True, is_wan=True, inbound_direction="download", outbound_direction="upload"),
            }
            db.add_all(interfaces.values())
            db.flush()
            totals: dict = {}
            for key, interface in interfaces.items():
                for seconds, (download, upload) in VALUES[key].items():
                    buckets = _buckets(now, seconds)
                    if key == "a0" and seconds == 300:
                        buckets = buckets[MISSING_300:]
                    for bucket in buckets:
                        for direction, value in (("download", download), ("upload", upload)):
                            db.add(TrafficAggregate(source_id=interface.source_id, interface_id=interface.id, bucket_start=bucket, bucket_seconds=seconds, direction=direction, traffic_class="interface_total", bytes_total=value, sample_count=1, is_approximate=True, first_observed_at=bucket, last_observed_at=bucket))
                    totals[(key, seconds)] = (download * len(buckets), upload * len(buckets))
                db.add(TrafficCounterObservation(source_id=interface.source_id, interface_id=interface.id, observation_key=f"stage2b-wan-live-{key}", observed_at=now - timedelta(seconds=30), inbound_counter=1, outbound_counter=1, inbound_bps=80_000_000, outbound_bps=8_000_000))
            db.commit()
            expected["sources"] = {"a": sources["a"].id, "b": sources["b"].id}
            for report_range, seconds in (("24h", 300), ("7d", 3600), ("30d", 86400), ("90d", 86400)):
                keys = {"all": ("a0", "a1", "b0"), "a": ("a0", "a1"), "b": ("b0",)}
                expected["ranges"][report_range] = {}
                for scope, members in keys.items():
                    if report_range == "30d":
                        # 30 days covers only the daily buckets within the last 30 days.
                        in_window = [bucket for bucket in _buckets(now, 86400) if bucket >= now - timedelta(days=30)]
                        download = sum(VALUES[member][86400][0] * len(in_window) for member in members)
                        upload = sum(VALUES[member][86400][1] * len(in_window) for member in members)
                    else:
                        download = sum(totals[(member, seconds)][0] for member in members)
                        upload = sum(totals[(member, seconds)][1] for member in members)
                    expected["ranges"][report_range][scope] = {"download": download, "upload": upload}
            # Custom window of 30 whole hours (hourly resolution), entered in the
            # fixture's UTC site timezone.
            custom_end = _aligned(now, 3600) - timedelta(hours=18)
            custom_start = custom_end - timedelta(hours=30)
            expected["custom"] = {
                "start": custom_start.strftime("%Y-%m-%dT%H:%M"), "end": custom_end.strftime("%Y-%m-%dT%H:%M"),
                "all": {"download": 30 * sum(VALUES[key][3600][0] for key in VALUES), "upload": 30 * sum(VALUES[key][3600][1] for key in VALUES)},
            }
        print(json.dumps(expected))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
