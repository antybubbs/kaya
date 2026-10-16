"""Selected-period WAN transfer totals come from persisted SNMP counter deltas.

All data is synthetic. Bucket starts are aligned explicitly so the tests do not
depend on the host timezone.
"""

import os
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    TrafficAggregate,
    TrafficCounterObservation,
    TrafficFlowAccountingAggregate,
    TrafficFlowAggregate,
    TrafficInterface,
    TrafficSource,
)
from app.services.network_traffic_reporting import custom_report_window, wan_report
from app.services.network_traffic_snmp import calculate_rate

NOW = datetime(2026, 3, 10, 12, 0, 0)


def _aligned(value: datetime, seconds: int) -> datetime:
    epoch = int((value - datetime(1970, 1, 1)).total_seconds())
    return datetime(1970, 1, 1) + timedelta(seconds=epoch - epoch % seconds)


def _first_bucket(start: datetime, seconds: int) -> datetime:
    """First persisted bucket whose start lies inside a window beginning at ``start``."""
    aligned = _aligned(start, seconds)
    return aligned if aligned == start else aligned + timedelta(seconds=seconds)


DURATIONS = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "90d": timedelta(days=90)}


@pytest.fixture(params=["sqlite", "postgresql"])
def db(request):
    if request.param == "sqlite":
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        session = sessionmaker(bind=engine)()
        yield session
        session.close()
        return
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url)
    connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")()
    yield session
    session.close()
    transaction.rollback()
    connection.close()
    engine.dispose()


def _wan(db, name, *, interfaces=1):
    source = TrafficSource(name=f"Synthetic WAN {name}", provider_key="snmpv3", source_category="interface_polling", is_enabled=True, is_deleted=False)
    db.add(source)
    db.flush()
    rows = []
    for index in range(interfaces):
        rows.append(TrafficInterface(source_id=source.id, interface_key=f"wan{index}", interface_index=index + 1, display_name=f"WAN {index}", is_enabled=True, is_wan=True, inbound_direction="download", outbound_direction="upload"))
    db.add_all(rows)
    db.flush()
    return source, rows


def _fill(db, source, interface, *, seconds, start, count, download, upload, skip=()):
    for index in range(count):
        if index in skip:
            continue
        bucket = start + timedelta(seconds=seconds * index)
        for direction, value in (("download", download), ("upload", upload)):
            db.add(TrafficAggregate(source_id=source.id, interface_id=interface.id, bucket_start=bucket, bucket_seconds=seconds, direction=direction, traffic_class="interface_total", bytes_total=value, sample_count=1, is_approximate=True))
    db.commit()


@pytest.mark.parametrize(("report_range", "seconds", "buckets"), [("24h", 300, 288), ("7d", 3600, 168), ("30d", 86400, 30), ("90d", 86400, 90)])
def test_selected_period_totals_follow_the_range(db, report_range, seconds, buckets):
    source, (interface,) = _wan(db, report_range)
    first = _first_bucket(NOW - DURATIONS[report_range], seconds)
    _fill(db, source, interface, seconds=seconds, start=first, count=buckets, download=1000, upload=100)
    # A bucket before the window, one at the exclusive end and a different
    # resolution are never counted.
    _fill(db, source, interface, seconds=seconds, start=first - timedelta(seconds=seconds), count=1, download=10**9, upload=10**9)
    _fill(db, source, interface, seconds=seconds, start=first + timedelta(seconds=seconds * buckets), count=1, download=10**9, upload=10**9)
    _fill(db, source, interface, seconds=60 if seconds != 60 else 120, start=_aligned(NOW, 300) - timedelta(minutes=10), count=1, download=10**9, upload=10**9)
    summary = wan_report(db, report_range=report_range, now=NOW)["summary"]
    period = summary["period"]
    assert (summary["download_bytes_period"], summary["upload_bytes_period"]) == (1000 * buckets, 100 * buckets)
    assert period["bucket_seconds"] == seconds
    assert (period["download_coverage_percent"], period["upload_coverage_percent"], period["coverage"]) == (100, 100, "complete")
    # Totals and graph use identical boundaries.
    history = wan_report(db, report_range=report_range, now=NOW)["history"]
    assert sum(point["download_bytes"] for point in history) == summary["download_bytes_period"]


def test_missing_buckets_are_partial_coverage_not_zero_traffic(db):
    source, (interface,) = _wan(db, "gaps")
    _fill(db, source, interface, seconds=300, start=_first_bucket(NOW - DURATIONS["24h"], 300), count=288, download=50, upload=5, skip=set(range(0, 144)))
    period = wan_report(db, report_range="24h", now=NOW)["summary"]["period"]
    assert (period["download_bytes"], period["upload_bytes"]) == (50 * 144, 5 * 144)
    assert (period["download_coverage_percent"], period["coverage"]) == (50, "partial")


def test_no_counter_data_is_unavailable_not_zero(db):
    _wan(db, "empty")
    summary = wan_report(db, report_range="30d", now=NOW)["summary"]
    assert (summary["download_bytes_period"], summary["upload_bytes_period"], summary["period"]["coverage"]) == (None, None, "unavailable")


def test_source_filter_and_multiple_interfaces(db):
    first, interfaces = _wan(db, "multi", interfaces=2)
    second, (other,) = _wan(db, "other")
    start = _first_bucket(NOW - DURATIONS["1h"], 300)
    _fill(db, first, interfaces[0], seconds=300, start=start, count=12, download=100, upload=10)
    _fill(db, first, interfaces[1], seconds=300, start=start, count=6, download=200, upload=20)
    _fill(db, second, other, seconds=300, start=start, count=12, download=7, upload=1)
    selected = wan_report(db, report_range="1h", source_id=first.id, now=NOW)["summary"]["period"]
    assert (selected["download_bytes"], selected["upload_bytes"]) == (100 * 12 + 200 * 6, 10 * 12 + 20 * 6)
    assert (selected["expected_buckets"], selected["download_coverage_percent"], selected["coverage"]) == (24, 75, "partial")
    everything = wan_report(db, report_range="1h", now=NOW)["summary"]["period"]
    assert everything["download_bytes"] == 100 * 12 + 200 * 6 + 7 * 12


def test_custom_range_uses_one_validated_window(db):
    source, (interface,) = _wan(db, "custom")
    _fill(db, source, interface, seconds=3600, start=_aligned(NOW, 3600) - timedelta(days=5), count=120, download=10, upload=1)
    window = custom_report_window(db, (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M"), (NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"), now=NOW)
    assert window[2] == 3600
    period = wan_report(db, now=NOW, window=window)["summary"]["period"]
    assert (period["download_bytes"], period["expected_buckets"], period["coverage"]) == (10 * 48, 48, "complete")
    with pytest.raises(HTTPException):
        custom_report_window(db, (NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"), None, now=NOW)


def test_counter_reset_contributes_no_fabricated_bytes(db):
    """Reproduce the poller's per-sample path: a reset yields no rate and no bytes."""
    source, (interface,) = _wan(db, "reset")
    counters = [0, 30_000, 60_000, 5_000, 35_000]  # reset between samples 2 and 3
    start = _aligned(NOW, 300) - timedelta(minutes=25)
    previous = None
    for index, value in enumerate(counters):
        at = start + timedelta(minutes=5 * (index + 1))
        rate = calculate_rate(previous, value, 300).bits_per_second
        if rate is not None:
            bucket = at - timedelta(minutes=5)
            db.add(TrafficAggregate(source_id=source.id, interface_id=interface.id, bucket_start=bucket, bucket_seconds=300, direction="download", traffic_class="interface_total", bytes_total=int(rate * 300 / 8), sample_count=1, is_approximate=True))
        previous = value
    db.commit()
    period = wan_report(db, report_range="1h", now=NOW)["summary"]["period"]
    assert period["download_bytes"] == 30_000 * 3  # the reset interval is missing, not negative or inflated
    assert period["coverage"] == "partial"


def test_live_throughput_is_unchanged_and_flow_data_is_not_mixed(db):
    source, (interface,) = _wan(db, "live")
    _fill(db, source, interface, seconds=300, start=_aligned(NOW, 300) - timedelta(minutes=5), count=1, download=500, upload=50)
    db.add(TrafficCounterObservation(source_id=source.id, interface_id=interface.id, observation_key="synthetic-live", observed_at=NOW - timedelta(minutes=1), inbound_counter=1, outbound_counter=1, inbound_bps=8000, outbound_bps=800))
    flow = TrafficSource(name="Synthetic NSEL", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False)
    db.add(flow)
    db.flush()
    db.add(TrafficFlowAggregate(source_id=flow.id, exporter_identity="192.0.2.1", bucket_start=_aligned(NOW, 300) - timedelta(minutes=5), bucket_seconds=300, direction="download", bytes_total=10**9))
    db.add(TrafficFlowAccountingAggregate(source_id=flow.id, exporter_identity="192.0.2.1", bucket_start=_aligned(NOW, 300) - timedelta(minutes=5), bucket_seconds=300, traffic_class="internet_download", bytes_total=10**9))
    db.commit()
    summary = wan_report(db, report_range="24h", now=NOW)["summary"]
    assert (summary["current_download_bps"], summary["current_upload_bps"]) == (8000, 800)
    assert (summary["download_bytes_period"], summary["upload_bytes_period"]) == (500, 50)


def test_report_route_rejects_an_incomplete_custom_range(db):
    from app.routers.network_monitor import traffic_reporting_report

    with pytest.raises(HTTPException) as failure:
        traffic_reporting_report(report_range="custom", start="2026-03-09T00:00", end=None, source_id=None, device_id=None, db=db, user=None)
    assert failure.value.status_code == 400
