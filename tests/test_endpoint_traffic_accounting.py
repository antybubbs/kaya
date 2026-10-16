"""Automatic observed-endpoint usage through the real flow pipeline.

All data is synthetic (RFC 5737 / RFC 3849 addresses, example.invalid accounts).
"""

import os
import threading
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    HardwareAsset,
    IPAddress,
    TrafficDeviceMonitoring,
    TrafficEndpointAggregate,
    TrafficFlowAccountingAggregate,
    TrafficFlowAggregate,
    TrafficFlowCollectorState,
    TrafficFlowDeduplication,
    TrafficLocalNetwork,
    TrafficMonitoringConfiguration,
    TrafficSource,
    User,
)
from app.services.asset_profile_reporting import asset_reporting_context
from app.services.endpoint_traffic import bucket_start, cleanup_endpoint_aggregates
from app.services.flow_accounting import retention_cutoffs
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord
from app.services.modules import grant_all_registered_modules
from app.services.network_traffic_reporting import device_usage_report

NOW = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
LAN = "192.0.2.0/24"
EXPORTER = "192.0.2.1"
REMOTE = "198.51.100.20"


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


def _setup(db, *, enabled=True, tag=""):
    config = db.get(TrafficMonitoringConfiguration, 1)
    if config is None:
        db.add(TrafficMonitoringConfiguration(id=1, is_enabled=enabled))
    else:
        config.is_enabled = enabled
    if not db.query(TrafficLocalNetwork).filter_by(network_cidr=LAN).first():
        db.add(TrafficLocalNetwork(name=f"Synthetic LAN {tag}", network_cidr=LAN, is_enabled=True))
    sources = [
        TrafficSource(name=f"Synthetic NSEL {tag}{uuid.uuid4().hex[:6]}", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False),
        TrafficSource(name=f"Synthetic NetFlow {tag}{uuid.uuid4().hex[:6]}", provider_key="netflow_v9", source_category="flow", is_enabled=True, is_deleted=False),
    ]
    db.add_all(sources)
    db.commit()
    return sources


def _record(source_id, *, at=None, source_ip="192.0.2.10", destination_ip=REMOTE, forward=1000, reverse=4000, directional=True, exporter=EXPORTER, sequence=1, translated_source=None, translated_destination=None):
    at = at or NOW - timedelta(hours=1)
    return NormalizedFlowRecord(
        exporter_identity=exporter, source_id=source_id, sequence=sequence, record_index=0,
        observed_at=at, flow_start=None, flow_end=None, source_ip=source_ip, destination_ip=destination_ip,
        source_port=50000 + sequence, destination_port=443, protocol=6, input_interface=None, output_interface=None,
        translated_source_ip=translated_source, translated_destination_ip=translated_destination,
        translated_source_port=None, translated_destination_port=None,
        bytes_total=(forward + reverse) if directional else forward, packets_total=4,
        direction="unknown", event_type=None, connection_id=None, cumulative_counters=False, data_quality="complete",
        forward_bytes=forward if directional else None, reverse_bytes=reverse if directional else None,
        forward_packets=2 if directional else None, reverse_packets=2 if directional else None,
    )


def _ingest(db, source, *records):
    result = process_records(db, list(records), source_id=source.id)
    db.commit()
    return result


def _usage(db, address, *, seconds=300, **filters):
    query = db.query(TrafficEndpointAggregate.direction, func.sum(TrafficEndpointAggregate.bytes_total)).filter(
        TrafficEndpointAggregate.endpoint_ip == address, TrafficEndpointAggregate.bucket_seconds == seconds,
    )
    for key, value in filters.items():
        query = query.filter(getattr(TrafficEndpointAggregate, key) == value)
    return {direction: int(total) for direction, total in query.group_by(TrafficEndpointAggregate.direction).all()}


def _admin(db):
    user = User(email=f"synthetic-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role="admin", is_active=True)
    db.add(user)
    db.flush()
    grant_all_registered_modules(db, user)
    db.commit()
    return user


# ----------------------------------------------------------------- eligibility


def test_unknown_dhcp_only_and_static_endpoints_are_accounted_without_any_records(db):
    nsel, _ = _setup(db)
    db.add(DHCPLeaseHistory(ip_address="192.0.2.11", mac_address="02:00:00:00:00:11", hostname="synthetic-dhcp", lease_started_at=NOW - timedelta(days=1)))
    db.commit()
    _ingest(db, nsel, _record(nsel.id, source_ip="192.0.2.10", sequence=1), _record(nsel.id, source_ip="192.0.2.11", sequence=2), _record(nsel.id, source_ip="192.0.2.12", sequence=3))
    for address in ("192.0.2.10", "192.0.2.11", "192.0.2.12"):
        assert _usage(db, address) == {"upload": 1000, "download": 4000}
    # Nothing is created as a side effect.
    assert db.query(IPAddress).count() == 0
    assert db.query(TrafficDeviceMonitoring).count() == 0
    assert db.query(HardwareAsset).count() == 0
    assert db.query(AssetNetworkAssignment).count() == 0


def test_only_local_original_endpoints_are_counted_never_translated_addresses(db):
    nsel, _ = _setup(db)
    _ingest(
        db, nsel,
        # Public original source NATed to a local address: the translated address is never counted.
        _record(nsel.id, source_ip="203.0.113.5", destination_ip=REMOTE, translated_source="192.0.2.50", sequence=1),
        # Local original source with a translated public address: counted on the original only.
        _record(nsel.id, source_ip="192.0.2.51", destination_ip=REMOTE, translated_source="203.0.113.9", sequence=2),
    )
    assert _usage(db, "192.0.2.50") == {}
    assert _usage(db, "203.0.113.9") == {}
    assert _usage(db, "203.0.113.5") == {} and _usage(db, REMOTE) == {}
    assert _usage(db, "192.0.2.51") == {"upload": 1000, "download": 4000}


def test_disabled_network_traffic_or_no_local_networks_records_nothing(db):
    nsel, _ = _setup(db, enabled=False)
    _ingest(db, nsel, _record(nsel.id))
    assert db.query(TrafficEndpointAggregate).count() == 0
    db.get(TrafficMonitoringConfiguration, 1).is_enabled = True
    db.query(TrafficLocalNetwork).update({"is_enabled": False})
    db.commit()
    _ingest(db, nsel, _record(nsel.id, sequence=2))
    assert db.query(TrafficEndpointAggregate).count() == 0


# ----------------------------------------------------------------- directions and duplicates


def test_initiator_responder_and_internal_to_internal_directions(db):
    nsel, _ = _setup(db)
    _ingest(
        db, nsel,
        _record(nsel.id, source_ip="192.0.2.10", destination_ip=REMOTE, forward=100, reverse=900, sequence=1),  # initiator
        _record(nsel.id, source_ip=REMOTE, destination_ip="192.0.2.10", forward=30, reverse=70, sequence=2),    # responder
        _record(nsel.id, source_ip="192.0.2.10", destination_ip="192.0.2.20", forward=5, reverse=7, sequence=3),  # LAN to LAN
    )
    assert _usage(db, "192.0.2.10") == {"upload": 100 + 70 + 5, "download": 900 + 30 + 7}
    # The LAN peer's own share of the conversation, mirrored.
    assert _usage(db, "192.0.2.20") == {"upload": 7, "download": 5}


def test_unidirectional_netflow_is_source_upload_and_destination_download(db):
    _, netflow = _setup(db)
    _ingest(db, netflow, _record(netflow.id, source_ip="192.0.2.10", destination_ip=REMOTE, forward=1234, directional=False, sequence=1))
    _ingest(db, netflow, _record(netflow.id, source_ip=REMOTE, destination_ip="192.0.2.10", forward=4321, directional=False, sequence=2))
    assert _usage(db, "192.0.2.10") == {"upload": 1234, "download": 4321}


def test_replayed_flows_are_counted_once(db):
    nsel, _ = _setup(db)
    record = _record(nsel.id)
    first = _ingest(db, nsel, record, record)  # duplicated within one datagram
    second = _ingest(db, nsel, record)         # replayed in a later datagram
    assert (first["accepted"], first["duplicates"], second["duplicates"]) == (1, 1, 1)
    assert _usage(db, "192.0.2.10") == {"upload": 1000, "download": 4000}
    assert db.query(TrafficFlowDeduplication).count() == 1


def test_sources_and_exporters_stay_separate(db):
    nsel, netflow = _setup(db)
    _ingest(db, nsel, _record(nsel.id, sequence=1), _record(nsel.id, exporter="192.0.2.2", sequence=2))
    _ingest(db, netflow, _record(netflow.id, directional=False, forward=50, sequence=3))
    assert _usage(db, "192.0.2.10", source_id=nsel.id, exporter_identity=EXPORTER) == {"upload": 1000, "download": 4000}
    assert _usage(db, "192.0.2.10", source_id=nsel.id, exporter_identity="192.0.2.2") == {"upload": 1000, "download": 4000}
    assert _usage(db, "192.0.2.10", source_id=netflow.id) == {"upload": 50}


def test_every_resolution_holds_the_same_total_once(db):
    nsel, _ = _setup(db)
    _ingest(db, nsel, *[_record(nsel.id, at=NOW - timedelta(minutes=55 - 5 * index), sequence=index) for index in range(10)])
    five_minute = _usage(db, "192.0.2.10", seconds=300)
    assert five_minute == {"upload": 10_000, "download": 40_000}
    assert _usage(db, "192.0.2.10", seconds=3600) == five_minute
    assert _usage(db, "192.0.2.10", seconds=86400) == five_minute
    assert db.query(TrafficEndpointAggregate).filter_by(endpoint_ip="192.0.2.10", bucket_seconds=300).count() == 20


def test_monitoring_preference_never_changes_observed_usage(db):
    from app.services.device_traffic import set_asset_monitoring

    nsel, _ = _setup(db)
    admin = _admin(db)
    asset = HardwareAsset(name="Synthetic tracked", status="In use")
    db.add(asset)
    db.flush()
    db.add(AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.10", address_family=4, source_id=nsel.id, exporter_identity=EXPORTER, started_at=NOW - timedelta(days=1), provenance="synthetic", status="confirmed"))
    db.commit()
    _ingest(db, nsel, _record(nsel.id, at=NOW - timedelta(hours=3), sequence=1))
    set_asset_monitoring(db, admin, asset, True, now=NOW - timedelta(hours=2))
    db.commit()
    _ingest(db, nsel, _record(nsel.id, at=NOW - timedelta(hours=1), sequence=2))
    set_asset_monitoring(db, admin, asset, False, now=NOW - timedelta(minutes=30))
    db.commit()
    _ingest(db, nsel, _record(nsel.id, at=NOW - timedelta(minutes=10), sequence=3))
    assert _usage(db, "192.0.2.10") == {"upload": 3000, "download": 12000}


# ----------------------------------------------------------------- reporting and identity


def test_device_usage_shows_unidentified_usage_and_reconciles_with_asset_profile(db):
    nsel, _ = _setup(db)
    admin = _admin(db)
    _ingest(db, nsel, _record(nsel.id, at=NOW - timedelta(hours=3), sequence=1), _record(nsel.id, at=NOW - timedelta(hours=1), forward=10, reverse=20, sequence=2))
    (row,) = [item for item in device_usage_report(db, admin, report_range="24h", now=NOW)["devices"] if item["address"] == "192.0.2.10"]
    assert (row["download_bytes"], row["upload_bytes"], row["identity_status"], row["usage_available"]) == (4020, 1010, "unidentified", True)
    # Explicit adoption with a confirmed assignment from two hours ago: the
    # profile gets only the usage inside that interval; Device Usage is unchanged.
    asset = HardwareAsset(name="Synthetic adopted", status="In use")
    db.add(asset)
    db.flush()
    db.add(AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.10", address_family=4, source_id=nsel.id, exporter_identity=EXPORTER, started_at=NOW - timedelta(hours=2), provenance="synthetic adoption", status="confirmed"))
    db.commit()
    (row,) = [item for item in device_usage_report(db, admin, report_range="24h", now=NOW)["devices"] if item["address"] == "192.0.2.10"]
    assert (row["download_bytes"], row["upload_bytes"], row["asset_name"], row["identity_whole_period"]) == (4020, 1010, "Synthetic adopted", False)
    traffic = asset_reporting_context(db, admin, asset.id, period="24h")["traffic"]
    assert (traffic["download_bytes"], traffic["upload_bytes"]) == (20, 10)


def test_dhcp_address_change_keeps_each_interval_with_its_owner(db):
    nsel, _ = _setup(db)
    admin = _admin(db)
    asset = HardwareAsset(name="Synthetic DHCP device", status="In use")
    other = HardwareAsset(name="Synthetic later occupant", status="In use")
    db.add_all([asset, other])
    db.flush()
    change = bucket_start(NOW - timedelta(hours=4), 300)
    db.add_all([
        AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.30", address_family=4, started_at=NOW - timedelta(days=1), ended_at=change, provenance="synthetic", status="confirmed"),
        AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.31", address_family=4, started_at=change, provenance="synthetic renewal", status="confirmed"),
        AssetNetworkAssignment(asset_id=other.id, address="192.0.2.30", address_family=4, started_at=change, provenance="synthetic reuse", status="confirmed"),
    ])
    db.commit()
    _ingest(
        db, nsel,
        _record(nsel.id, source_ip="192.0.2.30", at=NOW - timedelta(hours=6), forward=1, reverse=2, sequence=1),   # old IP, device
        _record(nsel.id, source_ip="192.0.2.30", at=NOW - timedelta(hours=2), forward=10, reverse=20, sequence=2),  # old IP, later occupant
        _record(nsel.id, source_ip="192.0.2.31", at=NOW - timedelta(hours=1), forward=100, reverse=200, sequence=3),  # new IP, device
    )
    device = asset_reporting_context(db, admin, asset.id, period="24h")["traffic"]
    later = asset_reporting_context(db, admin, other.id, period="24h")["traffic"]
    assert (device["download_bytes"], device["upload_bytes"]) == (2 + 200, 1 + 100)
    assert (later["download_bytes"], later["upload_bytes"]) == (20, 10)


def test_bucket_crossing_an_ip_handover_is_excluded(db):
    nsel, _ = _setup(db)
    admin = _admin(db)
    asset = HardwareAsset(name="Synthetic handover", status="In use")
    db.add(asset)
    db.flush()
    handover = bucket_start(NOW - timedelta(hours=1), 300) + timedelta(minutes=2)  # mid-bucket
    db.add(AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.40", address_family=4, started_at=handover, provenance="synthetic", status="confirmed"))
    db.commit()
    _ingest(db, nsel, _record(nsel.id, source_ip="192.0.2.40", at=handover + timedelta(minutes=1), sequence=1), _record(nsel.id, source_ip="192.0.2.40", at=handover + timedelta(minutes=30), forward=7, reverse=9, sequence=2))
    traffic = asset_reporting_context(db, admin, asset.id, period="24h")["traffic"]
    assert (traffic["download_bytes"], traffic["upload_bytes"], traffic["excluded_buckets"]) == (9, 7, 1)


def test_conflicting_permanent_identities_exclude_the_contested_buckets(db):
    nsel, _ = _setup(db)
    admin = _admin(db)
    first = HardwareAsset(name="Synthetic claimant one", status="In use")
    second = HardwareAsset(name="Synthetic claimant two", status="In use")
    db.add_all([first, second])
    db.flush()
    for asset in (first, second):
        db.add(AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.60", address_family=4, started_at=NOW - timedelta(days=1), provenance="synthetic", status="confirmed"))
    db.commit()
    _ingest(db, nsel, _record(nsel.id, source_ip="192.0.2.60"))
    for asset in (first, second):
        traffic = asset_reporting_context(db, admin, asset.id, period="24h")["traffic"]
        assert (traffic["download_bytes"], traffic["excluded_buckets"]) == (0, 1)
    (row,) = [item for item in device_usage_report(db, admin, report_range="24h", now=NOW)["devices"] if item["address"] == "192.0.2.60"]
    # Usage stays visible; two claimants leave the identity only "recognised".
    assert (row["download_bytes"], row["identity_status"], row["asset_url"]) == (4000, "suggested", None)


def test_pending_assignment_never_confirms_identity_or_attributes_usage(db):
    nsel, _ = _setup(db)
    admin = _admin(db)
    asset = HardwareAsset(name="Synthetic pending", status="In use")
    db.add(asset)
    db.flush()
    db.add(AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.70", address_family=4, started_at=NOW - timedelta(days=1), provenance="synthetic proposal", status="pending"))
    db.commit()
    _ingest(db, nsel, _record(nsel.id, source_ip="192.0.2.70"))
    (row,) = [item for item in device_usage_report(db, admin, report_range="24h", now=NOW)["devices"] if item["address"] == "192.0.2.70"]
    assert (row["identity_status"], row["asset_url"], row["download_bytes"]) == ("suggested", None, 4000)
    traffic = asset_reporting_context(db, admin, asset.id, period="24h")["traffic"]
    # No confirmed assignment: totals are unavailable, never reported as zero.
    assert (traffic["download_bytes"], traffic["upload_bytes"]) == (None, None)
    assert traffic["status"]["state"] == "no_assignment"


def test_missing_local_networks_is_reported_not_shown_as_zero_usage(db):
    """The DEV shape: exporter-to-VLAN mapping and discovery observations exist,
    but no local network, so no usage can be recorded. Device Usage must say so
    explicitly; mappings never become accounting eligibility."""
    from app.models.models import TrafficDiscoveryConfiguration, TrafficDiscoveryNetworkMapping, TrafficDiscoveryObservation, VLAN
    from app.services.network_discovery import persist_discovery_batch

    nsel, _ = _setup(db)
    db.query(TrafficLocalNetwork).delete()
    vlan = VLAN(name=f"Synthetic home {uuid.uuid4().hex[:6]}", subnet_cidr=LAN)
    db.add(vlan)
    if db.get(TrafficDiscoveryConfiguration, 1) is None:
        db.add(TrafficDiscoveryConfiguration(id=1, is_enabled=True))
    db.flush()
    db.add(TrafficDiscoveryNetworkMapping(source_id=nsel.id, exporter_identity=EXPORTER, vlan_id=vlan.id, is_enabled=True))
    db.commit()
    admin = _admin(db)
    accepted = []
    process_records(db, [_record(nsel.id, source_ip="192.0.2.154")], source_id=nsel.id, accepted_records=accepted)
    persist_discovery_batch(db, nsel.id, accepted)
    db.commit()
    assert db.query(TrafficDiscoveryObservation).filter_by(endpoint_ip="192.0.2.154").count() >= 1
    assert db.query(TrafficEndpointAggregate).count() == 0
    report = device_usage_report(db, admin, report_range="24h", now=NOW)
    assert report["summary"]["accounting"] == {"ready": False, "reason": "no_local_networks", "enabled_local_networks": 0}
    (row,) = [item for item in report["devices"] if item["address"] == "192.0.2.154"]
    assert (row["usage_available"], row["download_bytes"]) == (False, None)
    # Configuring the supported setting records new flows (no backfill).
    db.add(TrafficLocalNetwork(name="Synthetic LAN", network_cidr=LAN, is_enabled=True))
    db.commit()
    process_records(db, [_record(nsel.id, source_ip="192.0.2.154", sequence=2)], source_id=nsel.id)
    db.commit()
    report = device_usage_report(db, admin, report_range="24h", now=NOW)
    assert report["summary"]["accounting"]["ready"] is True
    (row,) = [item for item in report["devices"] if item["address"] == "192.0.2.154"]
    assert (row["download_bytes"], row["upload_bytes"]) == (4000, 1000)


def test_disabled_network_traffic_is_reported(db):
    _setup(db, enabled=False)
    admin = _admin(db)
    assert device_usage_report(db, admin, report_range="24h", now=NOW)["summary"]["accounting"]["reason"] == "traffic_disabled"


@pytest.mark.parametrize("report_range", ["24h", "7d", "30d", "90d"])
def test_ranges_report_the_same_usage(db, report_range):
    nsel, _ = _setup(db)
    admin = _admin(db)
    _ingest(db, nsel, _record(nsel.id, at=NOW - timedelta(hours=3)))
    (row,) = [item for item in device_usage_report(db, admin, report_range=report_range, now=NOW)["devices"] if item["address"] == "192.0.2.10"]
    assert (row["download_bytes"], row["upload_bytes"]) == (4000, 1000)


def test_custom_range_excludes_usage_outside_the_window(db):
    nsel, _ = _setup(db)
    admin = _admin(db)
    _ingest(db, nsel, _record(nsel.id, at=NOW - timedelta(hours=8), sequence=1), _record(nsel.id, at=NOW - timedelta(hours=2), forward=1, reverse=2, sequence=2))
    start, end = (NOW - timedelta(hours=9)).strftime("%Y-%m-%dT%H:%M"), (NOW - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M")
    rows = [item for item in device_usage_report(db, admin, report_range="custom", start_text=start, end_text=end, now=NOW)["devices"] if item["address"] == "192.0.2.10"]
    assert [(row["download_bytes"], row["upload_bytes"]) for row in rows] == [(4000, 1000)]


def test_profile_without_network_traffic_access_exposes_no_usage(db):
    nsel, _ = _setup(db)
    viewer = User(email=f"synthetic-viewer-{uuid.uuid4().hex[:6]}@example.invalid", password_hash="x", role="viewer", is_active=True)
    asset = HardwareAsset(name="Synthetic private", status="In use")
    db.add_all([viewer, asset])
    db.commit()
    _ingest(db, nsel, _record(nsel.id))
    assert asset_reporting_context(db, viewer, asset.id, period="24h")["traffic"] is None


# ----------------------------------------------------------------- retention


def test_retention_removes_each_tier_after_its_policy_and_is_idempotent(db):
    nsel, _ = _setup(db)
    _ingest(
        db, nsel,
        _record(nsel.id, at=NOW - timedelta(days=8), sequence=1),    # 5-minute row expired, hourly/daily kept
        _record(nsel.id, at=NOW - timedelta(days=100), sequence=2),  # hourly expired too
        _record(nsel.id, at=NOW - timedelta(days=400), sequence=3),  # everything expired
        _record(nsel.id, at=NOW - timedelta(hours=1), sequence=4),
    )
    cutoffs = retention_cutoffs(NOW, short_days=7, hourly_days=90, daily_days=365)
    removed = cleanup_endpoint_aggregates(db, cutoffs)
    db.commit()
    assert removed == 2 * (3 + 2 + 1)
    assert cleanup_endpoint_aggregates(db, cutoffs) == 0
    counts = {seconds: db.query(TrafficEndpointAggregate).filter_by(bucket_seconds=seconds).count() for seconds in (300, 3600, 86400)}
    assert counts == {300: 2, 3600: 4, 86400: 6}


# ----------------------------------------------------------------- concurrency


def test_postgres_concurrent_ingestion_sums_exactly():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=6, max_overflow=0)
    factory = sessionmaker(bind=engine)
    tag = uuid.uuid4().hex[:8]
    address = "192.0.2.222"
    with factory() as db:
        nsel, netflow = _setup(db, tag=tag)
        source_ids = [nsel.id, netflow.id]
        # The collector creates its per-source state once, under its write lock;
        # a warm-up packet does the same here so the race tested is the usage upsert.
        process_records(db, [_record(nsel.id, source_ip="192.0.2.223", sequence=999_999)], source_id=nsel.id)
        db.commit()
    errors = []

    def worker(thread_index):
        try:
            with factory() as db:
                source = db.get(TrafficSource, source_ids[0])
                for packet in range(20):
                    records = [_record(source.id, source_ip=address, at=NOW - timedelta(minutes=30), forward=10, reverse=20, sequence=thread_index * 1000 + packet * 10 + item) for item in range(5)]
                    process_records(db, records, source_id=source.id)
                    db.commit()
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(4)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        assert not errors
        with factory() as db:
            assert _usage(db, address, source_id=source_ids[0]) == {"upload": 4 * 20 * 5 * 10, "download": 4 * 20 * 5 * 20}
    finally:
        with factory() as db:
            db.query(TrafficEndpointAggregate).filter(TrafficEndpointAggregate.source_id.in_(source_ids)).delete(synchronize_session=False)
            db.query(TrafficFlowDeduplication).filter(TrafficFlowDeduplication.source_id.in_(source_ids)).delete(synchronize_session=False)
            db.query(TrafficFlowCollectorState).filter(TrafficFlowCollectorState.source_id.in_(source_ids)).delete(synchronize_session=False)
            for model in (TrafficFlowAggregate, TrafficFlowAccountingAggregate):
                db.query(model).filter(model.source_id.in_(source_ids)).delete(synchronize_session=False)
            db.query(TrafficSource).filter(TrafficSource.id.in_(source_ids)).delete(synchronize_session=False)
            db.commit()
        engine.dispose()
