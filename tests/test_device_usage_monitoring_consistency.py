"""Asset Manager monitoring and Network Traffic Device Usage must agree.

Reproduces the DEV defect where a doorbell-style asset held both a source-less
confirmed assignment and the administrator-confirmed source-scoped traffic
context for the same address: monitoring was enabled, but every flow was
dropped as ambiguous and Device Usage reported the endpoint as "Not monitored".
All data is synthetic (RFC 5737 addresses, example.invalid accounts).
"""

import os
import threading
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    AssetNetworkAssignment,
    AuditLog,
    DHCPLeaseHistory,
    HardwareAsset,
    IPAddress,
    TrafficDeviceAggregate,
    TrafficDeviceMonitoring,
    TrafficDeviceMonitoringPeriod,
    TrafficDiscoveryNetworkMapping,
    TrafficDiscoveryObservation,
    TrafficLocalNetwork,
    TrafficMonitoringConfiguration,
    TrafficSource,
    User,
    UserModulePermission,
    VLAN,
)
from app.services.asset_identity import assign_network_identity
from app.services.asset_profile_reporting import asset_reporting_context
from app.services.device_traffic import (
    ASSIGNMENT_CANDIDATE_LIMIT,
    asset_monitoring_status,
    endpoint_monitoring_states,
    persist_device_traffic,
    set_asset_monitoring,
    set_device_monitoring,
)
from app.services.endpoint_traffic import EndpointUsageBatch
from app.services.flow_protocol import NormalizedFlowRecord
from app.services.modules import grant_all_registered_modules
from app.services.network_traffic_reporting import device_report, device_usage_report

DOORBELL = "192.0.2.154"
EXPORTER = "192.0.2.1"
OTHER_EXPORTER = "192.0.2.2"
REMOTE = "198.51.100.20"
NOW = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
ENABLED_AT = NOW - timedelta(hours=10)


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


SOURCES = {}


def _flow(at, *, source_ip=DOORBELL, destination_ip=REMOTE, forward=1000, reverse=4000, source="firepower", exporter=EXPORTER, sequence=1):
    source_id = SOURCES[source]
    return NormalizedFlowRecord(
        exporter_identity=exporter, source_id=source_id, sequence=sequence, record_index=0,
        observed_at=at, flow_start=None, flow_end=None, source_ip=source_ip,
        destination_ip=destination_ip, source_port=50000, destination_port=443, protocol=6,
        input_interface=2, output_interface=10, translated_source_ip=None,
        translated_destination_ip=None, translated_source_port=None,
        translated_destination_port=None, bytes_total=forward + reverse, packets_total=4,
        direction="unknown", event_type=None, connection_id=None, cumulative_counters=False,
        data_quality="complete", forward_bytes=forward, reverse_bytes=reverse,
        forward_packets=2, reverse_packets=2,
    )


def _persist(db, record):
    """Mirror the flow pipeline: tracked-device attribution plus automatic
    observed-endpoint usage. Returns the tracked-device attribution count."""
    count = persist_device_traffic(db, record, record.bytes_total, record.packets_total, record.source_id)
    batch = EndpointUsageBatch(db)
    batch.add(record, record.bytes_total, record.packets_total, record.data_quality, record.source_id)
    batch.flush()
    db.commit()
    return count


def _observe(db, *, address=DOORBELL, source="firepower", exporter=EXPORTER, buckets=1, start=None):
    source_id = SOURCES[source]
    start = start or NOW - timedelta(minutes=5 * buckets)
    for index in range(buckets):
        at = start + timedelta(minutes=5 * index)
        db.add(TrafficDiscoveryObservation(
            source_id=source_id, exporter_identity=exporter, endpoint_ip=address, address_family=4,
            endpoint_role="original_source", classification="internal", confidence="high",
            bucket_start=at, bucket_seconds=300, observation_count=1, first_seen_at=at, last_seen_at=at,
        ))
    db.commit()


def doorbell_scenario(db, *, with_lease=True, with_source_less=True):
    """The DEV shape: a DHCP-identified doorbell adopted into Asset Manager, then
    given an administrator-confirmed Cisco source context for the same address."""
    admin = User(email="synthetic-admin@example.invalid", password_hash="x", role="admin", is_active=True)
    db.add(admin)
    db.flush()
    grant_all_registered_modules(db, admin)
    vlan = VLAN(name="Synthetic VLAN 1", subnet_cidr="192.0.2.0/24")
    asset = HardwareAsset(name="Synthetic doorbell", status="In use")
    firepower = TrafficSource(name="Synthetic Firepower consistency", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False)
    second = TrafficSource(name="Synthetic second exporter consistency", provider_key="netflow_v9", source_category="flow", is_enabled=True, is_deleted=False)
    db.add_all([vlan, asset, firepower, second])
    if not db.query(TrafficLocalNetwork).filter_by(network_cidr="192.0.2.0/24").first():
        db.add(TrafficLocalNetwork(name="Synthetic LAN", network_cidr="192.0.2.0/24", is_enabled=True))
    config = db.get(TrafficMonitoringConfiguration, 1)
    if config is None:
        db.add(TrafficMonitoringConfiguration(id=1, is_enabled=True))
    else:
        config.is_enabled = True
    db.flush()
    SOURCES.clear()
    SOURCES.update(firepower=firepower.id, second=second.id)
    if with_lease:
        db.add(DHCPLeaseHistory(ip_address=DOORBELL, mac_address="02:00:00:00:01:54", hostname="synthetic-doorbell", lease_started_at=NOW - timedelta(days=3)))
    if with_source_less:
        db.add(AssetNetworkAssignment(
            asset_id=asset.id, address=DOORBELL, address_family=4, vlan_id=vlan.id, network_cidr=vlan.subnet_cidr,
            started_at=NOW - timedelta(days=3), provenance="discovered_device_adoption", status="confirmed",
        ))
    db.commit()
    scoped = assign_network_identity(
        db, admin, asset_id=asset.id, address=DOORBELL, started_at=NOW - timedelta(days=2),
        vlan_id=vlan.id, source_id=firepower.id, exporter_identity=EXPORTER, provenance="administrator traffic context",
    )
    db.commit()
    return SimpleNamespace(admin=admin, asset=asset, vlan=vlan, scoped=scoped)


def _enable(db, scenario, at=ENABLED_AT):
    result = set_asset_monitoring(db, scenario.admin, scenario.asset, True, now=at)
    db.commit()
    return result


def _usage_row(db, user, address=DOORBELL, **kwargs):
    rows = [row for row in device_usage_report(db, user, report_range="24h", now=NOW, **kwargs)["devices"] if row["address"] == address]
    assert len(rows) <= 1, rows
    return rows[0] if rows else None


def _profile_traffic(db, user, asset_id):
    return asset_reporting_context(db, user, asset_id, period="24h")["traffic"]


def _profile_totals(db, user, asset_id):
    traffic = _profile_traffic(db, user, asset_id)
    return traffic["download_bytes"], traffic["upload_bytes"]


def _tracked_totals(db, **filters):
    """Totals of the optional tracked-device aggregates (legacy lifecycle)."""
    rows = db.query(TrafficDeviceAggregate).filter_by(bucket_seconds=300, **filters).all()
    return sum(r.bytes_total for r in rows if r.direction == "download"), sum(r.bytes_total for r in rows if r.direction == "upload")


# ----------------------------------------------------------------- root cause


def test_source_less_and_scoped_assignment_of_one_asset_no_longer_drops_traffic(db):
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    assert _persist(db, _flow(NOW - timedelta(hours=2))) == 1
    status = asset_monitoring_status(db, scenario.asset.id, now=NOW)
    assert status["status"] == "active"
    rows = db.query(TrafficDeviceAggregate).filter_by(bucket_seconds=300).all()
    assert {row.assignment_id for row in rows} == {scenario.scoped.id}
    # Initiator forward bytes are the doorbell's upload; reverse bytes its download.
    assert {row.direction: row.bytes_total for row in rows} == {"upload": 1000, "download": 4000}


def test_assignments_of_different_assets_for_the_same_address_fail_closed(db):
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    intruder = HardwareAsset(name="Synthetic conflicting asset", status="In use")
    db.add(intruder)
    db.flush()
    db.add(AssetNetworkAssignment(
        asset_id=intruder.id, address=DOORBELL, address_family=4, started_at=NOW - timedelta(days=1),
        provenance="synthetic conflict", status="confirmed",
    ))
    db.commit()
    assert _persist(db, _flow(NOW - timedelta(hours=2))) == 0
    assert db.query(TrafficDeviceAggregate).count() == 0


# ----------------------------------------------------------------- reconciliation


def test_eligible_traffic_reconciles_between_device_usage_and_asset_profile(db):
    scenario = doorbell_scenario(db)
    _persist(db, _flow(ENABLED_AT - timedelta(hours=3), sequence=1))  # before activation
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=6), forward=1500, reverse=6000, sequence=2))
    _persist(db, _flow(NOW - timedelta(hours=3), source_ip=REMOTE, destination_ip=DOORBELL, forward=700, reverse=300, sequence=3))
    _persist(db, _flow(NOW - timedelta(hours=2), source="second", exporter=OTHER_EXPORTER, sequence=4))  # other source
    _observe(db, buckets=3)

    rows = {row["source_breakdown"][0]["source"]: row for row in _rows(db, scenario.admin)}
    firepower, second = rows["Synthetic Firepower consistency"], rows["Synthetic second exporter consistency"]
    assert (firepower["monitoring_status"], firepower["identity_status"]) == ("monitored", "confirmed")
    assert firepower["asset_url"] == f"/infrastructure/asset-manager/{scenario.asset.id}"
    # Observed usage is automatic, including before tracking was enabled. As
    # initiator the doorbell uploads forward and downloads reverse bytes; as
    # responder reverse 300 is its upload and forward 700 its download.
    assert (firepower["download_bytes"], firepower["upload_bytes"]) == (4000 + 6000 + 700, 1000 + 1500 + 300)
    # The other exporter is its own context, never added to the Firepower row.
    assert (second["download_bytes"], second["upload_bytes"], second["separate_source_observation"]) == (4000, 1000, True)
    summary = device_usage_report(db, scenario.admin, report_range="24h", now=NOW)["summary"]
    assert (summary["overlapping_sources"], summary["download_bytes"]) == (True, None)
    # The source-less adoption assignment covers both contexts: the profile
    # reports per-source totals rather than a sum that could double count.
    traffic = _profile_traffic(db, scenario.admin, scenario.asset.id)
    assert traffic["multiple_sources"] is True and traffic["download_bytes"] is None
    assert {(item["source"], item["download_bytes"], item["upload_bytes"]) for item in traffic["sources"]} == {
        ("Synthetic Firepower consistency", 10700, 2800), ("Synthetic second exporter consistency", 4000, 1000),
    }
    # Optional device tracking keeps its own lifecycle: only post-activation,
    # in-scope traffic, and nothing from the other exporter.
    assert _tracked_totals(db) == (6700, 1800)
    assert db.query(TrafficDeviceAggregate).filter(TrafficDeviceAggregate.source_id == SOURCES["second"]).count() == 0


def test_traffic_after_ip_reassignment_is_not_attributed_to_the_previous_owner(db):
    scenario = doorbell_scenario(db, with_lease=False)
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=8), sequence=1))
    handover = NOW - timedelta(hours=5)
    for assignment in db.query(AssetNetworkAssignment).filter_by(asset_id=scenario.asset.id).all():
        assignment.ended_at = handover
    newcomer = HardwareAsset(name="Synthetic new owner", status="In use")
    db.add(newcomer)
    db.flush()
    db.add(AssetNetworkAssignment(
        asset_id=newcomer.id, address=DOORBELL, address_family=4, source_id=SOURCES["firepower"], exporter_identity=EXPORTER,
        started_at=handover, provenance="synthetic reassignment", status="confirmed",
    ))
    db.commit()
    assert _persist(db, _flow(NOW - timedelta(hours=2), sequence=2)) == 0
    assert _profile_totals(db, scenario.admin, scenario.asset.id) == (4000, 1000)


# ----------------------------------------------------------------- monitoring state


def test_enabled_monitor_without_eligible_aggregates_is_awaiting_data_not_unmonitored(db):
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    _observe(db, buckets=2)
    row = _usage_row(db, scenario.admin)
    assert row["monitoring_status"] == "awaiting_data"
    assert row["download_bytes"] is None
    assert asset_monitoring_status(db, scenario.asset.id, now=NOW)["status"] == "awaiting_data"


def test_disabled_monitor_is_not_monitored_and_preserves_its_period(db):
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=6)))
    set_asset_monitoring(db, scenario.admin, scenario.asset, False, now=NOW - timedelta(hours=4))
    db.commit()
    assert _persist(db, _flow(NOW - timedelta(hours=2), sequence=2)) == 0  # expired period
    _observe(db)
    assert _usage_row(db, scenario.admin)["monitoring_status"] == "not_monitored"
    period = db.query(TrafficDeviceMonitoringPeriod).one()
    assert period.ended_at == NOW - timedelta(hours=4)
    assert db.query(TrafficDeviceAggregate).filter_by(period_id=period.id, bucket_seconds=300).count() == 2


def test_changed_vlan_context_is_review_required_in_both_views(db):
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    scenario.vlan.subnet_cidr = "198.51.100.0/24"
    db.commit()
    _observe(db)
    assert asset_monitoring_status(db, scenario.asset.id, now=NOW)["status"] == "review_required"
    assert _usage_row(db, scenario.admin)["monitoring_status"] == "review_required"


def test_monitor_state_is_source_scoped(db):
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    firepower, second = SOURCES["firepower"], SOURCES["second"]
    states = endpoint_monitoring_states(db, {(firepower, EXPORTER, DOORBELL), (second, OTHER_EXPORTER, DOORBELL)}, now=NOW)
    assert set(states) == {(firepower, EXPORTER, DOORBELL)}


# ----------------------------------------------------------------- managed IP


def _managed_ip(db, address="192.0.2.60"):
    vlan = VLAN(name=f"Synthetic VLAN {address}", subnet_cidr="192.0.2.0/24")
    db.add(vlan)
    db.flush()
    ip = IPAddress(address=address, vlan_id=vlan.id, name="synthetic-managed", assignment_type="Static")
    db.add(ip)
    db.flush()
    return ip


def test_legacy_managed_ip_monitoring_still_reports(db):
    scenario = doorbell_scenario(db)
    ip = _managed_ip(db)
    set_device_monitoring(db, ip, True, now=ENABLED_AT)
    db.commit()
    _persist(db, _flow(NOW - timedelta(hours=2), source_ip=ip.address))
    rows = [row for row in device_report(db, report_range="24h", now=NOW)["devices"] if row["address"] == ip.address]
    assert [(row["download_bytes"], row["upload_bytes"]) for row in rows] == [(4000, 1000)]
    assert _usage_row(db, scenario.admin, address=ip.address)["monitoring_status"] == "monitored"


def test_assignment_with_managed_ip_is_counted_once_when_legacy_monitoring_is_also_enabled(db):
    scenario = doorbell_scenario(db, with_lease=False, with_source_less=False)
    ip = _managed_ip(db)
    asset = HardwareAsset(name="Synthetic camera", status="In use")
    db.add(asset)
    db.flush()
    db.add(AssetNetworkAssignment(
        asset_id=asset.id, address=ip.address, address_family=4, vlan_id=ip.vlan_id, network_cidr="192.0.2.0/24",
        ip_address_id=ip.id, source_id=SOURCES["firepower"], exporter_identity=EXPORTER, started_at=NOW - timedelta(days=1),
        provenance="synthetic", status="confirmed",
    ))
    db.commit()
    set_asset_monitoring(db, scenario.admin, asset, True, now=ENABLED_AT)
    db.commit()
    _persist(db, _flow(NOW - timedelta(hours=6), source_ip=ip.address))
    set_device_monitoring(db, ip, True, now=NOW - timedelta(hours=4))
    db.commit()
    rows = [row for row in device_report(db, report_range="24h", now=NOW)["devices"] if row["address"] == ip.address]
    assert sum(row["total_bytes"] for row in rows) == 5000


# ----------------------------------------------------------------- coverage and filters


def test_observed_share_counts_buckets_in_the_report_window(db):
    scenario = doorbell_scenario(db)
    _observe(db, buckets=176, start=NOW - timedelta(hours=24))
    assert _usage_row(db, scenario.admin)["coverage_percent"] == 61  # 176 of 288 five-minute buckets
    seven_day = [row for row in device_usage_report(db, scenario.admin, report_range="7d", now=NOW)["devices"] if row["address"] == DOORBELL][0]
    assert seven_day["coverage_percent"] == 9  # 15 hourly buckets of 168


def test_custom_historical_range_excludes_traffic_outside_the_window(db):
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=8), sequence=1))
    _persist(db, _flow(NOW - timedelta(hours=2), forward=10, reverse=20, sequence=2))
    start = (NOW - timedelta(hours=9)).isoformat() + "Z"
    end = (NOW - timedelta(hours=5)).isoformat() + "Z"
    rows = [row for row in device_usage_report(db, scenario.admin, report_range="custom", start_text=start, end_text=end, now=NOW)["devices"] if row["address"] == DOORBELL]
    assert [(row["download_bytes"], row["upload_bytes"]) for row in rows] == [(4000, 1000)]


def test_identity_link_requires_asset_manager_access(db):
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=2)))
    viewer = User(email="synthetic-viewer@example.invalid", password_hash="x", role="viewer", is_active=True)
    db.add(viewer)
    db.flush()
    grant_all_registered_modules(db, viewer)
    db.query(UserModulePermission).filter_by(user_id=viewer.id, module_key="asset_manager").update({"allowed": False})
    db.commit()
    row = _usage_row(db, viewer)
    assert row["monitoring_status"] == "monitored"
    assert row["asset_url"] is None and row["asset_name"] is None


# ----------------------------------------------------------------- mutation route


def _request(token):
    return SimpleNamespace(session={"csrf_token": token}, headers={}, client=SimpleNamespace(host="127.0.0.1"), url=SimpleNamespace(path="/x"), state=SimpleNamespace())


def test_monitoring_route_requires_csrf_and_audits_once(db):
    from app.routers.hardware_assets import update_asset_network_monitoring

    scenario = doorbell_scenario(db)
    with pytest.raises(HTTPException) as failure:
        update_asset_network_monitoring(_request("expected-fake-token"), scenario.asset.id, "1", "wrong-fake-token", db, scenario.admin)
    assert failure.value.status_code == 400
    assert db.query(TrafficDeviceMonitoring).count() == 0
    response = update_asset_network_monitoring(_request("expected-fake-token"), scenario.asset.id, "1", "expected-fake-token", db, scenario.admin)
    assert response.status_code == 303
    assert db.query(TrafficDeviceMonitoring).filter_by(asset_id=scenario.asset.id, is_enabled=True).count() == 1
    assert db.query(AuditLog).filter_by(entity="traffic_device_monitoring").count() == 1


def test_monitoring_mutation_is_administrator_only(db):
    scenario = doorbell_scenario(db)
    viewer = User(email="synthetic-viewer@example.invalid", password_hash="x", role="viewer", is_active=True)
    db.add(viewer)
    db.commit()
    with pytest.raises(PermissionError):
        set_asset_monitoring(db, viewer, scenario.asset, True, now=ENABLED_AT)
    assert db.query(TrafficDeviceMonitoring).count() == 0


# ----------------------------------------------------------------- PostgreSQL


@pytest.fixture()
def postgres_db():
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


@pytest.fixture(params=["sqlite", "postgresql"])
def any_db(request):
    if request.param == "sqlite":
        yield request.getfixturevalue("db")
    else:
        yield request.getfixturevalue("postgres_db")


def _rows(db, user, address=DOORBELL, report_range="24h"):
    return [row for row in device_usage_report(db, user, report_range=report_range, now=NOW)["devices"] if row["address"] == address]


def _map_exporter(db, vlan, *, source="firepower", exporter=EXPORTER):
    db.add(TrafficDiscoveryNetworkMapping(source_id=SOURCES[source], exporter_identity=exporter, vlan_id=vlan.id, is_enabled=True))
    db.commit()


def _end_assignments(db, asset_id, at):
    for assignment in db.query(AssetNetworkAssignment).filter_by(asset_id=asset_id).all():
        assignment.ended_at = at
    db.commit()


# ----------------------------------------------------------------- VLAN context


def test_vlan_from_confirmed_assignment_on_unmonitored_row_matches_asset_profile(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    _observe(db)
    row = _usage_row(db, scenario.admin)
    assert (row["monitoring_status"], row["vlan"], row["vlan_status"]) == ("not_monitored", "Synthetic VLAN 1", "confirmed")
    # Asset Profile renders the confirmed assignment's VLAN name.
    assert scenario.scoped.vlan.name == row["vlan"]
    _enable(db, scenario)
    assert (_usage_row(db, scenario.admin)["vlan"], _usage_row(db, scenario.admin)["monitoring_status"]) == ("Synthetic VLAN 1", "awaiting_data")
    _persist(db, _flow(NOW - timedelta(hours=1)))
    assert (_usage_row(db, scenario.admin)["vlan"], _usage_row(db, scenario.admin)["monitoring_status"]) == ("Synthetic VLAN 1", "monitored")


def test_vlan_is_never_inferred_from_the_address_alone(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    _observe(db, address="192.0.2.77")  # inside the VLAN CIDR, but no assignment or mapping
    row = _usage_row(db, scenario.admin, address="192.0.2.77")
    assert (row["vlan"], row["vlan_status"]) == (None, "unknown")


def test_vlan_from_exporter_mapping_is_source_and_exporter_scoped(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    _map_exporter(db, scenario.vlan)
    _observe(db, address="192.0.2.77")
    _observe(db, address="192.0.2.77", source="second", exporter=OTHER_EXPORTER)
    rows = {tuple(entry["source"] for entry in row["source_breakdown"]): row for row in _rows(db, scenario.admin, address="192.0.2.77")}
    assert (rows[("Synthetic Firepower consistency",)]["vlan"], rows[("Synthetic Firepower consistency",)]["vlan_status"]) == ("Synthetic VLAN 1", "confirmed")
    # The other exporter has no mapping: the same address stays unknown there.
    assert (rows[("Synthetic second exporter consistency",)]["vlan"], rows[("Synthetic second exporter consistency",)]["vlan_status"]) == (None, "unknown")


def test_stale_vlan_context_is_not_displayed(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    scenario.vlan.subnet_cidr = "198.51.100.0/24"
    db.commit()
    _observe(db)
    row = _usage_row(db, scenario.admin)
    assert (row["vlan"], row["vlan_status"]) == (None, "stale")


def test_conflicting_vlan_evidence_is_unresolved(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    other = VLAN(name="Synthetic overlapping VLAN", subnet_cidr="192.0.2.128/25")
    db.add(other)
    db.commit()
    _map_exporter(db, other)  # exporter says VLAN B; the confirmed assignment says VLAN 1
    _observe(db)
    row = _usage_row(db, scenario.admin)
    assert (row["vlan"], row["vlan_status"]) == (None, "conflicting")


# ----------------------------------------------------------------- multiple exporters


def test_secondary_source_without_usage_is_a_breakdown_of_the_measured_asset_row(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=6), forward=1500, reverse=6000, sequence=1))
    _persist(db, _flow(NOW - timedelta(hours=3), source_ip=REMOTE, destination_ip=DOORBELL, forward=700, reverse=300, sequence=2))
    _observe(db, buckets=3)
    _observe(db, source="second", exporter=OTHER_EXPORTER, buckets=2)
    rows = _rows(db, scenario.admin)
    assert len(rows) == 1
    row = rows[0]
    assert (row["monitoring_status"], row["download_bytes"], row["upload_bytes"]) == ("monitored", 6700, 1800)
    assert row["asset_url"] == f"/infrastructure/asset-manager/{scenario.asset.id}"
    assert [(entry["source"], entry["exporter_identity"], entry["usage"], entry["monitoring_status"]) for entry in row["source_breakdown"]] == [
        ("Synthetic Firepower consistency", EXPORTER, "measured", "monitored"),
        ("Synthetic second exporter consistency", OTHER_EXPORTER, "observed", "not_monitored"),
    ]
    assert row["source_breakdown"][1]["coverage_percent"] == 1  # 2 of 288 buckets
    # The second exporter observed the endpoint without byte data: no usage is invented.
    summary = device_usage_report(db, scenario.admin, report_range="24h", now=NOW)["summary"]
    assert (summary["download_bytes"], summary["upload_bytes"], summary["overlapping_sources"]) == (6700, 1800, False)
    assert _profile_totals(db, scenario.admin, scenario.asset.id) == (6700, 1800)


def test_unmonitored_asset_seen_by_two_sources_is_one_row_with_source_aware_status(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    _enable(db, scenario)  # monitor is scoped to the Firepower context only
    _observe(db)
    _observe(db, source="second", exporter=OTHER_EXPORTER)
    rows = _rows(db, scenario.admin)
    assert len(rows) == 1
    assert rows[0]["monitoring_status"] == "awaiting_data"
    assert {(entry["source"], entry["monitoring_status"]) for entry in rows[0]["source_breakdown"]} == {
        ("Synthetic Firepower consistency", "awaiting_data"),
        ("Synthetic second exporter consistency", "not_monitored"),
    }


def test_source_scoped_only_asset_keeps_other_exporter_as_labelled_separate_row(any_db):
    db = any_db
    scenario = doorbell_scenario(db, with_source_less=False)
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=2)))
    _observe(db)
    _observe(db, source="second", exporter=OTHER_EXPORTER)
    rows = sorted(_rows(db, scenario.admin), key=lambda row: row["monitoring_status"])
    # The other exporter may see a different device on the same address; no
    # confirmed evidence ties it to this asset, so it is not merged, and both
    # rows are labelled as separate source observations.
    assert [(row["monitoring_status"], row["total_bytes"], row["separate_source_observation"]) for row in rows] == [
        ("monitored", 5000, True), ("not_monitored", None, True),
    ]
    assert rows[1]["asset_url"] is None


def test_without_asset_manager_access_same_source_is_not_duplicated(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=2)))
    _observe(db)
    viewer = User(email="synthetic-viewer@example.invalid", password_hash="x", role="viewer", is_active=True)
    db.add(viewer)
    db.flush()
    grant_all_registered_modules(db, viewer)
    db.query(UserModulePermission).filter_by(user_id=viewer.id, module_key="asset_manager").update({"allowed": False})
    db.commit()
    rows = _rows(db, viewer)
    assert [(row["monitoring_status"], row["total_bytes"], row["asset_url"]) for row in rows] == [("monitored", 5000, None)]


# ----------------------------------------------------------------- status ownership


def test_previous_owner_monitor_never_labels_the_reassigned_address(any_db):
    db = any_db
    scenario = doorbell_scenario(db, with_lease=False)
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=8), sequence=1))
    handover = NOW - timedelta(hours=5)
    _end_assignments(db, scenario.asset.id, handover)  # old monitor record stays enabled
    newcomer = HardwareAsset(name="Synthetic new owner", status="In use")
    db.add(newcomer)
    db.flush()
    db.add(AssetNetworkAssignment(
        asset_id=newcomer.id, address=DOORBELL, address_family=4, vlan_id=scenario.vlan.id, network_cidr=scenario.vlan.subnet_cidr,
        source_id=SOURCES["firepower"], exporter_identity=EXPORTER, started_at=handover, provenance="synthetic reassignment", status="confirmed",
    ))
    db.commit()
    assert _persist(db, _flow(NOW - timedelta(hours=2), sequence=2)) == 0  # no tracked attribution
    _observe(db, buckets=2)
    # Device Usage reports the address: both occupants' usage, identified by the
    # current holder only, which is flagged as not holding it for the whole span.
    (row,) = _rows(db, scenario.admin)
    assert (row["download_bytes"], row["upload_bytes"]) == (8000, 2000)
    assert (row["asset_name"], row["identity_whole_period"], row["vlan"]) == ("Synthetic new owner", False, "Synthetic VLAN 1")
    # The previous owner's still-enabled monitor never labels the new occupant.
    assert row["monitoring_status"] == "not_monitored"
    # Each Asset Profile shows only traffic inside its own confirmed interval.
    assert _profile_totals(db, scenario.admin, scenario.asset.id) == (4000, 1000)
    assert _profile_totals(db, scenario.admin, newcomer.id) == (4000, 1000)
    assert asset_monitoring_status(db, scenario.asset.id, now=NOW)["status"] == "review_required"


def test_two_monitors_claiming_one_endpoint_are_review_required(any_db):
    db = any_db
    scenario = doorbell_scenario(db, with_source_less=False)
    _enable(db, scenario)
    rival = HardwareAsset(name="Synthetic rival", status="In use")
    db.add(rival)
    db.flush()
    rival_assignment = AssetNetworkAssignment(
        asset_id=rival.id, address=DOORBELL, address_family=4, source_id=SOURCES["firepower"], exporter_identity=None,
        started_at=NOW - timedelta(days=1), provenance="synthetic rival", status="confirmed",
    )
    db.add(rival_assignment)
    db.flush()
    db.add(TrafficDeviceMonitoring(asset_id=rival.id, assignment_id=rival_assignment.id, is_enabled=True, status="awaiting_data"))
    db.commit()
    key = (SOURCES["firepower"], EXPORTER, DOORBELL)
    state = endpoint_monitoring_states(db, [key], now=NOW, observed_at={key: NOW - timedelta(minutes=5)})[key]
    assert (state["status"], state["asset_id"]) == ("review_required", None)


# ----------------------------------------------------------------- candidate bound


def _extra_assignments(db, asset_id, count, *, provenance="synthetic extra"):
    for index in range(count):
        db.add(AssetNetworkAssignment(
            asset_id=asset_id, address=DOORBELL, address_family=4, started_at=NOW - timedelta(days=1, minutes=index),
            provenance=f"{provenance} {index}", status="confirmed",
        ))
    db.commit()


def test_conflicting_owner_beyond_the_candidate_bound_fails_closed(any_db):
    db = any_db
    scenario = doorbell_scenario(db)  # source-less + scoped
    _enable(db, scenario)
    _extra_assignments(db, scenario.asset.id, ASSIGNMENT_CANDIDATE_LIMIT)
    rival = HardwareAsset(name="Synthetic rival beyond bound", status="In use")
    db.add(rival)
    db.flush()
    db.add(AssetNetworkAssignment(asset_id=rival.id, address=DOORBELL, address_family=4, started_at=NOW - timedelta(days=1), provenance="synthetic rival", status="confirmed"))
    db.commit()
    assert _persist(db, _flow(NOW - timedelta(hours=2))) == 0
    assert _persist(db, _flow(NOW - timedelta(hours=1), source_ip=REMOTE, destination_ip=DOORBELL, sequence=2)) == 0
    assert db.query(TrafficDeviceAggregate).count() == 0


def test_more_candidates_than_the_bound_fail_closed_even_for_one_asset(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    _extra_assignments(db, scenario.asset.id, ASSIGNMENT_CANDIDATE_LIMIT - 1)  # 2 + 9 = 11 candidates
    assert _persist(db, _flow(NOW - timedelta(hours=2))) == 0


def test_candidates_at_the_bound_keep_scoped_precedence(any_db):
    db = any_db
    scenario = doorbell_scenario(db)
    _enable(db, scenario)
    _extra_assignments(db, scenario.asset.id, ASSIGNMENT_CANDIDATE_LIMIT - 2)  # exactly the bound
    assert _persist(db, _flow(NOW - timedelta(hours=2))) == 1
    assert {row.assignment_id for row in db.query(TrafficDeviceAggregate)} == {scenario.scoped.id}


def test_postgres_concurrent_conflicting_owner_never_receives_traffic():
    """Flows ingested while a conflicting owner is committed are either
    attributed to the original owner (before the conflict is visible) or
    dropped; never attributed to the newcomer, never double counted."""
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=4, max_overflow=0)
    factory = sessionmaker(bind=engine)
    tag = uuid.uuid4().hex[:8]
    created: dict[str, list[int]] = {"users": [], "assets": [], "sources": [], "vlans": []}
    try:
        with factory() as db:
            SOURCES.clear()
            admin = User(email=f"synthetic-race-{tag}@example.invalid", password_hash="x", role="admin", is_active=True)
            vlan = VLAN(name=f"Synthetic race VLAN {tag}", subnet_cidr="192.0.2.0/24")
            asset = HardwareAsset(name=f"Synthetic race owner {tag}", status="In use")
            rival = HardwareAsset(name=f"Synthetic race rival {tag}", status="In use")
            source = TrafficSource(name=f"Synthetic race source {tag}", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False)
            db.add_all([admin, vlan, asset, rival, source])
            if db.get(TrafficMonitoringConfiguration, 1) is None:
                db.add(TrafficMonitoringConfiguration(id=1, is_enabled=True))
            db.flush()
            created.update(users=[admin.id], assets=[asset.id, rival.id], sources=[source.id], vlans=[vlan.id])
            db.add(AssetNetworkAssignment(asset_id=asset.id, address=DOORBELL, address_family=4, vlan_id=vlan.id, network_cidr=vlan.subnet_cidr, source_id=source.id, exporter_identity=EXPORTER, started_at=NOW - timedelta(days=2), provenance="synthetic race", status="confirmed"))
            db.commit()
            set_asset_monitoring(db, admin, asset, True, now=ENABLED_AT)
            db.commit()
            SOURCES["firepower"] = source.id
            asset_id, rival_id = asset.id, rival.id
        barrier = threading.Barrier(2)
        attributed: list[int] = []

        def ingest():
            barrier.wait()
            with factory() as db:
                for sequence in range(40):
                    attributed.append(_persist(db, _flow(NOW - timedelta(hours=1), forward=10, reverse=20, sequence=sequence)))

        def conflict():
            barrier.wait()
            with factory() as db:
                db.add(AssetNetworkAssignment(asset_id=rival_id, address=DOORBELL, address_family=4, started_at=NOW - timedelta(days=1), provenance="synthetic race rival", status="confirmed"))
                db.commit()

        threads = [threading.Thread(target=ingest), threading.Thread(target=conflict)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        with factory() as db:
            rows = db.query(TrafficDeviceAggregate).filter(TrafficDeviceAggregate.asset_id.in_([asset_id, rival_id]), TrafficDeviceAggregate.bucket_seconds == 300).all()
            assert {row.asset_id for row in rows} <= {asset_id}
            assert sum(row.bytes_total for row in rows) == 30 * sum(attributed)
            assert _persist(db, _flow(NOW - timedelta(minutes=30), sequence=99)) == 0  # conflict now visible
    finally:
        with factory() as db:
            asset_ids = created["assets"] or [-1]
            monitor_ids = [row.id for row in db.query(TrafficDeviceMonitoring).filter(TrafficDeviceMonitoring.asset_id.in_(asset_ids))]
            db.query(TrafficDeviceAggregate).filter(TrafficDeviceAggregate.asset_id.in_(asset_ids)).delete(synchronize_session=False)
            db.query(TrafficDeviceMonitoringPeriod).filter(TrafficDeviceMonitoringPeriod.monitoring_id.in_(monitor_ids or [-1])).delete(synchronize_session=False)
            db.query(TrafficDeviceMonitoring).filter(TrafficDeviceMonitoring.id.in_(monitor_ids or [-1])).delete(synchronize_session=False)
            db.query(AuditLog).filter(AuditLog.user_id.in_(created["users"] or [-1])).delete(synchronize_session=False)
            db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.asset_id.in_(asset_ids)).delete(synchronize_session=False)
            db.query(UserModulePermission).filter(UserModulePermission.user_id.in_(created["users"] or [-1])).delete(synchronize_session=False)
            db.query(HardwareAsset).filter(HardwareAsset.id.in_(asset_ids)).delete(synchronize_session=False)
            db.query(TrafficSource).filter(TrafficSource.id.in_(created["sources"] or [-1])).delete(synchronize_session=False)
            db.query(VLAN).filter(VLAN.id.in_(created["vlans"] or [-1])).delete(synchronize_session=False)
            db.query(User).filter(User.id.in_(created["users"] or [-1])).delete(synchronize_session=False)
            db.commit()
        engine.dispose()


def test_postgres_doorbell_reconciliation(postgres_db):
    db = postgres_db
    scenario = doorbell_scenario(db)
    _persist(db, _flow(ENABLED_AT - timedelta(hours=3), sequence=1))
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=6), forward=1500, reverse=6000, sequence=2))
    _persist(db, _flow(NOW - timedelta(hours=2), source="second", exporter=OTHER_EXPORTER, sequence=3))
    _observe(db)
    rows = {row["source_breakdown"][0]["source"]: row for row in _rows(db, scenario.admin)}
    firepower = rows["Synthetic Firepower consistency"]
    assert firepower["monitoring_status"] == "monitored"
    # Observed usage includes the flow before tracking started; tracking does not.
    assert (firepower["download_bytes"], firepower["upload_bytes"]) == (10000, 2500)
    assert _tracked_totals(db) == (6000, 1500)
    profile = {item["source"]: (item["download_bytes"], item["upload_bytes"]) for item in _profile_traffic(db, scenario.admin, scenario.asset.id)["sources"]}
    assert profile["Synthetic Firepower consistency"] == (10000, 2500)
