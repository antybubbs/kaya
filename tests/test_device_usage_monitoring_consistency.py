"""Asset Manager monitoring and Network Traffic Device Usage must agree.

Reproduces the DEV defect where a doorbell-style asset held both a source-less
confirmed assignment and the administrator-confirmed source-scoped traffic
context for the same address: monitoring was enabled, but every flow was
dropped as ambiguous and Device Usage reported the endpoint as "Not monitored".
All data is synthetic (RFC 5737 addresses, example.invalid accounts).
"""

import os
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
    TrafficDiscoveryObservation,
    TrafficMonitoringConfiguration,
    TrafficSource,
    User,
    UserModulePermission,
    VLAN,
)
from app.services.asset_identity import assign_network_identity
from app.services.asset_profile_reporting import asset_reporting_context
from app.services.device_traffic import (
    asset_monitoring_status,
    endpoint_monitoring_states,
    persist_device_traffic,
    set_asset_monitoring,
    set_device_monitoring,
)
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
    count = persist_device_traffic(db, record, record.bytes_total, record.packets_total, record.source_id)
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


def _profile_totals(db, user, asset_id):
    traffic = asset_reporting_context(db, user, asset_id, period="24h")["traffic"]
    return traffic["download_bytes"], traffic["upload_bytes"]


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

    row = _usage_row(db, scenario.admin)
    assert row["monitoring_status"] == "monitored"
    assert row["identity_status"] == "confirmed"
    assert row["asset_url"] == f"/infrastructure/asset-manager/{scenario.asset.id}"
    # Doorbell as initiator: up 1500 / down 6000. As responder: reverse 300 is its
    # upload and forward 700 its download.
    assert (row["download_bytes"], row["upload_bytes"]) == (6700, 1800)
    assert _profile_totals(db, scenario.admin, scenario.asset.id) == (6700, 1800)
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


def test_postgres_doorbell_reconciliation(postgres_db):
    db = postgres_db
    scenario = doorbell_scenario(db)
    _persist(db, _flow(ENABLED_AT - timedelta(hours=3), sequence=1))
    _enable(db, scenario)
    _persist(db, _flow(NOW - timedelta(hours=6), forward=1500, reverse=6000, sequence=2))
    _persist(db, _flow(NOW - timedelta(hours=2), source="second", exporter=OTHER_EXPORTER, sequence=3))
    _observe(db)
    row = _usage_row(db, scenario.admin)
    assert row["monitoring_status"] == "monitored"
    assert (row["download_bytes"], row["upload_bytes"]) == (6000, 1500)
    assert _profile_totals(db, scenario.admin, scenario.asset.id) == (6000, 1500)
