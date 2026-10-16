"""Asset Profile automatic Network Traffic status versus optional device tracking.

The primary status must describe automatically attributed usage; optional
device tracking is secondary and clearly labelled. Uses the real flow pipeline
and the real Asset Profile route. All data is synthetic (RFC 5737 addresses,
example.invalid accounts).
"""

import os
import re
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

import app.routers.auth as auth
import app.routers.hardware_assets as hardware_assets
from app.core.csrf import CSRF_SESSION_KEY
from app.core.paths import STATIC_DIR
from app.db.session import Base, get_db
from app.models.models import (
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSProviderConfig,
    HardwareAsset,
    TrafficDeviceMonitoring,
    TrafficDiscoveryNetworkMapping,
    TrafficLocalNetwork,
    TrafficMonitoringConfiguration,
    TrafficSource,
    User,
    UserModulePermission,
    VLAN,
)
from app.services.asset_discovery import adopt_discovered_device, get_discovered_device
from app.services.asset_profile_reporting import asset_reporting_context
from app.services.device_traffic import asset_monitoring_status, set_asset_monitoring
from app.services.dns_insights import _persist_dhcp_leases
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord
from app.services.modules import grant_all_registered_modules

NOW = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
ADDRESS = "192.0.2.154"
EXPORTER = "192.0.2.1"


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


def _setup(db, *, enabled=True):
    config = db.get(TrafficMonitoringConfiguration, 1)
    if config is None:
        db.add(TrafficMonitoringConfiguration(id=1, is_enabled=True))
    else:
        config.is_enabled = True
    if not db.query(TrafficLocalNetwork).filter_by(network_cidr="192.0.2.0/24").first():
        db.add(TrafficLocalNetwork(name="Synthetic LAN", network_cidr="192.0.2.0/24", is_enabled=True))
    source = TrafficSource(name=f"Synthetic NSEL {uuid.uuid4().hex[:6]}", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False)
    db.add(source)
    db.commit()
    return source


def _set_collection(db, enabled):
    db.get(TrafficMonitoringConfiguration, 1).is_enabled = enabled
    db.commit()


def _record(source_id, *, at, sequence=1, forward=39_127_796, reverse=316_019):
    return NormalizedFlowRecord(
        exporter_identity=EXPORTER, source_id=source_id, sequence=sequence, record_index=0,
        observed_at=at, flow_start=None, flow_end=None, source_ip=ADDRESS, destination_ip="198.51.100.20",
        source_port=50000 + sequence, destination_port=443, protocol=6, input_interface=None, output_interface=None,
        translated_source_ip=None, translated_destination_ip=None, translated_source_port=None, translated_destination_port=None,
        bytes_total=forward + reverse, packets_total=4, direction="unknown", event_type=None, connection_id=None,
        cumulative_counters=False, data_quality="complete",
        forward_bytes=forward, reverse_bytes=reverse, forward_packets=2, reverse_packets=2,
    )


def _ingest(db, source, *records):
    process_records(db, list(records), source_id=source.id)
    db.commit()


def _user(db, role="admin", *, grant=True):
    user = User(email=f"synthetic-{role}-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role=role, is_active=True)
    db.add(user)
    db.flush()
    if grant:
        grant_all_registered_modules(db, user)
    db.commit()
    return user


def _asset(db, source=None, *, name="Synthetic doorbell", address=ADDRESS, scoped=True):
    asset = HardwareAsset(name=f"{name} {uuid.uuid4().hex[:6]}", status="In use")
    db.add(asset)
    db.flush()
    db.add(AssetNetworkAssignment(
        asset_id=asset.id, address=address, address_family=4, started_at=NOW - timedelta(days=2),
        source_id=source.id if (source and scoped) else None, exporter_identity=EXPORTER if (source and scoped) else None,
        provenance="synthetic confirmation", status="confirmed",
    ))
    db.commit()
    return asset


def _traffic(db, user, asset):
    return asset_reporting_context(db, user, asset.id, period="24h")["traffic"]


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr(auth, "current_user", lambda request, db=None: db.get(User, request.session.get("user_id")) if request.session.get("user_id") else None)
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="synthetic-test-session-key-0123456789")

    @app.get("/test-login/{user_id}")
    def _login(user_id: int, request: Request):
        request.session["user_id"] = user_id
        request.session[CSRF_SESSION_KEY] = "synthetic-csrf-token"
        return {"ok": True}

    @app.get("/manifest.webmanifest", name="manifest")
    def _manifest():
        return {}

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(hardware_assets.router)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as test_client:
        yield test_client


def _page(client, user, asset):
    assert client.get(f"/test-login/{user.id}").status_code == 200
    response = client.get(f"/infrastructure/asset-manager/{asset.id}?tab=history")
    assert response.status_code == 200
    return response.text


def _statuses(html):
    return [re.sub(r"\s+", " ", value).strip() for value in re.findall(r"data-asset-traffic-status>([^<]*)<", html)]


# --------------------------------------------------------------- 1. automatic traffic, tracking awaiting


def test_automatic_traffic_is_primary_while_optional_tracking_awaits_data(db, client):
    source = _setup(db)
    admin = _user(db)
    asset = _asset(db, source)
    _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=1)))
    set_asset_monitoring(db, admin, asset, True, now=datetime.utcnow())
    db.commit()
    assert asset_monitoring_status(db, asset.id)["status"] == "awaiting_data"

    traffic = _traffic(db, admin, asset)
    assert traffic["status"]["state"] == "recorded"
    assert (traffic["download_bytes"], traffic["upload_bytes"]) == (316_019, 39_127_796)

    html = _page(client, admin, asset)
    assert _statuses(html) == ["Traffic recorded in selected period"] * 2
    assert "Download 308.6 KiB · Upload 37.3 MiB" in html
    assert "Optional device tracking: Awaiting data" in html
    # The tracking state is never presented as the overall traffic status.
    assert '<span class="ad-cap">Device tracking</span>' not in html
    assert "Recording traffic" not in html
    # Times are presented through the site-timezone <time> helper, never as raw microseconds.
    visible = re.sub(r'data-utc-time="[^"]*"', '', html)
    assert not re.search(r"\d{2}:\d{2}:\d{2}\.\d{6}", visible)
    assert 'data-utc-time=' in html


# --------------------------------------------------------------- 2. automatic traffic, tracking disabled


def test_automatic_traffic_with_tracking_disabled(db, client):
    source = _setup(db)
    admin = _user(db)
    asset = _asset(db, source)
    _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=1)))
    traffic = _traffic(db, admin, asset)
    assert traffic["status"]["state"] == "recorded"
    html = _page(client, admin, asset)
    assert "Optional device tracking: Disabled" in html
    assert "Start device tracking" in html
    assert db.query(TrafficDeviceMonitoring).filter_by(asset_id=asset.id).count() == 0  # never auto-started


# --------------------------------------------------------------- 3. automatic and tracked traffic


def test_automatic_and_tracked_traffic_both_present(db, client):
    source = _setup(db)
    admin = _user(db)
    asset = _asset(db, source)
    set_asset_monitoring(db, admin, asset, True, now=NOW - timedelta(hours=3))
    db.commit()
    _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=1)))
    assert asset_monitoring_status(db, asset.id)["status"] == "active"
    traffic = _traffic(db, admin, asset)
    assert traffic["status"]["state"] == "recorded"
    html = _page(client, admin, asset)
    assert _statuses(html) == ["Traffic recorded in selected period"] * 2
    assert "Optional device tracking: Active" in html
    assert "Stop device tracking" in html


# --------------------------------------------------------------- 4. no measured traffic, tracking enabled


def test_no_measured_traffic_with_tracking_enabled(db, client):
    source = _setup(db)
    admin = _user(db)
    asset = _asset(db, source)
    set_asset_monitoring(db, admin, asset, True)
    db.commit()
    traffic = _traffic(db, admin, asset)
    assert traffic["status"]["state"] == "none"
    assert traffic["status"]["label"] == "No measured traffic in selected period"
    html = _page(client, admin, asset)
    assert _statuses(html) == ["No measured traffic in selected period"] * 2
    assert "Optional device tracking: Awaiting data" in html


# --------------------------------------------------------------- 5. no confirmed eligible assignment


def test_no_confirmed_assignment_never_reports_zero(db, client):
    source = _setup(db)
    admin = _user(db)
    asset = HardwareAsset(name="Synthetic unassigned", status="In use")
    db.add(asset)
    db.flush()
    db.add(AssetNetworkAssignment(asset_id=asset.id, address=ADDRESS, address_family=4, started_at=NOW - timedelta(days=1), provenance="synthetic proposal", status="pending"))
    db.commit()
    _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=1)))
    traffic = _traffic(db, admin, asset)
    assert traffic["status"]["state"] == "no_assignment"
    assert (traffic["download_bytes"], traffic["upload_bytes"]) == (None, None)
    html = _page(client, admin, asset)
    assert _statuses(html) == ["No confirmed network assignment"] * 2
    assert "0 B" not in html


# --------------------------------------------------------------- 6. historical traffic, no recent activity


def test_historical_traffic_is_not_described_as_live(db, client):
    source = _setup(db)
    admin = _user(db)
    asset = _asset(db, source)
    _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=20)))
    traffic = _traffic(db, admin, asset)
    assert traffic["status"]["label"] == "Traffic recorded in selected period"
    assert traffic["last_measured_at"] is not None
    assert datetime.fromisoformat(traffic["last_measured_at"]).replace(tzinfo=None) <= NOW - timedelta(hours=19)
    html = _page(client, admin, asset)
    assert "Latest measured interval" in html
    for claim in ("Recording traffic", "receiving", "Live"):
        assert claim not in html


# --------------------------------------------------------------- 7. ambiguous ownership


def test_ambiguous_ownership_buckets_are_excluded_not_attributed(db, client):
    source = _setup(db)
    admin = _user(db)
    asset = _asset(db, source)
    _asset(db, source, name="Synthetic competitor")
    _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=1)))
    traffic = _traffic(db, admin, asset)
    assert traffic["status"]["state"] == "ambiguous"
    assert traffic["excluded_buckets"] >= 1
    assert traffic["sources"] == []
    html = _page(client, admin, asset)
    assert _statuses(html) == ["No attributable traffic in selected period"] * 2
    assert "Excluded ambiguous buckets" in html


# --------------------------------------------------------------- 8. Network Traffic disabled


def test_network_traffic_collection_disabled_is_stated(db, client):
    source = _setup(db)
    admin = _user(db)
    asset = _asset(db, source)
    _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=1)))
    _set_collection(db, False)
    traffic = _traffic(db, admin, asset)
    assert traffic["status"]["collection_enabled"] is False
    assert traffic["status"]["state"] == "recorded"  # history stays visible
    html = _page(client, admin, asset)
    assert "Network Traffic collection is currently disabled." in html

    other = _asset(db, None, name="Synthetic quiet", address="192.0.2.200")
    quiet = _traffic(db, admin, other)
    assert quiet["status"]["state"] == "none"
    assert "collection is currently disabled" in quiet["status"]["detail"]


# --------------------------------------------------------------- 9. no Network Traffic permission


def test_user_without_network_traffic_permission_sees_no_usage(db, client):
    source = _setup(db)
    asset = _asset(db, source)
    _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=1)))
    viewer = _user(db, "viewer")
    db.query(UserModulePermission).filter_by(user_id=viewer.id, module_key="network_monitor").delete()
    db.commit()
    assert _traffic(db, viewer, asset) is None
    html = _page(client, viewer, asset)
    assert "Network Traffic access is not granted" in html
    assert _statuses(html) == []
    for leaked in ("37.3 MiB", "308.6 KiB", "39127796", "Optional device tracking:"):
        assert leaked not in html


# --------------------------------------------------------------- 10. header and reporting consistency


@pytest.mark.parametrize("scenario", ["recorded", "none", "no_assignment"])
def test_header_and_reporting_section_agree(db, client, scenario):
    source = _setup(db)
    admin = _user(db)
    if scenario == "no_assignment":
        asset = HardwareAsset(name="Synthetic bare", status="In use")
        db.add(asset)
        db.commit()
    else:
        asset = _asset(db, source)
    if scenario == "recorded":
        _ingest(db, source, _record(source.id, at=NOW - timedelta(hours=1)))
    html = _page(client, admin, asset)
    header, section = _statuses(html)
    assert header == section == _traffic(db, admin, asset)["status"]["label"]


# --------------------------------------------------------------- DHCP-bound source context


def test_confirmed_source_context_from_a_dhcp_assignment_ends_with_its_lease(db, client):
    source = _setup(db)
    admin = _user(db)
    provider = DNSProviderConfig(name=f"Synthetic Pi-hole {uuid.uuid4().hex[:6]}", base_url="https://dns.example.invalid", provider_type="pihole")
    vlan = VLAN(name=f"Synthetic LAN {uuid.uuid4().hex[:6]}", subnet_cidr="192.0.2.0/24")
    db.add_all([provider, vlan])
    db.flush()
    db.add(TrafficDiscoveryNetworkMapping(source_id=source.id, exporter_identity=EXPORTER, vlan_id=vlan.id, is_enabled=True))
    db.commit()
    mac = "02:00:5e:" + ":".join(uuid.uuid4().hex[i:i + 2] for i in (0, 2, 4))
    lease_item = {"ip": ADDRESS, "hwaddr": mac, "name": "synthetic-doorbell"}
    _persist_dhcp_leases(db, provider, {"leases": [lease_item]}, [], NOW - timedelta(hours=3))
    db.commit()
    lease = db.query(DHCPLeaseHistory).filter_by(provider_id=provider.id, ip_address=ADDRESS, is_active=True).one()
    asset = adopt_discovered_device(db, admin, get_discovered_device(db, f"dhcp:{lease.id}"), new_name="Synthetic DHCP doorbell")
    _persist_dhcp_leases(db, provider, {"leases": [lease_item]}, [], NOW - timedelta(hours=2))
    db.commit()

    assert client.get(f"/test-login/{admin.id}").status_code == 200
    response = client.post(
        f"/infrastructure/asset-manager/{asset.id}/network-assignment/source-context",
        data={"mapping_id": str(db.query(TrafficDiscoveryNetworkMapping).filter_by(source_id=source.id).one().id), "csrf_token": "synthetic-csrf-token"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    rows = db.query(AssetNetworkAssignment).filter_by(asset_id=asset.id).all()
    scoped = [row for row in rows if row.source_id == source.id]
    assert len(scoped) == 1 and scoped[0].dhcp_lease_id == lease.id

    _persist_dhcp_leases(db, provider, {"leases": []}, [], NOW - timedelta(hours=1))  # the lease ends
    db.commit()
    assert all(row.ended_at is not None for row in db.query(AssetNetworkAssignment).filter_by(asset_id=asset.id))
