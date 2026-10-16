"""Local-network administration for automatic per-IP traffic accounting.

Exercised through the real Network Traffic router: module gate, administrator
gate, session-bound CSRF validation and atomic audit. Only the session identity
lookup is stubbed. All data is synthetic (RFC 5737 / RFC 3849, example.invalid).
"""

import os
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

import app.routers.auth as auth
import app.routers.network_discovery as network_discovery
import app.routers.network_monitor as network_monitor
from app.core.csrf import CSRF_SESSION_KEY
from app.db.session import Base, get_db
from app.models.models import (
    AuditLog,
    HardwareAsset,
    IPAddress,
    TrafficDiscoveryNetworkMapping,
    TrafficEndpointAggregate,
    TrafficLocalNetwork,
    TrafficMonitoringConfiguration,
    TrafficSource,
    User,
    UserModulePermission,
    VLAN,
)
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord
from app.services.modules import grant_all_registered_modules
from app.services.network_traffic_reporting import device_usage_report

API = "/networking/ip-wan-monitor/traffic/local-networks"
CSRF = "synthetic-csrf-token"
NOW = datetime.utcnow().replace(second=0, microsecond=0)


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


@pytest.fixture()
def users(db):
    config = db.get(TrafficMonitoringConfiguration, 1)
    if config is None:
        db.add(TrafficMonitoringConfiguration(id=1, is_enabled=True))
    db.query(TrafficLocalNetwork).delete()
    tag = uuid.uuid4().hex[:8]
    admin = User(email=f"synthetic-admin-{tag}@example.invalid", password_hash="x", role="admin", is_active=True)
    viewer = User(email=f"synthetic-viewer-{tag}@example.invalid", password_hash="x", role="viewer", is_active=True)
    outsider = User(email=f"synthetic-outsider-{tag}@example.invalid", password_hash="x", role="viewer", is_active=True)
    db.add_all([admin, viewer, outsider])
    db.flush()
    grant_all_registered_modules(db, admin)
    grant_all_registered_modules(db, viewer)
    grant_all_registered_modules(db, outsider)
    db.query(UserModulePermission).filter_by(user_id=outsider.id, module_key="network_monitor").update({"allowed": False})
    db.commit()
    return {"admin": admin, "viewer": viewer, "outsider": outsider}


@pytest.fixture()
def client(db, users, monkeypatch):
    """The real Network Traffic router with session middleware and the app's
    PermissionError handling; only the session user lookup is stubbed."""
    monkeypatch.setattr(auth, "current_user", lambda request, db=None: db.get(User, request.session.get("user_id")) if request.session.get("user_id") else None)
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="synthetic-test-session-key-0123456789")

    @app.exception_handler(PermissionError)
    async def _forbidden(request: Request, exc: PermissionError):
        return PlainTextResponse("Forbidden", status_code=403)

    @app.get("/test-login/{user_id}")
    def _login(user_id: int, request: Request):
        request.session["user_id"] = user_id
        request.session[CSRF_SESSION_KEY] = CSRF
        return {"ok": True}

    app.include_router(network_monitor.router)
    app.include_router(network_discovery.router)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as test_client:
        yield test_client


def _login(client, user):
    assert client.get(f"/test-login/{user.id}").status_code == 200


def _post(client, cidr, name="Synthetic LAN", token=CSRF, confirm_broad=False):
    body = {"name": name, "network_cidr": cidr, **({"confirm_broad": True} if confirm_broad else {})}
    return client.post(API, json=body, headers={"x-csrf-token": token} if token else {})


def _audits(db, action=None):
    query = db.query(AuditLog).filter(AuditLog.entity == "traffic_local_network")
    return query.filter(AuditLog.action == action).count() if action else query.count()


def _record(source_id, address, *, sequence=1, exporter="192.0.2.1"):
    return NormalizedFlowRecord(
        exporter_identity=exporter, source_id=source_id, sequence=sequence, record_index=0, observed_at=NOW - timedelta(minutes=10),
        flow_start=None, flow_end=None, source_ip=address, destination_ip="198.51.100.40", source_port=50000 + sequence, destination_port=443,
        protocol=6, input_interface=None, output_interface=None, translated_source_ip=None, translated_destination_ip=None,
        translated_source_port=None, translated_destination_port=None, bytes_total=5000, packets_total=10, direction="unknown",
        event_type=None, connection_id=None, cumulative_counters=False, data_quality="complete",
        forward_bytes=1000, reverse_bytes=4000, forward_packets=4, reverse_packets=6,
    )


def _source(db, provider="cisco_nsel"):
    source = TrafficSource(name=f"Synthetic {provider} {uuid.uuid4().hex[:6]}", provider_key=provider, source_category="flow", is_enabled=True, is_deleted=False)
    db.add(source)
    db.commit()
    return source


# ----------------------------------------------------------------- configuration contract


def test_empty_configuration_lists_nothing_and_reports_not_ready(db, users, client):
    _login(client, users["admin"])
    assert client.get(API).json() == {"local_networks": []}
    summary = device_usage_report(db, users["admin"], report_range="24h", now=NOW)["summary"]
    assert summary["accounting"] == {"ready": False, "reason": "no_local_networks", "enabled_local_networks": 0}


def test_admin_adds_a_normalised_network_with_one_audit_event(db, users, client):
    _login(client, users["admin"])
    response = _post(client, "192.0.2.77/24", name="  Home LAN  ")
    assert response.status_code == 201
    assert response.json() == {"id": response.json()["id"], "name": "Home LAN", "network_cidr": "192.0.2.0/24", "is_enabled": True, "overlaps": [], "policy": {"allowed": True, "broad": False, "message": None}}
    assert _audits(db, "create") == 1
    assert device_usage_report(db, users["admin"], report_range="24h", now=NOW)["summary"]["accounting"]["ready"] is True


@pytest.mark.parametrize("cidr", ["not-a-network", "192.0.2.0/33", "300.1.1.0/24", "2001:db8::/129"])
def test_invalid_cidrs_are_rejected_without_changes(db, users, client, cidr):
    _login(client, users["admin"])
    assert _post(client, cidr).status_code == 400
    assert db.query(TrafficLocalNetwork).count() == 0 and _audits(db) == 0


def test_duplicate_network_is_rejected_even_with_different_host_bits(db, users, client):
    _login(client, users["admin"])
    assert _post(client, "192.0.2.0/24").status_code == 201
    assert _post(client, "192.0.2.200/24", name="Duplicate").status_code == 409
    assert db.query(TrafficLocalNetwork).count() == 1 and _audits(db, "create") == 1


def test_overlapping_networks_are_allowed_by_policy_and_reported(db, users, client):
    _login(client, users["admin"])
    assert _post(client, "192.0.2.0/24", name="LAN").status_code == 201
    assert _post(client, "192.0.2.128/25", name="Upper half").status_code == 201
    assert _post(client, "2001:db8:10::/64", name="IPv6 LAN").status_code == 201
    rows = {row["network_cidr"]: row for row in client.get(API).json()["local_networks"]}
    assert rows["192.0.2.0/24"]["overlaps"] == ["192.0.2.128/25"]
    assert rows["192.0.2.128/25"]["overlaps"] == ["192.0.2.0/24"]
    assert rows["2001:db8:10::/64"]["overlaps"] == []


def test_rename_and_disable_are_audited_and_disabled_networks_are_ineligible(db, users, client):
    _login(client, users["admin"])
    network_id = _post(client, "192.0.2.0/24").json()["id"]
    renamed = client.patch(f"{API}/{network_id}", json={"name": "Renamed LAN"}, headers={"x-csrf-token": CSRF})
    assert (renamed.status_code, renamed.json()["name"]) == (200, "Renamed LAN")
    disabled = client.patch(f"{API}/{network_id}", json={"is_enabled": False}, headers={"x-csrf-token": CSRF})
    assert (disabled.status_code, disabled.json()["is_enabled"]) == (200, False)
    assert _audits(db, "update") == 2
    # An unchanged update writes nothing.
    assert client.patch(f"{API}/{network_id}", json={"is_enabled": False}, headers={"x-csrf-token": CSRF}).status_code == 200
    assert _audits(db, "update") == 2
    assert client.patch(f"{API}/{network_id}", json={"name": "   "}, headers={"x-csrf-token": CSRF}).status_code == 400
    source = _source(db)
    process_records(db, [_record(source.id, "192.0.2.10")], source_id=source.id)
    db.commit()
    assert db.query(TrafficEndpointAggregate).count() == 0
    assert device_usage_report(db, users["admin"], report_range="24h", now=NOW)["summary"]["accounting"]["reason"] == "no_local_networks"


def test_removal_is_audited_and_keeps_recorded_usage(db, users, client):
    _login(client, users["admin"])
    network_id = _post(client, "192.0.2.0/24").json()["id"]
    source = _source(db)
    process_records(db, [_record(source.id, "192.0.2.10")], source_id=source.id)
    db.commit()
    recorded = db.query(TrafficEndpointAggregate).count()
    assert recorded == 6
    assert client.delete(f"{API}/{network_id}", headers={"x-csrf-token": CSRF}).json() == {"deleted": network_id}
    assert _audits(db, "delete") == 1
    assert db.query(TrafficEndpointAggregate).count() == recorded
    assert client.delete(f"{API}/{network_id}", headers={"x-csrf-token": CSRF}).status_code == 404


# ----------------------------------------------------------------- permissions, CSRF and audit


def test_read_only_user_can_view_but_not_change(db, users, client):
    _login(client, users["admin"])
    network_id = _post(client, "192.0.2.0/24").json()["id"]
    _login(client, users["viewer"])
    assert [row["network_cidr"] for row in client.get(API).json()["local_networks"]] == ["192.0.2.0/24"]
    assert _post(client, "198.51.100.0/24").status_code == 403
    assert client.patch(f"{API}/{network_id}", json={"is_enabled": False}, headers={"x-csrf-token": CSRF}).status_code == 403
    assert client.delete(f"{API}/{network_id}", headers={"x-csrf-token": CSRF}).status_code == 403
    assert db.query(TrafficLocalNetwork).count() == 1 and db.get(TrafficLocalNetwork, network_id).is_enabled is True


def test_users_without_network_traffic_access_are_denied(db, users, client):
    _login(client, users["outsider"])
    assert client.get(API).status_code == 403
    assert _post(client, "192.0.2.0/24").status_code == 403
    assert db.query(TrafficLocalNetwork).count() == 0


@pytest.mark.parametrize("token", [None, "wrong-synthetic-token"])
def test_missing_or_wrong_csrf_is_rejected_without_changes(db, users, client, token):
    _login(client, users["admin"])
    assert _post(client, "192.0.2.0/24", token=token).status_code == 400
    network_id = _post(client, "198.51.100.0/24").json()["id"]
    headers = {"x-csrf-token": token} if token else {}
    assert client.patch(f"{API}/{network_id}", json={"is_enabled": False}, headers=headers).status_code == 400
    assert client.delete(f"{API}/{network_id}", headers=headers).status_code == 400
    assert [row.network_cidr for row in db.query(TrafficLocalNetwork)] == ["198.51.100.0/24"]
    assert db.get(TrafficLocalNetwork, network_id).is_enabled is True
    assert _audits(db) == 1


def test_changes_roll_back_when_the_audit_event_cannot_be_written(db, users, client, monkeypatch):
    _login(client, users["admin"])
    network_id = _post(client, "192.0.2.0/24").json()["id"]
    monkeypatch.setattr(network_monitor, "write_audit", lambda *args, **kwargs: None)
    assert _post(client, "198.51.100.0/24").status_code == 500
    assert client.patch(f"{API}/{network_id}", json={"is_enabled": False}, headers={"x-csrf-token": CSRF}).status_code == 500
    assert client.delete(f"{API}/{network_id}", headers={"x-csrf-token": CSRF}).status_code == 500
    db.expire_all()
    assert [(row.network_cidr, row.is_enabled) for row in db.query(TrafficLocalNetwork)] == [("192.0.2.0/24", True)]


# ----------------------------------------------------------------- accounting effect


def test_dhcp_only_endpoint_is_accounted_after_a_local_network_is_configured(db, users, client):
    from app.models.models import DHCPLeaseHistory

    source = _source(db)
    db.add(DHCPLeaseHistory(ip_address="192.0.2.191", mac_address="02:00:00:00:01:91", hostname="synthetic-ring-garage", lease_started_at=NOW - timedelta(days=1)))
    db.commit()
    process_records(db, [_record(source.id, "192.0.2.191", sequence=1)], source_id=source.id)
    db.commit()
    assert db.query(TrafficEndpointAggregate).count() == 0  # not configured yet
    _login(client, users["admin"])
    assert _post(client, "192.0.2.0/24", name="Home LAN").status_code == 201
    process_records(db, [_record(source.id, "192.0.2.191", sequence=2)], source_id=source.id)
    db.commit()
    (row,) = [item for item in device_usage_report(db, users["admin"], report_range="24h", now=NOW)["devices"] if item["address"] == "192.0.2.191"]
    assert (row["download_bytes"], row["upload_bytes"], row["usage_available"]) == (4000, 1000, True)  # new flows only
    assert db.query(IPAddress).count() == 0 and db.query(HardwareAsset).count() == 0


def test_eligibility_is_independent_of_vlan_mappings_and_spans_sources(db, users, client):
    first, second = _source(db), _source(db, "netflow_v9")
    vlan = VLAN(name=f"Synthetic VLAN {uuid.uuid4().hex[:6]}", subnet_cidr="203.0.113.0/24")
    db.add(vlan)
    db.flush()
    # A mapping alone never makes an address eligible.
    db.add(TrafficDiscoveryNetworkMapping(source_id=first.id, exporter_identity="192.0.2.1", vlan_id=vlan.id, is_enabled=True))
    db.commit()
    process_records(db, [_record(first.id, "203.0.113.5", sequence=1)], source_id=first.id)
    db.commit()
    assert db.query(TrafficEndpointAggregate).count() == 0
    # A local network with no mapping is eligible for every source, each kept separate.
    _login(client, users["admin"])
    assert _post(client, "192.0.2.0/24").status_code == 201
    process_records(db, [_record(first.id, "192.0.2.10", sequence=2)], source_id=first.id)
    process_records(db, [_record(second.id, "192.0.2.10", sequence=3, exporter="192.0.2.2")], source_id=second.id)
    db.commit()
    assert {row.source_id for row in db.query(TrafficEndpointAggregate).filter_by(endpoint_ip="192.0.2.10")} == {first.id, second.id}
    assert db.query(TrafficEndpointAggregate).filter_by(endpoint_ip="203.0.113.5").count() == 0


# ----------------------------------------------------------------- breadth policy


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "10.0.0.0/7", "10.20.30.40/7", "::/0", "2001:db8::/31", "2001:db8:ffff::1/20"])
def test_ranges_broader_than_the_limits_are_rejected(db, users, client, cidr):
    _login(client, users["admin"])
    for confirm in (False, True):  # confirmation never bypasses the limit
        response = _post(client, cidr, confirm_broad=confirm)
        assert response.status_code == 400 and "too broad" in response.json()["detail"]
    assert db.query(TrafficLocalNetwork).count() == 0 and _audits(db) == 0


@pytest.mark.parametrize(("cidr", "normalised", "broad"), [
    ("10.0.0.0/8", "10.0.0.0/8", True), ("172.16.9.9/16", "172.16.0.0/16", False), ("192.0.2.0/24", "192.0.2.0/24", False),
    ("2001:db8::/32", "2001:db8::/32", True), ("2001:db8:1::/48", "2001:db8:1::/48", False), ("2001:db8:1:2::1/64", "2001:db8:1:2::/64", False),
])
def test_ranges_within_the_limits_are_accepted(db, users, client, cidr, normalised, broad):
    _login(client, users["admin"])
    response = _post(client, cidr, confirm_broad=broad)
    assert response.status_code == 201
    assert (response.json()["network_cidr"], response.json()["policy"]["broad"]) == (normalised, broad)


def test_broad_range_needs_explicit_confirmation(db, users, client):
    _login(client, users["admin"])
    unconfirmed = _post(client, "10.0.0.0/12")
    assert unconfirmed.status_code == 428 and "broad range" in unconfirmed.json()["detail"]
    assert db.query(TrafficLocalNetwork).count() == 0 and _audits(db) == 0
    assert _post(client, "10.0.0.0/12", confirm_broad=True).status_code == 201
    audit = db.query(AuditLog).filter(AuditLog.entity == "traffic_local_network").one()
    assert '"broad_confirmed":true' in audit.metadata_json


def test_existing_over_limit_networks_are_preserved_flagged_and_cannot_be_re_enabled(db, users, client):
    db.add_all([
        TrafficLocalNetwork(name="Legacy default route", network_cidr="0.0.0.0/0", is_enabled=True),
        TrafficLocalNetwork(name="Legacy broad disabled", network_cidr="10.0.0.0/7", is_enabled=False),
    ])
    db.commit()
    _login(client, users["admin"])
    rows = {row["network_cidr"]: row for row in client.get(API).json()["local_networks"]}
    assert rows["0.0.0.0/0"]["policy"]["allowed"] is False and "limit of /8" in rows["0.0.0.0/0"]["policy"]["message"]
    assert rows["0.0.0.0/0"]["is_enabled"] is True  # never changed automatically
    disabled_id = rows["10.0.0.0/7"]["id"]
    refused = client.patch(f"{API}/{disabled_id}", json={"is_enabled": True}, headers={"x-csrf-token": CSRF})
    assert refused.status_code == 400 and "cannot be re-enabled" in refused.json()["detail"]
    db.expire_all()
    assert db.get(TrafficLocalNetwork, disabled_id).is_enabled is False and _audits(db) == 0
    # Renaming, disabling and removing an over-limit range still work.
    enabled_id = rows["0.0.0.0/0"]["id"]
    assert client.patch(f"{API}/{enabled_id}", json={"name": "Legacy renamed"}, headers={"x-csrf-token": CSRF}).status_code == 200
    assert client.patch(f"{API}/{enabled_id}", json={"is_enabled": False}, headers={"x-csrf-token": CSRF}).status_code == 200
    assert client.delete(f"{API}/{disabled_id}", headers={"x-csrf-token": CSRF}).status_code == 200


def test_policy_mutations_keep_admin_csrf_and_atomic_audit(db, users, client, monkeypatch):
    _login(client, users["viewer"])
    assert _post(client, "10.0.0.0/8", confirm_broad=True).status_code == 403
    _login(client, users["admin"])
    assert _post(client, "10.0.0.0/8", confirm_broad=True, token="wrong-synthetic-token").status_code == 400
    monkeypatch.setattr(network_monitor, "write_audit", lambda *args, **kwargs: None)
    assert _post(client, "10.0.0.0/8", confirm_broad=True).status_code == 500
    db.expire_all()
    assert db.query(TrafficLocalNetwork).count() == 0


def test_vlan_and_exporter_mapping_validation_are_unchanged(db, users, client):
    source = _source(db)
    vlan = VLAN(name=f"Synthetic wide VLAN {uuid.uuid4().hex[:6]}", subnet_cidr="10.0.0.0/7")
    db.add(vlan)
    db.commit()
    _login(client, users["admin"])
    response = client.post("/api/network-discovery/network-mappings", json={"source_id": source.id, "exporter_identity": "192.0.2.1", "vlan_id": vlan.id, "is_enabled": True}, headers={"x-csrf-token": CSRF})
    assert response.status_code in (200, 201), response.text
    assert db.query(TrafficDiscoveryNetworkMapping).filter_by(vlan_id=vlan.id).count() == 1
