"""DHCP lease lifecycle reconciliation: expiry, legacy adoption rows, MAC-first
lease identity and managed static promotion on administrator record saves.

Leases enter through the real DNS Manager ingestion path and devices through
the real Review / Adopt service. Runs on SQLite and, when
KAYA_TEST_POSTGRES_URL is set, PostgreSQL. All data is synthetic (RFC 5737
addresses, locally administered MACs, example.invalid accounts).
"""

import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.middleware.sessions import SessionMiddleware

import app.routers.auth as auth
import app.routers.ip_addresses as ip_addresses_router
import tests.test_dhcp_identity_continuity as continuity
from app.core.csrf import CSRF_SESSION_KEY
from app.db.session import get_db
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    AuditLog,
    DHCPLeaseHistory,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    User,
    VLAN,
)
from app.services.asset_identity import (
    close_ended_dhcp_assignments,
    confirm_identity_evidence,
    pending_legacy_adoption_closures,
    promote_managed_static_record,
)
from app.services.data_integrity_checks import detect_subject
from app.services.dns_insights import NormalisedClient, _persist_dhcp_leases
from app.services.modules import grant_all_registered_modules
from tests.test_dhcp_identity_continuity import (
    LATER,
    NEW_IP,
    OLD_IP,
    STATIC_IP,
    T0,
    T1,
    T2,
    T3,
    _adopt,
    _adopted_device,
    _admin,
    _closure_audits,
    _collect,
    _dhcp_asset_with_open_adoption_row,
    _item,
    _lease,
    _mac,
    _measure,
    _open,
    _provider,
    _rows,
    _sync,
    _traffic_source,
    _vlan,
)
from app.services.asset_profile_reporting import asset_reporting_context

db = continuity.db
# Review / Adopt stamps its assignment with the wall clock, inside the hour
# after NOW; every observation that must follow adoption is after LATER.
A1, A2, A3 = LATER, LATER + timedelta(hours=1), LATER + timedelta(hours=2)
TOKEN = "synthetic-csrf-token"


def _epoch(value):
    return (value - datetime(1970, 1, 1)).total_seconds()


def _legacy_adopted(db, mac, *, record_type="Dynamic", provider=None, expires=None):
    """A device adopted from DHCP while its address had a managed record.

    Adoption makes a lease-less ``discovered_device_adoption`` row; the next
    collection renews the same lease, so no lease-linked row is created.
    """
    vlan = _vlan(db)
    db.add(IPAddress(address=OLD_IP, vlan_id=vlan.id, assignment_type=record_type))
    db.commit()
    provider = provider or _provider(db)
    admin = _admin(db)
    _sync(db, provider, _item(OLD_IP, mac), at=T0, authoritative=False)
    asset = _adopt(db, admin, provider, OLD_IP)
    renewal = {**_item(OLD_IP, mac), **({"expires": _epoch(expires)} if expires else {})}
    _sync(db, provider, renewal, at=A1, authoritative=False)
    (row,) = _rows(db, asset)
    assert row.provenance == "discovered_device_adoption" and row.dhcp_lease_id is None and row.ended_at is None
    return provider, admin, asset


def _closure_metadata(db, asset):
    return [json.loads(row.metadata_json or "{}") for row in _closure_audits(db, asset)]


# ------------------------------------------------------------ legacy adoption rows


def test_legacy_adoption_row_survives_unverified_snapshot_then_closes_when_lease_ends(db):
    mac = _mac()
    provider, _, asset = _legacy_adopted(db, mac)
    leases_before = db.query(DHCPLeaseHistory).count()
    _sync(db, provider, at=A2, authoritative=False)                  # incomplete snapshot: proves nothing
    assert _open(db, asset) == [OLD_IP]
    _sync(db, provider, at=A3)                                       # authoritative snapshot ends the lease
    (row,) = _rows(db, asset)
    assert row.ended_at == A1                                        # the lease's last observation
    assert db.query(DHCPLeaseHistory).count() == leases_before       # lease history kept
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=asset.id, evidence_type="mac", status="confirmed").count() == 1
    (metadata,) = _closure_metadata(db, asset)
    assert metadata["lease_link"] == "inferred_adoption" and metadata["reason"] == "lease_ended"


def test_legacy_adoption_row_closes_when_another_mac_takes_the_address(db):
    mac_a, mac_b = _mac(), _mac()
    provider, admin, asset_a = _legacy_adopted(db, mac_a)
    asset_b = HardwareAsset(name=f"Synthetic tablet {uuid.uuid4().hex[:6]}", status="In use")
    db.add(asset_b)
    db.commit()
    confirm_identity_evidence(db, admin, asset_id=asset_b.id, evidence_type="mac", value=mac_b, source="manual")
    assets_before = db.query(HardwareAsset).count()
    _sync(db, provider, _item(OLD_IP, mac_b, name="synthetic-tablet"), at=A2, authoritative=False)
    assert _open(db, asset_a) == []
    assert _rows(db, asset_a)[0].ended_at == A1
    assert _open(db, asset_b) == [OLD_IP]                            # the new owner links in the same collection
    assert _rows(db, asset_b)[0].started_at == A2
    assert db.query(HardwareAsset).count() == assets_before          # no duplicate asset


def test_legacy_adoption_row_with_static_record_is_never_closed_by_dhcp(db):
    mac = _mac()
    expires = A1 + timedelta(minutes=30)
    provider, _, asset = _legacy_adopted(db, mac, record_type="Static", expires=expires)
    _sync(db, provider, at=A2, authoritative=False)                  # provider expiry has passed
    _sync(db, provider, at=A3)                                       # and the lease has ended
    assert _open(db, asset) == [OLD_IP]
    assert _closure_audits(db, asset) == []


def test_legacy_adoption_row_stays_open_when_its_mac_is_not_uniquely_confirmed(db):
    mac = _mac()
    provider, _, asset = _legacy_adopted(db, mac)
    other = HardwareAsset(name=f"Synthetic duplicate {uuid.uuid4().hex[:6]}", status="In use")
    db.add(other)
    db.flush()
    # A duplicate confirmed MAC (a Data Integrity finding) makes ownership ambiguous.
    db.add(AssetIdentityEvidence(asset_id=other.id, evidence_type="mac", normalised_value=mac, source="manual", status="confirmed", first_observed_at=T0, last_observed_at=T0))
    db.commit()
    _sync(db, provider, at=A2)
    assert _open(db, asset) == [OLD_IP]


def test_legacy_adoption_row_stays_open_while_another_provider_still_leases_it(db):
    mac = _mac()
    provider, _, asset = _legacy_adopted(db, mac)
    secondary = _provider(db, "Synthetic secondary Pi-hole")
    _sync(db, secondary, _item(OLD_IP, mac), at=A1, authoritative=False)
    _sync(db, provider, at=A2)                                       # only the primary's lease ends
    assert _open(db, asset) == [OLD_IP]


def test_provider_outage_closes_legacy_adoption_row_only_after_provider_expiry(db, monkeypatch):
    mac = _mac()
    expires = A1 + timedelta(minutes=30)
    provider, _, asset = _legacy_adopted(db, mac, expires=expires)
    _collect(db, provider, monkeypatch, None, at=A1 + timedelta(minutes=10))   # outage before expiry
    assert _open(db, asset) == [OLD_IP]
    _collect(db, provider, monkeypatch, None, at=A2)                            # outage after expiry
    assert _rows(db, asset)[0].ended_at == A1
    assert len(_closure_audits(db, asset)) == 1


def test_preview_lists_historical_legacy_rows_without_changing_them(db):
    mac = _mac()
    provider, _, asset = _legacy_adopted(db, mac)
    lease = _lease(db, provider, OLD_IP)
    lease.is_active, lease.ended_at = False, A2                      # ended before this version ran
    db.commit()
    audits_before = db.query(AuditLog).count()
    (pending,) = pending_legacy_adoption_closures(db, observed_at=A3)
    assert (pending[0].asset_id, pending[1].id, pending[2]) == (asset.id, lease.id, "lease_ended")
    db.rollback()
    assert _open(db, asset) == [OLD_IP] and db.query(AuditLog).count() == audits_before
    _sync(db, provider, at=A3, authoritative=False)                  # the next collection closes it
    assert _rows(db, asset)[0].ended_at == A1


# ------------------------------------------------------------ expiry with the provider online


def test_expired_lease_missing_from_unverified_snapshot_closes_at_last_observation(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    _sync(db, provider, {**_item(OLD_IP, mac), "expires": _epoch(T2 + timedelta(minutes=30))}, at=T2, authoritative=False)
    _sync(db, provider, _item("192.0.2.190", _mac(), name="synthetic-other"), at=T3, authoritative=False)
    (row,) = _rows(db, asset)
    assert row.ended_at == T2
    lease = _lease(db, provider, OLD_IP)
    assert lease is not None and lease.is_active is True            # the unverified lease row is not rewritten
    assert len(_closure_audits(db, asset)) == 1


def test_expired_lease_still_reported_by_the_provider_is_not_closed(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    stale = {**_item(OLD_IP, mac), "expires": _epoch(T2 + timedelta(minutes=30))}
    _sync(db, provider, stale, at=T2, authoritative=False)
    _sync(db, provider, stale, at=T3, authoritative=False)           # still listed: still current evidence
    assert _open(db, asset) == [OLD_IP]


def test_unexpired_lease_missing_from_unverified_snapshot_is_retained(db):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    _sync(db, provider, {**_item(OLD_IP, mac), "expires": _epoch(T3 + timedelta(hours=1))}, at=T2, authoritative=False)
    _sync(db, provider, at=T3, authoritative=False)
    assert _open(db, asset) == [OLD_IP]


def test_infinite_renewal_clears_an_earlier_finite_expiry(db, monkeypatch):
    mac = _mac()
    provider, _, asset = _adopted_device(db, mac=mac)
    _collect(db, provider, monkeypatch, [{**_item(OLD_IP, mac), "expires": _epoch(T1 + timedelta(minutes=30))}], at=T1)
    _collect(db, provider, monkeypatch, [{**_item(OLD_IP, mac), "expires": 0}], at=T2)
    assert _lease(db, provider, OLD_IP).expires_at is None
    _collect(db, provider, monkeypatch, None, at=T3)                 # outage: no expiry evidence remains
    assert _open(db, asset) == [OLD_IP]


def test_expiry_closure_preserves_traffic_attributed_inside_the_supported_interval(db):
    source = _traffic_source(db)
    mac = _mac()
    provider, admin, asset = _adopted_device(db, mac=mac)
    _measure(db, source, OLD_IP, T0 + timedelta(minutes=30), 31)     # inside the confirmed lease
    _sync(db, provider, {**_item(OLD_IP, mac), "expires": _epoch(T2 + timedelta(minutes=30))}, at=T2, authoritative=False)
    _sync(db, provider, at=T3, authoritative=False)
    _measure(db, source, OLD_IP, T3 + timedelta(minutes=30), 32)     # after the lease: unattributed
    traffic = asset_reporting_context(db, admin, asset.id, period="24h")["traffic"]
    assert traffic["upload_bytes"] == 3100


# ------------------------------------------------------------ MAC-first lease identity


def test_address_derived_dns_client_never_merges_a_different_mac_into_the_lease(db):
    mac_a, mac_b = _mac(), _mac()
    provider, _, asset = _adopted_device(db, mac=mac_a)
    client = DNSRecognisedDevice(
        provider_id=provider.id, logical_provider_key=f"synthetic-{uuid.uuid4().hex[:6]}",
        identity_key=f"ip:{OLD_IP}", identity_type="ip", identity_value=OLD_IP, hostname="synthetic-phone",
        normalised_hostname="synthetic-phone", current_ip=OLD_IP, first_seen_at=T0, last_seen_at=T2,
    )
    db.add(client)
    db.flush()
    original = _lease(db, provider, OLD_IP)
    original.dns_client_id = client.id
    db.commit()
    # The provider's client list has the address without a MAC, so the DNS
    # client is matched by address only; the lease carries another MAC.
    by_address = NormalisedClient("ip", OLD_IP, "synthetic-phone", OLD_IP, "-", device_id=client.id)
    _persist_dhcp_leases(db, provider, {"leases": [_item(OLD_IP, mac_b, name="synthetic-guest")]}, [by_address], T2)
    db.commit()
    db.refresh(original)
    assert original.mac_address == mac_a and original.is_active is False
    assert _lease(db, provider, OLD_IP).mac_address == mac_b
    assert _open(db, asset) == [] and _rows(db, asset)[0].ended_at == T1


def test_one_asset_with_two_confirmed_macs_keeps_each_interface_assignment(db):
    wired, wifi = _mac(), _mac()
    provider, admin, asset = _adopted_device(db, mac=wired)
    confirm_identity_evidence(db, admin, asset_id=asset.id, evidence_type="mac", value=wifi, source="manual")
    _sync(db, provider, _item(OLD_IP, wired), _item(NEW_IP, wifi, name="synthetic-phone-wifi"), at=T2)
    assert sorted(_open(db, asset)) == sorted([OLD_IP, NEW_IP])
    _sync(db, provider, _item(OLD_IP, wired), at=T3)                 # only the Wi-Fi lease ends
    assert _open(db, asset) == [OLD_IP]
    assert next(row for row in _rows(db, asset) if row.address == NEW_IP).ended_at == T2


# ------------------------------------------------------------ DHCP → static on a record save


def _seed_static_change(db):
    mac = _mac()
    vlan = _vlan(db)
    provider, admin, asset = _dhcp_asset_with_open_adoption_row(db, mac, vlan)
    asset.asset_tag = f"SYN-{uuid.uuid4().hex[:8]}"
    record = IPAddress(address=STATIC_IP, vlan_id=vlan.id, assignment_type="Static", name="synthetic-phone-static")
    db.add(record)
    db.commit()
    return mac, vlan, asset, record


def test_promotion_is_a_no_op_for_editors_and_without_a_unique_owner(db):
    mac, _vlan_row, asset, record = _seed_static_change(db)
    record.mac_address = mac
    db.commit()
    editor = User(email=f"synthetic-editor-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role="editor", is_active=True)
    inactive = User(email=f"synthetic-inactive-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role="admin", is_active=False)
    db.add_all([editor, inactive])
    db.commit()
    assert promote_managed_static_record(db, record.id, actor=editor) == "not_applicable"
    assert promote_managed_static_record(db, record.id, actor=inactive) == "not_applicable"
    assert promote_managed_static_record(db, record.id, actor=None) == "not_applicable"
    other = HardwareAsset(name=f"Synthetic duplicate {uuid.uuid4().hex[:6]}", status="In use")
    db.add(other)
    db.flush()
    db.add(AssetIdentityEvidence(asset_id=other.id, evidence_type="mac", normalised_value=mac, source="manual", status="confirmed", first_observed_at=T0, last_observed_at=T0))
    db.commit()
    admin = _admin(db)
    assert promote_managed_static_record(db, record.id, actor=admin) == "review_required"
    assert _open(db, asset) == [OLD_IP]


def test_promotion_refuses_an_address_held_by_another_asset(db):
    mac, vlan, asset, record = _seed_static_change(db)
    record.mac_address = mac
    holder = HardwareAsset(name=f"Synthetic holder {uuid.uuid4().hex[:6]}", status="In use")
    db.add(holder)
    db.flush()
    db.add(AssetNetworkAssignment(asset_id=holder.id, address=STATIC_IP, address_family=4, vlan_id=vlan.id, started_at=T0, provenance="manual", status="confirmed"))
    db.commit()
    assert promote_managed_static_record(db, record.id, actor=_admin(db)) == "review_required"
    assert _open(db, asset) == [OLD_IP]


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr(auth, "current_user", lambda request, db=None: db.get(User, request.session.get("user_id")) if request.session.get("user_id") else None)
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="synthetic-test-session-key-0123456789")

    @app.exception_handler(PermissionError)
    async def _forbidden(request: Request, exc: PermissionError):
        return PlainTextResponse("Forbidden", status_code=403)

    @app.get("/test-login/{user_id}")
    def _login(user_id: int, request: Request):
        request.session["user_id"] = user_id
        request.session[CSRF_SESSION_KEY] = TOKEN
        return {"ok": True}

    app.include_router(ip_addresses_router.router)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def _role_user(db, role):
    user = User(email=f"synthetic-{role}-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role=role, is_active=True)
    db.add(user)
    db.flush()
    grant_all_registered_modules(db, user)
    db.commit()
    return user


def _save_record(client, user, record, vlan, mac):
    assert client.get(f"/test-login/{user.id}").status_code == 200
    return client.post(f"/networking/vlan-ip-manager/{record.id}/edit", data={
        "address": STATIC_IP, "vlan_id": str(vlan.id), "mac_address": mac, "assignment_type": "Static",
        "name": "synthetic-phone-static", "csrf_token": TOKEN,
    })


def test_administrator_record_save_promotes_the_managed_static_assignment(db, client):
    mac, vlan, asset, record = _seed_static_change(db)
    admin = _role_user(db, "admin")
    assets_before = db.query(HardwareAsset).count()
    response = _save_record(client, admin, record, vlan, mac)
    assert response.status_code == 303
    db.expire_all()
    assert _open(db, asset) == [STATIC_IP]
    rows = _rows(db, asset)
    current = next(row for row in rows if row.ended_at is None)
    assert current.provenance == "managed_static_repair" and current.ip_address_id == record.id and current.confirmed_by == admin.id
    old = next(row for row in rows if row.address == OLD_IP)
    assert old.ended_at is not None and old.ended_at >= old.started_at   # kept as history
    assert db.query(HardwareAsset).count() == assets_before
    audit = db.query(AuditLog).filter(AuditLog.action == "repair", AuditLog.entity == "asset_network_assignment", AuditLog.entity_id == str(current.id)).one()
    assert audit.user_id == admin.id and json.loads(audit.metadata_json)["trigger"] == "managed_record_saved"
    assert detect_subject(db, "managed_static_assignment", f"{asset.id}|{mac}|{record.id}") is None


def test_editor_record_save_leaves_assignments_for_data_integrity_review(db, client):
    mac, vlan, asset, record = _seed_static_change(db)
    editor = _role_user(db, "editor")
    response = _save_record(client, editor, record, vlan, mac)
    assert response.status_code == 303
    db.expire_all()
    assert db.get(IPAddress, record.id).mac_address == mac           # the record change itself is saved
    assert _open(db, asset) == [OLD_IP]                              # asset identity is unchanged
    assert detect_subject(db, "managed_static_assignment", f"{asset.id}|{mac}|{record.id}") is not None


# ------------------------------------------------------------ PostgreSQL concurrency


def test_postgres_concurrent_legacy_closure_and_static_promotion_both_complete():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=4, max_overflow=0)
    factory = sessionmaker(bind=engine)
    mac, token = _mac(), uuid.uuid4().hex[:8]
    old_ip, static_ip = f"198.51.100.{10 + int(token[:2], 16) % 200}", f"203.0.113.{10 + int(token[2:4], 16) % 200}"
    with factory.begin() as session:
        admin = User(email=f"synthetic-concurrent-{token}@example.invalid", password_hash="x", role="admin", is_active=True)
        provider = DNSProviderConfig(name=f"Synthetic concurrent DNS {token}", base_url="https://dns.example.invalid", provider_type="pihole")
        vlan = VLAN(name=f"Synthetic concurrent LAN {token}")
        asset = HardwareAsset(name=f"Synthetic concurrent asset {token}", asset_tag=f"SYN-{token}", status="In use")
        session.add_all([admin, provider, vlan, asset])
        session.flush()
        dynamic = IPAddress(address=old_ip, vlan_id=vlan.id, assignment_type="Dynamic")
        static = IPAddress(address=static_ip, vlan_id=vlan.id, assignment_type="Static", mac_address=mac)
        session.add_all([dynamic, static])
        session.flush()
        session.add(AssetIdentityEvidence(asset_id=asset.id, evidence_type="mac", normalised_value=mac, source="discovery", source_scope="dhcp", status="confirmed", first_observed_at=T0, last_observed_at=T0))
        session.add(DHCPLeaseHistory(provider_id=provider.id, ip_address=old_ip, mac_address=mac, lease_started_at=T0, first_seen_at=T0, last_seen_at=T1, is_active=False, ended_at=T3))
        session.add(AssetNetworkAssignment(asset_id=asset.id, address=old_ip, address_family=4, vlan_id=vlan.id, ip_address_id=dynamic.id, started_at=T0 + timedelta(minutes=1), provenance="discovered_device_adoption", status="confirmed"))
        ids = {"admin": admin.id, "provider": provider.id, "vlan": vlan.id, "asset": asset.id, "records": [dynamic.id, static.id]}
    barrier = threading.Barrier(2)

    def close():
        with factory() as session:
            barrier.wait()
            closed = close_ended_dhcp_assignments(session, provider_id=ids["provider"], observed_at=T3)
            session.commit()
            return closed

    def promote():
        with factory() as session:
            barrier.wait()
            return promote_managed_static_record(session, ids["records"][1], actor=session.get(User, ids["admin"]))

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            closed, promoted = pool.submit(close), pool.submit(promote)
            assert closed.result(timeout=30) in {0, 1}
            assert promoted.result(timeout=30) == "promoted"
        with factory() as session:
            rows = session.query(AssetNetworkAssignment).filter_by(asset_id=ids["asset"]).all()
            assert [row.address for row in rows if row.ended_at is None] == [static_ip]
            old = next(row for row in rows if row.address == old_ip)
            assert old.ended_at is not None and old.ended_at >= old.started_at
    finally:
        with factory.begin() as session:
            row_ids = [str(row.id) for row in session.query(AssetNetworkAssignment.id).filter_by(asset_id=ids["asset"])]
            session.query(AuditLog).filter((AuditLog.user_id == ids["admin"]) | AuditLog.entity_id.in_(row_ids or ["-"])).delete(synchronize_session=False)
            session.query(AssetNetworkAssignment).filter_by(asset_id=ids["asset"]).delete(synchronize_session=False)
            session.query(AssetIdentityEvidence).filter_by(asset_id=ids["asset"]).delete(synchronize_session=False)
            session.query(DHCPLeaseHistory).filter_by(provider_id=ids["provider"]).delete(synchronize_session=False)
            session.query(IPAddress).filter(IPAddress.id.in_(ids["records"])).delete(synchronize_session=False)
            session.query(HardwareAsset).filter_by(id=ids["asset"]).delete(synchronize_session=False)
            session.query(VLAN).filter_by(id=ids["vlan"]).delete(synchronize_session=False)
            session.query(DNSProviderConfig).filter_by(id=ids["provider"]).delete(synchronize_session=False)
            session.query(User).filter_by(id=ids["admin"]).delete(synchronize_session=False)
        engine.dispose()
