"""Identity integrity: managed static repair, global MAC ownership, DHCP client
identifiers and managed hostname authority.

Runs on SQLite and (when KAYA_TEST_POSTGRES_URL is set) PostgreSQL through the
real ingestion, adoption and repair services. All data is synthetic (RFC 5737
addresses, locally administered MACs, example.invalid accounts).
"""

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.services.asset_identity as asset_identity
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    AuditLog,
    DHCPLeaseHistory,
    DNSClientEvent,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    RemoteManagerSetting,
    User,
)
from app.services.asset_discovery import adopt_discovered_device, get_discovered_device
from app.services.asset_identity import confirm_identity_evidence, reconcile_dhcp_assignment, repair_managed_static_assignment
from app.services.dns_clients import _suggest_managed_record
from scripts.audit_dhcp_identity import run_audit
import tests.test_dhcp_identity_continuity as continuity
from tests.test_dhcp_identity_continuity import (
    LATER,
    NEW_IP,
    OLD_IP,
    STATIC_IP,
    T0,
    T1,
    T2,
    _admin,
    _adopt,
    _dhcp_asset_with_open_adoption_row,
    _dns_candidate,
    _item,
    _lease,
    _mac,
    _open,
    _provider,
    _rows,
    _static_record,
    _sync,
    _vlan,
)

# Shared SQLite/PostgreSQL session fixture.
db = continuity.db


def _tagged(db, asset):
    asset.asset_tag = f"SYN-{uuid.uuid4().hex[:8]}"
    db.commit()
    return asset.asset_tag


def _state(db, asset):
    return (
        sorted((row.id, row.address, row.ended_at) for row in _rows(db, asset)),
        db.query(DHCPLeaseHistory).count(),
        db.query(AssetIdentityEvidence).count(),
        db.query(AuditLog).filter(AuditLog.action == "repair").count(),
    )


def _repair(db, asset, mac, **overrides):
    values = {"asset_id": asset.id, "asset_tag": asset.asset_tag, "mac": mac, "address": STATIC_IP}
    values.update(overrides)  # may replace any target, including the MAC
    return repair_managed_static_assignment(db, **values)


# ------------------------------------------------------------ 1. managed static repair


def _affected_asset(db):
    """The pre-fix state: DHCP address still open, no managed static assignment."""
    mac = _mac()
    vlan = _vlan(db)
    provider, admin, asset = _dhcp_asset_with_open_adoption_row(db, mac, vlan)
    _static_record(db, vlan, mac)
    _tagged(db, asset)
    return mac, provider, admin, asset


def test_repair_dry_run_reports_plan_without_changes(db):
    mac, _, _, asset = _affected_asset(db)
    before = _state(db, asset)
    plan = _repair(db, asset, mac)
    assert plan["executed"] is False and plan["changes_required"] is True
    assert plan["create_assignment"] is True
    assert [row["address"] for row in plan["close_assignments"]] == [OLD_IP]
    assert _state(db, asset) == before


def test_repair_executes_once_with_audit_and_preserves_history(db):
    mac, _, admin, asset = _affected_asset(db)
    leases, evidence = db.query(DHCPLeaseHistory).count(), db.query(AssetIdentityEvidence).count()
    now = LATER

    result = _repair(db, asset, mac, actor=admin, execute=True, now=now)

    assert result["executed"] is True
    assert _open(db, asset) == [STATIC_IP]
    rows = _rows(db, asset)
    created = next(row for row in rows if row.ended_at is None)
    assert created.provenance == "managed_static_repair" and created.started_at == now and created.confirmed_by == admin.id
    old = next(row for row in rows if row.address == OLD_IP)
    assert old.ended_at == now  # closed at repair time: earlier attribution is unchanged
    assert db.query(DHCPLeaseHistory).count() == leases and db.query(AssetIdentityEvidence).count() == evidence
    (audit,) = db.query(AuditLog).filter(AuditLog.action == "repair").all()
    assert audit.entity == "asset_network_assignment" and audit.entity_id == str(created.id)
    # Idempotent: a second run plans nothing and writes nothing.
    again = _repair(db, asset, mac, actor=admin, execute=True, now=now + timedelta(minutes=5))
    assert again["changes_required"] is False and again["executed"] is False
    assert db.query(AuditLog).filter(AuditLog.action == "repair").count() == 1
    assert _open(db, asset) == [STATIC_IP]


def test_repaired_static_is_not_reclaimed_by_the_old_lease(db):
    mac, provider, _, asset = _affected_asset(db)
    lease = _lease(db, provider, OLD_IP, active=False)
    lease.is_active, lease.ended_at = True, None  # the provider still lists the unexpired lease
    db.commit()
    _repair(db, asset, mac, execute=True, now=LATER)
    _sync(db, provider, _item(OLD_IP, mac), at=LATER + timedelta(minutes=1))
    assert _open(db, asset) == [STATIC_IP]


@pytest.mark.parametrize("problem", ["tag", "mac_not_confirmed", "record_mac", "dynamic_record", "held_elsewhere", "mac_elsewhere"])
def test_repair_refuses_unverified_targets_without_changes(db, problem):
    mac, _, admin, asset = _affected_asset(db)
    overrides = {}
    if problem == "tag":
        overrides["asset_tag"] = "SYN-not-this-asset"
    elif problem == "mac_not_confirmed":
        overrides["mac"] = _mac()
    elif problem == "record_mac":
        db.query(IPAddress).filter_by(address=STATIC_IP).update({"mac_address": _mac()})
        db.commit()
    elif problem == "dynamic_record":
        db.query(IPAddress).filter_by(address=STATIC_IP).update({"assignment_type": "Dynamic"})
        db.commit()
    elif problem == "held_elsewhere":
        other = HardwareAsset(name="Synthetic other holder", status="In use")
        db.add(other)
        db.flush()
        db.add(AssetNetworkAssignment(asset_id=other.id, address=STATIC_IP, address_family=4, started_at=T0, provenance="discovered_device_adoption", status="confirmed"))
        db.commit()
    elif problem == "mac_elsewhere":
        other = HardwareAsset(name="Synthetic duplicate owner", status="In use")
        db.add(other)
        db.flush()
        db.add(AssetIdentityEvidence(asset_id=other.id, evidence_type="mac", normalised_value=mac, source="discovery", source_scope="dns", status="confirmed"))
        db.commit()
    before = _state(db, asset)
    with pytest.raises(ValueError):
        _repair(db, asset, overrides.pop("mac", mac), actor=admin, execute=True, **overrides)
    assert _state(db, asset) == before


def test_repair_audit_failure_rolls_back_everything(db, monkeypatch):
    mac, _, _, asset = _affected_asset(db)
    before = _state(db, asset)
    monkeypatch.setattr(asset_identity, "write_audit", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError):
        _repair(db, asset, mac, execute=True, now=LATER)
    assert _state(db, asset) == before


def test_repair_attribution_requires_an_active_administrator(db):
    mac, _, _, asset = _affected_asset(db)
    viewer = User(email=f"synthetic-viewer-{uuid.uuid4().hex[:8]}@example.invalid", password_hash="x", role="viewer", is_active=True)
    db.add(viewer)
    db.commit()
    with pytest.raises(PermissionError):
        _repair(db, asset, mac, actor=viewer, execute=True)


# ------------------------------------------------------------ 2. static ↔ DHCP conversions and re-adoption


def test_static_record_made_dynamic_lets_dhcp_reconcile_again(db):
    mac = _mac()
    vlan = _vlan(db)
    provider, admin, asset = _dhcp_asset_with_open_adoption_row(db, mac, vlan)
    record = _static_record(db, vlan, mac)
    adopt_discovered_device(db, admin, _dns_candidate(db, provider, mac), asset_id=asset.id)
    record.assignment_type = "Dynamic"  # the administrator moves the device back to DHCP
    db.commit()
    _sync(db, provider, _item(OLD_IP, mac), at=LATER)
    assert OLD_IP in _open(db, asset)


def test_adopted_discovery_cannot_be_adopted_again(db):
    mac = _mac()
    vlan = _vlan(db)
    provider, admin, asset = _dhcp_asset_with_open_adoption_row(db, mac, vlan)
    _static_record(db, vlan, mac)
    candidate = _dns_candidate(db, provider, mac)
    adopt_discovered_device(db, admin, candidate, asset_id=asset.id)
    with pytest.raises(ValueError, match="already associated"):
        adopt_discovered_device(db, admin, get_discovered_device(db, candidate["id"]) or candidate, asset_id=asset.id)
    db.rollback()
    assert _open(db, asset) == [STATIC_IP]


# ------------------------------------------------------------ 3. confirmed MAC ownership is global


def test_dns_discovery_cannot_create_second_asset_for_mac_confirmed_through_dhcp(db):
    mac = _mac()
    vlan = _vlan(db)
    provider, admin, asset = _dhcp_asset_with_open_adoption_row(db, mac, vlan)
    candidate = _dns_candidate(db, provider, mac)
    assets_before = db.query(HardwareAsset).count()
    with pytest.raises(ValueError, match="already confirmed for another asset"):
        adopt_discovered_device(db, admin, candidate, new_name="Wrong duplicate")
    db.rollback()
    assert db.query(HardwareAsset).count() == assets_before
    owners = {row.asset_id for row in db.query(AssetIdentityEvidence).filter_by(evidence_type="mac", normalised_value=mac, status="confirmed")}
    assert owners == {asset.id}


def test_manual_confirmation_cannot_claim_a_mac_confirmed_by_discovery(db):
    mac = _mac()
    _, admin, asset = _dhcp_asset_with_open_adoption_row(db, mac, _vlan(db))
    other = HardwareAsset(name="Synthetic manual claimant", status="In use")
    db.add(other)
    db.commit()
    with pytest.raises(ValueError, match="already confirmed for another asset"):
        confirm_identity_evidence(db, admin, asset_id=other.id, evidence_type="mac", value=mac.upper().replace(":", "-"), source="manual")


def test_one_asset_may_hold_many_macs_and_one_mac_under_many_sources(db):
    mac = _mac()
    _, admin, asset = _dhcp_asset_with_open_adoption_row(db, mac, _vlan(db))
    confirm_identity_evidence(db, admin, asset_id=asset.id, evidence_type="mac", value=mac, source="manual")
    confirm_identity_evidence(db, admin, asset_id=asset.id, evidence_type="mac", value=_mac(), source="manual")
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=asset.id, evidence_type="mac", status="confirmed").count() == 3


def test_revoked_and_suggested_mac_evidence_never_blocks_confirmation(db):
    mac = _mac()
    admin = _admin(db)
    previous, suggested, owner = (HardwareAsset(name=f"Synthetic {label}", status="In use") for label in ("previous", "suggested", "owner"))
    db.add_all([previous, suggested, owner])
    db.flush()
    db.add_all([
        AssetIdentityEvidence(asset_id=previous.id, evidence_type="mac", normalised_value=mac, source="manual", status="revoked", revoked_at=T1),
        AssetIdentityEvidence(asset_id=suggested.id, evidence_type="mac", normalised_value=mac, source="dns", status="pending"),
    ])
    db.commit()
    row = confirm_identity_evidence(db, admin, asset_id=owner.id, evidence_type="mac", value=mac, source="manual")
    assert row.status == "confirmed"


def _pg_factory():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=8, max_overflow=0, pool_pre_ping=True)
    return engine, sessionmaker(bind=engine)


def test_postgres_concurrent_adoption_from_different_sources_confirms_mac_once():
    engine, factory = _pg_factory()
    mac = _mac()
    token = uuid.uuid4().hex[:8]
    with factory.begin() as session:
        actor = User(email=f"synthetic-race-{token}@example.invalid", password_hash="x", role="admin", is_active=True)
        provider = DNSProviderConfig(name=f"Synthetic race DNS {token}", base_url="https://dns.example.invalid", provider_type="pihole")
        first, second = HardwareAsset(name=f"Synthetic race one {token}", status="In use"), HardwareAsset(name=f"Synthetic race two {token}", status="In use")
        session.add_all([actor, provider, first, second])
        session.flush()
        client = DNSRecognisedDevice(provider_id=provider.id, logical_provider_key=f"race-{token}", identity_key=f"mac:{mac}", identity_type="mac", identity_value=mac, hostname="race.example.invalid", mac_address=mac, normalised_mac=mac, first_seen_at=T0, last_seen_at=T0)
        lease = DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.230", mac_address=mac, lease_started_at=T0, first_seen_at=T0, last_seen_at=T0, is_active=True)
        session.add_all([client, lease])
        session.flush()
        ids = {"actor": actor.id, "provider": provider.id, "assets": [first.id, second.id], "client": client.id, "lease": lease.id}
    try:
        with factory() as session:
            candidates = [get_discovered_device(session, f"dns:{ids['client']}"), get_discovered_device(session, f"dhcp:{ids['lease']}")]
        assert all(candidate and candidate["asset_id"] is None for candidate in candidates)
        barrier = threading.Barrier(2)

        def worker(index):
            with factory() as session:
                actor = session.get(User, ids["actor"])
                barrier.wait()
                try:
                    adopt_discovered_device(session, actor, candidates[index], asset_id=ids["assets"][index])
                    return "ok"
                except ValueError:
                    session.rollback()
                    return "ValueError"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = sorted(pool.map(worker, range(2)))
        assert results == ["ValueError", "ok"]
        with factory() as session:
            owners = {row.asset_id for row in session.query(AssetIdentityEvidence).filter_by(evidence_type="mac", normalised_value=mac, status="confirmed")}
            assert len(owners) == 1
    finally:
        with factory.begin() as session:
            session.query(AuditLog).filter(AuditLog.user_id == ids["actor"]).delete(synchronize_session=False)
            session.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.asset_id.in_(ids["assets"])).delete(synchronize_session=False)
            session.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id.in_(ids["assets"])).delete(synchronize_session=False)
            session.query(DHCPLeaseHistory).filter_by(id=ids["lease"]).delete(synchronize_session=False)
            session.query(DNSRecognisedDevice).filter_by(id=ids["client"]).delete(synchronize_session=False)
            session.query(HardwareAsset).filter(HardwareAsset.id.in_(ids["assets"])).delete(synchronize_session=False)
            session.query(DNSProviderConfig).filter_by(id=ids["provider"]).delete(synchronize_session=False)
            session.query(User).filter_by(id=ids["actor"]).delete(synchronize_session=False)
        engine.dispose()


# ------------------------------------------------------------ 4. DHCP client identifiers


def _record_item(ip, mac, record_id, clientid=None):
    item = {"ip": ip, "hwaddr": mac, "name": "synthetic-lease", "id": record_id}
    if clientid:
        item["clientid"] = clientid
    return item


def test_provider_lease_record_id_is_not_stored_as_client_identifier(db):
    provider = _provider(db)
    _sync(db, provider, _record_item(OLD_IP, _mac(), "179"), at=T0)
    assert _lease(db, provider, OLD_IP).provider_lease_id is None


def test_genuine_client_identifier_is_still_recorded(db):
    provider = _provider(db)
    clientid = f"01:{uuid.uuid4().hex[:12]}"
    _sync(db, provider, _record_item(OLD_IP, _mac(), "179", clientid), at=T0)
    assert _lease(db, provider, OLD_IP).provider_lease_id == clientid


def test_reused_lease_record_id_never_transfers_identity(db):
    mac_a, mac_b = _mac(), _mac()
    provider, admin = _provider(db), _admin(db)
    _sync(db, provider, _record_item(OLD_IP, mac_a, "179"), at=T0)
    asset = _adopt(db, admin, provider, OLD_IP)
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=asset.id, evidence_type="dhcp_client_id").count() == 0
    # The provider later reuses record number 179 for a different device.
    _sync(db, provider, _record_item(NEW_IP, mac_b, "179"), at=T2)
    assert reconcile_dhcp_assignment(db, _lease(db, provider, NEW_IP), observed_at=T2) == "review_required"
    assert NEW_IP not in _open(db, asset)


def test_legacy_record_id_on_an_existing_lease_is_cleared_on_renewal(db):
    provider = _provider(db)
    mac = _mac()
    _sync(db, provider, _record_item(OLD_IP, mac, "179"), at=T0)
    lease = _lease(db, provider, OLD_IP)
    lease.provider_lease_id = "179"  # as written by the former fallback
    db.commit()
    _sync(db, provider, _record_item(OLD_IP, mac, "179"), at=T1)
    db.refresh(lease)
    assert lease.provider_lease_id is None


def test_mac_continuity_survives_changing_record_ids(db):
    mac = _mac()
    provider, admin = _provider(db), _admin(db)
    _sync(db, provider, _record_item(OLD_IP, mac, "10"), at=T0)
    asset = _adopt(db, admin, provider, OLD_IP)
    _sync(db, provider, _record_item(OLD_IP, mac, "10"), at=T1)
    _sync(db, provider, _record_item(NEW_IP, mac, "11"), at=T2)
    assert _open(db, asset) == [NEW_IP]


# ------------------------------------------------------------ 5. managed hostname authority


def _setting(db, key, value):
    row = db.query(RemoteManagerSetting).filter_by(key=key).first()
    if row is None:
        db.add(RemoteManagerSetting(key=key, value=value))
    else:
        row.value = value


def _hostname_case(db, *, assignment_type, name):
    for key in ("dns_vlan_integration_enabled", "dns_match_suggestions_enabled", "dns_auto_link_exact_mac", "dns_update_empty_managed_hostname"):
        _setting(db, key, "1")
    _setting(db, "dns_auto_update_dynamic_ip", "0")
    mac = _mac()
    vlan = _vlan(db)
    record = IPAddress(address=STATIC_IP, vlan_id=vlan.id, assignment_type=assignment_type, mac_address=mac, name=name)
    provider = _provider(db)
    db.add(record)
    db.flush()
    client = DNSRecognisedDevice(
        provider_id=provider.id, logical_provider_key=f"synthetic-{uuid.uuid4().hex[:6]}", identity_key=f"mac:{mac}",
        identity_type="mac", identity_value=mac, hostname="stale-dhcp-name.example.invalid",
        normalised_hostname="stale-dhcp-name.example.invalid", current_ip=STATIC_IP, mac_address=mac, normalised_mac=mac,
        linked_ip_record_id=record.id, first_seen_at=T0, last_seen_at=T1,
    )
    db.add(client)
    db.commit()
    _suggest_managed_record(db, client)
    db.commit()
    db.refresh(record)
    return record, client


def test_stale_observed_hostname_never_fills_an_empty_static_name(db):
    record, client = _hostname_case(db, assignment_type="Static", name=None)
    assert record.name is None
    assert client.hostname == "stale-dhcp-name.example.invalid"  # kept as discovery evidence
    assert db.query(DNSClientEvent).filter_by(dns_client_id=client.id, source="automatic empty hostname update").count() == 0


def test_conflicting_observed_hostname_never_replaces_a_static_name(db):
    record, _ = _hostname_case(db, assignment_type="Static", name="administrator-name.example.invalid")
    assert record.name == "administrator-name.example.invalid"


def test_blank_dynamic_record_may_still_be_filled_from_observation(db):
    record, client = _hostname_case(db, assignment_type="Dynamic", name=None)
    assert record.name == "stale-dhcp-name.example.invalid"
    assert db.query(DNSClientEvent).filter_by(dns_client_id=client.id, source="automatic empty hostname update").count() == 1


# ------------------------------------------------------------ 6. read-only review report


def test_identity_audit_reports_duplicates_suspect_client_ids_and_filled_static_names(db):
    mac = _mac()
    first, second = HardwareAsset(name="Synthetic dup one", status="In use"), HardwareAsset(name="Synthetic dup two", status="In use")
    db.add_all([first, second])
    db.flush()
    db.add_all([
        AssetIdentityEvidence(asset_id=first.id, evidence_type="mac", normalised_value=mac, source="discovery", source_scope="dhcp", status="confirmed"),
        AssetIdentityEvidence(asset_id=second.id, evidence_type="mac", normalised_value=mac, source="discovery", source_scope="dns", status="confirmed"),
        AssetIdentityEvidence(asset_id=first.id, evidence_type="dhcp_client_id", normalised_value="179", source="dhcp", source_scope="provider:1:range:unscoped", status="confirmed"),
        AssetIdentityEvidence(asset_id=first.id, evidence_type="dhcp_client_id", normalised_value="01:02:00:00:00:00:01", source="dhcp", status="confirmed"),
    ])
    db.commit()
    for key in ("dns_vlan_integration_enabled", "dns_update_empty_managed_hostname"):
        _setting(db, key, "1")
    record, client = _hostname_case(db, assignment_type="Dynamic", name=None)
    record.assignment_type = "Static"  # filled while Dynamic (or before this fix), now Static
    db.commit()

    report = run_audit(db, 100)

    duplicate = next(row for row in report["cross_asset_confirmed_mac_duplicates"] if row["mac"] == mac)
    assert duplicate["distinct_asset_count"] == 2
    suspect = [row["value"] for row in report["suspect_dhcp_client_id_evidence"] if row["asset_id"] == first.id]
    assert suspect == ["179"]
    filled = [row for row in report["auto_filled_static_hostnames"] if row["ip_address_id"] == record.id]
    assert filled and filled[0]["name_unchanged_since_fill"] is True
    # The report is review-only: nothing was merged, revoked or renamed.
    assert db.query(AssetIdentityEvidence).filter_by(normalised_value=mac, status="confirmed").count() == 2
