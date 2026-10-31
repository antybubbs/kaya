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
import app.services.asset_identity as asset_identity
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
    RemoteManagerSetting,
    User,
    UserModulePermission,
    VLAN,
)
from app.services.asset_identity import (
    RECONCILIATION_BASELINE_KEY,
    close_ended_dhcp_assignments,
    confirm_identity_evidence,
    lock_identity_scope,
    promote_managed_static_record,
    reconciliation_baseline,
)
from app.services import dns_insights
from app.services.data_integrity_checks import detect_subject
from app.services.data_integrity_repairs import BULK_CONFIRMATION, RepairRefused, execute_bulk, execute_repair, preview_bulk, preview_repair
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
    T4,
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
from tests.test_data_integrity import _audit, _finding

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


def _set_baseline(db, value):
    """Simulate when this version was deployed: the baseline is stored data."""
    row = db.query(RemoteManagerSetting).filter_by(key=RECONCILIATION_BASELINE_KEY).first()
    if row is None:
        row = RemoteManagerSetting(key=RECONCILIATION_BASELINE_KEY)
        db.add(row)
    row.value = value.isoformat() if isinstance(value, datetime) else value
    db.commit()


def _old_legacy_adopted(db, mac):
    """A lease-less adoption row from before this version: adopted at T0, renewed at T1,
    and its lease ended at T2 under the previous rules, which left the row open."""
    vlan = _vlan(db)
    db.add(IPAddress(address=OLD_IP, vlan_id=vlan.id, assignment_type="Dynamic"))
    db.commit()
    provider, admin = _provider(db), _admin(db)
    _sync(db, provider, _item(OLD_IP, mac), at=T0, authoritative=False)
    asset = _adopt(db, admin, provider, OLD_IP)
    (row,) = _rows(db, asset)
    row.started_at = T0 + timedelta(minutes=1)
    db.commit()
    _sync(db, provider, _item(OLD_IP, mac), at=T1, authoritative=False)
    lease = _lease(db, provider, OLD_IP)
    lease.is_active, lease.ended_at = False, T2
    db.commit()
    assert _open(db, asset) == [OLD_IP]
    return provider, admin, asset, lease


def _detection(db, row):
    return detect_subject(db, "obsolete_dhcp_assignment", str(row.id))


def _restart(db):
    """What survives a process restart is only what the database holds."""
    db.expire_all()
    db.info.clear()


# ------------------------------------------------------------ retrospective review


def test_first_collection_records_the_baseline_once_and_audits_it(db):
    provider = _provider(db)
    assert reconciliation_baseline(db) is None
    audits_before = db.query(AuditLog).filter_by(entity="dhcp_reconciliation_baseline").count()
    _sync(db, provider, _item(OLD_IP, _mac()), at=T0, authoritative=False)
    _sync(db, provider, _item(OLD_IP, _mac()), at=T1, authoritative=False)
    _restart(db)
    assert reconciliation_baseline(db) == T0
    audits = db.query(AuditLog).filter_by(entity="dhcp_reconciliation_baseline").order_by(AuditLog.id).all()
    assert len(audits) == audits_before + 1 and json.loads(audits[-1].metadata_json)["baseline_at"] == T0.isoformat()


def test_baseline_audit_failure_rolls_back_the_collection(db, monkeypatch):
    provider = _provider(db)
    monkeypatch.setattr(asset_identity, "write_audit", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError):
        _persist_dhcp_leases(db, provider, {"leases": [_item(OLD_IP, _mac())]}, [], T0)
    db.rollback()
    monkeypatch.undo()
    assert reconciliation_baseline(db) is None
    assert db.query(DHCPLeaseHistory).filter_by(provider_id=provider.id).count() == 0


def test_retrospective_legacy_closure_waits_for_review_then_is_authorised_once(db):
    mac = _mac()
    provider, admin, asset, lease = _old_legacy_adopted(db, mac)
    _set_baseline(db, T3)                                            # this version deployed afterwards
    (row,) = _rows(db, asset)
    for at, authoritative in ((T3, False), (T3 + timedelta(minutes=5), True), (T3 + timedelta(minutes=10), False)):
        _sync(db, provider, at=at, authoritative=authoritative)      # repeated polls
        _restart(db)                                                 # and restarts
        assert _open(db, asset) == [OLD_IP]
    assert reconciliation_baseline(db) == T3                         # nothing moved the baseline
    assert _closure_audits(db, asset) == []
    detection = _detection(db, row)
    evidence = detection.evidence
    assert evidence["reason"] == "lease_ended" and evidence["lease_link"] == "inferred_adoption"
    assert evidence["retrospective_review"] is True and evidence["proposed_end"] == T1.isoformat()
    assert evidence["lease"]["mac"] == mac and evidence["assignment"]["address"] == OLD_IP and detection.bulk_repairable

    _audit(db, admin)
    finding = _finding(db, "obsolete_dhcp_assignment", str(row.id))
    preview = preview_repair(db, admin, finding, "close_obsolete_dhcp")
    assert preview["state"] == "ready"
    db.expire_all()
    assert _open(db, asset) == [OLD_IP]                              # a preview changes nothing
    result = execute_repair(db, admin, finding.id, "close_obsolete_dhcp", {}, preview["preview_token"])
    assert result["outcome"] == "applied"
    db.expire_all()
    (row,) = _rows(db, asset)
    assert row.ended_at == T1                                        # the previewed end, not repair time
    assert db.query(DHCPLeaseHistory).filter_by(id=lease.id).one().is_active is False
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=asset.id, evidence_type="mac", status="confirmed").count() == 1
    assert db.query(AuditLog).filter(AuditLog.action == "data_integrity_repair", AuditLog.user_id == admin.id).count() == 1
    # Ordinary reconciliation after the review is automatic again: the device
    # returns, then its lease expires and is no longer reported.
    back, gone = T4, T4 + timedelta(hours=2)
    _sync(db, provider, {**_item(OLD_IP, mac), "expires": _epoch(back + timedelta(minutes=30))}, at=back, authoritative=False)
    assert _open(db, asset) == [OLD_IP]
    _sync(db, provider, at=gone, authoritative=False)
    assert _open(db, asset) == []
    assert [row.ended_at for row in _rows(db, asset)] == [T1, back]


def test_retrospective_expiry_survives_polls_and_outages_then_bulk_authorisation_keeps_traffic(db, monkeypatch):
    source = _traffic_source(db)
    mac = _mac()
    provider, admin, asset = _adopted_device(db, mac=mac)
    _measure(db, source, OLD_IP, T0 + timedelta(minutes=30), 41)     # inside the supported interval
    _sync(db, provider, {**_item(OLD_IP, mac), "expires": _epoch(T2 + timedelta(minutes=30))}, at=T2, authoritative=False)
    _set_baseline(db, T3)                                            # deployed after the lease expired
    _measure(db, source, OLD_IP, T2 + timedelta(minutes=45), 42)     # after the last observation
    _sync(db, provider, at=T3, authoritative=False)
    _collect(db, provider, monkeypatch, None, at=T3 + timedelta(minutes=30))   # provider outage
    _restart(db)
    _sync(db, provider, at=T3 + timedelta(hours=1), authoritative=False)
    assert _open(db, asset) == [OLD_IP] and _closure_audits(db, asset) == []
    (row,) = _rows(db, asset)
    evidence = _detection(db, row).evidence
    assert (evidence["reason"], evidence["lease_link"], evidence["retrospective_review"]) == ("lease_expired", "direct", True)
    assert evidence["proposed_end"] == T2.isoformat()

    _audit(db, admin)
    finding = _finding(db, "obsolete_dhcp_assignment", str(row.id))
    preview = preview_bulk(db, admin, [finding.id])
    (item,) = preview["items"]
    assert item["finding_id"] == finding.id and preview["skipped"] == []
    with pytest.raises(RepairRefused):                               # no confirmation: nothing changes
        execute_bulk(db, admin, [{"finding_id": finding.id, "preview_token": item["preview_token"]}], confirmation="")
    db.rollback()
    assert _open(db, asset) == [OLD_IP]
    result = execute_bulk(db, admin, [{"finding_id": finding.id, "preview_token": item["preview_token"]}], confirmation=BULK_CONFIRMATION)
    assert result["status"] == "completed"
    db.expire_all()
    assert _rows(db, asset)[0].ended_at == T2
    traffic = asset_reporting_context(db, admin, asset.id, period="24h")["traffic"]
    assert traffic["upload_bytes"] == 4100                           # only the supported interval


def test_retrospective_review_cannot_be_authorised_without_repair_permission(db):
    provider, admin, asset, _lease_row = _old_legacy_adopted(db, _mac())
    _set_baseline(db, T3)
    _audit(db, admin)
    (row,) = _rows(db, asset)
    finding = _finding(db, "obsolete_dhcp_assignment", str(row.id))
    token = preview_repair(db, admin, finding, "close_obsolete_dhcp")["preview_token"]
    db.query(UserModulePermission).filter_by(user_id=admin.id, module_key="data_integrity.repair").delete()
    db.commit()
    with pytest.raises(PermissionError):
        execute_repair(db, admin, finding.id, "close_obsolete_dhcp", {}, token)
    db.rollback()
    assert _open(db, asset) == [OLD_IP]


def test_unreadable_baseline_fails_closed(db):
    mac = _mac()
    provider, _, asset = _legacy_adopted(db, mac)
    _set_baseline(db, "not-a-timestamp")
    _sync(db, provider, at=A2)                                       # the lease ends now, but no baseline is trusted
    assert _open(db, asset) == [OLD_IP]
    (row,) = _rows(db, asset)
    assert _detection(db, row).evidence["retrospective_review"] is True


def test_established_lease_end_closure_is_not_held_for_review(db):
    """Lease-linked rows whose lease ended were always closed automatically."""
    provider, _, asset = _adopted_device(db, mac=_mac())
    _set_baseline(db, T3)
    _sync(db, provider, at=T2)                                       # authoritative end before the baseline
    assert _open(db, asset) == [] and _rows(db, asset)[0].ended_at == T1


# ------------------------------------------------------------ address and time normalisation

IPV6, IPV6_SPELLED, IPV6_OTHER_SPELLING = "2001:db8::10", "2001:DB8:0:0::10", "2001:db8:0::10"


def test_ipv6_spellings_match_the_adoption_address(db):
    mac = _mac()
    vlan = _vlan(db)
    db.add(IPAddress(address=IPV6, vlan_id=vlan.id, assignment_type="Dynamic"))
    db.commit()
    provider, admin = _provider(db), _admin(db)
    _sync(db, provider, _item(IPV6_SPELLED, mac), at=T0, authoritative=False)
    asset = _adopt(db, admin, provider, IPV6_SPELLED)
    _sync(db, provider, _item(IPV6_SPELLED, mac), at=A1, authoritative=False)
    assert _open(db, asset) == [IPV6]
    secondary = _provider(db, "Synthetic secondary Pi-hole")
    _sync(db, secondary, _item(IPV6_OTHER_SPELLING, mac), at=A1, authoritative=False)
    _sync(db, provider, at=A2)
    assert _open(db, asset) == [IPV6]                                # the secondary still leases it
    _sync(db, secondary, at=A3)                                      # the secondary releases it too
    _sync(db, provider, at=A3 + timedelta(minutes=5))
    assert _open(db, asset) == [] and _rows(db, asset)[0].ended_at == A1


@pytest.mark.parametrize(("raw", "expected"), [
    ("2026-10-31T12:00:00+01:00", datetime(2026, 10, 31, 11, 0)),
    ("2026-10-31T12:00:00Z", datetime(2026, 10, 31, 12, 0)),
    ("2026-10-31T12:00:00-05:30", datetime(2026, 10, 31, 17, 30)),
    ("2026-10-31T12:00:00", datetime(2026, 10, 31, 12, 0)),
])
def test_offset_timestamps_are_converted_to_utc(raw, expected):
    assert dns_insights._timestamp(raw) == expected


def test_offset_lease_expiry_is_stored_as_utc(db):
    provider = _provider(db)
    expires = (T2 + timedelta(hours=2)).replace(microsecond=0)
    _sync(db, provider, {**_item(OLD_IP, _mac()), "expires": expires.isoformat() + "+02:00"}, at=T2, authoritative=False)
    assert _lease(db, provider, OLD_IP).expires_at == expires - timedelta(hours=2)


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


def _pg_factory():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=4, max_overflow=0)
    return engine, sessionmaker(bind=engine)


def _seed_committed_legacy(factory):
    """A committed lease-less adoption row whose lease ended at T3, plus a Static record for its MAC.

    The baseline is pinned before T3 so these tests never depend on rows other
    tests committed; ``_cleanup_committed`` restores the previous value.
    """
    mac, token = _mac(), uuid.uuid4().hex[:8]
    old_ip, static_ip = f"198.51.100.{10 + int(token[:2], 16) % 200}", f"203.0.113.{10 + int(token[2:4], 16) % 200}"
    with factory.begin() as session:
        previous = session.query(RemoteManagerSetting).filter_by(key=RECONCILIATION_BASELINE_KEY).first()
        previous_value = previous.value if previous else None
        if previous is None:
            session.add(RemoteManagerSetting(key=RECONCILIATION_BASELINE_KEY, value=T0.isoformat()))
        else:
            previous.value = T0.isoformat()
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
        return {"admin": admin.id, "provider": provider.id, "vlan": vlan.id, "asset": asset.id, "records": [dynamic.id, static.id],
                "old_ip": old_ip, "static_ip": static_ip, "previous_baseline": previous_value, "had_baseline": previous is not None}


def _cleanup_committed(factory, ids):
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
        baseline = session.query(RemoteManagerSetting).filter_by(key=RECONCILIATION_BASELINE_KEY).first()
        if not ids["had_baseline"]:
            session.delete(baseline)
        else:
            baseline.value = ids["previous_baseline"]


def test_postgres_concurrent_legacy_closure_and_static_promotion_both_complete():
    engine, factory = _pg_factory()
    ids = _seed_committed_legacy(factory)
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
            assert [row.address for row in rows if row.ended_at is None] == [ids["static_ip"]]
            old = next(row for row in rows if row.address == ids["old_ip"])
            assert old.ended_at is not None and old.ended_at >= old.started_at
    finally:
        _cleanup_committed(factory, ids)
        engine.dispose()


def test_postgres_contended_closure_is_skipped_without_waiting_then_retried():
    """A collection holding address locks never waits for an asset lock, so it cannot complete a deadlock cycle."""
    engine, factory = _pg_factory()
    ids = _seed_committed_legacy(factory)
    try:
        with factory() as holder:
            lock_identity_scope(holder, asset_ids=[ids["asset"]])    # e.g. an adoption or repair of this asset
            with factory() as collection:
                collection.execute(asset_identity.text("SET LOCAL lock_timeout = '2s'"))
                assert close_ended_dhcp_assignments(collection, provider_id=ids["provider"], observed_at=T3) == 0
                collection.commit()
            holder.commit()
        with factory() as collection:                                # the next collection closes it
            assert close_ended_dhcp_assignments(collection, provider_id=ids["provider"], observed_at=T4) == 1
            collection.commit()
        with factory() as session:
            (row,) = session.query(AssetNetworkAssignment).filter_by(asset_id=ids["asset"]).all()
            assert row.ended_at == T1                                # the lease's last observation
            audits = session.query(AuditLog).filter(AuditLog.entity == "asset_network_assignment", AuditLog.entity_id == str(row.id)).count()
            assert audits == 1
    finally:
        _cleanup_committed(factory, ids)
        engine.dispose()
