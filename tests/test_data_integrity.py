"""Data Integrity detection and finding lifecycle (Stage A).

Runs on SQLite and (when KAYA_TEST_POSTGRES_URL is set) PostgreSQL through the
shared ``db`` fixture. All data is synthetic: RFC 5737 / RFC 3849 addresses,
locally administered MACs and example.invalid names.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
import uuid

import pytest

import app.services.data_integrity as data_integrity
import app.services.data_integrity_checks as checks
import tests.test_dhcp_identity_continuity as continuity
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    AuditLog,
    DataIntegrityFinding,
    DataIntegrityFindingEvent,
    DataIntegrityRun,
    DHCPLeaseHistory,
    DNSClientEvent,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    NotificationOutbox,
    VLAN,
)
from app.services.asset_identity import repair_managed_static_assignment
from app.services.data_integrity_checks import Detection, detect_subject, run_check
from tests.test_dhcp_identity_continuity import NOW, STATIC_IP, T0, T1, T2, _admin, _dhcp_asset_with_open_adoption_row, _mac, _provider, _static_record, _vlan

db = continuity.db


# ------------------------------------------------------------- builders


def _asset(db, name=None):
    asset = HardwareAsset(name=name or f"Synthetic asset {uuid.uuid4().hex[:6]}", status="In use", asset_tag=f"SYN-{uuid.uuid4().hex[:8]}")
    db.add(asset)
    db.flush()
    return asset


def _evidence(db, asset, value, *, evidence_type="mac", source="manual", scope=None, status="confirmed", revoked=False):
    row = AssetIdentityEvidence(
        asset_id=asset.id if asset else None, evidence_type=evidence_type, normalised_value=value, source=source, source_scope=scope,
        status=status, first_observed_at=T0, last_observed_at=T1, confirmed_at=T0 if status == "confirmed" else None,
        revoked_at=T1 if revoked else None,
    )
    db.add(row)
    db.flush()
    return row


def _open(db, asset, address, *, vlan=None, started=T0, ended=None, provenance="manual", lease=None, record=None):
    row = AssetNetworkAssignment(
        asset_id=asset.id if asset else None, address=address, address_family=6 if ":" in address else 4, vlan_id=vlan.id if vlan else None,
        ip_address_id=record.id if record else None, dhcp_lease_id=lease.id if lease else None,
        started_at=started, ended_at=ended, provenance=provenance, status="confirmed", confirmed_at=started,
    )
    db.add(row)
    db.flush()
    return row


def _address():
    return f"198.51.100.{uuid.uuid4().int % 250 + 1}"


def _types(detections):
    return {(detection.finding_type, detection.subject) for detection in detections}


def _keys(db, finding_type):
    return {detection.subject for detection in run_check(db, finding_type, now=NOW).detections}


@contextmanager
def _borrow(session):
    yield session


def _factory(session):
    return lambda: _borrow(session)


def _audit(db, user=None):
    """One full audit on the real clock, so each run starts after earlier decisions."""
    run = data_integrity.queue_audit(db, user)
    run_id = data_integrity.claim_queued_run(db)
    assert run_id == run.id
    status = data_integrity.execute_run(run_id, _factory(db))
    db.expire_all()
    return db.get(DataIntegrityRun, run_id), status


def _finding(db, finding_type, subject):
    key = Detection(finding_type, subject, "", "", {}, None).key
    return db.query(DataIntegrityFinding).filter_by(finding_key=key).one_or_none()


# ------------------------------------------------------------- 5.1 duplicate confirmed MAC


def test_cross_source_duplicate_mac_is_detected_once(db):
    mac = _mac()
    first, second = _asset(db), _asset(db)
    _evidence(db, first, mac, source="discovery", scope="dns")
    _evidence(db, second, mac, source="dhcp", scope="provider:1")
    db.commit()
    detection = detect_subject(db, "duplicate_confirmed_mac", mac, now=NOW)
    assert detection is not None and detection.severity is None and detection.definition.severity == "critical"
    assert {owner["asset_id"] for owner in detection.evidence["owners"]} == {first.id, second.id}
    assert mac in _keys(db, "duplicate_confirmed_mac")


def test_many_macs_on_one_asset_and_one_mac_under_many_sources_are_legitimate(db):
    asset = _asset(db)
    mac, other = _mac(), _mac()
    _evidence(db, asset, mac, source="discovery", scope="dns")
    _evidence(db, asset, mac, source="dhcp", scope="provider:1")
    _evidence(db, asset, other, source="manual")
    db.commit()
    assert detect_subject(db, "duplicate_confirmed_mac", mac, now=NOW) is None
    assert detect_subject(db, "duplicate_confirmed_mac", other, now=NOW) is None


@pytest.mark.parametrize("variant", ["revoked", "suggested"])
def test_revoked_and_suggested_evidence_is_not_conflicting_ownership(db, variant):
    mac = _mac()
    owner, other = _asset(db), _asset(db)
    _evidence(db, owner, mac)
    _evidence(db, other, mac, status="revoked" if variant == "revoked" else "pending", revoked=variant == "revoked")
    db.commit()
    assert detect_subject(db, "duplicate_confirmed_mac", mac, now=NOW) is None


# ------------------------------------------------------------- 5.2 managed static assignment


def _affected(db):
    mac = _mac()
    vlan = _vlan(db)
    provider, admin, asset = _dhcp_asset_with_open_adoption_row(db, mac, vlan)
    record = _static_record(db, vlan, mac)
    asset.asset_tag = f"SYN-{uuid.uuid4().hex[:8]}"
    db.commit()
    return mac, vlan, provider, admin, asset, record


def test_dhcp_to_static_inconsistency_is_detected_and_clears_after_repair(db):
    mac, _vlan_row, _provider_row, _admin_row, asset, record = _affected(db)
    subject = f"{asset.id}|{mac}|{record.id}"
    detection = detect_subject(db, "managed_static_assignment", subject, now=NOW)
    assert detection is not None and detection.repairable and detection.bulk_repairable
    assert detection.evidence["plan"]["create_assignment"] is True
    assert [row["address"] for row in detection.evidence["plan"]["close_assignments"]] == [continuity.OLD_IP]
    repair_managed_static_assignment(db, asset_id=asset.id, asset_tag=asset.asset_tag, mac=mac, address=STATIC_IP, execute=True)
    assert detect_subject(db, "managed_static_assignment", subject, now=NOW) is None


def test_static_record_held_by_another_asset_needs_review_and_is_not_repairable(db):
    mac, vlan, _provider_row, _admin_row, asset, record = _affected(db)
    _open(db, _asset(db), STATIC_IP, vlan=vlan)
    db.commit()
    detection = detect_subject(db, "managed_static_assignment", f"{asset.id}|{mac}|{record.id}", now=NOW)
    assert detection.status == "needs_review" and not detection.repairable and not detection.bulk_repairable
    assert "assigned to another asset" in detection.evidence["blocked_reason"]


def test_hardcoded_example_values_are_not_special_cased():
    source = open(checks.__file__, encoding="utf-8").read() + open(data_integrity.__file__, encoding="utf-8").read()
    for value in ("HAL-0020", "fc:4c:ea:29:15:4a", "192.168.1.148", "192.168.1.199"):
        assert value not in source


# ------------------------------------------------------------- 5.3 duplicate active IP


def test_duplicate_current_ip_in_one_scope_is_detected(db):
    vlan = _vlan(db)
    address = _address()
    first, second = _asset(db), _asset(db)
    _open(db, first, address, vlan=vlan)
    _open(db, second, address)  # VLAN-less DHCP row shares every VLAN scope
    db.commit()
    detections = [d for d in run_check(db, "duplicate_active_ip", now=NOW).detections if d.evidence["address"] == address]
    assert len(detections) == 1 and {row["asset_id"] for row in detections[0].evidence["assignments"]} == {first.id, second.id}


def test_historical_reuse_and_separate_vlans_are_not_conflicts(db):
    address = _address()
    first, second, third = _asset(db), _asset(db), _asset(db)
    _open(db, first, address, started=T0, ended=T1)  # closed: legitimate reuse
    _open(db, second, address, vlan=_vlan(db), started=T1)
    _open(db, third, address, vlan=_vlan(db), started=T1)  # same private address on another VLAN
    db.commit()
    assert not [d for d in run_check(db, "duplicate_active_ip", now=NOW).detections if d.evidence["address"] == address]


# ------------------------------------------------------------- 5.4 DHCP client IDs


def test_numeric_client_ids_are_classified_by_confidence_and_genuine_ids_are_not_flagged(db):
    provider = _provider(db)
    mac = _mac()
    asset = _asset(db)
    _evidence(db, asset, mac)
    consistent = _evidence(db, asset, "4242", evidence_type="dhcp_client_id", source="dhcp", scope=f"provider:{provider.id}")
    reused = _evidence(db, asset, "179", evidence_type="dhcp_client_id", source="dhcp", scope=f"provider:{provider.id}")
    genuine = _evidence(db, asset, "01:02:00:00:5e:00:53:01", evidence_type="dhcp_client_id", source="dhcp")
    db.add_all([
        DHCPLeaseHistory(provider_id=provider.id, ip_address=_address(), mac_address=mac, provider_lease_id="4242", is_active=True),
        DHCPLeaseHistory(provider_id=provider.id, ip_address=_address(), mac_address=mac, provider_lease_id="179", is_active=True),
        DHCPLeaseHistory(provider_id=provider.id, ip_address=_address(), mac_address=_mac(), provider_lease_id="179", is_active=True),
    ])
    db.commit()
    low = detect_subject(db, "suspect_dhcp_client_id", str(consistent.id), now=NOW)
    high = detect_subject(db, "suspect_dhcp_client_id", str(reused.id), now=NOW)
    assert low.evidence["confidence"] == "low" and low.severity == "info"
    assert high.evidence["confidence"] == "high" and high.severity == "warning"
    assert detect_subject(db, "suspect_dhcp_client_id", str(genuine.id), now=NOW) is None


# ------------------------------------------------------------- 5.5 static hostnames


def _auto_filled(db, *, name="old-phone.example.invalid"):
    provider = _provider(db)
    vlan = _vlan(db)
    mac = _mac()
    record = IPAddress(address=_address(), vlan_id=vlan.id, assignment_type="Static", mac_address=mac, name=name)
    db.add(record)
    db.flush()
    client = DNSRecognisedDevice(
        provider_id=provider.id, logical_provider_key=f"syn-{uuid.uuid4().hex[:6]}", identity_key=f"mac:{mac}", identity_type="mac",
        identity_value=mac, hostname="new-phone.example.invalid", mac_address=mac, normalised_mac=mac, linked_ip_record_id=record.id,
        first_seen_at=T0, last_seen_at=T2,
    )
    db.add(client)
    db.flush()
    db.add(DNSClientEvent(dns_client_id=client.id, event_type="managed_record_updated", event_summary="Empty managed hostname populated from observation",
                          new_value=name, source=checks.AUTO_FILL_SOURCE))
    db.add(DHCPLeaseHistory(provider_id=provider.id, ip_address=record.address, mac_address=mac, hostname="dhcp-phone.example.invalid", is_active=True, last_seen_at=T2))
    db.commit()
    return record, client


def test_auto_filled_static_hostname_is_detected_with_observed_alternatives(db):
    record, _client = _auto_filled(db)
    detection = detect_subject(db, "static_hostname_auto_filled", str(record.id), now=NOW)
    assert detection is not None
    assert set(detection.evidence["observed_hostnames"]) == {"new-phone.example.invalid", "dhcp-phone.example.invalid"}


def test_administrator_renamed_static_hostname_is_not_flagged(db):
    record, _client = _auto_filled(db)
    record.name = "admin-chosen.example.invalid"
    db.commit()
    assert detect_subject(db, "static_hostname_auto_filled", str(record.id), now=NOW) is None


# ------------------------------------------------------------- 5.6 orphans and links


def test_orphaned_open_assignment_and_evidence_are_detected(db):
    assignment = _open(db, None, _address())
    evidence = _evidence(db, None, _mac())
    db.commit()
    assert detect_subject(db, "orphaned_open_assignment", str(assignment.id), now=NOW) is not None
    assert detect_subject(db, "orphaned_confirmed_evidence", str(evidence.id), now=NOW) is not None


def test_dns_client_linked_to_the_wrong_asset_is_a_definite_conflict(db):
    provider = _provider(db)
    mac = _mac()
    owner, wrong = _asset(db), _asset(db)
    _evidence(db, owner, mac)
    client = DNSRecognisedDevice(provider_id=provider.id, logical_provider_key="syn-link", identity_type="mac", identity_value=mac,
                                 normalised_mac=mac, mac_address=mac, hardware_asset_id=wrong.id, first_seen_at=T0, last_seen_at=T1)
    db.add(client)
    db.commit()
    detection = detect_subject(db, "dns_asset_link_conflict", str(client.id), now=NOW)
    assert detection.evidence["classification"] == "definite_conflict"
    assert [row["asset_id"] for row in detection.evidence["mac_owners"]] == [owner.id]


# ------------------------------------------------------------- 5.7 chronology


def test_invalid_interval_duplicate_open_rows_and_obsolete_leases_are_detected(db):
    asset = _asset(db)
    address = _address()
    backwards = _open(db, asset, _address(), started=T2, ended=T1)
    _open(db, asset, address, started=T0)
    _open(db, asset, address, started=T1)
    provider = _provider(db)
    lease = DHCPLeaseHistory(provider_id=provider.id, ip_address=_address(), mac_address=_mac(), is_active=False, ended_at=T2, last_seen_at=T1)
    db.add(lease)
    db.flush()
    obsolete = _open(db, asset, lease.ip_address, lease=lease, provenance="dhcp_reconciliation")
    db.commit()
    assert detect_subject(db, "invalid_assignment_interval", str(backwards.id), now=NOW) is not None
    assert any(subject.startswith(f"{asset.id}|{address}|") for subject in _keys(db, "duplicate_open_assignment"))
    found = detect_subject(db, "obsolete_dhcp_assignment", str(obsolete.id), now=NOW)
    assert found.evidence["reason"] == "lease_ended" and found.bulk_repairable


def test_legitimate_dhcp_history_is_not_flagged(db):
    asset = _asset(db)
    provider = _provider(db)
    old = DHCPLeaseHistory(provider_id=provider.id, ip_address=_address(), mac_address=_mac(), is_active=False, ended_at=T1, last_seen_at=T1)
    current = DHCPLeaseHistory(provider_id=provider.id, ip_address=_address(), mac_address=old.mac_address, is_active=True, last_seen_at=T2)
    db.add_all([old, current])
    db.flush()
    closed = _open(db, asset, old.ip_address, lease=old, started=T0, ended=T1, provenance="dhcp_reconciliation")
    live = _open(db, asset, current.ip_address, lease=current, started=T1, provenance="dhcp_reconciliation")
    db.commit()
    for finding_type in ("obsolete_dhcp_assignment", "invalid_assignment_interval", "assignment_provenance_mismatch"):
        assert detect_subject(db, finding_type, str(closed.id), now=NOW) is None
        assert detect_subject(db, finding_type, str(live.id), now=NOW) is None


# ------------------------------------------------------------- lifecycle


def _duplicate_mac(db):
    mac = _mac()
    first, second = _asset(db), _asset(db)
    _evidence(db, first, mac, source="discovery", scope="dns")
    rival = _evidence(db, second, mac, source="dhcp", scope="provider:1")
    db.commit()
    return mac, first, second, rival


def test_repeated_audits_keep_one_finding_and_resolve_when_fixed(db):
    mac, _first, _second, rival = _duplicate_mac(db)
    run, status = _audit(db)
    assert status in {"completed", "incomplete"} and run.active_slot is None
    finding = _finding(db, "duplicate_confirmed_mac", mac)
    assert finding.status == "needs_review" and finding.last_run_id == run.id
    second_run, _status = _audit(db)
    assert db.query(DataIntegrityFinding).filter_by(finding_key=finding.finding_key).count() == 1
    rival.status, rival.revoked_at = "revoked", NOW
    db.commit()
    _audit(db)
    db.refresh(finding)
    assert finding.status == "resolved" and finding.resolution == "not_detected"
    rival.status, rival.revoked_at = "confirmed", None
    db.commit()
    _audit(db)
    db.refresh(finding)
    assert finding.status == "needs_review" and finding.reopened_count == 1
    events = [row.event for row in db.query(DataIntegrityFindingEvent).filter_by(finding_id=finding.id).order_by(DataIntegrityFindingEvent.id)]
    assert events[0] == "detected" and "resolved" in events and events[-1] == "reopened"
    assert second_run.new_count == 0


def test_ignored_finding_stays_ignored_until_evidence_changes(db):
    mac, _first, _second, _rival = _duplicate_mac(db)
    admin = _admin(db)
    _audit(db)
    finding = _finding(db, "duplicate_confirmed_mac", mac)
    data_integrity.ignore_finding(db, finding, admin, "Synthetic lab duplicate, tracked elsewhere.")
    _audit(db)
    db.refresh(finding)
    assert finding.status == "ignored" and finding.ignored_by == admin.id
    _evidence(db, _asset(db), mac, source="manual")
    db.commit()
    _audit(db)
    db.refresh(finding)
    assert finding.status == "needs_review" and finding.ignore_reason is None


def test_ignore_requires_a_reason(db):
    mac, *_rest = _duplicate_mac(db)
    _audit(db)
    with pytest.raises(ValueError):
        data_integrity.ignore_finding(db, _finding(db, "duplicate_confirmed_mac", mac), _admin(db), "  no ")


def test_only_one_audit_may_be_queued_and_stale_runs_are_interrupted(db):
    run = data_integrity.queue_audit(db, None, now=NOW)
    with pytest.raises(data_integrity.AuditAlreadyRunning):
        data_integrity.queue_audit(db, None, now=NOW)
    assert data_integrity.recover_stale_runs(db, now=NOW + timedelta(minutes=11)) == 1
    db.refresh(run)
    assert run.status == "interrupted" and run.active_slot is None
    data_integrity.queue_audit(db, None, now=NOW + timedelta(minutes=12))


def test_a_failing_check_makes_the_run_incomplete_without_resolving_its_findings(db, monkeypatch):
    mac, _first, _second, rival = _duplicate_mac(db)
    _audit(db)
    rival.status = "revoked"
    db.commit()

    def broken(*_args, **_kwargs):
        raise RuntimeError("synthetic check failure")

    monkeypatch.setitem(checks.CHECKS, "duplicate_confirmed_mac", broken)
    monkeypatch.setattr(data_integrity, "CHECKS", checks.CHECKS)
    run, status = _audit(db)
    assert status == "incomplete" and any(error["check"] == "duplicate_confirmed_mac" for error in data_integrity._loads(run.errors_json, []))
    assert _finding(db, "duplicate_confirmed_mac", mac).status == "needs_review"
    assert data_integrity.summary(db, _admin(db))["freshness"] == "incomplete"


def test_audit_does_not_modify_source_records(db):
    _affected(db)
    _duplicate_mac(db)
    snapshot = lambda: (  # noqa: E731
        sorted((row.id, row.ended_at, row.status) for row in db.query(AssetNetworkAssignment)),
        sorted((row.id, row.status, row.revoked_at) for row in db.query(AssetIdentityEvidence)),
        sorted((row.id, row.name, row.assignment_type) for row in db.query(IPAddress)),
        db.query(DHCPLeaseHistory).count(), db.query(VLAN).count(),
    )
    before = snapshot()
    _audit(db)
    db.expire_all()
    assert snapshot() == before


def test_critical_findings_notify_once_until_their_evidence_changes(db):
    mac, *_rest = _duplicate_mac(db)
    _audit(db)
    query = db.query(NotificationOutbox).filter(NotificationOutbox.event_type == data_integrity.NOTIFICATION_EVENT)
    first = query.count()
    assert first >= 1
    _audit(db)
    assert query.count() == first
    _evidence(db, _asset(db), mac, source="manual")
    db.commit()
    _audit(db)
    assert query.count() == first + 1


def test_audit_request_is_audited(db):
    admin = _admin(db)
    run = data_integrity.queue_audit(db, admin, now=NOW)
    assert db.query(AuditLog).filter(AuditLog.action == "data_integrity_audit_requested", AuditLog.entity_id == str(run.id)).count() == 1


def test_visibility_follows_module_grants(db):
    admin = _admin(db)
    viewer = _admin(db)
    viewer.role = "viewer"
    db.commit()
    assert "duplicate_confirmed_mac" in data_integrity.visible_types(db, admin)
    assert data_integrity.visible_types(db, viewer) == []


# ------------------------------------------------------------- scheduling (Stage E)


def test_scheduled_audit_is_due_by_interval_and_can_be_disabled(db):
    admin = _admin(db)
    assert data_integrity.scheduled_audit_due(db, now=NOW)
    run = data_integrity.queue_audit(db, None, trigger="scheduled", now=NOW)
    run.status, run.active_slot = "completed", None
    db.commit()
    assert not data_integrity.scheduled_audit_due(db, now=NOW + timedelta(hours=23))
    assert data_integrity.scheduled_audit_due(db, now=NOW + timedelta(hours=24))
    data_integrity.update_schedule(db, admin, schedule_hours="0", notify_critical=True)
    assert not data_integrity.scheduled_audit_due(db, now=NOW + timedelta(days=30))


def test_scheduled_worker_pass_audits_read_only_and_never_repairs(db):
    _affected(db)
    _duplicate_mac(db)
    before = (
        sorted((row.id, row.ended_at) for row in db.query(AssetNetworkAssignment)),
        sorted((row.id, row.status) for row in db.query(AssetIdentityEvidence)),
    )
    data_integrity.run_data_integrity_pass(_factory(db))
    db.expire_all()
    run = db.query(DataIntegrityRun).order_by(DataIntegrityRun.id.desc()).first()
    assert run.trigger == "scheduled" and run.status in {"completed", "incomplete"} and run.active_slot is None
    assert db.query(DataIntegrityFinding).filter(DataIntegrityFinding.finding_type == "managed_static_assignment").count() >= 1
    after = (
        sorted((row.id, row.ended_at) for row in db.query(AssetNetworkAssignment)),
        sorted((row.id, row.status) for row in db.query(AssetIdentityEvidence)),
    )
    assert after == before
    assert db.query(AuditLog).filter(AuditLog.action.in_(("repair", "data_integrity_repair"))).count() == 0
    data_integrity.run_data_integrity_pass(_factory(db))  # not due again: no second run
    assert db.query(DataIntegrityRun).count() == 1


def test_notifications_respect_the_administrator_setting(db):
    _duplicate_mac(db)
    data_integrity.update_schedule(db, _admin(db), schedule_hours="24", notify_critical=False)
    _audit(db)
    assert db.query(NotificationOutbox).filter(NotificationOutbox.event_type == data_integrity.NOTIFICATION_EVENT).count() == 0
