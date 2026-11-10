"""Data Integrity remediation: previews, transactional repairs, verification, bulk (Stages C and D).

Runs on SQLite and, when KAYA_TEST_POSTGRES_URL is set, PostgreSQL. The
PostgreSQL-only tests exercise concurrent execution against committed data.
All data is synthetic.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

import app.services.data_integrity as data_integrity
import app.services.data_integrity_repairs as repairs
import tests.test_dhcp_identity_continuity as continuity
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    AuditLog,
    DataIntegrityFinding,
    DataIntegrityFindingEvent,
    DHCPLeaseHistory,
    DNSClientEvent,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    User,
    UserModulePermission,
    VLAN,
)
from app.services.asset_identity import confirm_identity_evidence, reconcile_dhcp_assignment
from app.services.data_integrity_repairs import BULK_CONFIRMATION, RepairRefused, StaleRepair, execute_bulk, execute_repair, preview_bulk, preview_repair
from tests.test_asset_identity_integrity import _pg_factory
from tests.test_data_integrity import _address, _affected, _asset, _audit, _auto_filled, _evidence, _finding, _open
from tests.test_dhcp_identity_continuity import NOW, OLD_IP, STATIC_IP, T0, T1, _admin, _mac, _provider, _rows

db = continuity.db


def _state(db):
    db.expire_all()
    return (
        sorted((row.id, row.asset_id, row.address, row.ended_at) for row in db.query(AssetNetworkAssignment)),
        sorted((row.id, row.status, row.revoked_at) for row in db.query(AssetIdentityEvidence)),
        sorted((row.id, row.name) for row in db.query(IPAddress)),
        db.query(DHCPLeaseHistory).count(),
    )


def _static(db):
    mac, vlan, provider, admin, asset, record = _affected(db)
    _audit(db)
    return _finding(db, "managed_static_assignment", f"{asset.id}|{mac}|{record.id}"), asset, admin, mac, record


def _duplicate_mac(db):
    mac = _mac()
    owner, other = _asset(db), _asset(db)
    _evidence(db, owner, mac, source="discovery", scope="dns")
    rival = _evidence(db, other, mac, source="dhcp", scope="provider:1")
    db.commit()
    _audit(db)
    return _finding(db, "duplicate_confirmed_mac", mac), owner, other, rival, mac


# ------------------------------------------------------------- managed static repair


def test_preview_reports_the_plan_and_changes_nothing(db):
    finding, asset, admin, _mac_value, record = _static(db)
    before = _state(db)
    preview = preview_repair(db, admin, finding, "repair_static_assignment")
    assert preview["state"] == "ready" and len(preview["preview_token"]) == 64
    assert preview["changes"][0]["proposed"].startswith(STATIC_IP)
    assert [row["address"] for row in preview["closes"]] == [OLD_IP]
    assert any("DHCP lease history" in text for text in preview["preserved"])
    assert _state(db) == before


def test_repair_is_transactional_verified_audited_and_preserves_history(db):
    finding, asset, admin, _mac_value, _record = _static(db)
    leases = db.query(DHCPLeaseHistory).count()
    evidence = sorted(row.id for row in db.query(AssetIdentityEvidence).filter_by(asset_id=asset.id))
    preview = preview_repair(db, admin, finding, "repair_static_assignment")
    result = execute_repair(db, admin, finding.id, "repair_static_assignment", {}, preview["preview_token"])
    assert result["outcome"] == "applied" and result["verified"] is True
    db.expire_all()
    assert db.get(DataIntegrityFinding, finding.id).status == "resolved"
    rows = _rows(db, asset)
    assert [row.address for row in rows if row.ended_at is None] == [STATIC_IP]
    assert OLD_IP in [row.address for row in rows if row.ended_at is not None]  # closed, never deleted
    assert db.query(DHCPLeaseHistory).count() == leases
    assert sorted(row.id for row in db.query(AssetIdentityEvidence).filter_by(asset_id=asset.id)) == evidence
    assert db.get(HardwareAsset, asset.id) is not None
    actions = {row.action for row in db.query(AuditLog).filter(AuditLog.user_id == admin.id)}
    assert {"repair", "data_integrity_repair"} <= actions
    events = [row.event for row in db.query(DataIntegrityFindingEvent).filter_by(finding_id=finding.id)]
    assert "repaired" in events and events[-1] == "resolved"


def test_retry_is_idempotent(db):
    finding, asset, admin, *_rest = _static(db)
    token = preview_repair(db, admin, finding, "repair_static_assignment")["preview_token"]
    execute_repair(db, admin, finding.id, "repair_static_assignment", {}, token)
    after = _state(db)
    retry = execute_repair(db, admin, finding.id, "repair_static_assignment", {}, token)
    assert retry["outcome"] == "not_active"
    finding_row = db.get(DataIntegrityFinding, finding.id)
    finding_row.status = "open"  # even if a client still believes it is open, nothing is duplicated
    db.commit()
    assert execute_repair(db, admin, finding.id, "repair_static_assignment", {}, token)["outcome"] == "already_resolved"
    assert _state(db) == after


def test_stale_preview_is_rejected_without_changes(db):
    finding, asset, admin, _mac_value, record = _static(db)
    token = preview_repair(db, admin, finding, "repair_static_assignment")["preview_token"]
    _open(db, asset, "198.51.100.250", started=T1, provenance="dhcp_reconciliation")
    db.add(DHCPLeaseHistory(provider_id=db.query(DHCPLeaseHistory).first().provider_id, ip_address="198.51.100.250", mac_address=record.mac_address, is_active=True))
    db.commit()
    before = _state(db)
    with pytest.raises(StaleRepair):
        execute_repair(db, admin, finding.id, "repair_static_assignment", {}, token)
    assert _state(db) == before
    assert db.query(AuditLog).filter(AuditLog.action == "data_integrity_repair_failed").count() == 1
    assert db.query(DataIntegrityFindingEvent).filter_by(finding_id=finding.id, event="repair_failed").count() == 1


def test_audit_failure_rolls_the_repair_back(db, monkeypatch):
    finding, asset, admin, *_rest = _static(db)
    token = preview_repair(db, admin, finding, "repair_static_assignment")["preview_token"]
    before = _state(db)
    real = data_integrity.write_audit

    def failing(session, user, action, *args, **kwargs):
        return None if action == "data_integrity_repair" else real(session, user, action, *args, **kwargs)

    monkeypatch.setattr(data_integrity, "write_audit", failing)
    with pytest.raises(RuntimeError):
        execute_repair(db, admin, finding.id, "repair_static_assignment", {}, token)
    assert _state(db) == before
    assert db.get(DataIntegrityFinding, finding.id).status == "open"


def test_repair_requires_the_capability_and_the_administrator_role(db):
    finding, _asset_row, admin, *_rest = _static(db)
    token = preview_repair(db, admin, finding, "repair_static_assignment")["preview_token"]
    db.query(UserModulePermission).filter_by(user_id=admin.id, module_key="data_integrity.repair").update({"allowed": False})
    db.commit()
    with pytest.raises(PermissionError):
        execute_repair(db, admin, finding.id, "repair_static_assignment", {}, token)
    db.query(UserModulePermission).filter_by(user_id=admin.id, module_key="data_integrity.repair").update({"allowed": True})
    admin.role = "editor"
    db.commit()
    with pytest.raises(PermissionError):
        execute_repair(db, admin, finding.id, "repair_static_assignment", {}, token)


# ------------------------------------------------------------- ownership decisions


def test_mac_owner_decision_requires_a_choice_and_typed_confirmation(db):
    finding, owner, other, rival, mac = _duplicate_mac(db)
    admin = _admin(db)
    with pytest.raises(RepairRefused):
        preview_repair(db, admin, finding, "choose_mac_owner", {})
    with pytest.raises(RepairRefused):
        preview_repair(db, admin, finding, "choose_mac_owner", {"owner_asset_id": 999999})
    preview = preview_repair(db, admin, finding, "choose_mac_owner", {"owner_asset_id": owner.id})
    assert preview["high_risk"] and preview["confirmation_text"] == owner.asset_tag
    before = _state(db)
    with pytest.raises(RepairRefused):
        execute_repair(db, admin, finding.id, "choose_mac_owner", {"owner_asset_id": owner.id}, preview["preview_token"], confirmation="wrong")
    assert _state(db) == before
    result = execute_repair(db, admin, finding.id, "choose_mac_owner", {"owner_asset_id": owner.id}, preview["preview_token"], confirmation=owner.asset_tag)
    assert result["verified"] is True
    db.refresh(rival)
    assert rival.status == "revoked" and rival.revoked_at is not None  # kept as history
    with pytest.raises(ValueError):
        confirm_identity_evidence(db, admin, asset_id=other.id, evidence_type="mac", value=mac, source="manual")


def test_duplicate_ip_owner_decision_closes_the_other_assignment(db):
    address = _address()
    first, second = _asset(db), _asset(db)
    keep = _open(db, first, address)
    drop = _open(db, second, address)
    db.commit()
    _audit(db)
    finding = db.query(DataIntegrityFinding).filter(DataIntegrityFinding.finding_type == "duplicate_active_ip", DataIntegrityFinding.ip_address == address).one()
    admin = _admin(db)
    preview = preview_repair(db, admin, finding, "keep_assignment", {"keep_assignment_id": keep.id})
    assert [row["assignment_id"] for row in preview["closes"]] == [drop.id] and preview["confirmation_text"] == first.asset_tag
    result = execute_repair(db, admin, finding.id, "keep_assignment", {"keep_assignment_id": keep.id}, preview["preview_token"], confirmation=first.asset_tag)
    assert result["verified"] is True
    db.expire_all()
    assert db.get(AssetNetworkAssignment, drop.id).ended_at is not None and db.get(AssetNetworkAssignment, keep.id).ended_at is None


# ------------------------------------------------------------- other actions


def test_hostname_correction_accepts_only_an_observed_hostname(db):
    record, client = _auto_filled(db)
    _audit(db)
    finding = _finding(db, "static_hostname_auto_filled", str(record.id))
    admin = _admin(db)
    with pytest.raises(RepairRefused):
        preview_repair(db, admin, finding, "replace_hostname", {"hostname": "attacker-chosen.example.invalid"})
    preview = preview_repair(db, admin, finding, "replace_hostname", {"hostname": "new-phone.example.invalid"})
    result = execute_repair(db, admin, finding.id, "replace_hostname", {"hostname": "new-phone.example.invalid"}, preview["preview_token"])
    assert result["verified"] is True
    db.refresh(record)
    assert record.name == "new-phone.example.invalid"
    assert db.query(DNSClientEvent).filter_by(dns_client_id=client.id, source=repairs.HOSTNAME_SOURCE).count() == 1


def _hostname_finding(db):
    """An auto-filled Static record whose MAC is confirmed for exactly one asset."""
    record, _client = _auto_filled(db)
    asset = _asset(db)
    _evidence(db, asset, record.mac_address)
    db.commit()
    _audit(db)
    return record, asset, _finding(db, "static_hostname_auto_filled", str(record.id))


def _administrator_hostnames(db, asset):
    return db.query(AssetIdentityEvidence).filter_by(asset_id=asset.id, evidence_type="hostname", source="administrator").all()


def test_set_asset_hostname_repair_is_attributed_to_the_repairing_administrator(db):
    record, asset, finding = _hostname_finding(db)
    admin, other_admin = _admin(db), _admin(db)
    preview = preview_repair(db, admin, finding, "set_asset_hostname", {"hostname": "Phone.Example.Invalid"})
    assert preview["state"] == "ready"
    result = execute_repair(db, admin, finding.id, "set_asset_hostname", {"hostname": "Phone.Example.Invalid"}, preview["preview_token"])
    assert result["outcome"] == "applied"
    assert result["affected"]["hostname"] == "phone.example.invalid"
    db.expire_all()
    (row,) = _administrator_hostnames(db, asset)
    assert (row.normalised_value, row.status, row.confirmed_by) == ("phone.example.invalid", "confirmed", admin.id)
    audits = db.query(AuditLog).filter(AuditLog.action.in_(["set_hostname", "data_integrity_repair"]), AuditLog.user_id.in_([admin.id, other_admin.id])).all()
    assert sorted((audit.action, audit.user_id) for audit in audits) == [("data_integrity_repair", admin.id), ("set_hostname", admin.id)]
    assert db.get(IPAddress, record.id).name == "old-phone.example.invalid"   # only the asset's preference changes


def test_set_asset_hostname_rejects_an_invalid_hostname_as_a_refusal(db):
    _record, asset, finding = _hostname_finding(db)
    with pytest.raises(RepairRefused):
        preview_repair(db, _admin(db), finding, "set_asset_hostname", {"hostname": "not a hostname"})
    db.rollback()
    assert _administrator_hostnames(db, asset) == []


def test_set_asset_hostname_requires_the_repair_permission(db):
    _record, asset, finding = _hostname_finding(db)
    admin = _admin(db)
    token = preview_repair(db, admin, finding, "set_asset_hostname", {"hostname": "phone.example.invalid"})["preview_token"]
    db.query(UserModulePermission).filter_by(user_id=admin.id, module_key="data_integrity.repair").delete()
    db.commit()
    with pytest.raises(PermissionError):
        execute_repair(db, admin, finding.id, "set_asset_hostname", {"hostname": "phone.example.invalid"}, token)
    db.rollback()
    assert _administrator_hostnames(db, asset) == []


def test_set_asset_hostname_audit_failure_rolls_back(db, monkeypatch):
    import app.services.asset_identity as asset_identity

    _record, asset, finding = _hostname_finding(db)
    admin = _admin(db)
    token = preview_repair(db, admin, finding, "set_asset_hostname", {"hostname": "phone.example.invalid"})["preview_token"]
    monkeypatch.setattr(asset_identity, "write_audit", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError):
        execute_repair(db, admin, finding.id, "set_asset_hostname", {"hostname": "phone.example.invalid"}, token)
    monkeypatch.undo()
    db.rollback()
    db.expire_all()
    assert _administrator_hostnames(db, asset) == []
    assert db.get(DataIntegrityFinding, finding.id).status != "resolved"


def test_set_asset_hostname_for_a_deleted_asset_is_stale_not_a_crash(db, monkeypatch):
    _record, _asset_row, finding = _hostname_finding(db)
    admin = _admin(db)
    token = preview_repair(db, admin, finding, "set_asset_hostname", {"hostname": "phone.example.invalid"})["preview_token"]

    def vanished(*args, **kwargs):
        raise ValueError("Hardware asset not found.")

    monkeypatch.setattr(repairs, "set_administrator_hostname", vanished)
    with pytest.raises(StaleRepair):
        execute_repair(db, admin, finding.id, "set_asset_hostname", {"hostname": "phone.example.invalid"}, token)


def test_retaining_a_hostname_survives_later_audits(db):
    record, _client = _auto_filled(db)
    _audit(db)
    finding = _finding(db, "static_hostname_auto_filled", str(record.id))
    repairs.acknowledge_finding(db, _admin(db), finding, "retain_hostname", "Confirmed with the device owner.")
    _audit(db)
    db.refresh(finding)
    assert finding.status == "ignored" and finding.ignore_reason.startswith("Retained the administrator-managed hostname")
    assert record.name == "old-phone.example.invalid"


def test_suspect_client_id_can_be_revoked_and_lease_history_is_kept(db):
    provider = _provider(db)
    asset = _asset(db)
    mac = _mac()
    _evidence(db, asset, mac)
    evidence = _evidence(db, asset, "179", evidence_type="dhcp_client_id", source="dhcp", scope=f"provider:{provider.id}")
    db.add(DHCPLeaseHistory(provider_id=provider.id, ip_address=_address(), mac_address=_mac(), provider_lease_id="179", is_active=True))
    db.commit()
    _audit(db)
    finding = _finding(db, "suspect_dhcp_client_id", str(evidence.id))
    admin = _admin(db)
    leases = db.query(DHCPLeaseHistory).count()
    preview = preview_repair(db, admin, finding, "revoke_client_id")
    assert execute_repair(db, admin, finding.id, "revoke_client_id", {}, preview["preview_token"])["verified"] is True
    db.refresh(evidence)
    assert evidence.status == "revoked" and db.query(DHCPLeaseHistory).count() == leases


def test_dns_client_relink_moves_the_link_to_the_mac_owner(db):
    provider = _provider(db)
    mac = _mac()
    owner, wrong = _asset(db), _asset(db)
    _evidence(db, owner, mac)
    client = DNSRecognisedDevice(provider_id=provider.id, logical_provider_key="syn-relink", identity_type="mac", identity_value=mac,
                                 normalised_mac=mac, mac_address=mac, hardware_asset_id=wrong.id, first_seen_at=T0, last_seen_at=T1)
    db.add(client)
    db.commit()
    _audit(db)
    finding = _finding(db, "dns_asset_link_conflict", str(client.id))
    admin = _admin(db)
    preview = preview_repair(db, admin, finding, "relink_dns_client")
    execute_repair(db, admin, finding.id, "relink_dns_client", {}, preview["preview_token"], confirmation=owner.asset_tag)
    db.refresh(client)
    assert client.hardware_asset_id == owner.id


def test_orphan_and_interval_corrections_preserve_rows(db):
    orphan = _open(db, None, _address())
    asset = _asset(db)
    backwards = _open(db, asset, _address(), started=T1, ended=T0)
    db.commit()
    _audit(db)
    admin = _admin(db)
    for finding_type, subject, action in (("orphaned_open_assignment", orphan.id, "close_orphan_assignment"), ("invalid_assignment_interval", backwards.id, "clamp_assignment_interval")):
        finding = _finding(db, finding_type, str(subject))
        preview = preview_repair(db, admin, finding, action)
        assert execute_repair(db, admin, finding.id, action, {}, preview["preview_token"])["verified"] is True
    db.expire_all()
    assert db.get(AssetNetworkAssignment, orphan.id).ended_at is not None
    row = db.get(AssetNetworkAssignment, backwards.id)
    assert row.ended_at == row.started_at


# ------------------------------------------------------------- bulk


def test_bulk_preview_offers_only_deterministic_repairs(db):
    static, *_rest = _static(db)
    duplicate, *_more = _duplicate_mac(db)
    admin = _admin(db)
    preview = preview_bulk(db, admin, [static.id, duplicate.id])
    assert [item["finding_id"] for item in preview["items"]] == [static.id]
    assert [row["finding_id"] for row in preview["skipped"]] == [duplicate.id]


def _obsolete(db):
    provider = _provider(db)
    asset = _asset(db)
    lease = DHCPLeaseHistory(provider_id=provider.id, ip_address=_address(), mac_address=_mac(), is_active=False, ended_at=T1, last_seen_at=T0)
    db.add(lease)
    db.flush()
    row = _open(db, asset, lease.ip_address, lease=lease, started=T0, provenance="dhcp_reconciliation")
    db.commit()
    return asset, lease, row


def test_bulk_execution_reports_each_item_and_never_claims_partial_success_as_complete(db):
    static, static_asset, admin, *_rest = _static(db)
    _asset_row, lease, obsolete_row = _obsolete(db)
    _audit(db)
    obsolete = _finding(db, "obsolete_dhcp_assignment", str(obsolete_row.id))
    preview = preview_bulk(db, admin, [static.id, obsolete.id])
    assert sorted(item["finding_id"] for item in preview["items"]) == sorted([static.id, obsolete.id])
    tokens = {item["finding_id"]: item["preview_token"] for item in preview["items"]}
    with pytest.raises(RepairRefused):
        execute_bulk(db, admin, [{"finding_id": key, "preview_token": value} for key, value in tokens.items()])
    lease.last_seen_at = T1  # the lease evidence changes after the preview
    db.commit()
    result = execute_bulk(db, admin, [{"finding_id": key, "preview_token": value} for key, value in tokens.items()], confirmation=BULK_CONFIRMATION)
    outcomes = {row["finding_id"]: row["outcome"] for row in result["results"]}
    assert outcomes == {static.id: "applied", obsolete.id: "stale"}
    assert result["status"] == "partial" and result["succeeded"] == 1
    assert continuity._open(db, static_asset) == [STATIC_IP]
    db.expire_all()
    assert db.get(AssetNetworkAssignment, obsolete_row.id).ended_at is None  # the stale item changed nothing
    retry = preview_bulk(db, admin, [obsolete.id])
    again = execute_bulk(db, admin, [{"finding_id": obsolete.id, "preview_token": retry["items"][0]["preview_token"]}], confirmation=BULK_CONFIRMATION)
    assert again["status"] == "completed"
    db.expire_all()
    assert db.get(AssetNetworkAssignment, obsolete_row.id).ended_at == T1  # closed at the lease's last observation


# ------------------------------------------------------------- PostgreSQL concurrency


def _committed_static(factory):
    """An affected asset committed for real, so concurrent sessions can see it."""
    with factory() as session:
        mac, vlan, provider, admin, asset, record = _affected(session)
        ids = {"admin": admin.id, "asset": asset.id, "provider": provider.id, "vlan": vlan.id, "record": record.id, "mac": mac}
        ids["run"] = data_integrity.queue_audit(session, None).id
        data_integrity.claim_queued_run(session)
    try:
        data_integrity.execute_run(ids["run"], factory)
        with factory() as session:
            finding = _finding(session, "managed_static_assignment", f"{ids['asset']}|{mac}|{ids['record']}")
            ids["finding"] = finding.id
            ids["token"] = preview_repair(session, session.get(User, ids["admin"]), finding, "repair_static_assignment")["preview_token"]
            ids["lease"] = session.query(DHCPLeaseHistory.id).filter_by(provider_id=ids["provider"]).order_by(DHCPLeaseHistory.id.desc()).scalar()
    except Exception:
        _cleanup(factory, ids)
        raise
    return ids


def _cleanup(factory, ids):
    with factory.begin() as session:
        session.query(DataIntegrityFinding).delete(synchronize_session=False)
        session.query(data_integrity.DataIntegrityRun).delete(synchronize_session=False)
        session.query(AuditLog).filter(AuditLog.user_id == ids["admin"]).delete(synchronize_session=False)
        session.query(AssetNetworkAssignment).filter_by(asset_id=ids["asset"]).delete(synchronize_session=False)
        session.query(AssetIdentityEvidence).filter_by(asset_id=ids["asset"]).delete(synchronize_session=False)
        session.query(DHCPLeaseHistory).filter_by(provider_id=ids["provider"]).delete(synchronize_session=False)
        session.query(IPAddress).filter_by(vlan_id=ids["vlan"]).delete(synchronize_session=False)
        session.query(HardwareAsset).filter_by(id=ids["asset"]).delete(synchronize_session=False)
        session.query(VLAN).filter_by(id=ids["vlan"]).delete(synchronize_session=False)
        session.query(UserModulePermission).filter_by(user_id=ids["admin"]).delete(synchronize_session=False)
        session.query(User).filter_by(id=ids["admin"]).delete(synchronize_session=False)
        session.query(continuity.DNSProviderConfig).filter_by(id=ids["provider"]).delete(synchronize_session=False)


def test_postgres_concurrent_repairs_of_one_finding_apply_once():
    engine, factory = _pg_factory()
    ids = _committed_static(factory)
    try:
        barrier = threading.Barrier(2)

        def worker(_index):
            with factory() as session:
                admin = session.get(User, ids["admin"])
                barrier.wait()
                try:
                    return execute_repair(session, admin, ids["finding"], "repair_static_assignment", {}, ids["token"])["outcome"]
                except StaleRepair:
                    return "stale"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = sorted(pool.map(worker, range(2)))
        assert outcomes.count("applied") == 1 and set(outcomes) <= {"applied", "already_resolved", "not_active", "stale"}
        with factory() as session:
            open_rows = session.query(AssetNetworkAssignment).filter_by(asset_id=ids["asset"], ended_at=None, status="confirmed").all()
            assert [row.address for row in open_rows] == [STATIC_IP]
    finally:
        _cleanup(factory, ids)
        engine.dispose()


def test_postgres_dhcp_reconciliation_during_a_repair_cannot_reclaim_the_old_address():
    engine, factory = _pg_factory()
    ids = _committed_static(factory)
    try:
        barrier = threading.Barrier(2)

        def repair():
            with factory() as session:
                admin = session.get(User, ids["admin"])
                barrier.wait()
                return execute_repair(session, admin, ids["finding"], "repair_static_assignment", {}, ids["token"])["outcome"]

        def reconcile():
            with factory() as session:
                barrier.wait()
                result = reconcile_dhcp_assignment(session, session.get(DHCPLeaseHistory, ids["lease"]), observed_at=NOW)
                session.commit()
                return result

        with ThreadPoolExecutor(max_workers=2) as pool:
            repaired, reconciled = pool.submit(repair), pool.submit(reconcile)
            assert repaired.result(timeout=30) == "applied"
            assert reconciled.result(timeout=30) in {"renewed", "superseded", "reassigned", "review_required"}
        with factory() as session:
            open_rows = session.query(AssetNetworkAssignment).filter_by(asset_id=ids["asset"], ended_at=None, status="confirmed").all()
            assert STATIC_IP in [row.address for row in open_rows]
            assert OLD_IP not in [row.address for row in open_rows]
    finally:
        _cleanup(factory, ids)
        engine.dispose()
