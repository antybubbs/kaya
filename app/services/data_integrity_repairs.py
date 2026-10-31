"""Previewed, locked, audited remediation for Data Integrity findings.

Workflow: a preview re-runs the finding's check against current data, builds
the exact change plan and returns a token over that plan. Execution takes the
shared identity locks in the global order (MAC, then asset, then address; on
SQLite the single writer lock), re-runs the check, rebuilds the plan and
refuses unless its token matches the preview, so a preview never authorises a
change to records that have since changed. The change, its mandatory audit
record and the finding history commit together or not at all. The finding is
then re-checked against fresh data and marked Resolved only if the
inconsistency is gone. Retries are idempotent: a finding that is no longer
detected makes no change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import re

from sqlalchemy.orm import Session

from app.db.dialect import begin_serialised_write
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DataIntegrityFinding,
    DNSClientEvent,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    User,
)
from app.services.asset_identity import (
    _assignment_lock_key,
    dhcp_address_lock_key,
    lock_identity_scope,
    normalise_hostname_value,
    repair_managed_static_assignment,
    set_administrator_hostname,
)
from app.services.audit import write_audit
from app.services.data_integrity import (
    ACTIVE_STATUSES,
    _hash,
    _now,
    apply_detection,
    audit_or_fail,
    finding_subject,
    record_event,
    resolve_finding,
    visible_finding,
)
from app.services.data_integrity_checks import FINDING_TYPES, Detection, detect_subject
from app.services.modules import has_capability

REPAIR_CAPABILITY = "data_integrity.repair"
MAX_BULK = 50
BULK_CONFIRMATION = "APPLY BULK REPAIRS"
HOSTNAME_SOURCE = "data integrity hostname correction"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class RepairRefused(ValueError):
    """The repair is not valid for the finding's current evidence."""


class StaleRepair(RepairRefused):
    """The records changed after the preview; a fresh preview is required."""


@dataclass(frozen=True)
class RepairAction:
    key: str
    label: str
    finding_types: tuple[str, ...]
    high_risk: bool = False
    description: str = ""


ACTIONS = {
    row.key: row
    for row in (
        RepairAction("choose_mac_owner", "Assign MAC owner", ("duplicate_confirmed_mac",), True,
                     "Keep the MAC on the selected asset and revoke its confirmed MAC evidence on every other asset."),
        RepairAction("repair_static_assignment", "Repair assignment", ("managed_static_assignment",), False,
                     "Make the managed static address current and close obsolete DHCP-derived assignments at repair time."),
        RepairAction("keep_assignment", "Keep selected assignment", ("duplicate_active_ip", "duplicate_open_assignment"), True,
                     "Keep the selected assignment open and close the others at repair time."),
        RepairAction("close_obsolete_dhcp", "Close obsolete assignment", ("obsolete_dhcp_assignment",), False,
                     "Close the assignment at the lease's last observation."),
        RepairAction("revoke_client_id", "Revoke client ID", ("suspect_dhcp_client_id",), False,
                     "Revoke this DHCP client-ID evidence. Lease history is kept."),
        RepairAction("replace_hostname", "Replace hostname", ("static_hostname_auto_filled",), False,
                     "Replace the managed name with the selected observed hostname."),
        RepairAction("set_asset_hostname", "Set asset hostname", ("static_hostname_auto_filled",), False,
                     "Set the linked asset's administrator-confirmed hostname."),
        RepairAction("clear_hostname", "Clear hostname", ("static_hostname_auto_filled",), False,
                     "Clear the automatically copied managed name."),
        RepairAction("relink_dns_client", "Link to MAC owner", ("dns_asset_link_conflict",), True,
                     "Link the DNS client to the asset that holds its MAC as confirmed evidence."),
        RepairAction("unlink_dns_client", "Unlink DNS client", ("dns_asset_link_conflict",), False,
                     "Remove the DNS client's asset link. DNS history is kept."),
        RepairAction("close_orphan_assignment", "Close assignment", ("orphaned_open_assignment",), False,
                     "Close the orphaned assignment at repair time."),
        RepairAction("revoke_orphan_evidence", "Revoke evidence", ("orphaned_confirmed_evidence",), False,
                     "Revoke the orphaned confirmed evidence."),
        RepairAction("clamp_assignment_interval", "Correct interval", ("invalid_assignment_interval",), False,
                     "Set the end time to the start time; the interval stays empty."),
    )
}
ACKNOWLEDGEMENTS = {
    "retain_client_id": ("suspect_dhcp_client_id", "Retained as a valid DHCP client identifier"),
    "retain_hostname": ("static_hostname_auto_filled", "Retained the administrator-managed hostname"),
}
BULK_ACTIONS = {"repair_static_assignment", "close_obsolete_dhcp"}
assert all(set(action.finding_types) <= set(FINDING_TYPES) for action in ACTIONS.values())


@dataclass
class Plan:
    material: dict
    changes: list = field(default_factory=list)
    closes: list = field(default_factory=list)
    revokes: list = field(default_factory=list)
    preserved: list = field(default_factory=list)
    risks: list = field(default_factory=list)
    confirmation: str | None = None
    macs: list = field(default_factory=list)
    asset_ids: list = field(default_factory=list)
    assignment_keys: list = field(default_factory=list)


def can_repair(db: Session, user: User | None) -> bool:
    return bool(user and user.is_active and user.role == "admin" and has_capability(db, user, REPAIR_CAPABILITY))


def _asset_name(info: dict | None) -> str:
    info = info or {}
    return info.get("asset_tag") or info.get("asset_name") or f"Asset #{info.get('asset_id')}"


def _confirmation_for(info: dict | None) -> str:
    info = info or {}
    return (info.get("asset_tag") or f"asset {info.get('asset_id')}").strip()


def _int(params: dict, name: str) -> int:
    value = params.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RepairRefused(f"Select a valid {name.replace('_', ' ')}.")
    return value


def _assignment_keys(rows: list[dict]) -> list[int]:
    keys = []
    for row in rows:
        keys.append(_assignment_lock_key(row["address"], row["address_family"], row["vlan_id"], row["source_id"], row["exporter_identity"]))
        keys.append(dhcp_address_lock_key(row["address"], row["address_family"]))
    return keys


def _closing(row: dict, now: datetime, end: datetime | None = None) -> dict:
    started = datetime.fromisoformat(row["started_at"])
    return {"assignment_id": row["assignment_id"], "asset_id": row.get("asset_id"), "address": row["address"],
            "provenance": row["provenance"], "started_at": row["started_at"], "ended_at": (end or max(started, now)).isoformat()}


def _plan(db: Session, finding: DataIntegrityFinding, detection: Detection, action: str, params: dict, now: datetime) -> Plan:
    evidence = detection.evidence
    if action == "choose_mac_owner":
        owner_id = _int(params, "owner_asset_id")
        owners = {owner["asset_id"]: owner for owner in evidence["owners"]}
        if owner_id not in owners:
            raise RepairRefused("The selected owner is not one of the assets holding this MAC.")
        revoke = [{"evidence_id": row["evidence_id"], "asset_id": asset_id, "asset": _asset_name(owners[asset_id]), "source": row["source"], "source_scope": row["source_scope"]}
                  for asset_id, owner in owners.items() if asset_id != owner_id for row in owner["evidence"]]
        return Plan(
            {"owner": owner_id, "revoke": sorted(row["evidence_id"] for row in revoke), "keep": sorted(row["evidence_id"] for row in owners[owner_id]["evidence"])},
            revokes=revoke,
            preserved=[f"{_asset_name(owners[owner_id])} keeps {len(owners[owner_id]['evidence'])} confirmed evidence row(s).",
                       "Revoked rows, DHCP leases, DNS clients and assignments are kept as history."],
            risks=["Assets losing this MAC no longer match DHCP or DNS observations for it. Their current assignments are not changed."],
            confirmation=_confirmation_for(owners[owner_id]),
            macs=[evidence["mac"]], asset_ids=sorted(owners),
        )
    if action == "repair_static_assignment":
        plan = evidence.get("plan")
        if not plan or evidence.get("blocked_reason"):
            raise RepairRefused(evidence.get("blocked_reason") or "This assignment cannot be repaired automatically.")
        record = evidence["record"]
        changes = []
        if plan["create_assignment"]:
            changes.append({"record": "New network assignment", "field": "current address", "current": ", ".join(row["address"] for row in evidence["current_assignments"]) or "none",
                            "proposed": f"{record['address']} (managed static record #{record['ip_address_id']})"})
        return Plan(
            {key: value for key, value in plan.items() if key not in {"repair_time", "executed"}},
            changes=changes,
            closes=[{"assignment_id": row["assignment_id"], "address": row["address"], "provenance": row["provenance"], "started_at": row["started_at"], "ended_at": now.isoformat()}
                    for row in plan["close_assignments"]],
            preserved=["The asset ID and its identity evidence are unchanged.", "DHCP lease history is unchanged.",
                       "Closed assignments stay as history, so earlier traffic attribution is unchanged."],
            macs=[plan["mac"]], asset_ids=[plan["asset_id"]],
        )
    if action == "keep_assignment":
        keep_id = _int(params, "keep_assignment_id")
        rows = {row["assignment_id"]: row for row in evidence["assignments"]}
        if keep_id not in rows:
            raise RepairRefused("The selected assignment is not part of this finding.")
        closes = [_closing(row, now) for assignment_id, row in rows.items() if assignment_id != keep_id]
        kept = rows[keep_id]
        high_risk = detection.finding_type == "duplicate_active_ip"
        return Plan(
            {"keep": keep_id, "close": sorted(row["assignment_id"] for row in closes)},
            closes=closes,
            preserved=["Closed assignments stay as history; earlier traffic attribution is unchanged.", "No asset, evidence or lease is changed."],
            risks=["Traffic for this address is attributed to the kept assignment from now on."] if high_risk else [],
            confirmation=_confirmation_for(kept) if high_risk else None,
            asset_ids=sorted({row["asset_id"] for row in rows.values() if row.get("asset_id")}), assignment_keys=_assignment_keys(list(rows.values())),
        )
    if action == "close_obsolete_dhcp":
        row = evidence["assignment"]
        end = datetime.fromisoformat(evidence["proposed_end"])
        return Plan(
            {"assignment": row["assignment_id"], "end": evidence["proposed_end"], "reason": evidence["reason"], "lease": evidence["lease"]["lease_id"]},
            closes=[_closing(row, now, end)],
            preserved=["The DHCP lease history is unchanged.", "The assignment stays as history up to the lease's last observation."],
            asset_ids=[row["asset_id"]] if row.get("asset_id") else [], assignment_keys=_assignment_keys([row]),
        )
    if action in {"revoke_client_id", "revoke_orphan_evidence"}:
        row = evidence["evidence"]
        return Plan(
            {"evidence": row["evidence_id"]},
            revokes=[{"evidence_id": row["evidence_id"], "asset": _asset_name(evidence.get("asset")) if evidence.get("asset") else "No asset",
                      "source": row["source"], "source_scope": row["source_scope"], "value": row["value"]}],
            preserved=["The evidence row is kept as revoked history.", "DHCP lease history is unchanged."],
            risks=["DHCP continuity for this asset then relies on its confirmed MAC only."] if action == "revoke_client_id" else [],
            macs=[row["value"]] if row.get("evidence_type") == "mac" else [],
            asset_ids=[evidence["asset"]["asset_id"]] if (evidence.get("asset") or {}).get("asset_id") else [],
        )
    if action in {"replace_hostname", "clear_hostname"}:
        record = evidence["record"]
        if action == "replace_hostname":
            hostname = " ".join(str(params.get("hostname") or "").split())
            if not hostname or len(hostname) > 255 or _CONTROL.search(hostname) or hostname not in evidence["observed_hostnames"]:
                raise RepairRefused("Select one of the observed hostnames shown for this record.")
        else:
            hostname = None
        return Plan(
            {"record": record["ip_address_id"], "current": record["name"], "proposed": hostname},
            changes=[{"record": f"IP/VLAN Manager record #{record['ip_address_id']} ({record['address']})", "field": "name", "current": record["name"], "proposed": hostname or "(blank)"}],
            preserved=["The DNS client, its observations and DHCP history are unchanged."],
            risks=[] if hostname else ["The record will have no name until an administrator sets one."],
        )
    if action == "set_asset_hostname":
        record = evidence["record"]
        assignment = evidence.get("current_assignment")
        asset_id = assignment.get("asset_id") if assignment else None
        if asset_id is None and evidence.get("mac"):
            owner = db.query(AssetIdentityEvidence.asset_id).filter(
                AssetIdentityEvidence.evidence_type == "mac",
                AssetIdentityEvidence.normalised_value == evidence["mac"],
                AssetIdentityEvidence.status == "confirmed",
                AssetIdentityEvidence.revoked_at.is_(None),
            ).all()
            ids = {row[0] for row in owner if row[0] is not None}
            asset_id = next(iter(ids), None) if len(ids) == 1 else None
        if asset_id is None:
            raise RepairRefused("This managed record is not linked to one unambiguous asset.")
        if action == "set_asset_hostname":
            hostname = normalise_hostname_value(params.get("hostname"), allow_empty=True)
        return Plan(
            {"asset_id": asset_id, "record": record["ip_address_id"], "current": record.get("name"), "proposed": hostname},
            changes=[{"record": f"Asset #{asset_id}", "field": "preferred hostname", "current": "(current evidence)" if record.get("name") else "(unset)", "proposed": hostname or "(cleared)"}],
            preserved=["Revoked and observed hostname evidence remains historical.", "The managed IP record, DHCP leases and DNS observations are unchanged."],
            asset_ids=[asset_id],
        )
    if action in {"relink_dns_client", "unlink_dns_client"}:
        client = evidence["dns_client"]
        linked = evidence["linked_asset"]
        target = None
        if action == "relink_dns_client":
            if evidence["classification"] != "definite_conflict" or len(evidence["mac_owners"]) != 1:
                raise RepairRefused("The client can be relinked only when exactly one asset owns its MAC.")
            target = evidence["mac_owners"][0]
        return Plan(
            {"client": client["dns_client_id"], "from": linked.get("asset_id"), "to": target["asset_id"] if target else None},
            changes=[{"record": f"DNS client #{client['dns_client_id']} ({client.get('hostname') or client['mac']})", "field": "linked asset",
                      "current": _asset_name(linked), "proposed": _asset_name(target) if target else "(none)"}],
            preserved=["DNS observations and query history are unchanged.", "No identity evidence is changed."],
            confirmation=_confirmation_for(target) if target else None,
            macs=[client["mac"]], asset_ids=sorted({value for value in (linked.get("asset_id"), target["asset_id"] if target else None) if value}),
        )
    if action == "close_orphan_assignment":
        row = evidence["assignment"]
        return Plan({"assignment": row["assignment_id"]}, closes=[_closing(row, now)],
                    preserved=["The assignment stays as history."], assignment_keys=_assignment_keys([row]))
    if action == "clamp_assignment_interval":
        row = evidence["assignment"]
        return Plan(
            {"assignment": row["assignment_id"], "started_at": row["started_at"], "ended_at": row["ended_at"]},
            changes=[{"record": f"Assignment #{row['assignment_id']} ({row['address']})", "field": "ended at", "current": row["ended_at"], "proposed": row["started_at"]}],
            preserved=["The interval stays empty, so no traffic attribution changes."],
            asset_ids=[row["asset_id"]] if row.get("asset_id") else [], assignment_keys=_assignment_keys([row]),
        )
    raise RepairRefused("Unsupported repair action.")


def _validate_action(finding: DataIntegrityFinding, action: str) -> RepairAction:
    definition = ACTIONS.get(action)
    if definition is None or finding.finding_type not in definition.finding_types or action not in FINDING_TYPES[finding.finding_type].actions:
        raise RepairRefused("This action is not available for this finding.")
    return definition


def _clean_params(params: dict | None) -> dict:
    params = params or {}
    clean = {}
    for name in ("owner_asset_id", "keep_assignment_id"):
        if params.get(name) is not None:
            clean[name] = params[name]
    if params.get("hostname") is not None:
        clean["hostname"] = str(params["hostname"])[:255]
    return clean


def _token(finding: DataIntegrityFinding, action: str, params: dict, plan: Plan) -> str:
    return _hash({"finding": finding.id, "action": action, "params": params, "material": plan.material})


def _display(finding: DataIntegrityFinding, action: RepairAction, plan: Plan, token: str) -> dict:
    return {
        "state": "ready",
        "finding_id": finding.id,
        "action": action.key,
        "action_label": action.label,
        "description": action.description,
        "high_risk": bool(plan.confirmation),
        "confirmation_text": plan.confirmation,
        "changes": plan.changes,
        "closes": plan.closes,
        "revokes": plan.revokes,
        "preserved": plan.preserved,
        "risks": plan.risks,
        "preview_token": token,
    }


def preview_repair(db: Session, user: User, finding: DataIntegrityFinding, action: str, params: dict | None = None, *, now: datetime | None = None) -> dict:
    """Build the change plan from current data without changing anything."""
    now = now or _now()
    definition = _validate_action(finding, action)
    params = _clean_params(params)
    try:
        if finding.status not in ACTIVE_STATUSES:
            return {"state": "not_active", "finding_id": finding.id, "message": "Only open findings can be repaired. Reopen or revalidate it first."}
        detection = detect_subject(db, finding.finding_type, finding_subject(finding), now=now)
        if detection is None:
            return {"state": "not_detected", "finding_id": finding.id, "message": "The inconsistency is no longer detected. Revalidate to resolve the finding."}
        plan = _plan(db, finding, detection, action, params, now)
        return _display(finding, definition, plan, _token(finding, action, params, plan))
    finally:
        db.rollback()


def _verify(db: Session, finding_id: int, actor: User, now: datetime) -> dict:
    finding = db.get(DataIntegrityFinding, finding_id)
    detection = detect_subject(db, finding.finding_type, finding_subject(finding), now=now)
    if detection is None:
        resolve_finding(db, finding, now=_now(), resolution="repaired", actor=actor)
        db.commit()
        return {"verified": True, "status": finding.status}
    apply_detection(db, finding, detection, run=None, now=_now())
    record_event(db, finding, "verification_failed", actor=actor, detail={"fingerprint": detection.fingerprint})
    db.commit()
    return {"verified": False, "status": finding.status, "remaining": detection.title}


def _record_failure(db: Session, actor: User, finding_id: int, action: str, reason: str, message: str) -> None:
    db.rollback()
    finding = db.get(DataIntegrityFinding, finding_id)
    if finding is not None:
        record_event(db, finding, "repair_failed", actor=actor, detail={"action": action, "reason": reason, "message": message[:300]})
    write_audit(db, actor, "data_integrity_repair_failed", "data_integrity_finding", str(finding_id), detail=f"Repair refused: {reason}",
                metadata={"finding_id": finding_id, "action": action, "reason": reason}, severity="warning", force=True, commit=False)
    db.commit()


def _revoke(db: Session, evidence_id: int, now: datetime, reason: str) -> dict:
    row = db.get(AssetIdentityEvidence, evidence_id)
    if row is None or row.status != "confirmed" or row.revoked_at is not None:
        raise StaleRepair("Evidence changed after the preview.")
    row.status, row.revoked_at, row.conflict_reason = "revoked", now, reason[:500]
    return {"evidence_id": row.id, "asset_id": row.asset_id, "before": "confirmed", "after": "revoked"}


def _close(db: Session, assignment_id: int, ended_at: datetime) -> dict:
    row = db.get(AssetNetworkAssignment, assignment_id)
    if row is None or row.ended_at is not None or row.status != "confirmed":
        raise StaleRepair("An assignment changed after the preview.")
    row.ended_at = max(row.started_at, ended_at)
    return {"assignment_id": row.id, "asset_id": row.asset_id, "before": None, "after": row.ended_at.isoformat()}


def _apply(db: Session, finding: DataIntegrityFinding, action: str, plan: Plan, now: datetime) -> dict:
    material = plan.material
    if action == "choose_mac_owner":
        reason = f"Data Integrity finding {finding.id}: MAC ownership assigned to asset {material['owner']}"
        return {"owner_asset_id": material["owner"], "revoked": [_revoke(db, evidence_id, now, reason) for evidence_id in material["revoke"]]}
    if action == "keep_assignment":
        return {"kept_assignment_id": material["keep"], "closed": [_close(db, assignment_id, now) for assignment_id in material["close"]]}
    if action == "close_obsolete_dhcp":
        return {"closed": [_close(db, material["assignment"], datetime.fromisoformat(material["end"]))], "lease_id": material["lease"]}
    if action == "close_orphan_assignment":
        return {"closed": [_close(db, material["assignment"], now)]}
    if action in {"revoke_client_id", "revoke_orphan_evidence"}:
        return {"revoked": [_revoke(db, material["evidence"], now, f"Data Integrity finding {finding.id}: revoked by an administrator")]}
    if action == "clamp_assignment_interval":
        row = db.get(AssetNetworkAssignment, material["assignment"])
        if row is None or row.ended_at is None or row.ended_at >= row.started_at:
            raise StaleRepair("The assignment changed after the preview.")
        before = row.ended_at.isoformat()
        row.ended_at = row.started_at
        return {"assignment_id": row.id, "before": before, "after": row.ended_at.isoformat()}
    if action in {"replace_hostname", "clear_hostname"}:
        query = db.query(IPAddress).filter(IPAddress.id == material["record"])
        if db.get_bind().dialect.name == "postgresql":
            query = query.with_for_update()
        record = query.one_or_none()
        if record is None or record.name != material["current"]:
            raise StaleRepair("The IP/VLAN Manager record changed after the preview.")
        record.name = material["proposed"]
        evidence = finding_subject(finding)
        client = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.linked_ip_record_id == record.id).order_by(DNSRecognisedDevice.id.asc()).first()
        if client is not None:
            db.add(DNSClientEvent(
                dns_client_id=client.id, event_type="managed_record_updated", event_summary="Managed hostname corrected by an administrator in Data Integrity",
                old_value=material["current"], new_value=material["proposed"], source=HOSTNAME_SOURCE, provider_id=client.provider_id,
            ))
        return {"ip_address_id": record.id, "subject": evidence, "before": material["current"], "after": material["proposed"]}
    if action == "set_asset_hostname":
        result = set_administrator_hostname(
            db, user, asset_id=material["asset_id"], hostname=material["proposed"], commit=False,
        )
        return result
    if action in {"relink_dns_client", "unlink_dns_client"}:
        query = db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.id == material["client"])
        if db.get_bind().dialect.name == "postgresql":
            query = query.with_for_update()
        client = query.one_or_none()
        if client is None or client.hardware_asset_id != material["from"]:
            raise StaleRepair("The DNS client changed after the preview.")
        if material["to"] is not None and db.get(HardwareAsset, material["to"]) is None:
            raise StaleRepair("The target asset no longer exists.")
        client.hardware_asset_id = material["to"]
        db.add(DNSClientEvent(
            dns_client_id=client.id, event_type="asset_link_corrected", event_summary="Asset link corrected by an administrator in Data Integrity",
            old_value=str(material["from"]) if material["from"] else None, new_value=str(material["to"]) if material["to"] else None,
            source="data integrity", provider_id=client.provider_id,
        ))
        return {"dns_client_id": client.id, "before": material["from"], "after": material["to"]}
    raise RepairRefused("Unsupported repair action.")


def execute_repair(
    db: Session, user: User, finding_id: int, action: str, params: dict | None, preview_token: str, *,
    confirmation: str | None = None, now: datetime | None = None,
) -> dict:
    """Execute one previewed repair. Caller has verified the request; authority is re-checked here."""
    if not can_repair(db, user):
        raise PermissionError("The Data Integrity repair permission is required.")
    finding = visible_finding(db, user, finding_id)
    if finding is None:
        raise LookupError("Finding not found.")
    definition = _validate_action(finding, action)
    params = _clean_params(params)
    now = now or _now()
    if not isinstance(preview_token, str) or not re.fullmatch(r"[0-9a-f]{64}", preview_token or ""):
        raise RepairRefused("A current preview is required before repairing.")
    try:
        result = _execute(db, user, finding, definition, params, preview_token, confirmation, now)
    except (RepairRefused, RuntimeError) as exc:
        reason = "stale_preview" if isinstance(exc, StaleRepair) else "refused" if isinstance(exc, RepairRefused) else "audit_failure"
        _record_failure(db, user, finding_id, action, reason, str(exc))
        raise
    if result["outcome"] == "applied":
        result.update(_verify(db, finding_id, user, now))
    return result


def _execute(db: Session, user: User, finding: DataIntegrityFinding, definition: RepairAction, params: dict, preview_token: str, confirmation: str | None, now: datetime) -> dict:
    finding_id, action = finding.id, definition.key
    if finding.status not in ACTIVE_STATUSES:
        return {"outcome": "not_active", "finding_id": finding_id, "status": finding.status, "message": "The finding is not open; nothing was changed."}
    subject = finding_subject(finding)
    detection = detect_subject(db, finding.finding_type, subject, now=now)
    if detection is None:
        return _already_resolved(db, finding_id, user)
    scope = _plan(db, finding, detection, action, params, now)

    if action == "repair_static_assignment":
        return _execute_static(db, user, finding_id, detection, params, preview_token, now)

    begin_serialised_write(db)
    lock_identity_scope(db, macs=scope.macs, asset_ids=scope.asset_ids, assignment_keys=scope.assignment_keys)
    db.expire_all()
    finding = db.get(DataIntegrityFinding, finding_id)
    detection = detect_subject(db, finding.finding_type, subject, now=now)
    if detection is None:
        db.rollback()
        return _already_resolved(db, finding_id, user)
    plan = _plan(db, finding, detection, action, params, now)
    if not (set(plan.macs) <= set(scope.macs) and set(plan.asset_ids) <= set(scope.asset_ids) and set(plan.assignment_keys) <= set(scope.assignment_keys)):
        raise StaleRepair("The affected records changed after the preview. Preview the repair again.")
    if _token(finding, action, params, plan) != preview_token:
        raise StaleRepair("The affected records changed after the preview. Preview the repair again.")
    if plan.confirmation and (confirmation or "").strip().casefold() != plan.confirmation.casefold():
        raise RepairRefused(f"Type {plan.confirmation} to confirm this decision.")
    affected = _apply(db, finding, action, plan, now)
    db.flush()
    record_event(db, finding, "repaired", actor=user, detail={"action": action, "affected": affected})
    audit_or_fail(db, user, "data_integrity_repair", str(finding.id), f"Data Integrity repair: {definition.label}",
                  {"finding_id": finding.id, "finding_type": finding.finding_type, "action": action, "affected": affected})
    db.commit()
    return {"outcome": "applied", "finding_id": finding_id, "action": action, "affected": affected}


def _already_resolved(db: Session, finding_id: int, user: User) -> dict:
    finding = db.get(DataIntegrityFinding, finding_id)
    resolve_finding(db, finding, now=_now(), resolution="verified_absent", actor=user)
    db.commit()
    return {"outcome": "already_resolved", "finding_id": finding_id, "status": finding.status, "message": "The inconsistency is no longer present; nothing was changed."}


def _execute_static(db: Session, user: User, finding_id: int, detection: Detection, params: dict, preview_token: str, now: datetime) -> dict:
    plan = detection.evidence["plan"]
    asset = detection.evidence["asset"]
    holder = {}

    def check(locked_plan: dict) -> None:
        finding = db.get(DataIntegrityFinding, finding_id)
        material = Plan({key: value for key, value in locked_plan.items() if key not in {"repair_time", "executed"}})
        if _token(finding, "repair_static_assignment", params, material) != preview_token:
            raise StaleRepair("The affected records changed after the preview. Preview the repair again.")

    def record(executed_plan: dict) -> None:
        finding = db.get(DataIntegrityFinding, finding_id)
        affected = {"created_assignment_id": executed_plan.get("created_assignment_id"),
                    "closed_assignment_ids": [row["assignment_id"] for row in executed_plan["close_assignments"]], "ip_address_id": executed_plan["ip_address_id"]}
        holder["affected"] = affected
        record_event(db, finding, "repaired", actor=user, detail={"action": "repair_static_assignment", "affected": affected})
        audit_or_fail(db, user, "data_integrity_repair", str(finding_id), "Data Integrity repair: Repair assignment",
                      {"finding_id": finding_id, "finding_type": finding.finding_type, "action": "repair_static_assignment", "affected": affected})

    begin_serialised_write(db)
    try:
        result = repair_managed_static_assignment(
            db, asset_id=plan["asset_id"], asset_tag=asset.get("asset_tag") or "", mac=plan["mac"], address=plan["address"],
            ip_address_id=plan["ip_address_id"], actor=user, execute=True, now=now,
            audit_context={"finding_id": finding_id, "source": "data_integrity"}, on_plan=check, before_commit=record,
        )
    except StaleRepair:
        raise
    except ValueError as exc:
        raise RepairRefused(str(exc)) from exc
    if not result.get("executed"):
        return _already_resolved(db, finding_id, user)
    return {"outcome": "applied", "finding_id": finding_id, "action": "repair_static_assignment", "affected": holder.get("affected", {})}


def acknowledge_finding(db: Session, user: User, finding: DataIntegrityFinding, acknowledgement: str, note: str | None = None) -> dict:
    from app.services.data_integrity import ignore_finding

    finding_type, label = ACKNOWLEDGEMENTS.get(acknowledgement, (None, None))
    if finding_type != finding.finding_type:
        raise RepairRefused("This acknowledgement is not available for this finding.")
    note = " ".join(str(note or "").split())[:300]
    return ignore_finding(db, finding, user, f"{label}." + (f" {note}" if note else ""), event="retained")


# ------------------------------------------------------------- bulk


def _bulk_candidates(db: Session, user: User, finding_ids: list[int]) -> tuple[list[DataIntegrityFinding], list[dict]]:
    if not isinstance(finding_ids, list) or not finding_ids or len(finding_ids) > MAX_BULK:
        raise RepairRefused(f"Select 1 to {MAX_BULK} findings.")
    findings, skipped = [], []
    for finding_id in dict.fromkeys(finding_ids):
        finding = visible_finding(db, user, finding_id) if isinstance(finding_id, int) and finding_id > 0 else None
        if finding is None:
            skipped.append({"finding_id": finding_id, "reason": "Finding not found."})
        elif FINDING_TYPES[finding.finding_type].bulk_action not in BULK_ACTIONS or not finding.bulk_repairable:
            skipped.append({"finding_id": finding.id, "reason": "This finding needs an individual administrator decision."})
        elif finding.status not in ACTIVE_STATUSES:
            skipped.append({"finding_id": finding.id, "reason": "The finding is not open."})
        else:
            findings.append(finding)
    return findings, skipped


def preview_bulk(db: Session, user: User, finding_ids: list[int], *, now: datetime | None = None) -> dict:
    findings, skipped = _bulk_candidates(db, user, finding_ids)
    items = []
    for finding in findings:
        action = FINDING_TYPES[finding.finding_type].bulk_action
        try:
            preview = preview_repair(db, user, finding, action, {}, now=now)
        except RepairRefused as exc:
            skipped.append({"finding_id": finding.id, "reason": str(exc)})
            continue
        if preview["state"] != "ready" or preview["high_risk"]:
            skipped.append({"finding_id": finding.id, "reason": preview.get("message") or "This finding needs an individual decision."})
            continue
        items.append({"finding_id": finding.id, "title": finding.title, "affected_label": finding.affected_label, **preview})
    db.rollback()
    return {"items": items, "skipped": skipped, "change_count": sum(len(item["changes"]) + len(item["closes"]) + len(item["revokes"]) for item in items)}


def execute_bulk(db: Session, user: User, items: list[dict], *, confirmation: str | None = None, now: datetime | None = None) -> dict:
    """Execute previewed deterministic repairs, each in its own transaction."""
    if not can_repair(db, user):
        raise PermissionError("The Data Integrity repair permission is required.")
    if (confirmation or "").strip().casefold() != BULK_CONFIRMATION.casefold():
        raise RepairRefused(f"Type {BULK_CONFIRMATION} to confirm these repairs.")
    if not isinstance(items, list) or not items or len(items) > MAX_BULK:
        raise RepairRefused(f"Select 1 to {MAX_BULK} findings.")
    tokens = {}
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("finding_id"), int) and isinstance(item.get("preview_token"), str):
            tokens[item["finding_id"]] = item["preview_token"]
    findings, skipped = _bulk_candidates(db, user, list(tokens))
    results = [{"finding_id": row["finding_id"], "outcome": "skipped", "message": row["reason"]} for row in skipped]
    for finding in findings:
        finding_id, action = finding.id, FINDING_TYPES[finding.finding_type].bulk_action
        try:
            outcome = execute_repair(db, user, finding_id, action, {}, tokens[finding_id], now=now)
            results.append({"finding_id": finding_id, "outcome": outcome["outcome"], "verified": outcome.get("verified"),
                            "message": outcome.get("message") or ("Repaired and verified." if outcome.get("verified") else outcome.get("remaining"))})
        except StaleRepair as exc:
            results.append({"finding_id": finding_id, "outcome": "stale", "message": str(exc)})
        except (RepairRefused, RuntimeError, LookupError) as exc:
            db.rollback()
            results.append({"finding_id": finding_id, "outcome": "failed", "message": str(exc)})
    succeeded = sum(1 for row in results if row["outcome"] in {"applied", "already_resolved"})
    status = "completed" if succeeded == len(results) else "partial" if succeeded else "failed"
    write_audit(db, user, "data_integrity_bulk_repair", "data_integrity_finding", None, detail=f"Bulk repair {status}: {succeeded} of {len(results)} succeeded",
                metadata={"status": status, "requested": len(results), "succeeded": succeeded, "finding_ids": sorted(tokens)[:MAX_BULK]}, force=True)
    return {"status": status, "succeeded": succeeded, "requested": len(results), "results": results}
