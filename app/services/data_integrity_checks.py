"""Read-only Data Integrity detection shared by the frontend audit and CLI tools.

Every check is a bounded SELECT-only scan that returns ``Detection`` objects.
A detection has a stable ``key`` (its finding type and the identities of the
records involved) and a ``fingerprint`` of the evidence that matters for a
decision, so repeated audits update one logical finding and an administrator
decision is reconsidered only when that evidence changes. Each check can be
re-run for one subject, which is how previews, repairs and revalidation verify
a single finding against fresh data. Nothing here takes locks or writes.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json

from sqlalchemy import distinct, func, or_
from sqlalchemy.orm import Session

from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSClientEvent,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    VLAN,
)
from app.services.asset_identity import (
    MANAGED_STATIC_PROVENANCE,
    MANAGED_STATIC_REPAIR_PROVENANCE,
    managed_static_record_mac,
    plan_managed_static_assignment,
)

CHECK_SET_VERSION = "2026.10.30-1"
DEFAULT_LIMIT = 2000
MAX_LIMIT = 5000
ROWS_PER_SUBJECT = 50
AUTO_FILL_SOURCE = "automatic empty hostname update"


@dataclass(frozen=True)
class FindingType:
    key: str
    label: str
    category: str
    modules: tuple[str, ...]
    severity: str
    initial_status: str
    why: str
    recommendation: str
    consequence: str
    actions: tuple[str, ...] = ()
    acknowledgements: tuple[str, ...] = ()
    bulk_action: str | None = None


FINDING_TYPES = {
    row.key: row
    for row in (
        FindingType(
            "duplicate_confirmed_mac", "Duplicate confirmed MAC", "asset", ("asset_manager",), "critical", "needs_review",
            "The same MAC address is confirmed identity evidence for more than one asset. A MAC identifies one physical interface, so at most one asset can own it.",
            "Choose the asset that legitimately owns this MAC. Confirmed MAC evidence on every other asset is revoked; observation history is kept.",
            "Until resolved, DHCP and DNS evidence for this MAC cannot be attributed and new confirmations for it are refused.",
            ("choose_mac_owner",),
        ),
        FindingType(
            "managed_static_assignment", "Current IP differs from managed static record", "ipam", ("asset_manager", "vlan_ip_manager"), "warning", "open",
            "An asset's confirmed MAC is set on a Static IP/VLAN Manager record, but the asset's current network assignment does not match that managed address.",
            "Repair the assignment: the managed static address becomes current and obsolete DHCP-derived assignments end at repair time.",
            "Traffic attribution and the asset's current IP follow the obsolete address until repaired. Earlier attribution is not changed.",
            ("repair_static_assignment",), (), "repair_static_assignment",
        ),
        FindingType(
            "duplicate_active_ip", "Address currently assigned to several assets", "asset", ("asset_manager",), "critical", "needs_review",
            "More than one asset holds an open confirmed assignment for the same address in the same network scope.",
            "Choose the assignment that is genuinely current. The others are closed at repair time, never deleted.",
            "Traffic and monitoring for this address cannot be attributed to a single asset until resolved.",
            ("keep_assignment",),
        ),
        FindingType(
            "duplicate_open_assignment", "Duplicate open assignment on one asset", "asset", ("asset_manager",), "warning", "needs_review",
            "One asset holds several open confirmed assignments for the same address and scope.",
            "Choose the assignment to keep open; the duplicates are closed at repair time.",
            "Duplicate open rows can split traffic attribution for the asset.",
            ("keep_assignment",),
        ),
        FindingType(
            "obsolete_dhcp_assignment", "Assignment still open after its DHCP lease ended", "dhcp", ("asset_manager", "dns_manager"), "warning", "open",
            "An open assignment is linked to a DHCP lease that has ended, expired or been taken by another device.",
            "Close the assignment at the lease's last observation, the last supported evidence of ownership.",
            "The asset keeps an address it no longer holds; attribution for that address may be wrong.",
            ("close_obsolete_dhcp",), (), "close_obsolete_dhcp",
        ),
        FindingType(
            "suspect_dhcp_client_id", "Suspicious DHCP client identifier", "dhcp", ("asset_manager",), "warning", "needs_review",
            "Confirmed DHCP client-ID evidence is a bare number, the shape of a provider lease record number that older Kaya versions stored by mistake.",
            "Revoke it if it is a provider record number, or retain it if the device genuinely presents this identifier.",
            "A provider record number can be reused for another device, which could link that device to this asset.",
            ("revoke_client_id",), ("retain_client_id",),
        ),
        FindingType(
            "static_hostname_auto_filled", "Static hostname filled from observation", "ipam", ("vlan_ip_manager", "dns_manager"), "warning", "needs_review",
            "A Static IP/VLAN Manager record's name was filled automatically from a DNS observation and has not been changed by an administrator since.",
            "Retain the name, replace it with a selected observed hostname, or clear it.",
            "An automatically copied name may be stale, but it is treated as administrator-managed.",
            ("set_asset_hostname", "replace_hostname", "clear_hostname"), ("retain_hostname",),
        ),
        FindingType(
            "dns_asset_link_conflict", "DNS client linked to the wrong asset", "dns", ("dns_manager", "asset_manager"), "warning", "needs_review",
            "A DNS Manager client is linked to an asset that does not hold the client's MAC as confirmed evidence.",
            "Link the client to the asset that owns its MAC, or unlink it.",
            "DNS history and DNS-derived traffic for the client are shown on the wrong asset.",
            ("relink_dns_client", "unlink_dns_client"),
        ),
        FindingType(
            "orphaned_open_assignment", "Open assignment without an asset", "asset", ("asset_manager",), "warning", "open",
            "A confirmed network assignment is still open but its asset has been deleted.",
            "Close the assignment at repair time; it stays as history.",
            "The address looks currently assigned although no asset holds it.",
            ("close_orphan_assignment",),
        ),
        FindingType(
            "orphaned_confirmed_evidence", "Confirmed evidence without an asset", "asset", ("asset_manager",), "info", "open",
            "Identity evidence is still confirmed but its asset has been deleted.",
            "Revoke the evidence; the observation history is kept.",
            "No direct effect; it obscures the identity history for this value.",
            ("revoke_orphan_evidence",),
        ),
        FindingType(
            "invalid_assignment_interval", "Assignment ends before it starts", "asset", ("asset_manager",), "warning", "needs_review",
            "A network assignment's end time is earlier than its start time.",
            "Set the end time to the start time. The interval is empty either way, so no traffic attribution changes.",
            "Reports and interval queries may treat the row inconsistently.",
            ("clamp_assignment_interval",),
        ),
        FindingType(
            "assignment_provenance_mismatch", "Assignment no longer matches its origin", "asset", ("asset_manager", "vlan_ip_manager"), "info", "needs_review",
            "An open assignment's recorded origin is no longer supported: a managed static assignment whose record is gone, now Dynamic or carries another MAC, or a DHCP assignment whose lease record was removed.",
            "Review the asset's current address manually. No automatic correction is safe.",
            "The assignment may no longer reflect the device's actual address.",
        ),
    )
}
SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1}
CATEGORY_LABELS = {"asset": "Asset", "dhcp": "DHCP", "dns": "DNS", "ipam": "IPAM"}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass
class Detection:
    finding_type: str
    subject: str
    title: str
    affected_label: str
    evidence: dict
    material: object
    severity: str | None = None
    status: str | None = None
    asset_id: int | None = None
    mac: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    search_terms: list = field(default_factory=list)
    repairable: bool = True
    bulk_repairable: bool = False

    @property
    def key(self) -> str:
        return hashlib.sha256(f"{self.finding_type}\x1f{self.subject}".encode("utf-8")).hexdigest()

    @property
    def fingerprint(self) -> str:
        return _hash(self.material)

    @property
    def definition(self) -> FindingType:
        return FINDING_TYPES[self.finding_type]

    def search_text(self) -> str:
        terms = [self.affected_label, self.title, self.mac, self.ip_address, self.hostname, *self.search_terms]
        return " ".join(str(term).casefold() for term in terms if term)[:1000]


@dataclass
class CheckResult:
    detections: list
    examined: int = 0
    truncated: bool = False


def _bounded(limit: int | None) -> int:
    return max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))


def _assets(db: Session, ids) -> dict[int, dict]:
    ids = sorted({value for value in ids if value is not None})
    result = {}
    for start in range(0, len(ids), 500):
        for row in db.query(HardwareAsset.id, HardwareAsset.asset_tag, HardwareAsset.name, HardwareAsset.status).filter(HardwareAsset.id.in_(ids[start:start + 500])):
            result[row.id] = {"asset_id": row.id, "asset_tag": row.asset_tag, "asset_name": row.name, "asset_status": row.status}
    return result


def _asset_text(info: dict | None, asset_id: int | None) -> str:
    if not info:
        return f"Asset #{asset_id}" if asset_id else "No asset"
    return info.get("asset_tag") or info.get("asset_name") or f"Asset #{info['asset_id']}"


def _assignment(row: AssetNetworkAssignment) -> dict:
    return {
        "assignment_id": row.id,
        "asset_id": row.asset_id,
        "address": row.address,
        "address_family": row.address_family,
        "vlan_id": row.vlan_id,
        "source_id": row.source_id,
        "exporter_identity": row.exporter_identity,
        "ip_address_id": row.ip_address_id,
        "dhcp_lease_id": row.dhcp_lease_id,
        "provenance": row.provenance,
        "status": row.status,
        "started_at": _iso(row.started_at),
        "ended_at": _iso(row.ended_at),
        "confirmed_at": _iso(row.confirmed_at),
    }


def _confirmed_mac_filters():
    return (
        AssetIdentityEvidence.evidence_type == "mac",
        AssetIdentityEvidence.status == "confirmed",
        AssetIdentityEvidence.revoked_at.is_(None),
        AssetIdentityEvidence.asset_id.isnot(None),
    )


def _open_confirmed():
    return (AssetNetworkAssignment.status == "confirmed", AssetNetworkAssignment.ended_at.is_(None))


# ------------------------------------------------------------- shared query helpers (also used by scripts)


def confirmed_mac_duplicates(db: Session, limit: int, mac: str | None = None) -> list[tuple[str, list[AssetIdentityEvidence]]]:
    """Confirmed MACs owned by more than one asset, whatever the evidence source."""
    if mac:
        macs = [mac]
    else:
        macs = [value for (value,) in db.query(AssetIdentityEvidence.normalised_value).filter(*_confirmed_mac_filters()).group_by(
            AssetIdentityEvidence.normalised_value
        ).having(func.count(distinct(AssetIdentityEvidence.asset_id)) > 1).order_by(AssetIdentityEvidence.normalised_value).limit(limit)]
    result = []
    for value in macs:
        rows = db.query(AssetIdentityEvidence).filter(*_confirmed_mac_filters(), AssetIdentityEvidence.normalised_value == value).order_by(
            AssetIdentityEvidence.id.asc()
        ).limit(ROWS_PER_SUBJECT).all()
        if len({row.asset_id for row in rows}) > 1:
            result.append((value, rows))
    return result


def obsolete_dhcp_assignments(db: Session, now: datetime, limit: int, assignment_id: int | None = None) -> list[tuple]:
    """Open lease-linked assignments whose lease ended, expired or was taken by another device.

    Returns ``(assignment, lease, replacement_lease_or_None, reason)``.
    """
    query = db.query(AssetNetworkAssignment, DHCPLeaseHistory).join(
        DHCPLeaseHistory, DHCPLeaseHistory.id == AssetNetworkAssignment.dhcp_lease_id,
    ).filter(*_open_confirmed())
    if assignment_id is not None:
        query = query.filter(AssetNetworkAssignment.id == assignment_id)
    rows = query.order_by(AssetNetworkAssignment.id.asc()).limit(limit).all()
    provider_ids = {lease.provider_id for _assignment, lease in rows if lease.provider_id is not None}
    addresses = {lease.ip_address for _assignment, lease in rows}
    newest: dict[tuple, DHCPLeaseHistory] = {}
    if rows:
        for active in db.query(DHCPLeaseHistory).filter(
            DHCPLeaseHistory.is_active.is_(True),
            DHCPLeaseHistory.provider_id.in_(provider_ids or {-1}),
            DHCPLeaseHistory.ip_address.in_(addresses),
        ).order_by(DHCPLeaseHistory.id.asc()).limit(limit * 2):
            key = (active.provider_id, active.ip_address)
            current = newest.get(key)
            if current is None or (active.lease_started_at or datetime.min, active.id) > (current.lease_started_at or datetime.min, current.id):
                newest[key] = active
    result = []
    for assignment, lease in rows:
        replacement = newest.get((lease.provider_id, lease.ip_address))
        superseded = bool(
            replacement
            and replacement.id != lease.id
            and (replacement.lease_started_at or datetime.min, replacement.id) > (lease.lease_started_at or datetime.min, lease.id)
            and replacement.mac_address != lease.mac_address
        )
        if not lease.is_active or lease.ended_at is not None:
            reason = "lease_ended"
        elif superseded:
            reason = "superseded_by_other_device"
        elif lease.expires_at is not None and lease.lease_started_at is not None and lease.lease_started_at < lease.expires_at <= now:
            reason = "lease_expired"
        else:
            continue
        result.append((assignment, lease, replacement if superseded else None, reason))
    return result


def suspect_dhcp_client_id_evidence(db: Session, limit: int, evidence_id: int | None = None) -> list[AssetIdentityEvidence]:
    """Confirmed DHCP client-ID evidence that is a bare decimal (a possible provider record number)."""
    query = db.query(AssetIdentityEvidence).filter(
        AssetIdentityEvidence.evidence_type == "dhcp_client_id",
        AssetIdentityEvidence.status == "confirmed",
        AssetIdentityEvidence.revoked_at.is_(None),
    )
    if evidence_id is not None:
        query = query.filter(AssetIdentityEvidence.id == evidence_id)
    rows = query.order_by(AssetIdentityEvidence.id.asc()).limit(limit * 4).all()
    return [row for row in rows if row.normalised_value.isdigit()][:limit]


def auto_filled_static_hostnames(db: Session, limit: int, ip_address_id: int | None = None) -> list[tuple]:
    """``(event, dns_client, record)`` for Static records whose name was copied from observation."""
    query = db.query(DNSClientEvent, DNSRecognisedDevice, IPAddress).join(
        DNSRecognisedDevice, DNSRecognisedDevice.id == DNSClientEvent.dns_client_id,
    ).join(IPAddress, IPAddress.id == DNSRecognisedDevice.linked_ip_record_id).filter(
        DNSClientEvent.event_type == "managed_record_updated",
        DNSClientEvent.source == AUTO_FILL_SOURCE,
        or_(IPAddress.assignment_type.is_(None), IPAddress.assignment_type != "Dynamic"),
    )
    if ip_address_id is not None:
        query = query.filter(IPAddress.id == ip_address_id)
    return query.order_by(DNSClientEvent.id.asc()).limit(limit).all()


def asset_confirmed_macs(db: Session, asset_ids=None) -> dict[int, set[str]]:
    query = db.query(AssetIdentityEvidence.asset_id, AssetIdentityEvidence.normalised_value).filter(*_confirmed_mac_filters())
    if asset_ids is not None:
        ids = sorted(set(asset_ids))
        if not ids:
            return {}
        query = query.filter(AssetIdentityEvidence.asset_id.in_(ids))
    result: dict[int, set[str]] = defaultdict(set)
    for asset_id, value in query.limit(MAX_LIMIT * 4):
        result[asset_id].add(value.casefold())
    return result


def mac_owners(db: Session, macs) -> dict[str, set[int]]:
    macs = sorted({value for value in macs if value})
    result: dict[str, set[int]] = defaultdict(set)
    for start in range(0, len(macs), 500):
        for asset_id, value in db.query(AssetIdentityEvidence.asset_id, AssetIdentityEvidence.normalised_value).filter(
            *_confirmed_mac_filters(), AssetIdentityEvidence.normalised_value.in_(macs[start:start + 500])
        ):
            result[value].add(asset_id)
    return result


def dns_link_conflicts(db: Session, limit: int, dns_client_id: int | None = None) -> list[dict]:
    """DNS clients linked to an asset that does not hold the client's MAC as confirmed evidence."""
    query = db.query(DNSRecognisedDevice).filter(
        DNSRecognisedDevice.hardware_asset_id.isnot(None),
        DNSRecognisedDevice.normalised_mac.isnot(None),
    )
    if dns_client_id is not None:
        query = query.filter(DNSRecognisedDevice.id == dns_client_id)
    clients = query.order_by(DNSRecognisedDevice.id.asc()).limit(limit).all()
    observed = {(client.normalised_mac or "").casefold() for client in clients}
    owners = mac_owners(db, observed)
    linked = asset_confirmed_macs(db, {client.hardware_asset_id for client in clients})
    rows = []
    for client in clients:
        mac = (client.normalised_mac or "").casefold()
        confirmed = linked.get(client.hardware_asset_id, set())
        if mac in confirmed:
            continue
        others = sorted(owner for owner in owners.get(mac, set()) if owner != client.hardware_asset_id)
        rows.append({
            "client": client,
            "dns_client_id": client.id,
            "asset_id": client.hardware_asset_id,
            "observed_mac": mac,
            "confirmed_asset_macs": sorted(confirmed),
            "matching_other_asset_ids": others,
            "classification": "definite_conflict" if others else "suspected_unverified_link",
        })
    return rows


# ------------------------------------------------------------- checks


def _check_duplicate_confirmed_mac(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    groups = confirmed_mac_duplicates(db, limit, mac=subject)
    assets = _assets(db, {row.asset_id for _mac, rows in groups for row in rows})
    detections = []
    for mac, rows in groups:
        by_asset: dict[int, list] = defaultdict(list)
        for row in rows:
            by_asset[row.asset_id].append(row)
        owners = []
        for asset_id, evidence in sorted(by_asset.items()):
            owners.append({
                **(assets.get(asset_id) or {"asset_id": asset_id}),
                "evidence": [{
                    "evidence_id": row.id, "source": row.source, "source_scope": row.source_scope,
                    "confirmed_at": _iso(row.confirmed_at), "first_observed_at": _iso(row.first_observed_at), "last_observed_at": _iso(row.last_observed_at),
                } for row in evidence],
            })
        labels = [_asset_text(assets.get(asset_id), asset_id) for asset_id in sorted(by_asset)]
        detections.append(Detection(
            "duplicate_confirmed_mac", mac,
            f"MAC confirmed for {len(by_asset)} assets", f"{mac} · {', '.join(labels)}"[:255],
            {"mac": mac, "owners": owners},
            sorted((row.id, row.asset_id, row.source, row.source_scope or "") for row in rows),
            mac=mac, search_terms=labels + [owner.get("asset_name") for owner in owners],
        ))
    return CheckResult(detections, sum(len(rows) for _mac, rows in groups), len(groups) >= limit and not subject)


def _static_records(db: Session, limit: int, record_id: int | None):
    query = db.query(IPAddress).filter(
        or_(IPAddress.assignment_type.is_(None), IPAddress.assignment_type != "Dynamic"),
        IPAddress.mac_address.isnot(None),
    )
    if record_id is not None:
        query = query.filter(IPAddress.id == record_id)
    return query.order_by(IPAddress.id.asc()).limit(limit).all()


def _check_managed_static_assignment(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    record_id = int(subject.rsplit("|", 1)[1]) if subject else None
    records = _static_records(db, limit, record_id)
    macs = {record.id: managed_static_record_mac(record) for record in records}
    owners = mac_owners(db, set(macs.values()))
    assets = _assets(db, {next(iter(found)) for found in owners.values() if len(found) == 1})
    vlans = {row.id: row.name for row in db.query(VLAN.id, VLAN.name).filter(VLAN.id.in_({record.vlan_id for record in records if record.vlan_id} or {-1}))}
    detections = []
    for record in records:
        mac = macs.get(record.id)
        found = owners.get(mac, set()) if mac else set()
        if len(found) != 1:
            continue  # unowned MACs are not adopted; shared MACs are a duplicate-MAC finding
        asset_id = next(iter(found))
        asset = db.get(HardwareAsset, asset_id)
        if asset is None:
            continue
        blocked = None
        try:
            plan = plan_managed_static_assignment(db, asset=asset, mac=mac, address=record.address, ip_address_id=record.id, now=now)
        except ValueError as exc:
            plan, blocked = None, str(exc)
        if plan is not None and not plan["changes_required"]:
            continue
        open_rows = db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.asset_id == asset_id, *_open_confirmed()).order_by(
            AssetNetworkAssignment.started_at.desc()
        ).limit(ROWS_PER_SUBJECT).all()
        info = assets.get(asset_id) or {"asset_id": asset_id, "asset_tag": asset.asset_tag, "asset_name": asset.name, "asset_status": asset.status}
        label = _asset_text(info, asset_id)
        material = {"blocked": blocked, "plan": {key: value for key, value in (plan or {}).items() if key != "repair_time"}}
        detections.append(Detection(
            "managed_static_assignment", f"{asset_id}|{mac}|{record.id}",
            "Current IP differs from the managed static record" if not blocked else "Managed static record cannot become current",
            f"{label} · {mac} → {record.address}"[:255],
            {
                "asset": info, "mac": mac,
                "record": {"ip_address_id": record.id, "address": record.address, "vlan_id": record.vlan_id, "vlan_name": vlans.get(record.vlan_id), "name": record.name, "assignment_type": record.assignment_type},
                "current_assignments": [_assignment(row) for row in open_rows],
                "plan": plan, "blocked_reason": blocked,
            },
            material,
            status="needs_review" if blocked else None,
            asset_id=asset_id, mac=mac, ip_address=record.address, hostname=record.name,
            search_terms=[label, info.get("asset_name"), *(row.address for row in open_rows)],
            repairable=blocked is None, bulk_repairable=blocked is None,
        ))
    return CheckResult(detections, len(records), len(records) >= limit and not subject)


def _scope_groups(rows: list[AssetNetworkAssignment]) -> list[tuple[str, list[AssetNetworkAssignment]]]:
    """Split open rows for one address into network scopes.

    Rows observed by different traffic sources or exporters are separate
    scopes. Within one, rows on different VLANs are separate scopes, while a
    row without a VLAN (DHCP reconciliation) shares the scope of every VLAN.
    """
    partitions: dict[tuple, list] = defaultdict(list)
    for row in rows:
        partitions[(row.source_id, row.exporter_identity)].append(row)
    groups = []
    for (source_id, exporter), members in sorted(partitions.items(), key=lambda item: (item[0][0] or 0, item[0][1] or "")):
        vlans = sorted({row.vlan_id for row in members if row.vlan_id is not None})
        for vlan_id in vlans or [None]:
            scoped = [row for row in members if vlan_id is None or row.vlan_id in (vlan_id, None)]
            groups.append((f"{source_id or '-'}|{exporter or '-'}|{vlan_id if vlan_id is not None else 'any'}", scoped))
    return groups


def _check_duplicate_active_ip(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    if subject:
        address, family = subject.split("|")[:2]
        pairs = [(address, int(family))]
    else:
        pairs = db.query(AssetNetworkAssignment.address, AssetNetworkAssignment.address_family).filter(
            *_open_confirmed(), AssetNetworkAssignment.asset_id.isnot(None),
        ).group_by(AssetNetworkAssignment.address, AssetNetworkAssignment.address_family).having(
            func.count(distinct(AssetNetworkAssignment.asset_id)) > 1
        ).order_by(AssetNetworkAssignment.address).limit(limit).all()
    detections, examined = [], 0
    for address, family in pairs:
        rows = db.query(AssetNetworkAssignment).filter(
            *_open_confirmed(), AssetNetworkAssignment.asset_id.isnot(None),
            AssetNetworkAssignment.address == address, AssetNetworkAssignment.address_family == family,
        ).order_by(AssetNetworkAssignment.id.asc()).limit(ROWS_PER_SUBJECT).all()
        examined += len(rows)
        assets = _assets(db, {row.asset_id for row in rows})
        for scope, members in _scope_groups(rows):
            if len({row.asset_id for row in members}) < 2:
                continue
            labels = sorted({_asset_text(assets.get(row.asset_id), row.asset_id) for row in members})
            detections.append(Detection(
                "duplicate_active_ip", f"{address}|{family}|{scope}",
                f"{address} is current for {len({row.asset_id for row in members})} assets", f"{address} · {', '.join(labels)}"[:255],
                {"address": address, "address_family": family, "scope": scope, "assignments": [{**_assignment(row), **(assets.get(row.asset_id) or {})} for row in members]},
                sorted((row.id, row.asset_id) for row in members),
                ip_address=address, search_terms=labels,
            ))
    return CheckResult(detections, examined, len(pairs) >= limit and not subject)


def _check_duplicate_open_assignment(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    columns = (
        AssetNetworkAssignment.asset_id, AssetNetworkAssignment.address, AssetNetworkAssignment.address_family,
        AssetNetworkAssignment.vlan_id, AssetNetworkAssignment.source_id, AssetNetworkAssignment.exporter_identity,
    )
    query = db.query(*columns).filter(*_open_confirmed(), AssetNetworkAssignment.asset_id.isnot(None))
    if subject:
        asset_id, address, family = subject.split("|")[:3]
        query = query.filter(AssetNetworkAssignment.asset_id == int(asset_id), AssetNetworkAssignment.address == address, AssetNetworkAssignment.address_family == int(family))
    groups = query.group_by(*columns).having(func.count(AssetNetworkAssignment.id) > 1).order_by(AssetNetworkAssignment.asset_id).limit(limit).all()
    assets = _assets(db, {group[0] for group in groups})
    detections, examined = [], 0
    for asset_id, address, family, vlan_id, source_id, exporter in groups:
        rows = db.query(AssetNetworkAssignment).filter(
            *_open_confirmed(), AssetNetworkAssignment.asset_id == asset_id, AssetNetworkAssignment.address == address,
            AssetNetworkAssignment.address_family == family,
            AssetNetworkAssignment.vlan_id.is_(None) if vlan_id is None else AssetNetworkAssignment.vlan_id == vlan_id,
            AssetNetworkAssignment.source_id.is_(None) if source_id is None else AssetNetworkAssignment.source_id == source_id,
            AssetNetworkAssignment.exporter_identity.is_(None) if exporter is None else AssetNetworkAssignment.exporter_identity == exporter,
        ).order_by(AssetNetworkAssignment.id.asc()).limit(ROWS_PER_SUBJECT).all()
        examined += len(rows)
        label = _asset_text(assets.get(asset_id), asset_id)
        detections.append(Detection(
            "duplicate_open_assignment", f"{asset_id}|{address}|{family}|{vlan_id or '-'}|{source_id or '-'}|{exporter or '-'}",
            f"{len(rows)} open assignments for {address}", f"{label} · {address}"[:255],
            {"asset": assets.get(asset_id) or {"asset_id": asset_id}, "address": address, "assignments": [_assignment(row) for row in rows]},
            sorted(row.id for row in rows),
            asset_id=asset_id, ip_address=address, search_terms=[label],
        ))
    return CheckResult(detections, examined, len(groups) >= limit and not subject)


def _check_obsolete_dhcp_assignment(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    rows = obsolete_dhcp_assignments(db, now, limit, assignment_id=int(subject) if subject else None)
    assets = _assets(db, {assignment.asset_id for assignment, *_rest in rows})
    detections = []
    for assignment, lease, replacement, reason in rows:
        last_seen = lease.last_seen_at or lease.first_seen_at or assignment.started_at
        proposed_end = max(assignment.started_at, min(last_seen, now))
        label = _asset_text(assets.get(assignment.asset_id), assignment.asset_id)
        definite = reason in {"lease_ended", "superseded_by_other_device"}
        detections.append(Detection(
            "obsolete_dhcp_assignment", str(assignment.id),
            {"lease_ended": "DHCP lease ended but the assignment is still open",
             "superseded_by_other_device": "Another device now holds the leased address",
             "lease_expired": "DHCP lease expired but the assignment is still open"}[reason],
            f"{label} · {assignment.address}"[:255],
            {
                "asset": assets.get(assignment.asset_id) or {"asset_id": assignment.asset_id},
                "assignment": _assignment(assignment), "reason": reason, "proposed_end": _iso(proposed_end),
                "lease": {
                    "lease_id": lease.id, "provider_id": lease.provider_id, "ip_address": lease.ip_address, "mac": lease.mac_address,
                    "hostname": lease.hostname, "is_active": bool(lease.is_active), "lease_started_at": _iso(lease.lease_started_at),
                    "last_seen_at": _iso(lease.last_seen_at), "expires_at": _iso(lease.expires_at), "ended_at": _iso(lease.ended_at),
                },
                "replacement_lease": {"lease_id": replacement.id, "mac": replacement.mac_address, "lease_started_at": _iso(replacement.lease_started_at)} if replacement else None,
            },
            [assignment.id, _iso(assignment.ended_at), lease.id, bool(lease.is_active), _iso(lease.ended_at), _iso(lease.expires_at), replacement.id if replacement else None, reason],
            asset_id=assignment.asset_id, mac=lease.mac_address, ip_address=assignment.address, hostname=lease.hostname,
            search_terms=[label], bulk_repairable=definite,
        ))
    return CheckResult(detections, len(rows), len(rows) >= limit and not subject)


def _check_suspect_dhcp_client_id(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    rows = suspect_dhcp_client_id_evidence(db, limit, evidence_id=int(subject) if subject else None)
    assets = _assets(db, {row.asset_id for row in rows})
    confirmed = asset_confirmed_macs(db, {row.asset_id for row in rows if row.asset_id})
    detections = []
    for row in rows:
        leases = db.query(DHCPLeaseHistory.id, DHCPLeaseHistory.mac_address, DHCPLeaseHistory.last_seen_at).filter(
            DHCPLeaseHistory.provider_lease_id == row.normalised_value
        ).order_by(DHCPLeaseHistory.id.desc()).limit(ROWS_PER_SUBJECT).all()
        lease_macs = sorted({(lease.mac_address or "").casefold() for lease in leases if lease.mac_address})
        asset_macs = confirmed.get(row.asset_id, set())
        if len(lease_macs) > 1 or any(mac not in asset_macs for mac in lease_macs):
            confidence, reason = "high", "Leases carrying this identifier belong to more than one device or to a MAC this asset does not own."
        elif not leases:
            confidence, reason = "medium", "No current lease presents this identifier; it was most likely stored from a provider lease record number."
        else:
            confidence, reason = "low", "Every lease presenting this identifier belongs to this asset's confirmed MAC, so it may be genuine."
        label = _asset_text(assets.get(row.asset_id), row.asset_id)
        detections.append(Detection(
            "suspect_dhcp_client_id", str(row.id),
            f"Numeric DHCP client ID {row.normalised_value}", f"{label} · client ID {row.normalised_value}"[:255],
            {
                "asset": assets.get(row.asset_id) or {"asset_id": row.asset_id},
                "evidence": {"evidence_id": row.id, "value": row.normalised_value, "source": row.source, "source_scope": row.source_scope,
                             "confirmed_at": _iso(row.confirmed_at), "last_observed_at": _iso(row.last_observed_at)},
                "provider_record_id": None,
                "lease_macs": lease_macs, "asset_macs": sorted(asset_macs), "lease_ids": [lease.id for lease in leases[:10]],
                "confidence": confidence, "reason": reason,
            },
            [row.id, row.status, row.normalised_value, lease_macs, sorted(asset_macs)],
            severity="info" if confidence == "low" else "warning",
            asset_id=row.asset_id, mac=lease_macs[0] if len(lease_macs) == 1 else None, search_terms=[label, row.normalised_value],
        ))
    return CheckResult(detections, len(rows), len(rows) >= limit and not subject)


def _check_static_hostname_auto_filled(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    rows = auto_filled_static_hostnames(db, limit, ip_address_id=int(subject) if subject else None)
    latest: dict[int, tuple] = {}
    for event, client, record in rows:
        if record.id not in latest or event.id > latest[record.id][0].id:
            latest[record.id] = (event, client, record)
    detections = []
    for event, client, record in latest.values():
        if not record.name or record.name != event.new_value:
            continue  # changed by an administrator since, so it is managed
        mac = managed_static_record_mac(record)
        dhcp = []
        if mac:
            dhcp = db.query(DHCPLeaseHistory.hostname, func.max(DHCPLeaseHistory.last_seen_at)).filter(
                DHCPLeaseHistory.mac_address == mac, DHCPLeaseHistory.hostname.isnot(None),
            ).group_by(DHCPLeaseHistory.hostname).order_by(func.max(DHCPLeaseHistory.last_seen_at).desc()).limit(10).all()
        current = db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.ip_address_id == record.id, *_open_confirmed()).order_by(
            AssetNetworkAssignment.id.desc()
        ).first()
        observed = []
        for value in [client.hostname, *(hostname for hostname, _seen in dhcp)]:
            clean = (value or "").strip()
            if clean and clean != record.name and clean not in observed:
                observed.append(clean)
        detections.append(Detection(
            "static_hostname_auto_filled", str(record.id),
            "Static hostname was filled from a DNS observation", f"{record.name} · {record.address}"[:255],
            {
                "record": {"ip_address_id": record.id, "address": record.address, "name": record.name, "assignment_type": record.assignment_type, "mac": mac},
                "fill": {"event_id": event.id, "filled_at": _iso(event.created_at), "value": event.new_value},
                "dns_client": {"dns_client_id": client.id, "hostname": client.hostname, "current_ip": client.current_ip, "last_seen_at": _iso(client.last_seen_at)},
                "dhcp_hostnames": [{"hostname": hostname, "last_seen_at": _iso(seen)} for hostname, seen in dhcp],
                "current_assignment": _assignment(current) if current else None,
                "observed_hostnames": observed[:10],
            },
            [record.id, record.name, record.assignment_type, mac, event.id],
            mac=mac, ip_address=record.address, hostname=record.name, search_terms=observed[:10],
        ))
    return CheckResult(detections, len(rows), len(rows) >= limit and not subject)


def _check_dns_asset_link_conflict(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    rows = dns_link_conflicts(db, limit, dns_client_id=int(subject) if subject else None)
    assets = _assets(db, {row["asset_id"] for row in rows} | {owner for row in rows for owner in row["matching_other_asset_ids"]})
    detections = []
    for row in rows:
        client = row["client"]
        definite = row["classification"] == "definite_conflict"
        label = _asset_text(assets.get(row["asset_id"]), row["asset_id"])
        detections.append(Detection(
            "dns_asset_link_conflict", str(client.id),
            "DNS client's MAC is confirmed for another asset" if definite else "DNS client's MAC is not confirmed for its asset",
            f"{client.hostname or row['observed_mac']} · {label}"[:255],
            {
                "dns_client": {"dns_client_id": client.id, "hostname": client.hostname, "mac": row["observed_mac"], "current_ip": client.current_ip, "last_seen_at": _iso(client.last_seen_at)},
                "linked_asset": assets.get(row["asset_id"]) or {"asset_id": row["asset_id"]},
                "linked_asset_macs": row["confirmed_asset_macs"],
                "mac_owners": [assets.get(owner) or {"asset_id": owner} for owner in row["matching_other_asset_ids"]],
                "classification": row["classification"],
            },
            [client.id, row["asset_id"], row["observed_mac"], row["matching_other_asset_ids"], row["confirmed_asset_macs"]],
            severity="warning" if definite else "info",
            asset_id=row["asset_id"], mac=row["observed_mac"], ip_address=client.current_ip, hostname=client.hostname,
            search_terms=[label, *(_asset_text(assets.get(owner), owner) for owner in row["matching_other_asset_ids"])],
        ))
    return CheckResult(detections, len(rows), len(rows) >= limit and not subject)


def _check_orphaned_open_assignment(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    query = db.query(AssetNetworkAssignment).filter(*_open_confirmed(), AssetNetworkAssignment.asset_id.is_(None))
    if subject:
        query = query.filter(AssetNetworkAssignment.id == int(subject))
    rows = query.order_by(AssetNetworkAssignment.id.asc()).limit(limit).all()
    detections = [Detection(
        "orphaned_open_assignment", str(row.id), "Open assignment belongs to a deleted asset", f"{row.address} · assignment #{row.id}",
        {"assignment": _assignment(row)}, [row.id, row.status, _iso(row.ended_at), row.asset_id],
        ip_address=row.address,
    ) for row in rows]
    return CheckResult(detections, len(rows), len(rows) >= limit and not subject)


def _check_orphaned_confirmed_evidence(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    query = db.query(AssetIdentityEvidence).filter(
        AssetIdentityEvidence.status == "confirmed", AssetIdentityEvidence.revoked_at.is_(None), AssetIdentityEvidence.asset_id.is_(None),
    )
    if subject:
        query = query.filter(AssetIdentityEvidence.id == int(subject))
    rows = query.order_by(AssetIdentityEvidence.id.asc()).limit(limit).all()
    detections = [Detection(
        "orphaned_confirmed_evidence", str(row.id), f"Confirmed {row.evidence_type.replace('_', ' ')} evidence without an asset",
        f"{row.evidence_type} · {row.normalised_value}"[:255],
        {"evidence": {"evidence_id": row.id, "evidence_type": row.evidence_type, "value": row.normalised_value, "source": row.source,
                      "source_scope": row.source_scope, "confirmed_at": _iso(row.confirmed_at), "last_observed_at": _iso(row.last_observed_at)}},
        [row.id, row.status, _iso(row.revoked_at), row.asset_id],
        mac=row.normalised_value if row.evidence_type == "mac" else None,
        hostname=row.normalised_value if row.evidence_type == "hostname" else None,
        search_terms=[row.normalised_value],
    ) for row in rows]
    return CheckResult(detections, len(rows), len(rows) >= limit and not subject)


def _check_invalid_assignment_interval(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    query = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.ended_at.isnot(None), AssetNetworkAssignment.ended_at < AssetNetworkAssignment.started_at,
    )
    if subject:
        query = query.filter(AssetNetworkAssignment.id == int(subject))
    rows = query.order_by(AssetNetworkAssignment.id.asc()).limit(limit).all()
    assets = _assets(db, {row.asset_id for row in rows})
    detections = []
    for row in rows:
        label = _asset_text(assets.get(row.asset_id), row.asset_id)
        detections.append(Detection(
            "invalid_assignment_interval", str(row.id), "Assignment ends before it starts", f"{label} · {row.address}"[:255],
            {"asset": assets.get(row.asset_id) or {"asset_id": row.asset_id}, "assignment": _assignment(row)},
            [row.id, _iso(row.started_at), _iso(row.ended_at)],
            asset_id=row.asset_id, ip_address=row.address, search_terms=[label],
        ))
    return CheckResult(detections, len(rows), len(rows) >= limit and not subject)


def _check_assignment_provenance_mismatch(db: Session, now: datetime, limit: int, subject: str | None) -> CheckResult:
    managed = (MANAGED_STATIC_PROVENANCE, MANAGED_STATIC_REPAIR_PROVENANCE)
    query = db.query(AssetNetworkAssignment).filter(
        *_open_confirmed(), AssetNetworkAssignment.asset_id.isnot(None),
        or_(
            AssetNetworkAssignment.provenance.in_(managed),
            (AssetNetworkAssignment.provenance == "dhcp_reconciliation") & AssetNetworkAssignment.dhcp_lease_id.is_(None),
        ),
    )
    if subject:
        query = query.filter(AssetNetworkAssignment.id == int(subject))
    rows = query.order_by(AssetNetworkAssignment.id.asc()).limit(limit).all()
    records = {row.id: row for row in db.query(IPAddress).filter(IPAddress.id.in_({row.ip_address_id for row in rows if row.ip_address_id} or {-1}))}
    confirmed = asset_confirmed_macs(db, {row.asset_id for row in rows})
    assets = _assets(db, {row.asset_id for row in rows})
    detections = []
    for row in rows:
        if row.provenance in managed:
            record = records.get(row.ip_address_id)
            record_mac = managed_static_record_mac(record)
            if record is None:
                reason = "The managed IP record no longer exists."
            elif record_mac is None:
                reason = "The managed IP record is no longer Static or no longer carries a MAC."
            elif record_mac not in confirmed.get(row.asset_id, set()):
                reason = "The managed IP record now carries a MAC this asset does not own."
            elif record.address != row.address:
                reason = "The managed IP record now has a different address."
            else:
                continue
        else:
            reason = "The DHCP lease that created this assignment no longer exists, so lease expiry cannot close it."
        label = _asset_text(assets.get(row.asset_id), row.asset_id)
        detections.append(Detection(
            "assignment_provenance_mismatch", str(row.id), "Assignment no longer matches its origin", f"{label} · {row.address}"[:255],
            {"asset": assets.get(row.asset_id) or {"asset_id": row.asset_id}, "assignment": _assignment(row), "reason": reason},
            [row.id, reason, row.ip_address_id, row.dhcp_lease_id],
            asset_id=row.asset_id, ip_address=row.address, search_terms=[label], repairable=False,
        ))
    return CheckResult(detections, len(rows), len(rows) >= limit and not subject)


CHECKS = {
    "duplicate_confirmed_mac": _check_duplicate_confirmed_mac,
    "managed_static_assignment": _check_managed_static_assignment,
    "duplicate_active_ip": _check_duplicate_active_ip,
    "duplicate_open_assignment": _check_duplicate_open_assignment,
    "obsolete_dhcp_assignment": _check_obsolete_dhcp_assignment,
    "suspect_dhcp_client_id": _check_suspect_dhcp_client_id,
    "static_hostname_auto_filled": _check_static_hostname_auto_filled,
    "dns_asset_link_conflict": _check_dns_asset_link_conflict,
    "orphaned_open_assignment": _check_orphaned_open_assignment,
    "orphaned_confirmed_evidence": _check_orphaned_confirmed_evidence,
    "invalid_assignment_interval": _check_invalid_assignment_interval,
    "assignment_provenance_mismatch": _check_assignment_provenance_mismatch,
}
assert set(CHECKS) == set(FINDING_TYPES)


def run_check(db: Session, finding_type: str, *, now: datetime | None = None, limit: int | None = None) -> CheckResult:
    return CHECKS[finding_type](db, now or datetime.utcnow(), _bounded(limit), None)


def detect_subject(db: Session, finding_type: str, subject: str, *, now: datetime | None = None) -> Detection | None:
    """Re-run one finding's check for its subject against current data."""
    if finding_type not in CHECKS or not subject:
        return None
    key = Detection(finding_type, subject, "", "", {}, None).key
    result = CHECKS[finding_type](db, now or datetime.utcnow(), ROWS_PER_SUBJECT, subject)
    return next((detection for detection in result.detections if detection.key == key), None)
