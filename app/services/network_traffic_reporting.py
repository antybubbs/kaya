"""Bounded, canonical reporting queries for the Network Traffic dashboard."""
from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress

from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.models.models import (
    IPAddress,
    TrafficAggregate,
    TrafficCounterObservation,
    TrafficDeviceAggregate,
    TrafficDeviceMonitoring,
    TrafficDiscoveryObservation,
    TrafficInterface,
    TrafficSource,
    VLAN,
    AssetNetworkAssignment,
    HardwareAsset,
)
from app.services.device_traffic import asset_monitoring_status, endpoint_monitoring_states
from app.services.modules import has_module_access
from app.services.network_discovery_mapping import mapped_network_contexts
from app.services.network_monitor_history import resolve_range

REPORT_RANGES = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
    "1y": timedelta(days=365),
}
MAX_REPORT_ROWS = 10000
MAX_DEVICE_USAGE_PAGE = 50
EVIDENCE_ADDRESS_CHUNK = 500
MONITORING_PRIORITY = {"not_monitored": 0, "awaiting_data": 1, "review_required": 2}


def report_window(value: str = "24h", *, now: datetime | None = None) -> tuple[str, datetime, int]:
    if value not in REPORT_RANGES:
        raise ValueError("Unsupported reporting range.")
    now = now or datetime.utcnow()
    duration = REPORT_RANGES[value]
    # Select exactly one persisted resolution. Never add fine and coarse rows.
    bucket_seconds = 300 if duration <= timedelta(hours=24) else 3600 if duration <= timedelta(days=7) else 86400
    return value, now - duration, bucket_seconds


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _wan_interfaces(db: Session, source_id: int | None = None) -> list[TrafficInterface]:
    query = db.query(TrafficInterface).join(TrafficSource).filter(
        TrafficInterface.is_enabled.is_(True),
        TrafficInterface.is_wan.is_(True),
        TrafficSource.is_deleted.is_(False),
    )
    if source_id is not None:
        query = query.filter(TrafficInterface.source_id == source_id)
    return query.order_by(TrafficInterface.id.asc()).all()


def _wan_current(db: Session, interfaces: list[TrafficInterface]) -> tuple[int | None, int | None, datetime | None]:
    download = upload = None
    latest_at = None
    for interface in interfaces:
        observation = db.query(TrafficCounterObservation).filter_by(interface_id=interface.id).order_by(
            TrafficCounterObservation.observed_at.desc()
        ).first()
        if not observation:
            continue
        latest_at = max((latest_at, observation.observed_at), key=lambda item: item or datetime.min)
        for direction, value in ((interface.inbound_direction, observation.inbound_bps), (interface.outbound_direction, observation.outbound_bps)):
            if value is None or direction not in {"download", "upload"}:
                continue
            if direction == "download":
                download = (download or 0) + max(0, int(value))
            else:
                upload = (upload or 0) + max(0, int(value))
    return download, upload, latest_at


def custom_report_window(db: Session, start_text: str | None, end_text: str | None, *, now: datetime | None = None) -> tuple[str, datetime, int, datetime]:
    """Validate a custom range once, in the site timezone, for every report on the page.

    Uses the same persisted-resolution rule as the preset ranges.
    """
    window = resolve_range(db, "custom", start_text, end_text, now=now)
    start, end = window["start"], window["end"]
    duration = end - start
    bucket_seconds = 300 if duration <= timedelta(hours=24) else 3600 if duration <= timedelta(days=7) else 86400
    return "custom", start, bucket_seconds, end


def _period_bucket_count(start: datetime, end: datetime, bucket_seconds: int) -> int:
    """Number of persisted buckets whose start lies in ``[start, end)``."""
    epoch = int((start - datetime(1970, 1, 1)).total_seconds())
    first = epoch + (-epoch % bucket_seconds)
    last = int((end - datetime(1970, 1, 1)).total_seconds())
    return max(0, (last - first + bucket_seconds - 1) // bucket_seconds)


def wan_report(db: Session, *, report_range: str = "24h", source_id: int | None = None, now: datetime | None = None, window: tuple | None = None) -> dict:
    if window is not None:
        selected, start, bucket_seconds, end = window
    else:
        selected, start, bucket_seconds = report_window(report_range, now=now)
        end = now or datetime.utcnow()
    now = now or datetime.utcnow()
    interfaces = _wan_interfaces(db, source_id)
    interface_ids = {item.id for item in interfaces}
    query = db.query(TrafficAggregate).filter(
        TrafficAggregate.interface_id.in_(interface_ids or [-1]),
        TrafficAggregate.bucket_seconds == bucket_seconds,
        TrafficAggregate.bucket_start >= start,
        TrafficAggregate.bucket_start < end,
        TrafficAggregate.direction.in_(["download", "upload"]),
    ).order_by(TrafficAggregate.bucket_start.asc()).limit(MAX_REPORT_ROWS + 1)
    rows = query.all()
    truncated = len(rows) > MAX_REPORT_ROWS
    rows = rows[:MAX_REPORT_ROWS]
    history: dict[datetime, dict] = {}
    totals = {"download": 0, "upload": 0}
    covered: dict[str, set] = {"download": set(), "upload": set()}
    for row in rows:
        covered[row.direction].add((row.interface_id, row.bucket_start))
        point = history.setdefault(row.bucket_start, {"download_bytes": 0, "upload_bytes": 0, "approximate": False, "quality": "observed"})
        key = f"{row.direction}_bytes"
        point[key] += max(0, int(row.bytes_total or 0))
        point["approximate"] = bool(point["approximate"]) or bool(row.is_approximate)
        if row.is_approximate:
            point["quality"] = "approximate"
        totals[row.direction] += max(0, int(row.bytes_total or 0))
    today_start = datetime(now.year, now.month, now.day)
    today = {"download": 0, "upload": 0}
    for row in db.query(TrafficAggregate).filter(
        TrafficAggregate.interface_id.in_(interface_ids or [-1]),
        TrafficAggregate.bucket_seconds == 300,
        TrafficAggregate.bucket_start >= today_start,
        TrafficAggregate.direction.in_(["download", "upload"]),
    ).limit(MAX_REPORT_ROWS).all():
        today[row.direction] += max(0, int(row.bytes_total or 0))
    current_download, current_upload, current_at = _wan_current(db, interfaces)
    # Selected-period transfer totals come from the same persisted, counter-
    # derived rows and boundaries as the history graph; they are never derived
    # from displayed rates. Buckets without a delta (no poll, counter reset or
    # rejected sample) are reported as missing coverage, not as zero traffic.
    expected = _period_bucket_count(start, end, bucket_seconds) * len(interfaces)
    period = {"start": _iso(start), "end": _iso(end), "bucket_seconds": bucket_seconds, "expected_buckets": expected, "truncated": truncated}
    for direction in ("download", "upload"):
        present = len(covered[direction])
        period[f"{direction}_bytes"] = totals[direction] if present else None
        period[f"{direction}_coverage_percent"] = min(100, round(present / expected * 100)) if expected else None
    coverages = [period["download_coverage_percent"], period["upload_coverage_percent"]]
    period["coverage"] = "unavailable" if not any(covered.values()) else "partial" if truncated or any(value is None or value < 100 for value in coverages) else "complete"
    history_items = []
    for at, value in history.items():
        item = {"at": _iso(at), **value}
        item["download_bps"] = round(item["download_bytes"] * 8 / bucket_seconds, 2)
        item["upload_bps"] = round(item["upload_bytes"] * 8 / bucket_seconds, 2)
        history_items.append(item)
    return {
        "range": selected,
        "bucket_seconds": bucket_seconds,
        "source_id": source_id,
        "summary": {
            "current_download_bps": current_download,
            "current_upload_bps": current_upload,
            "download_bytes_today": today["download"],
            "upload_bytes_today": today["upload"],
            "total_bytes": totals["download"] + totals["upload"],
            "download_bytes_period": period["download_bytes"],
            "upload_bytes_period": period["upload_bytes"],
            "period": period,
            "last_observation_at": _iso(current_at),
            "interface_count": len(interfaces),
            "quality": "approximate" if any(point["approximate"] for point in history.values()) else "observed",
        },
        "history": history_items,
    }


def _device_rows(
    db: Session,
    *,
    start: datetime,
    bucket_seconds: int,
    ip_address_id: int | None = None,
    include_context: bool = False,
    end: datetime | None = None,
) -> list[dict]:
    query = db.query(TrafficDeviceAggregate, IPAddress, VLAN).join(
        IPAddress, IPAddress.id == TrafficDeviceAggregate.ip_address_id
    ).outerjoin(VLAN, VLAN.id == IPAddress.vlan_id).join(
        TrafficDeviceMonitoring, TrafficDeviceMonitoring.ip_address_id == IPAddress.id
    ).filter(
        TrafficDeviceMonitoring.is_enabled.is_(True),
        # Assignment-backed aggregates may also carry a managed IP; they are
        # reported once, by the assignment branch below.
        TrafficDeviceAggregate.assignment_id.is_(None),
        TrafficDeviceAggregate.bucket_seconds == bucket_seconds,
        TrafficDeviceAggregate.bucket_start >= start,
    )
    if end is not None:
        query = query.filter(TrafficDeviceAggregate.bucket_start < end)
    if ip_address_id is not None:
        query = query.filter(IPAddress.id == ip_address_id)
    rows = query.order_by(TrafficDeviceAggregate.bucket_start.asc()).limit(MAX_REPORT_ROWS).all()
    grouped: dict[int, dict] = {}
    for aggregate, address, vlan in rows:
        item = grouped.setdefault(address.id, {
            "id": address.id, "name": address.name or address.description or address.address, "address": address.address,
            "vlan": vlan.name if vlan else None, "download_bytes": 0, "upload_bytes": 0, "total_bytes": 0,
            "last_observed_at": None, "quality": "observed", "confidence": aggregate.attribution_confidence or "unknown",
            "source_ids": set(), "observed_bucket_count": set(),
        })
        item["source_ids"].add(aggregate.source_id)
        item["observed_bucket_count"].add(aggregate.bucket_start)
        amount = max(0, int(aggregate.bytes_total or 0))
        if aggregate.direction in {"download", "upload"}:
            item[f"{aggregate.direction}_bytes"] += amount
            item["total_bytes"] += amount
        observed_at = aggregate.last_observed_at or aggregate.bucket_start
        item["last_observed_at"] = max((item["last_observed_at"], observed_at), key=lambda value: value or datetime.min)
        if aggregate.data_quality != "complete":
            item["quality"] = aggregate.data_quality or "partial"
        if aggregate.attribution_confidence == "low":
            item["confidence"] = "low"
        item["monitoring_status"] = "monitored"
    assignment_rows = db.query(TrafficDeviceAggregate, AssetNetworkAssignment, HardwareAsset, VLAN).join(
        AssetNetworkAssignment, AssetNetworkAssignment.id == TrafficDeviceAggregate.assignment_id
    ).outerjoin(HardwareAsset, HardwareAsset.id == AssetNetworkAssignment.asset_id).outerjoin(
        VLAN, VLAN.id == AssetNetworkAssignment.vlan_id
    ).join(TrafficDeviceMonitoring, TrafficDeviceMonitoring.assignment_id == TrafficDeviceAggregate.assignment_id).filter(
        TrafficDeviceMonitoring.is_enabled.is_(True),
        TrafficDeviceAggregate.assignment_id.is_not(None),
        TrafficDeviceAggregate.bucket_seconds == bucket_seconds,
        TrafficDeviceAggregate.bucket_start >= start,
        AssetNetworkAssignment.status == "confirmed",
    )
    if end is not None:
        assignment_rows = assignment_rows.filter(TrafficDeviceAggregate.bucket_start < end)
    if ip_address_id is not None:
        assignment_rows = assignment_rows.filter(AssetNetworkAssignment.ip_address_id == ip_address_id)
    for aggregate, assignment, asset, vlan in assignment_rows.order_by(TrafficDeviceAggregate.bucket_start.asc()).limit(MAX_REPORT_ROWS).all():
        if assignment.started_at > aggregate.bucket_start or (assignment.ended_at and aggregate.bucket_start >= assignment.ended_at):
            continue
        key = f"assignment:{assignment.id}"
        item = grouped.setdefault(key, {
            "id": None, "assignment_id": assignment.id,
            "name": asset.name if asset else assignment.address, "address": assignment.address,
            "vlan": vlan.name if vlan else None, "download_bytes": 0, "upload_bytes": 0, "total_bytes": 0,
            "last_observed_at": None, "quality": "observed", "confidence": aggregate.attribution_confidence or "unknown",
            "source_ids": set(), "observed_bucket_count": set(), "monitoring_status": "monitored",
        })
        item["source_ids"].add(aggregate.source_id)
        item["observed_bucket_count"].add(aggregate.bucket_start)
        amount = max(0, int(aggregate.bytes_total or 0))
        if aggregate.direction in {"download", "upload"}:
            item[f"{aggregate.direction}_bytes"] += amount
            item["total_bytes"] += amount
        observed_at = aggregate.last_observed_at or aggregate.bucket_start
        item["last_observed_at"] = max((item["last_observed_at"], observed_at), key=lambda value: value or datetime.min)
        if aggregate.data_quality != "complete":
            item["quality"] = aggregate.data_quality or "partial"
    now = datetime.utcnow()
    for item in grouped.values():
        last_observed = item["last_observed_at"]
        item["last_observed_at"] = _iso(item["last_observed_at"])
        if include_context:
            item["source_ids"] = sorted(item["source_ids"])
            item["observed_bucket_count"] = len(item["observed_bucket_count"])
        else:
            item.pop("source_ids", None)
            item.pop("observed_bucket_count", None)
        item["status"] = "stale" if last_observed and last_observed < now - timedelta(hours=1) else "active"
    return sorted(grouped.values(), key=lambda item: (-item["total_bytes"], item["name"].lower()))


def device_report(db: Session, *, report_range: str = "24h", ip_address_id: int | None = None, now: datetime | None = None, window: tuple | None = None) -> dict:
    selected, start, bucket_seconds, end = window if window is not None else (*report_window(report_range, now=now), None)
    rows = _device_rows(db, start=start, bucket_seconds=bucket_seconds, ip_address_id=ip_address_id, end=end)
    return {"range": selected, "bucket_seconds": bucket_seconds, "devices": rows}


def device_history(db: Session, ip_address_id: int, *, report_range: str = "24h", now: datetime | None = None, window: tuple | None = None) -> dict:
    selected, start, bucket_seconds, end = window if window is not None else (*report_window(report_range, now=now), None)
    query = db.query(TrafficDeviceAggregate).join(TrafficDeviceMonitoring, TrafficDeviceMonitoring.ip_address_id == TrafficDeviceAggregate.ip_address_id).filter(
        TrafficDeviceAggregate.ip_address_id == ip_address_id,
        TrafficDeviceAggregate.assignment_id.is_(None),
        TrafficDeviceMonitoring.is_enabled.is_(True),
        TrafficDeviceAggregate.bucket_seconds == bucket_seconds,
        TrafficDeviceAggregate.bucket_start >= start,
    )
    if end is not None:
        query = query.filter(TrafficDeviceAggregate.bucket_start < end)
    rows = query.order_by(TrafficDeviceAggregate.bucket_start.asc()).limit(MAX_REPORT_ROWS).all()
    points: dict[datetime, dict] = {}
    for row in rows:
        point = points.setdefault(row.bucket_start, {"download_bytes": 0, "upload_bytes": 0, "quality": "observed", "confidence": row.attribution_confidence})
        if row.direction in {"download", "upload"}:
            point[f"{row.direction}_bytes"] += max(0, int(row.bytes_total or 0))
        if row.data_quality != "complete":
            point["quality"] = row.data_quality or "partial"
        if row.attribution_confidence == "low":
            point["confidence"] = "low"
    return {"ip_address_id": ip_address_id, "range": selected, "bucket_seconds": bucket_seconds, "history": [{"at": _iso(at), **value} for at, value in points.items()]}


def _valid_at(assignment: AssetNetworkAssignment, at: datetime) -> bool:
    return assignment.started_at <= at and (assignment.ended_at is None or at < assignment.ended_at)


def _in_source_scope(assignment: AssetNetworkAssignment, source_id: int | None, exporter_identity: str | None) -> bool:
    return (assignment.source_id is None or assignment.source_id == source_id) and (
        assignment.exporter_identity is None or assignment.exporter_identity == exporter_identity
    )


def _vlan_context_current(assignment: AssetNetworkAssignment) -> bool:
    if assignment.vlan_id is None:
        return True
    vlan = assignment.vlan
    return bool(vlan and vlan.subnet_cidr and assignment.network_cidr and assignment.network_cidr.strip() == vlan.subnet_cidr.strip())


def _assignment_evidence(db: Session, addresses) -> tuple[dict[str, list[AssetNetworkAssignment]], bool]:
    """Confirmed assignments for the addresses, and whether the set is complete.

    Loaded in bounded chunks; if the bound is reached the evidence is reported as
    incomplete so callers resolve nothing from it rather than a partial view.
    """
    by_address: dict[str, list[AssetNetworkAssignment]] = {}
    values = sorted({address for address in addresses if address})
    remaining = MAX_REPORT_ROWS
    for index in range(0, len(values), EVIDENCE_ADDRESS_CHUNK):
        rows = db.query(AssetNetworkAssignment).options(
            joinedload(AssetNetworkAssignment.asset), joinedload(AssetNetworkAssignment.vlan)
        ).filter(
            AssetNetworkAssignment.address.in_(values[index:index + EVIDENCE_ADDRESS_CHUNK]),
            AssetNetworkAssignment.status == "confirmed",
        ).order_by(AssetNetworkAssignment.id.asc()).limit(remaining + 1).all()
        if len(rows) > remaining:
            return {}, False
        remaining -= len(rows)
        for row in rows:
            by_address.setdefault(row.address, []).append(row)
    return by_address, True


def _mapped_vlans(db: Session, cache: dict, source_id: int | None, exporter_identity: str | None) -> list[tuple[int, str, object]]:
    """Enabled exporter-to-VLAN mappings for one source/exporter pair, with VLAN names."""
    key = (source_id, exporter_identity)
    if key not in cache:
        contexts = mapped_network_contexts(db, source_id, exporter_identity) if source_id is not None and exporter_identity else []
        names = {vlan.id: vlan.name for vlan in db.query(VLAN).filter(VLAN.id.in_([vlan_id for vlan_id, _, _ in contexts] or [-1])).all()}
        cache[key] = [(vlan_id, names.get(vlan_id), network) for vlan_id, _, network in contexts]
    return cache[key]


def _resolve_vlan(assignments: list[AssetNetworkAssignment], mappings: list, address: str, source_id: int | None, exporter_identity: str | None, at: datetime) -> tuple[str | None, str]:
    """Return ``(vlan_name, vlan_status)`` from validated context only.

    Evidence is a confirmed assignment valid at ``at`` within the source/exporter
    scope whose VLAN CIDR is still current, or an enabled exporter-to-VLAN mapping
    for that source/exporter whose network contains the address. An address alone
    never establishes a VLAN. Status is ``confirmed``, ``stale`` (an in-scope
    assignment's VLAN context changed), ``conflicting`` (evidence disagrees) or
    ``unknown`` (no evidence).
    """
    established: dict[int, str | None] = {}
    for assignment in assignments:
        if assignment.vlan_id is None or not _in_source_scope(assignment, source_id, exporter_identity) or not _valid_at(assignment, at):
            continue
        if not _vlan_context_current(assignment):
            return None, "stale"
        established[assignment.vlan_id] = assignment.vlan.name
    try:
        endpoint = ipaddress.ip_address(address)
    except ValueError:
        endpoint = None
    if endpoint is not None:
        for vlan_id, name, network in mappings:
            if endpoint.version == network.version and endpoint in network:
                established.setdefault(vlan_id, name)
    if len(established) > 1:
        return None, "conflicting"
    if established:
        return next(iter(established.values())), "confirmed"
    return None, "unknown"


def _single_owner(assignments: list[AssetNetworkAssignment], source_id: int | None, exporter_identity: str | None, first_seen: datetime, last_seen: datetime) -> AssetNetworkAssignment | None:
    """The one asset whose confirmed, in-scope assignment covers the whole span.

    Any other asset holding an in-scope assignment that overlaps the span, or a
    changed VLAN context, leaves the observation unowned.
    """
    overlapping = [
        assignment for assignment in assignments
        if _in_source_scope(assignment, source_id, exporter_identity)
        and assignment.started_at <= last_seen and (assignment.ended_at is None or assignment.ended_at > first_seen)
    ]
    if not overlapping or any(assignment.asset_id is None or not _vlan_context_current(assignment) for assignment in overlapping):
        return None
    if len({assignment.asset_id for assignment in overlapping}) != 1:
        return None
    covering = [assignment for assignment in overlapping if _valid_at(assignment, first_seen) and _valid_at(assignment, last_seen)]
    return covering[0] if covering else None


def device_usage_report(
    db: Session,
    user,
    *,
    report_range: str = "24h",
    start_text: str | None = None,
    end_text: str | None = None,
    query: str = "",
    page: int = 1,
    sort: str = "total",
    now: datetime | None = None,
) -> dict:
    """Return a bounded, read-only Device Usage view.

    Traffic remains limited to administrator-enabled monitoring aggregates. Identity
    labels are derived from existing reviewed evidence and are omitted when the
    caller lacks Asset Manager access.
    """
    if report_range == "custom":
        selected, start, bucket_seconds, end = custom_report_window(db, start_text, end_text, now=now)
    else:
        selected, start, bucket_seconds = report_window(report_range, now=now)
        end = now or datetime.utcnow()
    page = max(1, min(int(page), 100000))
    query = (query or "").strip()[:120].lower()
    sort = sort if sort in {"total", "download", "upload", "name", "last"} else "total"
    can_assets = has_module_access(db, user, "asset_manager")
    all_rows = _device_rows(db, start=start, bucket_seconds=bucket_seconds, include_context=True, end=end)
    observed_rows = db.query(TrafficDiscoveryObservation).filter(
        TrafficDiscoveryObservation.bucket_start >= start,
        TrafficDiscoveryObservation.bucket_start < end,
        TrafficDiscoveryObservation.endpoint_role.like("original%"),
        TrafficDiscoveryObservation.classification == "internal",
    ).order_by(TrafficDiscoveryObservation.last_seen_at.desc()).limit(MAX_REPORT_ROWS).all()

    def bucket_of(value: datetime) -> int:
        # Count presence at the report's resolution so the share cannot exceed
        # the number of buckets in the selected period.
        epoch = int((value - datetime(1970, 1, 1)).total_seconds())
        return epoch - epoch % bucket_seconds

    # One group per source/exporter context and endpoint. Observations carry no
    # usage; they never add bytes to any row.
    groups: dict[tuple, dict] = {}
    for observation in observed_rows:
        key = (observation.source_id, observation.exporter_identity, observation.endpoint_ip)
        group = groups.setdefault(key, {
            "source_id": observation.source_id, "exporter_identity": observation.exporter_identity, "address": observation.endpoint_ip,
            "first_seen": observation.first_seen_at or observation.bucket_start, "last_seen": observation.last_seen_at,
            "confidence": observation.confidence or "unknown", "buckets": set(),
        })
        group["first_seen"] = min(group["first_seen"], observation.first_seen_at or observation.bucket_start)
        group["last_seen"] = max(group["last_seen"], observation.last_seen_at)
        group["buckets"].add(bucket_of(observation.bucket_start))

    evidence, evidence_complete = _assignment_evidence(db, [row["address"] for row in all_rows] + [group["address"] for group in groups.values()])
    assignment_by_id = {assignment.id: assignment for rows in evidence.values() for assignment in rows}
    mapping_cache: dict = {}

    # Measured rows: VLAN from the monitored record's validated context, and a
    # per-source breakdown that starts with the measured source(s).
    measured_by_asset: dict[int, dict | None] = {}
    measured_assignments: dict[tuple, list[tuple[AssetNetworkAssignment, dict]]] = {}
    legacy_by_source: dict[tuple, dict] = {}
    for row in all_rows:
        row["source_breakdown"] = {}
        assignment = assignment_by_id.get(row.get("assignment_id"))
        if row.get("assignment_id") is not None:
            if assignment is None:
                row["vlan"], row["vlan_status"] = None, "unresolved"
            else:
                last_seen = datetime.fromisoformat(row["last_observed_at"].rstrip("Z")) if row.get("last_observed_at") else end
                mappings = _mapped_vlans(db, mapping_cache, assignment.source_id, assignment.exporter_identity)
                row["vlan"], row["vlan_status"] = _resolve_vlan(evidence.get(assignment.address, []), mappings, assignment.address, assignment.source_id, assignment.exporter_identity, last_seen)
                # Two measured rows for one asset are never combined.
                measured_by_asset[assignment.asset_id] = None if assignment.asset_id in measured_by_asset else row
                measured_assignments.setdefault((assignment.address, assignment.source_id), []).append((assignment, row))
            for source_id in row["source_ids"]:
                row["source_breakdown"][(source_id, assignment.exporter_identity if assignment else None)] = {"usage": "measured", "monitoring_status": "monitored", "buckets": set()}
        else:
            row["vlan_status"] = "confirmed" if row.get("vlan") else "none"
            for source_id in row["source_ids"]:
                row["source_breakdown"][(source_id, None)] = {"usage": "measured", "monitoring_status": "monitored", "buckets": set()}
                legacy_by_source[(row["address"], source_id)] = row

    pending: list[tuple] = []
    for key, group in groups.items():
        source_id, exporter_identity, address = key
        legacy = legacy_by_source.get((address, source_id))
        if legacy is not None:
            # Same managed-IP endpoint and source as eligible usage: one row.
            legacy["source_breakdown"][(source_id, None)]["buckets"] |= group["buckets"]
            continue
        # The measured assignment's own source context, valid for the whole
        # observation span: the same endpoint, already listed with its usage.
        same_context = next((
            (assignment, row) for assignment, row in measured_assignments.get((address, source_id), [])
            if _in_source_scope(assignment, source_id, exporter_identity)
            and _valid_at(assignment, group["first_seen"]) and _valid_at(assignment, group["last_seen"])
        ), None)
        if same_context is not None:
            assignment, row = same_context
            row["source_breakdown"][(source_id, assignment.exporter_identity)]["buckets"] |= group["buckets"]
            continue
        pending.append((key, group))

    states = endpoint_monitoring_states(db, [key for key, _ in pending], now=end, observed_at={key: group["last_seen"] for key, group in pending})
    observation_rows: dict[tuple, dict] = {}
    for key, group in pending:
        source_id, exporter_identity, address = key
        state = states.get(key)
        # An enabled monitor without eligible usage in this period is never
        # reported as "not monitored"; the state is source- and time-scoped.
        status = ("review_required" if state.get("status") == "review_required" else "awaiting_data") if state else "not_monitored"
        entry = {"usage": "observed", "monitoring_status": status, "buckets": group["buckets"], "reason": state.get("reason") if state else None}
        owner = _single_owner(evidence.get(address, []), source_id, exporter_identity, group["first_seen"], group["last_seen"]) if evidence_complete and can_assets else None
        target = measured_by_asset.get(owner.asset_id) if owner else None
        if target is not None:
            # The same permanent asset already has measured usage: list this
            # source as a separate context of that row. Bytes are not merged.
            existing = target["source_breakdown"].get((source_id, exporter_identity)) or target["source_breakdown"].get((source_id, None))
            if existing is not None and existing["usage"] == "measured":
                existing["buckets"] |= group["buckets"]
            else:
                target["source_breakdown"][(source_id, exporter_identity)] = entry
            target["source_ids"] = sorted(set(target["source_ids"]) | {source_id})
            continue
        row_key = ("asset", owner.asset_id) if owner else key
        if evidence_complete:
            vlan, vlan_status = _resolve_vlan(evidence.get(address, []), _mapped_vlans(db, mapping_cache, source_id, exporter_identity), address, source_id, exporter_identity, group["last_seen"])
        else:
            vlan, vlan_status = None, "unresolved"
        item = observation_rows.get(row_key)
        if item is None:
            item = observation_rows[row_key] = {
                "id": None, "assignment_id": None, "name": address, "address": address,
                "vlan": vlan, "vlan_status": vlan_status, "download_bytes": None, "upload_bytes": None, "total_bytes": None,
                "last_observed_at": group["last_seen"], "quality": "unavailable", "confidence": group["confidence"],
                "source_ids": set(), "observed_bucket_count": set(), "source_breakdown": {},
                "monitoring_status": "not_monitored", "usage_available": False,
                "_owner": owner,
            }
        elif (item["vlan"], item["vlan_status"]) != (vlan, vlan_status):
            item["vlan"], item["vlan_status"] = None, "conflicting"
        item["source_ids"].add(source_id)
        item["observed_bucket_count"] |= group["buckets"]
        item["last_observed_at"] = max(item["last_observed_at"], group["last_seen"])
        item["source_breakdown"][(source_id, exporter_identity)] = entry
        if MONITORING_PRIORITY[status] > MONITORING_PRIORITY[item["monitoring_status"]]:
            item["monitoring_status"] = status
            item["monitoring_reason"] = entry["reason"]
    # Rows for the same address that could not be tied to one permanent asset
    # remain separate and are labelled as separate source observations.
    address_counts: dict[str, int] = {}
    for row in [*all_rows, *observation_rows.values()]:
        address_counts[row["address"]] = address_counts.get(row["address"], 0) + 1
    for item in observation_rows.values():
        item["separate_source_observation"] = item["_owner"] is None and address_counts[item["address"]] > 1
    all_rows.extend(observation_rows.values())
    rows = list(all_rows)
    if query:
        rows = [row for row in rows if query in f"{row['name']} {row['address']} {row.get('vlan') or ''}".lower()]
    if sort == "name":
        rows.sort(key=lambda row: row["name"].lower())
    elif sort == "last":
        rows.sort(key=lambda row: str(row.get("last_observed_at") or ""), reverse=True)
    else:
        rows.sort(key=lambda row: int(row.get(f"{sort}_bytes", 0) or 0), reverse=True)

    total = len(rows)
    page_count = max(1, (total + MAX_DEVICE_USAGE_PAGE - 1) // MAX_DEVICE_USAGE_PAGE)
    page = min(page, page_count)
    selected_rows = rows[(page - 1) * MAX_DEVICE_USAGE_PAGE : page * MAX_DEVICE_USAGE_PAGE]
    ip_ids = [int(row["id"]) for row in selected_rows if row.get("id") is not None]
    assignment_ids = [int(row["assignment_id"]) for row in selected_rows if row.get("assignment_id") is not None]
    addresses = [row["address"] for row in selected_rows if row.get("address")]
    source_ids = set()
    for row in selected_rows:
        source_ids.update(int(value) for value in row.get("source_ids", []))
    sources = {
        source.id: source.name
        for source in db.query(TrafficSource).filter(TrafficSource.id.in_(source_ids or [-1])).limit(100).all()
    }
    assignments = db.query(AssetNetworkAssignment).options(
        joinedload(AssetNetworkAssignment.asset), joinedload(AssetNetworkAssignment.vlan)
    ).filter(
        or_(AssetNetworkAssignment.ip_address_id.in_(ip_ids or [-1]), AssetNetworkAssignment.id.in_(assignment_ids or [-1]), AssetNetworkAssignment.address.in_(addresses or ["0.0.0.0"])),
        AssetNetworkAssignment.status.in_(("confirmed", "pending")),
    ).order_by(AssetNetworkAssignment.started_at.desc()).limit(500).all()
    by_ip: dict[int, list[AssetNetworkAssignment]] = {}
    by_assignment: dict[int, AssetNetworkAssignment] = {}
    for assignment in assignments:
        if assignment.ip_address_id is not None:
            by_ip.setdefault(assignment.ip_address_id, []).append(assignment)
        by_assignment[assignment.id] = assignment
    measured_asset_ids = {
        by_assignment[row["assignment_id"]].asset_id for row in selected_rows
        if row.get("monitoring_status") == "monitored" and row.get("assignment_id") in by_assignment
    } - {None}
    monitors = {
        monitor.asset_id: monitor
        for monitor in db.query(TrafficDeviceMonitoring).filter(TrafficDeviceMonitoring.asset_id.in_(measured_asset_ids or [-1])).limit(MAX_DEVICE_USAGE_PAGE).all()
    }
    for row in selected_rows:
        last_value = row.get("last_observed_at")
        observed = last_value if isinstance(last_value, datetime) else datetime.fromisoformat(last_value.rstrip("Z")) if last_value else None
        candidates = []
        reviewable = []
        source_candidates = [by_assignment[row["assignment_id"]]] if row.get("assignment_id") in by_assignment else by_ip.get(row.get("id"), [])
        if not source_candidates and row.get("address"):
            source_candidates = [item for item in assignments if item.address == row["address"]]
        for assignment in source_candidates:
            if observed and assignment.started_at <= observed and (assignment.ended_at is None or observed < assignment.ended_at):
                if assignment.source_id is not None and assignment.source_id not in row.get("source_ids", []):
                    continue
                # Device aggregates retain source context but not exporter identity;
                # exporter-scoped assignments therefore remain reviewable suggestions.
                if assignment.exporter_identity and assignment.id != row.get("assignment_id"):
                    reviewable.append(assignment)
                    continue
                if assignment.vlan_id is not None and assignment.vlan and assignment.network_cidr != assignment.vlan.subnet_cidr:
                    continue
                candidates.append(assignment)
        asset_ids = {item.asset_id for item in candidates if item.asset_id is not None}
        owner = row.pop("_owner", None)
        if owner is not None and can_assets:
            # Observations already tied to one permanent asset for their whole span.
            candidates, asset_ids = [owner], {owner.asset_id}
        if len(asset_ids) == 1 and can_assets:
            assignment = next(item for item in candidates if item.asset_id in asset_ids)
            row.update({
                "identity_status": "confirmed",
                "asset_id": assignment.asset_id,
                "asset_name": assignment.asset.name if assignment.asset else None,
                "asset_url": f"/infrastructure/asset-manager/{assignment.asset_id}",
            })
        elif candidates or reviewable:
            row.update({"identity_status": "suggested", "asset_id": None, "asset_name": None, "asset_url": None})
        else:
            row.update({"identity_status": "unidentified", "asset_id": None, "asset_name": None, "asset_url": None})
        row["source_context"] = [sources[source_id] for source_id in row.get("source_ids", []) if source_id in sources]
        if isinstance(last_value, datetime):
            row["last_observed_at"] = _iso(last_value)
        period_buckets = max(1, int((end - start).total_seconds() / bucket_seconds))
        bucket_count = row.get("observed_bucket_count", 0)
        if isinstance(bucket_count, (set, list, tuple)):
            bucket_count = len(bucket_count)
        row["coverage_percent"] = min(100, round((int(bucket_count or 0) / period_buckets) * 100))
        # Each source/exporter context stays distinguishable, with its own
        # monitoring status and observed share; only measured contexts carry usage.
        row["source_breakdown"] = [
            {
                "source": sources.get(source_id) or "Unknown source", "exporter_identity": exporter_identity,
                "usage": entry["usage"], "monitoring_status": entry["monitoring_status"],
                "coverage_percent": min(100, round(len(entry["buckets"]) / period_buckets * 100)) if entry["buckets"] else None,
            }
            for (source_id, exporter_identity), entry in sorted(row.get("source_breakdown", {}).items(), key=lambda item: (item[1]["usage"] != "measured", item[0][0], item[0][1] or ""))
        ]
        if row.get("assignment_id") is not None and row.get("monitoring_status") == "monitored":
            assignment = by_assignment.get(row["assignment_id"])
            state = asset_monitoring_status(db, assignment.asset_id, now=end, monitor=monitors.get(assignment.asset_id)) if assignment and assignment.asset_id else None
            if state and state.get("status") == "review_required":
                # Usage already measured stays visible; the monitor itself needs review.
                row["monitoring_attention"] = "review_required"
                row["monitoring_reason"] = state.get("reason")
        row.pop("source_ids", None)
        row.pop("observed_bucket_count", None)
    return {
        "range": selected, "bucket_seconds": bucket_seconds, "page": page,
        "page_size": MAX_DEVICE_USAGE_PAGE, "total": total, "page_count": page_count,
        "devices": selected_rows,
        "summary": {
            "monitored_devices": sum(1 for row in all_rows if row.get("monitoring_status") == "monitored"),
            "download_bytes": sum(int(row.get("download_bytes", 0) or 0) for row in all_rows),
            "upload_bytes": sum(int(row.get("upload_bytes", 0) or 0) for row in all_rows),
            "total_bytes": sum(int(row.get("total_bytes", 0) or 0) for row in all_rows),
            "coverage_percent": round(sum(int(row.get("coverage_percent", 0) or 0) for row in all_rows if row.get("monitoring_status") == "monitored") / max(1, sum(1 for row in all_rows if row.get("monitoring_status") == "monitored"))),
        },
    }
