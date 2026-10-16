"""Opt-in, bounded device traffic attribution and rollups."""
from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress

from sqlalchemy import case, or_, text
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models.models import (
    IPAddress, TrafficDeviceAggregate, TrafficDeviceMonitoring,
    TrafficDeviceMonitoringPeriod, TrafficMonitoringConfiguration, TrafficSource, TrafficLocalNetwork,
    AssetNetworkAssignment, HardwareAsset, VLAN,
)
from app.services.audit import write_audit
from app.services.asset_identity import _lock_assignment_context
from app.services.flow_accounting import resolve_flow_attribution
from app.services.flow_protocol import NormalizedFlowRecord


def traffic_monitoring_for(db: Session, ip_address_id: int) -> TrafficDeviceMonitoring | None:
    return db.query(TrafficDeviceMonitoring).filter_by(ip_address_id=ip_address_id).first()


def asset_monitoring_for(db: Session, asset_id: int) -> TrafficDeviceMonitoring | None:
    return db.query(TrafficDeviceMonitoring).filter_by(asset_id=asset_id).first()


# Upper bound on candidate assignments considered for one flow endpoint. One
# extra row is fetched so an incomplete candidate set is detected, never judged.
ASSIGNMENT_CANDIDATE_LIMIT = 10


def _assignment_for_record(db: Session, record: NormalizedFlowRecord, address: str | None) -> AssetNetworkAssignment | None:
    if not address:
        return None
    try:
        normalised = ipaddress.ip_address(address).compressed
        family = ipaddress.ip_address(address).version
    except ValueError:
        return None
    rows = db.query(AssetNetworkAssignment).outerjoin(VLAN, VLAN.id == AssetNetworkAssignment.vlan_id).filter(
        AssetNetworkAssignment.address == normalised,
        AssetNetworkAssignment.address_family == family,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.started_at <= record.observed_at,
        or_(AssetNetworkAssignment.ended_at.is_(None), AssetNetworkAssignment.ended_at > record.observed_at),
        or_(AssetNetworkAssignment.source_id.is_(None), AssetNetworkAssignment.source_id == record.source_id),
        or_(AssetNetworkAssignment.exporter_identity.is_(None), AssetNetworkAssignment.exporter_identity == record.exporter_identity),
        or_(AssetNetworkAssignment.vlan_id.is_(None), AssetNetworkAssignment.network_cidr == VLAN.subnet_cidr),
    ).order_by(AssetNetworkAssignment.id.asc()).limit(ASSIGNMENT_CANDIDATE_LIMIT + 1).all()
    if len(rows) > ASSIGNMENT_CANDIDATE_LIMIT:
        # Ownership cannot be proven unique from a truncated candidate set; a
        # conflicting owner may lie beyond the bound. Fail closed.
        return None
    if len(rows) == 1:
        return rows[0]
    # A single asset commonly holds both a source-less assignment and the
    # administrator-confirmed source-scoped context for the same address. Only
    # then is the fully scoped row selected; claims spanning assets, or several
    # equally specific rows, remain ambiguous and fail closed.
    if not rows or len({row.asset_id for row in rows}) != 1 or None in {row.asset_id for row in rows}:
        return None
    scoped = [
        row for row in rows
        if row.source_id == record.source_id and row.exporter_identity == record.exporter_identity
    ]
    return scoped[0] if len(scoped) == 1 else None


def _asset_monitoring_period(db: Session, monitoring_id: int, assignment_id: int, observed_at: datetime) -> TrafficDeviceMonitoringPeriod | None:
    return db.query(TrafficDeviceMonitoringPeriod).filter(
        TrafficDeviceMonitoringPeriod.monitoring_id == monitoring_id,
        TrafficDeviceMonitoringPeriod.assignment_id == assignment_id,
        TrafficDeviceMonitoringPeriod.started_at <= observed_at,
        or_(TrafficDeviceMonitoringPeriod.ended_at.is_(None), TrafficDeviceMonitoringPeriod.ended_at >= observed_at),
    ).order_by(TrafficDeviceMonitoringPeriod.started_at.desc()).first()


def set_asset_monitoring(db: Session, user, asset: HardwareAsset, enabled: bool, *, now: datetime | None = None) -> dict:
    """Enable one explicitly selected, confirmed assignment for an asset.

    The operation is intentionally source-scoped and requires a usable flow source;
    it never creates a managed IP record or follows an address automatically.
    """
    if not user or user.role != "admin":
        raise PermissionError("Administrator access is required.")
    if not asset or not db.get(HardwareAsset, asset.id):
        raise ValueError("Hardware asset not found.")
    now = now or datetime.utcnow()
    assignments = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.asset_id == asset.id,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.started_at <= now,
        or_(AssetNetworkAssignment.ended_at.is_(None), AssetNetworkAssignment.ended_at > now),
        AssetNetworkAssignment.source_id.is_not(None),
    ).order_by(AssetNetworkAssignment.started_at.desc()).limit(10).all()
    eligible = []
    for assignment in assignments:
        source = db.query(TrafficSource).filter(
            TrafficSource.id == assignment.source_id,
            TrafficSource.is_enabled.is_(True),
            TrafficSource.is_deleted.is_(False),
            TrafficSource.provider_key.in_(("netflow_v9", "cisco_nsel")),
        ).first()
        if source:
            eligible.append(assignment)
    if len(eligible) != 1:
        raise ValueError("Exactly one current, source-scoped network assignment is required for monitoring.")
    assignment = eligible[0]
    _lock_assignment_context(
        db,
        address=assignment.address,
        family=assignment.address_family,
        vlan_id=assignment.vlan_id,
        source_id=assignment.source_id,
        exporter_identity=assignment.exporter_identity,
    )
    row = asset_monitoring_for(db, asset.id)
    if enabled and assignment.ip_address_id is not None:
        legacy = traffic_monitoring_for(db, assignment.ip_address_id)
        if legacy and legacy.is_enabled and (not row or row.assignment_id != assignment.id):
            raise ValueError("This endpoint is already monitored through its managed IP record.")
    if row is None:
        row = TrafficDeviceMonitoring(asset_id=asset.id, assignment_id=assignment.id, is_enabled=False, status="disabled")
        db.add(row)
        db.flush()
    if row.assignment_id != assignment.id:
        if row.is_enabled:
            raise ValueError("Another asset assignment is already monitored for this asset.")
        row.assignment_id = assignment.id
    changed = bool(row.is_enabled) != bool(enabled)
    period_id = None
    if changed and enabled:
        period = TrafficDeviceMonitoringPeriod(
            monitoring_id=row.id, asset_id=asset.id, assignment_id=assignment.id,
            endpoint_address=assignment.address, address_family=assignment.address_family,
            exporter_identity=assignment.exporter_identity, started_at=now,
        )
        db.add(period)
        db.flush()
        period_id = period.id
        row.is_enabled = True
        row.enabled_at = now
        row.disabled_at = None
        row.status = "awaiting_data"
        row.status_reason = "Waiting for an eligible flow observation"
    elif changed and not enabled:
        active = db.query(TrafficDeviceMonitoringPeriod).filter_by(monitoring_id=row.id, ended_at=None).first()
        if active:
            active.ended_at = now
        row.is_enabled = False
        row.disabled_at = now
        row.status = "disabled"
        row.status_reason = "Disabled by administrator"
    if changed:
        audit = write_audit(db, user, "update", "traffic_device_monitoring", str(row.id), detail="Changed asset network traffic monitoring", metadata={"asset_id": asset.id, "assignment_id": assignment.id, "enabled": bool(enabled)}, force=True, commit=False)
        if audit is None:
            db.rollback()
            raise RuntimeError("The monitoring change could not be audited.")
    return {"changed": changed, "enabled": bool(row.is_enabled), "period_id": period_id, "assignment_id": assignment.id, "status": row.status, "reason": row.status_reason}


def asset_monitoring_status(db: Session, asset_id: int, *, now: datetime | None = None, monitor: TrafficDeviceMonitoring | None = None) -> dict:
    """Return the asset's monitoring lifecycle state.

    ``monitor`` may be supplied when the caller already loaded the asset's
    monitoring row, avoiding a repeat lookup; it must belong to ``asset_id``.
    """
    now = now or datetime.utcnow()
    row = monitor if monitor is not None and monitor.asset_id == asset_id else asset_monitoring_for(db, asset_id)
    if not row or not row.is_enabled:
        return {"enabled": False, "status": "disabled", "reason": row.status_reason if row else "Not enabled", "assignment_id": row.assignment_id if row else None}
    assignment = db.get(AssetNetworkAssignment, row.assignment_id) if row.assignment_id else None
    if not assignment or assignment.status != "confirmed":
        return {"enabled": True, "status": "review_required", "reason": "The confirmed network assignment is no longer available.", "assignment_id": row.assignment_id}
    if assignment.started_at > now or (assignment.ended_at is not None and now >= assignment.ended_at):
        return {"enabled": True, "status": "review_required", "reason": "The monitored network assignment is outside its valid time period.", "assignment_id": assignment.id, "source_id": assignment.source_id}
    if assignment.vlan_id is not None and (not assignment.vlan or assignment.network_cidr != assignment.vlan.subnet_cidr):
        return {"enabled": True, "status": "review_required", "reason": "The VLAN network context changed; review the assignment before monitoring continues.", "assignment_id": assignment.id, "source_id": assignment.source_id}
    return {"enabled": True, "status": row.status, "reason": row.status_reason, "enabled_at": row.enabled_at, "disabled_at": row.disabled_at, "last_attributed_at": row.last_attributed_at, "assignment_id": row.assignment_id, "source_id": row.last_source_id}


def endpoint_monitoring_states(db: Session, endpoints, *, now: datetime | None = None, observed_at: dict | None = None) -> dict[tuple, dict]:
    """Return the existing monitoring status for observed endpoints that have one.

    ``endpoints`` are ``(source_id, exporter_identity, address)`` keys. Asset
    monitors match only their confirmed assignment's address and source context;
    managed-IP monitors match their managed address. When ``observed_at`` maps a
    key to its observation time, an asset monitor matches only if its assignment
    was valid then, so a previous owner's monitor never labels a reassigned
    address. Status comes from ``asset_monitoring_status``/``device_monitoring_status``
    so every view shares one lifecycle. Endpoints without an enabled monitor are
    omitted; an endpoint claimed by two asset monitors is ``review_required``.
    """
    now = now or datetime.utcnow()
    observed_at = observed_at or {}
    keys = list(endpoints)
    addresses = {address for _, _, address in keys if address}
    if not addresses:
        return {}
    states: dict[tuple, dict] = {}
    asset_monitors = db.query(TrafficDeviceMonitoring, AssetNetworkAssignment).join(
        AssetNetworkAssignment, AssetNetworkAssignment.id == TrafficDeviceMonitoring.assignment_id
    ).filter(
        TrafficDeviceMonitoring.is_enabled.is_(True),
        TrafficDeviceMonitoring.asset_id.is_not(None),
        AssetNetworkAssignment.address.in_(addresses),
    ).limit(500).all()
    asset_status: dict[int, dict] = {}
    keys_by_context: dict[tuple, list[tuple]] = {}
    for key in keys:
        keys_by_context.setdefault((key[2], key[0]), []).append(key)
    for monitor, assignment in asset_monitors:
        for key in keys_by_context.get((assignment.address, assignment.source_id), ()):
            source_id, exporter_identity, address = key
            if assignment.exporter_identity is not None and assignment.exporter_identity != exporter_identity:
                continue
            seen_at = observed_at.get(key)
            if seen_at is not None and (assignment.started_at > seen_at or (assignment.ended_at is not None and seen_at >= assignment.ended_at)):
                continue
            if key in states and states[key].get("asset_id") != monitor.asset_id:
                states[key] = {"enabled": True, "status": "review_required", "reason": "More than one monitored asset claims this address and source.", "assignment_id": None, "asset_id": None}
                continue
            if monitor.asset_id not in asset_status:
                asset_status[monitor.asset_id] = asset_monitoring_status(db, monitor.asset_id, now=now, monitor=monitor)
            states[key] = {**asset_status[monitor.asset_id], "assignment_id": assignment.id, "asset_id": monitor.asset_id}
    legacy_monitors = db.query(TrafficDeviceMonitoring, IPAddress).join(
        IPAddress, IPAddress.id == TrafficDeviceMonitoring.ip_address_id
    ).filter(
        TrafficDeviceMonitoring.is_enabled.is_(True),
        IPAddress.address.in_(addresses),
    ).limit(500).all()
    for monitor, ip_record in legacy_monitors:
        status = device_monitoring_status(db, ip_record.id, now=now)
        for key in keys:
            if key[2] == ip_record.address and key not in states:
                states[key] = {**status, "ip_address_id": ip_record.id}
    return states


def set_device_monitoring(db: Session, ip_address: IPAddress, enabled: bool, *, now: datetime | None = None) -> dict:
    now = now or datetime.utcnow()
    row = traffic_monitoring_for(db, ip_address.id)
    if row is None:
        row = TrafficDeviceMonitoring(ip_address_id=ip_address.id, is_enabled=False, status="disabled")
        db.add(row)
        db.flush()
    changed = bool(row.is_enabled) != bool(enabled)
    period_id = None
    if changed and enabled:
        period = TrafficDeviceMonitoringPeriod(monitoring_id=row.id, ip_address_id=ip_address.id, started_at=now)
        db.add(period)
        db.flush()
        period_id = period.id
        row.is_enabled = True
        row.enabled_at = now
        row.disabled_at = None
        row.status = "awaiting_data"
        row.status_reason = "Waiting for an eligible flow observation"
    elif changed and not enabled:
        active = db.query(TrafficDeviceMonitoringPeriod).filter_by(monitoring_id=row.id, ended_at=None).first()
        if active:
            active.ended_at = now
        row.is_enabled = False
        row.disabled_at = now
        row.status = "disabled"
        row.status_reason = "Disabled by administrator"
    return {"changed": changed, "enabled": bool(row.is_enabled), "period_id": period_id}


def device_monitoring_status(db: Session, ip_address_id: int, *, now: datetime | None = None) -> dict:
    now = now or datetime.utcnow()
    row = traffic_monitoring_for(db, ip_address_id)
    if not row or not row.is_enabled:
        return {"enabled": False, "status": "disabled", "reason": row.status_reason if row else "Not enabled"}
    config = db.get(TrafficMonitoringConfiguration, 1)
    source = db.query(TrafficSource).filter(TrafficSource.is_enabled.is_(True), TrafficSource.is_deleted.is_(False), TrafficSource.provider_key.in_(["netflow_v9", "cisco_nsel"])).first()
    status, reason = row.status, row.status_reason
    if not config or not config.is_enabled:
        status, reason = "awaiting_data", "The global flow collector is disabled"
    elif not source:
        status, reason = "awaiting_data", "No compatible enabled flow source is configured"
    elif not row.last_attributed_at:
        status, reason = "awaiting_data", "Waiting for an eligible attributed observation"
    elif row.last_attributed_at < now - timedelta(hours=1):
        status, reason = "stale", "No attributed observation in the last hour"
    return {"enabled": True, "status": status, "reason": reason, "enabled_at": row.enabled_at, "disabled_at": row.disabled_at, "last_attributed_at": row.last_attributed_at, "source_id": row.last_source_id}


def _insert(db: Session, values: dict):
    table = TrafficDeviceAggregate.__table__
    statement = postgres_insert(table) if db.bind.dialect.name == "postgresql" else sqlite_insert(table) if db.bind.dialect.name == "sqlite" else None
    if statement is None:
        return None
    excluded = statement.excluded
    assignment_target = values.get("assignment_id") is not None
    return statement.values(**values).on_conflict_do_update(
        index_elements=(
            ["period_id", "assignment_id", "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction"]
            if values.get("assignment_id") is not None
            else ["period_id", "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction"]
        ),
        index_where=text("assignment_id IS NOT NULL" if assignment_target else "assignment_id IS NULL"),
        set_={
            "bytes_total": table.c.bytes_total + excluded.bytes_total,
            "packets_total": table.c.packets_total + excluded.packets_total,
            "sample_count": table.c.sample_count + excluded.sample_count,
            "data_quality": case((or_(table.c.data_quality == "partial", excluded.data_quality == "partial"), "partial"), else_=table.c.data_quality),
            "first_observed_at": case((table.c.first_observed_at > excluded.first_observed_at, excluded.first_observed_at), else_=table.c.first_observed_at),
            "last_observed_at": case((table.c.last_observed_at < excluded.last_observed_at, excluded.last_observed_at), else_=table.c.last_observed_at),
        },
    )


def persist_device_traffic(db: Session, record: NormalizedFlowRecord, byte_count: int, packet_count: int, source_id: int) -> int:
    config = db.get(TrafficMonitoringConfiguration, 1)
    if not config or not config.is_enabled or byte_count <= 0 and packet_count <= 0:
        return 0
    source = db.get(TrafficSource, source_id)
    if not source:
        return 0
    networks = [n.network_cidr for n in db.query(TrafficLocalNetwork).filter(TrafficLocalNetwork.is_enabled.is_(True)).limit(256).all()]
    attributed = []
    directional_nsel = record.forward_bytes is not None or record.reverse_bytes is not None or record.forward_packets is not None or record.reverse_packets is not None
    if directional_nsel:
        source_attribution = resolve_flow_attribution(db, record, address=record.source_ip, local_networks=networks)
        destination_attribution = resolve_flow_attribution(db, record, address=record.destination_ip, local_networks=networks)
        if source_attribution.state == "resolved":
            direction_specs = (("upload", record.source_ip, record.input_interface, source_attribution, record.forward_bytes, record.forward_packets), ("download", record.source_ip, record.output_interface, source_attribution, record.reverse_bytes, record.reverse_packets))
        elif destination_attribution.state == "resolved":
            direction_specs = (("upload", record.destination_ip, record.output_interface, destination_attribution, record.reverse_bytes, record.reverse_packets), ("download", record.destination_ip, record.input_interface, destination_attribution, record.forward_bytes, record.forward_packets))
        else:
            # A confirmed asset assignment is source-scoped and may exist without
            # a managed IP record. Select the endpoint that holds the assignment
            # and apply the same initiator/responder byte mapping as above, so
            # both halves of the conversation are attributed to that endpoint.
            if _assignment_for_record(db, record, record.source_ip):
                direction_specs = (("upload", record.source_ip, record.input_interface, None, record.forward_bytes, record.forward_packets), ("download", record.source_ip, record.output_interface, None, record.reverse_bytes, record.reverse_packets))
            elif _assignment_for_record(db, record, record.destination_ip):
                direction_specs = (("upload", record.destination_ip, record.output_interface, None, record.reverse_bytes, record.reverse_packets), ("download", record.destination_ip, record.input_interface, None, record.forward_bytes, record.forward_packets))
            else:
                direction_specs = (("upload", record.source_ip, record.input_interface, None, record.forward_bytes, record.forward_packets), ("download", record.destination_ip, record.output_interface, None, record.reverse_bytes, record.reverse_packets))
    else:
        direction_specs = (("upload", record.source_ip, record.input_interface, None, None, None), ("download", record.destination_ip, record.output_interface, None, None, None))
    for direction, address, interface_index, supplied_attribution, supplied_bytes, supplied_packets in direction_specs:
        direction_bytes = byte_count
        direction_packets = packet_count
        if directional_nsel:
            direction_bytes = supplied_bytes
            direction_bytes = int(direction_bytes or 0)
        if directional_nsel:
            direction_packets = supplied_packets
            direction_packets = int(direction_packets or 0)
        if direction_bytes <= 0 and direction_packets <= 0:
            continue
        attribution = supplied_attribution or resolve_flow_attribution(db, record, address=address, local_networks=networks)
        assignment = None
        monitor = traffic_monitoring_for(db, attribution.ip_record_id) if attribution.state == "resolved" and attribution.ip_record_id else None
        if not monitor or not monitor.is_enabled:
            assignment = _assignment_for_record(db, record, address)
        if attribution.state != "resolved" and not assignment:
            continue
        if assignment:
            monitor = db.query(TrafficDeviceMonitoring).filter_by(assignment_id=assignment.id, is_enabled=True).first()
        if not monitor or not monitor.is_enabled:
            continue
        period = (
            _asset_monitoring_period(db, monitor.id, assignment.id, record.observed_at)
            if assignment else db.query(TrafficDeviceMonitoringPeriod).filter(
                TrafficDeviceMonitoringPeriod.monitoring_id == monitor.id,
                TrafficDeviceMonitoringPeriod.started_at <= record.observed_at,
                or_(TrafficDeviceMonitoringPeriod.ended_at.is_(None), TrafficDeviceMonitoringPeriod.ended_at >= record.observed_at),
            ).order_by(TrafficDeviceMonitoringPeriod.started_at.desc()).first()
        )
        if not period:
            continue
        interface = next((i for i in source.interfaces if i.interface_index == interface_index), None)
        for bucket_seconds in (300, 3600, 86400):
            values = {"period_id": period.id, "ip_address_id": attribution.ip_record_id if attribution.state == "resolved" else None, "asset_id": assignment.asset_id if assignment else None, "assignment_id": assignment.id if assignment else None, "endpoint_address": assignment.address if assignment else None, "address_family": assignment.address_family if assignment else None, "exporter_identity": record.exporter_identity if assignment else None, "source_id": source_id, "interface_id": interface.id if interface else None, "bucket_start": datetime.utcfromtimestamp(int(record.observed_at.timestamp()) - int(record.observed_at.timestamp()) % bucket_seconds), "bucket_seconds": bucket_seconds, "direction": direction, "bytes_total": direction_bytes, "packets_total": direction_packets, "sample_count": 1, "data_quality": record.data_quality, "attribution_confidence": attribution.confidence if attribution.state == "resolved" else "high", "first_observed_at": record.observed_at, "last_observed_at": record.observed_at}
            # PostgreSQL UNIQUE constraints treat NULL interface IDs as
            # distinct values, so the database upsert cannot merge flows when
            # the exporter omits interface fields. Lock and merge that row
            # explicitly while preserving the existing upsert for known IDs.
            if interface is None:
                match = db.query(TrafficDeviceAggregate).filter(
                    TrafficDeviceAggregate.period_id == period.id,
                    TrafficDeviceAggregate.assignment_id == values["assignment_id"],
                    TrafficDeviceAggregate.asset_id == values["asset_id"],
                    TrafficDeviceAggregate.source_id == source_id,
                    TrafficDeviceAggregate.interface_id.is_(None),
                    TrafficDeviceAggregate.bucket_start == values["bucket_start"],
                    TrafficDeviceAggregate.bucket_seconds == bucket_seconds,
                    TrafficDeviceAggregate.direction == direction,
                ).with_for_update().first()
                if match:
                    match.bytes_total += direction_bytes
                    match.packets_total += direction_packets
                    match.sample_count += 1
                    continue
                db.add(TrafficDeviceAggregate(**values))
                continue
            statement = _insert(db, values)
            if statement is not None:
                db.execute(statement)
            else:
                match = db.query(TrafficDeviceAggregate).filter_by(**{k: values[k] for k in ("period_id", "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction")}).first()
                if match:
                    match.bytes_total += direction_bytes
                    match.packets_total += direction_packets
                    match.sample_count += 1
                else:
                    db.add(TrafficDeviceAggregate(**values))
        monitor.last_attributed_at = record.observed_at
        monitor.last_source_id = source_id
        monitor.status = "active"
        monitor.status_reason = None
        attributed.append(attribution.ip_record_id or -assignment.id)
    return len(set(attributed))
