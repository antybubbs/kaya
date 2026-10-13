"""Opt-in, bounded device traffic attribution and rollups."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import case, or_
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models.models import (
    IPAddress, TrafficDeviceAggregate, TrafficDeviceMonitoring,
    TrafficDeviceMonitoringPeriod, TrafficMonitoringConfiguration, TrafficSource, TrafficLocalNetwork,
)
from app.services.flow_accounting import resolve_flow_attribution
from app.services.flow_protocol import NormalizedFlowRecord


def traffic_monitoring_for(db: Session, ip_address_id: int) -> TrafficDeviceMonitoring | None:
    return db.query(TrafficDeviceMonitoring).filter_by(ip_address_id=ip_address_id).first()


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
    return statement.values(**values).on_conflict_do_update(
        index_elements=["period_id", "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction"],
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
            direction_specs = ()
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
        if attribution.state != "resolved" or not attribution.ip_record_id:
            continue
        monitor = traffic_monitoring_for(db, attribution.ip_record_id)
        if not monitor or not monitor.is_enabled:
            continue
        period = db.query(TrafficDeviceMonitoringPeriod).filter(
            TrafficDeviceMonitoringPeriod.monitoring_id == monitor.id,
            TrafficDeviceMonitoringPeriod.started_at <= record.observed_at,
            or_(TrafficDeviceMonitoringPeriod.ended_at.is_(None), TrafficDeviceMonitoringPeriod.ended_at >= record.observed_at),
        ).order_by(TrafficDeviceMonitoringPeriod.started_at.desc()).first()
        if not period:
            continue
        interface = next((i for i in source.interfaces if i.interface_index == interface_index), None)
        for bucket_seconds in (300, 3600, 86400):
            values = {"period_id": period.id, "ip_address_id": attribution.ip_record_id, "source_id": source_id, "interface_id": interface.id if interface else None, "bucket_start": datetime.utcfromtimestamp(int(record.observed_at.timestamp()) - int(record.observed_at.timestamp()) % bucket_seconds), "bucket_seconds": bucket_seconds, "direction": direction, "bytes_total": direction_bytes, "packets_total": direction_packets, "sample_count": 1, "data_quality": record.data_quality, "attribution_confidence": attribution.confidence, "first_observed_at": record.observed_at, "last_observed_at": record.observed_at}
            # PostgreSQL UNIQUE constraints treat NULL interface IDs as
            # distinct values, so the database upsert cannot merge flows when
            # the exporter omits interface fields. Lock and merge that row
            # explicitly while preserving the existing upsert for known IDs.
            if interface is None:
                match = db.query(TrafficDeviceAggregate).filter(
                    TrafficDeviceAggregate.period_id == period.id,
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
                    match.bytes_total += direction_bytes; match.packets_total += direction_packets; match.sample_count += 1
                else:
                    db.add(TrafficDeviceAggregate(**values))
        monitor.last_attributed_at = record.observed_at
        monitor.last_source_id = source_id
        monitor.status = "active"
        monitor.status_reason = None
        attributed.append(attribution.ip_record_id)
    return len(set(attributed))
