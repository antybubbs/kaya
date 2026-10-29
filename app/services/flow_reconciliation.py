"""Bounded rollup retention and deliberately conservative SNMP/flow comparison."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.models import TrafficDeviceAggregate, TrafficFlowAccountingAggregate, TrafficFlowReconciliation, TrafficInterface, TrafficSource
from app.services.endpoint_traffic import cleanup_endpoint_aggregates
from app.services.flow_accounting import retention_cutoffs


def cleanup_flow_accounting(db: Session, *, now: datetime, short_days: int, hourly_days: int, daily_days: int) -> int:
    cutoffs = retention_cutoffs(now, short_days=short_days, hourly_days=hourly_days, daily_days=daily_days)
    removed = 0
    for bucket_seconds, cutoff in cutoffs.items():
        removed += db.query(TrafficFlowAccountingAggregate).filter(
            TrafficFlowAccountingAggregate.bucket_seconds == bucket_seconds,
            TrafficFlowAccountingAggregate.bucket_start < cutoff,
        ).delete(synchronize_session=False)
        removed += db.query(TrafficDeviceAggregate).filter(
            TrafficDeviceAggregate.bucket_seconds == bucket_seconds,
            TrafficDeviceAggregate.bucket_start < cutoff,
        ).delete(synchronize_session=False)
    removed += cleanup_endpoint_aggregates(db, cutoffs)
    return removed


def reconcile_window(db: Session, *, source_id: int, window_start: datetime, window_end: datetime, interface_id: int | None = None, persist: bool = True) -> TrafficFlowReconciliation:
    source = db.get(TrafficSource, source_id)
    if source is None:
        raise ValueError("Traffic source not found")
    interface = db.get(TrafficInterface, interface_id) if interface_id else None
    if interface and interface.source_id != source_id:
        raise ValueError("Traffic interface does not belong to source")
    flow_bytes = db.query(func.coalesce(func.sum(TrafficFlowAccountingAggregate.bytes_total), 0)).filter(
        TrafficFlowAccountingAggregate.source_id == source_id,
        TrafficFlowAccountingAggregate.bucket_seconds == 300,
        TrafficFlowAccountingAggregate.bucket_start >= window_start,
        TrafficFlowAccountingAggregate.bucket_start < window_end,
    ).scalar()
    row = TrafficFlowReconciliation(
        source_id=source_id, interface_id=interface_id, window_start=window_start, window_end=window_end,
        flow_bytes=int(flow_bytes or 0), comparable=False, status="unavailable",
        reason="SNMP and flow providers are not mapped to the same interface/time series",
    )
    if persist:
        db.add(row)
    return row
