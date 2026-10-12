"""Bounded, canonical reporting queries for the Network Traffic dashboard."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.models import (
    IPAddress,
    TrafficAggregate,
    TrafficCounterObservation,
    TrafficDeviceAggregate,
    TrafficDeviceMonitoring,
    TrafficInterface,
    TrafficSource,
    VLAN,
)

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


def wan_report(db: Session, *, report_range: str = "24h", source_id: int | None = None, now: datetime | None = None) -> dict:
    selected, start, bucket_seconds = report_window(report_range, now=now)
    now = now or datetime.utcnow()
    interfaces = _wan_interfaces(db, source_id)
    interface_ids = {item.id for item in interfaces}
    query = db.query(TrafficAggregate).filter(
        TrafficAggregate.interface_id.in_(interface_ids or [-1]),
        TrafficAggregate.bucket_seconds == bucket_seconds,
        TrafficAggregate.bucket_start >= start,
        TrafficAggregate.direction.in_(["download", "upload"]),
    ).order_by(TrafficAggregate.bucket_start.asc()).limit(MAX_REPORT_ROWS)
    rows = query.all()
    history: dict[datetime, dict] = {}
    totals = {"download": 0, "upload": 0}
    for row in rows:
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
            "last_observation_at": _iso(current_at),
            "interface_count": len(interfaces),
            "quality": "approximate" if any(point["approximate"] for point in history.values()) else "observed",
        },
        "history": history_items,
    }


def _device_rows(db: Session, *, start: datetime, bucket_seconds: int, ip_address_id: int | None = None) -> list[dict]:
    query = db.query(TrafficDeviceAggregate, IPAddress, VLAN).join(
        IPAddress, IPAddress.id == TrafficDeviceAggregate.ip_address_id
    ).outerjoin(VLAN, VLAN.id == IPAddress.vlan_id).join(
        TrafficDeviceMonitoring, TrafficDeviceMonitoring.ip_address_id == IPAddress.id
    ).filter(
        TrafficDeviceMonitoring.is_enabled.is_(True),
        TrafficDeviceAggregate.bucket_seconds == bucket_seconds,
        TrafficDeviceAggregate.bucket_start >= start,
    )
    if ip_address_id is not None:
        query = query.filter(IPAddress.id == ip_address_id)
    rows = query.order_by(TrafficDeviceAggregate.bucket_start.asc()).limit(MAX_REPORT_ROWS).all()
    grouped: dict[int, dict] = {}
    for aggregate, address, vlan in rows:
        item = grouped.setdefault(address.id, {
            "id": address.id, "name": address.name or address.description or address.address, "address": address.address,
            "vlan": vlan.name if vlan else None, "download_bytes": 0, "upload_bytes": 0, "total_bytes": 0,
            "last_observed_at": None, "quality": "observed", "confidence": aggregate.attribution_confidence or "unknown",
        })
        amount = max(0, int(aggregate.bytes_total or 0))
        if aggregate.direction in {"download", "upload"}:
            item[f"{aggregate.direction}_bytes"] += amount
            item["total_bytes"] += amount
        item["last_observed_at"] = max((item["last_observed_at"], aggregate.last_observed_at), key=lambda value: value or datetime.min)
        if aggregate.data_quality != "complete":
            item["quality"] = aggregate.data_quality or "partial"
        if aggregate.attribution_confidence == "low":
            item["confidence"] = "low"
    now = datetime.utcnow()
    for item in grouped.values():
        last_observed = item["last_observed_at"]
        item["last_observed_at"] = _iso(item["last_observed_at"])
        item["status"] = "stale" if last_observed and last_observed < now - timedelta(hours=1) else "active"
    return sorted(grouped.values(), key=lambda item: (-item["total_bytes"], item["name"].lower()))


def device_report(db: Session, *, report_range: str = "24h", ip_address_id: int | None = None, now: datetime | None = None) -> dict:
    selected, start, bucket_seconds = report_window(report_range, now=now)
    rows = _device_rows(db, start=start, bucket_seconds=bucket_seconds, ip_address_id=ip_address_id)
    return {"range": selected, "bucket_seconds": bucket_seconds, "devices": rows}


def device_history(db: Session, ip_address_id: int, *, report_range: str = "24h", now: datetime | None = None) -> dict:
    selected, start, bucket_seconds = report_window(report_range, now=now)
    rows = db.query(TrafficDeviceAggregate).join(TrafficDeviceMonitoring, TrafficDeviceMonitoring.ip_address_id == TrafficDeviceAggregate.ip_address_id).filter(
        TrafficDeviceAggregate.ip_address_id == ip_address_id,
        TrafficDeviceMonitoring.is_enabled.is_(True),
        TrafficDeviceAggregate.bucket_seconds == bucket_seconds,
        TrafficDeviceAggregate.bucket_start >= start,
    ).order_by(TrafficDeviceAggregate.bucket_start.asc()).limit(MAX_REPORT_ROWS).all()
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
