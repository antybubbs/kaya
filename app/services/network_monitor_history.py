import json
import math
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import HTTPException
from sqlalchemy import Integer, case, cast, func
from sqlalchemy.orm import Session

from app.models.models import (
    NetworkMonitor, NetworkMonitorCheck, NetworkMonitorEvent,
    NetworkMonitorOutage, NetworkMonitorStatistic,
)
from app.services.network_monitor import effective_monitor_thresholds
from app.services.site_settings import get_site_setting


PERFORMANCE_RANGES = {
    "1h": (timedelta(hours=1), 0, "Raw observations"),
    "6h": (timedelta(hours=6), 60, "1-minute aggregated observations"),
    "24h": (timedelta(hours=24), 300, "5-minute aggregated observations"),
    "7d": (timedelta(days=7), 1800, "30-minute aggregated observations"),
    "30d": (timedelta(days=30), 7200, "2-hour aggregated observations"),
    "90d": (timedelta(days=90), 43200, "12-hour aggregated observations"),
    "1y": (timedelta(days=365), 86400, "1-day aggregated observations"),
}
PERFORMANCE_MAX_SOURCE_ROWS = 50000
PERFORMANCE_MAX_INCIDENTS = 1000
PERFORMANCE_SORTS = {
    "time", "latency_min", "latency_avg", "latency_max", "jitter_avg",
    "packet_loss", "availability", "successful", "failed", "status",
}
STATE_PRIORITY = {
    "unknown": 0, "healthy": 1, "paused": 2, "maintenance": 3,
    "recovering": 4, "warning": 5, "critical": 6, "offline": 7,
}
PRIORITY_STATE = {value: key for key, value in STATE_PRIORITY.items()}
CUSTOM_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})?$")


def site_timezone(db: Session) -> tuple[str, ZoneInfo]:
    name = (get_site_setting(db, "timezone_region") or "UTC").strip()
    try:
        return name, ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return "UTC", ZoneInfo("UTC")


def parse_custom_time(value: str, zone: ZoneInfo) -> datetime:
    clean = value.strip()
    if len(clean) > 40 or not CUSTOM_TIME_RE.fullmatch(clean):
        raise HTTPException(status_code=400, detail="Custom dates must use an ISO date and time")
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid custom date or time") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def automatic_bucket_seconds(duration: timedelta) -> int:
    seconds = duration.total_seconds()
    if seconds <= 3600:
        return 0
    if seconds <= 21600:
        return 60
    if seconds <= 86400:
        return 300
    if seconds <= 7 * 86400:
        return 1800
    if seconds <= 30 * 86400:
        return 7200
    if seconds <= 90 * 86400:
        return 43200
    return 86400


def aggregation_label(seconds: int) -> str:
    if not seconds:
        return "Raw observations"
    if seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}-minute aggregated observations"
    if seconds < 86400:
        hours = seconds // 3600
        return f"{hours}-hour aggregated observations"
    days = seconds // 86400
    return f"{days}-day aggregated observations"


def resolve_range(
    db: Session,
    selected: str,
    start_text: str | None = None,
    end_text: str | None = None,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.utcnow()
    timezone_name, zone = site_timezone(db)
    if selected == "custom":
        if not start_text or not end_text:
            raise HTTPException(status_code=400, detail="Custom start and end are required")
        start = parse_custom_time(start_text, zone)
        end = parse_custom_time(end_text, zone)
        if end > now + timedelta(minutes=5):
            raise HTTPException(status_code=400, detail="Custom end must not be in the future")
        duration = end - start
        if duration < timedelta(minutes=1) or duration > timedelta(days=366):
            raise HTTPException(status_code=400, detail="Custom range must be between 1 minute and 366 days")
        bucket_seconds = automatic_bucket_seconds(duration)
    else:
        definition = PERFORMANCE_RANGES.get(selected)
        if not definition:
            raise HTTPException(status_code=400, detail="Unsupported performance range")
        duration, bucket_seconds, _ = definition
        end = now
        start = end - duration
    if start >= end:
        raise HTTPException(status_code=400, detail="Custom start must be before custom end")
    return {
        "key": selected, "start": start, "end": end,
        "bucket_seconds": bucket_seconds,
        "aggregation": aggregation_label(bucket_seconds),
        "timezone": timezone_name,
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _utc_epoch(value: datetime) -> int:
    """Convert the application's naive-UTC datetimes without using host local time."""
    return int((value - datetime(1970, 1, 1)).total_seconds())


def _blank_bucket(start: datetime, seconds: int) -> dict:
    return {
        "start": start, "end": start + timedelta(seconds=seconds) if seconds else start,
        "samples": 0, "successful": 0, "latency_count": 0, "latency_total": 0.0,
        "latency_min": None, "latency_max": None, "jitter_count": 0, "jitter_total": 0.0,
        "jitter_max": None, "loss_count": 0, "loss_total": 0.0, "state_priority": 0,
    }


def _merge_bucket(target: dict, source: dict) -> None:
    target["samples"] += int(source.get("samples") or 0)
    target["successful"] += int(source.get("successful") or 0)
    latency_count = int(source.get("latency_count") or 0)
    if latency_count and source.get("latency_avg") is not None:
        target["latency_count"] += latency_count
        target["latency_total"] += float(source["latency_avg"]) * latency_count
    for key, reducer in (("latency_min", min), ("latency_max", max), ("jitter_max", max)):
        value = source.get(key)
        if value is not None:
            target[key] = value if target[key] is None else reducer(target[key], value)
    jitter_count = int(source.get("jitter_count") or 0)
    if jitter_count and source.get("jitter_avg") is not None:
        target["jitter_count"] += jitter_count
        target["jitter_total"] += float(source["jitter_avg"]) * jitter_count
    loss_count = int(source.get("loss_count") or 0)
    if loss_count and source.get("loss_avg") is not None:
        target["loss_count"] += loss_count
        target["loss_total"] += float(source["loss_avg"]) * loss_count
    target["state_priority"] = max(target["state_priority"], int(source.get("state_priority") or 0))


def _raw_points(db: Session, monitor_id: int, start: datetime, end: datetime) -> list[dict]:
    rows = db.query(NetworkMonitorCheck).filter(
        NetworkMonitorCheck.monitor_id == monitor_id,
        NetworkMonitorCheck.checked_at >= start,
        NetworkMonitorCheck.checked_at < end,
    ).order_by(NetworkMonitorCheck.checked_at.asc()).limit(5000).all()
    result = []
    previous_latency = None
    for row in rows:
        state = row.health_state or ("healthy" if row.status == "up" else "offline")
        jitter = abs(row.latency_ms - previous_latency) if row.latency_ms is not None and previous_latency is not None else None
        if row.latency_ms is not None:
            previous_latency = row.latency_ms
        result.append({
            "start": row.checked_at, "end": row.checked_at, "samples": 1,
            "successful": 1 if row.status == "up" else 0,
            "latency_count": 1 if row.latency_ms is not None else 0,
            "latency_total": float(row.latency_ms) if row.latency_ms is not None else 0.0,
            "latency_avg": row.latency_ms, "latency_min": row.latency_ms, "latency_max": row.latency_ms,
            "jitter_count": 1 if jitter is not None else 0,
            "jitter_total": float(jitter) if jitter is not None else 0.0,
            "jitter_avg": jitter, "jitter_max": jitter,
            "loss_count": 1 if row.packet_loss_percent is not None else 0,
            "loss_total": float(row.packet_loss_percent) if row.packet_loss_percent is not None else 0.0,
            "loss_avg": row.packet_loss_percent, "state_priority": STATE_PRIORITY.get(state, 0),
            "error": row.error,
        })
    return result


def _raw_aggregates(db: Session, monitor_id: int, start: datetime, end: datetime, seconds: int) -> list[dict]:
    epoch = cast(func.strftime("%s", NetworkMonitorCheck.checked_at), Integer)
    bucket_epoch = (epoch - (epoch % seconds)).label("bucket_epoch")
    previous = func.lag(NetworkMonitorCheck.latency_ms).over(order_by=NetworkMonitorCheck.checked_at.asc())
    state_priority = case(
        (NetworkMonitorCheck.health_state == "offline", 7),
        (NetworkMonitorCheck.health_state == "critical", 6),
        (NetworkMonitorCheck.health_state == "warning", 5),
        (NetworkMonitorCheck.health_state == "recovering", 4),
        (NetworkMonitorCheck.health_state == "maintenance", 3),
        (NetworkMonitorCheck.health_state == "paused", 2),
        (NetworkMonitorCheck.status != "up", 7),
        else_=1,
    )
    source = db.query(
        bucket_epoch, NetworkMonitorCheck.status.label("status"),
        NetworkMonitorCheck.latency_ms.label("latency"),
        NetworkMonitorCheck.packet_loss_percent.label("loss"),
        previous.label("previous_latency"), state_priority.label("state_priority"),
    ).filter(
        NetworkMonitorCheck.monitor_id == monitor_id,
        NetworkMonitorCheck.checked_at >= start,
        NetworkMonitorCheck.checked_at < end,
    ).subquery()
    jitter = func.abs(source.c.latency - source.c.previous_latency)
    rows = db.query(
        source.c.bucket_epoch,
        func.count().label("samples"),
        func.sum(case((source.c.status == "up", 1), else_=0)).label("successful"),
        func.count(source.c.latency).label("latency_count"),
        func.avg(source.c.latency).label("latency_avg"),
        func.min(source.c.latency).label("latency_min"),
        func.max(source.c.latency).label("latency_max"),
        func.count(jitter).label("jitter_count"),
        func.avg(jitter).label("jitter_avg"),
        func.max(jitter).label("jitter_max"),
        func.count(source.c.loss).label("loss_count"),
        func.avg(source.c.loss).label("loss_avg"),
        func.max(source.c.state_priority).label("state_priority"),
    ).group_by(source.c.bucket_epoch).order_by(source.c.bucket_epoch.asc()).all()
    return [{
        "start": datetime.utcfromtimestamp(row.bucket_epoch),
        "end": datetime.utcfromtimestamp(row.bucket_epoch) + timedelta(seconds=seconds),
        **{key: getattr(row, key) for key in (
            "samples", "successful", "latency_count", "latency_avg", "latency_min", "latency_max",
            "jitter_count", "jitter_avg", "jitter_max", "loss_count", "loss_avg", "state_priority",
        )},
    } for row in rows]


def _statistic_rows(db: Session, monitor_id: int, start: datetime, end: datetime) -> list[NetworkMonitorStatistic]:
    return db.query(NetworkMonitorStatistic).filter(
        NetworkMonitorStatistic.monitor_id == monitor_id,
        NetworkMonitorStatistic.bucket_start >= start,
        NetworkMonitorStatistic.bucket_start < end,
    ).order_by(NetworkMonitorStatistic.bucket_start.asc()).limit(PERFORMANCE_MAX_SOURCE_ROWS).all()


def _combined_points(db: Session, monitor: NetworkMonitor, selection: dict) -> tuple[list[dict], int]:
    stats = _statistic_rows(db, monitor.id, selection["start"], selection["end"])
    retained_resolution = max((row.bucket_seconds for row in stats), default=0)
    effective_seconds = max(selection["bucket_seconds"], retained_resolution)
    if not effective_seconds:
        return _raw_points(db, monitor.id, selection["start"], selection["end"]), 0
    raw_rows = _raw_aggregates(db, monitor.id, selection["start"], selection["end"], effective_seconds)
    buckets: dict[int, dict] = {}
    for row in raw_rows:
        key = _utc_epoch(row["start"])
        target = buckets.setdefault(key, _blank_bucket(row["start"], effective_seconds))
        _merge_bucket(target, row)
    for row in stats:
        epoch = _utc_epoch(row.bucket_start)
        key = epoch - (epoch % effective_seconds)
        start = datetime.utcfromtimestamp(key)
        target = buckets.setdefault(key, _blank_bucket(start, effective_seconds))
        _merge_bucket(target, {
            "samples": row.sample_count, "successful": row.up_count,
            "latency_count": row.latency_sample_count or row.up_count,
            "latency_avg": row.avg_latency_ms, "latency_min": row.min_latency_ms,
            "latency_max": row.max_latency_ms,
            "jitter_count": row.jitter_sample_count, "jitter_avg": row.avg_jitter_ms,
            "jitter_max": row.max_jitter_ms,
            "loss_count": row.loss_sample_count or (row.sample_count if row.avg_packet_loss_percent is not None else 0),
            "loss_avg": row.avg_packet_loss_percent,
            "state_priority": STATE_PRIORITY.get(row.health_state or "unknown", 0),
        })
    points = []
    for bucket in sorted(buckets.values(), key=lambda item: item["start"]):
        bucket["latency_avg"] = round(bucket["latency_total"] / bucket["latency_count"], 3) if bucket["latency_count"] else None
        bucket["jitter_avg"] = round(bucket["jitter_total"] / bucket["jitter_count"], 3) if bucket["jitter_count"] else None
        bucket["loss_avg"] = round(bucket["loss_total"] / bucket["loss_count"], 2) if bucket["loss_count"] else None
        points.append(bucket)
    return points, effective_seconds


def _weighted_percentile(points: list[dict], quantile: float) -> float | None:
    values = sorted(
        (float(point["latency_avg"]), int(point["latency_count"]))
        for point in points if point.get("latency_avg") is not None and point.get("latency_count")
    )
    total = sum(weight for _, weight in values)
    if not total:
        return None
    target = max(1, math.ceil(total * quantile))
    seen = 0
    for value, weight in values:
        seen += weight
        if seen >= target:
            return round(value, 2)
    return round(values[-1][0], 2)


def _overlap_seconds(start: datetime, end: datetime, row: NetworkMonitorOutage) -> float:
    overlap_start = max(start, row.started_at)
    overlap_end = min(end, row.ended_at or end)
    return max(0.0, (overlap_end - overlap_start).total_seconds())


def _serialise_point(point: dict) -> dict:
    samples = int(point["samples"])
    successful = int(point["successful"])
    failed = max(0, samples - successful)
    return {
        "at": _iso(point["start"]), "end": _iso(point["end"]),
        "latency_min": round(point["latency_min"], 3) if point.get("latency_min") is not None else None,
        "latency_avg": round(point["latency_avg"], 3) if point.get("latency_avg") is not None else None,
        "latency_max": round(point["latency_max"], 3) if point.get("latency_max") is not None else None,
        "jitter_avg": round(point["jitter_avg"], 3) if point.get("jitter_avg") is not None else None,
        "jitter_max": round(point["jitter_max"], 3) if point.get("jitter_max") is not None else None,
        "packet_loss": round(point["loss_avg"], 2) if point.get("loss_avg") is not None else None,
        "availability": round((successful / samples) * 100, 3) if samples else None,
        "successful": successful, "failed": failed, "total": samples,
        "status": PRIORITY_STATE.get(int(point.get("state_priority") or 0), "unknown"),
        "error": point.get("error"),
    }


def performance_history(
    db: Session,
    monitor: NetworkMonitor,
    selected: str,
    start_text: str | None = None,
    end_text: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort: str = "time",
    direction: str = "desc",
    query: str = "",
    now: datetime | None = None,
) -> dict:
    selection = resolve_range(db, selected, start_text, end_text, now)
    if sort not in PERFORMANCE_SORTS or direction not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail="Unsupported performance table ordering")
    points, effective_seconds = _combined_points(db, monitor, selection)
    serialised = [_serialise_point(point) for point in points]
    thresholds = effective_monitor_thresholds(db, monitor)
    outages = db.query(NetworkMonitorOutage).filter(
        NetworkMonitorOutage.monitor_id == monitor.id,
        NetworkMonitorOutage.started_at < selection["end"],
        (NetworkMonitorOutage.ended_at.is_(None)) | (NetworkMonitorOutage.ended_at >= selection["start"]),
    ).order_by(NetworkMonitorOutage.started_at.asc()).limit(PERFORMANCE_MAX_INCIDENTS).all()
    events = db.query(NetworkMonitorEvent).filter(
        NetworkMonitorEvent.monitor_id == monitor.id,
        NetworkMonitorEvent.occurred_at >= selection["start"],
        NetworkMonitorEvent.occurred_at < selection["end"],
        NetworkMonitorEvent.event_type.in_([
            "degraded_recovered", "recovered", "state_changed",
            "maintenance_started", "maintenance_ended", "paused", "resumed",
        ]),
    ).order_by(NetworkMonitorEvent.occurred_at.asc()).limit(500).all()
    available_check = db.query(func.min(NetworkMonitorCheck.checked_at)).filter(NetworkMonitorCheck.monitor_id == monitor.id).scalar()
    available_stat = db.query(func.min(NetworkMonitorStatistic.bucket_start)).filter(NetworkMonitorStatistic.monitor_id == monitor.id).scalar()
    available_from = min((value for value in (available_check, available_stat) if value), default=None)
    sample_count = sum(point["total"] for point in serialised)
    successful = sum(point["successful"] for point in serialised)
    failed = sum(point["failed"] for point in serialised)
    latency_count = sum(point["latency_count"] for point in points)
    latency_total = sum(point["latency_total"] for point in points)
    jitter_count = sum(point["jitter_count"] for point in points)
    jitter_total = sum(point["jitter_total"] for point in points)
    loss_count = sum(point["loss_count"] for point in points)
    loss_total = sum(point["loss_total"] for point in points)
    offline_incidents = [row for row in outages if row.incident_type == "offline"]
    ended_offline = [row for row in offline_incidents if row.ended_at]
    incident_durations = [_overlap_seconds(selection["start"], selection["end"], row) for row in offline_incidents]
    summary = {
        "availability": round((successful / sample_count) * 100, 3) if sample_count else None,
        "average_latency": round(latency_total / latency_count, 3) if latency_count else None,
        "median_latency": _weighted_percentile(points, .5),
        "minimum_latency": min((point["latency_min"] for point in points if point.get("latency_min") is not None), default=None),
        "maximum_latency": max((point["latency_max"] for point in points if point.get("latency_max") is not None), default=None),
        "p95_latency": _weighted_percentile(points, .95), "p99_latency": _weighted_percentile(points, .99),
        "average_jitter": round(jitter_total / jitter_count, 3) if jitter_count else None,
        "maximum_jitter": max((point["jitter_max"] for point in points if point.get("jitter_max") is not None), default=None),
        "packet_loss": round(loss_total / loss_count, 3) if loss_count else None,
        "successful_checks": successful, "failed_checks": failed,
        "downtime_seconds": round(sum(incident_durations)),
        "longest_outage_seconds": round(max(incident_durations, default=0)) if offline_incidents else None,
        "average_recovery_seconds": round(sum((row.ended_at - row.started_at).total_seconds() for row in ended_offline) / len(ended_offline)) if ended_offline else None,
        "incident_count": len(outages), "total_checks": sample_count,
        "percentile_basis": "raw observations" if not effective_seconds else "weighted bucket averages",
    }
    incident_payload = []
    for row in outages:
        details = {}
        try:
            details = json.loads(row.details_json or "{}")
        except (TypeError, ValueError):
            pass
        incident_payload.append({
            "id": row.id, "type": row.incident_type, "start": _iso(row.started_at), "end": _iso(row.ended_at),
            "duration_seconds": round((row.ended_at - row.started_at).total_seconds()) if row.ended_at else None,
            "reason": row.failure_reason or details.get("reason") or "Threshold exceeded",
            "status": "resolved" if row.ended_at else "ongoing",
        })
    event_payload = [{
        "type": row.event_type, "at": _iso(row.occurred_at), "severity": row.severity, "message": row.message,
    } for row in events]
    clean_query = query.strip().lower()[:50]
    filtered = serialised
    if clean_query:
        filtered = [row for row in serialised if clean_query in " ".join(str(row.get(key) or "") for key in ("at", "status", "latency_avg", "packet_loss")).lower()]
    sort_key = {
        "time": "at", "latency_min": "latency_min", "latency_avg": "latency_avg",
        "latency_max": "latency_max", "jitter_avg": "jitter_avg", "packet_loss": "packet_loss",
        "availability": "availability", "successful": "successful", "failed": "failed", "status": "status",
    }[sort]
    present = [row for row in filtered if row.get(sort_key) is not None]
    missing = [row for row in filtered if row.get(sort_key) is None]
    filtered = sorted(present, key=lambda row: row[sort_key], reverse=direction == "desc") + missing
    total_rows = len(filtered)
    pages = max(1, math.ceil(total_rows / page_size))
    page = min(page, pages)
    offset = (page - 1) * page_size
    selection["bucket_seconds"] = effective_seconds
    selection["aggregation"] = aggregation_label(effective_seconds)
    return {
        "range": {
            "key": selection["key"], "start": _iso(selection["start"]), "end": _iso(selection["end"]),
            "timezone": selection["timezone"], "bucket_seconds": effective_seconds,
            "aggregation": selection["aggregation"], "available_from": _iso(available_from),
            "partial": bool(available_from and available_from > selection["start"] and available_from < selection["end"]),
        },
        "summary": summary, "points": serialised, "incidents": incident_payload, "events": event_payload,
        "thresholds": {
            "latency_warning": thresholds["latency_warning_ms"], "latency_critical": thresholds["latency_critical_ms"],
            "packet_loss_warning": thresholds["packet_loss_warning_percent"],
            "packet_loss_critical": thresholds["packet_loss_critical_percent"],
        },
        "table": {
            "rows": filtered[offset:offset + page_size], "page": page, "pages": pages,
            "page_size": page_size, "total": total_rows, "sort": sort, "direction": direction, "query": query.strip()[:50],
        },
    }
