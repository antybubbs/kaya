"""Read-only builders for the Command centre dashboard panels.

Every value is read from an existing Kaya store. Nothing here collects new
data, estimates missing values or creates alerts; absent values are returned
as ``None`` so the browser can render an explicit empty state.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import threading

from sqlalchemy import Integer, case, cast, func
from sqlalchemy.orm import Session, selectinload

from app.models.models import (
    IPAddress,
    NetworkMonitor,
    NetworkMonitorCheck,
    NetworkMonitorOutage,
    NetworkMonitorStatistic,
    TrafficDeviceAggregate,
    TrafficDeviceMonitoring,
    VLAN,
)
from app.services.network_monitor import active_dashboard_interval, monitor_label
from app.services.network_traffic_reporting import wan_report

TRAFFIC_RANGES = ("1h", "24h", "7d", "30d")
TRAFFIC_RANGE_LABELS = {
    "1h": "last hour",
    "24h": "last 24 hours",
    "7d": "last 7 days",
    "30d": "last 30 days",
}
UPTIME_DAYS = 30
UPTIME_CACHE_SECONDS = 60
VLAN_BUCKET_SECONDS = 300
VLAN_FRESHNESS = timedelta(minutes=15)
MAX_VLAN_TILES = 48
MAX_HIDDEN_MONITORS = 500
OFFLINE_STATES = {"offline", "down", "failed"}
DEGRADED_STATES = {"warning", "critical", "recovering"}

_uptime_cache: dict[str, tuple[datetime, dict]] = {}
_uptime_cache_guard = threading.Lock()


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _epoch(column, dialect: str):
    if dialect == "postgresql":
        return cast(func.extract("epoch", column), Integer)
    return cast(func.strftime("%s", column), Integer)


# --------------------------------------------------------------------------- traffic


def vlan_rates(db: Session, now: datetime) -> dict:
    """Per-VLAN rate from the latest complete 5-minute opted-in device bucket."""
    vlans = db.query(VLAN).order_by(VLAN.name.asc()).all()
    cutoff = now - timedelta(seconds=VLAN_BUCKET_SECONDS)
    latest = (
        db.query(func.max(TrafficDeviceAggregate.bucket_start))
        .join(
            TrafficDeviceMonitoring,
            TrafficDeviceMonitoring.ip_address_id == TrafficDeviceAggregate.ip_address_id,
        )
        .filter(
            TrafficDeviceMonitoring.is_enabled.is_(True),
            TrafficDeviceAggregate.bucket_seconds == VLAN_BUCKET_SECONDS,
            TrafficDeviceAggregate.bucket_start <= cutoff,
        )
        .scalar()
    )
    totals: dict[int, int] = {}
    if latest and latest >= now - VLAN_FRESHNESS:
        rows = (
            db.query(IPAddress.vlan_id, func.sum(TrafficDeviceAggregate.bytes_total))
            .join(IPAddress, IPAddress.id == TrafficDeviceAggregate.ip_address_id)
            .join(
                TrafficDeviceMonitoring,
                TrafficDeviceMonitoring.ip_address_id == TrafficDeviceAggregate.ip_address_id,
            )
            .filter(
                TrafficDeviceMonitoring.is_enabled.is_(True),
                TrafficDeviceAggregate.bucket_seconds == VLAN_BUCKET_SECONDS,
                TrafficDeviceAggregate.bucket_start == latest,
                TrafficDeviceAggregate.direction.in_(["download", "upload"]),
                IPAddress.vlan_id.isnot(None),
            )
            .group_by(IPAddress.vlan_id)
            .all()
        )
        totals = {vlan_id: max(0, int(total or 0)) for vlan_id, total in rows}
    else:
        latest = None
    tiles = [
        {
            "name": vlan.name,
            "bps": round(totals[vlan.id] * 8 / VLAN_BUCKET_SECONDS) if vlan.id in totals else None,
        }
        for vlan in vlans
    ]
    tiles.sort(key=lambda item: (item["bps"] is None, -(item["bps"] or 0), item["name"].lower()))
    busiest = max((item["bps"] or 0 for item in tiles), default=0)
    for item in tiles:
        item["share"] = round(item["bps"] / busiest * 100, 1) if item["bps"] and busiest else 0
    return {
        "bucket_start": _iso(latest),
        "total": len(tiles),
        "tiles": tiles[:MAX_VLAN_TILES],
    }


def traffic_panel(
    db: Session,
    *,
    report_range: str,
    allowed_modules: frozenset[str],
    dns_blocked_percentage: float | None,
    now: datetime | None = None,
) -> dict:
    if report_range not in TRAFFIC_RANGES:
        raise ValueError("Unsupported traffic range")
    now = now or datetime.utcnow()
    report = wan_report(db, report_range=report_range, now=now)
    summary = report["summary"]
    configured = summary["interface_count"] > 0
    points = [
        {
            "at": item["at"],
            "in_bps": item["download_bps"],
            "out_bps": item["upload_bps"],
        }
        for item in report["history"]
    ] if configured else []
    peak = max((max(point["in_bps"], point["out_bps"]) for point in points), default=None)
    vlans = None
    if configured and "vlan_ip_manager" in allowed_modules:
        vlans = vlan_rates(db, now)
    return {
        "configured": configured,
        "range": report_range,
        "range_label": TRAFFIC_RANGE_LABELS[report_range],
        "bucket_seconds": report["bucket_seconds"],
        "start": _iso(now - _range_delta(report_range)),
        "end": _iso(now),
        "inbound_bps": summary["current_download_bps"] if configured else None,
        "outbound_bps": summary["current_upload_bps"] if configured else None,
        "peak_bps": peak,
        "transferred_bytes": summary["total_bytes"] if configured and points else None,
        "dns_blocked_percentage": dns_blocked_percentage,
        "quality": summary["quality"],
        "last_observation_at": summary["last_observation_at"],
        "points": points,
        "vlans": vlans,
    }


def _range_delta(report_range: str) -> timedelta:
    return {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }[report_range]


# --------------------------------------------------------------------------- uptime


def _priority_case(state_column, status_column=None):
    whens = [
        (state_column == "offline", 7),
        (state_column == "critical", 6),
        (state_column == "warning", 5),
        (state_column == "recovering", 4),
        (state_column == "maintenance", 3),
        (state_column == "paused", 2),
    ]
    if status_column is not None:
        whens.append((status_column != "up", 7))
    return case(*whens, else_=1)


def _daily_history(db: Session, start: datetime, end: datetime) -> dict[int, dict[int, dict]]:
    """Return {monitor_id: {day_epoch: {samples, successful, priority}}} for the window."""
    dialect = db.bind.dialect.name
    day = 86400
    check_epoch = _epoch(NetworkMonitorCheck.checked_at, dialect)
    check_day = (check_epoch - (check_epoch % day)).label("day")
    check_rows = (
        db.query(
            NetworkMonitorCheck.monitor_id,
            check_day,
            func.count(NetworkMonitorCheck.id),
            func.sum(case((NetworkMonitorCheck.status == "up", 1), else_=0)),
            func.max(_priority_case(NetworkMonitorCheck.health_state, NetworkMonitorCheck.status)),
        )
        .filter(NetworkMonitorCheck.checked_at >= start, NetworkMonitorCheck.checked_at < end)
        .group_by(NetworkMonitorCheck.monitor_id, check_day)
        .all()
    )
    stat_epoch = _epoch(NetworkMonitorStatistic.bucket_start, dialect)
    stat_day = (stat_epoch - (stat_epoch % day)).label("day")
    stat_rows = (
        db.query(
            NetworkMonitorStatistic.monitor_id,
            stat_day,
            func.sum(NetworkMonitorStatistic.sample_count),
            func.sum(NetworkMonitorStatistic.up_count),
            func.max(_priority_case(NetworkMonitorStatistic.health_state)),
        )
        .filter(NetworkMonitorStatistic.bucket_start >= start, NetworkMonitorStatistic.bucket_start < end)
        .group_by(NetworkMonitorStatistic.monitor_id, stat_day)
        .all()
    )
    result: dict[int, dict[int, dict]] = {}
    for monitor_id, day_epoch, samples, successful, priority in [*check_rows, *stat_rows]:
        bucket = result.setdefault(monitor_id, {}).setdefault(
            int(day_epoch), {"samples": 0, "successful": 0, "priority": 0}
        )
        bucket["samples"] += int(samples or 0)
        bucket["successful"] += int(successful or 0)
        bucket["priority"] = max(bucket["priority"], int(priority or 0))
    return result


def _cached_daily_history(db: Session, start: datetime, end: datetime, now: datetime) -> dict:
    key = f"{db.bind.url}|{start.isoformat()}"
    with _uptime_cache_guard:
        cached = _uptime_cache.get(key)
        if cached and cached[0] > now - timedelta(seconds=UPTIME_CACHE_SECONDS):
            return cached[1]
    value = _daily_history(db, start, end)
    with _uptime_cache_guard:
        _uptime_cache.clear()
        _uptime_cache[key] = (now, value)
    return value


def clear_uptime_cache() -> None:
    with _uptime_cache_guard:
        _uptime_cache.clear()


def _day_state(bucket: dict | None) -> str:
    if not bucket or not bucket["samples"]:
        return "none"
    if bucket["priority"] >= 7:
        return "outage"
    if bucket["priority"] >= 4:
        return "degraded"
    return "operational"


def _percent_text(successful: int, samples: int) -> str | None:
    if not samples:
        return None
    if successful >= samples:
        return "100%"
    return f"{min(99.99, round(successful / samples * 100, 2)):.2f}%"


def _monitor_state(monitor: NetworkMonitor) -> str:
    if not monitor.is_enabled:
        return "paused"
    status = monitor.last_status or "unknown"
    if status == "up":
        return "healthy"
    if status in OFFLINE_STATES:
        return "offline"
    if status in DEGRADED_STATES:
        return "degraded"
    return "unknown"


def _duration_text(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def normalise_hidden_monitors(value: object) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_HIDDEN_MONITORS:
        raise ValueError("Invalid uptime host selection")
    result: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item < 1 or item > 2_147_483_647:
            raise ValueError("Invalid uptime host selection")
        if item not in result:
            result.append(item)
    return result


def uptime_panel(db: Session, *, hidden_ids: list[int], now: datetime | None = None) -> dict:
    now = now or datetime.utcnow()
    today = datetime(now.year, now.month, now.day)
    start = today - timedelta(days=UPTIME_DAYS - 1)
    day_epochs = [int((start + timedelta(days=offset) - datetime(1970, 1, 1)).total_seconds()) for offset in range(UPTIME_DAYS)]
    monitors = (
        db.query(NetworkMonitor)
        .options(selectinload(NetworkMonitor.ip_address))
        .order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc())
        .all()
    )
    hidden = set(hidden_ids)
    shown_monitors = [monitor for monitor in monitors if monitor.id not in hidden]
    history = _cached_daily_history(db, start, now, now) if shown_monitors else {}
    shown_ids = [monitor.id for monitor in shown_monitors]
    incidents = 0
    last_offline_end: dict[int, datetime] = {}
    open_offline: set[int] = set()
    if shown_ids:
        incidents = (
            db.query(func.count(NetworkMonitorOutage.id))
            .filter(
                NetworkMonitorOutage.monitor_id.in_(shown_ids),
                NetworkMonitorOutage.started_at < now,
                (NetworkMonitorOutage.ended_at.is_(None)) | (NetworkMonitorOutage.ended_at >= start),
            )
            .scalar()
            or 0
        )
        for monitor_id, ended_at in (
            db.query(NetworkMonitorOutage.monitor_id, func.max(NetworkMonitorOutage.ended_at))
            .filter(
                NetworkMonitorOutage.monitor_id.in_(shown_ids),
                NetworkMonitorOutage.incident_type == "offline",
                NetworkMonitorOutage.ended_at.isnot(None),
            )
            .group_by(NetworkMonitorOutage.monitor_id)
            .all()
        ):
            last_offline_end[monitor_id] = ended_at
        open_offline = {
            monitor_id
            for (monitor_id,) in db.query(NetworkMonitorOutage.monitor_id).filter(
                NetworkMonitorOutage.monitor_id.in_(shown_ids),
                NetworkMonitorOutage.incident_type == "offline",
                NetworkMonitorOutage.ended_at.is_(None),
            )
        }
    override = active_dashboard_interval()
    intervals = sorted({override or monitor.interval_seconds for monitor in monitors if monitor.is_enabled})
    rows = []
    total_samples = total_successful = 0
    longest: float | None = None
    for monitor in shown_monitors:
        days = history.get(monitor.id, {})
        samples = sum(item["samples"] for item in days.values())
        successful = sum(item["successful"] for item in days.values())
        total_samples += samples
        total_successful += successful
        strip = [_day_state(days.get(epoch)) for epoch in day_epochs]
        state = _monitor_state(monitor)
        if state in {"healthy", "degraded"} and monitor.id not in open_offline:
            since = last_offline_end.get(monitor.id) or monitor.created_at
            if since:
                elapsed = (now - since).total_seconds()
                longest = elapsed if longest is None else max(longest, elapsed)
        name = monitor_label(monitor)
        percent = _percent_text(successful, samples)
        counts = {key: strip.count(key) for key in ("outage", "degraded", "none")}
        rows.append(
            {
                "id": monitor.id,
                "name": name,
                "state": state,
                "percent": percent,
                "perfect": bool(samples) and successful >= samples,
                "days": strip,
                "aria": (
                    f"{name}: {percent or 'no'} uptime over {UPTIME_DAYS} days; "
                    f"{counts['outage']} outage days, {counts['degraded']} degraded days, "
                    f"{counts['none']} days without history"
                ),
            }
        )
    return {
        "interval_seconds": intervals,
        "days": UPTIME_DAYS,
        "total": len(monitors),
        "shown_count": len(shown_monitors),
        "overall": _percent_text(total_successful, total_samples),
        "incidents": incidents if shown_ids else None,
        "longest_uptime": _duration_text(longest) if longest is not None else None,
        "hosts": [
            {
                "id": monitor.id,
                "name": monitor_label(monitor),
                "kind": (monitor.check_type or "").upper() or None,
                "on": monitor.id not in hidden,
            }
            for monitor in monitors
        ],
        "rows": rows,
    }
