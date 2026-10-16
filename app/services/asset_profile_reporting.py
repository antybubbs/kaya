"""Bounded, read-only composition for the unified asset profile.

The source modules remain owners of their data.  This service only joins
already persisted, permission-approved records for presentation and never
changes attribution or creates relationships.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DNSClientTrafficEvent,
    DNSRecognisedDevice,
    NetworkMonitor,
    NetworkMonitorCheck,
    NetworkMonitorStatistic,
    TrafficEndpointAggregate,
    TrafficSource,
)
from app.services.modules import has_module_access
from app.services.network_monitor_history import resolve_range

MAX_ROWS = 5000
REPORT_RANGES = {"24h", "7d", "30d", "90d", "custom"}


def _bucket(value: datetime, seconds: int) -> datetime:
    epoch = int((value - datetime(1970, 1, 1)).total_seconds())
    return datetime(1970, 1, 1) + timedelta(seconds=epoch - (epoch % seconds))


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _range(db: Session, period: str, start: str | None, end: str | None) -> dict:
    if period not in REPORT_RANGES:
        period = "24h"
    return resolve_range(db, period, start, end)


def _assignment_matches(row: AssetNetworkAssignment, at: datetime) -> bool:
    return row.status == "confirmed" and row.started_at <= at and (row.ended_at is None or at < row.ended_at)


def _in_scope(row: AssetNetworkAssignment, source_id: int, exporter_identity: str) -> bool:
    return (row.source_id is None or row.source_id == source_id) and (row.exporter_identity is None or row.exporter_identity == exporter_identity)


def _context_current(row: AssetNetworkAssignment) -> bool:
    if row.vlan_id is None:
        return True
    return bool(row.vlan and row.vlan.subnet_cidr and row.network_cidr and row.network_cidr.strip() == row.vlan.subnet_cidr.strip())


def _traffic(db: Session, asset_id: int, assignments: list[AssetNetworkAssignment], window: dict) -> dict:
    """Observed-endpoint usage the asset's confirmed identity evidence supports.

    A bucket counts only when, for its whole duration, a confirmed assignment of
    this asset (current VLAN context, in source/exporter scope) held the address
    and no other asset's confirmed assignment overlapped it. Buckets crossing a
    handover, or with competing ownership, are excluded. Nothing is copied.
    When more than one source/exporter measured the address, per-source totals
    are reported instead of a sum, which could count the same flows twice.
    """
    own = [row for row in assignments if row.status == "confirmed" and row.asset_id == asset_id and _context_current(row)]
    addresses = {row.address for row in own}
    if not addresses:
        return {"available": True, "history": [], "download_bytes": 0, "upload_bytes": 0, "excluded_buckets": 0, "sources": []}
    duration = window["end"] - window["start"]
    bucket_seconds = 300 if duration <= timedelta(hours=24) else 3600 if duration <= timedelta(days=7) else 86400
    rows = db.query(TrafficEndpointAggregate).filter(
        TrafficEndpointAggregate.endpoint_ip.in_(addresses),
        TrafficEndpointAggregate.bucket_seconds == bucket_seconds,
        TrafficEndpointAggregate.bucket_start >= window["start"],
        TrafficEndpointAggregate.bucket_start < window["end"],
    ).order_by(TrafficEndpointAggregate.bucket_start.asc()).limit(MAX_ROWS).all()
    competitors = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.address.in_(addresses),
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.asset_id != asset_id,
    ).limit(MAX_ROWS).all()
    by_context: dict[tuple, dict[datetime, dict]] = {}
    excluded: set[tuple] = set()
    span = timedelta(seconds=bucket_seconds)
    for row in rows:
        bucket_end = row.bucket_start + span
        scoped = [item for item in own if item.address == row.endpoint_ip and _in_scope(item, row.source_id, row.exporter_identity)]
        covering = [item for item in scoped if item.started_at <= row.bucket_start and (item.ended_at is None or bucket_end <= item.ended_at)]
        contested = any(
            item.address == row.endpoint_ip and _in_scope(item, row.source_id, row.exporter_identity)
            and item.started_at < bucket_end and (item.ended_at is None or item.ended_at > row.bucket_start)
            for item in competitors
        )
        if not covering or contested:
            # Count as excluded only contexts this asset claims for part of the bucket.
            if any(item.started_at < bucket_end and (item.ended_at is None or item.ended_at > row.bucket_start) for item in scoped):
                excluded.add((row.source_id, row.exporter_identity, row.bucket_start))
            continue
        point = by_context.setdefault((row.source_id, row.exporter_identity), {}).setdefault(row.bucket_start, {"download_bytes": 0, "upload_bytes": 0, "quality": "observed"})
        if row.direction in {"download", "upload"}:
            point[f"{row.direction}_bytes"] += max(0, int(row.bytes_total or 0))
        if row.data_quality != "complete":
            point["quality"] = "partial"
    names = {source.id: source.name for source in db.query(TrafficSource).filter(TrafficSource.id.in_([key[0] for key in by_context] or [-1])).all()}
    sources = [
        {"source": names.get(key[0], "Unknown source"), "exporter_identity": key[1],
         "download_bytes": sum(point["download_bytes"] for point in points.values()),
         "upload_bytes": sum(point["upload_bytes"] for point in points.values())}
        for key, points in sorted(by_context.items(), key=lambda item: (item[0][0], item[0][1]))
    ]
    if len(by_context) != 1:
        return {"available": True, "history": [], "download_bytes": None if by_context else 0, "upload_bytes": None if by_context else 0, "excluded_buckets": len(excluded), "sources": sources, "multiple_sources": len(by_context) > 1}
    points = next(iter(by_context.values()))
    history = [{"at": _iso(at), **value} for at, value in sorted(points.items())]
    return {
        "available": True,
        "history": history,
        "download_bytes": sum(item["download_bytes"] for item in history),
        "upload_bytes": sum(item["upload_bytes"] for item in history),
        "excluded_buckets": len(excluded),
        "sources": sources,
        "multiple_sources": False,
    }


def _dns(db: Session, asset_id: int, window: dict, search: str = "", page: int = 1) -> dict:
    client_ids = [row[0] for row in db.query(DNSRecognisedDevice.id).filter(DNSRecognisedDevice.hardware_asset_id == asset_id).limit(MAX_ROWS).all()]
    if not client_ids:
        return {"available": True, "query_count": 0, "blocked_count": 0, "history": [], "top_domains": [], "rows": [], "pages": 1, "page": 1}
    base = db.query(DNSClientTrafficEvent).filter(
        DNSClientTrafficEvent.dns_client_id.in_(client_ids),
        DNSClientTrafficEvent.observed_at >= window["start"],
        DNSClientTrafficEvent.observed_at < window["end"],
    )
    rows = base.order_by(DNSClientTrafficEvent.observed_at.asc()).limit(MAX_ROWS).all()
    points: dict[datetime, dict] = defaultdict(lambda: {"queries": 0, "blocked": 0})
    domains: dict[str, int] = defaultdict(int)
    for row in rows:
        duration = window["end"] - window["start"]
        point = points[_bucket(row.observed_at, 3600 if duration <= timedelta(days=7) else 86400)]
        point["queries"] += 1
        point["blocked"] += 1 if row.is_blocked else 0
        domains[row.domain] += 1
    clean_search = search.strip().lower()
    detail_rows = [row for row in rows if not clean_search or clean_search in row.domain.lower()]
    page = max(1, page)
    pages = max(1, (len(detail_rows) + 24) // 25)
    page = min(page, pages)
    start = (page - 1) * 25
    return {"available": True, "query_count": len(rows), "blocked_count": sum(item["blocked"] for item in points.values()), "history": [{"at": _iso(at), **value} for at, value in sorted(points.items())], "top_domains": [{"domain": key, "count": count} for key, count in sorted(domains.items(), key=lambda item: (-item[1], item[0]))[:10]], "rows": [{"domain": row.domain, "observed_at": _iso(row.observed_at), "blocked": bool(row.is_blocked), "status": row.status} for row in detail_rows[start:start + 25]], "pages": pages, "page": page}


def _uptime(db: Session, assignments: list[AssetNetworkAssignment], window: dict) -> dict:
    ip_ids = {row.ip_address_id for row in assignments if row.ip_address_id is not None}
    if not ip_ids:
        return {"available": True, "history": [], "coverage": None}
    monitors = db.query(NetworkMonitor).filter(NetworkMonitor.ip_address_id.in_(ip_ids), NetworkMonitor.is_enabled.is_(True)).limit(100).all()
    monitor_ids = [row.id for row in monitors]
    if not monitor_ids:
        return {"available": True, "history": [], "coverage": None}
    if window["bucket_seconds"]:
        rows = db.query(NetworkMonitorStatistic).filter(
            NetworkMonitorStatistic.monitor_id.in_(monitor_ids),
            NetworkMonitorStatistic.bucket_seconds == window["bucket_seconds"],
            NetworkMonitorStatistic.bucket_start >= window["start"], NetworkMonitorStatistic.bucket_start < window["end"],
        ).order_by(NetworkMonitorStatistic.bucket_start.asc()).limit(MAX_ROWS).all()
        history = [{"at": _iso(row.bucket_start), "availability": round((row.up_count or 0) * 100 / row.sample_count, 1) if row.sample_count else None, "latency_ms": row.avg_latency_ms} for row in rows]
        return {"available": True, "history": history, "coverage": len(rows)}
    rows = db.query(NetworkMonitorCheck).filter(
        NetworkMonitorCheck.monitor_id.in_(monitor_ids),
        NetworkMonitorCheck.checked_at >= window["start"], NetworkMonitorCheck.checked_at < window["end"],
    ).order_by(NetworkMonitorCheck.checked_at.asc()).limit(MAX_ROWS).all()
    points: dict[datetime, dict] = defaultdict(lambda: {"samples": 0, "up": 0, "latency_total": 0.0, "latency_samples": 0})
    for row in rows:
        point = points[_bucket(row.checked_at, 3600)]
        point["samples"] += 1
        point["up"] += 1 if row.status == "up" else 0
        if row.latency_ms is not None:
            point["latency_total"] += float(row.latency_ms)
            point["latency_samples"] += 1
    history = []
    for at, item in sorted(points.items()):
        history.append({"at": _iso(at), "availability": round(item["up"] * 100 / item["samples"], 1) if item["samples"] else None, "latency_ms": round(item["latency_total"] / item["latency_samples"], 2) if item["latency_samples"] else None})
    return {"available": True, "history": history, "coverage": len(rows)}


def asset_reporting_context(db: Session, user, asset_id: int, *, period: str = "24h", start: str | None = None, end: str | None = None, dns_search: str = "", dns_page: int = 1) -> dict:
    """Compose only data the caller's module permissions allow."""
    window = _range(db, period, start, end)
    assignments = db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.asset_id == asset_id).limit(100).all()
    can_dns = has_module_access(db, user, "dns_manager")
    can_network = has_module_access(db, user, "network_monitor")
    can_uptime = can_network
    traffic = _traffic(db, asset_id, assignments, window) if can_network else None
    dns = _dns(db, asset_id, window, dns_search, dns_page) if can_dns else None
    uptime = _uptime(db, assignments, window) if can_uptime else None
    events = [{"at": row.created_at, "kind": "identity", "label": f"Identity evidence: {row.evidence_type}", "state": row.status} for row in db.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id == asset_id, AssetIdentityEvidence.created_at >= window["start"], AssetIdentityEvidence.created_at < window["end"]).order_by(AssetIdentityEvidence.created_at.desc()).limit(100).all()]
    events.extend({"at": row.started_at, "kind": "network", "label": f"Network assignment: {row.address}", "state": row.status} for row in assignments if window["start"] <= row.started_at < window["end"])
    events.sort(key=lambda item: item["at"], reverse=True)
    return {"window": window, "period": period if period in REPORT_RANGES else "24h", "traffic": traffic, "dns": dns, "uptime": uptime, "activity": events[:200]}
