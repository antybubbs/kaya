import asyncio
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from ipaddress import ip_address

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.models import (
    IPAddress, NetworkMonitor, NetworkMonitorCheck, NetworkMonitorEvent,
    NetworkMonitorOutage, NetworkMonitorStatistic,
)

CHECK_INTERVAL_SECONDS = 30
STARTUP_DELAY_SECONDS = 45
MAX_CONCURRENT_CHECKS = 5
PING_TIME_PATTERN = re.compile(r"time[=<]([0-9.]+)")
PING_AVERAGE_PATTERN = re.compile(r"= [0-9.]+/([0-9.]+)/")
PING_LOSS_PATTERN = re.compile(r"([0-9.]+)% packet loss")
_last_retention_run: datetime | None = None
_dashboard_override_leases: dict[str, datetime] = {}
_dashboard_collection_lock = threading.Lock()


def monitor_label(monitor: NetworkMonitor) -> str:
    if monitor.display_name:
        return monitor.display_name
    if monitor.ip_address and monitor.ip_address.name:
        return monitor.ip_address.name
    return monitor.ip_address.address if monitor.ip_address else "Unknown monitor"


def clamp_interval(value: int) -> int:
    return min(max(value, 60), 86400)


def clamp_timeout(value: int) -> int:
    return min(max(value, 500), 10000)


def ping_ipv4(address: str, timeout_ms: int) -> tuple[bool, int | None, str | None]:
    parsed = ip_address(address)
    if parsed.version != 4:
        return False, None, "IPv6 ping is not supported yet."
    timeout_seconds = max(1, int((timeout_ms + 999) / 1000))
    started = time.monotonic()
    try:
        result = subprocess.run(
            ["ping", "-4", "-c", "1", "-W", str(timeout_seconds), address],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds + 1,
        )
    except FileNotFoundError:
        return False, None, "Ping command is not installed in the container."
    except subprocess.TimeoutExpired:
        return False, None, "Timed out"
    except OSError:
        return False, None, "Ping execution failed."
    output = f"{result.stdout}\n{result.stderr}"
    if result.returncode == 0:
        match = PING_TIME_PATTERN.search(output)
        latency = int(float(match.group(1))) if match else int((time.monotonic() - started) * 1000)
        return True, latency, None
    error = result.stderr.strip() or result.stdout.strip() or "Ping failed"
    return False, None, error.splitlines()[-1][:500]


def ping_ipv4_samples(address: str, timeout_ms: int, samples: int = 4) -> tuple[bool, int | None, int, str | None]:
    parsed = ip_address(address)
    if parsed.version != 4:
        return False, None, 100, "IPv6 ping is not supported yet."
    timeout_seconds = max(1, int((timeout_ms + 999) / 1000))
    try:
        result = subprocess.run(
            ["ping", "-4", "-c", str(samples), "-W", str(timeout_seconds), address],
            capture_output=True, check=False, text=True, timeout=(timeout_seconds * samples) + 2,
        )
    except FileNotFoundError:
        return False, None, 100, "Ping command is not installed in the container."
    except subprocess.TimeoutExpired:
        return False, None, 100, "Timed out"
    except OSError:
        return False, None, 100, "Ping execution failed."
    output = f"{result.stdout}\n{result.stderr}"
    loss_match = PING_LOSS_PATTERN.search(output)
    packet_loss = round(float(loss_match.group(1))) if loss_match else (0 if result.returncode == 0 else 100)
    average_match = PING_AVERAGE_PATTERN.search(output)
    latency = round(float(average_match.group(1))) if average_match else None
    ok = packet_loss < 100
    error = None if ok else (result.stderr.strip() or result.stdout.strip() or "Ping failed").splitlines()[-1][:500]
    return ok, latency, packet_loss, error


def fallback_due_monitors(db: Session) -> list[NetworkMonitor]:
    if dashboard_override_active():
        return []
    now = datetime.utcnow()
    rows = db.query(NetworkMonitor).join(IPAddress).filter(NetworkMonitor.is_enabled == True).limit(250).all()
    return [
        row for row in rows
        if row.last_checked_at is None or row.last_checked_at <= now - timedelta(seconds=clamp_interval(row.interval_seconds))
    ][:25]


def dashboard_override_active() -> bool:
    now = datetime.utcnow()
    expired = [key for key, expires_at in _dashboard_override_leases.items() if expires_at <= now]
    for key in expired:
        _dashboard_override_leases.pop(key, None)
    return bool(_dashboard_override_leases)


def set_dashboard_override(client_id: str, ttl_seconds: int | None) -> None:
    if ttl_seconds:
        _dashboard_override_leases[client_id] = datetime.utcnow() + timedelta(seconds=max(ttl_seconds, 10))
    else:
        _dashboard_override_leases.pop(client_id, None)


def run_dashboard_collection(client_id: str, ttl_seconds: int) -> bool:
    """Run one non-overlapping dashboard-driven pass and temporarily replace record schedules."""
    set_dashboard_override(client_id, ttl_seconds)
    if not _dashboard_collection_lock.acquire(blocking=False):
        return False
    try:
        db = SessionLocal()
        try:
            monitor_ids = [row.id for row in db.query(NetworkMonitor.id).filter(NetworkMonitor.is_enabled == True).all()]  # noqa: E712
        finally:
            db.close()
        if monitor_ids:
            with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CHECKS) as executor:
                list(executor.map(run_monitor_check_by_id, monitor_ids))
        return True
    finally:
        _dashboard_collection_lock.release()


def _bucket_start(value: datetime, seconds: int) -> datetime:
    epoch = int(value.timestamp())
    return datetime.utcfromtimestamp(epoch - (epoch % seconds))


def _aggregate_checks(db: Session, cutoff: datetime, bucket_seconds: int) -> None:
    safe_cutoff = _bucket_start(cutoff, bucket_seconds)
    rows = db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.checked_at < safe_cutoff).order_by(NetworkMonitorCheck.checked_at.asc()).limit(10000).all()
    groups: dict[tuple[int, datetime], list[NetworkMonitorCheck]] = {}
    for row in rows:
        groups.setdefault((row.monitor_id, _bucket_start(row.checked_at, bucket_seconds)), []).append(row)
    for (monitor_id, bucket), checks in groups.items():
        if not db.query(NetworkMonitorStatistic.id).filter_by(monitor_id=monitor_id, bucket_start=bucket, bucket_seconds=bucket_seconds).first():
            latencies = [item.latency_ms for item in checks if item.latency_ms is not None]
            losses = [item.packet_loss_percent for item in checks if item.packet_loss_percent is not None]
            db.add(NetworkMonitorStatistic(
                monitor_id=monitor_id, bucket_start=bucket, bucket_seconds=bucket_seconds,
                sample_count=len(checks), up_count=sum(1 for item in checks if item.status == "up"),
                avg_latency_ms=round(sum(latencies) / len(latencies)) if latencies else None,
                max_latency_ms=max(latencies) if latencies else None,
                avg_packet_loss_percent=round(sum(losses) / len(losses)) if losses else None,
            ))
    if rows:
        db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.id.in_([row.id for row in rows])).delete(synchronize_session=False)


def enforce_retention(db: Session) -> None:
    """Keep raw checks for 24h, five-minute summaries for 30d and hourly summaries for 365d."""
    global _last_retention_run
    now = datetime.utcnow()
    if _last_retention_run and _last_retention_run > now - timedelta(hours=1):
        return
    _aggregate_checks(db, now - timedelta(hours=24), 300)
    hourly_cutoff = _bucket_start(now - timedelta(days=30), 3600)
    five_minute = db.query(NetworkMonitorStatistic).filter(
        NetworkMonitorStatistic.bucket_seconds == 300,
        NetworkMonitorStatistic.bucket_start < hourly_cutoff,
    ).order_by(NetworkMonitorStatistic.bucket_start.asc()).limit(10000).all()
    groups: dict[tuple[int, datetime], list[NetworkMonitorStatistic]] = {}
    for row in five_minute:
        groups.setdefault((row.monitor_id, _bucket_start(row.bucket_start, 3600)), []).append(row)
    for (monitor_id, bucket), rows in groups.items():
        if not db.query(NetworkMonitorStatistic.id).filter_by(monitor_id=monitor_id, bucket_start=bucket, bucket_seconds=3600).first():
            samples = sum(row.sample_count for row in rows)
            latency_samples = [row for row in rows if row.avg_latency_ms is not None]
            loss_samples = [row for row in rows if row.avg_packet_loss_percent is not None]
            db.add(NetworkMonitorStatistic(
                monitor_id=monitor_id, bucket_start=bucket, bucket_seconds=3600,
                sample_count=samples, up_count=sum(row.up_count for row in rows),
                avg_latency_ms=round(sum(row.avg_latency_ms * row.sample_count for row in latency_samples) / sum(row.sample_count for row in latency_samples)) if latency_samples else None,
                max_latency_ms=max((row.max_latency_ms for row in rows if row.max_latency_ms is not None), default=None),
                avg_packet_loss_percent=round(sum(row.avg_packet_loss_percent * row.sample_count for row in loss_samples) / sum(row.sample_count for row in loss_samples)) if loss_samples else None,
            ))
    if five_minute:
        db.query(NetworkMonitorStatistic).filter(NetworkMonitorStatistic.id.in_([row.id for row in five_minute])).delete(synchronize_session=False)
    db.query(NetworkMonitorStatistic).filter(NetworkMonitorStatistic.bucket_start < now - timedelta(days=365)).delete(synchronize_session=False)
    db.query(NetworkMonitorEvent).filter(NetworkMonitorEvent.occurred_at < now - timedelta(days=365)).delete(synchronize_session=False)
    db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.ended_at.isnot(None), NetworkMonitorOutage.ended_at < now - timedelta(days=365)).delete(synchronize_session=False)
    _last_retention_run = now


def _event(db: Session, monitor: NetworkMonitor, event_type: str, severity: str, message: str, now: datetime) -> None:
    db.add(NetworkMonitorEvent(monitor_id=monitor.id, event_type=event_type, severity=severity, message=message[:500], occurred_at=now))


def run_monitor_check(db: Session, monitor: NetworkMonitor) -> None:
    now = datetime.utcnow()
    previous_status = monitor.last_status
    ok, latency_ms, packet_loss, error = ping_ipv4_samples(monitor.ip_address.address, clamp_timeout(monitor.timeout_ms))
    status = "up" if ok else "down"
    if ok:
        monitor.consecutive_failures = 0
        if packet_loss >= monitor.packet_loss_critical_percent or (latency_ms is not None and latency_ms >= monitor.latency_critical_ms):
            health = "critical"
        elif packet_loss >= monitor.packet_loss_warning_percent or (latency_ms is not None and latency_ms >= monitor.latency_warning_ms):
            health = "warning"
        else:
            health = "up"
    else:
        monitor.consecutive_failures = (monitor.consecutive_failures or 0) + 1
        health = "down" if monitor.consecutive_failures >= monitor.failure_threshold else "warning"
    monitor.last_status = health
    monitor.last_latency_ms = latency_ms
    monitor.last_packet_loss_percent = packet_loss
    monitor.last_error = error
    monitor.last_checked_at = now
    db.add(NetworkMonitorCheck(monitor_id=monitor.id, status=status, latency_ms=latency_ms, packet_loss_percent=packet_loss, response_time_ms=latency_ms, error=error, checked_at=now))
    if health != previous_status:
        if health == "down":
            _event(db, monitor, "outage_started", "critical", error or "Monitor is offline", now)
            if not db.query(NetworkMonitorOutage.id).filter_by(monitor_id=monitor.id, ended_at=None).first():
                db.add(NetworkMonitorOutage(monitor_id=monitor.id, started_at=now, failure_reason=error))
        elif previous_status == "down":
            outage = db.query(NetworkMonitorOutage).filter_by(monitor_id=monitor.id, ended_at=None).order_by(NetworkMonitorOutage.started_at.desc()).first()
            if outage:
                outage.ended_at = now
            _event(db, monitor, "recovered", "info", f"Monitor recovered at {latency_ms} ms", now)
        elif health in {"warning", "critical"}:
            _event(db, monitor, "threshold", health, f"Latency {latency_ms} ms; packet loss {packet_loss}%" if ok else f"Check failed ({monitor.consecutive_failures}/{monitor.failure_threshold})", now)
        elif previous_status:
            _event(db, monitor, "healthy", "info", "Monitor returned to healthy thresholds", now)
    enforce_retention(db)
    db.commit()


def run_monitor_check_by_id(monitor_id: int) -> None:
    db = SessionLocal()
    try:
        monitor = db.get(NetworkMonitor, monitor_id)
        if monitor and monitor.is_enabled and monitor.ip_address:
            try:
                run_monitor_check(db, monitor)
            except Exception as exc:
                now = datetime.utcnow()
                monitor.last_status = "down"
                monitor.last_latency_ms = None
                monitor.last_error = str(exc)
                monitor.last_checked_at = now
                db.add(NetworkMonitorCheck(monitor_id=monitor.id, status="down", latency_ms=None, packet_loss_percent=100, response_time_ms=None, error=str(exc), checked_at=now))
                db.commit()
    finally:
        db.close()


async def monitor_loop() -> None:
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        db = SessionLocal()
        try:
            monitor_ids = [monitor.id for monitor in fallback_due_monitors(db)]
        finally:
            db.close()
        if monitor_ids:
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

            async def checked_monitor(monitor_id: int) -> None:
                async with semaphore:
                    await asyncio.to_thread(run_monitor_check_by_id, monitor_id)

            await asyncio.gather(*(checked_monitor(monitor_id) for monitor_id in monitor_ids))
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
