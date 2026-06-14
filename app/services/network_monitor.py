import asyncio
import re
import subprocess
import time
from datetime import datetime, timedelta
from ipaddress import ip_address

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.models import IPAddress, NetworkMonitor, NetworkMonitorCheck

CHECK_INTERVAL_SECONDS = 30
STARTUP_DELAY_SECONDS = 45
MAX_CONCURRENT_CHECKS = 5
MAX_CHECK_HISTORY = 1000
PING_TIME_PATTERN = re.compile(r"time[=<]([0-9.]+)")


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


def fallback_due_monitors(db: Session) -> list[NetworkMonitor]:
    now = datetime.utcnow()
    rows = db.query(NetworkMonitor).join(IPAddress).filter(NetworkMonitor.is_enabled == True).limit(250).all()
    return [
        row for row in rows
        if row.last_checked_at is None or row.last_checked_at <= now - timedelta(seconds=clamp_interval(row.interval_seconds))
    ][:25]


def prune_history(db: Session, monitor_id: int) -> None:
    old_rows = db.query(NetworkMonitorCheck.id).filter(
        NetworkMonitorCheck.monitor_id == monitor_id
    ).order_by(NetworkMonitorCheck.checked_at.desc()).offset(MAX_CHECK_HISTORY).all()
    if old_rows:
        old_ids = [row.id for row in old_rows]
        db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.id.in_(old_ids)).delete(synchronize_session=False)


def run_monitor_check(db: Session, monitor: NetworkMonitor) -> None:
    now = datetime.utcnow()
    ok, latency_ms, error = ping_ipv4(monitor.ip_address.address, clamp_timeout(monitor.timeout_ms))
    status = "up" if ok else "down"
    monitor.last_status = status
    monitor.last_latency_ms = latency_ms
    monitor.last_error = error
    monitor.last_checked_at = now
    db.add(NetworkMonitorCheck(monitor_id=monitor.id, status=status, latency_ms=latency_ms, error=error, checked_at=now))
    prune_history(db, monitor.id)
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
                db.add(NetworkMonitorCheck(monitor_id=monitor.id, status="down", latency_ms=None, error=str(exc), checked_at=now))
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
