import asyncio
import json
import logging
import re
import subprocess
import time
import threading
from datetime import datetime, timedelta
from ipaddress import ip_address
from uuid import uuid4

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.models import (
    IPAddress, NetworkMonitor, NetworkMonitorCheck, NetworkMonitorEvent,
    NetworkMonitorOutage, NetworkMonitorStatistic, NetworkMonitorTransition,
    NotificationEvent, NotificationOutbox,
)
from app.services.notification_outbox import enqueue_notification
from app.services.site_settings import get_site_settings

logger = logging.getLogger(__name__)

CHECK_INTERVAL_SECONDS = 1
STARTUP_DELAY_SECONDS = 45
MAX_CONCURRENT_CHECKS = 5
SCHEDULER_HEARTBEAT_SECONDS = 60
WATCHDOG_INTERVAL_SECONDS = 60
PING_TIME_PATTERN = re.compile(r"time[=<]([0-9.]+)")
PING_AVERAGE_PATTERN = re.compile(r"= [0-9.]+/([0-9.]+)/")
PING_LOSS_PATTERN = re.compile(r"([0-9.]+)% packet loss")
_last_retention_run: datetime | None = None
_monitor_check_locks: dict[int, threading.Lock] = {}
_monitor_check_locks_guard = threading.Lock()
_dashboard_interval_leases: dict[str, tuple[str, int, datetime]] = {}
_dashboard_interval_leases_guard = threading.Lock()
_scheduler_state_guard = threading.Lock()
_scheduler_task: asyncio.Task | None = None
_scheduler_watchdog_task: asyncio.Task | None = None
_scheduler_shutdown_requested = False
_scheduler_generation = 0
_worker_started_at: datetime | None = None
_last_scheduler_heartbeat: datetime | None = None
_last_monitor_execution: datetime | None = None
_last_observation_written: datetime | None = None
_last_due_scan: datetime | None = None
_due_monitors_found = 0
_active_monitor_started_at: dict[int, datetime] = {}
_last_scheduler_exception: str | None = None
_watchdog_restart_count = 0
_current_loop_iteration = 0
_pending_monitor_ids: set[int] = set()
DASHBOARD_INTERVALS = {"live": 1, "five": 5, "ten": 10, "sixty": 60}
MONITOR_THRESHOLD_DEFAULTS = {
    "latency_warning_ms": 100,
    "latency_critical_ms": 250,
    "packet_loss_warning_percent": 5,
    "packet_loss_critical_percent": 25,
    "degraded_threshold": 2,
    "failure_threshold": 3,
    "recovery_threshold": 3,
    "recovery_state_enabled": True,
}
MONITOR_THRESHOLD_SETTING_KEYS = {
    key: f"network_monitor_{key}" for key in MONITOR_THRESHOLD_DEFAULTS
}


def monitor_label(monitor: NetworkMonitor) -> str:
    if monitor.display_name:
        return monitor.display_name
    if monitor.ip_address and monitor.ip_address.name:
        return monitor.ip_address.name
    return monitor.ip_address.address if monitor.ip_address else "Unknown monitor"


def latency_label(value: float | int | None) -> str:
    if value is None:
        return "-"
    numeric = float(value)
    if 0 <= numeric < 1:
        return "<1 ms"
    rounded = round(numeric, 1)
    return f"{int(rounded) if rounded.is_integer() else rounded:g} ms"


def live_latency_label(value: float | int | None) -> str:
    """Format dashboard live readings without discarding captured precision."""
    if value is None:
        return "-"
    return f"{float(value):.3f}".rstrip("0").rstrip(".") + " ms"


def clamp_interval(value: int) -> int:
    return min(max(value, 5), 86400)


def clamp_timeout(value: int) -> int:
    return min(max(value, 500), 10000)


def validate_threshold_values(values: dict[str, int | bool]) -> dict[str, int | bool]:
    cleaned = {
        "latency_warning_ms": int(values["latency_warning_ms"]),
        "latency_critical_ms": int(values["latency_critical_ms"]),
        "packet_loss_warning_percent": int(values["packet_loss_warning_percent"]),
        "packet_loss_critical_percent": int(values["packet_loss_critical_percent"]),
        "degraded_threshold": int(values["degraded_threshold"]),
        "failure_threshold": int(values["failure_threshold"]),
        "recovery_threshold": int(values["recovery_threshold"]),
        "recovery_state_enabled": bool(values["recovery_state_enabled"]),
    }
    if not 0 <= cleaned["latency_warning_ms"] <= 60000:
        raise ValueError("Warning latency must be between 0 and 60000 milliseconds.")
    if not cleaned["latency_warning_ms"] <= cleaned["latency_critical_ms"] <= 60000:
        raise ValueError("Critical latency must be greater than or equal to warning latency.")
    if not 0 <= cleaned["packet_loss_warning_percent"] <= 100:
        raise ValueError("Warning packet loss must be between 0 and 100 percent.")
    if not cleaned["packet_loss_warning_percent"] <= cleaned["packet_loss_critical_percent"] <= 100:
        raise ValueError("Critical packet loss must be greater than or equal to warning packet loss.")
    for key, label in (
        ("degraded_threshold", "Degraded checks"),
        ("failure_threshold", "Failures before offline"),
        ("recovery_threshold", "Successes before recovery"),
    ):
        if not 1 <= cleaned[key] <= 20:
            raise ValueError(f"{label} must be between 1 and 20.")
    return cleaned


def validate_monitor_timing(interval_seconds: int, timeout_ms: int) -> tuple[int, int]:
    interval = clamp_interval(interval_seconds)
    timeout = clamp_timeout(timeout_ms)
    if timeout > interval * 1000:
        raise ValueError("Ping timeout must not exceed the selected check interval.")
    return interval, timeout


def effective_monitor_thresholds(db: Session, monitor: NetworkMonitor) -> dict[str, int | bool]:
    if not monitor.use_default_thresholds:
        return validate_threshold_values({
            key: getattr(monitor, key) for key in MONITOR_THRESHOLD_DEFAULTS
        })
    stored = get_site_settings(db, MONITOR_THRESHOLD_SETTING_KEYS.values())
    values: dict[str, int | bool] = {}
    for key, setting_key in MONITOR_THRESHOLD_SETTING_KEYS.items():
        raw = stored.get(setting_key)
        if key == "recovery_state_enabled":
            values[key] = raw == "1"
        else:
            try:
                values[key] = int(raw)
            except (TypeError, ValueError):
                values[key] = MONITOR_THRESHOLD_DEFAULTS[key]
    try:
        return validate_threshold_values(values)
    except ValueError:
        return MONITOR_THRESHOLD_DEFAULTS.copy()


def observation_health(
    thresholds: dict[str, int | bool],
    ok: bool,
    latency_ms: float | None,
    packet_loss: int | None,
) -> tuple[str, str, str | None, int | None, int | None]:
    if not ok or packet_loss == 100:
        return "offline", "No response from target", "availability", 100, packet_loss
    critical_reasons = []
    warning_reasons = []
    if latency_ms is not None:
        if latency_ms >= thresholds["latency_critical_ms"]:
            critical_reasons.append(("latency", thresholds["latency_critical_ms"], latency_ms, f"Latency {latency_ms} ms"))
        elif latency_ms >= thresholds["latency_warning_ms"]:
            warning_reasons.append(("latency", thresholds["latency_warning_ms"], latency_ms, f"Latency above {thresholds['latency_warning_ms']} ms"))
    if packet_loss is not None:
        if packet_loss >= thresholds["packet_loss_critical_percent"]:
            critical_reasons.append(("packet_loss", thresholds["packet_loss_critical_percent"], packet_loss, f"Packet loss {packet_loss}%"))
        elif packet_loss >= thresholds["packet_loss_warning_percent"]:
            warning_reasons.append(("packet_loss", thresholds["packet_loss_warning_percent"], packet_loss, f"Packet loss above {thresholds['packet_loss_warning_percent']}%"))
    selected = critical_reasons[0] if critical_reasons else warning_reasons[0] if warning_reasons else None
    if selected:
        return ("critical" if critical_reasons else "warning", selected[3], selected[0], selected[1], selected[2])
    return "healthy", f"{latency_ms} ms" if latency_ms is not None else "Response received", None, None, None


def _set_state(monitor: NetworkMonitor, state: str, reason: str, now: datetime) -> bool:
    changed = monitor.last_status != state
    monitor.last_status = state
    monitor.state_reason = reason[:500]
    if changed:
        monitor.state_changed_at = now
    return changed


def ping_ipv4(address: str, timeout_ms: int) -> tuple[bool, float | None, str | None]:
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
        latency = round(float(match.group(1)), 3) if match else round((time.monotonic() - started) * 1000, 3)
        return True, latency, None
    error = result.stderr.strip() or result.stdout.strip() or "Ping failed"
    return False, None, error.splitlines()[-1][:500]


def ping_ipv4_samples(address: str, timeout_ms: int, samples: int = 4) -> tuple[bool, float | None, int, str | None]:
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
    latency = round(float(average_match.group(1)), 3) if average_match else None
    ok = packet_loss < 100
    error = None if ok else (result.stderr.strip() or result.stdout.strip() or "Ping failed").splitlines()[-1][:500]
    return ok, latency, packet_loss, error


def fallback_due_monitors(db: Session) -> list[NetworkMonitor]:
    now = datetime.utcnow()
    dashboard_interval = active_dashboard_interval()
    rows = db.query(NetworkMonitor).join(IPAddress).filter(NetworkMonitor.is_enabled).order_by(NetworkMonitor.last_checked_at.asc()).limit(250).all()
    return [
        row for row in rows
        if row.last_checked_at is None or row.last_checked_at <= now - timedelta(seconds=dashboard_interval or clamp_interval(row.interval_seconds))
    ][:25]


def _prune_dashboard_interval_leases(now: datetime) -> None:
    for client_id, (_, _, expires_at) in list(_dashboard_interval_leases.items()):
        if expires_at <= now:
            _dashboard_interval_leases.pop(client_id, None)


def set_dashboard_interval_override(client_id: str, mode: str) -> bool:
    """Renew one dashboard lease and report whether its selected mode changed."""
    now = datetime.utcnow()
    with _dashboard_interval_leases_guard:
        _prune_dashboard_interval_leases(now)
        previous = _dashboard_interval_leases.get(client_id)
        if mode == "paused":
            _dashboard_interval_leases.pop(client_id, None)
            return previous is not None
        interval = DASHBOARD_INTERVALS[mode]
        _dashboard_interval_leases[client_id] = (mode, interval, now + timedelta(seconds=25))
        return previous is None or previous[0] != mode


def active_dashboard_interval() -> int | None:
    now = datetime.utcnow()
    with _dashboard_interval_leases_guard:
        _prune_dashboard_interval_leases(now)
        return min((interval for _, interval, _ in _dashboard_interval_leases.values()), default=None)


def monitor_check_lock(monitor_id: int) -> threading.Lock:
    with _monitor_check_locks_guard:
        return _monitor_check_locks.setdefault(monitor_id, threading.Lock())


def _bucket_start(value: datetime, seconds: int) -> datetime:
    epoch = int(value.timestamp())
    return datetime.utcfromtimestamp(epoch - (epoch % seconds))


def _worst_health(states) -> str | None:
    priority = {"unknown": 0, "healthy": 1, "maintenance": 2, "paused": 2, "recovering": 3, "warning": 4, "critical": 5, "offline": 6}
    values = [state for state in states if state]
    return max(values, key=lambda state: priority.get(state, 0), default=None)


def _aggregate_checks(db: Session, cutoff: datetime, bucket_seconds: int) -> None:
    safe_cutoff = _bucket_start(cutoff, bucket_seconds)
    rows = db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.checked_at < safe_cutoff).order_by(NetworkMonitorCheck.checked_at.asc()).limit(10000).all()
    groups: dict[tuple[int, datetime], list[NetworkMonitorCheck]] = {}
    for row in rows:
        groups.setdefault((row.monitor_id, _bucket_start(row.checked_at, bucket_seconds)), []).append(row)
    for (monitor_id, bucket), checks in groups.items():
        if not db.query(NetworkMonitorStatistic.id).filter_by(monitor_id=monitor_id, bucket_start=bucket, bucket_seconds=bucket_seconds).first():
            latencies = [item.latency_ms for item in checks if item.latency_ms is not None]
            jitters = [abs(current - previous) for previous, current in zip(latencies, latencies[1:])]
            losses = [item.packet_loss_percent for item in checks if item.packet_loss_percent is not None]
            db.add(NetworkMonitorStatistic(
                monitor_id=monitor_id, bucket_start=bucket, bucket_seconds=bucket_seconds,
                sample_count=len(checks), up_count=sum(1 for item in checks if item.status == "up"),
                latency_sample_count=len(latencies),
                avg_latency_ms=round(sum(latencies) / len(latencies), 3) if latencies else None,
                min_latency_ms=min(latencies) if latencies else None,
                max_latency_ms=max(latencies) if latencies else None,
                jitter_sample_count=len(jitters),
                avg_jitter_ms=round(sum(jitters) / len(jitters), 3) if jitters else None,
                max_jitter_ms=max(jitters) if jitters else None,
                loss_sample_count=len(losses),
                avg_packet_loss_percent=round(sum(losses) / len(losses)) if losses else None,
                health_state=_worst_health(item.health_state or ("healthy" if item.status == "up" else "offline") for item in checks),
            ))
    if rows:
        db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.id.in_([row.id for row in rows])).delete(synchronize_session=False)


def _rollup_statistics(db: Session, source_seconds: int, cutoff: datetime, target_seconds: int) -> None:
    safe_cutoff = _bucket_start(cutoff, target_seconds)
    source_rows = db.query(NetworkMonitorStatistic).filter(
        NetworkMonitorStatistic.bucket_seconds == source_seconds,
        NetworkMonitorStatistic.bucket_start < safe_cutoff,
    ).order_by(NetworkMonitorStatistic.bucket_start.asc()).limit(10000).all()
    groups: dict[tuple[int, datetime], list[NetworkMonitorStatistic]] = {}
    for row in source_rows:
        groups.setdefault((row.monitor_id, _bucket_start(row.bucket_start, target_seconds)), []).append(row)
    for (monitor_id, bucket), rows in groups.items():
        if not db.query(NetworkMonitorStatistic.id).filter_by(monitor_id=monitor_id, bucket_start=bucket, bucket_seconds=target_seconds).first():
            samples = sum(row.sample_count for row in rows)
            latency_samples = [row for row in rows if row.avg_latency_ms is not None and (row.latency_sample_count or row.up_count)]
            jitter_samples = [row for row in rows if row.avg_jitter_ms is not None and row.jitter_sample_count]
            loss_samples = [row for row in rows if row.avg_packet_loss_percent is not None and (row.loss_sample_count or row.sample_count)]
            latency_count = sum(row.latency_sample_count or row.up_count for row in latency_samples)
            jitter_count = sum(row.jitter_sample_count for row in jitter_samples)
            loss_count = sum(row.loss_sample_count or row.sample_count for row in loss_samples)
            db.add(NetworkMonitorStatistic(
                monitor_id=monitor_id, bucket_start=bucket, bucket_seconds=target_seconds,
                sample_count=samples, up_count=sum(row.up_count for row in rows),
                latency_sample_count=latency_count,
                avg_latency_ms=round(sum(row.avg_latency_ms * (row.latency_sample_count or row.up_count) for row in latency_samples) / latency_count, 3) if latency_count else None,
                min_latency_ms=min((row.min_latency_ms for row in rows if row.min_latency_ms is not None), default=None),
                max_latency_ms=max((row.max_latency_ms for row in rows if row.max_latency_ms is not None), default=None),
                jitter_sample_count=jitter_count,
                avg_jitter_ms=round(sum(row.avg_jitter_ms * row.jitter_sample_count for row in jitter_samples) / jitter_count, 3) if jitter_count else None,
                max_jitter_ms=max((row.max_jitter_ms for row in rows if row.max_jitter_ms is not None), default=None),
                loss_sample_count=loss_count,
                avg_packet_loss_percent=round(sum(row.avg_packet_loss_percent * (row.loss_sample_count or row.sample_count) for row in loss_samples) / loss_count) if loss_count else None,
                health_state=_worst_health(row.health_state for row in rows),
            ))
    if source_rows:
        db.query(NetworkMonitorStatistic).filter(NetworkMonitorStatistic.id.in_([row.id for row in source_rows])).delete(synchronize_session=False)


def enforce_retention(db: Session) -> None:
    """Keep raw checks for 30d, 5-minute summaries for 90d, hourly for 365d, and daily indefinitely."""
    global _last_retention_run
    now = datetime.utcnow()
    if _last_retention_run and _last_retention_run > now - timedelta(hours=1):
        return
    _aggregate_checks(db, now - timedelta(days=30), 300)
    _rollup_statistics(db, 300, now - timedelta(days=90), 3600)
    _rollup_statistics(db, 3600, now - timedelta(days=365), 86400)
    _last_retention_run = now


def _event(db: Session, monitor: NetworkMonitor, event_type: str, severity: str, message: str, now: datetime) -> None:
    db.add(NetworkMonitorEvent(monitor_id=monitor.id, event_type=event_type, severity=severity, message=message[:500], occurred_at=now))


def _enqueue_monitor_notification(
    db: Session,
    monitor: NetworkMonitor,
    event_type_id: str,
    title: str,
    message: str,
    deduplication_key: str,
    *,
    resolved: bool = False,
    resolve_deduplication_key: str | None = None,
    correlation_id: str | None = None,
) -> NotificationOutbox:
    return enqueue_notification(
        db,
        event_type_id=event_type_id,
        title=title,
        message=message,
        target_route=f"/networking/ip-wan-monitor/{monitor.id}",
        source_entity_type="network_monitor",
        source_entity_id=monitor.id,
        deduplication_key=deduplication_key,
        resolve_deduplication_key=resolve_deduplication_key,
        correlation_id=correlation_id,
        resolved=resolved,
    )


def reconcile_offline_notifications(db: Session) -> dict[str, int]:
    """Create one real notification for confirmed offline monitors lacking one."""
    monitors = (
        db.query(NetworkMonitor)
        .filter(
            NetworkMonitor.is_enabled.is_(True),
            NetworkMonitor.is_in_maintenance.is_(False),
            NetworkMonitor.last_status.in_(["offline", "down"]),
        )
        .order_by(NetworkMonitor.id.asc())
        .limit(1000)
        .all()
    )
    created = 0
    existing = 0
    for monitor in monitors:
        key = f"ipwan:host:{monitor.id}:offline"
        active = db.query(NotificationEvent.id).filter_by(
            deduplication_key=key, resolved_at=None
        ).first()
        if active:
            existing += 1
            continue
        label = monitor_label(monitor)
        pending = db.query(NotificationOutbox.id).filter(
            NotificationOutbox.deduplication_key == key,
            NotificationOutbox.status.in_(["pending", "processing", "retry"]),
        ).first()
        if pending:
            existing += 1
            continue
        row = _enqueue_monitor_notification(
            db,
            monitor,
            "ipwan.host.offline",
            "Host offline",
            f"{label} is no longer responding.",
            key,
        )
        if row:
            created += 1
    db.commit()
    logger.info(
        "notification.reconcile.completed module=network_monitor candidates=%s created=%s existing=%s",
        len(monitors),
        created,
        existing,
    )
    return {"candidates": len(monitors), "created": created, "existing": existing}


def record_monitor_result(
    db: Session,
    monitor: NetworkMonitor,
    ok: bool,
    latency_ms: float | None,
    packet_loss: int | None,
    error: str | None,
    now: datetime | None = None,
) -> None:
    now = now or datetime.utcnow()
    thresholds = effective_monitor_thresholds(db, monitor)
    previous_state = {"up": "healthy", "down": "offline", "pending": "unknown"}.get(monitor.last_status, monitor.last_status or "unknown")
    raw_state, raw_reason, threshold_type, configured_value, actual_value = observation_health(
        thresholds, ok, latency_ms, packet_loss
    )
    open_incidents = db.query(NetworkMonitorOutage).filter_by(
        monitor_id=monitor.id, ended_at=None
    ).order_by(NetworkMonitorOutage.started_at.asc()).all()
    offline_incident = next((row for row in open_incidents if (row.incident_type or "offline") == "offline"), None)
    degraded_incident = next((row for row in open_incidents if row.incident_type == "degraded"), None)

    if monitor.is_in_maintenance:
        state, reason = "maintenance", "Active maintenance window"
    elif ok:
        monitor.consecutive_failures = 0
        recovering = previous_state in {"offline", "recovering"} or offline_incident is not None
        monitor.consecutive_successes = (
            (monitor.consecutive_successes or 0) + 1
            if recovering or raw_state == "healthy"
            else 0
        )
        if raw_state in {"warning", "critical"}:
            monitor.consecutive_degraded = (monitor.consecutive_degraded or 0) + 1
        else:
            monitor.consecutive_degraded = 0
        if recovering and monitor.consecutive_successes < thresholds["recovery_threshold"]:
            if thresholds["recovery_state_enabled"]:
                state = "recovering"
                reason = f"{monitor.consecutive_successes} of {thresholds['recovery_threshold']} successful checks"
            else:
                state = "offline"
                reason = f"Recovery confirmation {monitor.consecutive_successes} of {thresholds['recovery_threshold']}"
        elif raw_state in {"warning", "critical"} and monitor.consecutive_degraded >= thresholds["degraded_threshold"]:
            state, reason = raw_state, raw_reason
        else:
            state = "healthy"
            reason = raw_reason if raw_state == "healthy" else f"{monitor.consecutive_degraded} of {thresholds['degraded_threshold']} degraded checks"
    else:
        monitor.consecutive_degraded = 0
        monitor.consecutive_successes = 0
        monitor.consecutive_failures = (monitor.consecutive_failures or 0) + 1
        if previous_state in {"offline", "recovering"} or offline_incident is not None:
            state, reason = "offline", f"Recovery interrupted: {error or raw_reason}"
        elif monitor.consecutive_failures >= thresholds["failure_threshold"]:
            state, reason = "offline", f"{monitor.consecutive_failures} consecutive failed checks"
        else:
            state, reason = "warning", f"Check failed ({monitor.consecutive_failures}/{thresholds['failure_threshold']})"

    changed = _set_state(monitor, state, reason, now)
    monitor.last_latency_ms = latency_ms
    monitor.last_packet_loss_percent = packet_loss
    monitor.last_error = error
    monitor.last_checked_at = now
    observation = NetworkMonitorCheck(
        monitor_id=monitor.id,
        status="up" if ok else "down",
        health_state="maintenance" if monitor.is_in_maintenance else raw_state,
        latency_ms=latency_ms,
        packet_loss_percent=packet_loss,
        response_time_ms=latency_ms,
        error=error,
        checked_at=now,
    )
    db.add(observation)
    db.flush()

    if not monitor.is_in_maintenance:
        if state == "offline" and not offline_incident:
            if degraded_incident:
                degraded_incident.ended_at = now
            failed_checks = db.query(NetworkMonitorCheck).filter_by(
                monitor_id=monitor.id, status="down"
            ).order_by(NetworkMonitorCheck.checked_at.desc()).limit(monitor.consecutive_failures).all()
            first_failed_at = min((row.checked_at for row in failed_checks), default=now)
            last_success = db.query(NetworkMonitorCheck).filter_by(monitor_id=monitor.id, status="up").order_by(NetworkMonitorCheck.checked_at.desc()).first()
            details = {
                "failure_count": monitor.consecutive_failures,
                "timeout_ms": monitor.timeout_ms,
                "first_failed_at": first_failed_at.isoformat() + "Z",
                "confirmed_at": now.isoformat() + "Z",
                "last_success_at": last_success.checked_at.isoformat() + "Z" if last_success else None,
                "last_known_latency_ms": last_success.latency_ms if last_success else None,
            }
            offline_incident = NetworkMonitorOutage(
                monitor_id=monitor.id, started_at=first_failed_at, incident_type="offline",
                failure_reason=(error or reason)[:500], details_json=json.dumps(details),
            )
            db.add(offline_incident)
            _event(db, monitor, "incident_started", "critical", reason, now)
        elif offline_incident and state not in {"offline", "recovering"}:
            offline_incident.ended_at = now
            _event(db, monitor, "recovered", "info", f"Offline incident resolved after {monitor.consecutive_successes} successful checks", now)

        confirmed_degraded = ok and state in {"warning", "critical"}
        if confirmed_degraded and not degraded_incident:
            breach_checks = db.query(NetworkMonitorCheck).filter(
                NetworkMonitorCheck.monitor_id == monitor.id,
                NetworkMonitorCheck.health_state.in_(["warning", "critical"]),
            ).order_by(NetworkMonitorCheck.checked_at.desc()).limit(monitor.consecutive_degraded).all()
            first_breach_at = min((row.checked_at for row in breach_checks), default=now)
            details = {
                "threshold_type": threshold_type,
                "configured_threshold": configured_value,
                "actual_value": actual_value,
                "first_breach_at": first_breach_at.isoformat() + "Z",
                "confirmed_at": now.isoformat() + "Z",
                "consecutive_breaches": monitor.consecutive_degraded,
            }
            degraded_incident = NetworkMonitorOutage(
                monitor_id=monitor.id, started_at=first_breach_at, incident_type="degraded",
                failure_reason=reason[:500], details_json=json.dumps(details),
            )
            db.add(degraded_incident)
            _event(db, monitor, "degraded_incident_started", state, reason, now)
        elif degraded_incident and state == "healthy" and monitor.consecutive_successes >= thresholds["recovery_threshold"]:
            degraded_incident.ended_at = now
            _event(db, monitor, "degraded_recovered", "info", f"Threshold incident resolved after {monitor.consecutive_successes} healthy checks", now)

    if changed:
        _event(db, monitor, "state_changed", state, f"State changed to {state}: {reason}", now)
        correlation_id = uuid4().hex
        db.add(
            NetworkMonitorTransition(
                monitor_id=monitor.id,
                previous_state=previous_state,
                new_state=state,
                transitioned_at=now,
                triggering_observation_id=observation.id,
                consecutive_successes=monitor.consecutive_successes or 0,
                consecutive_failures=monitor.consecutive_failures or 0,
                reason=reason[:500],
                correlation_id=correlation_id,
            )
        )
        label = monitor_label(monitor)
        if state == "offline":
            _enqueue_monitor_notification(
                db,
                monitor,
                "ipwan.host.offline",
                "Host offline",
                f"{label} is no longer responding.",
                f"ipwan:host:{monitor.id}:offline",
                correlation_id=correlation_id,
            )
        elif (
            previous_state in {"offline", "recovering"}
            and state not in {"offline", "recovering"}
        ):
            _enqueue_monitor_notification(
                db,
                monitor,
                "ipwan.host.recovered",
                "Host recovered",
                f"{label} is responding again.",
                f"ipwan:host:{monitor.id}:recovered:{correlation_id}",
                resolve_deduplication_key=f"ipwan:host:{monitor.id}:offline",
                correlation_id=correlation_id,
                resolved=True,
            )
    enforce_retention(db)
    db.commit()
    if changed:
        logger.info(
            "monitor.transition.committed monitor_id=%s previous_state=%s new_state=%s "
            "observation_id=%s correlation_id=%s",
            monitor.id,
            previous_state,
            state,
            observation.id,
            correlation_id,
        )
    with _scheduler_state_guard:
        global _last_observation_written
        _last_observation_written = datetime.utcnow()
    logger.info("IP/WAN observation written monitor_id=%s", monitor.id)


def run_monitor_check(db: Session, monitor: NetworkMonitor) -> None:
    started_at = datetime.utcnow()
    monitor_id = monitor.id
    address = monitor.ip_address.address
    timeout_ms = clamp_timeout(monitor.timeout_ms)
    fast_check = active_dashboard_interval() == 1
    # Ping is a subprocess boundary and can take several seconds. It needs no
    # live ORM transaction; reload the monitor before recording the result.
    db.rollback()
    if fast_check:
        ok, latency_ms, error = ping_ipv4(
            address, timeout_ms
        )
        packet_loss = 0 if ok else 100
    else:
        ok, latency_ms, packet_loss, error = ping_ipv4_samples(
            address, timeout_ms
        )
    monitor = db.get(NetworkMonitor, monitor_id)
    if monitor is None or not monitor.is_enabled:
        return
    record_monitor_result(db, monitor, ok, latency_ms, packet_loss, error, now=started_at)


def run_monitor_check_by_id(monitor_id: int) -> bool:
    lock = monitor_check_lock(monitor_id)
    if not lock.acquire(blocking=False):
        return False
    db = SessionLocal()
    try:
        monitor = db.get(NetworkMonitor, monitor_id)
        if monitor and monitor.is_enabled and monitor.ip_address:
            try:
                run_monitor_check(db, monitor)
            except Exception:
                db.rollback()
                monitor = db.get(NetworkMonitor, monitor_id)
                if monitor:
                    record_monitor_result(
                        db, monitor, False, None, 100,
                        "Monitor check failed unexpectedly.",
                    )
            return True
        return False
    finally:
        db.close()
        lock.release()


def _utc_iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") + "Z" if value else None


def monitor_scheduler_diagnostics() -> dict:
    """Return a minimal, thread-safe snapshot of the scheduler's runtime state."""
    with _scheduler_state_guard:
        task = _scheduler_task
        started_at = _worker_started_at
        pending = sorted(_pending_monitor_ids)
        active_started = dict(_active_monitor_started_at)
        oldest_started = min(active_started.values(), default=None)
        now = datetime.utcnow()
        return {
            "scheduler_running": bool(task and not task.done()),
            "scheduler_task_id": task.get_name() if task else None,
            "task_id": task.get_name() if task else None,
            "last_scheduler_heartbeat": _utc_iso(_last_scheduler_heartbeat),
            "last_due_scan": _utc_iso(_last_due_scan),
            "due_monitors_found": _due_monitors_found,
            "last_monitor_execution": _utc_iso(_last_monitor_execution),
            "last_observation_written": _utc_iso(_last_observation_written),
            "pending_monitors": pending,
            "pending_monitor_count": len(pending),
            "active_monitor_tasks": len(active_started),
            "available_worker_slots": max(0, MAX_CONCURRENT_CHECKS - len(active_started)),
            "stuck_monitor_count": sum(
                1
                for started in active_started.values()
                if started < now - timedelta(minutes=5)
            ),
            "oldest_active_monitor": _utc_iso(oldest_started),
            "last_scheduler_exception": _last_scheduler_exception,
            "watchdog_restart_count": _watchdog_restart_count,
            "current_loop_iteration": _current_loop_iteration,
            "worker_uptime_seconds": max(0, int((datetime.utcnow() - started_at).total_seconds())) if started_at else None,
        }


def _scheduler_disappearance_reason(task: asyncio.Task | None) -> str:
    if task is None:
        return "task reference is missing"
    if task.cancelled():
        return "task was cancelled"
    if not task.done():
        return "task is running"
    try:
        exception = task.exception()
    except asyncio.CancelledError:
        return "task was cancelled"
    if exception:
        return f"task failed with {type(exception).__name__}"
    return "task exited without an exception"


def _queue_scheduler_failure_notification(reason: str) -> None:
    try:
        with SessionLocal() as db:
            enqueue_notification(
                db,
                event_type_id="system.background_task.failed",
                title="IP/WAN scheduler failure",
                message="The monitoring scheduler stopped and Kaya initiated recovery.",
                target_route="/system/site-administration/notifications",
                source_entity_type="background_worker",
                source_entity_id="ip_wan_scheduler",
                deduplication_key="system:background-worker:ip-wan-scheduler:failed",
                correlation_id=uuid4().hex,
                metadata={"worker": "ip_wan_scheduler", "reason_code": reason[:80]},
            )
            db.commit()
    except Exception:
        logger.exception("IP/WAN scheduler failure notification could not be queued")


def _create_scheduler_task(reason: str) -> asyncio.Task:
    global _scheduler_task, _scheduler_generation, _current_loop_iteration, _last_scheduler_heartbeat
    _scheduler_generation += 1
    task = asyncio.create_task(
        monitor_loop(), name=f"ip-wan-monitor-scheduler-{_scheduler_generation}"
    )
    with _scheduler_state_guard:
        _scheduler_task = task
        _current_loop_iteration = 0
        _last_scheduler_heartbeat = None
    logger.info("IP/WAN scheduler task created reason=%s task_id=%s", reason, task.get_name())
    return task


def start_monitor_scheduler() -> tuple[asyncio.Task, asyncio.Task]:
    """Start the supervised scheduler and its independently-owned watchdog."""
    global _scheduler_shutdown_requested, _scheduler_watchdog_task, _worker_started_at
    with _scheduler_state_guard:
        scheduler = _scheduler_task if _scheduler_task and not _scheduler_task.done() else None
        watchdog = (
            _scheduler_watchdog_task
            if _scheduler_watchdog_task and not _scheduler_watchdog_task.done()
            else None
        )
        if scheduler and watchdog:
            return scheduler, watchdog
        _scheduler_shutdown_requested = False
        if not _worker_started_at:
            _worker_started_at = datetime.utcnow()
    if not scheduler:
        scheduler = _create_scheduler_task("application startup")
    if not watchdog:
        watchdog = asyncio.create_task(
            monitor_scheduler_watchdog(), name="ip-wan-monitor-watchdog"
        )
        with _scheduler_state_guard:
            _scheduler_watchdog_task = watchdog
    return scheduler, watchdog


def supervise_monitor_scheduler() -> asyncio.Task | None:
    """Recreate a missing scheduler; called by the watchdog every minute."""
    with _scheduler_state_guard:
        task = _scheduler_task
        shutting_down = _scheduler_shutdown_requested
    if shutting_down or (task and not task.done()):
        return None
    global _last_scheduler_exception, _watchdog_restart_count
    reason = _scheduler_disappearance_reason(task)
    _last_scheduler_exception = reason
    _watchdog_restart_count += 1
    _queue_scheduler_failure_notification(reason)
    if task and task.done() and not task.cancelled():
        exception = task.exception()
        if exception:
            logger.error(
                "IP/WAN scheduler disappeared: %s", reason,
                exc_info=(type(exception), exception, exception.__traceback__),
            )
        else:
            logger.error("IP/WAN scheduler disappeared: %s", reason, stack_info=True)
    else:
        logger.error("IP/WAN scheduler disappeared: %s", reason, stack_info=True)
    return _create_scheduler_task(reason)


async def monitor_scheduler_watchdog() -> None:
    logger.info("IP/WAN scheduler watchdog started")
    try:
        while True:
            await asyncio.sleep(WATCHDOG_INTERVAL_SECONDS)
            try:
                with _scheduler_state_guard:
                    task = _scheduler_task
                    heartbeat = _last_scheduler_heartbeat
                    shutting_down = _scheduler_shutdown_requested
                stale = bool(
                    task
                    and not task.done()
                    and heartbeat
                    and heartbeat < datetime.utcnow() - timedelta(seconds=120)
                )
                if stale and not shutting_down:
                    global _last_scheduler_exception, _watchdog_restart_count
                    logger.critical(
                        "IP/WAN scheduler heartbeat stale; watchdog is restarting the scheduler"
                    )
                    _last_scheduler_exception = "stale_heartbeat"
                    _watchdog_restart_count += 1
                    await asyncio.to_thread(
                        _queue_scheduler_failure_notification, "stale_heartbeat"
                    )
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    _create_scheduler_task("stale heartbeat")
                    continue
                supervise_monitor_scheduler()
            except Exception:
                logger.exception("IP/WAN scheduler watchdog exception")
    except asyncio.CancelledError:
        logger.info("IP/WAN scheduler watchdog cancelled")
        raise


async def stop_monitor_scheduler() -> None:
    global _scheduler_shutdown_requested, _scheduler_task, _scheduler_watchdog_task, _worker_started_at
    with _scheduler_state_guard:
        _scheduler_shutdown_requested = True
        scheduler = _scheduler_task
        watchdog = _scheduler_watchdog_task
    for task in (watchdog, scheduler):
        if task and not task.done():
            task.cancel()
    await asyncio.gather(*(task for task in (watchdog, scheduler) if task), return_exceptions=True)
    with _scheduler_state_guard:
        _scheduler_task = None
        _scheduler_watchdog_task = None
        _worker_started_at = None
        _pending_monitor_ids.clear()
        _active_monitor_started_at.clear()


def _reap_finished_monitor_tasks(in_flight: dict[int, asyncio.Task]) -> dict[int, asyncio.Task]:
    for monitor_id, task in list(in_flight.items()):
        if not task.done():
            continue
        if task.cancelled():
            logger.warning("IP/WAN monitor task cancelled monitor_id=%s", monitor_id)
            continue
        try:
            task.result()
        except Exception:
            logger.exception("IP/WAN monitor task failed monitor_id=%s", monitor_id)
    return {monitor_id: task for monitor_id, task in in_flight.items() if not task.done()}


async def _run_monitor_loop() -> None:
    logger.info("IP/WAN scheduler started")
    logger.info("IP/WAN scheduler sleeping seconds=%s reason=startup_delay", STARTUP_DELAY_SECONDS)
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    logger.info("IP/WAN scheduler resumed reason=startup_delay_complete")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    in_flight: dict[int, asyncio.Task] = {}
    next_tick = time.monotonic()
    last_heartbeat = 0.0

    async def checked_monitor(monitor_id: int) -> None:
        try:
            async with semaphore:
                with _scheduler_state_guard:
                    _active_monitor_started_at[monitor_id] = datetime.utcnow()
                completed = await asyncio.to_thread(run_monitor_check_by_id, monitor_id)
                if completed:
                    with _scheduler_state_guard:
                        global _last_monitor_execution
                        _last_monitor_execution = datetime.utcnow()
                logger.info("IP/WAN monitor completed monitor_id=%s executed=%s", monitor_id, completed)
        finally:
            with _scheduler_state_guard:
                _pending_monitor_ids.discard(monitor_id)
                _active_monitor_started_at.pop(monitor_id, None)

    try:
        while True:
            iteration_started = time.monotonic()
            with _scheduler_state_guard:
                global _current_loop_iteration, _last_scheduler_heartbeat
                _current_loop_iteration += 1
                iteration = _current_loop_iteration
                _last_scheduler_heartbeat = datetime.utcnow()
            if iteration_started - last_heartbeat >= SCHEDULER_HEARTBEAT_SECONDS:
                logger.info("IP/WAN scheduler heartbeat iteration=%s pending=%s", iteration, len(in_flight))
                last_heartbeat = iteration_started
            logger.info("IP/WAN scheduler iteration started iteration=%s", iteration)
            in_flight = _reap_finished_monitor_tasks(in_flight)
            db = SessionLocal()
            try:
                monitor_ids = [
                    monitor.id for monitor in fallback_due_monitors(db)
                    if monitor.id not in in_flight
                ]
                with _scheduler_state_guard:
                    global _last_due_scan, _due_monitors_found
                    _last_due_scan = datetime.utcnow()
                    _due_monitors_found = len(monitor_ids)
            except Exception as exc:
                with _scheduler_state_guard:
                    global _last_scheduler_exception
                    _last_scheduler_exception = type(exc).__name__
                logger.exception("IP/WAN scheduler due scan failed")
                monitor_ids = []
            finally:
                db.close()
            for monitor_id in monitor_ids:
                with _scheduler_state_guard:
                    _pending_monitor_ids.add(monitor_id)
                logger.info("IP/WAN monitor queued monitor_id=%s", monitor_id)
                in_flight[monitor_id] = asyncio.create_task(checked_monitor(monitor_id))
            logger.info("IP/WAN scheduler iteration finished iteration=%s queued=%s pending=%s", iteration, len(monitor_ids), len(in_flight))
            next_tick += CHECK_INTERVAL_SECONDS
            sleep_seconds = max(0, next_tick - time.monotonic())
            logger.info("IP/WAN scheduler sleeping seconds=%.3f", sleep_seconds)
            await asyncio.sleep(sleep_seconds)
            logger.info("IP/WAN scheduler resumed")
            if next_tick < time.monotonic() - CHECK_INTERVAL_SECONDS:
                next_tick = time.monotonic()
    finally:
        for task in in_flight.values():
            task.cancel()
        await asyncio.gather(*in_flight.values(), return_exceptions=True)
        with _scheduler_state_guard:
            _pending_monitor_ids.clear()
            _active_monitor_started_at.clear()


async def monitor_loop() -> None:
    try:
        await _run_monitor_loop()
    except asyncio.CancelledError:
        logger.info("IP/WAN scheduler cancelled", stack_info=True)
        raise
    except BaseException:
        logger.exception("IP/WAN scheduler exception")
        raise
    finally:
        logger.info("IP/WAN scheduler exiting", stack_info=True)
