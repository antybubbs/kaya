"""Bounded SNMP polling, rate accounting and traffic scheduler lifecycle."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
import time
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, selectinload

from app.core.security import decrypt_secret
from app.db.session import SessionLocal, database_write_context
from app.models.models import (
    TrafficAggregate,
    TrafficCounterObservation,
    TrafficInterface,
    TrafficMonitoringConfiguration,
    TrafficPollingLease,
    TrafficSource,
)
from app.services.network_traffic_snmp import (
    InterfaceSnapshot,
    SNMPProviderError,
    SNMPv3Provider,
    calculate_counter_rates,
)

logger = logging.getLogger(__name__)
MAX_CONCURRENT_SOURCES = 4
LEASE_SECONDS = 90
HEARTBEAT_SECONDS = 20
STALE_MULTIPLIER = 3
_scheduler_task: asyncio.Task | None = None
_scheduler_shutdown = False
_scheduler_lock = threading.Lock()
_source_locks: dict[int, asyncio.Lock] = {}
_source_locks_guard = threading.Lock()
_lease_token: str | None = None
_diagnostics = {
    "state": "stopped", "started_at": None, "last_cycle_at": None,
    "last_error": None, "owner": False, "sources_polled": 0,
}


def _now() -> datetime:
    return datetime.utcnow()


def _source_lock(source_id: int) -> asyncio.Lock:
    with _source_locks_guard:
        return _source_locks.setdefault(source_id, asyncio.Lock())


def _bucket(value: datetime, seconds: int) -> datetime:
    epoch = int(value.timestamp())
    return datetime.utcfromtimestamp(epoch - epoch % seconds)


def _observation_key(source_id: int, interface_id: int, observed_at: datetime, snapshot: InterfaceSnapshot) -> str:
    raw = f"{source_id}:{interface_id}:{observed_at.isoformat()}:{snapshot.inbound_octets}:{snapshot.outbound_octets}:{snapshot.device_uptime_ticks}:{snapshot.discontinuity_ticks}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _upsert_aggregate_piece(db: Session, source_id: int, interface_id: int, bucket_start: datetime, seconds: int, direction: str, byte_count: int, observed_at: datetime, sample_count: int = 1) -> None:
    values = {
        "source_id": source_id,
        "interface_id": interface_id,
        "bucket_start": bucket_start,
        "bucket_seconds": seconds,
        "direction": direction,
        "traffic_class": "interface_total",
        "bytes_total": max(0, byte_count),
        "sample_count": sample_count,
        "is_approximate": True,
        "first_observed_at": observed_at,
        "last_observed_at": observed_at,
    }
    dialect = db.bind.dialect.name if db.bind is not None else ""
    if dialect == "postgresql":
        statement = postgresql_insert(TrafficAggregate).values(**values)
    elif dialect == "sqlite":
        statement = sqlite_insert(TrafficAggregate).values(**values)
    else:
        row = db.query(TrafficAggregate).filter_by(
            source_id=source_id, interface_id=interface_id, bucket_start=bucket_start,
            bucket_seconds=seconds, direction=direction, traffic_class="interface_total",
        ).first()
        if row is None:
            row = TrafficAggregate(**values)
            db.add(row)
        else:
            row.bytes_total = (row.bytes_total or 0) + max(0, byte_count)
            row.sample_count = (row.sample_count or 0) + sample_count
            row.is_approximate = True
            row.first_observed_at = min((row.first_observed_at or observed_at), observed_at)
            row.last_observed_at = max((row.last_observed_at or observed_at), observed_at)
        return

    excluded = statement.excluded
    statement = statement.on_conflict_do_update(
        index_elements=[
            "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction", "traffic_class",
        ],
        set_={
            "bytes_total": func.coalesce(TrafficAggregate.bytes_total, 0) + excluded.bytes_total,
            "sample_count": func.coalesce(TrafficAggregate.sample_count, 0) + excluded.sample_count,
            "is_approximate": True,
            "first_observed_at": case(
                (TrafficAggregate.first_observed_at.is_(None), excluded.first_observed_at),
                (excluded.first_observed_at < TrafficAggregate.first_observed_at, excluded.first_observed_at),
                else_=TrafficAggregate.first_observed_at,
            ),
            "last_observed_at": case(
                (TrafficAggregate.last_observed_at.is_(None), excluded.last_observed_at),
                (excluded.last_observed_at > TrafficAggregate.last_observed_at, excluded.last_observed_at),
                else_=TrafficAggregate.last_observed_at,
            ),
        },
    )
    db.execute(statement)


def _upsert_aggregate(db: Session, source_id: int, interface_id: int, observed_at: datetime, seconds: int, direction: str, value_bps: int, elapsed_seconds: float) -> None:
    """Persist a constant-rate approximation split across every UTC bucket touched.

    SNMP counters provide a delta, not packet timestamps. Proportional allocation
    across the elapsed interval avoids assigning a whole delta to the ending
    bucket while explicitly marking the resulting aggregate approximate.
    """
    elapsed_seconds = float(elapsed_seconds)
    if elapsed_seconds <= 0 or value_bps < 0:
        return
    start = observed_at - timedelta(seconds=elapsed_seconds)
    total_bytes = max(0, int(round(value_bps * elapsed_seconds / 8)))
    remaining_bytes = total_bytes
    remaining_seconds = elapsed_seconds
    cursor = start
    while cursor < observed_at:
        bucket_start = _bucket(cursor, seconds)
        bucket_end = bucket_start + timedelta(seconds=seconds)
        overlap_end = min(bucket_end, observed_at)
        overlap = max(0.0, (overlap_end - cursor).total_seconds())
        if overlap <= 0:
            break
        if overlap_end >= observed_at:
            piece_bytes = remaining_bytes
        else:
            piece_bytes = int(round(total_bytes * overlap / elapsed_seconds))
            piece_bytes = min(remaining_bytes, max(0, piece_bytes))
        _upsert_aggregate_piece(db, source_id, interface_id, bucket_start, seconds, direction, piece_bytes, observed_at)
        remaining_bytes -= piece_bytes
        remaining_seconds -= overlap
        cursor = overlap_end


def _record_failure(db: Session, source: TrafficSource, error: SNMPProviderError, now: datetime) -> None:
    source.last_failed_at = now
    source.last_error_category = error.category
    source.consecutive_failures += 1
    backoff_seconds = min(900, 5 * (2 ** min(source.consecutive_failures - 1, 7)))
    source.backoff_until = now + timedelta(seconds=backoff_seconds)
    source.health_state = "error" if error.category in {"authentication_failure", "configuration_error"} else "degraded"
    source.health_reason = "SNMP polling failed"


def _record_success(source: TrafficSource, now: datetime, duration_ms: int, snapshots: list[InterfaceSnapshot]) -> None:
    source.last_success_at = now
    source.last_received_at = now
    source.last_poll_duration_ms = duration_ms
    source.last_error_category = None
    source.consecutive_failures = 0
    source.backoff_until = None
    source.health_state = "healthy" if snapshots else "degraded"
    source.health_reason = None if snapshots else "No interfaces returned by the device"


def persist_discovered_interfaces(db: Session, source: TrafficSource, snapshots: list[InterfaceSnapshot]) -> list[TrafficInterface]:
    rows = []
    for snapshot in snapshots:
        row = db.query(TrafficInterface).filter_by(source_id=source.id, interface_key=snapshot.interface_key).first()
        if row is None:
            row = TrafficInterface(source_id=source.id, interface_key=snapshot.interface_key, interface_index=snapshot.interface_index, display_name=snapshot.display_name, description=snapshot.description, admin_status=snapshot.admin_status, oper_status=snapshot.oper_status, speed_bps=snapshot.speed_bps, is_enabled=True, last_discovered_at=_now())
            db.add(row)
        else:
            row.interface_index = snapshot.interface_index
            row.display_name = snapshot.display_name
            row.description = snapshot.description
            row.admin_status = snapshot.admin_status
            row.oper_status = snapshot.oper_status
            row.speed_bps = snapshot.speed_bps
            row.last_discovered_at = _now()
        rows.append(row)
    db.flush()
    return rows


async def discover_source_interfaces(db: Session, source: TrafficSource, *, provider: SNMPv3Provider | None = None) -> list[InterfaceSnapshot]:
    provider = provider or SNMPv3Provider(timeout_seconds=min(30, max(1, source.polling_interval_seconds // 2)))
    snapshots = await asyncio.wait_for(provider.discover_interfaces(source), timeout=min(30, max(2, source.polling_interval_seconds // 2)))
    persist_discovered_interfaces(db, source, snapshots)
    return snapshots


def _lease_is_owned(db: Session, token: str | None, now: datetime, *, lock: bool = False) -> bool:
    if not token:
        return True
    query = db.query(TrafficPollingLease).filter_by(id=1)
    if lock:
        query = query.with_for_update()
    row = query.first()
    return bool(row and row.owner_token == token and row.lease_until and row.lease_until > now)


def _poll_is_authorized(db: Session, source_id: int, lease_token: str | None, now: datetime, *, fence: bool = False):
    source_query = db.query(TrafficSource).options(selectinload(TrafficSource.interfaces)).filter(TrafficSource.id == source_id, TrafficSource.is_deleted.is_(False))
    config_query = db.query(TrafficMonitoringConfiguration).filter_by(id=1)
    if fence:
        source_query = source_query.with_for_update()
        config_query = config_query.with_for_update()
    source = source_query.first()
    config = config_query.first()
    if not source or not source.is_enabled or not config or not config.is_enabled or not _lease_is_owned(db, lease_token, now, lock=fence):
        return None
    return source


async def poll_source_once(db_factory=SessionLocal, source_id: int | None = None, *, provider: SNMPv3Provider | None = None, now: datetime | None = None, lease_token: str | None = None) -> bool:
    """Poll one source and commit observations atomically, with no HTTP dependency."""
    now = now or _now()
    db = db_factory()
    started = time.monotonic()
    try:
        source = _poll_is_authorized(db, source_id, lease_token, now)
        if not source:
            return False
        if source.backoff_until and source.backoff_until > now:
            return False
        provider = provider or SNMPv3Provider(timeout_seconds=min(30, max(1, source.polling_interval_seconds // 2)))
        lock = _source_lock(source.id)
        if lock.locked():
            return False
        async with lock:
            try:
                snapshots = await asyncio.wait_for(provider.discover_interfaces(source), timeout=min(30, max(2, source.polling_interval_seconds // 2)))
            except SNMPProviderError as exc:
                if not _poll_is_authorized(db, source.id, lease_token, _now(), fence=True):
                    db.rollback()
                    return False
                _record_failure(db, source, exc, now)
                source.last_poll_duration_ms = int((time.monotonic() - started) * 1000)
                db.commit()
                return False
            elapsed_default = max(1.0, source.polling_interval_seconds)
            for snapshot in snapshots:
                interface = next((row for row in source.interfaces if row.interface_key == snapshot.interface_key), None)
                if interface is None:
                    interface = TrafficInterface(source_id=source.id, interface_key=snapshot.interface_key, interface_index=snapshot.interface_index, display_name=snapshot.display_name, description=snapshot.description, admin_status=snapshot.admin_status, oper_status=snapshot.oper_status, speed_bps=snapshot.speed_bps, is_enabled=True, last_discovered_at=now)
                    db.add(interface)
                    db.flush()
                    source.interfaces.append(interface)
                else:
                    interface.interface_index = snapshot.interface_index
                    interface.display_name = snapshot.display_name
                    interface.description = snapshot.description
                    interface.admin_status = snapshot.admin_status
                    interface.oper_status = snapshot.oper_status
                    interface.speed_bps = snapshot.speed_bps
                    interface.last_discovered_at = now
                if not interface.is_enabled:
                    continue
                previous = db.query(TrafficCounterObservation).filter_by(interface_id=interface.id).order_by(TrafficCounterObservation.observed_at.desc()).first()
                previous_snapshot = InterfaceSnapshot(snapshot.interface_index, snapshot.interface_key, snapshot.display_name, snapshot.description, snapshot.oper_status, snapshot.admin_status, snapshot.speed_bps, previous.inbound_counter if previous else None, previous.outbound_counter if previous else None, previous.counter_bits if previous else snapshot.counter_bits, None, int(previous.exporter_epoch) if previous and previous.exporter_epoch and previous.exporter_epoch.isdigit() else None)
                if previous:
                    previous_snapshot = InterfaceSnapshot(snapshot.interface_index, snapshot.interface_key, snapshot.display_name, snapshot.description, snapshot.oper_status, snapshot.admin_status, snapshot.speed_bps, previous.inbound_counter, previous.outbound_counter, previous.counter_bits, previous.discontinuity_ticks, int(previous.exporter_epoch) if previous.exporter_epoch and previous.exporter_epoch.isdigit() else None)
                elapsed = (now - previous.observed_at).total_seconds() if previous else elapsed_default
                inbound, outbound = calculate_counter_rates(previous_snapshot if previous else None, snapshot, elapsed)
                key = _observation_key(source.id, interface.id, now, snapshot)
                if db.query(TrafficCounterObservation.id).filter_by(observation_key=key).first():
                    continue
                db.add(TrafficCounterObservation(source_id=source.id, interface_id=interface.id, observation_key=key, observed_at=now, inbound_counter=snapshot.inbound_octets, outbound_counter=snapshot.outbound_octets, counter_bits=snapshot.counter_bits, reset_detected=inbound.reset or outbound.reset, exporter_epoch=str(snapshot.device_uptime_ticks) if snapshot.device_uptime_ticks is not None else None, discontinuity_ticks=snapshot.discontinuity_ticks, inbound_bps=inbound.bits_per_second, outbound_bps=outbound.bits_per_second))
                if inbound.bits_per_second is not None:
                    source.last_rate_in_bps = inbound.bits_per_second
                    source.last_counter_observation_at = now
                    for seconds in (300, 3600, 86400):
                        _upsert_aggregate(db, source.id, interface.id, now, seconds, interface.inbound_direction, inbound.bits_per_second, elapsed)
                if outbound.bits_per_second is not None:
                    source.last_rate_out_bps = outbound.bits_per_second
                    source.last_counter_observation_at = now
                    for seconds in (300, 3600, 86400):
                        _upsert_aggregate(db, source.id, interface.id, now, seconds, interface.outbound_direction, outbound.bits_per_second, elapsed)
            if not _poll_is_authorized(db, source.id, lease_token, _now(), fence=True):
                db.rollback()
                return False
            _record_success(source, now, int((time.monotonic() - started) * 1000), snapshots)
            db.commit()
            return True
    finally:
        db.close()


def acquire_polling_lease(db: Session, token: str, now: datetime | None = None) -> bool:
    now = now or _now()
    row = db.query(TrafficPollingLease).with_for_update().filter_by(id=1).first()
    if row is None:
        row = TrafficPollingLease(id=1)
        db.add(row)
        db.flush()
    if row.owner_token and row.owner_token != token and row.lease_until and row.lease_until > now:
        return False
    row.owner_token = token
    row.lease_until = now + timedelta(seconds=LEASE_SECONDS)
    row.heartbeat_at = now
    db.commit()
    return True


def renew_polling_lease(db: Session, token: str, now: datetime | None = None) -> bool:
    now = now or _now()
    row = db.query(TrafficPollingLease).with_for_update().filter_by(id=1, owner_token=token).first()
    if not row or not row.lease_until or row.lease_until <= now:
        db.rollback()
        return False
    row.lease_until = now + timedelta(seconds=LEASE_SECONDS)
    row.heartbeat_at = now
    db.commit()
    return True


def release_polling_lease(db: Session, token: str) -> None:
    row = db.query(TrafficPollingLease).filter_by(id=1, owner_token=token).first()
    if row:
        row.owner_token = None
        row.lease_until = None
        row.heartbeat_at = _now()
        db.commit()


def polling_diagnostics() -> dict:
    return dict(_diagnostics)


async def traffic_polling_loop() -> None:
    global _lease_token
    _lease_token = uuid4().hex
    _diagnostics.update(state="starting", started_at=_now().isoformat() + "Z", owner=False)
    due: dict[int, float] = {}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_SOURCES)
    try:
        while not _scheduler_shutdown:
            db = SessionLocal()
            try:
                config = db.get(TrafficMonitoringConfiguration, 1)
                if not config or not config.is_enabled:
                    _diagnostics.update(state="disabled", owner=False)
                    await asyncio.sleep(5)
                    continue
                owner = acquire_polling_lease(db, _lease_token)
                _diagnostics["owner"] = owner
                if not owner:
                    _diagnostics["state"] = "standby"
                    await asyncio.sleep(5)
                    continue
                _diagnostics["state"] = "running"
                sources = db.query(TrafficSource).filter(TrafficSource.is_deleted.is_(False), TrafficSource.is_enabled.is_(True)).all()
                now_mono = time.monotonic()
                jobs = [source.id for source in sources if now_mono >= due.get(source.id, 0)]
                for source in sources:
                    due.setdefault(source.id, now_mono)
                db.close()

                async def run(source_id: int) -> None:
                    async with semaphore:
                        success = await poll_source_once(SessionLocal, source_id, lease_token=_lease_token)
                        source_db = SessionLocal()
                        try:
                            source = source_db.get(TrafficSource, source_id)
                            due[source_id] = time.monotonic() + (source.polling_interval_seconds if source else 60)
                            if success:
                                _diagnostics["sources_polled"] += 1
                        finally:
                            source_db.close()

                await asyncio.gather(*(run(source_id) for source_id in jobs))
                _diagnostics["last_cycle_at"] = _now().isoformat() + "Z"
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _diagnostics["last_error"] = type(exc).__name__
                logger.exception("traffic.polling.cycle_failed")
                await asyncio.sleep(5)
            finally:
                if db.is_active:
                    db.close()
            await asyncio.sleep(1)
    finally:
        db = SessionLocal()
        try:
            if _lease_token:
                release_polling_lease(db, _lease_token)
        finally:
            db.close()
        _diagnostics.update(state="stopped", owner=False)
        _lease_token = None


def start_traffic_polling() -> asyncio.Task | None:
    global _scheduler_task, _scheduler_shutdown
    with _scheduler_lock:
        if _scheduler_task and not _scheduler_task.done():
            return _scheduler_task
        _scheduler_shutdown = False
        _scheduler_task = asyncio.create_task(traffic_polling_loop(), name="network-traffic-polling")
        return _scheduler_task


async def stop_traffic_polling() -> None:
    global _scheduler_task, _scheduler_shutdown
    with _scheduler_lock:
        _scheduler_shutdown = True
        task = _scheduler_task
        _scheduler_task = None
    if task:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
