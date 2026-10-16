"""Standalone, bounded UDP flow collector for NetFlow v9 and Cisco NSEL."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import signal
import socket
import threading
import time
from datetime import datetime, timedelta
from ipaddress import ip_address

from sqlalchemy import case, or_
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.db.session import SessionLocal
from app.models.models import (
    TrafficFlowAggregate,
    TrafficFlowAccountingAggregate,
    TrafficFlowCollectorState,
    TrafficFlowCollectorGlobalState,
    TrafficFlowCounterState,
    TrafficFlowDeduplication,
    TrafficMonitoringConfiguration,
    TrafficSource,
    TrafficLocalNetwork,
)
from app.services.flow_protocol import FlowDecodeError, MAX_DATAGRAM_SIZE, NetFlowV9Decoder, NormalizedFlowRecord
from app.services.network_discovery import DiscoveryRuntime, MAX_RECORD_BATCH
from app.services.flow_accounting import classify_flow, resolve_flow_attribution
from app.services.device_traffic import persist_device_traffic
from app.services.endpoint_traffic import EndpointUsageBatch

logger = logging.getLogger("kaya.flow_collector")
MAX_QUEUE_SIZE = 10000
MAX_WORKERS = 16
MAX_PACKET_RATE = 10000
STATE_REFRESH_SECONDS = 5
DEDUP_RETENTION = timedelta(hours=48)
COUNTER_RETENTION = timedelta(days=2)


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(int(os.environ.get(name, default)), maximum))
    except (TypeError, ValueError):
        return default


def collector_settings() -> dict:
    bind = os.environ.get("KAYA_FLOW_COLLECTOR_BIND_ADDRESS", "127.0.0.1").strip()
    try:
        ip_address(bind)
    except ValueError as exc:
        raise RuntimeError("KAYA_FLOW_COLLECTOR_BIND_ADDRESS must be a literal IP address") from exc
    return {
        "enabled": _env_bool("KAYA_FLOW_COLLECTOR_ENABLED"),
        "bind_address": bind,
        "port": _env_int("KAYA_FLOW_COLLECTOR_PORT", 2055, 1024, 65535),
        "queue_size": _env_int("KAYA_FLOW_COLLECTOR_QUEUE_SIZE", 2048, 1, MAX_QUEUE_SIZE),
        "workers": _env_int("KAYA_FLOW_COLLECTOR_WORKERS", 2, 1, MAX_WORKERS),
        "max_packets_per_second": _env_int("KAYA_FLOW_COLLECTOR_MAX_PACKETS_PER_SECOND", 1000, 1, MAX_PACKET_RATE),
    }


def _now() -> datetime:
    return datetime.utcnow()


def _bucket(value: datetime, seconds: int = 300) -> datetime:
    epoch = int(value.timestamp())
    return datetime.utcfromtimestamp(epoch - epoch % seconds)


def _state(db, source_id: int) -> TrafficFlowCollectorState:
    row = db.query(TrafficFlowCollectorState).filter_by(source_id=source_id).first()
    if row is None:
        row = TrafficFlowCollectorState(source_id=source_id)
        db.add(row)
        db.flush()
    return row


def _global_state(db) -> TrafficFlowCollectorGlobalState:
    row = db.get(TrafficFlowCollectorGlobalState, 1)
    if row is None:
        row = TrafficFlowCollectorGlobalState(id=1)
        db.add(row)
        db.flush()
    return row


def _append_template_lifecycle(state: TrafficFlowCollectorState, events: list[dict], now: datetime) -> None:
    """Keep only a small, redacted recent template lifecycle window."""
    try:
        history = json.loads(state.template_lifecycle_json or "[]")
    except (TypeError, ValueError):
        history = []
    if not isinstance(history, list):
        history = []
    for event in events:
        # Decoder events contain only bounded identifiers and state labels.
        item = {key: event[key] for key in ("exporter_identity", "source_id", "template_id", "status", "reason", "cache_present") if key in event}
        item["at"] = now.isoformat() + "Z"
        history.append(item)
    state.template_lifecycle_json = json.dumps(history[-32:], separators=(",", ":"))


def _update_template_lifecycle_summary(state: TrafficFlowCollectorState, events: list[dict], now: datetime) -> None:
    """Aggregate recent lifecycle events by bounded exporter/source/template/category keys."""
    try:
        summaries = json.loads(state.template_lifecycle_summary_json or "{}")
    except (TypeError, ValueError):
        summaries = {}
    if not isinstance(summaries, dict):
        summaries = {}
    observed_at = now.isoformat() + "Z"
    for event in events:
        exporter = str(event.get("exporter_identity", ""))[:45]
        source_id = int(event.get("source_id", 0))
        template_id = int(event.get("template_id", 0))
        category = str(event.get("status", "unknown"))[:24]
        reason = str(event.get("reason", "unknown"))[:32]
        key = f"{exporter}|{source_id}|{template_id}|{category}|{reason}"
        item = summaries.get(key)
        if not isinstance(item, dict):
            item = {
                "exporter_identity": exporter,
                "source_id": source_id,
                "template_id": template_id,
                "category": category,
                "reason": reason,
                "event_count": 0,
                "first_observed_at": observed_at,
            }
        item["event_count"] = min(int(item.get("event_count", 0)) + 1, 2_147_483_647)
        item["last_observed_at"] = observed_at
        item["current_cache_presence"] = bool(event.get("cache_present", False))
        if category == "accepted":
            item["last_accepted_at"] = observed_at
        if category == "rejected":
            item["last_rejected_at"] = observed_at
            item["last_rejection_reason"] = reason
        summaries[key] = item
    if len(summaries) > 64:
        ordered = sorted(summaries.items(), key=lambda pair: str(pair[1].get("last_observed_at", "")), reverse=True)[:64]
        summaries = dict(ordered)
    state.template_lifecycle_summary_json = json.dumps(summaries, separators=(",", ":"))


def _allowlisted_sources(db, port: int) -> dict[str, list[TrafficSource]]:
    configuration = db.get(TrafficMonitoringConfiguration, 1)
    if configuration is not None and not configuration.is_enabled:
        return {}
    result: dict[str, list[TrafficSource]] = {}
    rows = db.query(TrafficSource).filter(
        TrafficSource.is_deleted.is_(False), TrafficSource.is_enabled.is_(True),
        TrafficSource.provider_key.in_(["netflow_v9", "cisco_nsel"]), TrafficSource.collector_port == port,
    ).all()
    for source in rows:
        try:
            allowlist = json.loads(source.exporter_allowlist_json or "[]")
        except (TypeError, ValueError):
            allowlist = []
        for exporter in allowlist[:128]:
            result.setdefault(str(exporter), []).append(source)
    return result


def _flow_ingestion_enabled(db) -> bool:
    configuration = db.get(TrafficMonitoringConfiguration, 1)
    return configuration is None or bool(configuration.is_enabled)


def _event_key(record: NormalizedFlowRecord, source_id: int | None = None) -> str:
    raw = "|".join(str(value) for value in (
        source_id if source_id is not None else record.source_id, record.exporter_identity, record.sequence, record.record_index,
        record.connection_id, record.event_type, record.observed_at.isoformat(), record.bytes_total, record.packets_total,
    ))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _conflict_insert(db, table):
    if db.bind.dialect.name == "postgresql":
        return postgres_insert(table)
    if db.bind.dialect.name == "sqlite":
        return sqlite_insert(table)
    return None


def _aggregate(db, record: NormalizedFlowRecord, byte_count: int, packet_count: int, quality: str, source_id: int) -> None:
    if byte_count <= 0 and packet_count <= 0:
        return
    bucket_start = _bucket(record.observed_at)
    values = {
        "source_id": source_id, "exporter_identity": record.exporter_identity,
        "bucket_start": bucket_start, "bucket_seconds": 300,
        "direction": record.direction, "traffic_class": "flow_total",
        "bytes_total": byte_count, "packets_total": packet_count, "sample_count": 1,
        "data_quality": quality, "first_observed_at": record.observed_at,
        "last_observed_at": record.observed_at,
    }
    statement = _conflict_insert(db, TrafficFlowAggregate.__table__)
    if statement is not None:
        excluded = statement.excluded
        table = TrafficFlowAggregate.__table__
        statement = statement.values(**values).on_conflict_do_update(
            index_elements=["source_id", "exporter_identity", "bucket_start", "bucket_seconds", "direction", "traffic_class"],
            set_={
                "bytes_total": table.c.bytes_total + excluded.bytes_total,
                "packets_total": table.c.packets_total + excluded.packets_total,
                "sample_count": table.c.sample_count + excluded.sample_count,
                "data_quality": case(
                    (or_(table.c.data_quality == "partial", excluded.data_quality == "partial"), "partial"),
                    else_="complete",
                ),
                "first_observed_at": case(
                    (table.c.first_observed_at > excluded.first_observed_at, excluded.first_observed_at),
                    else_=table.c.first_observed_at,
                ),
                "last_observed_at": case(
                    (table.c.last_observed_at < excluded.last_observed_at, excluded.last_observed_at),
                    else_=table.c.last_observed_at,
                ),
            },
        )
        db.execute(statement)
        return
    row = db.query(TrafficFlowAggregate).filter_by(**{
        "source_id": source_id, "exporter_identity": record.exporter_identity,
        "bucket_start": bucket_start, "bucket_seconds": 300,
        "direction": record.direction, "traffic_class": "flow_total",
    }).first()
    if row is None:
        db.add(TrafficFlowAggregate(**values))
        return
    row.bytes_total = (row.bytes_total or 0) + byte_count
    row.packets_total = (row.packets_total or 0) + packet_count
    row.sample_count = (row.sample_count or 0) + 1
    row.data_quality = "partial" if "partial" in {row.data_quality, quality} else "complete"
    row.first_observed_at = min(row.first_observed_at or record.observed_at, record.observed_at)
    row.last_observed_at = max(row.last_observed_at or record.observed_at, record.observed_at)


def _accounting_aggregate(db, record: NormalizedFlowRecord, byte_count: int, packet_count: int, quality: str, source_id: int) -> None:
    """Write classified short/hourly/daily rollups without changing legacy totals."""
    source = db.get(TrafficSource, source_id)
    if source is None:
        return
    interfaces = source.interfaces
    networks = [row.network_cidr for row in db.query(TrafficLocalNetwork).filter(TrafficLocalNetwork.is_enabled.is_(True)).limit(256).all()]
    classification = classify_flow(record, interfaces=interfaces, local_networks=networks)
    attribution = resolve_flow_attribution(db, record)
    for bucket_seconds in (300, 3600, 86400):
        bucket_start = _bucket(record.observed_at, bucket_seconds)
        values = {
            "source_id": source_id, "exporter_identity": record.exporter_identity,
            "bucket_start": bucket_start, "bucket_seconds": bucket_seconds,
            "traffic_class": classification.traffic_class,
            "bytes_total": byte_count, "packets_total": packet_count, "sample_count": 1,
            "data_quality": quality, "classification_confidence": classification.confidence,
            "attribution_state": attribution.state, "unresolved_reason": attribution.unresolved_reason,
            "first_observed_at": record.observed_at, "last_observed_at": record.observed_at,
        }
        statement = _conflict_insert(db, TrafficFlowAccountingAggregate.__table__)
        if statement is not None:
            excluded = statement.excluded
            table = TrafficFlowAccountingAggregate.__table__
            statement = statement.values(**values).on_conflict_do_update(
                index_elements=["source_id", "exporter_identity", "bucket_start", "bucket_seconds", "traffic_class"],
                set_={
                    "bytes_total": table.c.bytes_total + excluded.bytes_total,
                    "packets_total": table.c.packets_total + excluded.packets_total,
                    "sample_count": table.c.sample_count + excluded.sample_count,
                    "data_quality": case((or_(table.c.data_quality == "partial", excluded.data_quality == "partial"), "partial"), else_=table.c.data_quality),
                    "classification_confidence": case(
                        (table.c.classification_confidence == excluded.classification_confidence, table.c.classification_confidence),
                        (table.c.classification_confidence == "unknown", excluded.classification_confidence),
                        else_="mixed",
                    ),
                    "attribution_state": case(
                        (table.c.attribution_state == excluded.attribution_state, table.c.attribution_state),
                        (table.c.attribution_state == "unknown", excluded.attribution_state),
                        else_="mixed",
                    ),
                    "unresolved_reason": case(
                        (table.c.unresolved_reason.is_(None), excluded.unresolved_reason),
                        (table.c.unresolved_reason == excluded.unresolved_reason, table.c.unresolved_reason),
                        else_="mixed",
                    ),
                    "first_observed_at": case((table.c.first_observed_at > excluded.first_observed_at, excluded.first_observed_at), else_=table.c.first_observed_at),
                    "last_observed_at": case((table.c.last_observed_at < excluded.last_observed_at, excluded.last_observed_at), else_=table.c.last_observed_at),
                },
            )
            db.execute(statement)
        else:
            row = db.query(TrafficFlowAccountingAggregate).filter_by(**{
                "source_id": source_id, "exporter_identity": record.exporter_identity,
                "bucket_start": bucket_start, "bucket_seconds": bucket_seconds,
                "traffic_class": classification.traffic_class,
            }).first()
            if row is None:
                db.add(TrafficFlowAccountingAggregate(**values))
            else:
                row.bytes_total += byte_count; row.packets_total += packet_count; row.sample_count += 1
                row.data_quality = "partial" if "partial" in {row.data_quality, quality} else row.data_quality


def _claim_event(db, source_id: int, event_key: str, now: datetime) -> bool:
    statement = _conflict_insert(db, TrafficFlowDeduplication.__table__)
    values = {"source_id": source_id, "event_key": event_key, "processed_at": now, "expires_at": now + DEDUP_RETENTION}
    if statement is not None:
        statement = statement.values(**values).on_conflict_do_nothing(
            index_elements=["event_key"]
        ).returning(TrafficFlowDeduplication.event_key)
        # RETURNING is unambiguous across PostgreSQL drivers: a newly
        # inserted key returns one row, while ON CONFLICT returns none.
        return db.execute(statement).first() is not None
    if db.query(TrafficFlowDeduplication.id).filter_by(event_key=event_key).first():
        return False
    db.add(TrafficFlowDeduplication(**values))
    return True


def process_records(
    db,
    records: list[NormalizedFlowRecord],
    *,
    source_id: int | None = None,
    packet_count: int = 1,
    accepted_records: list[NormalizedFlowRecord] | None = None,
) -> dict:
    """Persist one bounded packet batch idempotently and without raw payloads."""
    counters = {"accepted": 0, "duplicates": 0, "out_of_order": 0, "aggregates": 0}
    now = _now()
    endpoint_usage = EndpointUsageBatch(db)
    for record in records:
        effective_source_id = source_id if source_id is not None else record.source_id
        state = _state(db, effective_source_id)
        key = _event_key(record, effective_source_id)
        if not _claim_event(db, effective_source_id, key, now):
            state.duplicate_events += 1
            counters["duplicates"] += 1
            continue
        byte_count = int(record.bytes_total or 0)
        packet_count_value = int(record.packets_total or 0)
        quality = record.data_quality
        if record.cumulative_counters and record.connection_id and record.bytes_total is not None:
            counter = db.query(TrafficFlowCounterState).filter_by(
                source_id=effective_source_id, exporter_identity=record.exporter_identity,
                connection_id=record.connection_id,
            ).with_for_update().first()
            if counter and counter.last_event_at and record.observed_at < counter.last_event_at:
                state.out_of_order_events += 1
                counters["out_of_order"] += 1
                continue
            if counter and counter.last_bytes is not None:
                if byte_count >= counter.last_bytes:
                    byte_count -= counter.last_bytes
                else:
                    byte_count = byte_count
                    quality = "partial"
            if counter and counter.last_packets is not None and record.packets_total is not None:
                if int(record.packets_total) >= int(counter.last_packets):
                    packet_count_value = int(record.packets_total) - int(counter.last_packets)
                else:
                    quality = "partial"
            else:
                quality = "partial" if record.event_type not in {"create", None} else quality
            if counter is None:
                counter = TrafficFlowCounterState(
                    source_id=effective_source_id, exporter_identity=record.exporter_identity,
                    connection_id=record.connection_id, expires_at=now + COUNTER_RETENTION,
                )
                db.add(counter)
            counter.last_event_at = record.observed_at
            counter.last_bytes = int(record.bytes_total)
            counter.last_packets = record.packets_total
            counter.last_event_type = record.event_type
            counter.expires_at = now + COUNTER_RETENTION
        _aggregate(db, record, max(0, byte_count), max(0, packet_count_value), quality, effective_source_id)
        _accounting_aggregate(db, record, max(0, byte_count), max(0, packet_count_value), quality, effective_source_id)
        persist_device_traffic(db, record, max(0, byte_count), max(0, packet_count_value), effective_source_id)
        # Automatic observed-endpoint usage: after replay protection and counter
        # deltas, so each accepted flow contributes exactly once.
        endpoint_usage.add(record, max(0, byte_count), max(0, packet_count_value), quality, effective_source_id)
        state.last_valid_flow_at = record.observed_at
        state.last_aggregate_write_at = now
        state.packets_accepted += 1
        counters["accepted"] += 1
        counters["aggregates"] += 1
        if accepted_records is not None and len(accepted_records) < MAX_RECORD_BATCH:
            accepted_records.append(record)
    endpoint_usage.flush()
    db.query(TrafficFlowDeduplication).filter(TrafficFlowDeduplication.expires_at < now).delete(synchronize_session=False)
    db.query(TrafficFlowCounterState).filter(TrafficFlowCounterState.expires_at < now).delete(synchronize_session=False)
    return counters


class FlowCollector:
    def __init__(self, settings: dict | None = None):
        self.settings = settings or collector_settings()
        self.queue: queue.Queue[tuple[int, int, str, bytes]] = queue.Queue(maxsize=self.settings["queue_size"])
        self.stop_event = threading.Event()
        self.socket: socket.socket | None = None
        self.receiver: threading.Thread | None = None
        self.workers: list[threading.Thread] = []
        self.decoder = NetFlowV9Decoder()
        self._source_cache: dict[str, list[TrafficSource]] = {}
        self._source_cache_at = 0.0
        self._last_heartbeat = 0.0
        self._rate_lock = threading.Lock()
        self._rate_window = 0
        self._rate_count = 0
        self._write_lock = threading.Lock()
        self._decode_condition = threading.Condition()
        self._next_packet_ordinal = 0
        self._next_decode_ordinal = 0
        self.discovery = DiscoveryRuntime(SessionLocal)

    def _refresh_sources(self) -> None:
        if time.monotonic() - self._source_cache_at < STATE_REFRESH_SECONDS:
            return
        with SessionLocal() as db:
            self._source_cache = _allowlisted_sources(db, self.settings["port"])
        self._source_cache_at = time.monotonic()

    def _rate_allowed(self) -> bool:
        with self._rate_lock:
            now = int(time.monotonic())
            if now != self._rate_window:
                self._rate_window, self._rate_count = now, 0
            if self._rate_count >= self.settings["max_packets_per_second"]:
                return False
            self._rate_count += 1
            return True

    def _record_packet_state(self, source_id: int, *, increments: dict[str, int] | None = None, **values) -> None:
        with SessionLocal() as db:
            state = _state(db, source_id)
            for key, value in values.items():
                setattr(state, key, value)
            for key, value in (increments or {}).items():
                setattr(state, key, int(getattr(state, key) or 0) + int(value))
            error_category = values.get("last_error_category")
            if error_category:
                event = {
                    "source_id": source_id,
                    "template_id": 0,
                    "status": "error",
                    "reason": str(error_category),
                    "cache_present": False,
                }
                now = _now()
                _append_template_lifecycle(state, [event], now)
                _update_template_lifecycle_summary(state, [event], now)
            db.commit()

    def _record_global(self, *, increments: dict[str, int] | None = None, **values) -> None:
        with SessionLocal() as db:
            state = _global_state(db)
            for key, value in values.items():
                setattr(state, key, value)
            for key, value in (increments or {}).items():
                setattr(state, key, int(getattr(state, key) or 0) + int(value))
            db.commit()

    def _receive_loop(self) -> None:
        assert self.socket is not None
        while not self.stop_event.is_set():
            try:
                packet, address = self.socket.recvfrom(MAX_DATAGRAM_SIZE + 1)
            except socket.timeout:
                continue
            except OSError:
                if not self.stop_event.is_set():
                    logger.exception("flow_collector.receive_failed")
                return
            exporter = address[0]
            self._record_global(increments={"packets_received": 1}, last_datagram_at=_now())
            self._refresh_sources()
            sources = self._source_cache.get(exporter, [])
            if not sources:
                logger.warning("flow_collector.unknown_exporter exporter=%s", exporter)
                self._record_global(increments={"unknown_exporter_packets": 1})
                continue
            if len(packet) > MAX_DATAGRAM_SIZE or not self._rate_allowed():
                self._record_global(increments={"oversized_packets" if len(packet) > MAX_DATAGRAM_SIZE else "rate_limited_packets": 1})
                for source in sources:
                    self._record_packet_state(source.id, increments={"packets_rejected": 1}, last_error_category="rate_or_size_limit")
                continue
            for source in sources:
                try:
                    with self._decode_condition:
                        ordinal = self._next_packet_ordinal
                        self.queue.put_nowait((ordinal, source.id, exporter, packet))
                        self._next_packet_ordinal += 1
                except queue.Full:
                    self._record_packet_state(source.id, increments={"queue_drops": 1}, last_error_category="queue_full")

    def _worker_loop(self) -> None:
        while not self.stop_event.is_set() or not self.queue.empty():
            try:
                ordinal, source_id, exporter, packet = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                # Queue insertion assigns a monotonic ordinal only after the
                # bounded queue accepts the item. Workers therefore decode in
                # receiver order without gaps when queue backpressure drops a
                # packet.
                result = None
                with self._decode_condition:
                    while ordinal != self._next_decode_ordinal and not self.stop_event.is_set():
                        self._decode_condition.wait(timeout=0.2)
                    if self.stop_event.is_set() and ordinal != self._next_decode_ordinal:
                        continue
                    try:
                        with SessionLocal() as config_db:
                            if _flow_ingestion_enabled(config_db):
                                result = self.decoder.decode(packet, exporter)
                    finally:
                        self._next_decode_ordinal += 1
                        self._decode_condition.notify_all()
                if result is None:
                    continue
                now = _now()
                with self._write_lock, SessionLocal() as db:
                    accepted_records = [] if self.discovery.enabled() else None
                    state = _state(db, source_id)
                    state.listener_state = "running"
                    state.last_datagram_at = now
                    state.unknown_templates += result.unknown_templates
                    state.template_cache_size = len(self.decoder.templates)
                    if result.template_events:
                        _append_template_lifecycle(state, result.template_events, now)
                        _update_template_lifecycle_summary(state, result.template_events, now)
                    if result.unknown_template_details:
                        detail = result.unknown_template_details[-1]
                        state.last_unknown_template_id = int(detail["template_id"])
                        state.last_unknown_template_exporter = str(detail["exporter_identity"])
                        state.last_unknown_template_source_id = int(detail["source_id"])
                        state.last_template_error_category = str(detail["category"])
                        state.last_unknown_template_at = now
                    if result.sequence_gap or result.exporter_restart:
                        state.last_error_category = "sequence_discontinuity" if result.sequence_gap else "exporter_restart"
                        state.sequence_gaps += 1 if result.sequence_gap else 0
                        state.exporter_restarts += 1 if result.exporter_restart else 0
                        event = {
                            "source_id": source_id,
                            "template_id": 0,
                            "status": "error",
                            "reason": state.last_error_category,
                            "cache_present": True,
                        }
                        _append_template_lifecycle(state, [event], now)
                        _update_template_lifecycle_summary(state, [event], now)
                    process_records(db, result.records, source_id=source_id, accepted_records=accepted_records)
                    state.queue_depth = self.queue.qsize()
                    db.commit()
                if accepted_records:
                    self.discovery.enqueue(source_id, accepted_records)
            except FlowDecodeError as exc:
                with self._write_lock, SessionLocal() as db:
                    state = _state(db, source_id)
                    state.packets_rejected = int(state.packets_rejected or 0) + 1
                    state.malformed_packets = int(state.malformed_packets or 0) + 1
                    state.decode_failures = int(state.decode_failures or 0) + 1
                    state.last_error_category = exc.category
                    if exc.details:
                        event = {**exc.details, "status": "rejected", "reason": exc.category, "cache_present": False}
                        _append_template_lifecycle(state, [event], _now())
                        _update_template_lifecycle_summary(state, [event], _now())
                    db.commit()
            except Exception:
                logger.exception("flow_collector.persistence_failed source_id=%s", source_id)
                self._record_packet_state(source_id, increments={"persistence_failures": 1}, last_error_category="persistence_failure")
            finally:
                self.queue.task_done()

    def run(self) -> None:
        if not self.settings["enabled"]:
            logger.info("flow_collector.disabled")
            return
        self.socket = socket.socket(socket.AF_INET6 if ":" in self.settings["bind_address"] else socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        self.socket.settimeout(0.5)
        self.socket.bind((self.settings["bind_address"], self.settings["port"]))
        self.discovery.start()
        self._refresh_sources()
        self.receiver = threading.Thread(target=self._receive_loop, name="flow-receiver", daemon=True)
        self.receiver.start()
        self.workers = [threading.Thread(target=self._worker_loop, name=f"flow-worker-{index}", daemon=True) for index in range(self.settings["workers"])]
        for worker in self.workers:
            worker.start()
        self._set_listener_state("running")
        logger.info("flow_collector.started bind_address=%s port=%s workers=%s queue_size=%s", self.settings["bind_address"], self.settings["port"], self.settings["workers"], self.settings["queue_size"])
        try:
            while not self.stop_event.wait(1):
                self._refresh_sources()
                if time.monotonic() - self._last_heartbeat >= STATE_REFRESH_SECONDS:
                    self._set_listener_state("running")
                    self._last_heartbeat = time.monotonic()
        finally:
            self.stop()

    def _set_listener_state(self, value: str) -> None:
        with SessionLocal() as db:
            heartbeat = _now()
            global_state = _global_state(db)
            global_state.listener_state = value
            global_state.updated_at = heartbeat
            rows = db.query(TrafficSource).filter(TrafficSource.provider_key.in_(["netflow_v9", "cisco_nsel"]), TrafficSource.collector_port == self.settings["port"], TrafficSource.is_deleted.is_(False)).all()
            for source in rows:
                state = _state(db, source.id)
                state.listener_state = value
                state.updated_at = heartbeat
            db.commit()

    def stop(self) -> None:
        if self.stop_event.is_set() and self.socket is None:
            return
        self.stop_event.set()
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
        if self.receiver:
            self.receiver.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=2)
        try:
            self._set_listener_state("stopped")
        except Exception:
            logger.exception("flow_collector.stop_state_failed")
        finally:
            self.discovery.stop()


def main() -> None:
    collector = FlowCollector()
    signal.signal(signal.SIGTERM, lambda *_: collector.stop())
    signal.signal(signal.SIGINT, lambda *_: collector.stop())
    collector.run()


if __name__ == "__main__":
    main()
