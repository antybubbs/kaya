"""Provider-independent, bounded endpoint discovery from normalized flow records."""
from __future__ import annotations

import ipaddress
import logging
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import case, func, or_, text
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models.models import (
    TrafficDiscoveryConfiguration,
    TrafficDiscoveryObservation,
    TrafficDiscoverySummary,
    TrafficLocalNetwork,
    TrafficSource,
)
from app.services.flow_protocol import NormalizedFlowRecord


logger = logging.getLogger("kaya.network_discovery")
DISCOVERY_FLOW_PROVIDERS = frozenset({"netflow_v9", "cisco_nsel"})
DETAIL_BUCKET_SECONDS = 300
SUMMARY_BUCKET_SECONDS = 3600
MAX_RECORD_BATCH = 512
MAX_OBSERVATIONS_PER_BATCH = 2048
DISCOVERY_QUEUE_SIZE = 128
DISCOVERY_CONTROL_REFRESH_SECONDS = 2.0
DISCOVERY_SHUTDOWN_TIMEOUT_SECONDS = 2.0
DISCOVERY_STATEMENT_TIMEOUT_MS = 5000


@dataclass(frozen=True)
class DiscoveryObservation:
    exporter_identity: str
    endpoint_ip: str
    address_family: int
    endpoint_role: str
    observed_at: datetime
    classification: str
    confidence: str
    ambiguity_reason: str | None = None


@dataclass(frozen=True)
class DiscoveryWorkItem:
    """Immutable, bounded work handed from accounting to the discovery consumer."""

    source_id: int
    records: tuple[NormalizedFlowRecord, ...]


class DiscoveryRuntime:
    """Fail-closed enablement control and bounded best-effort persistence worker."""

    def __init__(
        self,
        session_factory,
        *,
        persist=None,
        queue_size: int = DISCOVERY_QUEUE_SIZE,
        control_refresh_seconds: float = DISCOVERY_CONTROL_REFRESH_SECONDS,
    ):
        self._session_factory = session_factory
        self._persist = persist
        self._queue: queue.Queue[DiscoveryWorkItem] = queue.Queue(maxsize=max(1, int(queue_size)))
        self._control_refresh_seconds = max(0.1, float(control_refresh_seconds))
        self._stop_event = threading.Event()
        self._invalidate_event = threading.Event()
        self._state_lock = threading.Lock()
        self._enabled = False
        self._control_thread: threading.Thread | None = None
        self._consumer_thread: threading.Thread | None = None
        self._stats_lock = threading.Lock()
        self._stats = {"enqueued": 0, "dropped": 0, "persisted": 0, "failed": 0, "disabled": 0}

    def enabled(self) -> bool:
        with self._state_lock:
            return self._enabled

    def _set_enabled(self, value: bool) -> None:
        with self._state_lock:
            self._enabled = bool(value)

    def invalidate_enablement(self) -> None:
        """Request an immediate refresh after a configuration writer commits."""
        self._invalidate_event.set()

    def _refresh_enablement(self) -> None:
        enabled = False
        try:
            with self._session_factory() as db:
                configuration = db.get(TrafficDiscoveryConfiguration, 1)
                enabled = bool(configuration and configuration.is_enabled)
        except Exception:
            logger.warning("flow_discovery.enablement_refresh_failed", exc_info=True)
        self._set_enabled(enabled)

    def _control_loop(self) -> None:
        while not self._stop_event.is_set():
            self._refresh_enablement()
            self._invalidate_event.wait(self._control_refresh_seconds)
            self._invalidate_event.clear()

    def start(self) -> None:
        if self._control_thread and self._control_thread.is_alive():
            return
        self._stop_event.clear()
        self._invalidate_event.clear()
        if self._persist is None:
            self._persist = persist_discovery_batch
        self._refresh_enablement()
        self._control_thread = threading.Thread(target=self._control_loop, name="flow-discovery-control", daemon=True)
        self._consumer_thread = threading.Thread(target=self._consumer_loop, name="flow-discovery-consumer", daemon=True)
        self._control_thread.start()
        self._consumer_thread.start()

    def enqueue(self, source_id: int, records: list[NormalizedFlowRecord]) -> bool:
        if not records or not self.enabled():
            return False
        item = DiscoveryWorkItem(source_id=source_id, records=tuple(records[:MAX_RECORD_BATCH]))
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._stats_lock:
                self._stats["dropped"] += 1
            logger.warning("flow_discovery.queue_full source_id=%s", source_id)
            return False
        with self._stats_lock:
            self._stats["enqueued"] += 1
        return True

    def _consumer_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if not self.enabled():
                    with self._stats_lock:
                        self._stats["disabled"] += 1
                    continue
                with self._session_factory() as db:
                    if getattr(getattr(db, "bind", None), "dialect", None) and db.bind.dialect.name == "postgresql":
                        db.execute(text(f"SET LOCAL statement_timeout = '{DISCOVERY_STATEMENT_TIMEOUT_MS}ms'"))
                    self._persist(db, item.source_id, list(item.records))
                    db.commit()
                with self._stats_lock:
                    self._stats["persisted"] += 1
            except Exception:
                with self._stats_lock:
                    self._stats["failed"] += 1
                logger.warning("flow_discovery.persistence_failed source_id=%s", item.source_id, exc_info=True)
            finally:
                self._queue.task_done()

    def stats(self) -> dict[str, int]:
        with self._stats_lock:
            return {**self._stats, "queued": self._queue.qsize()}

    def stop(self) -> None:
        self._stop_event.set()
        self._invalidate_event.set()
        for thread in (self._control_thread, self._consumer_thread):
            if thread:
                thread.join(timeout=DISCOVERY_SHUTDOWN_TIMEOUT_SECONDS)
        self._control_thread = None
        self._consumer_thread = None
        dropped = 0
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
            else:
                dropped += 1
                self._queue.task_done()
        if dropped:
            with self._stats_lock:
                self._stats["dropped"] += dropped
        self._set_enabled(False)


def discovery_enabled(db: Session) -> bool:
    configuration = db.get(TrafficDiscoveryConfiguration, 1)
    return bool(configuration and configuration.is_enabled)


def provider_supports_discovery(provider_key: str, record: NormalizedFlowRecord) -> bool:
    """Declare support from normalized evidence, never Cisco-specific fields."""
    return provider_key in DISCOVERY_FLOW_PROVIDERS and bool(
        record.source_ip or record.destination_ip or record.translated_source_ip or record.translated_destination_ip
    )


def _bucket(value: datetime, seconds: int) -> datetime:
    epoch = int(value.timestamp())
    return datetime.utcfromtimestamp(epoch - epoch % seconds)


def _networks(db: Session) -> list[ipaddress._BaseNetwork]:
    result: list[ipaddress._BaseNetwork] = []
    for row in db.query(TrafficLocalNetwork).filter(TrafficLocalNetwork.is_enabled.is_(True)).limit(256):
        try:
            result.append(ipaddress.ip_network(row.network_cidr, strict=False))
        except ValueError:
            continue
    return result


def _classify(address: str, networks: list[ipaddress._BaseNetwork], *, translated: bool) -> tuple[int, str, str, str | None] | None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    matches = [network for network in networks if parsed.version == network.version and parsed in network]
    if not matches:
        return None
    if len(matches) > 1:
        return parsed.version, "ambiguous", "unknown", "overlapping_local_networks"
    return parsed.version, "internal", "medium" if translated else "high", "translated_endpoint" if translated else None


def observations_for_records(
    records: list[NormalizedFlowRecord],
    networks: list[ipaddress._BaseNetwork],
) -> list[DiscoveryObservation]:
    observations: list[DiscoveryObservation] = []
    for record in records[:MAX_RECORD_BATCH]:
        endpoint_values = (
            ("original_source", record.source_ip, False),
            ("original_destination", record.destination_ip, False),
            ("translated_source", record.translated_source_ip, True),
            ("translated_destination", record.translated_destination_ip, True),
        )
        for role, address, translated in endpoint_values:
            if not address:
                continue
            classified = _classify(address, networks, translated=translated)
            if classified is None:
                continue
            family, classification, confidence, ambiguity_reason = classified
            observations.append(
                DiscoveryObservation(
                    exporter_identity=record.exporter_identity,
                    endpoint_ip=address,
                    address_family=family,
                    endpoint_role=role,
                    observed_at=record.observed_at,
                    classification=classification,
                    confidence=confidence,
                    ambiguity_reason=ambiguity_reason,
                )
            )
            if len(observations) >= MAX_OBSERVATIONS_PER_BATCH:
                return observations
    return observations


def _upsert(db: Session, table, values: dict, constraint: str):
    statement = postgres_insert(table) if db.bind.dialect.name == "postgresql" else sqlite_insert(table) if db.bind.dialect.name == "sqlite" else None
    if statement is None:
        return False
    excluded = statement.excluded
    values_to_update = {
        "first_seen_at": case((table.c.first_seen_at > excluded.first_seen_at, excluded.first_seen_at), else_=table.c.first_seen_at),
        "last_seen_at": case((table.c.last_seen_at < excluded.last_seen_at, excluded.last_seen_at), else_=table.c.last_seen_at),
        "observation_count": table.c.observation_count + excluded.observation_count,
        "classification": excluded.classification,
        "confidence": excluded.confidence,
        "ambiguity_reason": excluded.ambiguity_reason,
    }
    statement = statement.values(**values)
    if db.bind.dialect.name == "postgresql":
        statement = statement.on_conflict_do_update(constraint=constraint, set_=values_to_update)
    else:
        statement = statement.on_conflict_do_update(
            index_elements=["source_id", "exporter_identity", "endpoint_ip", "endpoint_role", "bucket_start"],
            set_=values_to_update,
        )
    db.execute(statement)
    return True


def _merge_observations(observations: list[DiscoveryObservation], seconds: int) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for item in observations:
        bucket_start = _bucket(item.observed_at, seconds)
        key = (item.exporter_identity, item.endpoint_ip, item.endpoint_role, bucket_start)
        current = merged.get(key)
        values = {
            "exporter_identity": item.exporter_identity,
            "endpoint_ip": item.endpoint_ip,
            "address_family": item.address_family,
            "endpoint_role": item.endpoint_role,
            "bucket_start": bucket_start,
            "bucket_seconds": seconds,
            "first_seen_at": item.observed_at,
            "last_seen_at": item.observed_at,
            "observation_count": 1,
            "classification": item.classification,
            "confidence": item.confidence,
            "ambiguity_reason": item.ambiguity_reason,
        }
        if current is None:
            merged[key] = values
        else:
            current["first_seen_at"] = min(current["first_seen_at"], item.observed_at)
            current["last_seen_at"] = max(current["last_seen_at"], item.observed_at)
            current["observation_count"] += 1
            current["classification"] = item.classification
            current["confidence"] = item.confidence
            current["ambiguity_reason"] = item.ambiguity_reason
    return list(merged.values())


def _trim_table(db: Session, model, maximum: int) -> None:
    maximum = max(1, min(int(maximum), 1_000_000))
    count = int(db.query(func.count(model.id)).scalar() or 0)
    if count <= maximum:
        return
    ids = [row[0] for row in db.query(model.id).order_by(model.last_seen_at.asc(), model.id.asc()).limit(count - maximum).all()]
    if ids:
        db.query(model).filter(model.id.in_(ids)).delete(synchronize_session=False)


def persist_discovery_batch(db: Session, source_id: int, records: list[NormalizedFlowRecord], *, now: datetime | None = None) -> int:
    """Persist only eligible endpoint metadata in a caller-owned transaction."""
    now = now or datetime.utcnow()
    configuration = db.get(TrafficDiscoveryConfiguration, 1)
    if not configuration or not configuration.is_enabled:
        return 0
    source = db.get(TrafficSource, source_id)
    if not records or not source or source.is_deleted:
        return 0
    if not all(provider_supports_discovery(source.provider_key, record) for record in records[:MAX_RECORD_BATCH]):
        return 0
    networks = _networks(db)
    if not networks:
        return 0
    observations = observations_for_records(records, networks)
    if not observations:
        return 0
    detail_values = _merge_observations(observations, DETAIL_BUCKET_SECONDS)
    summary_values = _merge_observations(observations, SUMMARY_BUCKET_SECONDS)
    for values in detail_values:
        values["source_id"] = source_id
        if not _upsert(db, TrafficDiscoveryObservation.__table__, values, "uq_traffic_discovery_observation_bucket"):
            raise RuntimeError("Unsupported database dialect for discovery observations")
    for values in summary_values:
        values["source_id"] = source_id
        if not _upsert(db, TrafficDiscoverySummary.__table__, values, "uq_traffic_discovery_summary_bucket"):
            raise RuntimeError("Unsupported database dialect for discovery summaries")
    detail_cutoff = now - timedelta(hours=max(1, min(int(configuration.detailed_retention_hours), 720)))
    summary_cutoff = now - timedelta(days=max(1, min(int(configuration.summary_retention_days), 3650)))
    db.query(TrafficDiscoveryObservation).filter(TrafficDiscoveryObservation.last_seen_at < detail_cutoff).delete(synchronize_session=False)
    db.query(TrafficDiscoverySummary).filter(TrafficDiscoverySummary.last_seen_at < summary_cutoff).delete(synchronize_session=False)
    _trim_table(db, TrafficDiscoveryObservation, configuration.max_detail_rows)
    _trim_table(db, TrafficDiscoverySummary, configuration.max_summary_rows)
    return len(observations)
