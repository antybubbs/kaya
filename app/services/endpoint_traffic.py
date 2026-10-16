"""Automatic, source-scoped usage accounting for observed endpoint IPs.

Called from the existing flow pipeline after replay protection and cumulative
counter conversion, so each accepted flow contributes once. Only original
(pre-NAT) endpoints inside enabled local networks are counted; translated
addresses never are. No monitoring record, managed IP or asset is required or
created.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress

from sqlalchemy import case
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models.models import TrafficEndpointAggregate, TrafficLocalNetwork, TrafficMonitoringConfiguration
from app.services.flow_protocol import NormalizedFlowRecord

RESOLUTIONS = (300, 3600, 86400)
UPSERT_CHUNK = 500
_EPOCH = datetime(1970, 1, 1)


def bucket_start(value: datetime, seconds: int) -> datetime:
    """Canonical UTC bucket for the application's naive-UTC timestamps."""
    epoch = int((value - _EPOCH).total_seconds())
    return _EPOCH + timedelta(seconds=epoch - epoch % seconds)


def endpoint_contributions(record: NormalizedFlowRecord, byte_count: int, packet_count: int) -> list[tuple[str | None, str, int, int]]:
    """``(address, direction, bytes, packets)`` for each original endpoint.

    Directional NSEL deltas follow the initiator/responder mapping used for
    device usage: the initiator uploads forward and downloads reverse bytes, the
    responder the opposite. A unidirectional NetFlow record is the source's
    upload and the destination's download.
    """
    directional = any(value is not None for value in (record.forward_bytes, record.reverse_bytes, record.forward_packets, record.reverse_packets))
    if directional:
        forward = (int(record.forward_bytes or 0), int(record.forward_packets or 0))
        reverse = (int(record.reverse_bytes or 0), int(record.reverse_packets or 0))
        return [
            (record.source_ip, "upload", *forward), (record.source_ip, "download", *reverse),
            (record.destination_ip, "upload", *reverse), (record.destination_ip, "download", *forward),
        ]
    return [(record.source_ip, "upload", byte_count, packet_count), (record.destination_ip, "download", byte_count, packet_count)]


class EndpointUsageBatch:
    """Merges one datagram's contributions and writes them in one upsert."""

    def __init__(self, db: Session):
        self.db = db
        self._networks: list | None = None
        self._rows: dict[tuple, dict] = {}

    def _local_networks(self) -> list:
        if self._networks is None:
            config = self.db.get(TrafficMonitoringConfiguration, 1)
            networks = []
            if config and config.is_enabled:
                for row in self.db.query(TrafficLocalNetwork.network_cidr).filter(TrafficLocalNetwork.is_enabled.is_(True)).limit(256):
                    try:
                        networks.append(ipaddress.ip_network(row[0], strict=False))
                    except ValueError:
                        continue
            self._networks = networks
        return self._networks

    def add(self, record: NormalizedFlowRecord, byte_count: int, packet_count: int, quality: str, source_id: int) -> None:
        networks = self._local_networks()
        if not networks or not record.exporter_identity:
            return
        for address, direction, direction_bytes, direction_packets in endpoint_contributions(record, byte_count, packet_count):
            if not address or (direction_bytes <= 0 and direction_packets <= 0):
                continue
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if not any(parsed.version == network.version and parsed in network for network in networks):
                continue
            for seconds in RESOLUTIONS:
                key = (parsed.compressed, seconds, bucket_start(record.observed_at, seconds), source_id, record.exporter_identity[:45], direction)
                row = self._rows.get(key)
                if row is None:
                    self._rows[key] = {
                        "endpoint_ip": key[0], "bucket_seconds": seconds, "bucket_start": key[2], "source_id": source_id,
                        "exporter_identity": key[4], "direction": direction, "address_family": parsed.version,
                        "bytes_total": max(0, direction_bytes), "packets_total": max(0, direction_packets), "sample_count": 1,
                        "data_quality": quality if quality in {"complete", "partial"} else "partial", "last_observed_at": record.observed_at,
                    }
                else:
                    row["bytes_total"] += max(0, direction_bytes)
                    row["packets_total"] += max(0, direction_packets)
                    row["sample_count"] += 1
                    row["last_observed_at"] = max(row["last_observed_at"], record.observed_at)
                    if quality != "complete":
                        row["data_quality"] = "partial"

    def flush(self) -> int:
        """Upsert merged rows in key order so concurrent writers lock consistently."""
        if not self._rows:
            return 0
        dialect = self.db.bind.dialect.name
        insert = postgres_insert if dialect == "postgresql" else sqlite_insert if dialect == "sqlite" else None
        if insert is None:
            raise RuntimeError("Unsupported database dialect for endpoint usage")
        table = TrafficEndpointAggregate.__table__
        values = [self._rows[key] for key in sorted(self._rows, key=lambda item: (item[0], item[1], item[2], item[3], item[4], item[5]))]
        for index in range(0, len(values), UPSERT_CHUNK):
            statement = insert(table).values(values[index:index + UPSERT_CHUNK])
            excluded = statement.excluded
            self.db.execute(statement.on_conflict_do_update(
                index_elements=["endpoint_ip", "bucket_seconds", "bucket_start", "source_id", "exporter_identity", "direction"],
                set_={
                    "bytes_total": table.c.bytes_total + excluded.bytes_total,
                    "packets_total": table.c.packets_total + excluded.packets_total,
                    "sample_count": table.c.sample_count + excluded.sample_count,
                    "data_quality": case((excluded.data_quality == "partial", "partial"), else_=table.c.data_quality),
                    "last_observed_at": case((table.c.last_observed_at.is_(None), excluded.last_observed_at), (excluded.last_observed_at > table.c.last_observed_at, excluded.last_observed_at), else_=table.c.last_observed_at),
                },
            ))
        written = len(values)
        self._rows.clear()
        return written


def cleanup_endpoint_aggregates(db: Session, cutoffs: dict[int, datetime]) -> int:
    """Delete rows older than each tier's cutoff; idempotent and retry-safe."""
    removed = 0
    for seconds, cutoff in cutoffs.items():
        removed += db.query(TrafficEndpointAggregate).filter(
            TrafficEndpointAggregate.bucket_seconds == seconds,
            TrafficEndpointAggregate.bucket_start < cutoff,
        ).delete(synchronize_session=False)
    return removed
