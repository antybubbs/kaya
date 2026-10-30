import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Barrier

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.models import TrafficFlowAggregate, TrafficFlowCollectorState, TrafficSource
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord


POSTGRES_URL = os.environ.get("FLOW_POSTGRES_TEST_URL")


def _record(index: int, *, key: str = "") -> NormalizedFlowRecord:
    return NormalizedFlowRecord(
        exporter_identity="192.0.2.10", source_id=7, sequence=index, record_index=0,
        observed_at=datetime(2026, 1, 1, 0, 1), flow_start=None, flow_end=None,
        source_ip="192.0.2.20", destination_ip="198.51.100.20", source_port=443,
        destination_port=51515, protocol=6, input_interface=None, output_interface=None,
        translated_source_ip=None, translated_destination_ip=None,
        translated_source_port=None, translated_destination_port=None,
        bytes_total=100, packets_total=1, direction="unknown", event_type=None,
        connection_id=key or str(index), cumulative_counters=False, data_quality="complete",
    )


def test_postgres_conflict_safe_aggregate_and_dedup_writes():
    if not POSTGRES_URL:
        return
    engine = create_engine(POSTGRES_URL, pool_size=10, max_overflow=0, pool_pre_ping=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        db.add(TrafficSource(id=1, name="Concurrency synthetic", provider_key="netflow_v9", source_category="flow_export", is_enabled=True, exporter_allowlist_json='["192.0.2.10"]', collector_port=2055))
        db.flush()
        db.add(TrafficFlowCollectorState(source_id=1))
        db.commit()

    barrier = Barrier(8)
    unique_records = [_record(index) for index in range(32)]

    def submit(record):
        with factory() as db:
            barrier.wait()
            result = process_records(db, [record], source_id=1)
            db.commit()
            return result

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(submit, unique_records))

    duplicate = _record(900, key="same-session")
    duplicate_barrier = Barrier(8)

    def submit_duplicate(_):
        with factory() as db:
            duplicate_barrier.wait()
            result = process_records(db, [duplicate], source_id=1)
            db.commit()
            return result

    with ThreadPoolExecutor(max_workers=8) as pool:
        duplicate_results = list(pool.map(submit_duplicate, range(8)))

    with factory() as db:
        aggregate = db.query(TrafficFlowAggregate).one()
        assert aggregate.bytes_total == 3300
        assert aggregate.sample_count == 33
        assert db.query(TrafficFlowAggregate).count() == 1
        assert sum(result["accepted"] for result in duplicate_results) == 1
        assert sum(result["duplicates"] for result in duplicate_results) == 7

        retry_record = _record(901, key="rollback-retry")
        process_records(db, [retry_record], source_id=1)
        db.rollback()
        process_records(db, [retry_record], source_id=1)
        db.commit()
        assert db.query(TrafficFlowAggregate).one().bytes_total == 3400
    engine.dispose()
