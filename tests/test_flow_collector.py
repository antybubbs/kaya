import struct
import time
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import TrafficFlowAggregate, TrafficFlowCollectorState, TrafficMonitoringConfiguration, TrafficSource
from app.services.flow_collector import _allowlisted_sources, process_records
from app.services.flow_protocol import FlowDecodeError, NetFlowV9Decoder


FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (148, 4), (233, 1), (323, 8)]


def packet(exporter_sequence=1, source_id=7, event=1, byte_count=1000, connection_id=42, event_time=1767225600000):
    template = struct.pack("!HH", 300, len(FIELDS)) + b"".join(struct.pack("!HH", field, length) for field, length in FIELDS)
    source = bytes([192, 0, 2, 10])
    destination = bytes([198, 51, 100, 20])
    record = b"".join([
        source, destination, struct.pack("!H", 443), struct.pack("!H", 51515), bytes([6]),
        struct.pack("!I", byte_count), struct.pack("!I", 10), struct.pack("!I", connection_id), bytes([event]), struct.pack("!Q", event_time),
    ])
    template_set = struct.pack("!HH", 0, 4 + len(template)) + template
    data_set = struct.pack("!HH", 300, 4 + len(record)) + record
    header = struct.pack("!HHIIII", 9, 1, 1000, 1767225600, exporter_sequence, source_id)
    return header + template_set + data_set


def test_netflow_v9_template_and_nsel_fields_are_decoded():
    result = NetFlowV9Decoder().decode(packet(), "192.0.2.1")
    assert result.template_count == 1
    assert result.unknown_templates == 0
    assert result.records[0].source_ip == "192.0.2.10"
    assert result.records[0].destination_ip == "198.51.100.20"
    assert result.records[0].connection_id == "42"
    assert result.records[0].event_type == "create"
    assert result.records[0].vendor == "cisco_nsel"
    assert result.template_events[0] == {
        "template_id": 300,
        "exporter_identity": "192.0.2.1",
        "source_id": 7,
        "status": "accepted",
        "reason": "received",
        "cache_present": True,
    }


def test_template_ids_are_scoped_to_exporter_and_source():
    decoder = NetFlowV9Decoder()
    first = decoder.decode(packet(event=1), "192.0.2.1")
    second = decoder.decode(packet(event=5, byte_count=2000), "192.0.2.2")
    assert first.records[0].event_type == "create"
    assert second.records[0].event_type == "update"
    assert len(decoder.templates) == 2


@pytest.mark.parametrize("value", [b"", b"\x00" * 19], ids=["empty", "truncated"])
def test_malformed_and_oversized_datagrams_are_rejected(value):
    with pytest.raises(FlowDecodeError):
        NetFlowV9Decoder().decode(value, "192.0.2.1")


def test_oversized_datagram_is_rejected():
    with pytest.raises(FlowDecodeError, match="Malformed flow datagram"):
        NetFlowV9Decoder().decode(b"\x00" * 8193, "192.0.2.1")


def test_unknown_template_is_counted_without_persisting_packet_bytes():
    header = struct.pack("!HHIIII", 9, 1, 1000, 1767225600, 1, 7)
    unknown_set = struct.pack("!HHI", 300, 8, 123)
    result = NetFlowV9Decoder().decode(header + unknown_set, "192.0.2.1")
    assert result.unknown_templates == 1
    assert result.records == []
    assert result.unknown_template_details == [{
        "template_id": 300,
        "exporter_identity": "192.0.2.1",
        "source_id": 7,
        "category": "unknown_template",
    }]
    assert result.template_events == [{
        "template_id": 300,
        "exporter_identity": "192.0.2.1",
        "source_id": 7,
        "status": "lookup_failed",
        "reason": "missing",
        "cache_present": False,
    }]


def test_template_refresh_and_expiry_are_distinguished():
    decoder = NetFlowV9Decoder()
    first = decoder.decode(packet(exporter_sequence=1), "192.0.2.1")
    assert first.template_events[0]["reason"] == "received"
    second = decoder.decode(packet(exporter_sequence=2), "192.0.2.1")
    assert second.template_events[0]["reason"] == "refresh"
    decoder.templates[("192.0.2.1", 7, 300)].refreshed_at = time.monotonic() - decoder.template_ttl_seconds - 1
    third = decoder.decode(struct.pack("!HHIIII", 9, 1, 1000, 1767225600, 3, 7) + struct.pack("!HHI", 300, 8, 123), "192.0.2.1")
    assert third.unknown_template_details[0]["category"] == "expired_template"
    assert third.template_events[0]["reason"] == "expired"
    assert third.template_events[-1]["status"] == "evicted"


def test_rejected_template_identifies_bounded_template_context():
    header = struct.pack("!HHIIII", 9, 1, 1000, 1767225600, 1, 0)
    # Template 263 declares one field but does not contain its field descriptor.
    template_set = struct.pack("!HHHH", 0, 10, 263, 1) + b"\x00\x01"
    with pytest.raises(FlowDecodeError) as caught:
        NetFlowV9Decoder().decode(header + template_set, "192.0.2.1")
    assert caught.value.category == "truncated_template"
    assert caught.value.details == {"exporter_identity": "192.0.2.1", "source_id": 0, "template_id": 263}


def test_cumulative_nsel_updates_are_delta_accounted_and_idempotent():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        source = TrafficSource(id=1, name="Synthetic NSEL", provider_key="cisco_nsel", source_category="flow_export", is_enabled=True, exporter_allowlist_json='["192.0.2.1"]', collector_port=2055)
        db.add(source)
        db.flush()
        decoder = NetFlowV9Decoder()
        first = decoder.decode(packet(exporter_sequence=1, event=1, byte_count=1000), "192.0.2.1").records
        second = decoder.decode(packet(exporter_sequence=2, event=5, byte_count=1600), "192.0.2.1").records
        process_records(db, first, source_id=source.id)
        process_records(db, second, source_id=source.id)
        process_records(db, second, source_id=source.id)
        db.commit()
        aggregate = db.query(TrafficFlowAggregate).one()
        assert aggregate.bytes_total == 1600
        assert aggregate.sample_count == 2


def test_global_network_traffic_disable_prevents_flow_source_resolution():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        db.add_all([
            TrafficMonitoringConfiguration(id=1, is_enabled=False),
            TrafficSource(id=1, name="Disabled flow", provider_key="cisco_nsel", source_category="flow_export", is_enabled=True, exporter_allowlist_json='["192.0.2.1"]', collector_port=2055),
        ])
        db.commit()
        assert _allowlisted_sources(db, 2055) == {}
        db.get(TrafficMonitoringConfiguration, 1).is_enabled = True
        db.commit()
        assert list(_allowlisted_sources(db, 2055)) == ["192.0.2.1"]
