"""Bounded NetFlow v9 and Cisco NSEL decoding.

The decoder accepts only binary NetFlow v9 datagrams. It keeps templates in a
bounded, exporter-scoped cache and returns normalised records without retaining
the original packet or arbitrary exporter fields.
"""
from __future__ import annotations

import ipaddress
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta


MAX_DATAGRAM_SIZE = 8192
MAX_RECORDS_PER_PACKET = 512
MAX_TEMPLATE_FIELDS = 64
MAX_TEMPLATES = 2048
TEMPLATE_TTL_SECONDS = 1800

# NetFlow v9 and Cisco ASA NSEL/IPFIX field IDs used by this implementation.
FIELD_BYTES = (1, 85)
FIELD_PACKETS = (2, 86)
FIELD_PROTOCOL = 4
FIELD_SRC_PORT = 7
FIELD_SRC_IPV4 = 8
FIELD_INPUT = 10
FIELD_DST_PORT = 11
FIELD_DST_IPV4 = 12
FIELD_OUTPUT = 14
FIELD_FIRST_SWITCHED = 22
FIELD_LAST_SWITCHED = 21
FIELD_SRC_IPV6 = 27
FIELD_DST_IPV6 = 28
FIELD_CONN_ID = 148
FIELD_FLOW_CREATE_TIME_MSEC = 152
FIELD_FWD_DELTA_BYTES = 231
FIELD_REV_DELTA_BYTES = 232
FIELD_FWD_DELTA_PACKETS = 298
FIELD_REV_DELTA_PACKETS = 299
FIELD_XLATE_SRC_IPV4 = 225
FIELD_XLATE_DST_IPV4 = 226
FIELD_XLATE_SRC_PORT = 227
FIELD_XLATE_DST_PORT = 228
FIELD_FW_EVENT = 233
FIELD_EVENT_TIME_MSEC = 323
FIELD_FW_EXT_EVENT = 33002

EVENT_TYPES = {1: "create", 2: "teardown", 3: "denied", 4: "alert", 5: "update"}


class FlowDecodeError(ValueError):
    def __init__(self, category: str, message: str = "Malformed flow datagram", details: dict | None = None):
        super().__init__(message)
        self.category = category
        self.details = details or {}


@dataclass(frozen=True)
class TemplateField:
    field_id: int
    length: int
    enterprise: int | None = None


@dataclass
class FlowTemplate:
    template_id: int
    fields: tuple[TemplateField, ...]
    is_options: bool = False
    refreshed_at: float = field(default_factory=time.monotonic)


@dataclass(frozen=True)
class NormalizedFlowRecord:
    exporter_identity: str
    source_id: int
    sequence: int
    record_index: int
    observed_at: datetime
    flow_start: datetime | None
    flow_end: datetime | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: int | None
    input_interface: int | None
    output_interface: int | None
    translated_source_ip: str | None
    translated_destination_ip: str | None
    translated_source_port: int | None
    translated_destination_port: int | None
    bytes_total: int | None
    packets_total: int | None
    direction: str
    event_type: str | None
    connection_id: str | None
    cumulative_counters: bool
    data_quality: str
    vendor: str | None = None
    extended_event: int | None = None
    forward_bytes: int | None = None
    reverse_bytes: int | None = None
    forward_packets: int | None = None
    reverse_packets: int | None = None


@dataclass
class DecodeResult:
    records: list[NormalizedFlowRecord] = field(default_factory=list)
    template_count: int = 0
    unknown_templates: int = 0
    sequence_gap: bool = False
    exporter_restart: bool = False
    unknown_template_details: list[dict[str, int | str]] = field(default_factory=list)
    template_events: list[dict[str, int | str | bool]] = field(default_factory=list)


def _u(data: bytes, offset: int, length: int) -> int:
    if length < 1 or length > 8 or offset < 0 or offset + length > len(data):
        raise FlowDecodeError("field_length")
    return int.from_bytes(data[offset : offset + length], "big", signed=False)


def _ip(data: bytes, offset: int, length: int) -> str | None:
    if offset + length > len(data):
        raise FlowDecodeError("field_length")
    if length not in (4, 16):
        return None
    return str(ipaddress.ip_address(data[offset : offset + length]))


def _timestamp_from_msec(value: int | None) -> datetime | None:
    if value is None or value < 0 or value > 4102444800000:
        return None
    return datetime.utcfromtimestamp(value / 1000)


class NetFlowV9Decoder:
    def __init__(self, *, max_templates: int = MAX_TEMPLATES, template_ttl_seconds: int = TEMPLATE_TTL_SECONDS):
        self.max_templates = max(1, min(int(max_templates), MAX_TEMPLATES))
        self.template_ttl_seconds = max(60, min(int(template_ttl_seconds), 86400))
        self.templates: dict[tuple[str, int, int], FlowTemplate] = {}
        self._last_sequence: dict[tuple[str, int], int] = {}
        self._last_uptime: dict[tuple[str, int], int] = {}

    def _prune(self) -> list[dict[str, int | str | bool]]:
        now = time.monotonic()
        expired = [key for key, template in self.templates.items() if now - template.refreshed_at > self.template_ttl_seconds]
        evicted: list[dict[str, int | str | bool]] = []
        for key in expired:
            exporter, source_id, template_id = key
            self.templates.pop(key, None)
            evicted.append({"exporter_identity": exporter, "source_id": source_id, "template_id": template_id, "status": "evicted", "reason": "expired"})
        if len(self.templates) > self.max_templates:
            victims = sorted(self.templates.items(), key=lambda item: item[1].refreshed_at)[: len(self.templates) - self.max_templates]
            for key, _ in victims:
                exporter, source_id, template_id = key
                self.templates.pop(key, None)
                evicted.append({"exporter_identity": exporter, "source_id": source_id, "template_id": template_id, "status": "evicted", "reason": "capacity"})
        return evicted

    def decode(self, datagram: bytes, exporter_identity: str) -> DecodeResult:
        if not isinstance(datagram, bytes) or len(datagram) > MAX_DATAGRAM_SIZE:
            raise FlowDecodeError("oversized")
        if len(datagram) < 20:
            raise FlowDecodeError("truncated_header")
        version, count, sys_uptime, unix_secs, sequence, source_id = struct.unpack_from("!HHIIII", datagram, 0)
        if version != 9:
            raise FlowDecodeError("unsupported_version")
        if count > MAX_RECORDS_PER_PACKET:
            raise FlowDecodeError("record_limit")
        try:
            exporter_identity = str(ipaddress.ip_address(exporter_identity))
        except ValueError as exc:
            raise FlowDecodeError("exporter_identity") from exc
        key = (exporter_identity, source_id)
        previous_sequence = self._last_sequence.get(key)
        sequence_gap = previous_sequence is not None and ((sequence - previous_sequence) & 0xFFFFFFFF) > max(count, 1)
        previous_uptime = self._last_uptime.get(key)
        exporter_restart = previous_uptime is not None and sys_uptime + 5000 < previous_uptime
        if exporter_restart:
            for template_key in [item for item in self.templates if item[:2] == key]:
                self.templates.pop(template_key, None)
        self._last_sequence[key] = sequence
        self._last_uptime[key] = sys_uptime
        result = DecodeResult(sequence_gap=sequence_gap, exporter_restart=exporter_restart)
        offset = 20
        record_index = 0
        while offset < len(datagram):
            if len(datagram) - offset < 4:
                raise FlowDecodeError("truncated_flowset")
            flowset_id, flowset_length = struct.unpack_from("!HH", datagram, offset)
            if flowset_length < 4 or offset + flowset_length > len(datagram):
                raise FlowDecodeError("invalid_flowset_length")
            body = datagram[offset + 4 : offset + flowset_length]
            if flowset_id == 0:
                result.template_count += self._decode_templates(body, exporter_identity, source_id, result.template_events, is_options=False)
            elif flowset_id == 1:
                result.template_count += self._decode_templates(body, exporter_identity, source_id, result.template_events, is_options=True)
            elif flowset_id >= 256:
                template = self.templates.get((exporter_identity, source_id, flowset_id))
                expired = template is not None and time.monotonic() - template.refreshed_at > self.template_ttl_seconds
                if template is None or expired:
                    result.unknown_templates += 1
                    if len(result.unknown_template_details) < 8:
                        result.unknown_template_details.append({
                            "template_id": flowset_id,
                            "exporter_identity": exporter_identity,
                            "source_id": source_id,
                            "category": "expired_template" if expired else "unknown_template",
                        })
                    if len(result.template_events) < 32:
                        result.template_events.append({
                            "template_id": flowset_id,
                            "exporter_identity": exporter_identity,
                            "source_id": source_id,
                            "status": "lookup_failed",
                            "reason": "expired" if expired else "missing",
                            "cache_present": not expired and template is not None,
                        })
                else:
                    if not template.is_options:
                        for raw in self._records(body, template):
                            if record_index >= MAX_RECORDS_PER_PACKET:
                                raise FlowDecodeError("record_limit")
                            result.records.append(self._normalise(raw, exporter_identity, source_id, sequence, record_index, sys_uptime, unix_secs))
                            record_index += 1
            offset += flowset_length
        result.template_events.extend(self._prune()[: max(0, 32 - len(result.template_events))])
        return result

    def _decode_templates(self, body: bytes, exporter: str, source_id: int, events: list[dict[str, int | str | bool]], *, is_options: bool) -> int:
        def reject(category: str, template_id: int | None = None) -> None:
            details = {"exporter_identity": exporter, "source_id": source_id}
            if template_id is not None:
                details["template_id"] = template_id
            raise FlowDecodeError(category, details=details)

        offset = 0
        parsed: list[tuple[int, tuple[TemplateField, ...]]] = []
        while offset < len(body):
            if len(body) - offset < 4:
                if any(body[offset:]):
                    reject("truncated_template")
                break
            template_id, field_count = struct.unpack_from("!HH", body, offset)
            offset += 4
            if template_id < 256:
                reject("invalid_template", template_id)
            if is_options:
                if offset + 2 > len(body):
                    reject("truncated_options_template", template_id)
                scope_length, option_length = field_count, struct.unpack_from("!H", body, offset)[0]
                offset += 2
                if scope_length == 0 or scope_length % 4 or option_length % 4:
                    reject("invalid_options_lengths", template_id)
                if (scope_length + option_length) // 4 > MAX_TEMPLATE_FIELDS or offset + scope_length + option_length > len(body):
                    reject("truncated_options_template", template_id)
                field_count = (scope_length + option_length) // 4
            elif not 1 <= field_count <= MAX_TEMPLATE_FIELDS:
                reject("invalid_template", template_id)
            fields: list[TemplateField] = []
            for _ in range(field_count):
                if offset + 4 > len(body):
                    reject("truncated_template", template_id)
                raw_id, length = struct.unpack_from("!HH", body, offset)
                offset += 4
                # NetFlow v9 uses the complete 16-bit field type value. The
                # IPFIX enterprise bit is not part of this wire format;
                # Cisco NSEL field 33002 is a valid v9 field ID.
                enterprise = None
                if length == 0 or length > 2048:
                    reject("invalid_field_length", template_id)
                fields.append(TemplateField(raw_id, length, enterprise))
            parsed.append((template_id, tuple(fields)))
        if any(body[offset:]):
            reject("nonzero_template_padding")
        created = 0
        for template_id, fields in parsed:
            key = (exporter, source_id, template_id)
            if len(events) < 32:
                events.append({
                    "template_id": template_id,
                    "exporter_identity": exporter,
                    "source_id": source_id,
                    "status": "accepted",
                    "reason": "refresh" if key in self.templates else "received",
                    "cache_present": True,
                })
            self.templates[key] = FlowTemplate(template_id, fields, is_options=is_options)
            created += 1
        return created

    @staticmethod
    def _records(body: bytes, template: FlowTemplate):
        width = sum(item.length for item in template.fields)
        if width <= 0:
            raise FlowDecodeError("invalid_template_width")
        offset = 0
        remainder = len(body) % width
        if remainder and (remainder > 3 or any(body[-remainder:])):
            raise FlowDecodeError("invalid_data_padding")
        while offset + width <= len(body) - remainder:
            raw: dict[tuple[int, int | None], bytes] = {}
            for item in template.fields:
                raw[(item.field_id, item.enterprise)] = body[offset : offset + item.length]
                offset += item.length
            yield raw

    def _normalise(self, raw, exporter: str, source_id: int, sequence: int, record_index: int, sys_uptime: int, unix_secs: int) -> NormalizedFlowRecord:
        def value(field_id: int | tuple[int, ...], enterprise: int | None = None) -> int | None:
            field_ids = field_id if isinstance(field_id, tuple) else (field_id,)
            value_bytes = next((raw.get((candidate, enterprise)) for candidate in field_ids if (candidate, enterprise) in raw), None)
            return int.from_bytes(value_bytes, "big") if value_bytes is not None and len(value_bytes) <= 8 else None

        def address(field_id: int) -> str | None:
            for (candidate, _), value_bytes in raw.items():
                if candidate == field_id:
                    return _ip(value_bytes, 0, len(value_bytes))
            return None

        def timestamp(field_id: int) -> datetime | None:
            milliseconds = value(field_id)
            if milliseconds is None:
                return None
            boot_seconds = unix_secs - (sys_uptime / 1000)
            return datetime.utcfromtimestamp(boot_seconds + milliseconds / 1000)

        event = value(FIELD_FW_EVENT)
        forward_bytes = value(FIELD_FWD_DELTA_BYTES)
        reverse_bytes = value(FIELD_REV_DELTA_BYTES)
        forward_packets = value(FIELD_FWD_DELTA_PACKETS)
        reverse_packets = value(FIELD_REV_DELTA_PACKETS)
        is_nsel = any(item is not None for item in (forward_bytes, reverse_bytes, forward_packets, reverse_packets))
        observed = _timestamp_from_msec(value(FIELD_EVENT_TIME_MSEC)) or datetime.utcfromtimestamp(unix_secs)
        conn = value(FIELD_CONN_ID)
        direction = "unknown"
        if value(FIELD_INPUT) is not None or value(FIELD_OUTPUT) is not None:
            direction = "bidirectional"
        return NormalizedFlowRecord(
            exporter_identity=exporter, source_id=source_id, sequence=sequence, record_index=record_index,
            observed_at=observed, flow_start=_timestamp_from_msec(value(FIELD_FLOW_CREATE_TIME_MSEC)) or timestamp(FIELD_FIRST_SWITCHED), flow_end=timestamp(FIELD_LAST_SWITCHED),
            source_ip=address(FIELD_SRC_IPV4) or address(FIELD_SRC_IPV6), destination_ip=address(FIELD_DST_IPV4) or address(FIELD_DST_IPV6),
            source_port=value(FIELD_SRC_PORT), destination_port=value(FIELD_DST_PORT), protocol=value(FIELD_PROTOCOL),
            input_interface=value(FIELD_INPUT), output_interface=value(FIELD_OUTPUT),
            translated_source_ip=address(FIELD_XLATE_SRC_IPV4), translated_destination_ip=address(FIELD_XLATE_DST_IPV4),
            translated_source_port=value(FIELD_XLATE_SRC_PORT), translated_destination_port=value(FIELD_XLATE_DST_PORT),
            bytes_total=((forward_bytes or 0) + (reverse_bytes or 0)) if is_nsel else value(FIELD_BYTES),
            packets_total=((forward_packets or 0) + (reverse_packets or 0)) if is_nsel else value(FIELD_PACKETS),
            forward_bytes=forward_bytes, reverse_bytes=reverse_bytes,
            forward_packets=forward_packets, reverse_packets=reverse_packets,
            direction=direction,
            event_type=EVENT_TYPES.get(event), connection_id=str(conn) if conn is not None else None,
            cumulative_counters=not is_nsel and (event in {2, 3, 4, 5} or event is not None),
            data_quality="complete" if (is_nsel and (forward_bytes is not None or reverse_bytes is not None)) or (not is_nsel and value(FIELD_BYTES) is not None) else "partial",
            vendor="cisco_nsel" if event is not None or value(FIELD_CONN_ID) is not None else None,
            extended_event=value(FIELD_FW_EXT_EVENT),
        )
