# Network Traffic Stage 3A flow collector

Stage 3A adds an optional standalone UDP collector for NetFlow v9 and the
validated Cisco ASA NSEL field subset. It is disabled unless the
`flow-collector` Docker Compose profile is explicitly enabled and a source is
enabled with a matching collector port and literal exporter allowlist.

## Process architecture

The collector is `scripts/flow_collector.py`, running independently from the
HTTP server and SNMP scheduler. It uses a bounded UDP receive size, bounded
queue, bounded worker count, per-second packet limit, exporter allowlisting,
exporter-scoped template caches and explicit start/stop lifecycle. It never
stores packet payloads or executes exporter data.

The default listener is loopback-only at `127.0.0.1:2055`. Docker deployment is
opt-in through `docker compose --profile flow-collector up`; the host bind is
also loopback by default. Operators must explicitly choose a trusted LAN bind
and firewall policy when exporters are external to the host.

## Protocol support

NetFlow v9 headers, template FlowSets, data FlowSets, exporter/source/template
namespaces, sequence discontinuities, exporter restarts, template expiry and
bounded IPv4/IPv6 field decoding are supported. Unknown templates, malformed
FlowSets, unsupported field lengths and oversized datagrams are rejected or
counted without retaining their bytes.

Cisco NSEL supports the documented connection identifier, original and
translated IPv4 addresses and ports, protocol, interfaces, event time,
firewall event, extended event, byte and packet counters, and the create,
teardown, denied, alert and update event classes. ASA NSEL fields use the
Cisco-documented field IDs; compatibility with every Firepower FTD export
profile is not claimed without a matching template fixture.

## Accounting and retention

Flow totals are stored in `traffic_flow_aggregates`, separate from SNMP
`traffic_aggregates`. Cumulative NSEL updates are converted to deltas using
durable exporter/connection state. Duplicate event keys are retained only for
48 hours; counter state is retained for two days. Out-of-order events are
counted and do not overwrite newer cumulative state. Partial data quality is
preserved in aggregate rows.

No raw flow records or packet payloads are persisted. The existing dashboard
API exposes flow totals separately from SNMP totals; it does not attribute
flows to VLAN/IP Manager records and does not implement Stage 4 reporting.

## Diagnostics and security

Administrator-only Network Traffic diagnostics expose listener state,
last-seen timestamps, accepted/rejected packets, unknown exporters, malformed
packets, template misses, queue drops, duplicate events, out-of-order events,
persistence failures and last aggregate writes. Credentials and packet
contents are never returned.

UDP exporters are not authenticated by the protocol. Exact source-IP
allowlisting and a non-public default bind are therefore mandatory. Source
spoofing remains a residual risk on networks where an attacker can inject UDP
with an allowed source address; use a trusted network path and firewall rules.

## Validation and acceptance evidence

The focused regression suite currently passes with 27 tests, including real
binary NetFlow v9/NSEL fixtures, template scoping, malformed and oversized
datagrams, cumulative delta accounting, duplicate handling, migration graph
validation and Compose entrypoint/healthcheck checks.

An isolated Docker run using Python 3.12 and PostgreSQL 16 validated the actual
UDP-to-PostgreSQL path. Two datagrams from an exact allowlisted Compose peer
were accepted and produced a 1,600-byte / 20-packet aggregate across two
samples. Two host-originated datagrams were rejected because Docker NAT
presented a non-allowlisted source address. Collector restart returned to a
healthy state with the persisted counters intact. An unauthenticated
diagnostics request was redirected by the existing authentication boundary.

Bounded sender measurements issued 100, 1,000 and 3,000 datagrams in 124.8 ms,
254.6 ms and 483.9 ms respectively from the disposable peer. The receiver
reported 500 datagrams during the final settled sample, including 497 accepted,
3 malformed and 2 unknown-exporter datagrams, with zero application queue drops,
zero persistence failures and queue depth returning to zero. These figures are
an acceptance smoke measurement, not a capacity claim: the fast sender lost
datagrams before the application queue and no CPU/memory benchmark was made.

The implementation supports the documented Cisco ASA NSEL field subset. Cisco
Firepower FTD compatibility remains unverified because no physical FTD export
profile or matching binary template fixture was available. Options Template
FlowSets, arbitrary enterprise fields and IPFIX-specific features are not
claimed as supported; unsupported or malformed input is counted and discarded.
