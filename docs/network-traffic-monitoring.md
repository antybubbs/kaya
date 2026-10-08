# Network Traffic Monitoring foundations

Stage 1 adds the disabled-by-default persistence and provider contracts for
Network Traffic under the existing IP/WAN Monitor module. It does not poll
SNMP, listen for UDP flow exports, decode flows, attribute devices, render
traffic charts or evaluate traffic alerts.

## Persistence contract

Traffic data is deliberately separate from `network_monitors` and its ICMP
observations. The configuration singleton controls the feature and retention
policy; `traffic_sources` stores one logical provider configuration per source;
`traffic_interfaces` stores source-local interface identity; and
`traffic_local_networks` stores canonical IPv4/IPv6 networks used later for
classification.

`traffic_counter_observations` is the bounded future interface-counter store.
It contains counters and timestamps only—never packets or payloads. Its
`observation_key` is the provider-defined idempotency key. Later collectors
must include source, interface, observation time and exporter epoch or an
equivalent restart boundary in that key.

`traffic_aggregates` is the future dashboard store. Its uniqueness key is:

```text
source + interface + bucket_start + bucket_seconds + direction + traffic_class
```

SNMP/interface totals and flow-derived totals remain separate by `source` and
`traffic_class`; they must be reconciled, not summed as if they were
independent traffic.

## Identity, timestamps and resets

- Source identity is stable within Kaya; deleting a source retires its
  configuration and does not mean a replacement source inherits its history.
- Interface identity is scoped to its source by `interface_key`; numeric
  interface indexes are metadata, not global identity.
- Device attribution is intentionally absent in Stage 1. A later attribution
  record must include a confidence state and an explicit time boundary so an IP
  reuse cannot silently merge two devices.
- All persisted timestamps are naive UTC values following Kaya’s existing
  database convention. API timestamps are emitted with a `Z` suffix.
- Counter reset and exporter restart fields already exist in the observation
  contract (`reset_detected`, `counter_bits`, `exporter_epoch`) so a later
  collector can discard invalid deltas rather than manufacture traffic.

## Retention and sizing

The initial policy is 24 hours of high-resolution observations, 7 days of
five-minute aggregates, 90 days of hourly aggregates and 365 days of daily
aggregates. These are configuration values, not an active cleanup job in Stage
1. No raw flow table is created. Approximate growth must be evaluated from the
number of enabled sources and selected interfaces before Stage 2 enables
collection; the bounded observation and aggregate indexes are designed for
time-range queries by source and interface.

## Lifecycle

Configuration and observed health are independent:

- configuration: `enabled`, `disabled`, `unconfigured`;
- health: `healthy`, `degraded`, `stale`, `error`, `unconfigured`.

Retiring a source sets it disabled and deleted while retaining its row and any
future historical foreign-key data. Existing IP/WAN monitoring has its own
scheduler and tables and is unaffected. The traffic feature defaults to
disabled and currently has no flow collector to start; Stage 2 only adds
bounded SNMP polling when explicitly enabled.

## Security boundary

SNMP destinations and exporter allowlists accept literal IP addresses only.
SNMP destinations must be usable private addresses; DNS names, loopback,
multicast, unspecified, link-local and public addresses are rejected. This
prevents Stage 1 configuration from becoming an SSRF primitive before an
outbound provider exists. SNMP credentials are encrypted with Kaya’s existing
Fernet helper and are represented in responses only by presence flags.

Source and configuration mutations require an authenticated administrator,
Network Monitor module access and a validated CSRF token. Reads require an
authenticated user with module access. Mutations create redacted audit events.

## Stage 2 SNMP polling

Stage 2 uses PySNMP 7.1’s asyncio v3arch API and standard IF-MIB OIDs. It
discovers interface names/descriptions, administrative and operational status,
speed (preferring IF-MIB high-speed), 64-bit counters when available, counter
discontinuity and device uptime. It falls back to 32-bit octets only when
high-capacity counters are not returned.

The scheduler is disabled unless the traffic configuration singleton is
explicitly enabled. It uses an expiring database lease so only one application
worker owns polling at a time, bounded concurrency, per-source locks, bounded
timeouts and exponential backoff. Lease ownership is revalidated and
row-fenced before persistence and commit, so an expired worker cannot write
late observations. A disabled or retired source is skipped immediately.

The first counter sample is a baseline. Rates use actual elapsed time and are
stored in bits per second. Device restarts, discontinuities, invalid negative
deltas and rates above 125% of known interface capacity produce no rate. Valid
wraparound is accepted only when the previous value is near the counter limit
and the new value is near zero.

Five-minute, hourly and daily aggregates store bytes derived from accepted
rates. When an observation interval crosses a UTC bucket boundary, bytes are
split proportionally using a constant-rate approximation and marked
`is_approximate`; a whole delta is never assigned to only the ending bucket.
Counter observations are idempotent by a SHA-256 observation key and retain no
packet contents. WAN interface direction is explicit per interface; SNMP
inbound/outbound values are not silently treated as internet-only totals.
