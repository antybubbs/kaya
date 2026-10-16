# Network Traffic Monitoring foundations

Network Traffic uses the existing Uptime module boundary for its separate,
disabled-by-default traffic domain. SNMP interface polling and the optional
Stage 3A UDP flow collector write separate datasets. Stage 4A adds opt-in
device attribution and bounded usage aggregates without creating a second
inventory or storing raw flow records. Stage 4B adds the central reporting
dashboard and compact VLAN/IP Manager usage card.

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
- Device attribution is intentionally absent. A later attribution
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
future historical foreign-key data. Existing Uptime monitoring has its own
scheduler and tables and is unaffected. The traffic feature defaults to
disabled. Stage 2 adds bounded SNMP polling when explicitly enabled; Stage 3A
adds a separate optional NetFlow v9/Cisco NSEL collector process.

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

## Approved future requirements

The following are approved future requirements, not implemented capabilities:

1. Network Traffic will become the central reporting dashboard for overall ISP/WAN bandwidth and individual device consumption.
2. Individual device traffic monitoring will be enabled or disabled from existing VLAN/IP Manager records.
3. Each device will have its own Network Traffic status and reporting section.
4. Monitoring will be opt-in and disabled by default per device.
5. Global WAN monitoring will remain independent of individual device monitoring.
6. The Network Traffic reporting dashboard will include device tables, rankings, graphs, history and filtering.
7. Existing VLAN/IP Manager device identities must be reused, not duplicated.
8. Device and dashboard views must link to one another.
9. Unknown or ambiguous client traffic must not be incorrectly attributed.
10. SNMP WAN totals and flow-derived device totals must remain separate and clearly labelled.
11. Per-device reporting depends on the future NetFlow/NSEL collection and attribution stages.

Stages 3 and 4 are not implemented by this rename or the current Network Traffic foundations.

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
## Stage 3B accounting foundations

Flow observations retain the original Stage 3A source-level totals separately
from the Stage 3B accounting aggregates. The accounting layer produces bounded
five-minute, hourly and daily rollups with explicit classes: WAN inbound and
outbound, internet download and upload, internal LAN, VPN/tunnel, or unknown.
Classification uses configured interface and local-network topology. RFC1918
or public addressing alone is never treated as proof of a traffic class.

Attribution is conservative and uses existing VLAN/IP Manager records, DHCP
lease intervals and linked DNS IP history; it does not create a second
inventory. Reused or ambiguous addresses return an unresolved reason.

The authenticated `/networking/ip-wan-monitor/traffic/accounting` endpoint
exposes bounded aggregate classes and completeness/confidence fields. The
`/traffic/reconciliation` endpoint records comparisons as unavailable unless
SNMP and flow data have a genuinely comparable interface and time mapping;
SNMP and flow totals are never added together. Administrator diagnostics report
unclassified bytes, unresolved attribution rows and incomplete accounting.

Retention is bounded by the Network Traffic short, hourly and daily settings.
Raw flow payloads are not stored. Cisco Firepower FTD export compatibility
remains unverified and requires the live validation procedure documented in the
Firepower checklist.

## Stage 4A device opt-in

Device monitoring is controlled from the existing VLAN/IP Manager `IPAddress`
record. It is disabled by default and administrator-only. Enabling creates an
activation period at the current UTC time; disabling closes that period.
Re-enabling creates a new period, so separate activations never merge and no
history is backfilled. Only confidently attributable observations are stored;
ambiguous or unlinked traffic remains outside device aggregates.

Device buckets retain direction, source, interface, quality and attribution
confidence at five-minute, hourly and daily resolutions, with bounded
retention. Protected status, state-change and usage endpoints live under
`/networking/vlan-ip-manager/{record_id}/network-traffic`. Reads require
authentication plus VLAN/IP Manager and Network Monitor module access; state
changes additionally require administrator role and CSRF. Stage 4B graphs and
dashboard reporting are not part of Stage 4A.

## Stage 4B reporting

The Network Traffic overview uses the authenticated
`GET /networking/ip-wan-monitor/traffic/report` endpoint. Its `range` parameter
is allowlisted to `1h`, `6h`, `24h`, `7d`, `30d`, `90d`, and `1y`; query windows
are bounded and the server chooses exactly one persisted resolution: 5-minute
for up to 24 hours, hourly for up to 7 days, and daily thereafter. The response
never adds multiple resolutions, combines SNMP and flow totals, or fabricates
missing buckets. WAN rates are derived from persisted counter observations and
WAN history is labelled observed or approximate. Device rows are restricted to
currently opted-in managed IP records and are returned in one bounded query,
with VLAN, status, freshness, quality, and confidence fields. The dashboard
uses the vendored ECharts library and the existing responsive page shell; the
compact IP detail card remains linked to the Network Traffic dashboard.

The Overview also accepts a bounded `custom` range (`start` and `end`, entered in
the site timezone and validated together); the graph, transfer totals and device
rows then share that one window. The browser sends a custom request only when both
values are present and ordered.

### Selected-period WAN transfer totals

The two live cards (current download and upload) keep reporting the latest counter
rate. The two transfer cards report bytes downloaded and uploaded over the selected
History Range for the selected WAN source, or for all enabled WAN interfaces. They
are the sum of the same persisted, counter-derived `traffic_aggregates` rows that
draw the history graph, at the one resolution the range selects, for buckets whose
start lies in `[start, end)`. They are never derived from displayed rates or chart
points, and SNMP totals are never combined with NSEL/NetFlow usage.

Buckets without a counter delta — no poll, a counter reset or discontinuity, or a
rejected sample — are reported as missing coverage, not as zero traffic. The
response includes per-direction coverage against the expected bucket count
(`complete`, `partial` or `unavailable`); with no data in the period the totals are
unavailable rather than zero. A missed poll's delta is spread proportionally across
the buckets it spans, as before, and remains marked approximate. Because interface
aggregates already exist per interface, summing all enabled WAN interfaces counts
each interface once; interfaces that measure the same link should not both be
marked as WAN.

## Automatic observed-endpoint usage

Download and upload usage is recorded automatically for every observed endpoint IP
inside the enabled local networks (`traffic_local_networks`, the same topology flow
accounting uses), per traffic source and exporter. No Asset Manager record, managed
IP record, Uptime monitor or device tracking is required, and none is created.

- **Pipeline.** The existing collector's `process_records` adds each accepted flow
  after replay protection and cumulative-counter conversion, so a flow contributes
  once. Contributions are merged per datagram and written as one sorted multi-row
  upsert. There is no new collector, decoder, worker or inventory.
- **Endpoints and NAT.** Only the original (pre-NAT) source and destination are
  counted. Translated addresses are never counted, so an inside host reached only
  through a public mapped address is not attributed from that flow.
- **Directions.** Directional NSEL deltas: the initiator uploads forward and
  downloads reverse bytes; the responder the opposite. A unidirectional NetFlow
  record is the source's upload and the destination's download. A LAN-to-LAN flow
  is usage for both endpoints.
- **Storage.** `traffic_endpoint_aggregates` holds one row per endpoint IP,
  resolution, UTC bucket, source, exporter and direction, at 5-minute, hourly and
  daily resolution. The primary key is the upsert target and per-IP history path;
  one `(bucket_seconds, bucket_start)` index serves reports and retention. No raw
  flows, identity or monitoring preference is stored.
- **Retention.** The existing hourly Network Traffic retention job removes rows
  older than the configured five-minute (default 7 days), hourly (90 days) and
  daily (365 days) tiers. Each resolution is written at ingestion, so there is no
  rollup to double count, and deletion by cutoff is idempotent.
- **Measured cost** (PostgreSQL 16, synthetic NSEL): about 254 bytes per row
  including indexes; 9,082 rows and about 2.2 MB per continuously active endpoint
  at full default retention (about 220 MB for 100 and 1.1 GB for 500 endpoints).
  Ingestion adds 3 statements and 1 write per single-record datagram, and 0.3
  statements and 0.1 writes per flow at ten records per datagram.

## Device Usage

The authenticated **Monitoring → Network Traffic → Device Usage** tab reports the
automatic observed-endpoint usage for 24-hour, 7-day, 30-day, 90-day and bounded
custom ranges, with server-side search, sorting and pagination, at the one
persisted resolution the range selects. SNMP WAN counters are not included.

Each row is one source/exporter context for an endpoint IP. Contexts are never
added together: when one address is measured by more than one source or exporter
each keeps its own row, labelled as a separate source observation, and the
summary reports per-source totals instead of a combined total that could count
the same traffic twice. Contexts tied to one permanent asset for their whole span
share a row when at most one of them carries usage. Endpoints seen by discovery
without byte data show "Traffic observed — usage unavailable"; usage is never
estimated from observation counts.

Identity is unidentified, recognised (unconfirmed or ambiguous evidence) or a
confirmed asset. An IP address, hostname or pending assignment alone never
confirms an asset. A confirmed asset that did not hold the address for the whole
reported span is marked as the current holder, because the row reports the
address's usage. Asset names and links are returned only with Asset Manager
access. Optional device tracking (the former monitoring control) is shown only as
a tracking label; it never hides or adds usage. Coverage is an observed-bucket
indication and may be partial.
