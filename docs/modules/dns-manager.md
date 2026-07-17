# DNS Manager Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

DNS Manager monitors and inspects DNS provider data. The current implemented provider is Pi-hole.

The module separates three related views:

- **Dashboard** shows current provider status and headline statistics.
- **Insights** explains rule-based conditions that may deserve investigation or action.
- **Reports** retains detailed investigation records and historical workflows.

Insights are advisory. They identify supported observations in available DNS data and must not be treated as definitive proof of a security incident.

## Routes

- `/networking/dns-manager`
- `POST /networking/dns-manager/insights/analyse`
- `POST /networking/dns-manager/insights/{insight_id}/acknowledge`

## Models Used

- `DNSProviderConfig`
- `DNSInvestigation`
- `RemoteManagerSetting`
- `DNSInsight`
- `DNSStatisticsSnapshot`
- `DNSRecognisedDevice`

## Workflows

- Dashboard provider status and summary.
- Query log inspection.
- Client inventory from Pi-hole network devices, DHCP leases, and query data.
- Local DNS records display.
- DHCP leases display.
- Blocklist display.
- Reports/investigations.
- Flag DNS queries for investigation.
- Generate and filter provider-neutral DNS insights.
- Acknowledge active insights without resolving them.
- Preserve resolved insight history and reactivate recurring logical conditions.
- Retain bounded hourly aggregate snapshots for explainable comparisons.

## Insights And Severity

Insights use the categories System, Network Activity, Security, Devices, Usage Trend and Recommendation. Severity is always represented by both text and colour:

- **Critical:** an immediate operational issue, such as a disconnected provider.
- **Warning:** a supported condition that requires review or may develop into an issue.
- **Information:** a meaningful observation without urgent action.
- **Healthy:** a positive supported condition. The initial implementation avoids filling the page with unnecessary healthy cards.

Initial rules cover provider connectivity, stale analysis data, disabled blocking, supported blocklist age, new unrecognised devices, recognised-device IP changes, high client volume when a baseline exists, high blocked-query rate, excessive NXDOMAIN responses, repeated client requests for the same blocked domain, network-wide query-volume changes and linked recommendations.

The Analysis coverage area also retains the latest bounded evidence for top blocked domains, the clients contributing to each blocked domain, and the most active client-domain relationships. These are factual sample summaries rather than security conclusions. Each row links to the Query Log with the relevant client and domain filters preserved.

Rules are provider-neutral and skip themselves when their required capability is unavailable. A failed rule does not stop the remaining analysis.

## DNS Health Score

The score starts at 100 and uses deterministic deductions:

- Provider disconnected: 40 points.
- Blocking disabled: 15 points.
- Last successful analysis older than the stale threshold: 10 points.
- Other active critical insights: 15 points each.
- Other active warning insights: 4 points each.
- Operational-insight deductions are capped at 30 points.

Unsupported checks are shown as unavailable and do not reduce the score. Status bands are Excellent (90-100), Healthy (75-89), Attention Required (50-74), Poor (25-49), and Critical (0-24).

## Lifecycle

- **Active:** the latest successful evaluation still detects the condition.
- **Acknowledged:** an editor or administrator reviewed an active condition. Acknowledgement does not resolve it.
- **Resolved:** a supported rule was evaluated and the condition disappeared.

Recurring conditions reactivate the same stable record. First-detected history is preserved. Previous successful results remain stored when a new analysis fails.

## Baselines And Retention

Kaya stores hourly provider-neutral aggregate snapshots for trend analysis. It also retains a deduplicated, bounded sample of per-client DNS query events for the traffic history shown on client profiles. Traffic retention defaults to 30 days and can be configured independently; cleanup runs during successful analysis. Trend rules only run when the required baseline and minimum volumes exist.

First-run operational insights are available immediately. Trend insights remain unavailable until Kaya has collected sufficient comparable snapshots.

## Default Insight Thresholds

- Provider stale analysis: 1 hour.
- Blocklist age: information after 7 days; warning after 14 days.
- Client query increase: 100% with at least 50 queries in both periods.
- Network query change: 40% with at least 500 queries in both periods.
- Blocked-query warning: 35% with at least 50 client queries.
- NXDOMAIN warning: 25% with at least 50 client queries.
- Recognised-device inactivity: 7 days (extension point; no initial alert until reliable expected-device behavior exists).
- Snapshot retention: 30 days.

Thresholds are centralized in `DNSInsightThresholds` so a future settings interface does not require rule or template changes.

## Permissions

- Viewing requires authenticated user.
- Provider configuration is admin-only through Site Administration.
- Manual analysis and acknowledgement require editor or administrator access, CSRF validation and audit logging.

## Settings

- `dns_manager_enabled`
- `dns_collector_enabled`
- `dns_refresh_interval_seconds` (30 to 86,400 seconds)
- `dns_traffic_history_days` (1 to 3,650 days; default 30)
- `dns_default_provider_id`
- Provider base URL
- Auth method
- Encrypted provider secret
- SSL verification
- Timeout

## Background collection

When DNS Manager and background collection are enabled, Kaya starts one process-local collector task after application startup. Each pass refreshes every enabled provider sequentially, stores statistics and insight results, then waits for the configured interval. Settings are re-read before every pass, so enabling, disabling or changing the interval does not require a restart.

Provider network calls use their configured bounded timeout and run outside an active SQLite transaction. Collection uses a fresh database session per provider, does not overlap another pass, and yields to an already-running manual analysis of the same provider. Dashboard and ordinary page rendering continue to read stored results only.

## Persistent client intelligence

The collector retains every observed client in `dns_recognised_devices`. Existing retained devices are migrated in place and treated as known; their IDs and provider relationships are preserved. Identity matching prefers provider identifiers and validated, normalised MAC addresses, then uses conservative IP/hostname fallbacks. A hostname never silently merges records with different MAC addresses.

IP and hostname observations are stored in `dns_client_ip_history` and `dns_client_hostname_history`. Repeated observations update the existing history row and count rather than creating duplicates. `dns_client_events` records discovery, IP/hostname changes, user state changes, links, managed-record updates, merges, and other meaningful transitions.

The Clients tab and VLAN/IP enrichment read retained database data and never call Pi-hole during page rendering. Client profiles provide current observations, IP and hostname histories, top requested and blocked domains, a searchable paginated DNS lookup timeline, notes, and an explicit managed-record workflow. Pi-hole supplies DNS lookups rather than browser history, so Kaya does not claim to know full URLs or page paths.

## VLAN/IP Manager integration

DNS Manager owns observed data; VLAN/IP Manager remains the source of truth for managed records. The managed hierarchy is VLAN → Category → allocation/device. VLANs, Categories, and DHCP ranges are configured under Site Administration → Module Settings → VLAN/IP Manager.

A DNS client may hold one nullable `linked_ip_record_id`. Foreign-key deletion behaviour is `SET NULL`, so deleting either retained DNS data or a managed IP record never deletes the other.

Editors can confirm a link, unlink it, create a reviewed managed record from an observation, or explicitly update a managed IP. Automatic exact-MAC linking and automatic Dynamic-record IP updates are off by default. Static records are never updated automatically. VLAN inference uses the most-specific populated `VLAN.subnet_cidr`; equally specific matches require an explicit choice.

Suggested and exact IP/MAC matches can be confirmed from either the DNS client profile or the matching VLAN/IP record. Suggested records are injected ahead of the client profile's bounded search results so a valid match cannot disappear from the confirmation control.

Unlinked retained clients also appear in VLAN/IP Manager under **Observed DNS clients**. If Kaya finds a possible existing record, the row directs the user to review the link instead of offering a duplicate creation. Otherwise, **Create record** opens the standard VLAN/IP form with observed IP, MAC and hostname values prefilled. The record is only created after an editor reviews and submits that form; the DNS client is then linked automatically.

Client-management settings under Site Administration → Modules → DNS Manager include integration and suggestion switches, exact-MAC linking, Dynamic-record updates, stale threshold, history retention, VLAN/IP enrichment, and optional filling of an empty managed hostname.

## DHCP identity and retained lease history

Addresses inside an enabled `DHCPRange` are treated as temporary lease evidence, not stable device identity. Kaya reunites observations in those ranges by provider client ID or normalised MAC address. An IP-only managed-record link is rejected inside a DHCP range because a later lease holder may reuse the address.

Each provider lease is persisted as a time-bounded `DHCPLeaseHistory` row. When an address changes owner, Kaya closes the previous active interval and creates another rather than overwriting it. New `DNSClientTrafficEvent` rows retain both the observed client IP and applicable lease ID, so historical DNS activity remains attributable after address reuse. Existing retained history remains available during Pi-hole outages; configured retention and explicit Kaya deletion policies still apply.

## Dependencies

- Pi-hole v6 session-style auth.
- Legacy Pi-hole API fallback.
- DNS provider settings stored in database.

## Edge Cases And Risks

- Only Pi-hole is currently implemented.
- Pi-hole v6 and legacy fallback increase provider complexity.
- API token auth is effectively legacy behaviour for Pi-hole.
- DNS investigation creation is available to authenticated users.
- Pi-hole exposes only a bounded recent query window through the current integration; per-client rules describe that window rather than claiming complete-day coverage.
- Blocklist-age analysis is unavailable when the provider does not expose a defensible update timestamp.
- In-process locking prevents duplicate analysis within one Kaya process. Deployments with multiple independent workers should use one application worker until a shared job coordinator is introduced.
- The current VLAN/IP model has one managed name and assignment type rather than separate reservation/owner/location fields. DHCP ranges and lease intervals provide the dynamic layer without pre-creating every pool address.
- Stable device matching prefers provider client identifier and MAC address. Outside configured DHCP ranges, conservative IP/hostname fallback remains available. Asset linkage is optional because the current DNS provider payload does not supply a Kaya asset relationship.
