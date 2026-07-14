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

Kaya stores hourly provider-neutral aggregate snapshots rather than duplicating raw DNS queries. Snapshots include supported totals and bounded per-client/response aggregates. Retention defaults to 30 days and cleanup runs after successful analysis. Trend rules only run when the required baseline and minimum volumes exist.

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
- `dns_default_provider_id`
- Provider base URL
- Auth method
- Encrypted provider secret
- SSL verification
- Timeout

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
- Stable device matching prefers MAC address, then provider client identifier, hostname and finally IP address. Asset linkage is optional because the current DNS provider payload does not supply a Kaya asset relationship.
