# IP/WAN Monitor

IP/WAN Monitor is a background collector for ICMP availability, latency and packet-loss evidence. Opening a dashboard or detail page only reads retained observations; it never triggers a network probe. The explicit **Check now** and VLAN/IP Manager **Ping** actions are the exceptions because they are initiated by a user.

## Health and outages

Each monitor has warning and critical latency/packet-loss thresholds plus confirmation counts for degraded, failed and recovered checks. Hosts may inherit the Site Administration defaults or retain custom values. Inherited values change with the site defaults; custom values remain attached to that monitor.

State is evaluated centrally by the collector. A threshold breach is retained on its observation immediately, while the host changes to Warning or Critical only after its degraded confirmation count. A responding Critical host is not treated as Offline. Failed checks become Offline only after the configured failure count. An Offline host becomes Recovering after its first successful response and returns to Healthy after its recovery count; the explicit Recovering display can be disabled without bypassing confirmation. Maintenance mode records observations with blue maintenance severity while suppressing new incidents, and paused monitors are excluded from collection.

Confirmed threshold breaches create degraded incidents. Confirmed availability failures create offline incidents with the first failure, confirmation time, failure count, timeout and last successful response recorded as structured, non-secret metadata. Incidents close only after the applicable recovery criteria. Automatic state changes are retained in the event feed.

Default thresholds are managed under **Site Administration → Module Settings → IP/WAN Monitor**. Per-host inheritance and overrides are managed in the existing **VLAN/IP Manager → host → Services → IP/WAN Monitor** section or on the monitor detail Settings tab. Editors may change per-host values; global defaults remain administrator-only.

## Detail workspace

The monitor detail workspace presents current health, response time, packet loss, recent heartbeat observations, incidents, checks and settings. Apache ECharts 6.1.0 is vendored locally so interactive line charts, threshold and incident markers, zoom, pan and PNG export work under Kaya's self-only Content Security Policy and in offline deployments. The Performance tab supports 1-hour, 6-hour, 24-hour, 7-day, 30-day, 90-day and 1-year views. Longer browser views are reduced automatically to five-minute, hourly or daily points.

Raw checks can be filtered in the browser and exported as CSV. Exports are limited to 10,000 rows, neutralise spreadsheet formula prefixes in text fields, require module access and produce an audit record.

## Live dashboard

Every dashboard card uses a five-minute rolling ECharts response-time graph made exclusively from stored monitor observations. The browser retrieves observations newer than its last observation ID; it never launches a ping or changes a monitor's saved interval. Multiple dashboards therefore consume the same check result. Duplicate IDs are ignored and data outside the five-minute browser window is discarded.

Cards use the backend state and reason, independently of the browser feed state. Healthy, Warning, Critical, Offline, Recovering, Maintenance, Paused and Unknown have restrained theme-aware shading plus text status. A feed reconnect changes only the LIVE indicator. Each observation stores its own health severity, so later threshold changes do not recolour retained raw or aggregate history. Failed checks remain graph gaps with failure markers rather than zero-millisecond responses.

The grid uses at most three columns, reduces to two below 1650 CSS pixels and one below 950 CSS pixels, and allows metrics, footers and actions to wrap. Charts use contained labels and a per-chart ResizeObserver, covering window resizing, sidebar changes, responsive grid changes and browser zoom. Observers are disconnected on navigation, and reduced-motion preferences disable heartbeat and state-attention animations.

For editors and administrators, the Active check rate selector temporarily overrides the shared backend scheduler while the dashboard is visible: Live every 5 seconds, Standard every 30 seconds, Relaxed every 60 seconds, or Paused. The browser renews a short lease but does not perform probes itself. If several dashboards are open, the fastest active rate wins. Hiding or leaving the dashboard releases its lease, and abandoned leases expire after 25 seconds. The saved per-monitor intervals then resume for historical collection. Viewer sessions can read the live feed but cannot create an override.

Each monitor retains its own backend check interval for collection when no authorised dashboard override is active. Editor and administrator users can configure a five-second interval from the monitor or VLAN/IP record. The shared scheduler checks due monitors once per second and uses a non-blocking per-monitor lock, so a slow check is skipped on the next scheduling pass rather than overlapped or queued.

The incremental feed is authenticated by the normal IP/WAN Monitor module gate, accepts only a non-negative last-observation ID, returns at most 1,000 observations from the current five-minute window, and exposes only the fields required by the charts. Changing the active rate additionally requires editor access, a valid CSRF token and allowlisted rate/client values, and mode changes are audited without recording the client token. Checks use a composite monitor/timestamp index for rolling-window queries.

## Retention

- Raw checks: 30 days.
- Five-minute summaries: 90 days.
- Hourly summaries: 365 days.
- Daily summaries: unlimited.
- Incidents and events: unlimited.

Retention maintenance runs from the collector, aggregates complete time buckets, and rolls data through the default tiers without deleting incident history. The detail page automatically combines raw and summarised data.

## VLAN/IP Manager integration

A managed IP record shows its current monitor state, last latency, 24-hour availability, average latency, outage count and recent availability timeline. The monitor detail page links back to the managed IP record and provides shortcuts to DNS Manager and Domain Manager.

## Notifications

The data model retains the existing notification switch, while notification-profile selection is deliberately shown as a future placeholder. No notification delivery is performed by this version.
