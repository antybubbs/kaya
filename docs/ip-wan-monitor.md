# IP/WAN Monitor

IP/WAN Monitor is a background collector for ICMP availability, latency and packet-loss evidence. Opening a dashboard or detail page only reads retained observations; it never triggers a network probe. The explicit **Check now** and VLAN/IP Manager **Ping** actions are the exceptions because they are initiated by a user.

## Health and outages

Each monitor has warning and critical latency/packet-loss thresholds plus confirmation counts for degraded, failed and recovered checks. Hosts may inherit the Site Administration defaults or retain custom values. Inherited values change with the site defaults; custom values remain attached to that monitor.

State is evaluated centrally by the collector. A threshold breach is retained on its observation immediately, while the host changes to Warning or Critical only after its degraded confirmation count. A responding Critical host is not treated as Offline. Failed checks become Offline only after the configured failure count. An Offline host becomes Recovering after its first successful response and returns to Healthy after its recovery count; the explicit Recovering display can be disabled without bypassing confirmation. Maintenance mode records observations with blue maintenance severity while suppressing new incidents, and paused monitors are excluded from collection.

Confirmed threshold breaches create degraded incidents. Confirmed availability failures create offline incidents with the first failure, confirmation time, failure count, timeout and last successful response recorded as structured, non-secret metadata. Incidents close only after the applicable recovery criteria. Automatic state changes are retained in the event feed.

Default thresholds are managed under **Site Administration → Module Settings → IP/WAN Monitor**. Per-host inheritance and overrides are managed in the existing **VLAN/IP Manager → host → Services → IP/WAN Monitor** section or on the monitor detail Settings tab. Editors may change per-host values; global defaults remain administrator-only.

## Detail workspace

The monitor detail workspace presents current health, response time, packet loss, recent heartbeat observations, incidents, checks and settings. Apache ECharts 6.1.0 is vendored locally so interactive charts work under Kaya's self-only Content Security Policy and in offline deployments.

The Performance tab is a selected-period workspace with 1-hour, 6-hour, 24-hour, 7-day, 30-day, 90-day, 1-year and custom date/time ranges. It updates in place and shows the exact site-timezone range and active resolution. Preset resolutions progress from raw checks through 1-minute, 5-minute, 30-minute, 2-hour, 12-hour and daily buckets; custom ranges select the matching resolution automatically. Existing retained buckets are reused and coarser retained evidence is never presented as finer data.

One shared timeline combines a latency average with its genuine minimum/maximum band, visually quiet packet-loss events, optional jitter and availability, configured threshold lines, incident/recovery markers and optional maintenance or paused periods. It retains one ECharts instance across range and theme changes, supports a shared crosshair, hover details, pan, zoom and reset, and resizes with its panel. Warning, critical and offline periods are shaded without changing incident evaluation. Missing retained measurements remain **No data** rather than becoming zero.

The 16 selected-period summary values, incident evidence and paginated table come from the same bounded response. Raw periods use individual checks; longer periods use server-side aggregation and retained statistics. Older buckets created before minimum latency and jitter retention was added expose those fields as unavailable rather than fabricating them. Percentiles over retained periods are explicitly identified as weighted bucket-average percentiles. Partial ranges show the first available observation, and empty ranges show a purpose-built message.

Performance-table filtering, sorting and pagination are server-side. Selected-period CSV export is bounded to 5,000 displayed buckets, neutralises spreadsheet formula prefixes in text fields, requires the existing IP/WAN Monitor viewer permission and creates the normal redacted export audit event. Changing range, overlays, table pages or zoom does not create audit noise.

Raw checks are searched, state-filtered and paginated server-side in 50-row pages, and can be exported as CSV. Exports are limited to 10,000 rows, neutralise spreadsheet formula prefixes in text fields, require module access and produce an audit record.

## Live dashboard

Every dashboard card uses a five-minute rolling ECharts response-time graph made exclusively from stored monitor observations. The browser retrieves observations newer than its last observation ID; it never launches a ping or changes a monitor's saved interval. Multiple dashboards therefore consume the same check result. Duplicate IDs are ignored and data outside the five-minute browser window is discarded.

Cards use the backend state and reason, independently of the browser feed state. Healthy, Warning, Critical, Offline, Recovering, Maintenance, Paused and Unknown have restrained theme-aware shading plus text status. A feed reconnect changes only the LIVE indicator. Each observation stores its own health severity, so later threshold changes do not recolour retained raw or aggregate history. Failed checks remain graph gaps with failure markers rather than zero-millisecond responses.

Dashboard summaries distinguish Healthy, Warning, Critical, Offline and Paused monitors and include active incidents, real configured checks per minute, average latency and 24-hour availability. Successful response times retain decimal precision; values below one millisecond display as `<1 ms` instead of `0 ms`.

Each dashboard ECharts instance receives its complete configuration once. Polls update only rolling axis bounds, state-aware series data and incident markers; the age clock does not repaint charts. Theme changes update mounted chart styles through `setOption()` without replacing cards or recreating chart instances.

The grid uses at most three columns, reduces to two below 1650 CSS pixels and one below 950 CSS pixels, and allows metrics, footers and actions to wrap. Charts use contained labels and a per-chart ResizeObserver, covering window resizing, sidebar changes, responsive grid changes and browser zoom. Observers are disconnected on navigation, and reduced-motion preferences disable heartbeat and state-attention animations.

For editors and administrators, the Active check rate selector temporarily overrides the shared backend scheduler while the dashboard is visible: Live every second, or fixed 5-second, 10-second and 60-second intervals. The browser renews a short lease but does not perform probes itself. If several dashboards are open, the fastest active rate wins. Hiding or leaving the dashboard releases its lease, and abandoned leases expire after 25 seconds. The saved per-monitor intervals then resume for historical collection. Viewer sessions can read the live feed but cannot create an override.

The card chart advances its time axis continuously and temporarily holds the latest genuine value at the live edge between backend results. That held edge exists only in the mounted ECharts series: it is never persisted, exported, counted or passed through health/incident evaluation. The next stored result replaces the held edge and joins the retained series. When the dashboard opens, it loads the full five-minute stored window, or the persisted last result as an older anchor when the window is otherwise empty.

Each monitor retains its own backend check interval for collection when no authorised dashboard override is active. Editor and administrator users can configure a five-second interval from the monitor or VLAN/IP record. The shared scheduler checks due monitors once per second and uses a non-blocking per-monitor lock, so a slow check is skipped on the next scheduling pass rather than overlapped or queued.

### Wallboard and saved layouts

Authenticated users can reorder overview cards and open the standalone Wallboard at `/monitoring/ip-wan-monitor/wallboard`. Card order and Wallboard presentation preferences are retained server-side per user; new monitors append to an existing layout and stale monitor identities are removed when preferences are read. The Wallboard removes normal Kaya navigation, supports Auto, 2, 3, 4, 5, 6 and 8-column layouts, Comfortable, Compact and Dense densities, container-responsive cards, optional browser full screen and immediate display toggles.

The Wallboard consumes the existing batched live observation feed and mounted ECharts instances. It does not create another collector or one request per card. The Controls panel defaults to the Live rate and offers 5-second, 10-second and 60-second alternatives through the existing short backend override lease. Authenticated overrides require editor access. Shared overrides require an active restricted Wallboard session, its CSRF token and the Allow display-setting changes permission. Leaving or locking the display releases the lease, and abandoned leases expire automatically.

Site administrators with IP/WAN Monitor module access can configure one shared Wallboard under **Site Administration > Module Settings > IP/WAN Monitor**. A shared link uses a random encrypted-at-rest URL identifier plus a separately configured Argon2-hashed PIN or passcode. Successful challenges create an opaque, hashed, revocable Wallboard session that is separate from the normal Kaya session and stored in an HttpOnly, path-scoped, SameSite cookie. The shared feed returns only allowlisted monitors, and every optional detail, Check now, Pause, reorder or display-setting operation is re-authorised server-side. The default shared configuration is disabled and read-only.

Challenge failures are keyed by the trusted client IP and Wallboard identity. Five failures within ten minutes lock that source for fifteen minutes; administrators can clear lockouts. Disabling sharing, replacing the passcode, regenerating or revoking the URL, and explicitly invalidating sessions remove existing shared access. Raw passcodes, session tokens and URL identifiers are excluded from audit metadata and request-path audit records.

The incremental feed is authenticated by the normal IP/WAN Monitor module gate, accepts only a non-negative last-observation ID, returns at most 1,000 observations from the current five-minute window, and exposes only the fields required by the charts. Changing the active rate requires the appropriate authenticated or restricted-session permission, a valid CSRF token and allowlisted rate/client values; mode changes are audited without recording the client token. Checks use a composite monitor/timestamp index for rolling-window queries.

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
