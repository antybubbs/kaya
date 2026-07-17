# Kaya v0.24.0

This release brings a redesigned live dashboard, expanded DNS intelligence, safer record management, mobile and PWA improvements, and additional protection for the public demo.

## Highlights

- A modular operational dashboard with live, silent tile refreshes.
- Configurable dashboard refresh intervals of 10 seconds, 30 seconds, 1 minute, or 5 minutes.
- Major DNS Manager improvements, including insights, investigations, reports, provider health, client visibility, and recognised-device tracking.
- Danger Zone deletion controls across Kaya modules, with confirmation and related-record cleanup.
- Installable Progressive Web App support and improved responsive navigation.
- Stronger public-demo isolation and visitor privacy.

## Dashboard

- Reworked the dashboard into configurable operational widgets.
- Added silent background refreshes so tile data stays current without reloading the page.
- Added a dashboard refresh interval setting under **Site Administration > General**.
- Simplified the live indicator to display **Live** without a seconds counter.
- Added dashboard layout editing, widget management, sizing, ordering, and monitor mode.
- Improved stale-data handling and source timestamps.
- DNS-backed tiles now refresh stale provider data before rendering in normal installations.
- Added `no-store` cache handling for dashboard snapshots.
- Improved widget failure isolation so one unavailable service does not break the dashboard.

## DNS Manager

- Added DNS Insights with critical, warning, and informational findings.
- Added provider health, query activity, blocked-query, active-client, and attention summaries.
- Added recognised-device tracking and known-hostname management.
- Added DNS investigations and investigation deletion.
- Added improved reports, query-log filtering, client views, and blocklist controls.
- Added safer analysis locking, failed-provider throttling, and snapshot retention.
- Fixed Pi-hole Gravity responses, domain inspection, domain query handling, and several DNS insight edge cases.
- Improved degraded, disconnected, stale, and unavailable provider states.

## Danger Zone deletion

Added confirmed deletion workflows for:

- IP addresses and their related monitor, remote-access, and custom-field records.
- Licences and associated custom-field values.
- Hardware assets and attachments, including uploaded files.
- Remote Manager targets and session recordings.
- Network monitors and check history.
- DNS investigations.
- Manual backup records.
- Runbook pages and spaces.
- Compute hosts and associated workloads, metrics, events, inventory, and backup jobs.
- Racks and rack items.
- Domain records.
- Custom fields and managed-list values.

Deletion actions require the appropriate editor or administrator permission, CSRF validation, and an explicit confirmation.

## Mobile and PWA

- Added an installable web-app manifest and service worker.
- Added offline navigation fallback and update notifications.
- Improved the mobile navigation drawer and responsive layouts.
- Improved tables, action buttons, headings, and smaller-screen presentation.
- Authenticated pages, API responses, uploads, remote sessions, WebSockets, and mutations are not stored in the service-worker cache.

## Public demo safety

- Blocked all Danger Zone deletion requests in demo mode.
- Blocked shared dashboard preference changes and hid dashboard editing and monitor controls.
- Prevented dashboard refreshes from contacting configured DNS providers.
- Kept Remote Manager connections, backup operations, network checks, DNS mutations, and background infrastructure monitoring disabled.
- Removed visitor IP addresses and browser user-agent strings from stored demo sessions and audit activity.
- Retained the daily seed-database and upload reset process.

Non-destructive sample-data editing remains available in the demo and is cleared by the scheduled daily reset.

## Reliability and maintenance

- Added database migrations for dashboard preferences, DNS insights, statistics snapshots, and recognised devices.
- Improved dashboard, DNS, PWA, and demo-mode automated coverage.
- Added documentation for the dashboard, DNS Manager, database changes, and mobile/PWA behavior.
- Improved error handling so provider failures preserve the most recent successful data.

## Validation

- 56 automated tests passed.
- 13 demo route-safety subtests passed.
- Full Python syntax validation passed.
- Git whitespace and patch validation passed.

## Upgrade notes

No manual database migration is required for the standard SQLite deployment. Kaya applies the required schema additions during startup. As always, back up the Kaya database and uploads before upgrading.
