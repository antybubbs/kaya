# Kaya v0.26.0 Release Notes

Kaya v0.26.0 introduces the Notification Centre, optional PWA Web Push, durable background delivery, more resilient IP/WAN monitoring, quieter Pi-hole HA reporting, and automatic versioned database migrations. These notes cover changes since v0.25.8.

## Notification Centre and Web Push

- A new per-user notification inbox provides unread counts, dismissal, filtering, retained history, and links to the affected Kaya module.
- Users can manage notification preferences and registered Push devices. Administrators control framework channels, retention, event-category policy, cooldowns, and whether users may customise preferences.
- In-application notifications are enabled by default. Push and email remain disabled until configured and enabled by an administrator.
- Initial production publishers cover IP/WAN outage and recovery, failed Kaya-managed backup jobs, background-worker failures, and Pi-hole HA node, cluster, sync, failover, and failback events.
- Administrators can generate, rotate, enable, disable, test, and delete VAPID keys. UI-managed private keys are validated and encrypted with Kaya's `ENCRYPTION_KEY`.
- Deployments may instead provide `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, and `VAPID_SUBJECT`. Deployment-managed values take precedence and incomplete or invalid configuration fails closed.
- Push permission is requested only after explicit user action. Signing out or disabling an account revokes its active device subscriptions.

## Durable notification delivery

- Operational state changes and notification outbox work commit together. Browser sessions, open pages, and provider availability are not required for event creation.
- In-app history is created before optional Push or email delivery. Provider failure cannot roll back completed monitoring, backup, or HA actions.
- Delivery uses bounded retries and explicit queued, accepted, temporary-failure, expired, cancelled, and exhausted states.
- Dedicated outbox, delivery, and reconciliation workers expose safe health, restart, queue-age, retry, and quarantine diagnostics to administrators.
- Repeated polling and reconciliation retain one incident identity rather than creating notification storms.

## IP/WAN Monitor

- Monitor ordering persists per user across the dashboard and authenticated Wallboard. New monitors append automatically, deleted monitors are ignored, and Reset layout restores canonical order without changing unrelated settings.
- Monitor-order input is type-checked, size-limited, restricted to existing monitor IDs, and committed transactionally.
- Changed derived states retain the observation that caused them. Scheduled checks and **Check now** use the same transition and notification path.
- Offline transitions and notification work commit atomically. Startup and periodic reconciliation restore only missing active incidents and resolve stale ones without duplicating history.
- An independent watchdog supervises the monitor scheduler and safely reports and restarts unexpected exits or stale heartbeats.

## Pi-hole High Availability

- Pi-hole HA publishes central notifications for cluster degradation and recovery, node unreachability, automatic-sync failure, controlled failover/failback stages, and verified automatic failover completion.
- Notification failure cannot reverse a verified failover or failback. Operation history contains redacted channel counts rather than subscription or provider details.
- Operational standby readiness, recovery workflow, and configuration-sync job state are now separate live fields.
- Headline **HA Readiness** is derived from fresh safety invariants and the last valid current-generation sync evidence, not from a temporary recovery workflow label.
- Routine `PENDING`, `CHECKING`, `RUNNING`, `VERIFYING`, and `IN_SYNC` comparisons do not downgrade a healthy standby, reset its stability evidence, increment Attention Needed, emit critical notifications, or flood Activity.
- Controlled handover retains its existing independent recovery stability gate; this change does not weaken failover or failback safety.
- Genuine supported drift, stale generations, unsafe VIP/DHCP ownership, failed DNS/FTL, and stale signed observations still invalidate operational readiness and show their specific blocker.
- Active and recently completed standby validation counts as progress. **Recovery state appears stale** is reserved for a mismatch that persists beyond five minutes without a legitimate operation or meaningful progress.

## Versioned database migrations

- Kaya now uses Alembic for versioned migrations. Existing SQLite installations are backed up, validated, upgraded, and baseline-stamped automatically before user traffic or background services start.
- Pre-Alembic upgrades create a verified timestamped backup under `/app/data/backups` and use targeted schema validation. Migration failure aborts startup and reports the recovery location.
- Docker allows a 120-second startup grace period while retaining genuine unhealthy startup reporting.
- Administrators can inspect the current revision with `alembic -c /app/alembic.ini current` inside the container. See [Administrator Database Upgrades](../admin-database-upgrades.md).

## Interface and documentation

- Values calculated in powers of 1,024 are labelled KiB, MiB, GiB, and TiB.
- The README now includes a fuller capability guide across Kaya's modules and deployment model.
- Notification documentation covers setup, Web Push, privacy, retention, backup and restore, delivery semantics, diagnostics, and troubleshooting.

## Upgrade and security notes

- Pull and start the new Kaya image normally. Preserve `/app/data`, review available disk space, and protect migration backups as sensitive application data.
- Preserve the original `ENCRYPTION_KEY` separately from database backups. UI-managed VAPID private keys and encrypted Push subscriptions cannot be recovered without it.
- Web Push requires HTTPS, except for supported localhost development. Trusted reverse proxies must forward the real scheme.
- All three deployment-managed VAPID values must be supplied together and valid.
- Kaya supports one application process per SQLite database; multiple replicas sharing one SQLite file remain unsupported.
- Notification APIs retain authentication, active-session, role/module, CSRF, object-access, and bounded-input controls. Notification possession never grants access to its destination.
- Push endpoints are constrained to supported public browser providers over HTTPS port 443; redirects, private resolution, secret diagnostics, and provider response logging are rejected.
