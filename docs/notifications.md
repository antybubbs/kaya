# Kaya notifications

Kaya has one central, backend-driven notification framework for in-application history, optional PWA Web Push, and email. Operational modules enqueue registered events through `app.services.notification_outbox.enqueue_notification` in the same transaction as their source transition; modules must not contact Push or email providers directly.

The durable pipeline is:

`source observation → committed state transition + outbox → notification event → user notification → channel delivery attempt → provider acceptance`

The browser and PWA are delivery clients only. The retained outbox, delivery and reconciliation workers run without logged-in users or open Kaya clients. Worker heartbeats, restarts, queue age, retry state and quarantined work are shown under **Site Administration → Notifications**.

## Administrator setup

Open **Site Administration → Notifications**. In-application notifications are enabled by default. Push and email are disabled by default and retain user choices while disabled. Configure retention, category policies, cooldowns, and whether users may customise preferences there.

Use **Send in-app test** on that page to verify the central publication path for the signed-in administrator. The result reports in-app creation separately from Push and Email, so missing VAPID or mail configuration cannot mask a working in-app channel.

Web Push requires an HTTPS Kaya origin (browser localhost exceptions are suitable only for development). From **Site Administration → Notifications**, an administrator can generate a P-256 VAPID key pair by supplying either a contact email or an HTTPS contact URL. Kaya validates the pair with its Web Push library before committing it, encrypts the private key with the installation's Fernet `ENCRYPTION_KEY`, and stores only ciphertext plus the public key, fingerprint, subject, label and lifecycle timestamps.

Generate, rotate, enable, disable, delete, test and revoke-all actions are administrator-only, CSRF-protected, rate-limited and security-audited. Rotation and deletion atomically revoke existing browser subscriptions. Disablement preserves the key pair, subscriptions, user preferences and notification history so it can be reversed without data loss.

Deployments may instead provide these environment variables:

```text
VAPID_PUBLIC_KEY=<URL-safe public application server key>
VAPID_PRIVATE_KEY=<private VAPID key or key file accepted by pywebpush>
VAPID_SUBJECT=mailto:admin@example.invalid
```

Environment-managed VAPID configuration always takes precedence over the database. All three values must be valid; partial or malformed deployment configuration fails closed and cannot be bypassed by a UI-managed key. Generate deployment keys with a reviewed Web Push/VAPID tool, never commit private keys, and restart Kaya after changing the environment. The administration page displays only non-sensitive status and public-key fingerprint data; it never returns or renders the private key.

Reverse proxies must preserve the real HTTPS scheme using Kaya's trusted-proxy configuration. If the browser does not consider the page a secure context, Kaya explains that push is unavailable and does not open a permission prompt.

## User enablement and devices

Open **Profile → Notification Settings**. Select **Enable push notifications on this device** to begin the browser permission flow. Permission is never requested during page load. A denied permission must be changed in browser/site settings before Kaya can try again.

On supported iPhone and iPad versions, install Kaya from Safari using **Share → Add to Home Screen**, open the installed PWA, then enable push. Browser and operating-system support still varies.

Registered devices can be removed from the preference page. Signing out revokes this account's registered subscriptions, preventing notifications from continuing on a shared signed-out device. Administrators automatically revoke active subscriptions when disabling an account.

## Delivery and privacy

Push subscription material is encrypted using Kaya's configured Fernet encryption key. APIs return device metadata but never endpoints or subscription key material. Push payload routes are Kaya-relative paths without query strings or fragments, and the service worker independently validates them before opening or focusing a window.

To prevent subscription registration from becoming an SSRF primitive, Kaya accepts only HTTPS port 443 endpoints belonging to the browser push services used by Google/Chromium, Mozilla, Apple, and Microsoft; every delivery rechecks that DNS resolves only to public addresses and refuses redirects. A newly supported browser vendor may therefore require a reviewed allow-list update.

Push text may appear on a locked device. Secret Vault and Secure Send event types therefore replace caller-supplied titles/messages with a generic safe summary. Notification possession never grants access: the destination route performs its normal authentication, role, module, and object checks.

Delivery is asynchronous, bounded to four retries with backoff, and permanently expires subscriptions rejected with HTTP 404 or 410. Provider response bodies and endpoints are not logged.

## Retention, backup, and restore

Read notifications default to 90 days. Unread notifications have a 365-day safety limit. The cleanup worker runs hourly. Dismissal or retention does not remove the corresponding security/audit record.

The notification tables, UI-managed encrypted VAPID private key and non-secret policy are part of the normal database backup. Push subscriptions are also present only as encrypted ciphertext. A successful restore of UI-managed VAPID material and subscriptions requires the original separately protected `ENCRYPTION_KEY`, consistent with Kaya's other encrypted secrets. Never store that key only inside the database backup.

Environment-managed `VAPID_PRIVATE_KEY` remains outside the database and must follow the deployment's secret backup process. After a restore to a different origin, key rotation or key deletion, revoke stale devices as needed and have users register again.

## Developer integration

Register the event contract in `app/services/notification_registry.py`, then enqueue it before committing the source state transition:

```python
from app.services.notification_outbox import enqueue_notification

enqueue_notification(
    db,
    event_type_id="ipwan.host.offline",
    title="Host offline",
    message="Core Router is no longer responding.",
    source_entity_type="network_monitor",
    source_entity_id=monitor.id,
    target_route=f"/networking/ip-wan-monitor/{monitor.id}",
    deduplication_key=f"ipwan:host:{monitor.id}:offline",
)
db.commit()
```

The source module must use a stable active-condition key or operation-specific key, publish a recovery transition where applicable, and provide only text safe for every resolved recipient. Recipient resolution filters inactive accounts and users without module allocation; active administrators are infrastructure-wide recipients even on older installations missing a materialised allocation row. Resource-specific features must supply explicit recipient IDs only after performing their own object-level access check.

High Availability publishes the Pi-hole-specific `pihole.*` event family only after its source transition has committed. Controlled failover and failback use the failover run UUID plus lifecycle stage in their deduplication keys. A notification persistence or delivery failure cannot roll back a completed network transition. The operation page retains only safe diagnostic counts (event status, recipients, and queued/delivery status by channel), never subscription endpoints or provider output.

IP/WAN offline notifications use `ipwan:host:{monitor_id}:offline` for the full lifetime of an outage. Every changed derived state is recorded in `network_monitor_transitions` and references its triggering observation. The offline transition and notification outbox commit together. Startup and five-minute reconciliation create only a missing active event and resolve stale active conditions. Both scheduled checks and **Check now** call the same result handler, so their transition and notification rules are identical.

## Delivery semantics

Push state is reported accurately as `queued`, `processing`, `accepted_by_push_service`, `temporary_failure`, `expired_subscription`, `cancelled`, or `retry_exhausted`. Provider acceptance does not prove that iOS displayed the notification. A failed Push or email attempt never removes the in-application record.

Kaya currently supports one application process per SQLite database. Workers use durable claims and recover stale claims after restart, but multiple application replicas sharing the same SQLite file are not a supported deployment topology.

## Diagnostics

The administrator in-app test, immediate Push test, delayed 30–60 second test, and simulated production event all enter the notification outbox. The safe pipeline report exposes stage counts and reason codes without endpoints, subscription keys, VAPID material, addresses or payload secrets. Registered event types without a proven production publisher remain visible in the registry report as unavailable and are not offered as configurable categories.

## Troubleshooting

- **Push disabled:** enable Web Push in Site Administration; disabling preserves keys, devices, preferences and history.
- **Not configured:** generate keys in Site Administration, or provide a complete valid deployment-managed VAPID configuration and restart Kaya.
- **Invalid deployment configuration:** correct or remove all deployment VAPID values. Kaya deliberately will not fall back to UI-managed keys.
- **Permission denied:** reset the notification permission in browser site settings.
- **iPhone/iPad guidance:** launch the installed Home Screen PWA.
- **No delivery:** confirm HTTPS/proxy scheme, active device state, category/user policy, and worker health. Provider failures are classified in delivery records without sensitive response content.
- **No IP/WAN notification:** confirm the framework, in-app channel, event category, user preference, and IP/WAN module allocation. The former hidden per-monitor `notify_enabled` field is not an active notification policy; central category and user policy are authoritative.
- **After restore or URL change:** remove stale devices and register again.
