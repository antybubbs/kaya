# Kaya notifications

Kaya has one central notification framework for in-application history, optional PWA Web Push, and future delivery channels. Modules publish registered events through `app.services.notifications.publish`; modules must not contact push or email providers directly.

## Administrator setup

Open **Site Administration → Notifications**. In-application notifications are enabled by default. Push and email are disabled by default and retain user choices while disabled. Configure retention, category policies, cooldowns, and whether users may customise preferences there.

Use **Send in-app test** on that page to verify the central publication path for the signed-in administrator. The result reports in-app creation separately from Push and Email, so missing VAPID or mail configuration cannot mask a working in-app channel.

Web Push requires an HTTPS Kaya origin (browser localhost exceptions are suitable only for development) and these environment variables:

```text
VAPID_PUBLIC_KEY=<URL-safe public application server key>
VAPID_PRIVATE_KEY=<private VAPID key or key file accepted by pywebpush>
VAPID_SUBJECT=mailto:admin@example.invalid
```

Generate VAPID keys with a reviewed Web Push/VAPID tool outside Kaya. Never commit private keys. Restart Kaya after changing the environment. The administration page displays only a short public-key identifier; it never returns or renders the private key.

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

The notification tables and non-secret policy are part of the normal database backup. Push subscriptions are present only as encrypted ciphertext. `VAPID_PRIVATE_KEY` is deliberately outside the database and must follow the deployment's secret backup process. After a restore to a different origin or after VAPID rotation, revoke old devices and have users register again.

## Developer integration

Register the event contract in `app/services/notification_registry.py`, then publish only after the source state transition has been committed:

```python
from app.services.notifications import publish

publish(
    db,
    event_type_id="ipwan.host.offline",
    title="Host offline",
    message="Core Router is no longer responding.",
    source_entity_type="network_monitor",
    source_entity_id=monitor.id,
    target_route=f"/networking/ip-wan-monitor/{monitor.id}",
    deduplication_key=f"ipwan:host:{monitor.id}:offline",
)
```

The source module must use a stable deduplication key, publish a recovery transition where applicable, and provide only text safe for every resolved recipient. Recipient resolution filters inactive accounts and users without module allocation. Resource-specific features must supply explicit recipient IDs only after performing their own object-level access check.

IP/WAN offline notifications use `ipwan:host:{monitor_id}:offline` for the full lifetime of an outage. The scheduler reconciles confirmed offline monitors once after startup and creates only a missing active event. Both scheduled checks and **Check now** call the same result handler, so their transition and notification rules are identical.

## Troubleshooting

- **Push disabled:** enable the channel and browser registration in Site Administration.
- **Not configured:** provide both VAPID keys and restart Kaya.
- **Permission denied:** reset the notification permission in browser site settings.
- **iPhone/iPad guidance:** launch the installed Home Screen PWA.
- **No delivery:** confirm HTTPS/proxy scheme, active device state, category/user policy, and worker health. Provider failures are classified in delivery records without sensitive response content.
- **No IP/WAN notification:** confirm the framework, in-app channel, event category, user preference, and IP/WAN module allocation. The former hidden per-monitor `notify_enabled` field is not an active notification policy; central category and user policy are authoritative.
- **After restore or URL change:** remove stale devices and register again.
