# IP/WAN Monitor

IP/WAN Monitor is a background collector for ICMP availability, latency and packet-loss evidence. Opening a dashboard or detail page only reads retained observations; it never triggers a network probe. The explicit **Check now** and VLAN/IP Manager **Ping** actions are the exceptions because they are initiated by a user.

## Health and outages

Each monitor has warning and critical latency/packet-loss thresholds plus a consecutive-failure threshold. A failed probe is recorded immediately, but an outage opens only when the configured failure count is reached. Recovery closes the active outage and creates a recovery event. Warning, critical, outage and recovery transitions are retained in the event feed.

## Dashboard collection rate

The dashboard defaults to each monitor's saved schedule. Selecting Live, 5 seconds, 10 seconds, 1 minute or 5 minutes temporarily replaces those schedules while that browser dashboard remains active. Live starts the next four-sample ICMP pass as soon as the previous non-overlapping pass completes. Collection pauses when the tab is hidden and the override uses a short-lived per-browser lease so normal record schedules resume after the dashboard closes or loses contact.

## Retention

- Raw checks: 24 hours.
- Five-minute summaries: 30 days.
- Hourly summaries: 365 days.
- Completed outages and events: 365 days.

Retention maintenance runs from the collector, aggregates complete time buckets, and removes data beyond the configured v2 tiers. The detail page automatically combines raw and summarised data for its 24-hour, 7-day, 30-day and 1-year views.

## VLAN/IP Manager integration

A managed IP record shows its current monitor state, last latency, 24-hour availability, average latency, outage count and recent availability timeline. The monitor detail page links back to the managed IP record and provides shortcuts to DNS Manager and Domain Manager.

## Notifications

The data model retains the existing notification switch, while notification-profile selection is deliberately shown as a future placeholder. No notification delivery is performed by this version.
