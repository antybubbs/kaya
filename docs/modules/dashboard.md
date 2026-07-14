# Dashboard Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

The Dashboard is the authenticated landing page for Kaya. It gives the user a high-level operational entry point into the application.

## Routes

- `/dashboard`

## Models Used

- User/session context
- Compute summary data from compute models

## Workflows

- Authenticated user opens dashboard after login.
- Dashboard renders server-side using current application context and available compute summary data.

## Permissions

- Requires any authenticated user.

## Dependencies

- Auth/session state
- Compute summary service/data where available

## Edge Cases And Risks

- Dashboard usefulness depends on available module data.
- Compute summary values depend on background polling and/or agent check-ins.

## DNS Manager Summary Panel

The main Dashboard includes a compact DNS Manager summary beneath CPU, memory and storage utilisation and before the VM / Docker Manager launch panel. It answers whether the selected DNS provider is healthy and whether an insight requires attention without reproducing detailed DNS reports.

The panel uses stored DNS analysis snapshots and never contacts the DNS provider during Dashboard rendering. It shows:

- Real provider status and stored-data freshness.
- Queries and blocked-query totals for a current local-day snapshot.
- Unique stable client identities present in stored snapshots from the previous 24 hours.
- Unacknowledged active critical and warning insight counts.
- One featured insight, selected deterministically by critical, warning, information, then recency.

Resolved, dismissed and acknowledged insights do not count toward Attention. Authenticated users see the same aggregate DNS information they can already access in DNS Manager. Multiple-provider installations follow the configured default provider and do not combine unrelated totals.
