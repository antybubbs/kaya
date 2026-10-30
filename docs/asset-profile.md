# Unified asset profile

The Asset Manager detail page now presents a bounded **Device Identity &
Connected Services** profile. It reuses existing identity evidence, reviewed
network assignments, DHCP lease history, DNS-recognised clients, managed IP
records and Network Traffic discovery links. It does not collect providers,
create assets or managed IP records, enable monitoring, or alter accounting.

`GET /infrastructure/asset-manager/{asset_id}/profile` returns the same
permission-aware data used by the detail page. Asset Manager access is
required. DNS, VLAN/IP Manager and Network Traffic sections are returned only
when the requesting user has the corresponding module access; unavailable
sections are returned as `null` rather than leaking retained records.

Administrator-only mutations are scoped to the asset and require CSRF:

- `POST .../{asset_id}/identity-evidence/{evidence_id}/confirm`
- `POST .../{asset_id}/identity-evidence/{evidence_id}/revoke`
- `POST .../{asset_id}/network-assignment/{assignment_id}/confirm`
- `POST .../{asset_id}/network-assignment/{assignment_id}/close`

Each mutation reloads the referenced row, verifies that it belongs to the
asset in the URL, validates its current state, writes a redacted audit event,
and commits the decision atomically. Existing history remains retained. A
review action never creates an asset, relinks a device automatically, creates
an IP record, enables device monitoring, or changes collection attribution.

Resolver results remain read-only and bounded. Suggested, ambiguous, stale and
unresolved evidence is not treated as a confirmed identity, and future API
callers must retain the same module and object-level permission checks.

## Historical profile reporting

The Asset Manager detail page includes read-only Overview, Network & DHCP, DNS,
Network Traffic, Activity and Lifecycle sections. The period selector supports
24 hours, 7 days, 30 days, 90 days and a validated custom range. The reporting
service reads source-owned tables with bounded result limits; it does not copy
records into Asset Manager, change traffic attribution, or merge SNMP WAN
totals with device usage.

Traffic history comes from the automatic observed-endpoint usage, read through
the asset's confirmed network assignments; nothing is copied. A bucket counts
only when a confirmed assignment (current VLAN context, in source/exporter scope)
held the address for the whole bucket and no other asset's confirmed assignment
overlapped it. Buckets crossing a handover or with competing ownership are
excluded and reported as excluded coverage, so a reused or reassigned address
never moves another device's traffic. When more than one source or exporter
measured the address, per-source totals are shown instead of a sum. Optional
device tracking is separate and is not needed for this history. DNS and Uptime
sections are independently permission-gated. Missing observations are shown as
unavailable rather than zero.

When a confirmed, currently valid relationship exists, DNS client and VLAN/IP
detail pages offer a link back to the Asset Manager parent. Existing specialist
routes remain unchanged for deep links and for users without Asset Manager
access.
