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
