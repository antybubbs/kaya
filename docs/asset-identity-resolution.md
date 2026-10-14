# Asset identity resolution

Phase 2 provides a read-only, provider-independent resolver in
`app/services/asset_identity_resolution.py`. It correlates an address and
observation time with existing DHCP lease history, DNS-recognised clients,
VLAN/IP Manager records represented by reviewed network assignments, and
Network Traffic discovery context. It does not create assets, IP records,
links, monitoring configuration, or new collection records.

The resolver returns bounded candidates with one of these states:

- `confirmed_match`: administrator-confirmed identity or time/context-valid
  reviewed assignment supports the observation.
- `suggested_match`: evidence is useful but requires administrator review.
- `ambiguous`: more than one asset or conflicting evidence may match.
- `unresolved`: evidence is absent, invalid, outside a current mapping, or is
  only an IP address.
- `stale`: retained evidence is no longer current when returned through
  `evidence_for_asset`.

All address matching is normalised by IP family and bounded by the supplied
observation time. DHCP reuse is evaluated against lease intervals. A VLAN-
bound asset assignment stores the CIDR that was current when it was confirmed;
if the VLAN is removed or its CIDR changes, the resolver does not present that
historical assignment as current. Network Traffic discovery additionally
requires a current enabled exporter-to-VLAN mapping. Translated or unsupported
discovery endpoint roles remain review-only.

The service is intentionally on-demand and has no HTTP routes or collector
integration. Future callers must enforce authentication, module access and
object-level permissions before exposing results. In particular, callers
must authorise access to the relevant asset, VLAN/IP record, DHCP/DNS source,
traffic source and exporter scope, and must not turn `suggested_match`,
`ambiguous`, `stale` or `unresolved` into an automatic mutation.

The result deliberately excludes raw DNS queries, flow payloads, credentials
and unrelated provider metadata. It is suitable for a later administrator
review workflow, not for automatic identity confirmation.
