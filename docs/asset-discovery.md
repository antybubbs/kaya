# Asset Manager discovered devices

Asset Manager's **Discovered Devices** view is a bounded, read-only composition of
retained DNS clients, DHCP lease observations and Network Traffic discovery
observations. The source modules remain the owners of their records; no duplicate
discovery table is created.

DNS and DHCP observations are grouped only when the DHCP record already references
the same retained DNS client. Network Traffic observations remain exporter- and
endpoint-role-scoped review candidates. Hostnames and IP addresses alone never merge
or confirm devices.

Administrators can review a candidate and explicitly adopt it into an existing
Hardware Asset or create one new asset. Adoption requires a stable MAC address or
DHCP client identifier, writes reviewed identity evidence and at most the current
observed managed-IP assignment in one transaction, and records a redacted audit
event. Conflicts abort the transaction. Network Traffic observations without a
source-scoped identity remain review-only and never cause historical traffic
reattribution or monitoring opt-in.

Confirmed DNS relationships are shown as Asset Profile links only when the
administrator-reviewed identity evidence still exists. Users with DNS access but
without Asset Manager access retain the specialist DNS experience and do not receive
asset metadata. DNS dismissals use the existing source-owned ignored state; DHCP-only
observations do not gain new persistent dismissal storage.
