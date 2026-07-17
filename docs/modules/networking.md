# Networking Modules

**Kaya version:** `dev`  
**Documentation version:** `dev`

This page covers VLAN/IP Manager, IP/WAN Monitor, and Domain Manager. DNS Manager has its own page.

## VLAN/IP Manager

Purpose: track IP addresses, VLAN context, assignment details, monitoring, and remote access linkage.

Routes:

- `/networking/vlan-ip-manager`

Models:

- `VLAN`
- `IPAddress`
- `DHCPRange`
- `DHCPLeaseHistory`
- `NetworkMonitor`
- `RemoteAccess`
- `CustomField`
- `CustomFieldValue`
- `ManagedListItem`
- `ComputeWorkload`

Workflows:

- List/search/filter IP records by VLAN, then Category.
- Create/edit IP address records.
- Bulk update VLAN, Category, and assignment type.
- Configure VLANs, Categories, and multiple DHCP ranges under Site Administration → Module Settings → VLAN/IP Manager.
- Review current and historical DHCP leases independently of provider availability.
- Attribute retained DNS traffic to the client IP and lease interval observed at query time.
- Ping an address.
- Configure monitoring from the IP form.
- Configure remote access from the IP form.
- Link compute workloads by discovered IP metadata.

Permissions:

- Read requires authenticated user.
- Write requires editor.
- Ping requires authenticated user.

Risks:

- Database uniqueness and form validation are per VLAN/address.
- Legacy placeholder rows created for every DHCP-pool address are not deleted automatically; administrators should review and retire them after configuring ranges.
- Ping depends on OS/container network capability.

## IP/WAN Monitor

Purpose: monitor reachability of IP-backed services.

Routes:

- `/networking/ip-wan-monitor`
- Refresh/card endpoints for live updates

Models:

- `NetworkMonitor`
- `NetworkMonitorCheck`
- `IPAddress`

Workflows:

- Display status cards.
- Calculate recent uptime.
- Run manual refresh.
- Background loop runs due checks.

Permissions:

- Read requires authenticated user.
- Manual refresh requires authenticated user with CSRF.

Dependencies:

- ICMP ping subprocesses.
- Docker `NET_RAW` capability.

Risks:

- Background monitoring runs in the web process.
- Multi-instance deployment could duplicate polling.

## Domain Manager

Purpose: track domain registrations, expiry, nameservers, DNS data, and lookup history.

Routes:

- `/networking/domain-manager`

Models:

- `DomainRecord`
- `DomainRecordHistory`
- `RemoteManagerSetting`

Workflows:

- Create/edit/delete domain records.
- Manual lookup.
- Background polling.
- Store lookup deltas in history.
- Store registrar, DNS provider, expiry, nameservers, DNS records, and lookup errors.

Permissions:

- Read requires authenticated user.
- Changes require editor.

Dependencies:

- Poll cadence setting.
- RDAP/WHOIS/DNS lookups.

Risks:

- External lookup reliability varies by registrar/TLD.
- Background polling runs in the app process.
