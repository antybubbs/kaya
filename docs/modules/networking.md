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
- `NetworkMonitor`
- `RemoteAccess`
- `CustomField`
- `CustomFieldValue`
- `ManagedListItem`
- `ComputeWorkload`

Workflows:

- List/search/filter IP records.
- Create/edit IP address records.
- Bulk update category/assignment type.
- Ping an address.
- Configure monitoring from the IP form.
- Configure remote access from the IP form.
- Link compute workloads by discovered IP metadata.

Permissions:

- Read requires authenticated user.
- Write requires editor.
- Ping requires authenticated user.

Risks:

- Database uniqueness is per VLAN/address, but parts of form logic treat address uniqueness more globally.
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
