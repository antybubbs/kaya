# DNS Manager Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

DNS Manager monitors and inspects DNS provider data. The current implemented provider is Pi-hole.

## Routes

- `/networking/dns-manager`

## Models Used

- `DNSProviderConfig`
- `DNSInvestigation`
- `RemoteManagerSetting`

## Workflows

- Dashboard provider status and summary.
- Query log inspection.
- Client inventory from Pi-hole network devices, DHCP leases, and query data.
- Local DNS records display.
- DHCP leases display.
- Blocklist display.
- Reports/investigations.
- Flag DNS queries for investigation.

## Permissions

- Viewing requires authenticated user.
- Provider configuration is admin-only through Site Administration.

## Settings

- `dns_manager_enabled`
- `dns_default_provider_id`
- Provider base URL
- Auth method
- Encrypted provider secret
- SSL verification
- Timeout

## Dependencies

- Pi-hole v6 session-style auth.
- Legacy Pi-hole API fallback.
- DNS provider settings stored in database.

## Edge Cases And Risks

- Only Pi-hole is currently implemented.
- Pi-hole v6 and legacy fallback increase provider complexity.
- API token auth is effectively legacy behaviour for Pi-hole.
- DNS investigation creation is available to authenticated users.
