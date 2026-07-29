# Module Navigation Inventory

This checklist records the registered modules reviewed for the standard module navigation migration. “Admin + allocation” means the server requires the administrator role and a persisted allocation for the specific module. Operational routes independently retain their existing module-access dependency.

| Module | Hero / shell template | Existing pages or sections | Previous settings shortcut | Central settings destination | Settings RBAC | Content | Badge | Mobile-specific behaviour |
|---|---|---|---|---|---|---|---|---|
| Asset Manager | `hardware_assets.html` | One page; category filters remain table controls | None | None | Omitted | Table | None | Shared responsive module/header/table rules |
| Backup Manager | `backup_manager.html` | One page | Storage settings in hero | `module-backup-manager` | Admin + allocation | Tables and job actions | None | Shared responsive navigation and table scrolling |
| VM/Docker Manager | `compute_manager.html` | Overview, Docker, Proxmox | None | None | Omitted | Cards and table | None | Existing compute responsive rules plus shared scrolling |
| Dashboard | `dashboard.html` | One page | None | `module-dashboard` | Admin + allocation | Widget grid | None | Existing dashboard/PWA behavior plus shared navigation |
| DNS Manager | `dns_manager.html` | Dashboard, Insights, Reports, Query Log, Clients, Local DNS, DHCP, Blocklists | Provider settings in hero | `module-dns-manager` | Admin + allocation | Dashboards and tables | None | Existing DNS controls plus shared horizontal scrolling |
| Domain Manager | `domain_manager.html` | One page | None | None | Omitted | Table | None | Shared responsive navigation and table scrolling |
| High Availability | `high_availability*.html`, shared HA headers | Overview, Clusters, Providers/Apps; nested cluster sections retained | None | None | Omitted | Cards, tables and operational workflows | Cluster activity count retained | Existing HA responsive rules plus shared scrolling |
| License Keys | `licences.html` | One page; type filters remain table controls | None | None | Omitted | Table | None | Shared responsive navigation and table scrolling |
| IP/WAN Monitor | `network_monitor.html` | One overview page; existing detail tabs retained | None | None | Omitted | Cards and detail charts | None | Existing monitor refresh/cards behavior plus shared navigation |
| Rack Manager | `rack_manager.html` | One overview page; rack-side detail controls retained | None | None | Omitted | Rack cards and interactive detail | None | Existing rack mobile layout plus shared navigation |
| Remote Manager | `remote_manager.html` | Remote workspace; recordings remain in the application sidebar | Module-local administration links | `module-remote-manager`, rendered in the hero by documented exception | Admin + allocation | Interactive workspace | None | Existing full-height remote workspace behavior |
| Runbook Manager | `_runbook_nav.html` across Runbook templates | Overview, Runbooks, Spaces, Tags, Templates, Import (editor/admin) | None | None | Omitted | Cards, editor and tables | None | Existing responsive runbook shell plus shared scrolling |
| Secret Vault | `secret_vault.html` | Vault, Collections, Shared, Favourites, Expiring, Activity, Backup/Recovery, personal preferences | Personal vault settings retained as preferences | `module-secret-vault` | Admin + allocation | Encrypted cards and table | None | Existing Vault responsive shell plus shared scrolling |
| Secure Send | `secure_send.html` | Dashboard, Sent, Received, Manage all (admin) | None | `module-secure-send` | Admin + allocation | Metrics and tables | None | Existing Secure Send rules plus shared scrolling |
| VLAN/IP Manager | `ip_addresses.html` | Managed records, Observed DNS clients, DHCP leases | None | `module-vlan-ip-manager` | Admin + allocation | Tables | Observed-client count retained | Existing table behavior plus shared horizontal scrolling |

The inventory is based on `app/services/modules.py`, registered router prefixes, their templates, central settings panels, and existing responsive CSS—not solely on sidebar entries.
