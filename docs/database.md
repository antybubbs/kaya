# Database

**Kaya version:** `dev`  
**Documentation version:** `dev`

The default database is SQLite.

## Location

- Docker default: `/app/data/kaya.db`
- Docker Compose bind mount: `./data/kaya.db`

Persistent application state also includes:

- `/app/data/.runtime.env`
- `/app/uploads`
- `/app/data/remote-recordings`

## Models And Tables

SQLAlchemy models are defined in `app/models/models.py`.

Major tables:

- `users`
- `password_reset_tokens`
- `app_sessions`
- `licences`
- `vlans`
- `ip_addresses`
- `network_monitors`
- `network_monitor_checks`
- `remote_access`
- `remote_manager_settings`
- `remote_session_recordings`
- `domain_records`
- `domain_record_history`
- `dns_providers`
- `dns_investigations`
- `hardware_assets`
- `hardware_asset_attachments`
- `racks`
- `rack_items`
- `custom_fields`
- `custom_field_values`
- `managed_list_items`
- `runbook_spaces`
- `runbook_pages`
- `runbook_page_history`
- `compute_hosts`
- `compute_workloads`
- `compute_inventory_items`
- `compute_metrics`
- `compute_events`
- `backup_records`
- `backup_jobs`
- `audit_logs`

## Key Relationships

- `IPAddress` belongs to `VLAN`.
- `NetworkMonitor` has a one-to-one relationship with `IPAddress`.
- `RemoteAccess` has a one-to-one relationship with `IPAddress`.
- `RemoteSessionRecording` references `RemoteAccess` and `User`.
- `RunbookPage` belongs to an optional `RunbookSpace`, optional parent page, creator, and updater.
- `RunbookPageHistory` references a page and saving user.
- `RackItem` belongs to `Rack` and may reference `HardwareAsset`.
- `HardwareAssetAttachment` belongs to `HardwareAsset`.
- `ComputeWorkload`, `ComputeInventoryItem`, `ComputeMetric`, and `ComputeEvent` belong to `ComputeHost`.
- `BackupJob` belongs to `ComputeHost` and optionally `ComputeWorkload`.
- `DNSInvestigation` references `DNSProviderConfig` and optionally creator user.
- `CustomFieldValue` uses polymorphic `entity_type` and `entity_id`.

## Migrations

Tables are created with `Base.metadata.create_all()` and evolved through manual SQLite migration logic in:

- `app/main.py`
- `scripts/migrate_sqlite.py`

There is no Alembic migration system.

Current migration risks:

- Runtime and script migrations can drift.
- Most migrations are additive.
- SQLite-specific assumptions are present.
- Model definitions and manual DDL must be kept in sync.

## Seed And Default Data

Bootstrap ensures a default VLAN named `VLAN 1`.

The first real admin is created through `/setup`.

Demo mode seeds synthetic users, VLANs, IPs, monitors, remotes, DNS provider data, hardware assets, licences, domains, runbooks, compute hosts/workloads, backup records/jobs, managed lists, and audit rows.

# DNS insight persistence

DNS Manager adds three additive tables:

- `dns_insights` stores stable rule results and active, acknowledged and resolved lifecycle timestamps.
- `dns_statistics_snapshots` stores bounded hourly provider aggregates with 30-day retention.
- `dns_recognised_devices` stores stable provider-scoped device identities and observed IP/hostname changes.

Existing databases are upgraded idempotently during normal application bootstrap. Existing DNS providers, investigations and recognised-hostname settings are preserved; recognised hostname settings are imported lazily into stable device records when a successful analysis observes the device.
