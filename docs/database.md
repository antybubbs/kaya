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
- `user_module_permissions`
- `password_reset_tokens`
- `app_sessions`
- `licences`
- `vlans`
- `ip_addresses`
- `network_monitors`
- `network_monitor_checks`
- `network_monitor_events`
- `network_monitor_outages`
- `network_monitor_statistics`
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
- `NetworkMonitorCheck`, `NetworkMonitorEvent`, `NetworkMonitorOutage`, and `NetworkMonitorStatistic` belong to `NetworkMonitor`. Check and statistic latency columns use floating-point storage so valid sub-millisecond responses are not reported as zero.
- `RemoteAccess` has a one-to-one relationship with `IPAddress`.
- `RemoteSessionRecording` references `RemoteAccess` and `User`.
- `UserModulePermission` grants one stable registered module key to a user. Its unique `(user_id, module_key)` constraint prevents duplicate grants, and `created_by` records the administrator responsible for the current grant.
- `RunbookPage` belongs to an optional `RunbookSpace`, optional parent page, creator, and updater.
- `RunbookPageHistory` references a page and saving user.
- `RackItem` belongs to `Rack` and may reference `HardwareAsset`.
- `HardwareAssetAttachment` belongs to `HardwareAsset`.
- `ComputeWorkload`, `ComputeInventoryItem`, `ComputeMetric`, and `ComputeEvent` belong to `ComputeHost`.
- `BackupJob` belongs to `ComputeHost` and optionally `ComputeWorkload`.
- `DNSInvestigation` references `DNSProviderConfig` and optionally creator user.
- `CustomFieldValue` uses polymorphic `entity_type` and `entity_id`.

## Schema authority and migrations

The SQLAlchemy models define the current schema contract. Static, reviewed Alembic revisions under `migrations/versions` are the authoritative creation and upgrade history, beginning with baseline `20260730_01`. The baseline explicitly contains every current table, column, type, nullability, server default, primary/foreign key, unique constraint, and index emitted by the models. SQLite partial indexes declared by the models are included. Kaya validates those objects after migration.

Application-side Python defaults are intentionally not treated as database server defaults. They are defined on the corresponding model columns and applied by SQLAlchemy. Required business records are owned by `app/db/seeds.py`; currently this includes the idempotent `VLAN 1` record, historical module-access preservation, and process-bound vault-session revocation. These assumptions are application invariants rather than check constraints.

Fresh databases are created by `alembic upgrade head`. Existing databases without Alembic metadata are backed up and brought to the baseline contract by the temporary compatibility bridge before being stamped. They are never blindly stamped and are not recreated from models. See [the assessment](database-migration-assessment.md) for deployed/model irregularities and [developer workflow](developer-migrations.md) for future changes.

## Seed And Default Data

Bootstrap ensures a default VLAN named `VLAN 1`.

The first real admin is created through `/setup`.

Demo mode seeds synthetic users, VLANs, IPs, monitors, remotes, DNS provider data, hardware assets, licences, domains, runbooks, compute hosts/workloads, backup records/jobs, managed lists, and audit rows.

# DNS insight persistence

DNS Manager adds three additive tables:

- `dns_insights` stores stable rule results and active, acknowledged and resolved lifecycle timestamps.
- `dns_statistics_snapshots` stores bounded hourly provider aggregates with 30-day retention.
- `dns_recognised_devices` stores stable provider-scoped device identities and observed IP/hostname changes.
- `dns_client_observations` stores bounded raw sightings linked to logical recognised devices.
- `dhcp_lease_history` stores time-bounded active and ended DHCP address assignments.

Pre-Alembic databases receive these additive changes through the retained compatibility bridge before baseline stamping. Existing DNS providers, investigations and recognised-hostname settings are preserved; recognised hostname settings are imported lazily into stable device records when a successful analysis observes the device.

Existing users are backfilled with every registered module when `user_module_permissions` is first introduced, preserving upgrade access. Users created afterwards receive no module grants by default; the first setup administrator is explicitly granted every registered module.
