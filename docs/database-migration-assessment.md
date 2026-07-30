# Database Migration Modernisation Assessment

**Assessment date:** 2026-07-30  
**Target release:** v0.26.0 development branch

This report records the historical Phase 1 implementation gate used before Alembic was adopted. Descriptions of `create_all()`, the former runtime migration function, and the overwriteable `.pre-migration` copy below are historical findings, not current behaviour. The implemented outcome is the static baseline and startup lifecycle described under **Recommendation and transition plan**.

## Historical startup behaviour (superseded)

Before Alembic, container startup called `Base.metadata.create_all()`, copied `/app/data/kaya.db` to one overwriteable `.pre-migration` file, and ran `scripts/migrate_sqlite.py`. Those entrypoint mechanisms have been removed. The current entrypoint invokes `app.db.cli`, which performs versioned preparation before starting Uvicorn as the unprivileged `kaya` user.

FastAPI startup still calls `bootstrap()` before accepting traffic or starting background work, but it now only invokes database preparation and idempotent application defaults. The former large `migrate_existing_database()` implementation has been removed from `app/main.py`; its required pre-Alembic behaviour remains isolated behind `app/db/compatibility.py`.

## Historical manual migration inventory

The removed runtime `migrate_existing_database()` was SQLite-only and ran in an SQLAlchemy transaction. Its responsibilities were:

- dashboard preferences: create the table and unique user index;
- authentication: add user TOTP, name, OIDC/authentication source, break-glass, and timestamp columns; backfill authentication defaults and timestamps; add session OIDC token storage; create password reset tokens; make `users.password_hash` nullable by rebuilding the table in the standalone script;
- permissions: create and backfill `user_module_permissions` in the standalone script/bootstrap path;
- licences, VLAN/IP/DHCP: add favourite, VLAN/category/MAC/subnet fields; create VLAN and DHCP range/history tables; seed the first VLAN; attach unassigned IPs to it;
- custom fields and managed lists: create definition/value/list tables, unique constraints, and indexes;
- assets and racks: create hardware asset, attachment, rack, and rack-item tables and indexes;
- network monitoring: create monitor/check/event/outage/statistics tables, add threshold/state/maintenance and measurement columns, reset monitor state when threshold semantics are introduced, and add history indexes;
- remote access: create remote/settings/recording tables, add SSH fingerprint and gateway fields, and change the Secure Send gateway default port from 8089 to 8999 when the old default is detected;
- runbooks: create spaces/pages/history/images, add page view and saved-scroll state, migrate image storage from URL/data to blob metadata, and preserve prior images;
- domains and DNS: create provider, investigation, insight, statistics, recognised-device, observation, traffic, DHCP history, and client identity history tables; add capability/summary/device identity/link columns; backfill IP and hostname histories; update HA logical provider keys; run the DNS identity repair routine;
- audit: add category/severity/user/status/request indexes and redaction-oriented request metadata columns;
- compute and backup: add agent timing/encrypted token fields and create backup record/job tables;
- Secret Vault and Secure Send: create their version-one schema and supporting indexes without creating user vaults or exposing stored secret values;
- high availability: create provider, cluster, node, health, credential, replay, event, action, sync, backup, drift, lease, failover, and maintenance tables; add later topology, DHCP observation, resolver, recovery, keepalived, preferred-node, and remediation fields; create ordinary and partial unique indexes; backfill authoritative/preferred-node and provider linkage state.

The retained `scripts/migrate_sqlite.py` contains the historical compatibility operations, including SQLite table rebuilds/repairs that are difficult to reverse. Ordinary startup reaches it only through `app/db/compatibility.py`; it is not an alternative schema authority. No HTTP or WebSocket route performs schema DDL.

## Schema creation and current authority

The SQLAlchemy models define the current contract and the ordered Alembic revisions are authoritative creation and upgrade history. The static baseline contains the reviewed schema; current startup does not reconstruct it dynamically from model metadata.

The authoritative baseline is the reviewed current model contract, supplemented only by reviewed SQLite-specific partial indexes and compatibility outcomes already required by the application. Differences are not silently repaired: pre-Alembic databases must open as readable SQLite databases, receive a verified SQLite API backup, run the compatibility bridge, and match the targeted baseline contract before stamping. Full-database `quick_check` remains an explicit diagnostic rather than a routine startup gate.

Known irregularities requiring explicit treatment are the nullable `users.password_hash` rebuild, historical integer-to-float network latency representations, image blob conversion, monitor-state reset, Secure Send port correction, DNS identity merge/backfill, and HA preferred/authoritative-node backfills. These are compatibility data changes rather than fresh-install seed data. They remain isolated in the bridge and must not be repeated by the baseline.

The current HA model contains a deliberate foreign-key cycle among `dns_providers`, `ha_clusters`, and `ha_nodes`. SQLite accepts the reviewed inline constraints and post-migration foreign-key validation passes, but Alembic emits a dependency-order warning during autogeneration checks. A future non-SQLite support decision must normalise or explicitly name/use-alter these constraints in a separate reviewed migration.

## Database and deployment support

The configured URL is centralised as `Settings.database_url`, defaulting to `sqlite:////app/data/kaya.db`. SQLite is the documented, supported, and tested production database; the backup, compatibility, Compose, and operational paths do not constitute non-SQLite migration support.

Compose persists `./data` at `/app/data`, `./uploads` at `/app/uploads`, and recordings below the data volume. The application image is read-only at runtime; writable data, uploads, and `/tmp` mounts are supplied. Root is used by the entrypoint only to prepare ownership, after which migration and application commands run as `kaya`.

## Tests and historical states

Migration coverage now includes Alembic fresh installation and repeated startup, reconstructed historical releases, OIDC/user upgrades, backup reuse and restoration, validation failures, and DNS/HA preservation. No committed genuine database snapshots exist for v0.18, v0.20, v0.22, v0.24, or v0.25; historical fixtures are therefore labelled as reconstructed.

Partially migrated historical schemas remain plausible because raw SQLite DDL has version-dependent transaction behaviour and a process can stop between individual statements. Unexpected partial states are rejected unless the compatibility bridge explicitly recognises and safely completes them. The current entrypoint does not create an overwriteable `.pre-migration` copy.

## Destructive and difficult-to-reverse operations

No current migration intentionally drops user features, but the compatibility user-table rebuild drops and renames an original table after copying data. DNS identity repair can merge duplicate logical identities. Monitor migration deliberately clears previous state. Image conversion and HA/DNS backfills mutate data. These operations are guarded by a verified, immutable SQLite API backup and preservation tests.

## Recommendation and transition plan

Use one reviewed baseline revision named `20260730_01_kaya_schema_baseline`. For a new, empty database, Alembic creates the complete schema and application initialisers add required defaults. For an existing database without `alembic_version`, Kaya must: confirm it is a readable, recognisable pre-Alembic database; create and verify a timestamped SQLite API backup; run the preserved compatibility migration; validate required objects, types, constraints, revision state, and critical queries; then stamp the baseline. A database with recognised Alembic metadata proceeds through ordinary `upgrade head`. Unknown revisions or inconsistent schemas abort startup with recovery guidance.

Keep the compatibility bridge for at least the v0.26 and v0.27 release lines, covering supported upgrades from reconstructed v0.18.x through v0.25.x. Review removal no earlier than v0.28, and only after published minimum-supported-version policy, upgrade telemetry/support evidence, retained restoration documentation, and removal-specific tests. Do not delete historical compatibility code in this change.

Normalisation of latency storage and legacy image/DNS identity states should remain separate, explicitly tested corrective migrations if the baseline contract proves a deployed/model mismatch. No destructive normalisation is approved by this report. Explicit owner approval is required before dropping a legacy column/table, merging data beyond the existing deterministic DNS repair, or declaring a non-SQLite backend supported.

## Security and trust boundaries

Migration runs locally before user traffic and has full database/file authority. It introduces no HTTP authentication or role change. Database and backup paths are configuration input and must resolve without URLs or credentials in logs; backup filenames must be generated, not user-controlled. SQL identifiers in compatibility code remain static. Backups may contain password hashes, encrypted secrets, personal and infrastructure metadata, so their directory must be persistent, private, and never exposed through routes or logs beyond a redacted administrative path. Failure must be closed: no backup or failed validation means no migration and no application startup.
