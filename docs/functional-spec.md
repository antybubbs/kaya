# Kaya Functional Specification

**Kaya version:** `dev`  
**Documentation version:** `dev`  
**Last inspected:** 2026-07-08

This is the top-level functional specification for Kaya. The documentation is split into focused, version-controlled Markdown files so future Kaya changes can update the relevant area without turning one document into a maintenance trap.

When Kaya's application version changes, the documentation version in these files should be updated in the same change set.

## Documentation Map

- [Introduction](introduction.md)
- [Architecture](architecture.md)
- [Database](database.md)
- [Security](security.md)
- [Deployment](deployment.md)
- [Developer Guide](developer-guide.md)
- [API And Integration Surface](api.md)

## Module Specifications

- [Dashboard](modules/dashboard.md)
- [Runbook Manager](modules/runbook-manager.md)
- [Remote Manager](modules/remote-manager.md)
- [Networking](modules/networking.md)
- [DNS Manager](modules/dns-manager.md)
- [Docker / Compute Manager](modules/docker-manager.md)
- [Backup Manager](modules/backup-manager.md)
- [Asset And Rack Management](modules/asset-and-rack-management.md)
- [Licence Manager](modules/licence-manager.md)
- [Site Administration](modules/site-administration.md)
- [Data Management](modules/data-management.md)

## Documentation Maintenance Rules

- Keep documentation changes in the same pull request or commit as feature changes.
- Update the relevant module file whenever routes, permissions, settings, workflows, or models change.
- Update [Database](database.md) whenever a table, column, relationship, migration, seed, or persistence path changes.
- Update [Security](security.md) whenever authentication, authorisation, session, upload, secret handling, or external integration behaviour changes.
- Update [API And Integration Surface](api.md) whenever agent APIs, webhooks, provider integrations, import/export contracts, or websocket protocols change.
- Keep planned features clearly marked as planned. Do not document future behaviour as if it exists.

## Current Application Summary

Kaya is a self-hosted infrastructure management application for homelabs, small IT environments, and technical administrators. It combines inventory, documentation, remote access, DNS visibility, network monitoring, compute host monitoring, backup coordination, licence tracking, audit logs, and site administration into one server-rendered web application.

The current application is a FastAPI/Jinja/SQLAlchemy application with PostgreSQL 16.14 as the default Docker production database and SQLite retained for legacy/recovery workflows. It uses Docker Compose for deployment, local static assets for the UI, Fernet encryption for stored secrets, Argon2 password hashing, signed session cookies, and Node.js helper processes for browser-based SSH and Guacamole/RDP bridging.

## Current Limitations And Technical Debt

- SQLite-first design.
- Alembic provides the versioned migration history and current baseline.
- Limited automated tests.
- Import/export only supports licences and IP addresses.
- RBAC is coarse-grained.
- No object-level permissions.
- Background workers run inside the web process.
- No queue system for backup jobs beyond database state.
- No antivirus/content scanning for uploads.
- No full REST API for most modules.
- A temporary, tested compatibility bridge retains the historical additive migration logic for pre-Alembic installations.
- `RemoteManagerSetting` stores many unrelated site-wide settings.
- Several routers are large, especially `admin.py` and `compute_manager.py`.
- The Markdown renderer, remote access flows, backup agent dispatch, DNS provider parsing, and compute metadata parsing are areas that need dedicated tests.
- Three `async` request handlers still make blocking network calls on the event loop, so a slow or unreachable target pauses other requests until it times out. These are not part of High Availability, whose equivalent handlers were moved to worker threads:
  - Network Monitor `POST /traffic/sources/{source_id}/test` (`test_traffic_source`): traffic-source connection test.
  - Remote Manager `POST /{remote_id}/ssh/host-key/scan` (`scan_remote_host_key`): SSH host-key scan.
  - Remote Manager `POST /{remote_id}/ssh/host-key/trust` (`trust_remote_host_key`): SSH host-key scan before trusting.
