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
- Update [Security](security.md) whenever authentication, authorisation, session, upload, secret handling, demo restrictions, or external integration behaviour changes.
- Update [API And Integration Surface](api.md) whenever agent APIs, webhooks, provider integrations, import/export contracts, or websocket protocols change.
- Keep planned features clearly marked as planned. Do not document future behaviour as if it exists.

## Current Application Summary

Kaya is a self-hosted infrastructure management application for homelabs, small IT environments, and technical administrators. It combines inventory, documentation, remote access, DNS visibility, network monitoring, compute host monitoring, backup coordination, licence tracking, audit logs, and site administration into one server-rendered web application.

The current application is a FastAPI/Jinja/SQLAlchemy application with SQLite as the default database. It uses Docker Compose for deployment, local static assets for the UI, Fernet encryption for stored secrets, Argon2 password hashing, signed session cookies, and Node.js helper processes for browser-based SSH and Guacamole/RDP bridging.

## Current Limitations And Technical Debt

- SQLite-first design.
- No formal Alembic migration system.
- Limited automated tests.
- Import/export only supports licences and IP addresses.
- RBAC is coarse-grained.
- No object-level permissions.
- Background workers run inside the web process.
- No queue system for backup jobs beyond database state.
- No antivirus/content scanning for uploads.
- No full REST API for most modules.
- Manual migration logic is duplicated across runtime startup and `scripts/migrate_sqlite.py`.
- `RemoteManagerSetting` stores many unrelated site-wide settings.
- Several routers are large, especially `admin.py` and `compute_manager.py`.
- The Markdown renderer, remote access flows, backup agent dispatch, DNS provider parsing, and compute metadata parsing are areas that need dedicated tests.
