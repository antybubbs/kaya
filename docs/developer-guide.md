# Developer Guide

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Running Locally

Run a local source build with Docker Compose:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

The local override deliberately tags the build as `kaya:local`, matching the image name Compose starts. The base Compose file remains suitable for registry-based deployments.

Then open:

```text
http://localhost:8080/setup
```

Useful commands:

```bash
make build
make run
make logs
make shell
```

## Publishing Releases

Production containers are published only when a non-draft, non-prerelease GitHub
Release is published with a tag that exactly matches `vMAJOR.MINOR.PATCH`. The
release must also be the release returned by GitHub's `releases/latest` API.
That single build publishes both the version tag and `latest`, so both tags refer
to the same image digest and contain the release tag as `APP_VERSION`.

From an authenticated GitHub CLI session, the repository release helper performs
the tag push and creates the GitHub Release:

```bash
make release VERSION=v0.26.0
```

Pushing a tag alone does not publish a production container. Development branches
publish only `dev...` tags, `main` publishes only a short-SHA tag, and `Kaya`
publishes only its branch tag. Production deployments continue to use
`ghcr.io/antybubbs/kaya:latest`.

To run without Docker, install Python dependencies and Node dependencies, then run Uvicorn against `app.main:app`. Local filesystem paths may need adjustment because defaults assume `/app/data` and `/app/uploads`.

## Adding A New Module

1. Add SQLAlchemy models in `app/models/models.py`.
2. Create and manually review an Alembic revision as described in `docs/developer-migrations.md`.
3. Add fresh-install, previous-revision, preservation, repeated-start, and relevant failure tests.
4. Create a router in `app/routers`.
5. Include the router in `app/main.py`.
6. Add templates under `app/templates`.
7. Add module JavaScript under `app/static/js` only if needed.
8. Add navigation in `app/templates/base.html`.
9. Register the module's stable key, label, route prefix, and optional enabled setting in `app/services/modules.py`.
10. Apply `require_module_access("<stable_key>")` to its router in addition to `require_user`, `require_editor`, or `require_admin`. Machine-authenticated routes must use a separate router so browser-user module checks are never applied to agent credentials.
11. Associate dashboard widgets and search results with that same stable module key.
12. Validate CSRF on mutating browser routes.
13. Write audit events for sensitive actions.
14. Add explicit authentication, authorisation, CSRF, validation and audit controls for dangerous operations.
15. Add tests for allowed and denied module access.
16. Update the matching docs file under `docs/`.

## Adding A New Admin Setting

1. Add a default in `app/services/site_settings.py` or the relevant module defaults.
2. Add it to the admin save/load allow-list.
3. Render it in `settings.html`.
4. Validate and normalise input before saving.
5. Encrypt it if it is secret.
6. Update any runtime service that must reload/restart after changes.
7. Update [Site Administration](modules/site-administration.md).

## Adding A Database Field Or Table

1. Update `app/models/models.py`.
2. Add a reviewed Alembic revision; never add startup-time schema DDL.
3. Consider indexes and uniqueness.
4. Update import/export, templates, forms, and tests as needed.
5. Avoid destructive migrations without a backup/restore plan.
6. Update [Database](database.md).

## Coding Patterns

- Server-rendered templates with small focused JS enhancements.
- SQLAlchemy sessions via `get_db`.
- Auth dependencies per route.
- CSRF on mutating form routes.
- Audit writes for important actions.
- Fernet encryption for stored secrets.
- Managed lists/custom fields for configurable user-facing categories.
- Local static assets rather than CDN dependencies.

### Shared data tables

All genuine user-facing data tables use the shared enhancer in `app/static/js/tables.js`. Give each table a stable `data-table-key`, stable `data-col` identifiers, and explicit non-exportable action/control columns. Tables with server pagination or large queries must provide a permission-checked `data-export-url` backed by the allowlisted streaming helpers in `app/services/table_export.py`; never fetch every page from browser JavaScript. See [Table export](table-export.md) for security rules, backend requirements and the coverage inventory.

## Things Not To Break

- Existing SQLite databases.
- `/app/data/.runtime.env`.
- Encryption key compatibility.
- Remote helper subprocess startup/shutdown.
- Guacamole bridge settings.
- Backup agent token validation.
- Upload and recording storage paths.
- Existing template navigation paths.

## Documentation Maintenance

Documentation is version-controlled and should be updated with code changes. The documentation version should match Kaya's version. 
