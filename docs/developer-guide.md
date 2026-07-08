# Developer Guide

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Running Locally

Run with Docker Compose:

```bash
docker compose up -d --build
```

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

To run without Docker, install Python dependencies and Node dependencies, then run Uvicorn against `app.main:app`. Local filesystem paths may need adjustment because defaults assume `/app/data` and `/app/uploads`.

## Adding A New Module

1. Add SQLAlchemy models in `app/models/models.py`.
2. Add migration logic in `app/main.py`.
3. Add matching migration logic in `scripts/migrate_sqlite.py` if needed for container startup upgrades.
4. Create a router in `app/routers`.
5. Include the router in `app/main.py`.
6. Add templates under `app/templates`.
7. Add module JavaScript under `app/static/js` only if needed.
8. Add navigation in `app/templates/base.html`.
9. Apply `require_user`, `require_editor`, or `require_admin`.
10. Validate CSRF on mutating browser routes.
11. Write audit events for sensitive actions.
12. Add demo-mode restrictions for dangerous operations.
13. Add tests.
14. Update the matching docs file under `docs/`.

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
2. Add additive SQLite migration logic.
3. Consider indexes and uniqueness.
4. Update import/export, seed demo data, templates, forms, and tests as needed.
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

## Things Not To Break

- Existing SQLite databases.
- `/app/data/.runtime.env`.
- Encryption key compatibility.
- Demo mode reset/seed flow.
- Remote helper subprocess startup/shutdown.
- Guacamole bridge settings.
- Backup agent token validation.
- Upload and recording storage paths.
- Existing template navigation paths.

## Documentation Maintenance

Documentation is version-controlled and should be updated with code changes. The documentation version should match Kaya's version. While Kaya reports `dev`, docs should also use `dev`.
