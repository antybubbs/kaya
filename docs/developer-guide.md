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

Kaya uses three release phases. Work is developed on the `dev` branch (with
historical versioned `dev*` branches retained where they already exist). Every
successful push publishes the moving `dev` development image and a
commit-specific image; no manual version tag or GitHub Release is required for
normal Development work:

```text
dev -> automatic kaya:dev -> explicit vX.Y.Z-rc.N -> RC validation -> Dev -> Main -> vX.Y.Z
```

The normal Development workflow is:

```bash
git commit
git push origin dev
docker pull ghcr.io/antybubbs/kaya:dev
```

CI also publishes `ghcr.io/antybubbs/kaya:dev-<short-git-sha>` for the exact
build. The `dev` tag is mutable and always points to the latest successful
Development build. Development pushes do not create GitHub Releases and never
publish `latest`.

If an immutable internal snapshot is specifically needed, it may still be
created with:

```bash
make release-dev VERSION=v0.28.0-dev.1
```

Create a feature-complete candidate with:

```bash
make release-rc VERSION=v0.28.0-rc.1
```

Both commands create an immutable Git tag and a GitHub prerelease. Never reuse
an existing tag. If validation finds a defect, fix it on Development and create
`v0.28.0-rc.2` (or the next number); do not modify the tested candidate.

After the latest RC passes validation, complete all Dev -> Main checks and
promote the tested source to `main`. Do not add functional changes during this
promotion. If the promoted source differs functionally from the approved RC,
return to Development and create a new RC.

For a merge that changes the commit ID, compare source trees before tagging
Stable:

```bash
git diff --exit-code v0.28.0-rc.1^{tree} main^{tree}
```

The command must produce no output and exit successfully. Release-note wording
may change during validation, but functional source changes require another RC.

Create the public stable release only when explicitly approved:

```bash
make release VERSION=v0.28.0
```

Stable releases must be non-draft, non-prerelease GitHub Releases with a
`vMAJOR.MINOR.PATCH` tag. The release must also be the release returned by
GitHub's `releases/latest` API. That build publishes both the version tag and
`latest`, so both tags refer to the same image digest and contain the release
tag as `APP_VERSION`.

From an authenticated GitHub CLI session, the repository release helper performs
the tag push and creates the GitHub Release:

```bash
make release VERSION=v0.26.0
```

Pushing a tag alone does not publish a container. Published development and RC
releases publish only their exact version-specific image tag, such as
`ghcr.io/antybubbs/kaya:0.28.0-rc.1`; they never publish or replace `latest`.
Development branches publish only `dev...` tags, `main` publishes only a
short-SHA tag, and `Kaya` publishes only its branch tag. Production deployments
continue to use `ghcr.io/antybubbs/kaya:latest`.

Existing stable installations continue using GitHub's `/releases/latest` stable
endpoint and are not offered development or RC builds. Existing stable tags
and releases are not renamed, recreated or rewritten.

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
