# Developer Database Migration Workflow

The SQLAlchemy models describe the current application contract. The ordered Alembic revisions are the authoritative history that creates and upgrades that contract. The baseline is static and must never import mutable current metadata. Production uses PostgreSQL 16; SQLite migration support is retained only for controlled legacy upgrades. See [Database platform policy](database-platform-policy.md).

The compatibility bridge is only for databases created before Alembic and is retained for legacy recovery. Its removal requires the sunset evidence defined in the platform policy; it must not be removed merely because new installations use PostgreSQL.

Common local commands are:

```bash
alembic current
alembic history
alembic upgrade head
alembic downgrade -1
alembic revision --autogenerate -m "description"
```

For Compose, prefix commands with `docker compose exec kaya`. Alembic resolves the migration directory from `alembic.ini`; application startup supplies the configured database URL, so it does not depend on the caller's working directory.

Autogeneration is only a starting point. Review every table, type, default, nullability, key, unique/check constraint, and index. Review generated drop operations especially carefully. Use SQLite batch operations when a table rebuild is necessary. Avoid long transactions and document expected locks and duration. Data migrations must be deterministic, idempotent where practical, redact logs, and never silently discard invalid rows.

Every database pull request includes:

- the revision and manually reviewed upgrade logic;
- a downgrade, or a written reason it is unsafe;
- data migration logic and preservation assertions where needed;
- upgrade tests from the immediately preceding revision and fresh-install tests;
- backup, recovery, compatibility, duration, locking and downtime notes.

Run at minimum the migration tests, a fresh upgrade, repeated startup, downgrade testing on disposable data where supported, and the complete test suite. No future column may be added with normal-startup `ALTER TABLE` code.

Ordinary clean startup uses bounded integrity, foreign-key, revision, and required-table checks. Use `validate_schema()` in migration tests and diagnostics when the complete table, column, type, index, unique-constraint, and foreign-key contract must be inspected.

## Disposable PostgreSQL Stage A validation

On Linux with Docker available, run the isolated PostgreSQL 16.15 workflow from the repository root:

```bash
export KAYA_STAGEA_TEST_MARKER=I_UNDERSTAND_DISPOSABLE_STAGEA
export KAYA_STAGEA_TEST_PASSWORD='synthetic-only-password'
bash scripts/validate-stagea-postgres.sh
```

The script creates only a run-scoped container and volume named `kaya-stagea-*`, binds the temporary server to `127.0.0.1`, uses test-only database names, verifies `current_database()` and the local server address before every migration operation, runs `scripts/kaya_test_migrations.py`, and removes its exact container and volume on exit. It refuses to run without the explicit marker or against production-like database names. It does not use the production Compose stack, live volumes, `C:\\app\\data\\kaya.db`, or production credentials.

The workflow validates fresh migration, the `20261014_03` upgrade path, downgrade/re-upgrade, link-context nullability, mapping indexes and foreign keys, and the PostgreSQL compatibility tests. Set `KAYA_STAGEA_PG_PORT` to another unprivileged localhost port if `55439` is occupied. The password is synthetic and disposable; do not use a deployment secret.
