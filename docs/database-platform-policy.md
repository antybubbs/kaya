# Kaya database platform policy

Kaya production uses PostgreSQL major version 16, pinned by the supported
Compose deployment to `postgres:16.14`. The pin is changed only to an
explicitly reviewed PostgreSQL 16.x tag after PostgreSQL upgrade validation. Alembic is
the schema authority and
the packaged migration graph must contain exactly one complete head.

Patch upgrades within PostgreSQL 16 are supported only after a verified
PostgreSQL backup, the read-only `kaya_postgres_upgrade.py preflight`, a
controlled stop/start or image replacement, health and revision checks, and a
representative application smoke test. Production Compose remains
deterministically pinned; operators upgrade the patch image deliberately and
retain the previous image only as a rollback option when its schema remains
compatible. Verified backup restore, not an assumed binary downgrade, is the
authoritative database rollback path.

Major upgrades such as PostgreSQL 16 to 17 are a separate future phase. They
require backup verification, extension review, disposable rehearsal, restore
testing, rollback planning, and a complete runtime acceptance matrix. A
PostgreSQL 16 data directory must never be mounted directly into a PostgreSQL
17 container.

Kaya performs supported Alembic upgrades at startup but never performs an
automatic production downgrade. Historical `downgrade()` functions remain in
the migration files for disposable testing and documented recovery decisions;
they are not a rollback mechanism for populated production databases.

Startup fails closed when PostgreSQL is not major version 16, when the schema
revision is missing from the packaged migration chain, when the schema is
newer than the application supports, or when the migration graph has multiple
heads. Kaya never falls back to SQLite. SQLite remains available only for
legacy migration, explicit recovery, and test fixtures.

Legacy SQLite migration support is retained until a minimum supported upgrade
baseline is published and maintained for at least three stable release lines,
with upgrade telemetry/support evidence and a removal-specific acceptance
matrix. Phase 10 defines this sunset criterion; it does not retire the path.

Database-sensitive releases must validate the migration graph, fresh and
supported upgrade paths, PostgreSQL integration tests, and focused legacy
migration tests. Release notes identify whether a migration is included,
backup requirements, PostgreSQL compatibility, minimum supported predecessor,
and rollback limitations.
