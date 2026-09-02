# SQLite lifecycle policy

PostgreSQL 16.14 is Kaya's only production database authority.

## Supported uses of SQLite

SQLite remains intentionally supported for:

- reading and validating a controlled legacy source during Phase 6 upgrade;
- creating a verified pre-migration recovery backup;
- offline SQLite-to-PostgreSQL conversion and explicit recovery tooling;
- retained-source fingerprint and integrity verification;
- migration tests and disposable development fixtures;
- the separate HA agent local queue/state database.

SQLite is not supported as a fresh production database, PostgreSQL fallback,
dual-write store, worker database, or post-cutover replica.

## Authority and rollback

`POSTGRES_ACTIVE` is the durable cutover authority. A successful migration
leaves the SQLite source unchanged and retained for operator-led recovery. It
does not make SQLite writable through Kaya and does not provide automatic
rollback. Application rollback means restoring a compatible PostgreSQL image
or verified PostgreSQL backup; it never means switching a live installation
back to SQLite.

Fresh production Compose starts PostgreSQL directly. Missing or invalid
PostgreSQL configuration fails closed. A legacy source is eligible only when
it is inside the configured data directory, opens read-only, passes integrity
validation, and contains exactly one Kaya Alembic revision. An arbitrary `.db`
file is never sufficient evidence for migration.

Legacy migration support is retained for the self-hosted support lifetime and
will be reconsidered only after a documented support-policy decision confirms
that no supported deployed installation requires SQLite conversion or recovery.
Historical migration revisions and conversion tooling must not be deleted as
part of routine PostgreSQL maintenance.
