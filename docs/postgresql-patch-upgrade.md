# PostgreSQL 16 patch upgrades

Kaya production is pinned to `postgres:16.14`. A reviewed, newer PostgreSQL
16.x patch image may be used after the Phase 11 readiness validation and a
verified backup. A patch upgrade is distinct from a Kaya application update,
legacy SQLite migration, and a PostgreSQL major upgrade.

## Prerequisites

- a maintenance window and access to the host running Docker Compose;
- a tested Kaya application image;
- enough storage for a custom-format PostgreSQL backup;
- the current PostgreSQL image pin and proposed explicit `postgres:16.x` tag;
- a local administrator recovery method;
- a recent verified backup including the encryption-key material required by
  Kaya and the files documented in the deployment backup section.

Create a pre-upgrade backup with the PostgreSQL backup worker. For an upgrade,
set the purpose to `pre_postgres_upgrade`; the metadata records the PostgreSQL
server version, Kaya build, Alembic revision, archive size, SHA-256 digest,
purpose and verification state.

```bash
KAYA_POSTGRES_BACKUP_PURPOSE=pre_postgres_upgrade \
  docker compose -f docker-compose.yml -f docker-compose.phase8-ops.yml \
  --profile postgres-ops run --rm postgres-backup backup
docker compose -f docker-compose.yml -f docker-compose.phase8-ops.yml \
  --profile postgres-ops run --rm postgres-backup verify
```

Run the read-only preflight inside the Kaya image. It fails closed when the
target is not an explicit PostgreSQL 16.x image, the current database is not
at the current Alembic head, PostgreSQL is unreachable, or no recent verified
backup is available. It never prints a DSN or password and does not modify
the database.

```bash
docker compose exec -T kaya python scripts/kaya_postgres_upgrade.py \
  preflight --target-image postgres:16.14
```

## Upgrade procedure

1. Confirm the verified backup and record the preflight output.
2. Pull the explicitly reviewed PostgreSQL 16.x image.
3. Stop Kaya and PostgreSQL cleanly during the maintenance window.
4. Change only the PostgreSQL image pin to the reviewed patch version.
5. Start PostgreSQL and wait for its health check.
6. Start Kaya and wait for `/healthz` plus a database-backed authenticated
   page.
7. Run the post-upgrade verification command and create a fresh verified
   backup.
8. Confirm application data, workers, diagnostics and backup/restore health.

The same PostgreSQL data volume may be reused for a supported same-major patch
upgrade after a clean stop and verified backup. Do not use `docker compose
down -v` during this operation. Keep the previous image reference until the
new deployment is accepted.

## Rollback and failure recovery

Application-image rollback is limited by Alembic schema compatibility. A
PostgreSQL data directory that has been started by a newer PostgreSQL binary
must not be assumed safe with an older binary. The authoritative rollback
mechanism is the verified pre-upgrade backup restored to a disposable or
replacement PostgreSQL 16 deployment after validation. Kaya does not automate
binary downgrade or destructive volume replacement.

If preflight fails, no image or database change has occurred. If the new image
fails after replacement, preserve the data volume and pre-upgrade backup,
restore the reviewed image only when PostgreSQL itself supports the state, or
perform the documented backup restore procedure. Do not mount a PostgreSQL 16
data directory into PostgreSQL 17.

## Expected downtime and verification

The maintenance window includes backup verification, clean stop, PostgreSQL
startup, Kaya recovery and smoke checks. CI timings are reference measurements
only; hardware, archive size and storage speed determine production duration.

## Troubleshooting

- Unsupported major: restore the reviewed PostgreSQL 16 image and do not
  continue with the proposed target.
- Missing or stale backup: create and verify a new backup; do not use an
  unverified archive.
- Schema mismatch: keep the database untouched and use a compatible Kaya
  image or verified restore.
- Application unhealthy: inspect Kaya logs and PostgreSQL readiness without
  deleting the data volume; retain the pre-upgrade backup for recovery.
