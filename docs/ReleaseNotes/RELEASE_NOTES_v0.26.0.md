# Kaya v0.26.0 Release Notes

## Versioned database migrations

Kaya now uses Alembic for versioned database migrations. Existing SQLite installations are not recreated and should not require users to rebuild their database. On the first upgrade, Kaya validates the database, creates a verified timestamped backup under `/app/data/backups`, runs the retained historical compatibility path where required, validates the resulting schema, and then records the baseline revision.

Pull and start the new Kaya image normally. Kaya performs required backup and migration work automatically; routine upgrades require no manual Alembic commands. Docker allows a 120-second startup grace period before health-check failures count, while genuine startup failures still become unhealthy.

Migration runs before user traffic and background services. Pre-Alembic upgrades now create a verified SQLite API backup before compatibility work and use targeted schema validation; a slow `PRAGMA quick_check` no longer blocks routine startup or masquerades as corruption. Strict quick-check diagnostics remain available from the database CLI. If backup, compatibility, or migration validation fails, Kaya aborts startup and reports the recovery location in its logs. Do not repeatedly edit or restart a failed database; preserve the logs and follow [Administrator Database Upgrades](../admin-database-upgrades.md).

Administrators can inspect the current revision with `alembic -c /app/alembic.ini current` inside the container. Backups may contain sensitive application data and remain private files on the existing persistent data volume.

Kaya now labels values calculated in powers of 1,024 as KiB, MiB, GiB, and TiB.
