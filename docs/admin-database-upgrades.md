# Administrator Database Upgrades

Pull and start the new Kaya image normally; routine upgrades do not require manual Alembic commands. Kaya upgrades its database automatically before user traffic or background services start. For SQLite, an existing database is integrity-checked and backed up before the first migration write. Backups are stored by default in `/app/data/backups`, which is inside the existing persistent data mount, with names such as `pre-migration-20260730_01-20260730-062300-000000.sqlite3`. A matching JSON file records the source and target revision without record contents or credentials.

Migration time depends on database size and storage speed. SQLite schema changes may hold an exclusive write lock; plan a maintenance window for large installations. Kaya logs concise transition milestones and one revision summary at info level. Per-operation validation timing, backup progress, and compatibility-object detail are available at debug level.

Startup validation opens a read-only SQLite connection, waits at most 5 seconds for a database lock, and limits each validation statement to 120 seconds. It uses `PRAGMA quick_check` for ordinary startup because SQLite documents it as providing most of `integrity_check`'s corruption detection while avoiding the much slower UNIQUE-index verification. Foreign-key consistency remains a separate mandatory `PRAGMA foreign_key_check`; clean starts also verify the revision and required table set without introspecting every column, index, and constraint. Full schema validation remains mandatory after a transition and available to tests and diagnostics. A migration backup has a 600-second limit and its resulting database is validated in the same way. Lock expiry, corruption, timeout, unreadable storage, and unexpected SQLite failures are reported separately and all stop startup.

Bind mounts do not change SQLite's validation algorithm, but their storage stack can materially change elapsed time. Windows Docker Desktop file sharing and synchronisation-backed directories such as Nextcloud can add metadata, antivirus, virtualisation, and sync latency. Keep the active SQLite database on local, container-supported storage where possible; exclude the live database, `-wal`, and `-shm` files from active synchronisation. Do not remove WAL sidecars to speed up validation. Kaya reads them as part of a WAL-mode database and preserves any sidecars encountered by the explicit demo reset workflow.

### Historical SQLite type compatibility

Schema validation follows SQLite's documented INTEGER, TEXT, BLOB, REAL, and NUMERIC affinities, but affinity alone is not treated as proof that unrelated semantic types are interchangeable. Dangerous conversions remain fatal. Kaya explicitly accepts the following historical declarations after confirming that every non-null stored value has SQLite storage class `integer` or `real`:

| Table | Column | Historical declaration | Canonical declaration | Action |
| --- | --- | --- | --- | --- |
| `network_monitors` | `last_latency_ms` | `INTEGER` | `FLOAT` | Approved historical compatibility |
| `network_monitor_checks` | `latency_ms` | `INTEGER` | `FLOAT` | Approved historical compatibility |
| `network_monitor_checks` | `response_time_ms` | `INTEGER` | `FLOAT` | Approved historical compatibility |
| `network_monitor_statistics` | `avg_latency_ms` | `INTEGER` | `FLOAT` | Approved historical compatibility |
| `network_monitor_statistics` | `max_latency_ms` | `INTEGER` | `FLOAT` | Approved historical compatibility |

These declarations came from the original network-monitor schema and were changed to SQLAlchemy `Float` in commit `ec21740` without rebuilding populated SQLite tables. SQLite safely stores fractional values in an INTEGER-affinity column using the REAL storage class. Fresh databases and the static Alembic baseline use canonical `FLOAT` declarations. Text or blob content in any approved historical numeric column is rejected.

Verified migration-backup metadata includes a source database/WAL fingerprint and a digest of the backup. When an unchanged failed transition restarts with the same source and target revisions, Kaya revalidates and references that backup instead of creating unlimited duplicates. A changed source still receives a new pre-migration backup.

If backup creation, integrity validation, compatibility, Alembic, or final validation fails, Kaya exits startup. Do not delete or edit the original database. Preserve the log and backup filenames, but redact host paths or other deployment details before posting publicly.

## Inspect and diagnose

Inside the container:

```bash
alembic -c /app/alembic.ini current
alembic -c /app/alembic.ini history
python -m app.db.cli
```

## Restore

1. Stop both Kaya and the Secure Send gateway.
2. Copy the failed database, WAL, and SHM files aside for diagnosis.
3. Verify the selected backup and its JSON metadata correspond to the attempted upgrade.
4. Restore the `.sqlite3` backup as `/app/data/kaya.db`, preserving owner and mode expected by the container.
5. Preserve `kaya.db-wal` and `kaya.db-shm` alongside the failed database for diagnosis. Do not delete them automatically; an operator may remove confirmed-stale sidecars only while every Kaya process is stopped and after retaining a recoverable copy.
6. Start Kaya and inspect migration logs before allowing normal use.

Test restoration first on a disposable copy. Automatic retention keeps the newest configured number of backup pairs (default 10) and never removes the only backup. Settings are `MIGRATION_BACKUP_DIR`, `MIGRATION_BACKUPS_ENABLED`, and `MIGRATION_BACKUP_RETENTION_COUNT`; automatic SQLite migration backups are enabled by default. Disabling them removes an important recovery control.
