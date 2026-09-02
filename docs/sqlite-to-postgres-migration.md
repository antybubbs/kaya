# Offline SQLite-to-PostgreSQL migration

Phase 5 provides the standalone command:

```text
python scripts/kaya_db_migrate.py sqlite-to-postgres \
  --source /path/to/kaya.db \
  --target-url postgresql+psycopg://... \
  --backup-directory /path/to/recovery-backups \
  --report /path/to/migration-report.json
```

The source is opened with SQLite `mode=ro` and `PRAGMA query_only=ON`. The tool requires the current single Alembic head, runs `quick_check` and `foreign_key_check`, creates or reuses a verified Kaya backup, and fingerprints the source before and after conversion.

The target must be PostgreSQL 16 and empty. Kaya’s Alembic migrations create the target schema. Application rows are copied in dependency-derived order, with bounded table/batch transactions and deterministic retry of foreign-key cycles. Existing integer IDs are retained; PostgreSQL sequences are repaired afterward.

The target contains a private `kaya_migration_state` marker. Failed conversions remain inspectable and are never dropped automatically. A failed or incomplete target must be removed or reset by an explicitly authorized operator before retrying. Normal Kaya startup rejects a target whose marker is not `COMPLETED/PASSED`.

Before any SQLite connection is opened, the command creates a mode-700 `sqlite-tmp` directory beside the source database, verifies that it is writable and on the database filesystem, and sets `SQLITE_TMPDIR` for the migration process. The preflight records the resolved source, backup, and temp paths, device identity, available bytes, and conservative shared requirement. Paths on the same device share one capacity budget; PostgreSQL data capacity is explicitly reported as unknown when the server is remote or container-managed and cannot be measured reliably by the client.

`--dry-run` performs source, target, revision, table-inventory, and local-filesystem capacity checks without creating a backup or copying rows. Reports contain counts, hashes, timings, sequence results, WAL growth, and validation state, but never row contents, secrets, passwords, or full DSNs.

This command is not invoked by ordinary application startup. Fresh production
Compose is PostgreSQL-only; the controlled Phase 6 upgrade path is the only
automatic startup path that may read an eligible retained SQLite source.

## Phase 6 test instrumentation

Disposable Phase 6 integration tests may set `KAYA_TEST_MODE=true` and one
predefined `KAYA_TEST_FAILPOINT`. Failpoints are disabled by default, are
rejected in production configuration, and are not available through HTTP or
any remote Kaya endpoint. Supported names and their intended boundaries are:

- `before_source_capture`, `after_source_capture`;
- `after_postgres_prepare`;
- `fail_during_copy`, `fail_during_validation`, `fail_state`;
- `pause_cutover_pending`, `pause_after_postgres_active`.

Pause points wait for a test-only release marker in the configured
`KAYA_TEST_FAILPOINT_DIR`; failure points raise a controlled exception through
the normal migration error path. Test evidence may be written to
`KAYA_TEST_OBSERVABILITY_FILE`. It contains lifecycle metadata, process IDs,
fingerprints, worker names, and database-engine names, never row contents or
credentials. These controls are for disposable test processes only and are
not operator recovery tools.
