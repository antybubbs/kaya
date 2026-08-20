# Deployment

**Kaya version:** `dev`  
**Documentation version:** `dev`

Kaya's supported production architecture is Docker Compose with PostgreSQL
16.14 as the normal database. SQLite remains available for legacy/recovery
operations and local development; it is not the default production database.

## Phase 7 runtime validation in CI

The repository provides `.github/workflows/phase7d-runtime.yml` for the
expensive production-Compose acceptance matrix. It runs manually through
`workflow_dispatch`, and automatically when database, migration, deployment,
Compose, Docker entrypoint, or Phase 7 validation files change on `main`,
`dev`, `Kaya`, or a pull request. Documentation-only changes do not trigger
this matrix.

The workflow builds two local synthetic images and validates fresh PostgreSQL,
legacy SQLite conversion through the primary Compose topology, existing
PostgreSQL startup, authenticated HTTP reads/writes, down/up persistence,
image replacement, bounded PostgreSQL outage, native backup/restore,
credential persistence, and migration artifact retention. Every Compose
project and volume is derived from the workflow run and is removed by an
always-run cleanup trap. It never uses production secrets or global Docker
prune commands.

The workflow uploads only redacted service status and logs for diagnosis; it
does not upload passwords, encryption keys, cookies, DSNs, or database files.
A green CI execution is required before Phase 7 can be recommended READY.

## New installation

From a clean checkout, start the primary stack:

```bash
docker compose up -d
```

The stack starts PostgreSQL, creates a deployment-managed password in the
persistent `kaya_phase6_postgres_secret` volume when one does not already
exist, waits for PostgreSQL health, and then runs Kaya's normal Alembic
preparation. PostgreSQL is private to the Compose network and is pinned to
`postgres:16.14`; port 5432 is not published on the host. Complete the setup
wizard at `http://SERVER-IP:8080/setup`.

To supply an existing private password file on first installation, place it at
`./data/secrets/postgres_password` or set `KAYA_POSTGRES_PASSWORD_DIR` to the
directory containing that file. The file is copied only when the persistent
Compose secret volume is empty, is owned by the database service account, and
is mode 0600. Do not put credentials in `DATABASE_URL`, shell arguments, logs,
or committed files.

## Existing SQLite to PostgreSQL upgrade

Existing SQLite installations use the same primary Compose file. Keep the
existing `./data` mount and start it normally:

```bash
docker compose up -d
```

When `/app/data/kaya.db` exists and the PostgreSQL database is empty, Kaya
enters the proven Phase 6 controlled upgrade path before starting application
workers. It validates SQLite, creates or reuses a verified backup under
`/app/data/backups`, migrates through the existing SQLite-to-PostgreSQL engine,
validates the target, and records PostgreSQL as authoritative only after
success. The original SQLite database, verified backup, and migration report
remain retained.

During this one-time operation Kaya is unavailable and normal writers are not
started. After cutover, PostgreSQL remains authoritative across restarts and
Kaya refuses SQLite fallback if PostgreSQL is unavailable. A failed or partial
upgrade is recorded durably and requires the explicit Phase 6 recovery/retry
procedure; do not delete the source database or use ad-hoc SQL.

The legacy `docker-compose.phase6-upgrade.yml` remains available for isolated
operator recovery and validation, but is not required for a normal upgrade.

## Docker Service

- Image: `ghcr.io/antybubbs/kaya:latest` by default
- Container port: `8080`
- Host port: `${KAYA_PORT:-8080}`
- Docker health probe: `http://127.0.0.1:8080/healthz`, checked every 15 seconds with a 5-second timeout, five retries, and a 120-second startup grace period for database preparation. Dependent services remain gated on a successful probe.
- Entrypoint: `docker-entrypoint.sh`
- Runtime: Uvicorn serving `app.main:app`
- Filesystem: read-only container with writable volumes and tmpfs
- Capability: `NET_RAW` for ping support
- Security option: `no-new-privileges`

## Compose Services

- `kaya`
- `postgres` using `postgres:16.14`
- `postgres-secret-init` (one-shot secret initialisation)
- `secure-send-gateway`
- `guacd` using `guacamole/guacd:1.6.0`

## Persistent Volumes

- `./data:/app/data` (application state, legacy SQLite source, runtime secrets and migration backups)
- `./uploads:/app/uploads`
- `./data/remote-recordings:/app/data/remote-recordings`
- Docker volume `kaya_postgres_data` (production PostgreSQL data)
- Docker volume `kaya_phase6_postgres_secret` (deployment-managed PostgreSQL password)

Important persistent files:

- `/app/data/kaya.db` (legacy/recovery source; not the normal production database)
- `/app/data/.runtime.env`
- `/app/uploads`
- `/app/data/remote-recordings`
- `/app/data/backups/pre-migration-*.sqlite3` and matching revision metadata when an existing database requires migration
- `/app/data/kaya-database-upgrade.json` and `/app/data/kaya-database-upgrade-report.json` during/after SQLite conversion

## Environment Settings

Important environment/configuration values include:

- `DATABASE_URL` (normally PostgreSQL in the primary Compose stack)
- `KAYA_POSTGRES_DATABASE_URL`
- `KAYA_SQLITE_SOURCE_URL`
- `KAYA_POSTGRES_PASSWORD_DIR` (optional host directory containing the first-install password file)
- `SECRET_KEY`
- `ENCRYPTION_KEY`
- `BASE_URL`
- `ALLOWED_HOSTS`
- `FORWARDED_ALLOW_IPS` (trusted reverse-proxy IPs or CIDR networks; defaults to `127.0.0.1`)
- `SESSION_COOKIE_SECURE`
- Guacamole-related settings
- Upload and recording size settings

## Startup Behaviour

The entrypoint:

- Creates persistent data/upload/recording directories.
- Generates and preserves runtime secrets in `/app/data/.runtime.env` when not supplied.
- Creates and verifies a timestamped pre-migration SQLite backup with SQLite's backup API before changing an existing legacy database.
- Detects an already prepared PostgreSQL schema and does not repeatedly attempt SQLite conversion when the legacy source is retained.
- Runs the safe `app.db` Alembic preparation lifecycle.
- Starts Uvicorn.

## Upgrade Considerations

- For a routine container upgrade, run `docker compose pull` followed by `docker compose up -d`; Kaya performs any required backup and Alembic upgrade automatically.
- Back up `data`, `uploads`, and recordings before upgrading.
- Preserve `.runtime.env`; losing the encryption key can make encrypted secrets unrecoverable.
- Normal startup runs the Alembic lifecycle automatically before application services.
- Pre-Alembic installations use the retained compatibility bridge and are stamped only after full validation.
- RDP certificate verification is strict after the security migration. Inventory RDP hosts before upgrade. Public/system-CA certificates require no trusted certificate when guacd trusts the CA; self-signed hosts require an administrator to discover and explicitly trust the host's certificate (compared via another channel first where practical) under Remote Manager's RDP certificate trust settings. Do not restore connectivity by enabling certificate bypass or TOFU.
- The supported guacd/FreeRDP 2.x boundary receives pins as `sha256:<colon-separated bytes>`; Kaya performs this conversion from its validated canonical storage form. Do not hand-edit connection tokens or substitute unvalidated fingerprint algorithms.
- The minimum safe RDP rollback boundary is database revision `20260804_02` plus application/bridge code enforcing NLA, `ignore-cert=false` and `cert-tofu=false`. Supported downgrade below that revision is blocked because older code universally accepts certificates. If rollback would cross the boundary, disable RDP and roll forward instead.
- Restoring a database backup from before `20260804_02` with the secure application is supported: startup upgrades it, creates no pins automatically and uses strict system-CA validation. Never pair a pre-fix backup with an older insecure image. Preserve the upgraded database and its endpoint-trust invalidation evidence in subsequent backups.

## Reverse proxies and real client IPs

Kaya uses `FORWARDED_ALLOW_IPS` as its trust boundary for proxy headers. It
accepts `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, `CF-Connecting-IP`, and
`X-Forwarded-Proto` only when the immediate socket connection is from a listed
IP address or CIDR network. Direct clients cannot spoof their recorded address
with these headers.

Create a `.env` beside `docker-compose.yml`:

```env
FORWARDED_ALLOW_IPS=172.20.0.0/16
```

Use the narrowest value that includes the proxy connecting directly to Kaya:

- Direct LAN access without a reverse proxy: keep `127.0.0.1`.
- Nginx Proxy Manager, Traefik, Caddy, or another Docker proxy: use its stable
  container IP or the dedicated Docker network CIDR.
- A reverse proxy connecting over NetBird: use its NetBird IP, or
  `100.64.0.0/10` when every NetBird peer on that range is trusted to proxy.
- Cloudflare Tunnel: trust only the local `cloudflared` container IP or its
  Docker network. Do not add all Cloudflare public ranges.

Multiple entries are comma-separated. Never use `*` for an installation that
can be reached directly. Recreate the container after changing the environment:

```bash
docker compose up -d --force-recreate kaya
```

In **Site Administration → Security**, the client-IP panel shows the effective
client IP, immediate peer, forwarded value, and whether the peer matched the
trusted-proxy configuration.

`ALLOWED_HOSTS` is unrelated: it restricts browser hostnames, while
`FORWARDED_ALLOW_IPS` identifies machines allowed to make forwarding claims.

## Backup Considerations

The application's own persistent state is not fully captured by the Backup Manager module.

Operational backups should include:

- SQLite database
- Runtime secrets
- Uploads
- Remote recordings

If using remote backup targets, verify credentials and mount/access behaviour outside Kaya as well.

## PostgreSQL operations

Kaya's PostgreSQL deployment includes an opt-in native backup worker in
`docker-compose.phase8-ops.yml`. It uses the pinned `postgres:16.14` client,
writes custom-format `pg_dump` archives to the persistent
`KAYA_POSTGRES_BACKUP_DIR`, verifies each archive with `pg_restore --list` and
a SHA-256 sidecar, and applies a count-based retention policy. The worker reads
the database password only from the mounted secret file; passwords are not
placed in command arguments, filenames, metadata, or logs.

Enable the scheduled worker explicitly with the `postgres-ops` profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.phase8-ops.yml --profile postgres-ops up -d postgres-backup
```

Set `KAYA_POSTGRES_BACKUP_INTERVAL_SECONDS`, `KAYA_POSTGRES_BACKUP_RETENTION`,
and `KAYA_POSTGRES_BACKUP_DIR` in the deployment environment. The worker is
separate from Kaya's request process and does not change the active database.
For a one-shot backup, verification, diagnostics, or restore drill, invoke the
same disposable service with `backup`, `verify`, `diagnostics`, or
`restore-drill`. A restore drill always targets a named disposable database;
never point it at the production database.

The admin-only About page reports PostgreSQL version, database size, active
connections, deadlocks, SQLAlchemy pool status, and the latest verified backup.
It deliberately excludes connection strings, usernames, passwords, backup
contents, and query values. `/healthz` remains a liveness check; database
readiness is exercised by the existing DB-backed application smoke path.

The supported architecture is:

```text
Kaya -> PostgreSQL 16.14 container -> kaya_postgres_data volume
```

The equivalent shell helper is `scripts/init-postgres-secret.sh`. The password
file is generated cryptographically, reused across restarts, ignored by Git,
and never printed by Kaya. Losing it prevents reconnection to that PostgreSQL
installation; protect it with the deployment backup.

PostgreSQL is not published on a host port. Kaya reaches it through the
private Compose network, and the service has a native `pg_isready` health
check. Kaya waits for that health check and uses SQLAlchemy pre-ping with a
conservative pool of five connections plus five overflow connections.

The bundled `kaya` role owns only the bundled `kaya` database and is not a
PostgreSQL superuser. It has the ownership needed for Alembic schema creation,
migrations, and normal application DDL; it is not granted access to other
databases.

`docker compose down` preserves `kaya_postgres_data`; `docker compose down -v`
is destructive and is not a routine upgrade command. PostgreSQL major version
16 is pinned to `postgres:16.14`, the current supported PostgreSQL 16 minor at
the time of this Phase 3 implementation. PostgreSQL major versions receive
five years of upstream support; PostgreSQL 16 is scheduled for support through
9 November 2028. Minor updates may be applied deliberately within major 16;
major upgrades require a backup, restore, and compatibility procedure.

### PostgreSQL backups and restore

PostgreSQL backups use the PostgreSQL 16 tools inside the pinned database
container, not SQLite file copying:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml exec -T postgres \
  pg_dump -U kaya -d kaya --format=custom --no-owner \
  --file=/var/backups/kaya-postgres/kaya-postgresql-$(date -u +%Y%m%dT%H%M%SZ)-20260818_02.dump
```

Backups are timestamped under `/var/backups/kaya-postgres`, backed by the host
directory `./postgres-backups` by default when the backup mount is added. Restore is explicit and must target
a new or disposable empty database:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml exec -T postgres \
  createdb -U kaya kaya_restore
docker compose -f docker-compose.yml -f docker-compose.postgres.yml exec -T postgres \
  pg_restore -U kaya -d kaya_restore --exit-on-error --no-owner \
  /var/backups/kaya-postgres/kaya-postgresql-YYYYMMDDTHHMMSSZ.dump
```

The database-container commands use its local PostgreSQL socket and do not put
the password in command arguments or logs. `pg_restore` targets the explicitly
created disposable database; it never drops or cleans a live target
automatically. Validate the restored Alembic revision and start Kaya against
the disposable target before accepting the backup.

Do not point an existing SQLite installation at an empty PostgreSQL database
outside the controlled Phase 6 path. Do not begin Phase 6 follow-on retirement
work as part of this deployment change.

## Downgrade boundary

PostgreSQL is the supported production architecture from this phase onward.
Downgrading an existing PostgreSQL installation to SQLite is not an automatic
or supported rollback: it can lose writes and would cross the proven migration
boundary. Roll back the application image only when its migrations are
compatible with the current PostgreSQL revision. If a PostgreSQL restore is
needed, restore a verified dump to a disposable database first, validate the
Alembic revision and application startup, and preserve the original database
until the replacement is accepted.

Kaya uses SQLite WAL mode. A running database can have `kaya.db-wal` and
`kaya.db-shm` beside `kaya.db`; these are live database state, not disposable
temporary files. Prefer Kaya's online backup workflow. If taking a raw
filesystem copy, stop Kaya cleanly first and copy the database directory as one
consistent unit rather than copying only `kaya.db`.
# Existing SQLite to PostgreSQL upgrade

Phase 6 upgrades an existing SQLite installation through a separate Compose
override. The base Compose file remains SQLite-compatible for new and
not-yet-migrated installations.

Before upgrading, ensure the existing `/app/data` storage is persistent and
that the PostgreSQL password file is private and contains a strong generated
password. Run the supported upgrade stack with:

```text
docker compose -f docker-compose.yml -f docker-compose.phase6-upgrade.yml up -d
```

Kaya detects the configured SQLite source, enters its durable upgrade state
machine before normal startup, validates the source, creates or reuses a
verified backup under `/app/data/backups`, migrates through the existing
SQLite-to-PostgreSQL engine, validates the target, and only then records
PostgreSQL as authoritative. The PostgreSQL service must be healthy before
copying begins.

During the upgrade, Kaya is not available for normal requests and database
writers are not started. Logs report stage and table progress without row
contents, credentials, hashes or filesystem paths intended for operators.

After success, PostgreSQL remains authoritative across restarts. Kaya does
not fall back to SQLite if PostgreSQL is unavailable. The original
`/app/data/kaya.db`, its verified migration backup, and the safe migration
report are retained for recovery. Do not delete or rename them as part of the
upgrade.

If the upgrade fails, Kaya records `FAILED`, leaves SQLite and its backup
preserved, and refuses an ambiguous retry. Review the logs and use the
explicit Phase 6 retry/target-cleanup procedure after confirming the failed
target is not active. Do not delete a database or use ad-hoc SQL against a
production target.
