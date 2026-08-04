# Deployment

**Kaya version:** `dev`  
**Documentation version:** `dev`

Kaya is designed for Docker Compose deployment.

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
- `guacd` using `guacamole/guacd:1.6.0`

## Persistent Volumes

- `./data:/app/data`
- `./uploads:/app/uploads`
- `./data/remote-recordings:/app/data/remote-recordings`

Important persistent files:

- `/app/data/kaya.db`
- `/app/data/.runtime.env`
- `/app/uploads`
- `/app/data/remote-recordings`
- `/app/data/backups/pre-migration-*.sqlite3` and matching revision metadata when an existing database requires migration

## Environment Settings

Important environment/configuration values include:

- `DATABASE_URL`
- `SECRET_KEY`
- `ENCRYPTION_KEY`
- `BASE_URL`
- `ALLOWED_HOSTS`
- `FORWARDED_ALLOW_IPS` (trusted reverse-proxy IPs or CIDR networks; defaults to `127.0.0.1`)
- `SESSION_COOKIE_SECURE`
- `DEMO_MODE`
- Guacamole-related settings
- Upload and recording size settings

## Startup Behaviour

The entrypoint:

- Creates persistent data/upload/recording directories.
- Generates and preserves runtime secrets in `/app/data/.runtime.env` when not supplied.
- Handles demo seed/reset behaviour when demo mode is enabled.
- Creates and verifies a timestamped pre-migration SQLite backup with SQLite's backup API before changing an existing database.
- Runs the safe `app.db` Alembic preparation lifecycle.
- Starts Uvicorn.

## Upgrade Considerations

- For a routine container upgrade, run `docker compose pull` followed by `docker compose up -d`; Kaya performs any required backup and Alembic upgrade automatically.
- Back up `data`, `uploads`, and recordings before upgrading.
- Preserve `.runtime.env`; losing the encryption key can make encrypted secrets unrecoverable.
- Normal startup runs the Alembic lifecycle automatically before application services.
- Pre-Alembic installations use the retained compatibility bridge and are stamped only after full validation.
- RDP certificate verification is strict after the security migration. Inventory RDP hosts before upgrade. Public/system-CA certificates require no Kaya pin when guacd trusts the CA; self-signed hosts require independently verified per-host SHA-256 pins. Do not restore connectivity by enabling certificate bypass or TOFU.
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
