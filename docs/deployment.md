# Deployment

**Kaya version:** `dev`  
**Documentation version:** `dev`

Kaya is designed for Docker Compose deployment.

## Docker Service

- Image: `ghcr.io/antybubbs/kaya:latest` by default
- Container port: `8080`
- Host port: `${KAYA_PORT:-8080}`
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
- `/app/data/kaya.db.pre-migration` when created

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
- Optionally creates a pre-migration SQLite backup.
- Runs `scripts/migrate_sqlite.py`.
- Starts Uvicorn.

## Upgrade Considerations

- Back up `data`, `uploads`, and recordings before upgrading.
- Preserve `.runtime.env`; losing the encryption key can make encrypted secrets unrecoverable.
- Migrations are manual and additive.
- Docker entrypoint can create a pre-migration SQLite backup.

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
