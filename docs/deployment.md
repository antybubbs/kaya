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

## Backup Considerations

The application's own persistent state is not fully captured by the Backup Manager module.

Operational backups should include:

- SQLite database
- Runtime secrets
- Uploads
- Remote recordings

If using remote backup targets, verify credentials and mount/access behaviour outside Kaya as well.
