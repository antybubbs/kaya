# KeyVault

Self-hosted product key and licence management for homelabs, small IT teams, and internal IT departments.

KeyVault stores, searches and maintains software licence records securely. It supports CSV import, role-based access, key masking, audit logging, Docker deployment and Forgejo-hosted container releases.

## What is included

- FastAPI web application
- Polished dark UI
- Docker and Docker Compose deployment
- Forgejo Actions workflow for container publishing
- SQLite database by default
- CSV import for Microsoft Volume Licensing style exports
- Local user authentication
- Argon2 password hashing
- Product key encryption at rest
- Key masking with audited reveal
- Audit log for sensitive actions
- Production compose file and installer script

## Security-first defaults

- Product keys are encrypted at rest using application-level Fernet encryption.
- Users authenticate locally using Argon2 password hashing.
- Sessions use signed cookies.
- Product keys are masked by default and only revealed to authorised admin/editor users.
- Reveal, create, update, delete and import actions are written to an audit log.
- Security headers are set by middleware.
- Secrets are injected using environment variables, not hard-coded.
- Production compose drops Linux capabilities and uses `no-new-privileges`.
- Uploads and database files are stored on persistent Docker volumes/directories.

## Local development quick start

```bash
cp .env.example .env
python scripts/generate_secrets.py
# Put the generated SECRET_KEY and ENCRYPTION_KEY into .env
docker compose up --build
```

Open:

```text
http://localhost:8080
```

Default admin credentials come from `.env`:

```text
ADMIN_EMAIL=admin@example.local
ADMIN_PASSWORD=change-me-now
```

Change these before using the app with real licence data.

## Import your initial CSV

After signing in as an admin:

```text
Admin > Import CSV
```

The importer supports the Microsoft Volume Licensing style CSV columns:

- License ID
- Parent Program
- Organization
- Product
- Product Key
- Type
- MAK Activations-Used/Available
- Seats
- OSA Status

## Install from Forgejo

This repository is packaged so Forgejo can host both the source code and the Docker image.

1. Push the repository to Forgejo at `https://forg.app.strubens.uk/cheezy/KeyVault.git`.
2. Enable Forgejo Actions.
3. Add a repository secret called `FORGEJO_TOKEN` with package publish rights.
4. Push to `main` or create a version tag such as `v1.0.0`.
5. Install using the published image.

Full guide:

```text
docs/INSTALL_FROM_FORGEJO.md
```

Basic install command on your Docker host:

```bash
./install-from-forgejo.sh
cd /opt/keyvault
docker compose up -d
```

## Production notes

For production deployment:

- Put KeyVault behind HTTPS using Caddy, Traefik or Nginx Proxy Manager.
- Set `SESSION_COOKIE_SECURE=true` once HTTPS is enabled.
- Set `BASE_URL` to the real HTTPS URL. If users browse by an IP address or additional hostname, add those exact hosts to `ALLOWED_HOSTS` as a comma-separated list.
- Keep `FORWARDED_ALLOW_IPS=*` only when KeyVault is reachable exclusively through your trusted proxy or Docker network.
- Generate a new `SECRET_KEY` and `ENCRYPTION_KEY`.
- Keep `/app/data` and `/app/uploads` on persistent storage.
- Back up the database, uploads and `.env` encryption key.
- Restrict access with VPN, Authentik, Cloudflare Access or an internal network boundary.

## Reverse proxy

Set these values when serving through HTTPS:

```text
BASE_URL=https://keyvault.example.com
ALLOWED_HOSTS=keyvault.example.com
SESSION_COOKIE_SECURE=true
FORWARDED_ALLOW_IPS=*
```

Your proxy must preserve the original host and forward the client scheme/IP.

Nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Caddy:

```caddyfile
keyvault.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

If KeyVault is served from a path prefix such as `/keyvault`, also set:

```text
ROOT_PATH=/keyvault
```

## Generate secure keys

```bash
python scripts/generate_secrets.py
```

## Updating

If installed from Forgejo packages:

```bash
cd /opt/keyvault
docker compose pull
docker compose up -d
```
