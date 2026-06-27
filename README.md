# Kaya

Kaya is a self-hosted infrastructure management platform for managing servers, services, assets, remote access, notes, licences and operational information from one place.

**Your Infrastructure. Your Home.**

Kaya was previously known as HomeLab. Some internal configuration keys, Docker image names, service names and database paths still use `homelab` or `HOMELAB_` for backwards compatibility.

<img width="2454" height="1227" alt="Kaya branding board" src="https://github.com/user-attachments/assets/f584720d-59df-4f40-a67a-42464bec5c2b" />


## FEATURES

TBC

## Docker Compose install

Use `docker-compose.yml` for a one-file install. It pulls `ghcr.io/antybubbs/homelab:kaya` by default; override `HOMELAB_IMAGE` only if you want another published tag.

Generate secure keys with:

```bash
python scripts/generate_secrets.py
```

Update an installer-based deployment:

```bash
cd /opt/homelab
cp data/homelab.db "data/homelab.db.backup-$(date +%Y%m%d-%H%M%S)"
docker compose pull
docker compose up -d
```

Preserve `/opt/homelab/.env`, `data`, and `uploads` when updating. Do not rerun
the installation script to perform a routine update.

## Development branch installs

Keep production on `ghcr.io/antybubbs/homelab:latest` or a pinned release such as `ghcr.io/antybubbs/homelab:v0.15.0`.

For a test server, switch the `.env` image line to the active development branch image:

```text
# HOMELAB_IMAGE=ghcr.io/antybubbs/homelab:latest
HOMELAB_IMAGE=ghcr.io/antybubbs/homelab:dev0.15.1
```

Then update the test server:

```bash
cd /opt/homelab
docker compose pull
docker compose up -d
```

Development builds show a Development channel in the sidebar version box.

## Reverse proxy

Set these values when serving through HTTPS:

```text
BASE_URL=https://homelab.example.com
ALLOWED_HOSTS=homelab.example.com
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
homelab.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

If Kaya is served from a path prefix such as `/homelab`, also set:

```text
ROOT_PATH=/homelab
```

## Public demo deployment

The demo deployment uses the current release image, synthetic seed data and three
fixed role accounts:

| Username | Password | Role |
| --- | --- | --- |
| `Admin` | `Admin` | Administrator |
| `Editor` | `Editor` | Editor |
| `Viewer` | `Viewer` | Viewer |

Identity, security, live remote connections, network checks, domain lookups and
agent operations are disabled when `DEMO_MODE=true`. Normal inventory and
runbook edits remain available until the next reset.

Deploy it on an isolated server with no route to a private LAN or VPN:

```bash
cp .env.demo.example .env.demo
# Set BASE_URL and ALLOWED_HOSTS in .env.demo.
docker compose -f docker-compose.demo.yml pull
docker compose -f docker-compose.demo.yml up -d
```

The first start creates `demo/seed/homelab.db` and copies it into the live demo
data directory. To restore that baseline manually:

```bash
docker compose -f docker-compose.demo.yml restart homelab
```

Run it every day at 03:00 with the host's cron:

```cron
0 3 * * * cd /opt/homelab && docker compose -f docker-compose.demo.yml restart homelab >> /var/log/homelab-demo-reset.log 2>&1
```

After changing to a newer Kaya release, rebuild the seed against that image
and immediately reset the live instance:

```bash
docker compose -f docker-compose.demo.yml pull
docker compose -f docker-compose.demo.yml run --rm --no-deps \
  -e DEMO_REBUILD_SEED=true homelab true
docker compose -f docker-compose.demo.yml restart homelab
```

Keep the demo behind HTTPS and reverse-proxy rate limiting. The published port
defaults to `8080`, and resource limits are applied. Do not attach this
deployment to NetBird, a home network, or any network containing real
infrastructure.

## Credit

Kaya Remote Manager is based on the same core architecture used by Termix:
- WebSocket transport between browser and backend
- Node.js SSH backend using ssh2
- xterm-compatible PTY sessions using xterm-256color
- JSON messages for connectToHost, input, resize, and disconnect

Termix is licensed under the Apache License, Version 2.0.

Original project: https://github.com/Termix-SSH/Termix

Copyright 2025 Luke Gustafson
