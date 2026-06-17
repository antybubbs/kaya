# HomeLab

Self-hosted home lab management solution.
<img width="2454" height="1227" alt="image" src="https://github.com/user-attachments/assets/f584720d-59df-4f40-a67a-42464bec5c2b" />


## FEATURES

TBC

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

Change these before using the app with real data.

## Docker Compose install

Create an `.env` file beside `docker-compose.prod.yml`:

```text
HOMELAB_IMAGE=ghcr.io/antybubbs/homelab:latest
# Development/test server only:
# HOMELAB_IMAGE=ghcr.io/antybubbs/homelab:dev0.15.1
HOMELAB_PORT=8080
APP_NAME=HomeLab
APP_ENV=production
BASE_URL=https://homelab.example.com
ALLOWED_HOSTS=homelab.example.com
SESSION_COOKIE_SECURE=true
FORWARDED_ALLOW_IPS=*
DATABASE_URL=sqlite:////app/data/homelab.db
UPLOAD_DIR=/app/uploads
MAX_UPLOAD_MB=25
GITHUB_REPO=antybubbs/HomeLab
```

Also set strong generated values for:

```text
SECRET_KEY
ENCRYPTION_KEY
ADMIN_EMAIL
ADMIN_PASSWORD
```

Generate secure keys with:

```bash
python scripts/generate_secrets.py
```

Start or update:

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

## Development branch installs

Keep production on `ghcr.io/antybubbs/homelab:latest` or a pinned release such as `ghcr.io/antybubbs/homelab:v0.15.0`.

For a test server, switch the `.env` image line to the active development branch image:

```text
# HOMELAB_IMAGE=ghcr.io/antybubbs/homelab:latest
HOMELAB_IMAGE=ghcr.io/antybubbs/homelab:dev0.15.1
```

Then update the test server:

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
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

If HomeLab is served from a path prefix such as `/homelab`, also set:

```text
ROOT_PATH=/homelab
```

## Credit

HomeLab Remote Manager is based on the same core architecture used by Termix:
- WebSocket transport between browser and backend
- Node.js SSH backend using ssh2
- xterm-compatible PTY sessions using xterm-256color
- JSON messages for connectToHost, input, resize, and disconnect

Termix is licensed under the Apache License, Version 2.0.

Original project: https://github.com/Termix-SSH/Termix

Copyright 2025 Luke Gustafson
