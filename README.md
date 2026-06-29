<img width="250" height="250" alt="image" src="https://github.com/user-attachments/assets/893ff230-83e1-4a2e-8a7a-f08d9a6a83f7" align="center"/>

# Kaya

**Your Infrastructure. Your Home.**

Kaya is a self-hosted infrastructure management platform for servers, services, assets, remote access, runbooks, licences and day-to-day operational information.

Kaya is built for home lab and small infrastructure environments where you want one place to understand what exists, how it is connected, how to access it, and what needs attention.

<img width="2544" height="1262" alt="image" src="https://github.com/user-attachments/assets/9c9bd1c1-1cbe-45c5-981c-28d9d7063fc7" />

## Features

- Infrastructure dashboard with live health and capacity overview
- VLAN/IP, domain, WAN and network monitoring workflows
- Hardware asset and rack management
- Remote Manager for browser-based SSH/RDP access
- VM/Docker monitoring integrations
- Runbooks and operational documentation
- Licence, user, audit and application administration
- Docker Compose deployment with persistent local data

## Demo
https://demo.kaya-app.uk

## One-file Docker Compose install

Use `docker-compose.yml` directly. It pulls the Kaya image and starts the app plus Guacamole daemon support:

```bash
mkdir -p /opt/kaya
cd /opt/kaya
curl -fsSLO https://raw.githubusercontent.com/antybubbs/Kaya/main/docker-compose.yml
docker compose up -d
```

Open `http://SERVER-IP:8080/setup` and create the first administrator account.

The compose file uses these defaults:

```text
KAYA_IMAGE=ghcr.io/antybubbs/kaya:latest
KAYA_PORT=8080
```

To override them, create a `.env` file beside `docker-compose.yml`:

```text
KAYA_IMAGE=ghcr.io/antybubbs/kaya:latest
KAYA_PORT=8080
```

Kaya stores application data in `./data` and uploaded files in `./uploads`. Back up both directories before updates.

## Updating

```bash
cd /opt/kaya
cp data/kaya.db "data/kaya.db.backup-$(date +%Y%m%d-%H%M%S)"
docker compose pull
docker compose up -d
```

Kaya stores its SQLite database at `data/kaya.db`.

## Reverse proxy

Set these values when serving through HTTPS:

```text
BASE_URL=https://kaya.example.com
ALLOWED_HOSTS=kaya.example.com
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
kaya.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

If Kaya is served from a path prefix such as `/kaya`, also set:

```text
ROOT_PATH=/kaya
```

## Remote Manager credit

Kaya Remote Manager is based on the same core architecture used by Termix:

- WebSocket transport between browser and backend
- Node.js SSH backend using ssh2
- xterm-compatible PTY sessions using xterm-256color
- JSON messages for connectToHost, input, resize and disconnect

Termix is licensed under the Apache License, Version 2.0.

Original project: https://github.com/Termix-SSH/Termix

Copyright 2025 Luke Gustafson
