# HomeLab

Self-hosted home lab management solution.
<img width="2443" height="1232" alt="image" src="https://github.com/user-attachments/assets/65577434-d6a5-49a4-9fde-3165666bfa10" />

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

## Security notes

- Product keys are encrypted at rest using application-level Fernet encryption.
- Users authenticate locally using Argon2 password hashing.
- Product keys are masked by default and only revealed to authorised admin/editor users.
- Reveal, create, update, delete, import and export actions are written to an audit log.
- Secrets are injected using environment variables, not hard-coded.
- Keep `/app/data`, `/app/uploads` and the `.env` encryption key backed up.
- Restrict access with VPN, Authentik, Cloudflare Access or an internal network boundary.
