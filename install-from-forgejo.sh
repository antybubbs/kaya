#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/keyvault}"
IMAGE="${1:-forg.app.strubens.uk/cheezy/keyvault:latest}"

if [ -z "$IMAGE" ]; then
  echo "Usage: $0 forgejo.example.local/owner/keyvault:latest"
  echo "Example: $0 forgejo.example.local/anthony/keyvault:v1.0.0"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required before installing KeyVault."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required before installing KeyVault."
  exit 1
fi

sudo mkdir -p "$APP_DIR/data" "$APP_DIR/uploads"
sudo chown -R "$(id -u):$(id -g)" "$APP_DIR"

cat > "$APP_DIR/docker-compose.yml" <<'COMPOSE'
services:
  keyvault:
    image: ${KEYVAULT_IMAGE:?Set KEYVAULT_IMAGE in .env}
    container_name: keyvault
    restart: unless-stopped
    env_file:
      - .env
    ports:
      - "${KEYVAULT_PORT:-8080}:8080"
    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    tmpfs:
      - /tmp:noexec,nosuid,size=64m
COMPOSE

SECRET_KEY=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(64))
PY
)

ENCRYPTION_KEY=$(python3 - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)

ADMIN_PASSWORD=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)

cat > "$APP_DIR/.env" <<ENV
KEYVAULT_IMAGE=$IMAGE
KEYVAULT_PORT=8080
APP_NAME=KeyVault
APP_ENV=production
BASE_URL=http://localhost:8080
ROOT_PATH=
SECRET_KEY=$SECRET_KEY
ENCRYPTION_KEY=$ENCRYPTION_KEY
ADMIN_EMAIL=admin@example.local
ADMIN_PASSWORD=$ADMIN_PASSWORD
DATABASE_URL=sqlite:////app/data/keyvault.db
UPLOAD_DIR=/app/uploads
MAX_UPLOAD_MB=25
ALLOWED_HOSTS=
SESSION_COOKIE_SECURE=false
FORWARDED_ALLOW_IPS=*
ENV

echo "KeyVault has been installed to $APP_DIR"
echo "Admin email: admin@example.local"
echo "Temporary admin password: $ADMIN_PASSWORD"
echo ""
echo "Start it with:"
echo "  cd $APP_DIR && docker compose up -d"
echo ""
echo "Once HTTPS is enabled, edit $APP_DIR/.env and set SESSION_COOKIE_SECURE=true."
