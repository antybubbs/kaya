#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/kaya}"
IMAGE="${1:-ghcr.io/antybubbs/kaya:latest}"

if [ -z "$IMAGE" ]; then
  echo "Usage: $0 ghcr.io/owner/kaya:latest"
  echo "Example: $0 ghcr.io/antybubbs/kaya:v1.0.0"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required before installing Kaya."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required before installing Kaya."
  exit 1
fi

sudo mkdir -p "$APP_DIR/data/remote-recordings" "$APP_DIR/data/secrets" "$APP_DIR/uploads"
if [ ! -f "$APP_DIR/data/secrets/postgres_password" ]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_urlsafe(64))' | sudo tee "$APP_DIR/data/secrets/postgres_password" >/dev/null
  sudo chmod 600 "$APP_DIR/data/secrets/postgres_password"
fi
sudo chown -R "$(id -u):$(id -g)" "$APP_DIR"

cat > "$APP_DIR/docker-compose.yml" <<COMPOSE
name: kaya

services:
  kaya:
    image: $IMAGE
    container_name: kaya
    restart: unless-stopped
    environment:
      DATABASE_URL: postgresql+psycopg://kaya@postgres:5432/kaya
      KAYA_POSTGRES_DATABASE_URL: postgresql+psycopg://kaya@postgres:5432/kaya
      KAYA_SQLITE_SOURCE_URL: sqlite:////app/data/kaya.db
      KAYA_PHASE6_AUTO_UPGRADE: "true"
      DATABASE_PASSWORD_FILE: /run/kaya-secrets/postgres_password
      FORWARDED_ALLOW_IPS: \${FORWARDED_ALLOW_IPS:-127.0.0.1}
    ports:
      - "\${KAYA_PORT:-8080}:8080"
    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
      - ./data/remote-recordings:/app/data/remote-recordings
      - kaya_postgres_secret:/run/kaya-secrets:ro
    security_opt:
      - no-new-privileges:true
    cap_add:
      - NET_RAW
    read_only: true
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=5).status == 200 else 1)\" >/dev/null 2>&1"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 120s
    tmpfs:
      - /tmp:size=128m,noexec,nosuid
  secure-send-gateway:
    image: $IMAGE
    container_name: kaya-secure-send
    restart: unless-stopped
    command: ["uvicorn", "app.security_gateway:app", "--host", "0.0.0.0", "--port", "8999", "--proxy-headers", "--forwarded-allow-ips", "\${FORWARDED_ALLOW_IPS:-127.0.0.1}", "--no-access-log", "--no-server-header"]
    environment:
      DATABASE_URL: postgresql+psycopg://kaya@postgres:5432/kaya
      KAYA_POSTGRES_DATABASE_URL: postgresql+psycopg://kaya@postgres:5432/kaya
      DATABASE_PASSWORD_FILE: /run/kaya-secrets/postgres_password
      FORWARDED_ALLOW_IPS: \${FORWARDED_ALLOW_IPS:-127.0.0.1}
      SKIP_DATABASE_MIGRATIONS: "true"
      KAYA_GATEWAY_MODE: "true"
    ports:
      - "\${KAYA_SECURE_SEND_PORT:-8999}:8999"
    volumes:
      - ./data:/app/data
      - kaya_postgres_secret:/run/kaya-secrets:ro
    depends_on:
      kaya:
        condition: service_healthy
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:size=64m,noexec,nosuid
      - /app/data/secret-vault:size=1m,noexec,nosuid
      - /app/data/remote-recordings:size=1m,noexec,nosuid
  guacd:
    image: guacamole/guacd:1.6.0
    container_name: kaya-guacd
    restart: unless-stopped

  postgres:
    image: postgres:16.14
    restart: unless-stopped
    environment:
      POSTGRES_DB: kaya
      POSTGRES_USER: kaya
      POSTGRES_PASSWORD_FILE: /run/kaya-secrets/postgres_password
    secrets:
      - postgres_password
    volumes:
      - kaya_postgres_data:/var/lib/postgresql/data
      - kaya_postgres_secret:/run/kaya-secrets:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U kaya -d kaya"]
      interval: 5s
      timeout: 5s
      retries: 30
      start_period: 10s

secrets:
  postgres_password:
    file: ./data/secrets/postgres_password

volumes:
  kaya_postgres_data:
    name: kaya_postgres_data
  kaya_postgres_secret:
    name: kaya_postgres_secret

networks:
  default:
    driver: bridge
    driver_opts:
      com.docker.network.driver.mtu: "1280"
COMPOSE

echo "Kaya has been installed to $APP_DIR"
echo ""
echo "Start it with:"
echo "  cd $APP_DIR && docker compose up -d"
echo ""
echo "Then open http://SERVER-IP:8080/setup to create the first admin account."
