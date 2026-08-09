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

sudo mkdir -p "$APP_DIR/data/remote-recordings" "$APP_DIR/uploads"
sudo chown -R "$(id -u):$(id -g)" "$APP_DIR"

cat > "$APP_DIR/docker-compose.yml" <<COMPOSE
name: kaya

services:
  kaya:
    image: $IMAGE
    container_name: kaya
    restart: unless-stopped
    environment:
      DATABASE_URL: sqlite:////app/data/kaya.db
      FORWARDED_ALLOW_IPS: \${FORWARDED_ALLOW_IPS:-127.0.0.1}
    ports:
      - "\${KAYA_PORT:-8080}:8080"
    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
      - ./data/remote-recordings:/app/data/remote-recordings
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
      DATABASE_URL: sqlite:////app/data/kaya.db
      FORWARDED_ALLOW_IPS: \${FORWARDED_ALLOW_IPS:-127.0.0.1}
      SKIP_DATABASE_MIGRATIONS: "true"
      KAYA_GATEWAY_MODE: "true"
    ports:
      - "\${KAYA_SECURE_SEND_PORT:-8999}:8999"
    volumes:
      - ./data:/app/data
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
