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
    ports:
      - "\${KAYA_PORT:-8080}:8080"
    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
      - ./data/remote-recordings:/app/data/remote-recordings
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=64m
COMPOSE

echo "Kaya has been installed to $APP_DIR"
echo ""
echo "Start it with:"
echo "  cd $APP_DIR && docker compose up -d"
echo ""
echo "Then open http://SERVER-IP:8080/setup to create the first admin account."
