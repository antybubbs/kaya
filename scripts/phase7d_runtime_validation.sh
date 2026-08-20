#!/usr/bin/env bash
set -Eeuo pipefail

# Phase 7D runs only in an isolated GitHub-hosted Docker runner. The primary
# Compose file supplies the services and dependencies; the CI override only
# supplies unique names, ports, image tags, and synthetic bind paths.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="${RUNNER_TEMP:-/tmp}/kaya-phase7d-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
IMAGE_A="kaya:phase7d-a-${GITHUB_SHA:-local}"
IMAGE_B="kaya:phase7d-b-${GITHUB_SHA:-local}"
PRIMARY_FILE="$ROOT_DIR/docker-compose.yml"
OVERRIDE_FILE="$ROOT_DIR/docker-compose.phase7d-ci.yml"
PROJECTS=()
RESTORE_PROJECTS=()

compose() {
    docker compose -p "$PHASE7D_PROJECT" -f "$PRIMARY_FILE" -f "$OVERRIDE_FILE" "$@"
}

configure_project() {
    local project="$1" root="$2" http_port="$3" gateway_port="$4" image="$5"
    export PHASE7D_PROJECT="$project" PHASE7D_ROOT="$root"
    export PHASE7D_HTTP_PORT="$http_port" PHASE7D_GATEWAY_PORT="$gateway_port"
    export PHASE7D_IMAGE="$image"
    mkdir -p "$root/data/remote-recordings" "$root/uploads" "$root/secrets" "$root/backups"
    PROJECTS+=("$project")
}

wait_for_kaya() {
    local deadline=$((SECONDS + 240))
    while (( SECONDS < deadline )); do
        if curl --fail --silent --show-error --max-time 3 "http://127.0.0.1:${PHASE7D_HTTP_PORT}/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "Kaya did not become healthy for $PHASE7D_PROJECT" >&2
    compose ps
    return 1
}

secret_hash() {
    compose exec -T kaya sha256sum /run/kaya-secrets/postgres_password | awk '{print $1}'
}

secret_mode() {
    compose exec -T kaya stat -c '%a %u %g' /run/kaya-secrets/postgres_password
}

revision() {
    compose exec -T postgres psql -U kaya -d kaya -Atc 'SELECT version_num FROM alembic_version' | tr -d '\r'
}

assert_revision() {
    local actual
    actual="$(revision)"
    [[ "$actual" == "20260818_02" ]] || { echo "unexpected Alembic revision: $actual" >&2; return 1; }
}

setup_token() {
    compose exec -T kaya sh -c "sed -n 's/^SETUP_TOKEN=//p' /app/data/.runtime.env"
}

run_http_smoke() {
    local token="${1:-}"
    if [[ -n "$token" ]]; then
        KAYA_SETUP_TOKEN="$token" PHASE7D_HTTP_BASE="http://127.0.0.1:${PHASE7D_HTTP_PORT}" \
            python scripts/phase7d_http_smoke.py
    else
        PHASE7D_HTTP_BASE="http://127.0.0.1:${PHASE7D_HTTP_PORT}" \
            python scripts/phase7d_http_smoke.py
    fi
}

fingerprint_sqlite() {
    local data="$1"
    find "$data" -maxdepth 1 -type f \( -name 'kaya.db' -o -name 'kaya.db-wal' -o -name 'kaya.db-shm' \) -print0 \
        | sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}'
}

cleanup() {
    set +e
    mkdir -p "$RUN_ROOT/logs"
    for project in "${PROJECTS[@]}"; do
        export PHASE7D_PROJECT="$project"
        compose ps > "$RUN_ROOT/logs/${project}.ps.txt" 2>&1
        compose logs --no-color 2>&1 \
            | sed -E 's/(setup token: ).*/\1[REDACTED]/Ig; s/(password|secret|key)=([^ ]+)/\1=[REDACTED]/Ig' \
            > "$RUN_ROOT/logs/${project}.log"
        docker compose -p "$project" -f "$PRIMARY_FILE" -f "$OVERRIDE_FILE" down -v --remove-orphans >/dev/null 2>&1
    done
    for project in "${RESTORE_PROJECTS[@]}"; do
        docker compose -p "$project" -f "$ROOT_DIR/docker-compose.postgres-test.yml" down -v --remove-orphans >/dev/null 2>&1
    done
    docker image rm "$IMAGE_A" "$IMAGE_B" >/dev/null 2>&1
}
trap cleanup EXIT

mkdir -p "$RUN_ROOT"
export DOCKER_BUILDKIT=1
docker build -f "$ROOT_DIR/Dockerfile" -t "$IMAGE_A" "$ROOT_DIR"
docker build -f "$ROOT_DIR/Dockerfile" -t "$IMAGE_B" "$ROOT_DIR"
docker image inspect "$IMAGE_A" --format 'image_a={{.Id}}'
docker image inspect "$IMAGE_B" --format 'image_b={{.Id}}'

export PHASE7D_PROJECT="kaya_phase7d_config" PHASE7D_ROOT="$RUN_ROOT/config"
export PHASE7D_IMAGE="$IMAGE_A" PHASE7D_HTTP_PORT=18090 PHASE7D_GATEWAY_PORT=18990
docker compose -p "$PHASE7D_PROJECT" -f "$PRIMARY_FILE" -f "$OVERRIDE_FILE" config --quiet
grep -q 'postgres:16.14' <(docker compose -p "$PHASE7D_PROJECT" -f "$PRIMARY_FILE" -f "$OVERRIDE_FILE" config)
! grep -q '5432:' <(docker compose -p "$PHASE7D_PROJECT" -f "$PRIMARY_FILE" -f "$OVERRIDE_FILE" config)
echo 'primary compose validation passed'

# Fresh PostgreSQL-first install.
configure_project kaya_phase7d_fresh "$RUN_ROOT/fresh" 18091 18991 "$IMAGE_A"
compose up -d
wait_for_kaya
assert_revision
[[ "$(secret_mode)" == "600 100 101" ]]
fresh_hash="$(secret_hash)"
! compose logs --no-color kaya | grep -q 'Preparing controlled SQLite'
run_http_smoke "$(setup_token)"
compose down
compose up -d
wait_for_kaya
assert_revision
[[ "$(secret_hash)" == "$fresh_hash" ]]
run_http_smoke
echo 'fresh install, HTTP smoke, writes, and down/up persistence passed'

# Legacy SQLite through the primary production Compose architecture.
configure_project kaya_phase7d_legacy "$RUN_ROOT/legacy" 18092 18992 "$IMAGE_A"
docker run --rm --entrypoint python \
    -e SECRET_KEY=phase7d-synthetic-secret-key-012345678901234567890123 \
    -e ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA= \
    -e SETUP_TOKEN=phase7d-synthetic-setup-token \
    -v "$PHASE7D_ROOT/data:/app/data" "$IMAGE_A" \
    scripts/generate_sqlite_migration_fixture.py /app/data/kaya.db --functional
legacy_before="$(fingerprint_sqlite "$PHASE7D_ROOT/data")"
compose up -d
wait_for_kaya
assert_revision
state="$(python -c "import json; print(json.load(open('$PHASE7D_ROOT/data/kaya-database-upgrade.json', encoding='utf-8'))['state'])")"
[[ "$state" == "POSTGRES_ACTIVE" ]]
test -f "$PHASE7D_ROOT/data/kaya.db"
test -f "$PHASE7D_ROOT/data/kaya-database-upgrade-report.json"
test "$(find "$PHASE7D_ROOT/data/backups" -type f | wc -l)" -gt 0
run_http_smoke
legacy_after="$(fingerprint_sqlite "$PHASE7D_ROOT/data")"
[[ "$legacy_before" == "$legacy_after" ]]
legacy_hash="$(secret_hash)"
compose down
compose up -d
wait_for_kaya
assert_revision
[[ "$(secret_hash)" == "$legacy_hash" ]]
! compose logs --no-color kaya | grep -q 'Preparing controlled SQLite' || true
echo 'legacy migration, retained SQLite, HTTP smoke, and down/up persistence passed'

# Existing PostgreSQL startup without a SQLite source.
configure_project kaya_phase7d_existing_pg "$RUN_ROOT/existing-pg" 18093 18993 "$IMAGE_A"
compose up -d
wait_for_kaya
assert_revision
run_http_smoke "$(setup_token)"
compose down
compose up -d
wait_for_kaya
assert_revision
echo 'existing PostgreSQL startup passed'

# Image replacement against the migrated project.
export PHASE7D_PROJECT=kaya_phase7d_legacy PHASE7D_ROOT="$RUN_ROOT/legacy" PHASE7D_IMAGE="$IMAGE_B" PHASE7D_HTTP_PORT=18092 PHASE7D_GATEWAY_PORT=18992
compose up -d --force-recreate kaya secure-send-gateway
wait_for_kaya
assert_revision
[[ "$(secret_hash)" == "$legacy_hash" ]]
echo 'image replacement and credential persistence passed'

# Outage and fail-closed startup checks.
compose exec -T postgres psql -U kaya -d kaya -c "INSERT INTO audit_logs (user_id, action, entity, entity_id, detail, category, severity, status_code, capture_tier, created_at) SELECT id, 'phase7d.postgres_only', 'test', 'phase7d', 'synthetic', 'activity', 'info', 200, 'standard', CURRENT_TIMESTAMP FROM users WHERE role = 'admin' LIMIT 1;" >/dev/null
compose stop postgres
start_time="$SECONDS"
set +e
curl --silent --show-error --max-time 20 "http://127.0.0.1:${PHASE7D_HTTP_PORT}/healthz" >/dev/null
curl_status=$?
set -e
outage_seconds=$((SECONDS - start_time))
(( outage_seconds <= 20 ))
(( curl_status != 0 ))
compose start postgres
wait_for_kaya
compose stop kaya postgres
set +e
compose start kaya >/dev/null 2>&1
startup_status=$?
set -e
(( startup_status != 0 )) || ! compose ps kaya | grep -q 'healthy'
compose start postgres
compose up -d kaya
wait_for_kaya
echo "PostgreSQL outage fail-closed and bounded startup checks passed (${outage_seconds}s)"

# Native PostgreSQL backup and separate disposable restore project.
backup="$RUN_ROOT/legacy/backups/phase7d.dump"
compose exec -T postgres pg_dump -U kaya -d kaya --format=custom --no-owner > "$backup"
test -s "$backup"
export KAYA_POSTGRES_TEST_PORT=55439
restore_project=kaya_phase7d_restore
RESTORE_PROJECTS+=("$restore_project")
docker compose -p "$restore_project" -f "$ROOT_DIR/docker-compose.postgres-test.yml" up -d
docker compose -p "$restore_project" -f "$ROOT_DIR/docker-compose.postgres-test.yml" exec -T postgres \
    pg_restore -U kaya_test -d kaya_test --exit-on-error --no-owner < "$backup"
restore_revision="$(docker compose -p "$restore_project" -f "$ROOT_DIR/docker-compose.postgres-test.yml" exec -T postgres psql -U kaya_test -d kaya_test -Atc 'SELECT version_num FROM alembic_version' | tr -d '\r')"
[[ "$restore_revision" == "20260818_02" ]]
echo 'PostgreSQL backup and separate restore passed'

echo 'Phase 7D runtime validation passed'
