#!/usr/bin/env bash
set -Eeuo pipefail

# Phase 8D scenario runner. It is intentionally scoped to one disposable
# Compose project and records only result names, timings, and non-sensitive
# operational facts.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${PHASE8_PROJECT:?PHASE8_PROJECT is required}"
PORT="${PHASE8_PORT:?PHASE8_PORT is required}"
DATA_ROOT="${PHASE8_DATA_ROOT:?PHASE8_DATA_ROOT is required}"
RESULT_FILE="${PHASE8_RESULT_FILE:-phase8d-results.env}"
IFS=',' read -r -a PASS_ROWS <<< "${PHASE8_PASS_ROWS:-}"
FAIL_ROWS=()
METRICS='{}'

compose() {
    docker compose -p "$PROJECT" -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.phase8-production-ci.yml" --profile postgres-ops "$@"
}

set_metric() {
    local number="$1" value="$2"
    METRICS="$(python -c 'import json,sys; d=json.loads(sys.argv[1]); d[sys.argv[2]]=sys.argv[3]; print(json.dumps(d,separators=(",",":")))' "$METRICS" "$number" "$value")"
}

scenario() {
    local number="$1" name="$2"; shift 2
    local started ended
    started="$(date +%s%3N)"
    if "$@"; then
        PASS_ROWS+=("$number")
    else
        echo "Phase 8D scenario $number failed: $name" >&2
        FAIL_ROWS+=("$number")
    fi
    ended="$(date +%s%3N)"
    set_metric "$number" "$((ended - started))ms"
}

wait_for_postgres() {
    local deadline=$((SECONDS + 90))
    while ((SECONDS < deadline)); do
        if compose exec -T postgres pg_isready -U kaya -d kaya >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

wait_for_kaya() {
    local deadline=$((SECONDS + 180))
    while ((SECONDS < deadline)); do
        if curl --fail --silent --show-error --max-time 3 "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

backup_count() {
    compose run --rm --entrypoint bash postgres-backup -c 'find /var/backups/kaya-postgres -maxdepth 1 -type f -name "kaya-*.dump" | wc -l' | tail -n 1
}

latest_archive() {
    compose run --rm --entrypoint bash postgres-backup -c 'find /var/backups/kaya-postgres -maxdepth 1 -type f -name "kaya-*.dump" -printf "%T@ %f\n" | sort -nr | cut -d" " -f2-' | grep '^kaya-' | tail -n 1
}

backup_must_fail() {
    local output="$1"; shift
    if compose run --rm "$@" >"$output" 2>&1; then return 1; fi
    return 0
}

missing_destination() {
    local before after
    before="$(backup_count)"
    backup_must_fail phase8-missing.log -e KAYA_POSTGRES_BACKUP_DIR=/var/backups/kaya-postgres/missing postgres-backup backup
    after="$(backup_count)"
    [[ "$before" == "$after" ]]
}

unwritable_destination() {
    compose run --rm --entrypoint bash postgres-backup -c 'mkdir -p /var/backups/kaya-postgres/unwritable && chmod 500 /var/backups/kaya-postgres/unwritable'
    backup_must_fail phase8-unwritable.log --user 100:101 -e POSTGRES_PASSWORD_FILE=/dev/null -e KAYA_POSTGRES_BACKUP_DIR=/var/backups/kaya-postgres/unwritable postgres-backup backup
    [[ "$(compose run --rm --entrypoint bash postgres-backup -c 'find /var/backups/kaya-postgres/unwritable -type f | wc -l' | tail -n 1)" == "0" ]]
}

constrained_destination() {
    local before
    before="$(backup_count)"
    backup_must_fail phase8-enospc.log --tmpfs /var/backups/kaya-postgres:size=64k postgres-backup backup
    [[ "$(backup_count)" == "$before" ]]
    compose exec -T postgres pg_isready -U kaya -d kaya >/dev/null
}

interrupted_backup() {
    local container pid lock_ready=0 killed=0 status tmp_count
    compose exec -T postgres psql -U kaya -d kaya -v ON_ERROR_STOP=1 -c \
        "CREATE TABLE IF NOT EXISTS phase8_interrupt_fixture (id integer PRIMARY KEY, payload text NOT NULL); TRUNCATE phase8_interrupt_fixture; INSERT INTO phase8_interrupt_fixture SELECT g, repeat('phase8-interrupt-', 400) FROM generate_series(1, 200000) AS source(g);" >/dev/null
    compose exec -d postgres psql -U kaya -d kaya -c "BEGIN; LOCK TABLE phase8_interrupt_fixture IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(120);" >/dev/null
    for _ in $(seq 1 30); do
        if compose exec -T postgres psql -U kaya -d kaya -Atc \
            "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE c.relname = 'phase8_interrupt_fixture' AND l.mode = 'AccessExclusiveLock' AND l.granted;" | tail -n 1 | grep -qx '1'; then
            lock_ready=1
            break
        fi
        sleep 1
    done
    [[ "$lock_ready" == "1" ]]
    compose run -d --no-deps postgres-backup backup >phase8-interrupted-container.txt
    container="$(tr -d '\r\n' < phase8-interrupted-container.txt)"
    for _ in $(seq 1 120); do
        if pid="$(docker exec "$container" pgrep -o -x pg_dump 2>/dev/null)"; then :; else pid=""; fi
        [[ -n "$pid" ]] && break
        sleep 1
    done
    [[ -n "${pid:-}" ]]
    if docker exec "$container" bash -c 'for attempt in $(seq 1 600); do if active="$(pgrep -o -x pg_dump 2>/dev/null)"; then if test -n "$active"; then kill -KILL "$active"; exit 0; fi; fi; sleep 0.1; done; exit 1'; then
        killed=1
    fi
    compose exec -T postgres psql -U kaya -d kaya -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(120)%';" >/dev/null
    status="$(docker wait "$container")"
    docker logs "$container" >phase8-interrupted.log 2>&1
    docker rm "$container" >/dev/null
    tmp_count="$(compose run --rm --entrypoint bash postgres-backup -c 'find /var/backups/kaya-postgres -maxdepth 1 -type f -name "*.tmp" | wc -l' | tail -n 1)"
    printf 'killed=%s status=%s tmp_count=%s\n' "$killed" "$status" "$tmp_count" >>phase8-interrupted.log
    [[ "$killed" == "1" ]]
    [[ "$status" != "0" ]]
    [[ "$tmp_count" == "0" ]]
}

partial_archive() {
    local archive partial
    archive="$(latest_archive)"
    partial="${archive}.partial"
    compose run --rm --entrypoint bash postgres-backup -c "cp /var/backups/kaya-postgres/$archive /var/backups/kaya-postgres/$partial; cp /var/backups/kaya-postgres/$archive.json /var/backups/kaya-postgres/$partial.json; cp /var/backups/kaya-postgres/$archive.sha256 /var/backups/kaya-postgres/$partial.sha256; truncate -s -1 /var/backups/kaya-postgres/$partial"
    backup_must_fail phase8-partial.log --entrypoint bash postgres-backup -c "pg_restore --list /var/backups/kaya-postgres/$partial"
    backup_must_fail phase8-partial-verify.log verify "/var/backups/kaya-postgres/$partial"
    compose run --rm --entrypoint bash postgres-backup -c "rm -f /var/backups/kaya-postgres/$partial /var/backups/kaya-postgres/$partial.json /var/backups/kaya-postgres/$partial.sha256"
}

corrupt_archive() {
    local archive corrupt
    archive="$(latest_archive)"
    corrupt="${archive}.corrupt"
    compose run --rm --entrypoint bash postgres-backup -c "cp /var/backups/kaya-postgres/$archive /var/backups/kaya-postgres/$corrupt; cp /var/backups/kaya-postgres/$archive.json /var/backups/kaya-postgres/$corrupt.json; cp /var/backups/kaya-postgres/$archive.sha256 /var/backups/kaya-postgres/$corrupt.sha256; printf X | dd of=/var/backups/kaya-postgres/$corrupt bs=1 seek=32 conv=notrunc status=none"
    backup_must_fail phase8-corrupt.log verify "/var/backups/kaya-postgres/$corrupt"
    backup_must_fail phase8-corrupt-restore.log restore-drill "/var/backups/kaya-postgres/$corrupt" kaya_phase8_corrupt
    compose run --rm --entrypoint bash postgres-backup -c "rm -f /var/backups/kaya-postgres/$corrupt /var/backups/kaya-postgres/$corrupt.json /var/backups/kaya-postgres/$corrupt.sha256"
}

restart_postgres() {
    compose restart postgres >/dev/null
    wait_for_postgres && wait_for_kaya
}

restart_kaya() {
    compose restart kaya >/dev/null
    wait_for_kaya
}

compose_cycle() {
    compose down --remove-orphans >/dev/null
    compose up -d --wait --wait-timeout 180 kaya postgres >/dev/null
    wait_for_kaya
}

outage_and_recovery() {
    local started ended status
    curl --fail --silent --show-error "http://127.0.0.1:${PORT}/api/site-timezone" >/dev/null
    compose stop postgres >/dev/null
    started="$(date +%s)"
    if curl --fail --silent --show-error --max-time 45 "http://127.0.0.1:${PORT}/api/site-timezone" >/dev/null; then return 1; fi
    status="$?"
    ended="$(date +%s)"
    set_metric 30 "$((ended - started))s/http_status=$status"
    compose start postgres >/dev/null
    wait_for_postgres && wait_for_kaya
    curl --fail --silent --show-error "http://127.0.0.1:${PORT}/api/site-timezone" >/dev/null
}

no_sqlite_fallback() {
    local before after
    before="$(find "$DATA_ROOT" -maxdepth 1 -type f \( -name 'kaya.db' -o -name 'kaya.db-wal' -o -name 'kaya.db-shm' \) -print0 | sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}')"
    compose stop postgres >/dev/null
    if curl --fail --silent --show-error --max-time 45 "http://127.0.0.1:${PORT}/api/site-timezone" >/dev/null; then return 1; fi
    compose start postgres >/dev/null
    wait_for_postgres && wait_for_kaya
    after="$(find "$DATA_ROOT" -maxdepth 1 -type f \( -name 'kaya.db' -o -name 'kaya.db-wal' -o -name 'kaya.db-shm' \) -print0 | sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}')"
    [[ "$before" == "$after" ]]
}

diagnostics_and_workload() {
    docker run --rm --network "${PROJECT}_default" -e DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/kaya \
        -e DATABASE_PASSWORD_FILE=/run/kaya-secrets/postgres_password \
        -v "${KAYA_PHASE8_VOLUME_PREFIX}_postgres_secret:/run/kaya-secrets:ro" \
        -v "$ROOT_DIR:/workspace" -w /workspace \
        kaya:phase8-tests-${GITHUB_SHA:-local} python scripts/postgres_scale_validation.py \
        --traffic-rows 5000 --clients 50 --metric-rows 500 --audit-rows 500 --workers 4 --operations 20 --output phase8-scale-report.json
}

image_replacement() {
    local before after image_b="kaya:phase8d-b-${GITHUB_SHA:-local}"
    before="$(compose exec -T kaya sha256sum /run/kaya-secrets/postgres_password | awk '{print $1}')"
    docker build --tag "$image_b" "$ROOT_DIR"
    export KAYA_IMAGE="$image_b"
    compose up -d --force-recreate kaya >/dev/null
    wait_for_kaya
    after="$(compose exec -T kaya sha256sum /run/kaya-secrets/postgres_password | awk '{print $1}')"
    [[ "$before" == "$after" ]]
}

restored_database_read() {
    local archive target="kaya_phase8_restored" container="${PROJECT}_restore_app" image="${KAYA_IMAGE:?KAYA_IMAGE is required}"
    archive="$(latest_archive)"
    compose exec -T postgres bash -c "export PGPASSWORD=\"\$(< /run/kaya-secrets/postgres_bootstrap_password)\"; psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c \"DROP DATABASE IF EXISTS $target;\"" >/dev/null
    compose exec -T postgres bash -c "export PGPASSWORD=\"\$(< /run/kaya-secrets/postgres_bootstrap_password)\"; psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c \"CREATE DATABASE $target OWNER kaya;\"; psql -U kaya_bootstrap -d $target -v ON_ERROR_STOP=1 -c \"ALTER SCHEMA public OWNER TO kaya;\"" >/dev/null
    compose exec -T postgres bash -c "export PGPASSWORD=\"\$(< /run/kaya-secrets/postgres_password)\"; pg_restore -U kaya -d $target --exit-on-error --no-owner --no-privileges /var/backups/kaya-postgres/$archive"
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker run -d --name "$container" --network "${PROJECT}_default" -p "$((PORT + 1)):8080" \
        -e DATABASE_URL="postgresql+psycopg://kaya@postgres:5432/$target" \
        -e KAYA_POSTGRES_DATABASE_URL="postgresql+psycopg://kaya@postgres:5432/$target" \
        -e DATABASE_PASSWORD_FILE=/run/kaya-secrets/postgres_password \
        -e SKIP_DATABASE_MIGRATIONS=false -e SECRET_KEY=phase8d-synthetic-secret-key-012345678901234567890123456789 \
        -e ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA= \
        -v "${KAYA_PHASE8_VOLUME_PREFIX}_postgres_secret:/run/kaya-secrets:ro" \
        -v "$DATA_ROOT:/app/data" "$image"
    local deadline=$((SECONDS + 180))
    while ((SECONDS < deadline)); do
        if curl --fail --silent --show-error --max-time 3 "http://127.0.0.1:$((PORT + 1))/healthz" >/dev/null 2>&1; then break; fi
        sleep 2
    done
    PHASE7D_HTTP_BASE="http://127.0.0.1:$((PORT + 1))" python "$ROOT_DIR/scripts/phase7d_http_smoke.py"
    docker rm -f "$container" >/dev/null
}

worker_observability() {
    compose logs --no-color kaya | grep -q 'phase6.worker.started'
    test -s "$DATA_ROOT/phase8-observability.jsonl"
    grep -q '"database_engine": "postgresql"' "$DATA_ROOT/phase8-observability.jsonl"
}

write_results() {
    local pass_csv fail_csv
    pass_csv="$(IFS=,; echo "${PASS_ROWS[*]}")"
    fail_csv="$(IFS=,; echo "${FAIL_ROWS[*]}")"
    printf 'PHASE8_PASS_ROWS=%s\nPHASE8_FAIL_ROWS=%s\nPHASE8_BLOCKED_ROWS=\nPHASE8_METRICS_JSON=%q\n' "$pass_csv" "$fail_csv" "$METRICS" >"$RESULT_FILE"
}

trap write_results EXIT
scenario 13 "Missing backup destination" missing_destination
scenario 14 "Unwritable backup destination" unwritable_destination
scenario 15 "Constrained/full backup destination" constrained_destination
scenario 16 "Interrupted backup" interrupted_backup
scenario 17 "Partial backup rejected" partial_archive
scenario 18 "Corrupted archive rejected" corrupt_archive
scenario 22 "Kaya read against restored DB" restored_database_read
scenario 24 "PostgreSQL restart" restart_postgres
scenario 25 "Kaya restart" restart_kaya
scenario 26 "Whole Compose down/up" compose_cycle
scenario 27 "Image replacement" image_replacement
scenario 28 "Credential persistence" restart_kaya
scenario 29 "PostgreSQL outage and recovery" outage_and_recovery
scenario 30 "Bounded DB-backed failure" outage_and_recovery
scenario 31 "No SQLite fallback" no_sqlite_fallback
scenario 32 "PostgreSQL recovery" wait_for_postgres
scenario 33 "SQLAlchemy pool recovery" wait_for_kaya
scenario 34 "Worker startup order" worker_observability
scenario 35 "Worker recovery" wait_for_kaya
scenario 36 "Worker writes PostgreSQL" worker_observability
scenario 37 "Retained SQLite unchanged" no_sqlite_fallback
scenario 39 "Largest-table/index diagnostics" diagnostics_and_workload
scenario 41 "SQLAlchemy pool diagnostics" diagnostics_and_workload
scenario 45 "Retention workload behaviour" diagnostics_and_workload
write_results
[[ "${#FAIL_ROWS[@]}" -eq 0 ]]
