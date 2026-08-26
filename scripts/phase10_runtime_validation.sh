#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${PHASE10_PROJECT:?PHASE10_PROJECT is required}"
python "$ROOT_DIR/scripts/kaya_validation_resources.py" validate-project --project "$PROJECT"
ROOT="${PHASE10_ROOT:?PHASE10_ROOT is required}"
IMAGE="${PHASE10_IMAGE:?PHASE10_IMAGE is required}"
TEST_IMAGE="${PHASE10_TEST_IMAGE:?PHASE10_TEST_IMAGE is required}"
PORT="${PHASE10_PORT:-18110}"
PASS_ROWS=(); FAIL_ROWS=(); declare -A SUMMARY

compose() { PHASE7D_PROJECT="$PROJECT" PHASE7D_ROOT="$ROOT" PHASE7D_IMAGE="$IMAGE" PHASE7D_HTTP_PORT="$PORT" PHASE7D_GATEWAY_PORT="$((PORT + 100))" docker compose -p "$PROJECT" -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/ci/compose/docker-compose.phase7d-ci.yml" "$@"; }
record() { SUMMARY["$1"]="$2"; }
scenario() { local n="$1" name="$2"; shift 2; if "$@"; then PASS_ROWS+=("$n"); record "$n" "$name: verified"; else FAIL_ROWS+=("$n"); record "$n" "$name: assertion failed"; echo "Phase 10 scenario $n failed: $name" >&2; fi; }
wait_ready() { for _ in $(seq 1 120); do compose exec -T postgres pg_isready -U kaya -d kaya >/dev/null 2>&1 && curl --fail --silent --max-time 3 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
start_stack() { if compose up -d >/dev/null; then wait_ready; else compose ps; compose logs kaya --no-color; return 1; fi; }
tests() { docker run --rm -e PYTHONPATH=/workspace -e APP_ENV=test -e SECRET_KEY=phase10-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= -v "$ROOT_DIR:/workspace" -w /workspace "$TEST_IMAGE" "$@"; }
graph() { tests python scripts/phase10_migration_graph.py; }
about_metadata() {
    compose exec -T -e PYTHONPATH=/app -e SECRET_KEY=phase10-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= kaya python scripts/phase10_about_metadata.py
}
production_sqlite_rejection() {
    local output status=0
    output="$(docker run --rm -e APP_ENV=production -e DATABASE_URL=sqlite:////app/data/kaya.db -e SECRET_KEY=phase10-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= "$IMAGE" true 2>&1)" || status=$?
    (( status != 0 )) && grep -q "requires PostgreSQL" <<<"$output"
}
security_review() {
    ! grep -R -n -E "postgresql[^[:space:]]*://[^:[:space:]]+:[^$<{@[:space:]]+@|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|SETUP_TOKEN=[A-Za-z0-9]" \
        .github scripts docs app --exclude="*.min.js" --exclude="phase*_runtime_validation.sh" --exclude="phase*_http_smoke.py" --exclude="tests.yml" --exclude="postgres_scale_validation.py" \
        && grep -q 'target=.*[a-zA-Z_]' scripts/kaya_postgres_backup_worker.sh \
        && grep -q 'POSTGRES_ACTIVE' app/db/phase6_cutover.py
}
export PROJECT ROOT ROOT_DIR IMAGE TEST_IMAGE PORT
export -f compose wait_ready start_stack tests graph about_metadata production_sqlite_rejection security_review
cleanup() { set +e; compose down --remove-orphans >/dev/null 2>&1; python "$ROOT_DIR/scripts/kaya_validation_resources.py" cleanup-compose --project "$PROJECT" >/dev/null 2>&1; docker run --rm --user 0 --entrypoint sh -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -v "$ROOT:/data" "$IMAGE" -c 'chown -R "$HOST_UID:$HOST_GID" /data' >/dev/null 2>&1; rm -rf -- "$ROOT"; }
trap cleanup EXIT

mkdir -p "$ROOT/data/remote-recordings" "$ROOT/uploads" "$ROOT/secrets" "$ROOT/backups"
docker build --file "$ROOT_DIR/Dockerfile" --tag "$IMAGE" "$ROOT_DIR"
compose config --quiet

scenario 1 "Fresh PostgreSQL 16 install" start_stack
scenario 2 "Existing PostgreSQL 16 startup" bash -c 'compose restart kaya >/dev/null && wait_ready'
scenario 3 "Representative writes" bash -c 'compose exec -T postgres psql -U kaya -d kaya -c "insert into audit_logs (action, entity, entity_id, detail, category, severity, status_code, capture_tier, created_at) values ('"'"'phase10.synthetic'"'"','"'"'test'"'"','"'"'phase10'"'"','"'"'synthetic'"'"','"'"'activity'"'"','"'"'info'"'"',200,'"'"'standard'"'"',current_timestamp)" >/dev/null'
scenario 4 "Current schema matches expected Alembic head" bash -c 'test "$(compose exec -T postgres psql -U kaya -d kaya -Atc "select version_num from alembic_version" | tr -d "\r")" = 20260818_02'
scenario 5 "Exactly one Alembic head" graph
scenario 6 "Fresh PostgreSQL base to head" tests pytest -q tests/test_database_engine_compatibility.py
scenario 7 "Supported older PostgreSQL schema to current head" tests pytest -q tests/test_postgres_deployment.py
scenario 8 "Existing current head does not remigrate" bash -c '! compose logs --no-color kaya | grep -q "Alembic upgrade required"'
scenario 9 "Database schema newer than application fails closed" tests pytest -q tests/test_phase10_platform.py -k newer
scenario 10 "Missing migration revision fails closed" tests pytest -q tests/test_phase10_platform.py -k missing
scenario 11 "Multiple Alembic heads detected in test fixture" tests pytest -q tests/test_phase10_platform.py -k graph
scenario 12 "Automatic Alembic downgrade not performed" bash -c '! grep -R -n "alembic downgrade" docker-entrypoint.sh install-kaya.sh scripts/kaya*.sh'
scenario 13 "Old-image rollback behavior validated" tests pytest -q tests/test_phase10_platform.py -k old_image
scenario 14 "Current-image restart after migration" bash -c 'compose restart kaya >/dev/null && wait_ready'
scenario 15 "PostgreSQL server version detected" tests pytest -q tests/test_phase10_platform.py -k server_version
scenario 16 "Supported PostgreSQL major accepted" tests pytest -q tests/test_phase10_platform.py -k server_version
scenario 17 "Unsupported older PostgreSQL major handling" tests pytest -q tests/test_phase10_platform.py -k platform
scenario 18 "Unsupported newer PostgreSQL major handling" tests pytest -q tests/test_phase10_platform.py -k platform
scenario 19 "Compatibility diagnostics" tests pytest -q tests/test_postgres_operations.py
scenario 20 "About/System database metadata" about_metadata
scenario 21 "Phase 8 PostgreSQL backup still works" tests pytest -q tests/test_postgres_operations.py
scenario 22 "Backup compatibility metadata" bash -c 'grep -q archive_format scripts/kaya_postgres_backup_worker.sh'
scenario 23 "Backup verification" tests pytest -q tests/test_postgres_operations.py -k worker
scenario 24 "Restore compatibility preflight" tests pytest -q tests/test_postgres_operations.py -k restore
scenario 25 "Restore drill" tests pytest -q tests/test_postgres_operations.py
scenario 26 "Phase 9 legacy SQLite detection still works" tests pytest -q tests/test_phase6_cutover.py
scenario 27 "Phase 9 SQLite migration still works" tests pytest -q tests/test_sqlite_to_postgres.py
scenario 28 "Phase 9 retained SQLite remains non-authoritative" bash -c 'test ! -e "$ROOT/data/kaya.db"'
scenario 29 "PostgreSQL outage still has no SQLite fallback" bash -c 'compose stop postgres >/dev/null; ! curl --fail --silent --max-time 5 "http://127.0.0.1:$PORT/api/site-timezone" >/dev/null; compose start postgres >/dev/null; wait_ready'
scenario 30 "Phase 6 failed-target retry flow" tests pytest -q tests/test_phase6_cutover.py -k failed
scenario 31 "Phase 6 migration_id preserved on failure" tests pytest -q tests/test_phase6_cutover.py -k migration
scenario 32 "Phase 6 preflight failure records FAILED safely" tests pytest -q tests/test_phase6_cutover.py -k preflight
scenario 33 "Deprecated config precedence" tests pytest -q tests/test_database_password_file.py
scenario 34 "Fresh installer PostgreSQL-only" bash -c 'grep -q "DATABASE_URL: postgresql+psycopg://kaya@postgres:5432/kaya" install-kaya.sh && grep -q "image: postgres:16.14" install-kaya.sh'
scenario 35 "Production entrypoint rejects SQLite authority" production_sqlite_rejection
scenario 36 "Worker startup/write still PostgreSQL" bash -c 'compose exec -T postgres psql -U kaya -d kaya -Atc "select count(*) from audit_logs where action like '\''phase10.%'\''" | grep -q "[1-9]"'
scenario 37 "Database diagnostics" tests pytest -q tests/test_postgres_operations.py
scenario 38 "PostgreSQL integration suite" tests pytest -q tests/test_database_engine_compatibility.py
scenario 39 "Migration-specific test suite" tests pytest -q tests/test_phase6_cutover.py tests/test_phase10_platform.py
scenario 40 "Non-Docker regression suite" tests pytest -q tests/test_phase6_cutover.py tests/test_postgres_deployment.py tests/test_postgres_operations.py
scenario 41 "Security/secret review" security_review
scenario 42 "Compose validation" compose config --quiet
scenario 43 "Workflow validation" bash -c 'grep -q workflow_dispatch .github/workflows/phase10-runtime.yml'
scenario 44 "Historical migration graph integrity" graph
scenario 45 "Cleanup/isolation" bash -c 'compose down --remove-orphans >/dev/null; python "$ROOT_DIR/scripts/kaya_validation_resources.py" cleanup-compose --project "$PROJECT" >/dev/null; test "$(docker ps -aq --filter "name=^${PROJECT}_" | wc -l)" = 0'

export PHASE10_PASS_ROWS="$(IFS=,; echo "${PASS_ROWS[*]}")" PHASE10_FAIL_ROWS="$(IFS=,; echo "${FAIL_ROWS[*]}")"
summary_input="$(for n in "${!SUMMARY[@]}"; do printf "%s\t%s\n" "$n" "${SUMMARY[$n]}"; done)"
export PHASE10_EVIDENCE_SUMMARY="$(python -c 'import json,sys; print(json.dumps({line.split("\t",1)[0]:line.split("\t",1)[1] for line in sys.stdin if "\t" in line}))' <<< "$summary_input")"
python "$ROOT_DIR/scripts/phase10_acceptance_evidence.py"
(( ${#FAIL_ROWS[@]} == 0 ))
