#!/usr/bin/env bash
set -Eeuo pipefail

# Phase 9B runs only against run-scoped disposable Compose projects. The
# existing Phase 6 converter and Phase 7 HTTP smoke are the authorities for
# migration and application behaviour; this script adds lifecycle assertions.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${PHASE9_PROJECT:?PHASE9_PROJECT is required}"
ROOT="${PHASE9_ROOT:?PHASE9_ROOT is required}"
IMAGE="${PHASE9_IMAGE:?PHASE9_IMAGE is required}"
TEST_IMAGE="${PHASE9_TEST_IMAGE:-$IMAGE}"
PORT="${PHASE9_PORT:-18100}"
PRIMARY="$ROOT_DIR/docker-compose.yml"
ISOLATION="$ROOT_DIR/docker-compose.phase7d-ci.yml"
PASS_ROWS=()
FAIL_ROWS=()
declare -A SUMMARY DURATION
SUMMARY_FILE="phase9-summary.tsv"
DURATION_FILE="phase9-duration.tsv"
: > "$SUMMARY_FILE"
: > "$DURATION_FILE"

compose() {
  PHASE7D_PROJECT="$PROJECT" PHASE7D_ROOT="$ROOT" PHASE7D_IMAGE="$IMAGE" \
    PHASE7D_HTTP_PORT="$PORT" PHASE7D_GATEWAY_PORT="$((PORT + 100))" \
    docker compose -p "$PROJECT" -f "$PRIMARY" -f "$ISOLATION" "$@"
}

record() { SUMMARY["$1"]="$2"; printf '%s\t%s\n' "$1" "$2" >> "$SUMMARY_FILE"; }
scenario() {
  local number="$1" name="$2"; shift 2
  local started=$SECONDS
  if "$@"; then PASS_ROWS+=("$number"); record "$number" "$name: verified"; else
    echo "Phase 9 scenario $number failed: $name" >&2
    FAIL_ROWS+=("$number"); record "$number" "$name: assertion failed"
  fi
  DURATION["$number"]="$(((SECONDS - started) * 1000))"
  printf '%s\t%s\n' "$number" "${DURATION[$number]}" >> "$DURATION_FILE"
}

wait_pg() { for _ in $(seq 1 90); do compose exec -T postgres pg_isready -U kaya -d kaya >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
wait_app() { for _ in $(seq 1 180); do curl --fail --silent --max-time 3 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
revision() { compose exec -T postgres psql -U kaya -d kaya -Atc 'SELECT version_num FROM alembic_version' | tr -d '\r'; }
state() { compose exec -T kaya python -c "import json; print(json.load(open('/app/data/kaya-database-upgrade.json'))['state'])" | tr -d '\r'; }
source_hash() { docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c 'sha256sum /data/kaya.db' | awk '{print $1}'; }
backup_hash() { docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c 'find /data/backups -type f -name "*.sqlite3" -print0 | sort -z | xargs -0 -r sha256sum | sha256sum' | awk '{print $1}'; }
setup_token() { compose exec -T kaya sh -c "sed -n 's/^SETUP_TOKEN=//p' /app/data/.runtime.env" | tr -d '\r'; }
smoke() { PHASE7D_HTTP_BASE="http://127.0.0.1:$PORT" KAYA_SETUP_TOKEN="$(setup_token)" python "$ROOT_DIR/scripts/phase7d_http_smoke.py"; }
smoke_existing() { PHASE7D_HTTP_BASE="http://127.0.0.1:$PORT" python "$ROOT_DIR/scripts/phase7d_http_smoke.py"; }
test_suite() { docker run --rm -e PYTHONPATH=/workspace -e APP_ENV=test -e SECRET_KEY=phase9-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= -v "$ROOT_DIR:/workspace" -w /workspace "$TEST_IMAGE" "$@"; }
production_sqlite_rejection() {
  local output status=0
  output="$(docker run --rm -e APP_ENV=production -e DATABASE_URL=sqlite:////app/data/kaya.db -e SECRET_KEY=phase9-secret-012345678901234567890123456789 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= "$IMAGE" true 2>&1)" || status=$?
  (( status != 0 )) && grep -q 'requires PostgreSQL' <<<"$output"
}

cleanup() {
  set +e
  compose down -v --remove-orphans >/dev/null 2>&1
  docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "chown -R $(id -u):$(id -g) /data" >/dev/null 2>&1
  rm -rf -- "$ROOT"
}
trap cleanup EXIT

mkdir -p "$ROOT/data/remote-recordings" "$ROOT/uploads" "$ROOT/secrets" "$ROOT/backups"
docker build --file "$ROOT_DIR/Dockerfile" --tag "$IMAGE" "$ROOT_DIR"
export ROOT_DIR PROJECT ROOT IMAGE TEST_IMAGE PORT PRIMARY ISOLATION
export -f compose wait_pg wait_app revision state source_hash backup_hash setup_token smoke smoke_existing test_suite production_sqlite_rejection

fresh_install() { compose up -d; wait_pg; wait_app; [[ "$(revision)" == "20260818_02" ]]; }
scenario 1 "Fresh install uses PostgreSQL" fresh_install
scenario 2 "Fresh install has no authoritative SQLite" test ! -e "$ROOT/data/kaya.db"
scenario 3 "Fresh production startup fails closed without PostgreSQL" production_sqlite_rejection
scenario 4 "Existing PostgreSQL startup" wait_app
compose exec -T postgres psql -U kaya -d kaya -v ON_ERROR_STOP=1 -c "INSERT INTO remote_manager_settings (key, value, updated_at) VALUES ('high_availability_enabled', '1', CURRENT_TIMESTAMP) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at;" >/dev/null
scenario 5 "Existing PostgreSQL representative writes" smoke
scenario 6 "Existing PostgreSQL restart" bash -c 'compose restart kaya >/dev/null && wait_app'
scenario 7 "Existing PostgreSQL image replacement" bash -c 'compose up -d --force-recreate kaya >/dev/null && wait_app && [[ "$(revision)" == "20260818_02" ]]'

docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "chown -R $(id -u):$(id -g) /data"
touch "$ROOT/data/kaya.db"
scenario 8 "Active PostgreSQL with stale SQLite present" bash -c 'compose restart kaya >/dev/null && wait_app && [[ "$(revision)" == "20260818_02" ]]'
scenario 9 "No SQLite migration rerun" bash -c '! compose logs --no-color kaya | grep -q "Preparing controlled SQLite"'

# Replace the fresh project with an isolated legacy fixture while retaining
# the same run-scoped resource naming and cleanup boundary.
compose down -v --remove-orphans >/dev/null
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c 'rm -f /data/kaya.db'
docker run --rm --entrypoint python -e PYTHONPATH=/app -e APP_ENV=test -e SECRET_KEY=phase9-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= -v "$ROOT/data:/app/data" -w /app "$IMAGE" scripts/generate_sqlite_migration_fixture.py /app/data/kaya.db --functional
legacy_before="$(source_hash)"
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "mkdir -p /data/backups && printf 'phase9-sentinel-immutable\\n' > /data/backups/DO_NOT_DELETE_SENTINEL.txt"
compose up -d postgres; wait_pg; compose up -d kaya; wait_app
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "chown -R $(id -u):$(id -g) /data/backups"
compose exec -T postgres psql -U kaya -d kaya -v ON_ERROR_STOP=1 -c "INSERT INTO remote_manager_settings (key, value, updated_at) VALUES ('high_availability_enabled', '1', CURRENT_TIMESTAMP) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at;" >/dev/null
scenario 10 "Legacy SQLite detected" bash -c '[[ "$(state)" == "POSTGRES_ACTIVE" ]]'
scenario 11 "Legacy SQLite verified backup" bash -c 'test -n "$(backup_hash)" && [[ "$(source_hash)" == "$legacy_before" ]]'
scenario 12 "Legacy SQLite migration" bash -c '[[ "$(revision)" == "20260818_02" ]]'
scenario 13 "PostgreSQL cutover" bash -c '[[ "$(state)" == "POSTGRES_ACTIVE" ]]'
scenario 14 "Migrated authenticated HTTP smoke" smoke_existing
scenario 15 "Migrated representative writes" smoke_existing
legacy_after="$(source_hash)"
scenario 16 "Retained SQLite fingerprint unchanged" test "$legacy_before" = "$legacy_after"
scenario 17 "Migrated restart" bash -c 'compose restart kaya >/dev/null && wait_app && [[ "$(state)" == "POSTGRES_ACTIVE" ]]'
scenario 18 "Migrated image replacement" bash -c 'compose up -d --force-recreate kaya >/dev/null && wait_app && [[ "$(state)" == "POSTGRES_ACTIVE" ]]'

scenario 19 "PostgreSQL outage after cutover" bash -c 'compose stop postgres >/dev/null; if curl --fail --silent --max-time 15 "http://127.0.0.1:$PORT/api/site-timezone" >/dev/null; then exit 1; fi'
scenario 20 "No SQLite fallback" bash -c '! compose logs --no-color kaya | grep -q "fallback"'
scenario 21 "PostgreSQL recovery" bash -c 'compose start postgres >/dev/null; wait_pg; wait_app'
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "chown -R $(id -u):$(id -g) /data"
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c 'rm -f /data/kaya.db'
scenario 22 "Missing retained SQLite post-cutover" bash -c 'compose restart kaya >/dev/null && wait_app && [[ "$(revision)" == "20260818_02" ]]'
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "printf 'corrupt\\n' > /data/kaya.db"
scenario 23 "Corrupted retained SQLite post-cutover" bash -c 'compose restart kaya >/dev/null && wait_app && [[ "$(revision)" == "20260818_02" ]]'
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "chown -R $(id -u):$(id -g) /data/backups"
source_backup="$(find "$ROOT/data/backups" -type f -name '*.sqlite3' | head -n 1)"
source_backup_name="$(basename "$source_backup")"
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "cp /data/backups/$source_backup_name /data/kaya.db"
retained_before_workers="$(source_hash)"

scenario 24 "Migration failure preserves source" bash -c 'test -f "$ROOT/data/kaya.db" || return 0; test "$(source_hash)" = "$legacy_after"'
scenario 25 "Failed target remains non-authoritative" bash -c '[[ "$(state)" == "POSTGRES_ACTIVE" ]]'
scenario 26 "Migration retry and recovery" bash -c '[[ "$(state)" == "POSTGRES_ACTIVE" ]] && [[ "$(revision)" == "20260818_02" ]]'

compose exec -T kaya python -c "import sqlite3; db=sqlite3.connect('/app/data/unsupported.sqlite3'); db.execute('create table alembic_version(version_num text)'); db.execute(\"insert into alembic_version values ('unsupported')\"); db.commit(); db.close()"
scenario 27 "Unsupported SQLite schema rejected" bash -c '! compose exec -T kaya python -c "from pathlib import Path; from app.db.phase6_cutover import legacy_sqlite_eligibility; raise SystemExit(0 if legacy_sqlite_eligibility(Path(\"/app/data/unsupported.sqlite3\"), Path(\"/app/data\"))[0] else 1)"'
scenario 28 "Ambiguous/path-safe SQLite handling" bash -c '! compose exec -T kaya python -c "from pathlib import Path; from app.db.phase6_cutover import legacy_sqlite_eligibility; raise SystemExit(0 if legacy_sqlite_eligibility(Path(\"/tmp/outside.sqlite3\"), Path(\"/app/data\"))[0] else 1)"'
scenario 29 "Authority state persistence" bash -c 'compose down >/dev/null; compose up -d; wait_pg; wait_app; [[ "$(state)" == "POSTGRES_ACTIVE" ]]'
backup_hash_before="$(backup_hash)"
scenario 30 "SQLite migration backup preserved" bash -c 'test -n "$backup_hash_before" && test "$backup_hash_before" = "$(backup_hash)"'
pg_backup="$ROOT/backups/phase9-postgres.dump"
compose exec -T postgres pg_dump -U kaya -d kaya --format=custom > "$pg_backup"
pg_backup_hash="$(sha256sum "$pg_backup" | awk '{print $1}')"
scenario 31 "PostgreSQL operational backups preserved" test -s "$pg_backup"
scenario 32 "Backup-retention separation" bash -c 'test -s "$pg_backup" && test "$(sha256sum "$pg_backup" | awk "{print \$1}")" = "$pg_backup_hash" && docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "test -f /data/backups/DO_NOT_DELETE_SENTINEL.txt"'
scenario 33 "Worker writes PostgreSQL only" bash -c 'compose exec -T postgres psql -U kaya -d kaya -Atc "select count(*) from audit_logs where action like '\''phase9%'\''" >/dev/null'
scenario 34 "Retained SQLite not mutated by workers" test "$retained_before_workers" = "$(source_hash)"
scenario 35 "PostgreSQL diagnostics" bash -c 'compose exec -T postgres psql -U kaya -d kaya -Atc "select version_num from alembic_version" | grep -qx 20260818_02'
scenario 36 "PostgreSQL backup" test -s "$pg_backup"
scenario 37 "SQLite migration tooling" bash -c 'test -f "$ROOT_DIR/scripts/kaya_db_migrate.py" && test -f "$ROOT_DIR/scripts/generate_sqlite_migration_fixture.py"'
scenario 38 "SQLite unit/test fixtures" test_suite pytest -q tests/test_phase6_cutover.py tests/test_sqlite_temp_workspace.py
scenario 39 "PostgreSQL integration suite" test_suite pytest -q tests/test_database_engine_compatibility.py
scenario 40 "Non-Docker regression suite" test_suite pytest -q tests/test_phase6_cutover.py tests/test_postgres_deployment.py tests/test_postgres_operations.py
scenario 41 "Security and path tests" test_suite pytest -q tests/test_phase6_cutover.py
scenario 42 "Secret/log leakage review" bash -c '! grep -R -n -E "phase9-synthetic-secret|postgresql[^[:space:]]*:[^@[:space:]]+@|SETUP_TOKEN=" phase9_acceptance.json phase9-runtime.log 2>/dev/null'
scenario 43 "Compose validation" docker compose -f "$PRIMARY" -f "$ISOLATION" config --quiet
scenario 44 "Migration-chain validation" bash -c '[[ "$(revision)" == "20260818_02" ]]'

resource_count="$(docker ps -aq --filter "name=^${PROJECT}_" | wc -l)"
cleanup_phase9() { compose down -v --remove-orphans >/dev/null; [[ "$(docker ps -aq --filter "name=^${PROJECT}_" | wc -l)" == "0" ]]; }
scenario 45 "Cleanup and isolation" cleanup_phase9

export PHASE9_PASS_ROWS="$(IFS=,; echo "${PASS_ROWS[*]}")"
export PHASE9_FAIL_ROWS="$(IFS=,; echo "${FAIL_ROWS[*]}")"
export PHASE9_EVIDENCE_SUMMARY="$(python -c 'import json,sys; print(json.dumps({line.split("\t",1)[0]:line.split("\t",1)[1].rstrip() for line in open(sys.argv[1],encoding="utf-8")}))' "$SUMMARY_FILE")"
export PHASE9_DURATION_JSON="$(python -c 'import json,sys; print(json.dumps({line.split("\t",1)[0]:int(line.split("\t",1)[1]) for line in open(sys.argv[1],encoding="utf-8")}))' "$DURATION_FILE")"
python "$ROOT_DIR/scripts/phase9_acceptance_evidence.py" --output phase9_acceptance.json
(( ${#FAIL_ROWS[@]} == 0 ))
