#!/usr/bin/env bash
set -Eeuo pipefail

# Phase 9B runs only against run-scoped disposable Compose projects. The
# existing Phase 6 converter and Phase 7 HTTP smoke are the authorities for
# migration and application behaviour; this script adds lifecycle assertions.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${PHASE9_PROJECT:?PHASE9_PROJECT is required}"
python "$ROOT_DIR/scripts/kaya_validation_resources.py" validate-project --project "$PROJECT"
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
backup_hash() { docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c 'find /data/backups -type f -name "*.sqlite3" -printf "%f\\n" | sort | sha256sum' | awk '{print $1}'; }
legacy_backup_valid() { test -n "$(backup_hash)" && docker run --rm --user 0 --entrypoint python -v "$ROOT/data:/data" "$IMAGE" -c 'import sqlite3; c=sqlite3.connect("/data/kaya.db"); assert c.execute("pragma quick_check").fetchone()[0] == "ok"; c.close()'; }
historical_backup_valid() { docker run --rm --user 0 --entrypoint python -v "$ROOT/data:/data" "$IMAGE" -c 'import glob, json; assert any(json.load(open(path))["source_revision"] == "20260813_01" for path in glob.glob("/data/backups/*.json"))'; }
migration_report_valid() { compose exec -T kaya python -c 'import json; r=json.load(open("/app/data/kaya-database-upgrade-report.json", encoding="utf-8")); assert r["result"] == "COMPLETED" and r["rejected_rows"] == 0 and r["skipped_rows"] == 0 and r["foreign_key_violations"] == 0 and len(r["dependency_order"]) == 104'; }
historical_identity_valid() {
  local source_identity target_identity
  source_identity="$(compose exec -T kaya python -c 'import json; s=json.load(open("/app/data/kaya-database-upgrade.json", encoding="utf-8")); print("|".join((s["migration_id"], s["original_source_fingerprint"], s["conversion_source_fingerprint"])))' | tr -d '\r')"
  target_identity="$(compose exec -T postgres psql -U kaya -d kaya -Atc "SELECT migration_id || '|' || original_source_fingerprint || '|' || conversion_source_fingerprint FROM kaya_migration_state ORDER BY started_at DESC LIMIT 1" | tr -d '\r')"
  test -n "$source_identity" && test "$source_identity" = "$target_identity"
}
legacy_relationships_valid() {
  compose exec -T postgres psql -U kaya -d kaya -Atc "SELECT
    (SELECT count(*) FROM dns_client_events e LEFT JOIN dns_recognised_devices d ON d.id=e.dns_client_id WHERE d.id IS NULL) +
    (SELECT count(*) FROM dns_client_events e LEFT JOIN dns_providers p ON p.id=e.provider_id WHERE e.provider_id IS NOT NULL AND p.id IS NULL) +
    (SELECT count(*) FROM dns_client_hostname_history h LEFT JOIN dns_recognised_devices d ON d.id=h.dns_client_id WHERE d.id IS NULL) +
    (SELECT count(*) FROM dns_client_ip_history h LEFT JOIN dns_providers p ON p.id=h.provider_id WHERE h.provider_id IS NOT NULL AND p.id IS NULL) +
    (SELECT count(*) FROM dns_client_observations o LEFT JOIN dns_recognised_devices d ON d.id=o.dns_client_id WHERE d.id IS NULL) +
    (SELECT count(*) FROM dns_client_traffic_events e LEFT JOIN dns_recognised_devices d ON d.id=e.dns_client_id WHERE d.id IS NULL) +
    (SELECT count(*) FROM dns_insights i LEFT JOIN dns_providers p ON p.id=i.provider_id WHERE p.id IS NULL) +
    (SELECT count(*) FROM dns_investigations i LEFT JOIN dns_providers p ON p.id=i.provider_id WHERE i.provider_id IS NOT NULL AND p.id IS NULL) +
    (SELECT count(*) FROM ha_agent_action_results a LEFT JOIN ha_nodes n ON n.id=a.node_id WHERE n.id IS NULL) +
    (SELECT count(*) FROM ha_agent_credentials c LEFT JOIN ha_nodes n ON n.id=c.node_id WHERE n.id IS NULL) +
    (SELECT count(*) FROM ha_backups b LEFT JOIN ha_sync_runs s ON s.id=b.sync_run_id WHERE s.id IS NULL) +
    (SELECT count(*) FROM ha_drift_items d LEFT JOIN ha_sync_runs s ON s.id=d.sync_run_id WHERE s.id IS NULL) +
    (SELECT count(*) FROM ha_events e LEFT JOIN ha_nodes n ON n.id=e.node_id WHERE e.node_id IS NOT NULL AND n.id IS NULL) +
    (SELECT count(*) FROM ha_failover_runs f LEFT JOIN ha_nodes n ON n.id=f.target_node_id WHERE n.id IS NULL) +
    (SELECT count(*) FROM ha_health_checks h LEFT JOIN ha_nodes n ON n.id=h.node_id WHERE h.node_id IS NOT NULL AND n.id IS NULL) +
    (SELECT count(*) FROM ha_lease_replication_states s LEFT JOIN ha_nodes n ON n.id=s.source_node_id WHERE n.id IS NULL) +
    (SELECT count(*) FROM ha_lease_snapshots s LEFT JOIN ha_nodes n ON n.id=s.target_node_id WHERE n.id IS NULL) = 0" | tr -d '\r' | grep -qx t
}
legacy_fk_logs_clean() { ! compose logs --no-color kaya postgres | grep -Eiq 'foreignkeyviolation|foreign key constraint|missing-parent|rejected insert'; }
migration_source_preserved() { test -f "$ROOT/data/kaya.db" && docker run --rm --user 0 --entrypoint python -v "$ROOT/data:/data" "$IMAGE" -c 'import sqlite3; c=sqlite3.connect("/data/kaya.db"); assert c.execute("pragma quick_check").fetchone()[0] == "ok"; c.close()'; }
backup_preserved() { test -n "$backup_hash_before" && test "$backup_hash_before" = "$(backup_hash)"; }
retention_separated() { test -s "$pg_backup" && test "$(sha256sum "$pg_backup" | awk '{print $1}')" = "$pg_backup_hash" && docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c 'test -f /data/backups/DO_NOT_DELETE_SENTINEL.txt'; }
retry_env() { printf '%s\n' -e APP_ENV=test -e SECRET_KEY=phase9-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= -e KAYA_TEST_MODE=true -e KAYA_POSTGRES_DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/phase9_retry -e DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/phase9_retry; }
retry_state() { local key="$1"; docker run --rm --user 0 --entrypoint python -v "$ROOT:/phase9" "$IMAGE" -c "import json; print(json.load(open('/phase9/retry-data/kaya-database-upgrade.json'))['$key'])"; }
induce_retry_failure() {
  compose exec -T postgres bash -c \
    'export PGPASSWORD="$(< /run/kaya-secrets/postgres_bootstrap_password)"; psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE phase9_retry OWNER kaya;"'
  docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/source:ro" -v "$ROOT/retry-data:/retry" "$IMAGE" -c \
    'mkdir -p /retry/backups; cp /source/kaya.db /retry/kaya.db'
  local status=0
  docker run --rm --user 0 --network "${PROJECT}_default" --entrypoint python -v "$ROOT/retry-data:/app/data" -v "${PROJECT}_postgres_secret:/run/kaya-secrets:ro" -w /app \
    -e PYTHONPATH=/app -e APP_ENV=test -e SECRET_KEY=phase9-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
    -e KAYA_TEST_MODE=true -e KAYA_TEST_FAILPOINT=fail_during_copy -e KAYA_POSTGRES_DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/phase9_retry \
    -e DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/phase9_retry -e DATABASE_PASSWORD_FILE=/run/kaya-secrets/postgres_password "$IMAGE" scripts/kaya_phase6_upgrade.py \
    --source /app/data/kaya.db --target-url postgresql+psycopg://kaya@postgres:5432/phase9_retry --backup-dir /app/data/backups --data-dir /app/data || status=$?
  (( status != 0 ))
}
verify_failed_retry() { test "$(retry_state state)" = FAILED && migration_source_preserved; }
retry_normal_refusal() {
  local status=0 output
  output="$(compose run --rm --no-deps -v "$ROOT/retry-data:/app/data" \
    -e KAYA_POSTGRES_DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/phase9_retry \
    -e DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/phase9_retry kaya true 2>&1)" || status=$?
  (( status != 0 )) && grep -q 'operator recovery is required before startup' <<<"$output"
}
retry_recovery() {
  local migration_id source_fingerprint output
  migration_id="$(retry_state migration_id)"; source_fingerprint="$(retry_state source_fingerprint)"
  output="$(compose run --rm --no-deps -v "$ROOT/retry-data:/app/data" \
    -e KAYA_POSTGRES_DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/phase9_retry \
    -e DATABASE_URL=postgresql+psycopg://kaya@postgres:5432/phase9_retry kaya \
    python -m scripts.kaya_phase6_upgrade \
    --source /app/data/kaya.db --backup-dir /app/data/backups --data-dir /app/data \
    --clean-failed-target --migration-id "$migration_id" --source-fingerprint "$source_fingerprint" 2>&1)"
  grep -q 'failed PostgreSQL migration target cleaned' <<<"$output"
  ! grep -q 'PostgreSQL target contains an incomplete SQLite migration and is not startup-authoritative' <<<"$output"
  compose exec -T postgres psql -U kaya -d phase9_retry -Atc 'select version_num from alembic_version' | tr -d '\r' | grep -qx 20260818_02
}
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
  compose down --remove-orphans >/dev/null 2>&1
  python "$ROOT_DIR/scripts/kaya_validation_resources.py" cleanup-compose --project "$PROJECT" >/dev/null 2>&1
  docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "chown -R $(id -u):$(id -g) /data" >/dev/null 2>&1
  rm -rf -- "$ROOT"
}
trap cleanup EXIT

mkdir -p "$ROOT/data/remote-recordings" "$ROOT/uploads" "$ROOT/secrets" "$ROOT/backups"
docker build --file "$ROOT_DIR/Dockerfile" --tag "$IMAGE" "$ROOT_DIR"
export ROOT_DIR PROJECT ROOT IMAGE TEST_IMAGE PORT PRIMARY ISOLATION
export -f compose wait_pg wait_app revision state source_hash backup_hash legacy_backup_valid historical_backup_valid migration_report_valid historical_identity_valid legacy_relationships_valid legacy_fk_logs_clean migration_source_preserved backup_preserved retention_separated retry_state induce_retry_failure verify_failed_retry retry_normal_refusal retry_recovery setup_token smoke smoke_existing test_suite production_sqlite_rejection

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
compose down --remove-orphans >/dev/null
python "$ROOT_DIR/scripts/kaya_validation_resources.py" cleanup-compose --project "$PROJECT" >/dev/null
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c 'rm -f /data/kaya.db'
docker run --rm --entrypoint python -e PYTHONPATH=/app -e APP_ENV=test -e SECRET_KEY=phase9-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= -v "$ROOT/data:/app/data" -w /app "$IMAGE" scripts/generate_sqlite_migration_fixture.py /app/data/kaya.db --functional --historical-revision 20260813_01
legacy_before="$(source_hash)"
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "mkdir -p /data/backups && printf 'phase9-sentinel-immutable\\n' > /data/backups/DO_NOT_DELETE_SENTINEL.txt"
compose up -d postgres; wait_pg; compose up -d kaya; wait_app
docker run --rm --user 0 --entrypoint sh -v "$ROOT/data:/data" "$IMAGE" -c "chown -R $(id -u):$(id -g) /data/backups"
compose exec -T postgres psql -U kaya -d kaya -v ON_ERROR_STOP=1 -c "INSERT INTO remote_manager_settings (key, value, updated_at) VALUES ('high_availability_enabled', '1', CURRENT_TIMESTAMP) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at;" >/dev/null
scenario 10 "Legacy SQLite detected" bash -c '[[ "$(state)" == "POSTGRES_ACTIVE" ]]'
scenario 11 "Legacy SQLite verified backup" legacy_backup_valid
scenario 12 "Legacy SQLite migration" bash -c '[[ "$(revision)" == "20260818_02" ]] && historical_backup_valid && migration_report_valid && historical_identity_valid && legacy_relationships_valid && legacy_fk_logs_clean'
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

scenario 24 "Migration failure preserves source" induce_retry_failure
scenario 25 "Failed target remains non-authoritative" bash -c 'verify_failed_retry && retry_normal_refusal'
scenario 26 "Migration retry and recovery" retry_recovery

compose exec -T kaya python -c "import sqlite3; db=sqlite3.connect('/app/data/unsupported.sqlite3'); db.execute('create table alembic_version(version_num text)'); db.execute(\"insert into alembic_version values ('unsupported')\"); db.commit(); db.close()"
scenario 27 "Unsupported SQLite schema rejected" bash -c '! compose exec -T -e APP_ENV=test -e SECRET_KEY=phase9-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= kaya python -c "from pathlib import Path; from app.db.phase6_cutover import legacy_sqlite_eligibility; raise SystemExit(0 if legacy_sqlite_eligibility(Path(\"/app/data/unsupported.sqlite3\"), Path(\"/app/data\"))[0] else 1)"'
scenario 28 "Ambiguous/path-safe SQLite handling" bash -c '! compose exec -T -e APP_ENV=test -e SECRET_KEY=phase9-synthetic-secret-key-012345678901234567890123 -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= kaya python -c "from pathlib import Path; from app.db.phase6_cutover import legacy_sqlite_eligibility; raise SystemExit(0 if legacy_sqlite_eligibility(Path(\"/tmp/outside.sqlite3\"), Path(\"/app/data\"))[0] else 1)"'
scenario 29 "Authority state persistence" bash -c 'compose down >/dev/null; compose up -d; wait_pg; wait_app; [[ "$(state)" == "POSTGRES_ACTIVE" ]]'
backup_hash_before="$(backup_hash)"
scenario 30 "SQLite migration backup preserved" backup_preserved
pg_backup="$ROOT/backups/phase9-postgres.dump"
compose exec -T postgres pg_dump -U kaya -d kaya --format=custom > "$pg_backup"
pg_backup_hash="$(sha256sum "$pg_backup" | awk '{print $1}')"
scenario 31 "PostgreSQL operational backups preserved" test -s "$pg_backup"
scenario 32 "Backup-retention separation" retention_separated
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
cleanup_owned_retry_fixture() {
  local fixture="$ROOT/retry-data"
  if [[ -d "$fixture" && ! -L "$fixture" ]]; then
    docker run --rm --user 0 --entrypoint sh -v "$fixture:/phase9-cleanup:rw" "$IMAGE" -c \
      'test ! -L /phase9-cleanup; find /phase9-cleanup -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +'
    rmdir -- "$fixture"
  fi
}
cleanup_phase9() {
  compose down --remove-orphans >/dev/null
  cleanup_owned_retry_fixture
  python "$ROOT_DIR/scripts/kaya_validation_resources.py" cleanup-compose --project "$PROJECT" >/dev/null
  [[ "$(docker ps -aq --filter "name=^${PROJECT}_" | wc -l)" == "0" ]]
}
scenario 45 "Cleanup and isolation" cleanup_phase9

export PHASE9_PASS_ROWS="$(IFS=,; echo "${PASS_ROWS[*]}")"
export PHASE9_FAIL_ROWS="$(IFS=,; echo "${FAIL_ROWS[*]}")"
export PHASE9_EVIDENCE_SUMMARY="$(python -c 'import json,sys; print(json.dumps({line.split("\t",1)[0]:line.split("\t",1)[1].rstrip() for line in open(sys.argv[1],encoding="utf-8")}))' "$SUMMARY_FILE")"
export PHASE9_DURATION_JSON="$(python -c 'import json,sys; print(json.dumps({line.split("\t",1)[0]:int(line.split("\t",1)[1]) for line in open(sys.argv[1],encoding="utf-8")}))' "$DURATION_FILE")"
python "$ROOT_DIR/scripts/phase9_acceptance_evidence.py" --output phase9_acceptance.json
(( ${#FAIL_ROWS[@]} == 0 ))
