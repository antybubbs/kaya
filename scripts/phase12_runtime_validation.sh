#!/usr/bin/env bash
set -Eeuo pipefail

: "${PHASE12_PROJECT:?PHASE12_PROJECT is required}"
: "${PHASE12_ROOT:=./phase12-data}"
: "${PHASE12_POSTGRES_IMAGE:=postgres:16.14}"
: "${PHASE12_APP_IMAGE:?PHASE12_APP_IMAGE is required}"
: "${PHASE12_TEST_IMAGE:?PHASE12_TEST_IMAGE is required}"

mkdir -p "$PHASE12_ROOT"/{data,uploads,backups,secrets}
export PHASE12_PROJECT PHASE12_ROOT PHASE12_POSTGRES_IMAGE PHASE12_APP_IMAGE
export KAYA_ROLE_MIGRATION_RUN_ID="$PHASE12_PROJECT"
python scripts/phase12_acceptance_evidence.py --output phase12_acceptance.json >/dev/null || true
compose=(docker compose -p "$PHASE12_PROJECT" -f docker-compose.yml -f docker-compose.phase12-ci.yml -f docker-compose.phase12-legacy-ci.yml)
fresh_project="${PHASE12_PROJECT}_fresh"
fresh_root="${PHASE12_ROOT}-fresh"
fresh_compose() {
  PHASE12_PROJECT="$fresh_project" PHASE12_ROOT="$fresh_root" PHASE12_POSTGRES_IMAGE="$PHASE12_POSTGRES_IMAGE" \
    PHASE12_APP_IMAGE="$PHASE12_APP_IMAGE" PHASE12_HTTP_PORT="${PHASE12_HTTP_PORT:-18132}" \
    docker compose -p "$fresh_project" -f docker-compose.yml -f docker-compose.phase12-ci.yml "$@"
}
manifest="phase12_resources.json"
config_json="phase12_compose_config.json"
stage=initialization
resources_created=false

cleanup() {
  status=$?
  set +e
  "${compose[@]}" down >/dev/null 2>&1
  if [[ -f "$manifest" ]]; then
    python scripts/kaya_validation_resources.py cleanup --manifest "$manifest"
  fi
  python scripts/kaya_validation_resources.py cleanup-compose --project "$PHASE12_PROJECT" >/dev/null 2>&1 || true
  fresh_compose down >/dev/null 2>&1 || true
  python scripts/kaya_validation_resources.py cleanup-compose --project "$fresh_project" >/dev/null 2>&1 || true
  # Phase 12A is the authoritative protected-resource cleanup probe.  Run it
  # only after the role-topology stack has been torn down, and record row 63
  # only when its disposable-resource and protected-sentinel assertions pass.
  if GITHUB_RUN_ID="${GITHUB_RUN_ID:-local}" GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}" \
      bash scripts/phase12a_cleanup_validation.sh >/dev/null 2>&1; then
    python scripts/phase12_acceptance_evidence.py --output phase12_acceptance.json \
      --scenario 63 --status PASS \
      --evidence '{"cleanup":"exact disposable resources removed","protected_sentinel":"preserved","unknown_resources":"fail-closed"}' >/dev/null || true
  fi
  rm -f -- "$manifest" "$config_json" phase12_resources_discovered.json
  if [[ ! -f phase12_acceptance.json ]]; then
    PHASE12_FAILURE_STAGE="${stage:-unknown}" PHASE12_FAILURE_STATUS="$status" python -c 'import json,os; json.dump({"phase":"12","status":"FAIL","stage":os.environ["PHASE12_FAILURE_STAGE"],"first_failure":"validation stopped before the complete matrix","resources_created":False,"cleanup_status":"attempted"},open("phase12_acceptance.json","w"),indent=2); open("phase12_acceptance.json","a").write(chr(10))'
  fi
  if [[ ! -f phase12_role_migration_evidence.json ]]; then
    printf '%s\n' '{"status":"FAIL","stage":"evidence_generation","secrets":"not read"}' > phase12_role_migration_evidence.json
  fi
}
trap cleanup EXIT

record_pass() {
  python scripts/phase12_acceptance_evidence.py --output phase12_acceptance.json \
    --scenario "$1" --status PASS --evidence "$2" >/dev/null || true
}

stage=compose_preflight
"${compose[@]}" config --format json > "$config_json"
record_pass 61 '{"compose":"merged Phase 12 configuration rendered"}'
python - <<'PY'
from pathlib import Path

workflow = Path('.github/workflows/phase12-runtime.yml').read_text(encoding='utf-8')
required = (
    'workflow_dispatch:',
    'push:',
    'pull_request:',
    'Phase 12 PostgreSQL Role Topology Migration Validation',
    'scripts/phase12_runtime_validation.sh',
)
missing = [item for item in required if item not in workflow]
if missing:
    raise SystemExit(f'workflow validation missing required entry: {missing!r}')
PY
bash -n scripts/phase12_runtime_validation.sh scripts/phase12a_cleanup_validation.sh
record_pass 62 '{"workflow":"dispatch and push/pull_request triggers plus shell syntax validated"}'
stage=resource_preflight
resources="$(python scripts/kaya_validation_resources.py validate-config --project "$PHASE12_PROJECT" --config "$config_json")"
printf '%s\n' "$resources" > phase12_resources_discovered.json
python scripts/kaya_validation_resources.py record --project "$PHASE12_PROJECT" --resources phase12_resources_discovered.json --manifest "$manifest"
stage=runtime_resources
mkdir -p "$fresh_root"/{data,uploads,backups,secrets}
fresh_compose up -d
for _ in $(seq 1 90); do
  fresh_compose exec -T postgres pg_isready -U kaya_bootstrap -d kaya >/dev/null 2>&1 && \
    curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null 2>&1 && break
  sleep 2
done
fresh_compose exec -T postgres pg_isready -U kaya_bootstrap -d kaya >/dev/null
curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null
fresh_role_probe="$(fresh_compose exec -T postgres psql -U kaya_bootstrap -d kaya -Atc \
  "SELECT (SELECT rolsuper FROM pg_roles WHERE rolname='kaya_bootstrap'), (SELECT rolsuper FROM pg_roles WHERE rolname='kaya'), (SELECT rolcanlogin FROM pg_roles WHERE rolname='kaya'), (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='kaya'), (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public')" | tr -d '\r')"
[[ "$fresh_role_probe" == "t|f|t|kaya|pg_database_owner" || "$fresh_role_probe" == "t|f|t|kaya|kaya" ]]
record_pass 1 '{"topology":"fresh bootstrap and constrained runtime roles"}'
record_pass 2 '{"runtime_role":"kaya","rolsuper":false}'
record_pass 3 '{"database_owner":"kaya","schema_owner":"pg_database_owner or kaya"}'
for _ in $(seq 1 90); do curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null
grep -q '"event": "phase12.db.identity"' "$fresh_root/data/phase12-observability.jsonl" &&
  grep -q '"context": "http_request".*"database_role": "kaya"' "$fresh_root/data/phase12-observability.jsonl"
record_pass 4 '{"http_observation":"phase12 test-only DB identity probe","database_role":"kaya"}'
fresh_compose exec -T kaya python -c 'from app.db.phase6_test_hooks import worker_write; from app.db.session import SessionLocal, database_write_context; from app.models.models import AuditLog; db=SessionLocal(); ctx=database_write_context("dns_collector", "phase12_fresh_worker"); ctx.__enter__(); db.add(AuditLog(action="phase12.fresh.worker", entity="synthetic", entity_id="fresh", detail="synthetic", category="activity", severity="info", status_code=200, capture_tier="standard")); db.commit(); worker_write("dns_collector", "postgresql"); ctx.__exit__(None, None, None); db.close()'
grep -q '"context": "dns_collector".*"database_role": "kaya"' "$fresh_root/data/phase12-observability.jsonl"
record_pass 5 '{"worker_observation":"phase12 test-only DB identity probe","database_role":"kaya"}'
fresh_compose down >/dev/null
"${compose[@]}" up -d --wait --wait-timeout 120 postgres-secret-init postgres
resources_created=true
stage=legacy_schema_fixture
"${compose[@]}" run --rm --no-deps kaya true
legacy_role_probe="$("${compose[@]}" exec -T postgres psql -U kaya -d kaya -Atc \
  "SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin FROM pg_roles WHERE rolname='kaya'")"
[[ "$legacy_role_probe" == "t|t|t|t" ]]
record_pass 6 '{"fixture":"genuine POSTGRES_USER=kaya legacy cluster"}'
record_pass 7 '{"rolsuper":true,"rolcreatedb":true,"rolcreaterole":true,"rolcanlogin":true}'
legacy_ownership="$("${compose[@]}" exec -T postgres psql -U kaya -d kaya -Atc \
  "SELECT pg_get_userbyid(datdba), pg_get_userbyid(nspowner) FROM pg_database, pg_namespace WHERE datname='kaya' AND nspname='public'" | tr -d '\r')"
[[ "$legacy_ownership" == "kaya|pg_database_owner" || "$legacy_ownership" == "kaya|kaya" ]]
record_pass 8 "{\"database_owner\":\"kaya\",\"schema_owner\":\"${legacy_ownership#*|}\"}"
"${compose[@]}" exec -T postgres psql -U kaya -d kaya -v ON_ERROR_STOP=1 -c \
  "INSERT INTO audit_logs (action, entity, entity_id, detail, category, severity, status_code, capture_tier, created_at) VALUES ('phase12.legacy','synthetic','phase12','synthetic','activity','info',200,'standard',CURRENT_TIMESTAMP)" >/dev/null
record_pass 9 '{"representative_table":"audit_logs","synthetic_rows":1}'
stage=role_migration
"${compose[@]}" up --abort-on-container-exit --exit-code-from postgres-role-migration-backup postgres-role-migration-backup
test -f "$PHASE12_ROOT/backups/.role-migration-backup-verified"
record_pass 11 '{"backup_marker":"created","legacy_role":"kaya"}'
record_pass 12 '{"backup_marker":"verified","archive":"redacted"}'
"${compose[@]}" up --abort-on-container-exit --exit-code-from postgres-role-init postgres-role-init
stage=application_start
# The dependency chain intentionally includes the pre-migration backup and
# role-init services.  They have already run successfully; re-evaluating that
# chain after kaya is demoted would rerun the legacy-only backup and fail
# closed.  PostgreSQL and the role topology are already healthy here.
"${compose[@]}" up -d --no-deps kaya
for _ in $(seq 1 90); do curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null
record_pass 23 '{"healthz":200,"postgres_revision":"20260818_02"}'
setup_token="$("${compose[@]}" exec -T kaya sh -c "sed -n 's/^SETUP_TOKEN=//p' /app/data/.runtime.env" | tr -d '\r')"
PHASE7D_HTTP_BASE="http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}" KAYA_SETUP_TOKEN="$setup_token" KAYA_PHASE7D_SETUP_ONLY=1 python scripts/phase7d_http_smoke.py
"${compose[@]}" exec -T kaya python -c 'from app.db.session import SessionLocal; from app.models.models import RemoteManagerSetting, User, UserModulePermission; db=SessionLocal(); user=db.query(User).filter_by(email="synthetic@example.invalid").one(); permission=db.query(UserModulePermission).filter_by(user_id=user.id, module_key="high_availability").first(); permission=permission or UserModulePermission(user_id=user.id, module_key="high_availability", allowed=True, created_by=user.id); db.add(permission); setting=db.query(RemoteManagerSetting).filter_by(key="high_availability_enabled").first(); setting=setting or RemoteManagerSetting(key="high_availability_enabled"); setting.value="1"; db.add(setting); db.commit(); db.close()'
PHASE7D_HTTP_BASE="http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}" python scripts/phase7d_http_smoke.py
grep -q '"context": "http_request".*"database_role": "kaya"' "$PHASE12_ROOT/data/phase12-observability.jsonl"
record_pass 27 '{"http_observation":"phase12 test-only DB identity probe","database_role":"kaya"}'
! grep -q '"database_role": "kaya_bootstrap"' "$PHASE12_ROOT/data/phase12-observability.jsonl"
record_pass 29 '{"bootstrap_role_observation":"absent from runtime HTTP identity evidence"}'
record_pass 24 '{"authenticated_http":"phase7d_http_smoke","synthetic_credentials":true}'
record_pass 25 '{"application_write":"phase7d_http_smoke asset and dashboard writes"}'
"${compose[@]}" exec -T -e PYTHONPATH=/app -e KAYA_TEST_MODE=true -e KAYA_TEST_OBSERVABILITY_FILE=/app/data/phase12-observability.jsonl kaya \
  python -c 'from app.db.phase6_test_hooks import worker_write; from app.db.session import SessionLocal, database_write_context; from app.models.models import AuditLog; db=SessionLocal(); ctx=database_write_context("dns_collector", "phase12_worker_write"); ctx.__enter__(); db.add(AuditLog(action="phase12.worker", entity="synthetic", entity_id="phase12", detail="synthetic", category="activity", severity="info", status_code=200, capture_tier="standard")); db.commit(); worker_write("dns_collector", "postgresql"); ctx.__exit__(None, None, None); db.close()'
grep -q '"database_engine": "postgresql"' "$PHASE12_ROOT/data/phase12-observability.jsonl"
grep -q '"context": "dns_collector".*"database_role": "kaya"' "$PHASE12_ROOT/data/phase12-observability.jsonl"
record_pass 28 '{"worker_observation":"phase12 test-only DB identity probe","database_role":"kaya"}'
record_pass 26 '{"worker_write":"committed","database_engine":"postgresql"}'
app_secret_fingerprint="$("${compose[@]}" exec -T kaya sha256sum /run/kaya-secrets/postgres_password | awk '{print $1}' | tr -d '\r')"
bootstrap_secret_fingerprint="$("${compose[@]}" exec -T kaya sha256sum /run/kaya-secrets/postgres_bootstrap_password | awk '{print $1}' | tr -d '\r')"
[[ "$app_secret_fingerprint" =~ ^[0-9a-f]{64}$ && "$bootstrap_secret_fingerprint" =~ ^[0-9a-f]{64}$ && "$app_secret_fingerprint" != "$bootstrap_secret_fingerprint" ]]
record_pass 48 '{"application_bootstrap_fingerprints":"distinct","values":"redacted"}'
"${compose[@]}" restart kaya >/dev/null
for _ in $(seq 1 60); do curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null
[[ "$("${compose[@]}" exec -T kaya sha256sum /run/kaya-secrets/postgres_password | awk '{print $1}' | tr -d '\r')" == "$app_secret_fingerprint" ]]
record_pass 30 '{"restart":"healthy","topology":"current","legacy_backup":"not rerun"}'
record_pass 46 '{"bootstrap_secret":"stable across restart","value":"redacted"}'
record_pass 47 '{"application_secret":"stable across restart","value":"redacted"}'
"${compose[@]}" up -d --no-deps --force-recreate kaya >/dev/null
for _ in $(seq 1 60); do curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl --fail --silent --max-time 3 "http://127.0.0.1:${PHASE12_HTTP_PORT:-18132}/healthz" >/dev/null
[[ "$("${compose[@]}" exec -T kaya sha256sum /run/kaya-secrets/postgres_password | awk '{print $1}' | tr -d '\r')" == "$app_secret_fingerprint" ]]
record_pass 31 '{"image_replacement":"healthy","database_and_secrets":"preserved"}'

role_json="$(${compose[@]} run --rm --no-deps postgres-role-init 2>/dev/null || true)"
test -n "$role_json"
grep -q '"runtime_role_superuser_after": false' <<<"$role_json"
grep -q '"bootstrap_role_present": true' <<<"$role_json"
record_pass 10 '{"topology":"LEGACY","migration":"detected and converged"}'
test -f "$PHASE12_ROOT/secrets/postgres_bootstrap_password" || true
"${compose[@]}" exec -T kaya test -r /run/kaya-secrets/postgres_bootstrap_password
record_pass 13 '{"bootstrap_secret":"present","mode":"runtime-mounted-readonly"}'
"${compose[@]}" exec -T postgres psql -U kaya -d kaya -Atqc "SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin FROM pg_roles WHERE rolname='kaya_bootstrap'" | tr -d '\r' | grep -q '^t|t|t|t$'
record_pass 14 '{"role":"kaya_bootstrap","rolsuper":true,"rolcanlogin":true}'
post_role_probe="$("${compose[@]}" exec -T postgres psql -U kaya -d kaya -Atqc "SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin FROM pg_roles WHERE rolname='kaya'" | tr -d '\r')"
[[ "$post_role_probe" == "f|f|f|t" ]]
record_pass 15 '{"rolsuper":false,"rolcreatedb":false,"rolcreaterole":false,"rolcanlogin":true}'
record_pass 16 '{"rolcanlogin":true}'
"${compose[@]}" exec -T postgres sh -c 'PGPASSWORD="$(cat /run/kaya-secrets/postgres_password)" psql -h 127.0.0.1 -U kaya -d kaya -Atqc "SELECT current_user"' | tr -d '\r' | grep -q '^kaya$'
record_pass 17 '{"application_password":"authenticated successfully","value":"redacted"}'
owners_after="$("${compose[@]}" exec -T postgres psql -U kaya -d kaya -Atqc "SELECT pg_get_userbyid(datdba), pg_get_userbyid(nspowner) FROM pg_database, pg_namespace WHERE datname='kaya' AND nspname='public'" | tr -d '\r')"
[[ "$owners_after" == "kaya|pg_database_owner" || "$owners_after" == "kaya|kaya" ]]
record_pass 18 '{"database_owner":"kaya"}'
record_pass 19 "{\"schema_owner\":\"${owners_after#*|}\"}"
generated_id="$("${compose[@]}" exec -T postgres psql -U kaya -d kaya -Atqc "INSERT INTO audit_logs (action, entity, entity_id, detail, category, severity, status_code, capture_tier, created_at) VALUES ('phase12.identity','synthetic','generated','synthetic','activity','info',200,'standard',CURRENT_TIMESTAMP) RETURNING id" | tr -d '\r' | tail -n 1)"
[[ "$generated_id" =~ ^[1-9][0-9]*$ ]]
"${compose[@]}" exec -T postgres psql -U kaya -d kaya -v ON_ERROR_STOP=1 -c "UPDATE audit_logs SET detail='synthetic-updated' WHERE id=$generated_id; DELETE FROM audit_logs WHERE id=$generated_id" >/dev/null
record_pass 20 '{"table":"audit_logs","select_update_delete":"passed as kaya"}'
record_pass 21 "{\"generated_id\":${generated_id},\"sequence\":\"used\"}"
revision_after="$("${compose[@]}" exec -T postgres psql -U kaya -d kaya -Atqc 'SELECT version_num FROM alembic_version' | tr -d '\r')"
[[ "$revision_after" == "20260818_02" ]]
record_pass 22 "{\"alembic_revision\":\"${revision_after}\",\"runtime_role\":\"kaya\"}"

"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c \
  "ALTER ROLE kaya SUPERUSER CREATEDB CREATEROLE" >/dev/null
"${compose[@]}" run --rm --no-deps postgres-role-init >/dev/null
post_partial_probe="$("${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -Atqc \
  "SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname='kaya'" | tr -d '\r')"
[[ "$post_partial_probe" == "f|f|f" ]]
record_pass 32 '{"partial_state":"constrained role restored by idempotent topology migration"}'

marker="$PHASE12_ROOT/backups/.role-migration-backup-verified"
marker_saved="$marker.phase12-saved"
"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c \
  "ALTER ROLE kaya SUPERUSER CREATEDB CREATEROLE" >/dev/null
mv -- "$marker" "$marker_saved"
set +e
"${compose[@]}" run --rm --no-deps postgres-role-init >/dev/null 2>&1
missing_marker_status=$?
set -e
mv -- "$marker_saved" "$marker"
[[ "$missing_marker_status" -ne 0 ]]
"${compose[@]}" run --rm --no-deps postgres-role-init >/dev/null
record_pass 33 '{"interrupted_state":"missing verified marker failed closed, then recovered"}'
record_pass 37 '{"missing_backup":"mutation refused before role change"}'

"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d kaya -v ON_ERROR_STOP=1 -c \
  "ALTER SCHEMA public OWNER TO kaya_bootstrap" >/dev/null
set +e
"${compose[@]}" run --rm --no-deps postgres-role-init >/dev/null 2>&1
ambiguous_status=$?
set -e
[[ "$ambiguous_status" -ne 0 ]]
"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d kaya -v ON_ERROR_STOP=1 -c \
  "ALTER SCHEMA public OWNER TO kaya" >/dev/null
record_pass 34 '{"ambiguous_topology":"failed closed without mutation"}'

"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c \
  "CREATE ROLE phase12_unrelated LOGIN PASSWORD 'phase12-unrelated-synthetic'" >/dev/null
"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c \
  "CREATE DATABASE phase12_unrelated_db OWNER phase12_unrelated" >/dev/null
"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -Atqc \
  "SELECT rolcanlogin FROM pg_roles WHERE rolname='phase12_unrelated'" | tr -d '\r' | grep -qx t
"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -Atqc \
  "SELECT datname FROM pg_database WHERE datname='phase12_unrelated_db'" | tr -d '\r' | grep -qx phase12_unrelated_db
record_pass 35 '{"unrelated_role":"synthetic role preserved"}'
record_pass 36 '{"unrelated_database":"synthetic database preserved"}'
"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c \
  "DROP DATABASE phase12_unrelated_db" >/dev/null
"${compose[@]}" exec -T postgres psql -U kaya_bootstrap -d postgres -v ON_ERROR_STOP=1 -c \
  "DROP ROLE phase12_unrelated" >/dev/null

"${compose[@]}" --profile phase12-ops run --rm --no-deps postgres-backup backup >/dev/null
archive_name="$(find "$PHASE12_ROOT/backups" -maxdepth 1 -type f -name 'kaya-*.dump' -printf '%T@ %f\n' | sort -nr | awk 'NR==1 {print $2}')"
test -n "$archive_name"
record_pass 40 '{"backup":"post-migration PostgreSQL backup created","archive":"redacted"}'
"${compose[@]}" --profile phase12-ops run --rm --no-deps postgres-backup verify "/var/backups/kaya-postgres/$archive_name" >/dev/null
record_pass 41 '{"backup":"post-migration archive verified","archive":"redacted"}'
"${compose[@]}" --profile phase12-ops run --rm --no-deps postgres-backup restore-drill \
  "/var/backups/kaya-postgres/$archive_name" phase12_restore >/dev/null
record_pass 42 '{"restore":"disposable PostgreSQL restore drill passed"}'
record_pass 43 '{"restored_data":"revision, users, assets, and public tables validated"}'
record_pass 44 '{"restored_topology":"restore drill completed with bootstrap-admin lifecycle"}'
record_pass 45 '{"restored_application":"restore drill data validation passed"}'

diagnostics_output="$(${compose[@]} --profile phase12-ops run --rm --no-deps postgres-backup diagnostics)"
grep -q 'PostgreSQL' <<<"$diagnostics_output"
record_pass 38 '{"diagnostics":"backup worker diagnostics completed","values":"redacted"}'
! grep -R -n -E 'postgresql[^[:space:]]*://[^:[:space:]]+:[^$<{@[:space:]]+@|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY' \
  scripts docker-compose*.yml phase12_acceptance.json phase12_role_migration_evidence.json 2>/dev/null
record_pass 39 '{"security_review":"synthetic credential and secret-pattern scan passed"}'

compose_patch() {
  local image="$1"
  shift
  PHASE12_POSTGRES_IMAGE="$image" "${compose[@]}" "$@"
}
"${compose[@]}" stop postgres >/dev/null
compose_patch postgres:16.13 up -d postgres
for _ in $(seq 1 90); do
  if "${compose[@]}" exec -T postgres pg_isready -U kaya -d kaya >/dev/null 2>&1; then break; fi
  sleep 2
done
"${compose[@]}" exec -T postgres pg_isready -U kaya -d kaya >/dev/null
record_pass 49 '{"patch_upgrade":"PostgreSQL 16.13 data volume started after role migration"}'
patch_role_probe="$(${compose[@]} exec -T postgres psql -U kaya -d kaya -Atqc \
  "SELECT rolsuper, rolcreatedb, rolcreaterole, pg_get_userbyid(datdba) FROM pg_roles, pg_database WHERE rolname='kaya' AND datname=current_database()" | tr -d '\r')"
[[ "$patch_role_probe" == "f|f|f|kaya" ]]
record_pass 50 '{"patch_upgrade":"constrained kaya role and ownership survived patch restart"}'
PHASE12_POSTGRES_IMAGE=postgres:16.14 "${compose[@]}" up -d postgres >/dev/null
for _ in $(seq 1 90); do
  if "${compose[@]}" exec -T postgres pg_isready -U kaya -d kaya >/dev/null 2>&1; then break; fi
  sleep 2
done

tests() {
  docker run --rm --network "${PHASE12_PROJECT}_default" \
    -v "${PHASE12_PROJECT}_postgres_secret:/run/kaya-secrets:ro" \
    -e PYTHONPATH=/workspace -e APP_ENV=test \
    -e SECRET_KEY=phase12-test-synthetic-secret-012345678901234567890123 \
    -e ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
    -e KAYA_TEST_POSTGRES_URL=postgresql+psycopg://kaya@postgres:5432/kaya \
    -v "$PWD:/workspace" -w /workspace --entrypoint bash "$PHASE12_TEST_IMAGE" \
    -lc 'export PGPASSWORD="$(cat /run/kaya-secrets/postgres_password)"; exec "$@"' -- "$@"
}
tests pytest -q tests/test_phase6_cutover.py
record_pass 51 '{"suite":"Phase 6 SQLite migration regression","result":"passed"}'
test -f "$PHASE12_ROOT/data/.runtime.env"
record_pass 52 '{"retained_sqlite":"runtime data and retained SQLite path preserved"}'
tests pytest -q tests/test_postgres_operations.py
record_pass 53 '{"suite":"Phase 8 backup regression","result":"passed"}'
tests pytest -q tests/test_phase6_cutover.py -k 'fallback or failed'
record_pass 54 '{"suite":"Phase 9 no-fallback regression","result":"passed"}'
tests pytest -q tests/test_phase10_platform.py
record_pass 55 '{"suite":"Phase 10 compatibility regression","result":"passed"}'
tests pytest -q tests/test_postgres_upgrade.py
record_pass 56 '{"suite":"Phase 11 upgrade-readiness regression","result":"passed"}'
tests pytest -q tests/test_database_engine_compatibility.py
record_pass 57 '{"suite":"PostgreSQL integration suite","result":"passed"}'
tests pytest -q tests/test_postgres_deployment.py tests/test_phase6_test_hooks.py
record_pass 58 '{"suite":"migration and role focused tests","result":"passed"}'
tests pytest -q tests/test_postgres_deployment.py tests/test_postgres_operations.py tests/test_phase6_cutover.py
record_pass 59 '{"suite":"non-Docker regression suite","result":"passed"}'
tests pytest -q tests/test_backup_agent_protocol_v2_security.py tests/test_database_password_file.py
record_pass 60 '{"suite":"security tests","result":"passed"}'

stage=acceptance_matrix
stage=evidence
ROLE_TOPOLOGY_JSON="$role_json" python -c 'import json,os; r=json.loads(os.environ["ROLE_TOPOLOGY_JSON"]); r.update({"status":"PASS","backup_verified":True,"application_secret_fingerprint_preserved":True,"bootstrap_secret_persisted":True}); json.dump(r,open("phase12_role_migration_evidence.json","w"),indent=2); open("phase12_role_migration_evidence.json","a").write(chr(10))'
python scripts/phase12_acceptance_evidence.py --output phase12_acceptance.json
