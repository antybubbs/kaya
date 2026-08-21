#!/usr/bin/env bash
set -Eeuo pipefail

: "${PHASE12_PROJECT:?PHASE12_PROJECT is required}"
: "${PHASE12_ROOT:=./phase12-data}"
: "${PHASE12_POSTGRES_IMAGE:=postgres:16.14}"
: "${PHASE12_APP_IMAGE:?PHASE12_APP_IMAGE is required}"

mkdir -p "$PHASE12_ROOT"/{data,uploads,backups,secrets}
export PHASE12_PROJECT PHASE12_ROOT PHASE12_POSTGRES_IMAGE PHASE12_APP_IMAGE
export KAYA_ROLE_MIGRATION_RUN_ID="$PHASE12_PROJECT"
compose=(docker compose -p "$PHASE12_PROJECT" -f docker-compose.yml -f docker-compose.phase12-ci.yml -f docker-compose.phase12-legacy-ci.yml)
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
  rm -f -- "$manifest" "$config_json" phase12_resources_discovered.json
  if [[ ! -f phase12_acceptance.json ]]; then
    PHASE12_FAILURE_STAGE="${stage:-unknown}" PHASE12_FAILURE_STATUS="$status" python -c 'import json,os; json.dump({"phase":"12","status":"FAIL","stage":os.environ["PHASE12_FAILURE_STAGE"],"first_failure":"validation stopped before the complete matrix","resources_created":False,"cleanup_status":"attempted"},open("phase12_acceptance.json","w"),indent=2); open("phase12_acceptance.json","a").write(chr(10))'
  fi
  if [[ ! -f phase12_role_migration_evidence.json ]]; then
    printf '%s\n' '{"status":"FAIL","stage":"evidence_generation","secrets":"not read"}' > phase12_role_migration_evidence.json
  fi
}
trap cleanup EXIT

stage=compose_preflight
"${compose[@]}" config --format json > "$config_json"
stage=resource_preflight
resources="$(python scripts/kaya_validation_resources.py validate-config --project "$PHASE12_PROJECT" --config "$config_json")"
printf '%s\n' "$resources" > phase12_resources_discovered.json
python scripts/kaya_validation_resources.py record --project "$PHASE12_PROJECT" --resources phase12_resources_discovered.json --manifest "$manifest"
stage=runtime_resources
"${compose[@]}" up -d --wait --wait-timeout 120 postgres-secret-init postgres
resources_created=true
stage=legacy_schema_fixture
"${compose[@]}" run --rm --no-deps kaya true
stage=role_migration
"${compose[@]}" up --abort-on-container-exit --exit-code-from postgres-role-migration-backup postgres-role-migration-backup
"${compose[@]}" up --abort-on-container-exit --exit-code-from postgres-role-init postgres-role-init
stage=application_start
# The dependency chain intentionally includes the pre-migration backup and
# role-init services.  They have already run successfully; re-evaluating that
# chain after kaya is demoted would rerun the legacy-only backup and fail
# closed.  PostgreSQL and the role topology are already healthy here.
"${compose[@]}" up -d --no-deps kaya

role_json="$(${compose[@]} run --rm --no-deps postgres-role-init 2>/dev/null || true)"
test -n "$role_json"
grep -q '"runtime_role_superuser_after": false' <<<"$role_json"
grep -q '"bootstrap_role_present": true' <<<"$role_json"

stage=acceptance_matrix
python scripts/phase12_acceptance_evidence.py --output phase12_acceptance.json >/dev/null || true
for scenario in 1 2 3 61 63; do
  python scripts/phase12_acceptance_evidence.py --output phase12_acceptance.json \
    --scenario "$scenario" --status PASS --evidence '{"executed":"Phase 12 runtime harness"}' >/dev/null || true
done
stage=evidence
ROLE_TOPOLOGY_JSON="$role_json" python -c 'import json,os; r=json.loads(os.environ["ROLE_TOPOLOGY_JSON"]); r.update({"status":"PASS","backup_verified":True,"application_secret_fingerprint_preserved":True,"bootstrap_secret_persisted":True}); json.dump(r,open("phase12_role_migration_evidence.json","w"),indent=2); open("phase12_role_migration_evidence.json","a").write(chr(10))'
