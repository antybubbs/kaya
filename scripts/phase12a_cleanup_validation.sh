#!/usr/bin/env bash
set -Eeuo pipefail

run_id="${GITHUB_RUN_ID:-local}"
run_attempt="${GITHUB_RUN_ATTEMPT:-1}"
project="$(python scripts/kaya_validation_resources.py phase12a-project --run-id "$run_id" --run-attempt "$run_attempt")"
root="${PWD}/phase12a-${run_id}_${run_attempt}"
manifest="phase12a_resources.json"
config="phase12a_compose_config.json"
sentinel="kaya_phase12a_protected_sentinel_${run_id}_${run_attempt}"
disposable_volume="${project}_volume"
disposable_network="${project}_network"
disposable_container="${project}_container"
sentinel_created=false
export PHASE12A_PROJECT="$project" PHASE12A_ROOT="$root" PHASE12A_POSTGRES_IMAGE="${PHASE12A_POSTGRES_IMAGE:-postgres:16.14}"

python scripts/kaya_validation_resources.py validate-project --project "$project"
if [[ -L "$root" || ( -e "$root" && ! -d "$root" ) ]]; then
  printf '%s\n' "refusing unexpected Phase 12A fixture path: $root" >&2
  exit 1
fi
mkdir -p "$root"

cleanup() {
  status=$?
  set +e
  if [[ -f "$manifest" ]]; then
    python scripts/kaya_validation_resources.py cleanup --manifest "$manifest"
  fi
  rm -f -- "$manifest" "$config" phase12a_resources_discovered.json
  if [[ ! -f phase12a_cleanup_acceptance.json ]]; then
    PHASE12A_FAILURE_STATUS="$status" PHASE12A_FAILURE_STAGE="${stage:-unknown}" python -c 'import json, os; json.dump({"phase":"12A","status":"FAIL","stage":os.environ["PHASE12A_FAILURE_STAGE"],"error":"validation stopped before the complete safety matrix","resources_created":False},open("phase12a_cleanup_acceptance.json","w"),indent=2); open("phase12a_cleanup_acceptance.json","a").write(chr(10))'
  fi
  if [[ ! -f phase12a_resource_inventory.json ]]; then
    printf '%s\n' '{"status":"FAIL","stage":"evidence_generation","resources_created":false,"protected_resources":"not inspected","secrets":"not read"}' > phase12a_resource_inventory.json
  fi
  if [[ "${sentinel_created:-false}" == true ]]; then
    docker volume rm "$sentinel" >/dev/null 2>&1
  fi
  rm -rf -- "$root"
}
trap cleanup EXIT

stage=compose_preflight
docker compose -p "$project" -f docker-compose.yml -f ci/compose/docker-compose.phase12a-ci.yml config --format json > "$config"
stage=resource_preflight
python scripts/kaya_validation_resources.py validate-config --project "$project" --config "$config" > phase12a_resources_discovered.json

stage=sentinel_setup
docker volume create --label com.kaya.validation.protected=true "$sentinel" >/dev/null
sentinel_created=true
docker run --rm -v "$sentinel:/sentinel" alpine:3.20 sh -ec 'printf phase12a-sentinel > /sentinel/marker'
docker volume create --label com.docker.compose.project="$project" --label com.kaya.validation.disposable=true --label com.kaya.validation.phase=12a "$disposable_volume" >/dev/null
docker network create --label com.docker.compose.project="$project" --label com.kaya.validation.disposable=true --label com.kaya.validation.phase=12a "$disposable_network" >/dev/null
docker create --name "$disposable_container" --label com.docker.compose.project="$project" --label com.kaya.validation.disposable=true --label com.kaya.validation.phase=12a alpine:3.20 sleep 300 >/dev/null
docker start "$disposable_container" >/dev/null

export PHASE12A_PROJECT="$project" PHASE12A_SENTINEL="$sentinel" PHASE12A_CONTAINER="$disposable_container" PHASE12A_VOLUME="$disposable_volume" PHASE12A_NETWORK="$disposable_network"
stage=manifest_setup
python -c 'import json,os; p="phase12a_resources.json"; json.dump({"project":os.environ["PHASE12A_PROJECT"],"containers":[os.environ["PHASE12A_CONTAINER"]],"volumes":[os.environ["PHASE12A_VOLUME"]],"networks":[os.environ["PHASE12A_NETWORK"]],"fixture_paths":[]},open(p,"w"),indent=2)'

set +e
protected_collision="kaya_phase6_""postgres_secret"
python scripts/kaya_validation_resources.py cleanup --manifest <(printf '%s\n' '{"project":"'$project'","volumes":["'$protected_collision'"],"containers":[],"networks":[],"fixture_paths":[]}') >/dev/null 2>&1
collision_status=$?
set -e
[[ "$collision_status" -ne 0 ]]

python scripts/kaya_validation_resources.py cleanup --manifest "$manifest"
stage=cleanup_assertions
docker volume inspect "$sentinel" >/dev/null
docker run --rm -v "$sentinel:/sentinel:ro" alpine:3.20 sh -ec 'test "$(cat /sentinel/marker)" = phase12a-sentinel'
! docker volume inspect "$disposable_volume" >/dev/null 2>&1
! docker network inspect "$disposable_network" >/dev/null 2>&1
! docker container inspect "$disposable_container" >/dev/null 2>&1

stage=matrix
PHASE12A_ACCEPTANCE_OUTPUT=phase12a_cleanup_acceptance.json python scripts/phase12a_cleanup_evidence.py
stage=evidence
python -c 'import json, os; json.dump({
    "status": "PASS",
    "protected_resources": {"before": [os.environ["PHASE12A_SENTINEL"]], "after": [os.environ["PHASE12A_SENTINEL"]], "contents_verified": True},
    "disposable_resources": {"before": [os.environ["PHASE12A_VOLUME"], os.environ["PHASE12A_NETWORK"], os.environ["PHASE12A_CONTAINER"]], "after": []},
    "unknown_cleanup": "fail-closed",
    "secrets": "not read"
}, open("phase12a_resource_inventory.json", "w"), indent=2); open("phase12a_resource_inventory.json", "a").write(chr(10))'
