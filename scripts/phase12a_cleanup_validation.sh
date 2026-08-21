#!/usr/bin/env bash
set -Eeuo pipefail

token="${GITHUB_RUN_ID:-local}_${GITHUB_RUN_ATTEMPT:-1}"
token="$(printf '%s' "$token" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_' '_' | sed 's/^_*//;s/_*$//')"
project="kaya_phase12a_${token}"
root="phase12a-${token}"
manifest="phase12a_resources.json"
config="phase12a_compose_config.json"
sentinel="kaya_phase12a_protected_sentinel_${token}"
disposable_volume="${project}_volume"
disposable_network="${project}_network"
disposable_container="${project}_container"
export PHASE12A_PROJECT="$project" PHASE12A_ROOT="$root" PHASE12A_POSTGRES_IMAGE="${PHASE12A_POSTGRES_IMAGE:-postgres:16.14}"

[[ "$project" =~ ^kaya_phase12a_[a-z0-9]+_[a-z0-9]+$ ]]
if [[ -L "$root" || ( -e "$root" && ! -d "$root" ) ]]; then
  printf '%s\n' "refusing unexpected Phase 12A fixture path: $root" >&2
  exit 1
fi
mkdir -p "$root"

cleanup() {
  set +e
  if [[ -f "$manifest" ]]; then
    python scripts/kaya_validation_resources.py cleanup --manifest "$manifest"
  fi
  rm -f -- "$manifest" "$config" phase12a_resources_discovered.json
  rm -rf -- "$root"
}
trap cleanup EXIT

docker compose -p "$project" -f docker-compose.yml -f docker-compose.phase12a-ci.yml config --format json > "$config"
python scripts/kaya_validation_resources.py validate-config --project "$project" --config "$config" > phase12a_resources_discovered.json

docker volume create --label com.kaya.validation.protected=true "$sentinel" >/dev/null
docker run --rm -v "$sentinel:/sentinel" alpine:3.20 sh -ec 'printf phase12a-sentinel > /sentinel/marker'
docker volume create --label com.docker.compose.project="$project" --label com.kaya.validation.disposable=true --label com.kaya.validation.phase=12a "$disposable_volume" >/dev/null
docker network create --label com.docker.compose.project="$project" --label com.kaya.validation.disposable=true --label com.kaya.validation.phase=12a "$disposable_network" >/dev/null
docker create --name "$disposable_container" --label com.docker.compose.project="$project" --label com.kaya.validation.disposable=true --label com.kaya.validation.phase=12a alpine:3.20 sleep 300 >/dev/null
docker start "$disposable_container" >/dev/null

export PHASE12A_PROJECT="$project" PHASE12A_CONTAINER="$disposable_container" PHASE12A_VOLUME="$disposable_volume" PHASE12A_NETWORK="$disposable_network"
python -c 'import json,os; p="phase12a_resources.json"; json.dump({"project":os.environ["PHASE12A_PROJECT"],"containers":[os.environ["PHASE12A_CONTAINER"]],"volumes":[os.environ["PHASE12A_VOLUME"]],"networks":[os.environ["PHASE12A_NETWORK"]],"fixture_paths":[]},open(p,"w"),indent=2)'

set +e
protected_collision="kaya_phase6_""postgres_secret"
python scripts/kaya_validation_resources.py cleanup --manifest <(printf '%s\n' '{"project":"'$project'","volumes":["'$protected_collision'"],"containers":[],"networks":[],"fixture_paths":[]}') >/dev/null 2>&1
collision_status=$?
set -e
[[ "$collision_status" -ne 0 ]]

python scripts/kaya_validation_resources.py cleanup --manifest "$manifest"
docker volume inspect "$sentinel" >/dev/null
docker run --rm -v "$sentinel:/sentinel:ro" alpine:3.20 sh -ec 'test "$(cat /sentinel/marker)" = phase12a-sentinel'
! docker volume inspect "$disposable_volume" >/dev/null 2>&1
! docker network inspect "$disposable_network" >/dev/null 2>&1
! docker container inspect "$disposable_container" >/dev/null 2>&1

PHASE12A_ACCEPTANCE_OUTPUT=phase12a_cleanup_acceptance.json python scripts/phase12a_cleanup_evidence.py
printf '%s\n' '{"protected_resources":"preserved","secrets":"not read","unknown_cleanup":"fail-closed","sentinel":"preserved"}' > phase12a_resource_inventory.json
