#!/usr/bin/env bash
set -Eeuo pipefail

# Linux-only, disposable PostgreSQL validation for Network Discovery Stage A.
# This script never uses docker-compose or the production database service.

: "${KAYA_STAGEA_TEST_MARKER:?Set KAYA_STAGEA_TEST_MARKER=I_UNDERSTAND_DISPOSABLE_STAGEA}"
if [[ "$KAYA_STAGEA_TEST_MARKER" != "I_UNDERSTAND_DISPOSABLE_STAGEA" ]]; then
    echo "Refusing to run without the explicit disposable-test marker." >&2
    exit 2
fi

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
run_id="${KAYA_STAGEA_RUN_ID:-$(date +%Y%m%d%H%M%S)-$$}"
container="kaya-stagea-pg-${run_id}"
volume="kaya-stagea-pg-data-${run_id}"
port="${KAYA_STAGEA_PG_PORT:-55439}"
user="kaya_stagea_test"
password="${KAYA_STAGEA_TEST_PASSWORD:-stagea-postgres-password-$(date +%s)}"
primary_db="kaya_stagea_test"
from03_db="kaya_stagea_from03_test"

if [[ "$primary_db" == "kaya" || "$from03_db" == "kaya" || "$primary_db" =~ production|prod ]]; then
    echo "Refusing a production-like database name." >&2
    exit 2
fi
if [[ ! "$port" =~ ^[0-9]+$ || "$port" -lt 1024 || "$port" -gt 65535 ]]; then
    echo "KAYA_STAGEA_PG_PORT must be an unprivileged TCP port." >&2
    exit 2
fi

cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$volume" >/dev/null
docker run -d --name "$container" \
    --mount "type=volume,src=$volume,dst=/var/lib/postgresql/data" \
    -e POSTGRES_USER="$user" \
    -e POSTGRES_PASSWORD="$password" \
    -e POSTGRES_DB="$primary_db" \
    -p "127.0.0.1:${port}:5432" \
    postgres:16.15 >/dev/null

for attempt in {1..60}; do
    if docker exec "$container" pg_isready -U "$user" -d "$primary_db" >/dev/null 2>&1; then
        break
    fi
    if [[ "$attempt" == 60 ]]; then
        echo "Disposable PostgreSQL did not become ready." >&2
        exit 1
    fi
    sleep 1
done

url="postgresql+psycopg://${user}:${password}@127.0.0.1:${port}/${primary_db}"
from03_url="postgresql+psycopg://${user}:${password}@127.0.0.1:${port}/${from03_db}"

# Positive target check for schema assertions. The migration runner additionally
# verifies the requested localhost URL and current database before every DDL call.
verify_target() {
    local database="$1"
    local expected="$2"
    [[ "$database" =~ _test$ ]] || { echo "Unsafe database name: $database" >&2; exit 2; }
    actual=$(docker exec "$container" psql -U "$user" -d "$database" -Atqc 'SELECT current_database()')
    [[ "$actual" == "$expected" ]] || {
        echo "Connected target verification failed: $actual" >&2
        exit 3
    }
}

verify_target "$primary_db" "$primary_db"
export KAYA_TEST_POSTGRES_URL="$url"
export KAYA_TEST_POSTGRES_SERVER_ADDR="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container")"
export KAYA_TEST_POSTGRES_CONTAINER=1
export DATABASE_URL="$url"
export SECRET_KEY="stagea-postgres-validation-secret-012345678901234567890123456789"
export ENCRYPTION_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

python "$project_root/scripts/kaya_test_migrations.py" upgrade head --url "$url"
python "$project_root/scripts/kaya_test_migrations.py" downgrade 20261014_04 --url "$url"
python "$project_root/scripts/kaya_test_migrations.py" upgrade head --url "$url"

docker exec "$container" psql -U "$user" -d "$primary_db" -v ON_ERROR_STOP=1 -c \
    "CREATE DATABASE ${from03_db} OWNER ${user};" >/dev/null
verify_target "$from03_db" "$from03_db"
python "$project_root/scripts/kaya_test_migrations.py" upgrade 20261014_03 --url "$from03_url"
python "$project_root/scripts/kaya_test_migrations.py" upgrade head --url "$from03_url"

for database in "$primary_db" "$from03_db"; do
    verify_target "$database" "$database"
    docker exec "$container" psql -U "$user" -d "$database" -v ON_ERROR_STOP=1 -c "
        SELECT 1 FROM information_schema.columns
          WHERE table_name = 'traffic_discovery_links' AND column_name = 'mapping_vlan_id';
        SELECT 1 FROM information_schema.columns
          WHERE table_name = 'traffic_discovery_links' AND column_name = 'mapping_network_cidr';
        SELECT 1 FROM pg_indexes
          WHERE tablename = 'traffic_discovery_network_mappings'
            AND indexname = 'uq_traffic_discovery_mapping_identity';
        SELECT 1 FROM pg_constraint
          WHERE conname = 'traffic_discovery_network_mappings_vlan_id_fkey';
        SELECT 1 FROM information_schema.columns
          WHERE table_name = 'traffic_discovery_links'
            AND column_name = 'mapping_vlan_id' AND is_nullable = 'YES';
    " >/dev/null
done

pytest -q "$project_root/tests/test_database_engine_compatibility.py"
echo "Stage A PostgreSQL validation passed for disposable PostgreSQL 16.15 targets."
