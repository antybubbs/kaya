#!/usr/bin/env bash
set -Eeuo pipefail

# Runs inside the pinned PostgreSQL container. Passwords are read from a mounted
# secret file and never placed in command arguments or backup metadata.
BACKUP_DIR="${KAYA_POSTGRES_BACKUP_DIR:-/var/backups/kaya-postgres}"
DB_NAME="${POSTGRES_DB:-kaya}"
DB_USER="${POSTGRES_USER:-kaya}"
ADMIN_USER="${KAYA_POSTGRES_ADMIN_USER:-}"
export PGHOST="${PGHOST:-postgres}"
PASSWORD_FILE="${POSTGRES_PASSWORD_FILE:-/run/kaya-secrets/postgres_password}"
ADMIN_PASSWORD_FILE="${KAYA_POSTGRES_ADMIN_PASSWORD_FILE:-$PASSWORD_FILE}"
RETENTION="${KAYA_POSTGRES_BACKUP_RETENTION:-7}"
KAYA_VERSION="${KAYA_VERSION:-unknown}"
KAYA_BUILD_SHA="${KAYA_BUILD_SHA:-unknown}"
BACKUP_PURPOSE="${KAYA_POSTGRES_BACKUP_PURPOSE:-manual}"

die() { echo "kaya-postgres-backup: $*" >&2; exit 1; }
admin_psql() {
  [[ -n "$ADMIN_USER" ]] || die "KAYA_POSTGRES_ADMIN_USER is required for database lifecycle operations"
  local previous_password="${PGPASSWORD:-}"
  if [[ -r "$ADMIN_PASSWORD_FILE" ]]; then
    PGPASSWORD="$(<"$ADMIN_PASSWORD_FILE")"
    export PGPASSWORD
  fi
  psql --username="$ADMIN_USER" "$@"
  if [[ -n "$previous_password" ]]; then PGPASSWORD="$previous_password"; export PGPASSWORD; else unset PGPASSWORD; fi
}
cleanup_backup_tmp() {
  if [[ -n "${tmp_cleanup:-}" ]]; then rm -f -- "$tmp_cleanup"; fi
}
[[ "$RETENTION" =~ ^[1-9][0-9]*$ ]] || die "retention must be a positive integer"
[[ "$BACKUP_PURPOSE" =~ ^[a-z][a-z0-9_]{0,63}$ ]] || die "backup purpose is invalid"
[[ -d "$BACKUP_DIR" ]] || die "backup destination does not exist"
chmod 700 "$BACKUP_DIR" || die "backup destination permissions could not be secured"
[[ -w "$BACKUP_DIR" ]] || die "backup destination is not writable"
if [[ -r "$PASSWORD_FILE" ]]; then
  export PGPASSWORD
  PGPASSWORD="$(<"$PASSWORD_FILE")"
elif [[ -n "${POSTGRES_PASSWORD:-}" ]]; then
  export PGPASSWORD="$POSTGRES_PASSWORD"
fi

latest() { find "$BACKUP_DIR" -maxdepth 1 -type f -name 'kaya-*.dump' -printf '%T@ %p\n' | sort -nr | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}'; }
verify() {
  local archive="$1" metadata="$1.json" checksum expected actual recorded_size
  [[ -f "$archive" && -f "$metadata" ]] || die "backup pair is missing"
  checksum="$archive.sha256"
  [[ -f "$checksum" ]] || die "backup checksum sidecar is missing"
  expected="$(sed -n 's/.*\"sha256\": \"\([^\"]*\)\".*/\1/p' "$metadata")"
  recorded_size="$(sed -n 's/.*\"archive_bytes\": \([0-9]*\).*/\1/p' "$metadata")"
  [[ -n "$expected" && -n "$recorded_size" ]] || die "backup metadata is incomplete"
  actual="$(sha256sum "$archive" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || die "backup digest verification failed"
  grep -q "^$expected  " "$checksum" || die "backup checksum sidecar is invalid"
  [[ "$(stat -c '%s' "$archive")" == "$recorded_size" ]] || die "backup size metadata is invalid"
  pg_restore --list "$archive" >/dev/null || die "backup archive verification failed"
}
backup() {
  local stamp archive metadata checksum tmp digest archive_bytes revision postgres_version
  stamp="$(date -u +%Y%m%dT%H%M%S%NZ)"
  archive="$BACKUP_DIR/kaya-$stamp.dump"
  metadata="$archive.json"
  tmp="$archive.tmp"
  tmp_cleanup="$tmp"
  trap cleanup_backup_tmp EXIT
  (umask 077; pg_dump --format=custom --no-owner --no-privileges --file="$tmp" --username="$DB_USER" --dbname="$DB_NAME")
  if psql --username="$DB_USER" --dbname="$DB_NAME" --tuples-only --no-align --command="SELECT to_regclass('public.alembic_version') IS NOT NULL;" | tr -d '[:space:]' | grep -qx t; then
    revision="$(psql --username="$DB_USER" --dbname="$DB_NAME" --tuples-only --no-align --command="SELECT COALESCE((SELECT version_num FROM public.alembic_version LIMIT 1), 'unknown');" | tr -d '[:space:]')"
  else
    revision="unknown"
  fi
  postgres_version="$(psql --username="$DB_USER" --dbname="$DB_NAME" --tuples-only --no-align --command="SELECT replace(replace(version(), chr(10), ' '), chr(13), ' ');" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ "$revision" != "unknown" && -n "$revision" && -n "$postgres_version" ]] || die "database revision or PostgreSQL version metadata is unavailable"
  mv -- "$tmp" "$archive"
  digest="$(sha256sum "$archive" | awk '{print $1}')"
  archive_bytes="$(stat -c '%s' "$archive")"
  (umask 077
    json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
    printf '{\n  "archive_bytes": %s,\n  "archive_format": "custom",\n  "created_at": "%s",\n  "postgresql_version": "%s",\n  "kaya_version": "%s",\n  "kaya_build_sha": "%s",\n  "backup_purpose": "%s",\n  "verification_state": "pending",\n  "sha256": "%s",\n  "alembic_revision": "%s"\n}\n' "$archive_bytes" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(json_escape "$postgres_version")" "$(json_escape "$KAYA_VERSION")" "$(json_escape "$KAYA_BUILD_SHA")" "$(json_escape "$BACKUP_PURPOSE")" "$digest" "$revision" > "$metadata"
    printf '%s  %s\n' "$digest" "$archive" > "$archive.sha256"
  )
  verify "$archive"
  sed -i 's/"verification_state": "pending"/"verification_state": "verified"/' "$metadata"
  find "$BACKUP_DIR" -maxdepth 1 -type f -name 'kaya-*.dump' -printf '%T@ %p\n' | sort -nr | awk -v keep="$RETENTION" 'NR > keep {sub(/^[^ ]+ /, ""); print}' | while IFS= read -r old; do rm -f -- "$old" "$old.json" "$old.sha256"; done
  echo "$archive"
}
restore_drill() {
  local archive="${1:-$(latest)}" target="${2:-kaya_restore_drill}" metadata expected_revision restored_revision user_count asset_count
  [[ -n "$archive" ]] || die "no backup archive available"
  [[ "$target" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || die "restore database name is invalid"
  verify "$archive"
  metadata="$archive.json"
  expected_revision="$(sed -n 's/.*\"alembic_revision\": \"\([^\"]*\)\".*/\1/p' "$metadata")"
  admin_psql --dbname=postgres --command="DROP DATABASE IF EXISTS \"$target\";" >/dev/null
  admin_psql --dbname=postgres --command="CREATE DATABASE \"$target\" OWNER \"$DB_USER\";" >/dev/null
  pg_restore --exit-on-error --no-owner --no-privileges --username="$DB_USER" --dbname="$target" "$archive"
  restored_revision="$(psql --username="$DB_USER" --dbname="$target" --tuples-only --no-align --command='SELECT version_num FROM alembic_version LIMIT 1;' | tr -d '[:space:]')"
  [[ -n "$expected_revision" && "$restored_revision" == "$expected_revision" ]] || die "restored Alembic revision does not match backup metadata"
  user_count="$(psql --username="$DB_USER" --dbname="$target" --tuples-only --no-align --command='SELECT count(*) FROM users;' | tr -d '[:space:]')"
  asset_count="$(psql --username="$DB_USER" --dbname="$target" --tuples-only --no-align --command='SELECT count(*) FROM hardware_assets;' | tr -d '[:space:]')"
  [[ "$user_count" =~ ^[1-9][0-9]*$ && "$asset_count" =~ ^[1-9][0-9]*$ ]] || die "restored representative data is missing"
  psql --username="$DB_USER" --dbname="$target" --tuples-only --no-align --command="SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" | grep -q '[1-9]' || die "restore drill has no public tables"
  admin_psql --dbname=postgres --command="DROP DATABASE \"$target\";" >/dev/null
  echo "restore-drill passed revision=$restored_revision users=$user_count assets=$asset_count"
}
diagnostics() {
  psql --username="$DB_USER" --dbname="$DB_NAME" --no-align --field-separator='|' --tuples-only <<'SQL'
SELECT current_database(), version();
SELECT pg_size_pretty(pg_database_size(current_database())), pg_database_size(current_database());
SELECT count(*) FROM pg_stat_activity WHERE datname = current_database();
SELECT datname, deadlocks FROM pg_stat_database WHERE datname = current_database();
SQL
}

case "${1:-backup}" in
  backup) backup ;;
  scheduled)
    interval="${KAYA_POSTGRES_BACKUP_INTERVAL_SECONDS:-86400}"
    [[ "$interval" =~ ^[1-9][0-9]*$ ]] || die "backup interval must be a positive integer"
    while :; do backup; sleep "$interval"; done
    ;;
  verify) verify "${2:-$(latest)}"; echo "verify passed" ;;
  restore-drill) restore_drill "${2:-}" "${3:-kaya_restore_drill}" ;;
  diagnostics) diagnostics ;;
  *) die "usage: $0 {backup|verify [archive]|restore-drill [archive] [database]|diagnostics}" ;;
esac
