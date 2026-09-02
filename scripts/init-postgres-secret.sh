#!/bin/sh
set -eu
path="${1:-./data/secrets/postgres_password}"
data_dir="${KAYA_POSTGRES_DATA_DIR:-/var/lib/postgresql/data}"
parent="$(dirname "$path")"
if [ ! -e "$path" ] && [ -f "$data_dir/PG_VERSION" ]; then
    printf '%s\n' "Existing PostgreSQL data detected but the Kaya PostgreSQL password secret is missing. Startup has been stopped to prevent credential divergence. Restore the original postgres_password secret or use the supported credential-recovery procedure. No database changes were made." >&2
    exit 1
fi
mkdir -p "$parent"
kaya_uid="$(id -u kaya)"
kaya_gid="$(id -g kaya)"
chown "$kaya_uid:$kaya_gid" "$parent"
chmod 700 "$parent"
if [ ! -e "$path" ]; then
    python - "$path" <<'PY'
import os
import secrets
import sys

target = sys.argv[1]
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(fd, "wb") as stream:
        stream.write(secrets.token_urlsafe(64).encode("ascii"))
except BaseException:
    try:
        os.unlink(target)
    except FileNotFoundError:
        pass
    raise
PY
    chmod 600 "$path"
    printf '%s\n' "Created PostgreSQL password file. Protect it and do not commit it."
else
    chmod 600 "$path"
    printf '%s\n' "PostgreSQL password file already exists; it was not replaced."
fi
chown "$kaya_uid:$kaya_gid" "$path"
