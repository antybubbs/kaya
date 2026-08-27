#!/bin/sh
set -eu
path="${1:-./data/secrets/postgres_password}"
parent="$(dirname "$path")"
mkdir -p "$parent"
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
