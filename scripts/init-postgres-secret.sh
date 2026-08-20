#!/bin/sh
set -eu
path="${1:-./data/secrets/postgres_password}"
mkdir -p "$(dirname "$path")"
if [ ! -e "$path" ]; then
    umask 077
    python -c 'import secrets; print(secrets.token_urlsafe(43), end="")' > "$path"
    chmod 600 "$path"
    printf '%s\n' "Created PostgreSQL password file. Protect it and do not commit it."
else
    printf '%s\n' "PostgreSQL password file already exists; it was not replaced."
fi
