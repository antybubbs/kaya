#!/bin/sh
set -eu

mkdir -p /app/data /app/uploads /app/data/remote-recordings /app/data/secret-vault
chown -R kaya:kaya /app/data /app/uploads
chmod 700 /app/data/secret-vault

SECRETS_FILE="/app/data/.runtime.env"

generate_secret_key() {
    python -c "import secrets; print(secrets.token_urlsafe(64))"
}

generate_encryption_key() {
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
}

if [ ! -f "$SECRETS_FILE" ]; then
    echo "Initialising persistent Kaya secrets..."

    # v0.16 (yes, there was once a time) and earlier supplied these values through Compose's .env file. (LOL, right?)
    # Preserve them on the first v0.18 start so existing encrypted data (ha ha ha, help us)
    # sessions remain valid. Generate only values that were not supplied. (duh)
    # Again, this is a one-time operation. After the first start, the secrets file is used. (we hope)
    # Lord help us if we ever need to change this logic again.

    PERSISTED_SECRET_KEY="${SECRET_KEY:-}"
    PERSISTED_ENCRYPTION_KEY="${ENCRYPTION_KEY:-}"

    if [ -z "$PERSISTED_SECRET_KEY" ]; then
        PERSISTED_SECRET_KEY="$(generate_secret_key)"
    fi

    if [ -z "$PERSISTED_ENCRYPTION_KEY" ]; then
        PERSISTED_ENCRYPTION_KEY="$(generate_encryption_key)"
    fi

    cat > "$SECRETS_FILE" <<EOF
SECRET_KEY=$PERSISTED_SECRET_KEY
ENCRYPTION_KEY=$PERSISTED_ENCRYPTION_KEY
EOF

    chown kaya:kaya "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
fi

set -a
. "$SECRETS_FILE"
set +a

export SECRET_KEY
export ENCRYPTION_KEY

if [ "${DEMO_MODE:-false}" = "true" ]; then
    DEMO_SEED_DIR="${DEMO_SEED_DIR:-/app/demo-seed}"
    DEMO_SEED_DATABASE="$DEMO_SEED_DIR/kaya.db"
    DEMO_DATABASE="/app/data/kaya.db"
    mkdir -p "$DEMO_SEED_DIR" "$DEMO_SEED_DIR/uploads"
    chown -R kaya:kaya "$DEMO_SEED_DIR"

    if [ "${DEMO_REBUILD_SEED:-false}" = "true" ] || [ ! -f "$DEMO_SEED_DATABASE" ]; then
        echo "Creating public demo seed database..."
        gosu kaya python -m scripts.seed_demo --database "$DEMO_SEED_DATABASE"
    fi

    if [ "${DEMO_RESET_ON_START:-false}" = "true" ] || [ ! -f "$DEMO_DATABASE" ]; then
        echo "Resetting public demo from seed..."
        cp "$DEMO_SEED_DATABASE" "$DEMO_DATABASE"
        chown kaya:kaya "$DEMO_DATABASE"
        rm -f /app/data/kaya.db-wal /app/data/kaya.db-shm
        find /app/uploads -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
        if [ -d "$DEMO_SEED_DIR/uploads" ]; then
            cp -a "$DEMO_SEED_DIR/uploads/." /app/uploads/
        fi
        chown -R kaya:kaya /app/uploads
    fi

    if [ "${DEMO_RESET_ON_START:-false}" = "true" ] || [ ! -s "${DEMO_GENERATION_FILE:-/app/data/.demo-generation}" ]; then
        printf '%s-%s\n' "$(date +%s)" "$$" > "${DEMO_GENERATION_FILE:-/app/data/.demo-generation}"
        chown kaya:kaya "${DEMO_GENERATION_FILE:-/app/data/.demo-generation}"
    fi
fi

echo "Starting Kaya with ENCRYPTION_KEY length: ${#ENCRYPTION_KEY}"

echo "Running database migrations..."
if [ "${SQLITE_PRE_MIGRATION_BACKUP:-true}" = "true" ] && [ -f /app/data/kaya.db ]; then
    cp /app/data/kaya.db /app/data/kaya.db.pre-migration
    chown kaya:kaya /app/data/kaya.db.pre-migration
fi
gosu kaya python /app/scripts/migrate_sqlite.py

exec gosu kaya "$@"
