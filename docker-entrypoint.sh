#!/bin/sh
set -eu

mkdir -p /app/data /app/data/secure-send
if [ "${KAYA_GATEWAY_MODE:-false}" != "true" ]; then
    mkdir -p /app/uploads /app/data/remote-recordings /app/data/secret-vault
    chown -R kaya:kaya /app/uploads
    chmod 700 /app/data/secret-vault
fi
chown -R kaya:kaya /app/data
chmod 700 /app/data/secure-send

SECRETS_FILE="/app/data/.runtime.env"

generate_secret_key() {
    python -c "import secrets; print(secrets.token_urlsafe(64))"
}

generate_encryption_key() {
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
}

generate_setup_token() {
    python -c "import secrets; print(secrets.token_urlsafe(32))"
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
    PERSISTED_SETUP_TOKEN="${SETUP_TOKEN:-}"

    if [ -z "$PERSISTED_SECRET_KEY" ]; then
        PERSISTED_SECRET_KEY="$(generate_secret_key)"
    fi

    if [ -z "$PERSISTED_ENCRYPTION_KEY" ]; then
        PERSISTED_ENCRYPTION_KEY="$(generate_encryption_key)"
    fi
    if [ -z "$PERSISTED_SETUP_TOKEN" ]; then
        PERSISTED_SETUP_TOKEN="$(generate_setup_token)"
    fi

    cat > "$SECRETS_FILE" <<EOF
SECRET_KEY=$PERSISTED_SECRET_KEY
ENCRYPTION_KEY=$PERSISTED_ENCRYPTION_KEY
SETUP_TOKEN=$PERSISTED_SETUP_TOKEN
EOF

    chown kaya:kaya "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
fi

if ! grep -q '^SETUP_TOKEN=' "$SECRETS_FILE"; then
    PERSISTED_SETUP_TOKEN="${SETUP_TOKEN:-$(generate_setup_token)}"
    printf '\nSETUP_TOKEN=%s\n' "$PERSISTED_SETUP_TOKEN" >> "$SECRETS_FILE"
    chown kaya:kaya "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
fi

set -a
. "$SECRETS_FILE"
set +a

export SECRET_KEY
export ENCRYPTION_KEY
export SETUP_TOKEN


echo "Starting Kaya with ENCRYPTION_KEY length: ${#ENCRYPTION_KEY}"

if [ "${SKIP_DATABASE_MIGRATIONS:-false}" != "true" ]; then
    echo "Preparing Kaya database..."
    gosu kaya python -m app.db.cli
fi

if gosu kaya python -c "from app.db.session import SessionLocal; from app.models.models import User; db=SessionLocal(); found=db.query(User.id).filter(User.role == 'admin').first(); db.close(); raise SystemExit(0 if found is None else 1)"; then
    echo "Kaya first-run setup token: $SETUP_TOKEN"
    echo "Enter this token on the first-run setup page. It is not accepted after an administrator exists."
fi

exec gosu kaya "$@"
