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

    if [ "${KAYA_REQUIRE_PERSISTED_RUNTIME_SECRETS:-false}" = "true" ] && {
        [ -z "$PERSISTED_SECRET_KEY" ] || [ -z "$PERSISTED_ENCRYPTION_KEY" ];
    }; then
        echo "Persistent Kaya runtime secrets are required for this operation." >&2
        exit 1
    fi

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

PHASE6_RECOVERY_MODE=false
if python -m scripts.kaya_phase6_recovery_policy "$@"; then
    PHASE6_RECOVERY_MODE=true
    echo "Phase 6 recovery CLI recognised; failed-target guards remain enabled."
fi
PHASE6_UPGRADE_MODE=false
if python -c "import sys; from scripts.kaya_phase6_recovery_policy import is_phase6_upgrade_command; raise SystemExit(0 if is_phase6_upgrade_command(sys.argv[1:]) else 1)" "$@"; then
    PHASE6_UPGRADE_MODE=true
    echo "Phase 6 upgrade CLI recognised; PRECHECK resume is permitted only for this command."
fi
PHASE6_RECOVERY_STATE=false

UPGRADE_STATE_FILE="/app/data/kaya-database-upgrade.json"
if [ -f "$UPGRADE_STATE_FILE" ]; then
    UPGRADE_STATE="$(python -c "import json; print(json.load(open('$UPGRADE_STATE_FILE', encoding='utf-8')).get('state', ''))")"
    AUTHORITATIVE_ENGINE="$(python -c "import json; print(json.load(open('$UPGRADE_STATE_FILE', encoding='utf-8')).get('database_engine', ''))")"
    case "$UPGRADE_STATE" in
        FAILED|PRECHECK|MAINTENANCE|BACKED_UP|POSTGRES_PREPARED|MIGRATING|VALIDATING|POSTGRES_READY|CUTOVER_PENDING)
            if [ "$UPGRADE_STATE" = "PRECHECK" ] && [ "$PHASE6_UPGRADE_MODE" = "true" ]; then
                echo "Kaya database upgrade is PRECHECK; resuming the explicit Phase 6 upgrade command."
            elif [ "$PHASE6_RECOVERY_MODE" != "true" ] || [ "$UPGRADE_STATE" != "FAILED" ]; then
                echo "Kaya database upgrade is $UPGRADE_STATE; operator recovery is required before startup." >&2
                exit 1
            fi
            PHASE6_RECOVERY_STATE=true
            echo "Kaya database upgrade is FAILED; running the explicit guarded recovery command."
            ;;
    esac
    if [ "$AUTHORITATIVE_ENGINE" = "postgresql" ]; then
        if [ -z "${KAYA_POSTGRES_DATABASE_URL:-}" ]; then
            echo "PostgreSQL is authoritative but KAYA_POSTGRES_DATABASE_URL is not configured; refusing SQLite fallback." >&2
            exit 1
        fi
        export DATABASE_URL="$KAYA_POSTGRES_DATABASE_URL"
    fi
fi

if [ "$PHASE6_RECOVERY_MODE" = "true" ]; then
    if [ "$PHASE6_RECOVERY_STATE" != "true" ]; then
        echo "Explicit Phase 6 recovery requires a FAILED migration state; refusing recovery handoff." >&2
        exit 1
    fi
    echo "database.recovery startup_database_prepare=skipped"
    echo "database.recovery command_handoff=starting"
    exec gosu kaya "$@"
fi

CONFIGURED_DATABASE_URL="${DATABASE_URL:-}"
SQLITE_SOURCE_URL="${KAYA_SQLITE_SOURCE_URL:-}"
SQLITE_SOURCE_PATH="${SQLITE_SOURCE_URL#sqlite:///}"
if [ "${APP_ENV:-production}" = "production" ] && [ "$CONFIGURED_DATABASE_URL" != "${CONFIGURED_DATABASE_URL#sqlite}" ]; then
    echo "Production Kaya requires PostgreSQL; SQLite is reserved for controlled legacy migration and recovery tooling." >&2
    exit 1
fi
POSTGRES_SCHEMA_READY="false"
if [ "$CONFIGURED_DATABASE_URL" != "${CONFIGURED_DATABASE_URL#postgresql}" ]; then
    if gosu kaya python -c "from sqlalchemy import inspect; from app.db.session import engine; raise SystemExit(0 if inspect(engine).has_table('alembic_version') else 1)"; then
        POSTGRES_SCHEMA_READY="true"
    fi
fi

if [ "${KAYA_PHASE6_AUTO_UPGRADE:-false}" = "true" ] && [ "$PHASE6_RECOVERY_MODE" != "true" ] && [ -n "$SQLITE_SOURCE_URL" ] && [ -f "$SQLITE_SOURCE_PATH" ] && [ "${AUTHORITATIVE_ENGINE:-}" != "postgresql" ] && [ "$POSTGRES_SCHEMA_READY" != "true" ]; then
    if ! KAYA_LEGACY_SOURCE="$SQLITE_SOURCE_PATH" KAYA_LEGACY_DATA_DIR="${DATA_DIR:-/app/data}" gosu kaya python -c "import os; from pathlib import Path; from app.db.phase6_cutover import legacy_sqlite_eligibility; ok, reason = legacy_sqlite_eligibility(Path(os.environ['KAYA_LEGACY_SOURCE']), Path(os.environ['KAYA_LEGACY_DATA_DIR'])); print(reason); raise SystemExit(0 if ok else 1)"; then
        echo "Legacy SQLite source is not an eligible Kaya database; refusing automatic migration." >&2
        exit 1
    fi
    echo "Preparing controlled SQLite to PostgreSQL upgrade..."
    gosu kaya python -m scripts.kaya_phase6_upgrade \
        --source "$SQLITE_SOURCE_PATH" \
        --target-url "${KAYA_POSTGRES_DATABASE_URL:-}" \
        --backup-dir "${MIGRATION_BACKUP_DIR:-/app/data/backups}" \
        --data-dir "${DATA_DIR:-/app/data}"
    export DATABASE_URL="${KAYA_POSTGRES_DATABASE_URL}"
fi


echo "Starting Kaya with ENCRYPTION_KEY length: ${#ENCRYPTION_KEY}"

if [ "${SKIP_DATABASE_MIGRATIONS:-false}" != "true" ]; then
    echo "Preparing Kaya database..."
    gosu kaya python -m app.db.cli
fi

if [ "${SKIP_DATABASE_MIGRATIONS:-false}" != "true" ] && [ "${KAYA_GATEWAY_MODE:-false}" != "true" ]; then
    if gosu kaya python -c "from app.db.session import SessionLocal; from app.models.models import User; db=SessionLocal(); found=db.query(User.id).filter(User.role == 'admin').first(); db.close(); raise SystemExit(0 if found is None else 1)"; then
        echo "Kaya first-run setup is required."
        echo "Setup token: $SETUP_TOKEN"
        echo "Open /setup in your browser to create the first administrator."
    fi
fi

exec gosu kaya "$@"
