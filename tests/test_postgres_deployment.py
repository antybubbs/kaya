from pathlib import Path

from app.core.config import redact_database_url


def test_postgresql_url_redaction_removes_password_and_preserves_identity():
    rendered = redact_database_url(
        "postgresql+psycopg://kaya:do-not-log@postgres:5432/kaya?sslmode=require"
    )

    assert "do-not-log" not in rendered
    assert "postgres" in rendered
    assert "kaya" in rendered
    assert "sslmode" not in rendered


def test_postgresql_compose_keeps_database_private_and_password_external():
    compose = Path("docker-compose.postgres.yml").read_text(encoding="utf-8")

    assert "image: postgres:16.14" in compose
    assert "POSTGRES_PASSWORD:" not in compose
    assert "5432:" not in compose
    assert "kaya_postgres_data" in compose
    assert "pg_isready" in compose


def test_primary_compose_uses_postgresql_and_keeps_sqlite_for_controlled_upgrade():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert "image: ${KAYA_POSTGRES_IMAGE:-postgres:16.14}" in compose
    assert "DATABASE_URL: postgresql+psycopg://kaya@postgres:5432/kaya" in compose
    assert "KAYA_SQLITE_SOURCE_URL: sqlite:////app/data/kaya.db" in compose
    assert "kaya_phase6_postgres_secret:/run/kaya-secrets:ro" in compose
    assert "kaya_postgres_data:/var/lib/postgresql/data" in compose
    assert "${KAYA_POSTGRES_BACKUP_DIR:-./postgres-backups}:/var/backups/kaya-postgres" in compose
    assert "5432:" not in compose


def test_primary_compose_separates_bootstrap_and_runtime_postgres_roles():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert "POSTGRES_USER: kaya_bootstrap" in compose
    assert "postgres-role-init:" in compose
    assert "CREATE ROLE kaya LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" in compose
    assert "ALTER DATABASE kaya OWNER TO kaya;" in compose
    assert "ALTER SCHEMA public OWNER TO kaya;" in compose
    assert "service_completed_successfully" in compose


def test_phase11_backup_lifecycle_uses_admin_role_without_granting_app_createdb():
    compose = Path("docker-compose.phase11-ci.yml").read_text(encoding="utf-8")
    worker = Path("scripts/kaya_postgres_backup_worker.sh").read_text(encoding="utf-8")

    assert "KAYA_POSTGRES_ADMIN_USER: kaya_bootstrap" in compose
    assert "ADMIN_USER=\"${KAYA_POSTGRES_ADMIN_USER:-}\"" in worker
    assert 'CREATE DATABASE \\"$target\\" OWNER \\"$DB_USER\\"' in worker
    assert "KAYA_POSTGRES_ADMIN_USER is required" in worker


def test_phase11_fixture_enables_high_availability_for_authenticated_smoke():
    script = Path("scripts/phase11_runtime_validation.sh").read_text(encoding="utf-8")

    assert "high_availability_enabled" in script
    assert "user_module_permissions" in script
    assert "allowed = true" in script
    assert 'PHASE7D_HTTP_BASE=' in script
