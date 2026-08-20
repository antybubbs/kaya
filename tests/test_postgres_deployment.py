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

    assert "image: postgres:16.14" in compose
    assert "DATABASE_URL: postgresql+psycopg://kaya@postgres:5432/kaya" in compose
    assert "KAYA_SQLITE_SOURCE_URL: sqlite:////app/data/kaya.db" in compose
    assert "kaya_phase6_postgres_secret:/run/kaya-secrets:ro" in compose
    assert "kaya_postgres_data:/var/lib/postgresql/data" in compose
    assert "${KAYA_POSTGRES_BACKUP_DIR:-./postgres-backups}:/var/backups/kaya-postgres" in compose
    assert "5432:" not in compose
