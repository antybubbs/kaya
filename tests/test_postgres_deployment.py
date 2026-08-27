import hashlib
import json
import sys
import types
from pathlib import Path

from app.core.config import redact_database_url


def _role_topology_module(monkeypatch):
    import importlib.util

    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(connect=None))
    spec = importlib.util.spec_from_file_location(
        "kaya_postgres_role_topology", "scripts/kaya_postgres_role_topology.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_postgresql_url_redaction_removes_password_and_preserves_identity():
    rendered = redact_database_url(
        "postgresql+psycopg://kaya:do-not-log@postgres:5432/kaya?sslmode=require"
    )

    assert "do-not-log" not in rendered
    assert "postgres" in rendered
    assert "kaya" in rendered
    assert "sslmode" not in rendered


def test_postgresql_compose_keeps_database_private_and_password_external():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert "image: ${KAYA_POSTGRES_IMAGE:-postgres:16.14}" in compose
    assert "POSTGRES_PASSWORD:" not in compose
    assert "5432:" not in compose
    assert "kaya_postgres_data" in compose
    assert "pg_isready" in compose
    assert "postgres-secret-init:" in compose
    assert "service_completed_successfully" in compose
    assert "kaya_postgres_password" not in compose
    assert "${KAYA_POSTGRES_PASSWORD_DIR:-./data/secrets}:/run/kaya-secrets" in compose


def test_primary_compose_is_postgresql_only_and_keeps_database_private():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert "image: ${KAYA_POSTGRES_IMAGE:-postgres:16.14}" in compose
    assert "DATABASE_URL: postgresql+psycopg://kaya@postgres:5432/kaya" in compose
    assert "KAYA_SQLITE_SOURCE_URL" not in compose
    assert "KAYA_PHASE6_AUTO_UPGRADE" not in compose
    assert "sqlite-postgres-upgrade" not in compose
    assert "postgres-secret-init" in compose
    assert "kaya_postgres_data:/var/lib/postgresql/data" in compose
    assert "5432:" not in compose


def test_upgrade_compose_is_explicit_and_contains_sqlite_runner():
    overlay = Path("docker-compose.upgrade.yml").read_text(encoding="utf-8")

    assert "sqlite-postgres-upgrade:" in overlay
    assert "KAYA_SQLITE_SOURCE_URL: sqlite:////app/data/kaya.db" in overlay
    assert "scripts.kaya_phase6_upgrade" in overlay
    assert 'entrypoint: ["/usr/local/bin/kaya-entrypoint"]' in overlay
    assert 'SKIP_DATABASE_MIGRATIONS: "true"' in overlay
    assert 'KAYA_REQUIRE_PERSISTED_RUNTIME_SECRETS: "true"' in overlay
    assert 'entrypoint: ["python", "-m", "scripts.kaya_phase6_upgrade"]' not in overlay
    assert "--source" in overlay
    assert "--backup-dir" in overlay
    assert "kaya_upgrade_secrets" not in overlay
    assert "${KAYA_POSTGRES_PASSWORD_DIR:-./data/secrets}:/run/kaya-secrets" in overlay
    assert 'entrypoint: ["/bin/sh", "/app/scripts/init-postgres-secret.sh"]' in overlay
    assert "secrets: !override []" in overlay
    assert "secrets: !override {}" in overlay
    assert "KAYA_PHASE6_AUTO_UPGRADE" not in overlay


def test_upgrade_secret_bootstrap_is_atomic_and_does_not_expose_values():
    helper = Path("scripts/init-postgres-secret.sh").read_text(encoding="utf-8")

    assert "os.O_EXCL" in helper
    assert "secrets.token_urlsafe(64)" in helper
    assert "0o600" in helper
    assert 'stream.write(secrets.token_urlsafe(64).encode("ascii"))' in helper
    assert "cat \"$path\"" not in helper
    assert 'echo "$' not in helper


def test_upgrade_runner_uses_persistent_runtime_secret_bootstrap_without_starting_web_app():
    overlay = Path("docker-compose.upgrade.yml").read_text(encoding="utf-8")
    entrypoint = Path("docker-entrypoint.sh").read_text(encoding="utf-8")

    assert 'entrypoint: ["/usr/local/bin/kaya-entrypoint"]' in overlay
    assert 'command:\n      - python\n      - -m\n      - scripts.kaya_phase6_upgrade' in overlay
    assert 'SKIP_DATABASE_MIGRATIONS: "true"' in overlay
    assert 'SECRETS_FILE="/app/data/.runtime.env"' in entrypoint
    assert 'KAYA_REQUIRE_PERSISTED_RUNTIME_SECRETS' in entrypoint
    assert 'Persistent Kaya runtime secrets are required for this operation.' in entrypoint
    assert '[ "${SKIP_DATABASE_MIGRATIONS:-false}" != "true" ]' in entrypoint
    assert 'from app.models.models import User' in entrypoint
    assert 'echo "Setup token: $SETUP_TOKEN"' in entrypoint
    assert 'Open /setup in your browser to create the first administrator.' in entrypoint
    assert 'SECRET_KEY=$PERSISTED_SECRET_KEY' not in entrypoint.split('if [ "${SKIP_DATABASE_MIGRATIONS:-false}"', 1)[-1]
    assert 'ENCRYPTION_KEY=$PERSISTED_ENCRYPTION_KEY' not in entrypoint.split('if [ "${SKIP_DATABASE_MIGRATIONS:-false}"', 1)[-1]
    assert 'postgres_password' not in entrypoint.split('if [ "${SKIP_DATABASE_MIGRATIONS:-false}"', 1)[-1]
    assert 'exec gosu kaya "$@"' in entrypoint
    assert "uvicorn" not in overlay


def test_upgrade_workflow_is_not_part_of_normal_startup():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert "depends_on:\n      postgres:\n        condition: service_healthy" in compose
    assert "postgres-secret-init" in compose


def test_phase7d_backup_probe_runs_with_postgres_client_image():
    overlay = Path("ci/compose/docker-compose.phase7d-ci.yml").read_text(encoding="utf-8")

    section = overlay.split("  postgres-role-migration-backup:", 1)[1].split("\n\n", 1)[0]
    assert "image: ${KAYA_POSTGRES_IMAGE:-postgres:16.14}" in section
    assert "image: ${PHASE7D_IMAGE}" not in section


def test_phase7d_runtime_uses_the_documented_explicit_sqlite_upgrade_runner():
    script = Path("scripts/phase7d_runtime_validation.sh").read_text(encoding="utf-8")

    assert 'UPGRADE_FILE="$ROOT_DIR/docker-compose.upgrade.yml"' in script
    assert 'upgrade_compose()' in script
    assert 'upgrade_compose run --rm sqlite-postgres-upgrade' in script
    assert 'compose_up\nwait_for_kaya' in script
    assert "kaya-database-upgrade-report.json" in script


def test_phase12_role_topology_helper_is_fail_closed_and_scoped():
    helper = Path("scripts/kaya_postgres_role_topology.py").read_text(encoding="utf-8")

    assert 'APP_ROLE = "kaya"' in helper
    assert 'BOOTSTRAP_ROLE = "kaya_bootstrap"' in helper
    assert "KAYA_ROLE_MIGRATION_MARKER" in helper
    assert "ambiguous or unsafe Kaya PostgreSQL role topology" in helper
    assert "REASSIGN OWNED" not in helper
    assert "pg_namespace" in helper
    assert 'schema_owner not in {APP_ROLE, "pg_database_owner"}' in helper
    assert 'schema_owner_before in {APP_ROLE, "pg_database_owner"}' in helper
    assert "public" in helper


def test_phase12_partial_role_recovery_does_not_parameterize_ddl_password():
    helper = Path("scripts/kaya_postgres_role_topology.py").read_text(encoding="utf-8")

    assert "ALTER ROLE %%I LOGIN SUPERUSER CREATEDB CREATEROLE PASSWORD %%L" in helper
    assert 'ALTER ROLE kaya_bootstrap LOGIN SUPERUSER CREATEDB CREATEROLE PASSWORD %s' not in helper


def test_phase12_backup_marker_is_bound_to_verified_archive(tmp_path, monkeypatch):
    module = _role_topology_module(monkeypatch)
    archive = tmp_path / "kaya-20260821T000000Z.dump"
    archive.write_bytes(b"synthetic disposable archive")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    metadata = {
        "verification_state": "verified",
        "sha256": digest,
        "alembic_revision": "20260818_02",
    }
    archive.with_name(f"{archive.name}.json").write_text(json.dumps(metadata), encoding="utf-8")
    archive.with_name(f"{archive.name}.sha256").write_text(f"{digest}  {archive}\n", encoding="utf-8")
    marker = tmp_path / ".role-migration-backup-verified"
    marker.write_text(
        json.dumps(
            {
                "archive": archive.name,
                "sha256": digest,
                "archive_bytes": archive.stat().st_size,
                "source_database": "kaya",
                "source_role": "kaya",
                "alembic_revision": "20260818_02",
                "backup_purpose": "pre_role_topology_migration",
                "run_id": "test-run",
            }
        ),
        encoding="utf-8",
    )
    marker.chmod(0o600)
    monkeypatch.setattr(module.stat, "S_IMODE", lambda _mode: 0)
    monkeypatch.setenv("KAYA_ROLE_MIGRATION_RUN_ID", "test-run")
    module.verify_backup_marker(marker)
    archive.write_bytes(b"tampered")
    try:
        module.verify_backup_marker(marker)
    except RuntimeError as exc:
        assert "not bound" in str(exc)
    else:
        raise AssertionError("tampered archive was accepted")


def test_phase12_acceptance_matrix_fails_closed_for_unexecuted_rows():
    import importlib.util

    spec = importlib.util.spec_from_file_location("phase12_acceptance_evidence", "scripts/phase12_acceptance_evidence.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert sorted(module.SCENARIOS) == list(range(1, 64))
    assert len(module.SCENARIOS) == 63
    assert len(set(module.SCENARIOS)) == 63
    assert all(row["status"] == "BLOCKED" for row in module.fresh().values())


def test_phase12_legacy_overlay_uses_historical_postgres_bootstrap_user():
    overlay = Path("ci/compose/docker-compose.phase12-legacy-ci.yml").read_text(encoding="utf-8")

    assert "POSTGRES_USER: kaya" in overlay
    assert "POSTGRES_PASSWORD_FILE: /run/kaya-secrets/postgres_password" in overlay
    assert "kaya_bootstrap" not in overlay


def test_phase12_backup_worker_separates_admin_and_runtime_passwords():
    worker = Path("scripts/kaya_postgres_backup_worker.sh").read_text(encoding="utf-8")

    assert 'ADMIN_PASSWORD_FILE="${KAYA_POSTGRES_ADMIN_PASSWORD_FILE:-$PASSWORD_FILE}"' in worker
    assert "admin_psql" in worker
    topology = Path("scripts/kaya_postgres_role_topology.py").read_text(encoding="utf-8")
    assert "ambiguous or unsafe Kaya PostgreSQL role topology" in topology
    assert '"sha256"' in Path("scripts/kaya_postgres_backup_worker.sh").read_text(encoding="utf-8")


def test_role_migration_backup_validation_remains_in_runtime_suite():
    script = Path("scripts/phase12_runtime_validation.sh").read_text(encoding="utf-8")

    assert "kaya_bootstrap" in script
    assert "postgres-role-migration-backup" in script
    assert "postgres-role-init" in script


def test_role_migration_backup_requires_conclusive_current_topology_invariants():
    script = Path("scripts/phase12_runtime_validation.sh").read_text(encoding="utf-8")

    helper = Path("scripts/kaya_postgres_role_topology.py").read_text(encoding="utf-8")
    assert "role_topology_already_migrated" in script
    assert "rolname='kaya_bootstrap'" in script
    assert "rolcanlogin" in helper
    assert "pg_get_userbyid(d.datdba)" in helper
    assert "pg_get_userbyid(n.nspowner)" in helper
    assert "ambiguous or unsafe Kaya PostgreSQL role topology" in helper


def test_phase12_overlay_isolates_all_persistent_postgres_mounts():
    overlay = Path("ci/compose/docker-compose.phase12-ci.yml").read_text(encoding="utf-8")

    assert "postgres-secret-init:" in overlay
    assert "source: postgres_data" in overlay
    assert "source: postgres_secret" in overlay
    assert "container_name: ${PHASE12_PROJECT}_kaya" in overlay
    assert "ports: !override []" in overlay


def test_phase12_runtime_starts_application_without_rerunning_legacy_backup():
    script = Path("scripts/phase12_runtime_validation.sh").read_text(encoding="utf-8")

    assert 'up -d --no-deps kaya' in script
    assert 'rm -sf postgres-role-init postgres-role-migration-backup' in script
    assert 'up --abort-on-container-exit --exit-code-from postgres-role-init postgres-role-init' in script
    assert "postgres.role_backup state=current action=not_required reason=role_topology_already_migrated' <<<\"$current_backup_log\"" in script
    assert '"legacy_backup":"not required"' in script


def test_phase12_runtime_validates_workflow_and_exact_cleanup():
    script = Path("scripts/phase12_runtime_validation.sh").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in Path(".github/workflows/database-deep-validation.yml").read_text(encoding="utf-8")
    workflow = Path(".github/workflows/database-deep-validation.yml").read_text(encoding="utf-8")
    assert "cancel-in-progress: false" in workflow
    assert "GITHUB_RUN_ID % 1000" in workflow
    assert "record_pass 62" in script
    assert "phase12a_cleanup_validation.sh" in script
    assert "--scenario 63 --status PASS" in script


def test_phase11_backup_lifecycle_uses_admin_role_without_granting_app_createdb():
    compose = Path("ci/compose/docker-compose.phase11-ci.yml").read_text(encoding="utf-8")
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
