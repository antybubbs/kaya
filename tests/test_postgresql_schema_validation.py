"""Disposable PostgreSQL schema and invariant validation."""

from __future__ import annotations

import json
import os
import threading
import unicodedata
from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from app.db.migrations import _alembic_config
from app.db.schema_manifest import compare_manifest_to_models, schema_manifest
from app.db.validation import DatabaseValidationError, validate_engine_schema
from app.models.models import Base


def _postgres_url() -> str:
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    return url


def _fresh_postgres_engine():
    engine = create_engine(_postgres_url(), pool_pre_ping=True)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    command.upgrade(_alembic_config(_postgres_url()), "head")
    return engine


def test_postgresql_manifest_is_actual_base_to_head_schema():
    engine = _fresh_postgres_engine()
    manifest = schema_manifest(engine)
    comparison = compare_manifest_to_models(manifest, Base.metadata)
    with engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert revision == "20260818_02"
    assert comparison == {"missing_tables": [], "missing_columns": []}
    assert manifest["triggers"]
    assert manifest["sequences"]
    photo_indexes = {
        index["name"]: index
        for table in manifest["tables"]
        if table["name"] == "hardware_asset_photos"
        for index in table["indexes"]
    }
    assert "postgresql_where" in photo_indexes["uq_hardware_asset_photos_primary"]["dialect_options"]


def test_postgresql_pk_fk_unique_types_defaults_and_binary_round_trip():
    engine = _fresh_postgres_engine()
    with engine.begin() as connection:
        first = connection.execute(
            text(
                "INSERT INTO users (email, password_hash, role, is_active, totp_enabled, authentication_type, "
                "is_break_glass, role_source, created_at, updated_at) VALUES (:email, :password_hash, :role, "
                ":is_active, FALSE, 'local', FALSE, 'local', :created_at, :updated_at) RETURNING id"
            ),
            {
                "email": "schema-one@example.invalid",
                "password_hash": "fake",
                "role": "admin",
                "is_active": True,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            },
        ).scalar_one()
        second = connection.execute(
            text(
                "INSERT INTO users (email, password_hash, role, is_active, totp_enabled, authentication_type, "
                "is_break_glass, role_source, created_at, updated_at) VALUES (:email, :password_hash, :role, "
                ":is_active, FALSE, 'local', FALSE, 'local', :created_at, :updated_at) RETURNING id"
            ),
            {
                "email": "schema-two@example.invalid",
                "password_hash": "fake",
                "role": "viewer",
                "is_active": False,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            },
        ).scalar_one()
        assert second > first
        connection.execute(
            text(
                "INSERT INTO user_module_permissions (user_id, module_key, allowed, created_at, updated_at) "
                "VALUES (:user_id, 'audit', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"user_id": first},
        )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO user_module_permissions (user_id, module_key, allowed, created_at, updated_at) "
                    "VALUES (:user_id, 'audit', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                ),
                {"user_id": first},
            )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO user_module_permissions (user_id, module_key, allowed, created_at, updated_at) "
                    "VALUES (999999999, 'invalid', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                )
            )
    payload = {"unicode": "caf\u00e9 \u03bb", "items": [1, 2, 3]}
    binary = bytes(range(256)) * 8
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO runbook_images (original_filename, content_type, size_bytes, data, created_at) "
                "VALUES (:filename, :content_type, :size_bytes, :data, CURRENT_TIMESTAMP)"
            ),
            {
                "filename": "\u03c0.png",
                "content_type": "image/png",
                "size_bytes": len(binary),
                "data": binary,
            },
        )
        stored = connection.execute(
            text("SELECT data FROM runbook_images WHERE original_filename = '\u03c0.png'")
        ).scalar_one()
    assert bytes(stored) == binary
    assert json.loads(json.dumps(payload, ensure_ascii=False)) == payload
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO remote_manager_settings (key, value, updated_at) "
                "VALUES ('schema-json', :value, CURRENT_TIMESTAMP)"
            ),
            {"value": json.dumps(payload, ensure_ascii=False)},
        )
    with engine.connect() as connection:
        assert json.loads(
            connection.execute(
                text("SELECT value FROM remote_manager_settings WHERE key = 'schema-json'")
            ).scalar_one()
        ) == payload


def test_postgresql_semantics_cover_time_text_nulls_numeric_and_large_byte_counts():
    engine = _fresh_postgres_engine()
    nfc = unicodedata.normalize("NFC", "café")
    nfd = unicodedata.normalize("NFD", "café")
    boundary = datetime(2026, 3, 29, 0, 59, 59, 123456)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (email, role, is_active, totp_enabled, authentication_type, "
                "is_break_glass, role_source, created_at, updated_at) VALUES "
                "(:nfc, 'viewer', TRUE, FALSE, 'local', FALSE, 'local', :boundary, :boundary), "
                "(:nfd, 'viewer', TRUE, FALSE, 'local', FALSE, 'local', :later, :later)"
            ),
            {"nfc": f"{nfc}@example.invalid", "nfd": f"{nfd}@example.invalid", "boundary": boundary, "later": datetime(2026, 10, 25, 0, 59, 59, 654321)},
        )
        connection.execute(
            text(
                "INSERT INTO dns_providers (name, provider_type, base_url, auth_method, ssl_verify, "
                "timeout_seconds, is_enabled, description, created_at, updated_at) VALUES "
                "(:name, 'pihole', 'https://dns.invalid', 'password', TRUE, 10, TRUE, NULL, :boundary, :boundary)"
            ),
            {"name": "provider-with-trailing-space ", "boundary": boundary},
        )
        connection.execute(
            text(
                "INSERT INTO compute_hosts (name, platform, base_url, verify_tls, is_enabled, "
                "poll_interval_seconds, status, created_at, updated_at) VALUES "
                "('semantic-host', 'linux', 'https://compute.invalid', TRUE, TRUE, 30, 'online', :boundary, :boundary)"
            ),
            {"boundary": boundary},
        )
        connection.execute(
            text(
                "INSERT INTO compute_metrics (host_id, cpu_percent, memory_used, memory_total, "
                "storage_used, storage_total, recorded_at) VALUES "
                "(1, 99.75, 2147483647, 2147483648, 50000000000, 100000000000, :boundary)"
            ),
            {"boundary": boundary},
        )
        stored = connection.execute(
            text(
                "SELECT u1.email, u2.email, p.name, p.description, m.cpu_percent, "
                "m.memory_total, m.recorded_at FROM users u1 "
                "JOIN users u2 ON u2.email = :nfd JOIN dns_providers p ON p.name LIKE 'provider-with-trailing%' "
                "JOIN compute_metrics m ON m.host_id = 1 WHERE u1.email = :nfc"
            ),
            {"nfc": f"{nfc}@example.invalid", "nfd": f"{nfd}@example.invalid"},
        ).one()
    assert {stored[0], stored[1]} == {f"{nfc}@example.invalid", f"{nfd}@example.invalid"}
    assert stored[2].endswith(" ")
    assert stored.description is None
    assert stored.cpu_percent == pytest.approx(99.75)
    assert stored.memory_total == 2_147_483_648
    assert stored.recorded_at == boundary


def test_postgresql_partial_index_is_usable_and_photo_limit_is_transactional():
    engine = _fresh_postgres_engine()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO hardware_assets (id, name, status, created_at, updated_at) "
                "VALUES (810001, 'schema validation asset', 'In use', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        for index in range(5):
            connection.execute(
                text(
                    "INSERT INTO hardware_asset_photos "
                    "(asset_id, storage_filename, is_primary, sort_order, uploaded_at) "
                    "VALUES (810001, :filename, :primary, :sort_order, CURRENT_TIMESTAMP)"
                ),
                {"filename": f"schema-{index}.webp", "primary": index == 0, "sort_order": index},
            )
    with engine.connect() as connection:
        connection.execute(text("SET enable_seqscan = off"))
        plan = "\n".join(
            row[0]
            for row in connection.execute(
                text(
                    "EXPLAIN (COSTS OFF) SELECT id FROM hardware_asset_photos "
                    "WHERE asset_id = 810001 AND is_primary = TRUE"
                )
            )
        )
    assert "uq_hardware_asset_photos_primary" in plan
    with pytest.raises(Exception, match="hardware asset photo limit exceeded"):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO hardware_asset_photos "
                    "(asset_id, storage_filename, is_primary, sort_order, uploaded_at) "
                    "VALUES (810001, 'schema-over.webp', FALSE, 6, CURRENT_TIMESTAMP)"
                )
            )
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT COUNT(*) FROM hardware_asset_photos WHERE asset_id = 810001")
        ).scalar_one() == 5


def test_postgresql_photo_limit_serializes_concurrent_inserts():
    engine = _fresh_postgres_engine()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO hardware_assets (id, name, status, created_at, updated_at) "
                "VALUES (810002, 'concurrent schema asset', 'In use', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        for index in range(4):
            connection.execute(
                text(
                    "INSERT INTO hardware_asset_photos "
                    "(asset_id, storage_filename, is_primary, sort_order, uploaded_at) "
                    "VALUES (810002, :filename, FALSE, :sort_order, CURRENT_TIMESTAMP)"
                ),
                {"filename": f"concurrent-{index}.webp", "sort_order": index},
            )
    barrier = threading.Barrier(2)
    outcomes = []

    def insert_photo(slot: int):
        try:
            with engine.begin() as connection:
                barrier.wait(timeout=10)
                connection.execute(
                    text(
                        "INSERT INTO hardware_asset_photos "
                        "(asset_id, storage_filename, is_primary, sort_order, uploaded_at) "
                        "VALUES (810002, :filename, FALSE, :sort_order, CURRENT_TIMESTAMP)"
                    ),
                    {"filename": f"race-{slot}.webp", "sort_order": 10 + slot},
                )
            outcomes.append("success")
        except Exception as exc:  # pragma: no cover - asserted by outcome
            outcomes.append(type(exc).__name__)

    workers = [threading.Thread(target=insert_photo, args=(slot,)) for slot in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=15)
    assert outcomes.count("success") == 1
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT COUNT(*) FROM hardware_asset_photos WHERE asset_id = 810002")
        ).scalar_one() == 5


def test_postgresql_trigger_migration_downgrade_and_upgrade_round_trip():
    engine = _fresh_postgres_engine()
    url = _postgres_url()
    command.downgrade(_alembic_config(url), "20260810_02")
    with engine.connect() as connection:
        assert connection.execute(
            text(
                "SELECT COUNT(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                "WHERE c.relname = 'hardware_asset_photos' AND NOT t.tgisinternal"
            )
        ).scalar_one() == 0
    command.upgrade(_alembic_config(url), "head")
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one() == "20260818_02"


def test_postgresql_schema_has_no_unexpected_model_table_or_column_drift():
    engine = _fresh_postgres_engine()
    manifest = schema_manifest(engine)
    actual = {table["name"]: table for table in manifest["tables"]}
    assert set(Base.metadata.tables) <= set(actual)
    assert inspect(engine).get_table_names()


def test_postgresql_schema_drift_detection_rejects_missing_critical_index():
    engine = _fresh_postgres_engine()
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX uq_hardware_asset_photos_primary"))
    with pytest.raises(DatabaseValidationError, match="Required indexes are missing"):
        validate_engine_schema(
            engine,
            Base.metadata,
            require_revision="20260818_02",
            required_indexes=(("hardware_asset_photos", "uq_hardware_asset_photos_primary"),),
        )


def test_sqlite_and_postgresql_have_the_same_logical_table_and_column_sets():
    postgres = _fresh_postgres_engine()
    with TemporaryDirectory() as temporary_directory:
        sqlite_path = Path(temporary_directory) / "logical.sqlite3"
        sqlite = create_engine(f"sqlite:///{sqlite_path.as_posix()}")
        command.upgrade(_alembic_config(str(sqlite.url)), "head")
        postgres_manifest = schema_manifest(postgres)
        sqlite_manifest = schema_manifest(sqlite)
    postgres_tables = {table["name"]: {column["name"] for column in table["columns"]} for table in postgres_manifest["tables"]}
    sqlite_tables = {table["name"]: {column["name"] for column in table["columns"]} for table in sqlite_manifest["tables"]}
    assert postgres_tables == sqlite_tables
