"""Cross-engine compatibility tests for the Phase 2 database boundary."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.dialect import begin_initial_setup_transaction, capabilities
from app.db.migrations import _alembic_config, prepare_database
from app.db.session import configure_sqlite_connection, verify_database_engine
from app.models.models import User


def _sqlite_engine(tmp_path: Path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'compatibility.sqlite3').as_posix()}")
    event.listen(engine, "connect", configure_sqlite_connection)
    return engine


def _postgres_engine():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    return create_engine(url, pool_pre_ping=True)


def _url_for(engine) -> str:
    if engine.dialect.name == "postgresql":
        return os.environ["KAYA_TEST_POSTGRES_URL"]
    return str(engine.url)


def _test_alembic_config(database_url: str, tmp_path: Path):
    """Fail closed if a SQLite migration test escapes its disposable directory."""
    parsed = make_url(database_url)
    if parsed.get_backend_name() == "sqlite" and parsed.database:
        database_path = Path(parsed.database).resolve()
        disposable_root = tmp_path.resolve()
        try:
            database_path.relative_to(disposable_root)
        except ValueError as exc:
            raise AssertionError("SQLite migration tests must target their disposable tmp_path") from exc
    return _alembic_config(database_url)


def _reset_postgres_schema(engine) -> None:
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))


def _settings(url: str) -> Settings:
    return Settings(
        app_env="test",
        encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
        database_url=url,
    )


@pytest.mark.parametrize("engine_factory", [_sqlite_engine, _postgres_engine])
def test_engine_dispatch_verifies_connectivity_without_cross_engine_pragmas(
    engine_factory, tmp_path
):
    engine = engine_factory(tmp_path) if engine_factory is _sqlite_engine else engine_factory()
    detected = verify_database_engine(engine)
    assert detected.name in {"sqlite", "postgresql"}
    assert capabilities(engine).name == detected.name


@pytest.mark.parametrize("engine_factory", [_sqlite_engine, _postgres_engine])
def test_initial_setup_lock_serializes_first_admin_creation(engine_factory, tmp_path):
    engine = engine_factory(tmp_path) if engine_factory is _sqlite_engine else engine_factory()
    User.__table__.create(engine, checkfirst=True)
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM users"))
    factory_errors = []

    def create_admin(email: str):
        try:
            with Session(engine) as db:
                begin_initial_setup_transaction(db)
                if db.query(User).filter(User.role == "admin").first() is None:
                    db.add(User(email=email, password_hash="fake", role="admin", is_active=True))
                    db.commit()
                else:
                    db.rollback()
        except Exception as exc:  # pragma: no cover - asserted below
            factory_errors.append(exc)

    workers = [threading.Thread(target=create_admin, args=(f"admin-{index}@example.invalid",)) for index in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
    assert factory_errors == []
    with Session(engine) as db:
        assert db.query(User).filter(User.role == "admin").count() == 1


@pytest.mark.parametrize("engine_factory", [_sqlite_engine, _postgres_engine])
def test_asset_photo_limit_trigger_and_partial_index(engine_factory, tmp_path):
    engine = engine_factory(tmp_path) if engine_factory is _sqlite_engine else engine_factory()
    url = _url_for(engine)
    _reset_postgres_schema(engine)
    command.upgrade(_test_alembic_config(url, tmp_path), "head")
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM hardware_asset_photos"))
        connection.execute(text("DELETE FROM hardware_assets"))
        connection.execute(
            text("INSERT INTO hardware_assets (id, name, status, created_at, updated_at) VALUES (900001, 'compatibility test', 'In use', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")
        )
        for index in range(5):
            connection.execute(
                text(
                    "INSERT INTO hardware_asset_photos (asset_id, storage_filename, is_primary, sort_order, uploaded_at) "
                    "VALUES (900001, :filename, :is_primary, :sort_order, CURRENT_TIMESTAMP)"
                ),
                {"filename": f"compat-{index}.webp", "is_primary": index == 0, "sort_order": index},
            )
    with pytest.raises((IntegrityError, ProgrammingError)):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO hardware_asset_photos (asset_id, storage_filename, is_primary, sort_order, uploaded_at) "
                    "VALUES (900001, 'compat-over-limit.webp', FALSE, 6, CURRENT_TIMESTAMP)"
                )
            )
    indexes = {item["name"] for item in inspect(engine).get_indexes("hardware_asset_photos")}
    assert "uq_hardware_asset_photos_primary" in indexes


def test_postgresql_fresh_alembic_base_to_head():
    engine = _postgres_engine()
    _reset_postgres_schema(engine)
    result = prepare_database(engine, _settings(os.environ["KAYA_TEST_POSTGRES_URL"]))
    assert result.current_revision == "20261008_02"


def test_sqlite_migration_guard_rejects_non_disposable_target(tmp_path):
    with pytest.raises(AssertionError):
        _test_alembic_config("sqlite:///C:/app/data/kaya.db", tmp_path)
