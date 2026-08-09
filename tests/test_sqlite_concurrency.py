import asyncio
import sqlite3
import threading
from time import monotonic

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.db.session import (
    SQLITE_BUSY_TIMEOUT_MS,
    configure_sqlite_connection,
    verify_sqlite_pragmas,
)
from app.models.models import OIDCProvider, RemoteManagerSetting
from app.services import dns_collector, ha_watchdog, site_settings


def sqlite_engine(tmp_path):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'concurrency.sqlite3').as_posix()}",
        connect_args={
            "check_same_thread": False,
            "timeout": SQLITE_BUSY_TIMEOUT_MS / 1_000,
        },
    )
    event.listen(engine, "connect", configure_sqlite_connection)
    return engine


def test_required_sqlite_pragmas_are_applied_and_verified(tmp_path):
    engine = sqlite_engine(tmp_path)

    assert verify_sqlite_pragmas(engine) == {
        "journal_mode": "wal",
        "busy_timeout": SQLITE_BUSY_TIMEOUT_MS,
        "synchronous": 2,
        "foreign_keys": 1,
    }


def test_wal_readers_continue_while_an_uncommitted_writer_exists(tmp_path):
    engine = sqlite_engine(tmp_path)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE synthetic_contention (id INTEGER PRIMARY KEY, value TEXT)"
        )
        connection.exec_driver_sql(
            "INSERT INTO synthetic_contention(value) VALUES ('committed')"
        )

    writer = engine.connect()
    transaction = writer.begin()
    writer.exec_driver_sql(
        "INSERT INTO synthetic_contention(value) VALUES ('uncommitted')"
    )
    try:
        started = monotonic()
        with engine.connect() as reader:
            values = reader.exec_driver_sql(
                "SELECT value FROM synthetic_contention ORDER BY id"
            ).scalars().all()
        assert values == ["committed"]
        assert monotonic() - started < 1
    finally:
        transaction.rollback()
        writer.close()


def test_short_competing_write_waits_then_commits(tmp_path):
    engine = sqlite_engine(tmp_path)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE synthetic_writers (id INTEGER PRIMARY KEY, value TEXT)"
        )

    first = engine.connect()
    first_transaction = first.begin()
    first.exec_driver_sql("INSERT INTO synthetic_writers(value) VALUES ('first')")
    attempted = threading.Event()
    completed = threading.Event()
    errors = []

    def competing_write():
        attempted.set()
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "INSERT INTO synthetic_writers(value) VALUES ('second')"
                )
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            completed.set()

    contender = threading.Thread(target=competing_write)
    contender.start()
    assert attempted.wait(1)
    assert not completed.wait(0.1)
    first_transaction.commit()
    first.close()
    contender.join(2)

    assert completed.is_set()
    assert errors == []
    with engine.connect() as connection:
        assert connection.exec_driver_sql(
            "SELECT count(*) FROM synthetic_writers"
        ).scalar_one() == 2


def test_security_settings_cache_uses_last_known_good_on_transient_lock(
    tmp_path, monkeypatch
):
    engine = sqlite_engine(tmp_path)
    RemoteManagerSetting.__table__.create(engine)
    OIDCProvider.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    site_settings.invalidate_security_settings_cache()
    with factory() as db:
        db.add(
            RemoteManagerSetting(
                key="csp_frame_ancestors",
                value="none",
            )
        )
        db.commit()
        security, _ = site_settings.cached_security_context(db, max_age_seconds=0)
    assert security["csp_frame_ancestors"] == "none"

    def locked(_db):
        raise OperationalError("SELECT", {}, Exception("database is locked"))

    monkeypatch.setattr(site_settings, "load_security_settings", locked)
    site_settings.invalidate_security_settings_cache()
    with factory() as db:
        fallback, _ = site_settings.cached_security_context(db, max_age_seconds=0)

    assert fallback["csp_frame_ancestors"] == "none"


def test_dns_collection_loop_recovers_after_transient_database_lock(monkeypatch):
    calls = 0
    sleeps = 0

    def collection_pass():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database is locked")
        return 30

    async def bounded_sleep(_delay):
        nonlocal sleeps
        sleeps += 1
        if sleeps >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(dns_collector, "run_dns_collection_pass", collection_pass)
    monkeypatch.setattr(dns_collector.asyncio, "sleep", bounded_sleep)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(dns_collector.dns_collector_loop())
    assert calls == 2


def test_ha_watchdog_loop_recovers_after_transient_database_lock(monkeypatch):
    calls = 0
    sleeps = 0

    def watchdog_pass():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database is locked")
        return 10

    async def bounded_sleep(_delay):
        nonlocal sleeps
        sleeps += 1
        if sleeps >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(ha_watchdog, "run_ha_watchdog_pass", watchdog_pass)
    monkeypatch.setattr(ha_watchdog.asyncio, "sleep", bounded_sleep)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(ha_watchdog.ha_watchdog_loop())
    assert calls == 2
