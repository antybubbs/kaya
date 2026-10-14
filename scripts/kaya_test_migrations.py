"""Run Alembic only against an explicitly verified disposable database.

This helper is intentionally stricter than the application's normal migration
configuration. It prevents a local test command from falling back to the
hard-coded container database in alembic.ini.
"""
from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


_TEST_NAME = re.compile(r"(?:^|[-_])(test|pytest|kaya-test)(?:[-_]|$)", re.I)
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def verify_disposable_url(database_url: str) -> None:
    """Reject URLs that could address application or non-local data."""
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        if not url.database:
            raise ValueError("A disposable SQLite file is required.")
        database = Path(url.database).expanduser().resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        if not _under(database, temp_root) or _under(database, _REPO_ROOT):
            raise ValueError("SQLite migration targets must be inside the system temp directory.")
        if not _TEST_NAME.search(database.stem):
            raise ValueError("SQLite migration targets must have a test-only filename.")
        return
    if url.get_backend_name() in {"postgresql", "postgres"}:
        host = (url.host or "").lower()
        if host not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("PostgreSQL migration targets must use the local host.")
        if not url.database or not _TEST_NAME.search(url.database):
            raise ValueError("PostgreSQL migration targets must use a test-only database name.")
        return
    raise ValueError("Only local disposable SQLite or PostgreSQL targets are supported.")


def _verify_connected_target(engine, database_url: str) -> None:
    url = make_url(database_url)
    with engine.connect() as connection:
        if url.get_backend_name() == "sqlite":
            actual = Path(connection.execute(text("PRAGMA database_list")).first().file).resolve()
            expected = Path(url.database).expanduser().resolve()
            if actual != expected:
                raise RuntimeError("Connected SQLite database does not match the requested target.")
        else:
            row = connection.execute(
                text("SELECT current_database(), inet_server_addr()::text")
            ).one()
            server_address = (row[1] or "").split("/", 1)[0]
            allowed_addresses = {"", "127.0.0.1", "::1"}
            if os.environ.get("KAYA_TEST_POSTGRES_CONTAINER") == "1":
                expected_container_address = os.environ.get("KAYA_TEST_POSTGRES_SERVER_ADDR")
                if not expected_container_address:
                    raise RuntimeError("Container PostgreSQL validation requires an expected server address.")
                allowed_addresses.add(expected_container_address)
            if row[0] != url.database or server_address not in allowed_addresses:
                raise RuntimeError("Connected PostgreSQL database does not match the requested target.")


def run_migration(database_url: str, operation: str, revision: str) -> None:
    verify_disposable_url(database_url)
    previous_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = database_url
    try:
        engine = create_engine(database_url, future=True)
        try:
            _verify_connected_target(engine, database_url)
            config = Config(str(_REPO_ROOT / "alembic.ini"))
            config.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
            config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
            getattr(command, operation)(config, revision)
        finally:
            engine.dispose()
    finally:
        if previous_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_url


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("upgrade", "downgrade"))
    parser.add_argument("revision")
    parser.add_argument("--url", default=os.environ.get("KAYA_TEST_DATABASE_URL"))
    args = parser.parse_args()
    if not args.url:
        parser.error("--url or KAYA_TEST_DATABASE_URL is required")
    run_migration(args.url, args.operation, args.revision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
