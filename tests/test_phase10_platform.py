from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.db.platform_compatibility import (
    DatabasePlatformCompatibilityError,
    migration_graph,
    postgres_server_version,
    validate_postgres_platform,
)


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return [self.value] if self.value is not None else []


class _Connection:
    def __init__(self, values, revisions=()):
        self.values = iter(values)
        self.revisions = revisions

    def execute(self, statement):
        sql = str(statement)
        if "server_version_num" in sql:
            return _Result(next(self.values))
        if "server_version" in sql:
            return _Result(next(self.values))
        if "version_num" in sql:
            return _Result(self.revisions[0] if self.revisions else None)
        return _Result(None)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Engine:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self, values, revisions=()):
        self.connection = _Connection(values, revisions)

    def connect(self):
        return self.connection


def _script():
    config = Config("alembic.ini")
    config.set_main_option("script_location", str(Path("migrations").resolve()))
    return ScriptDirectory.from_config(config)


def test_migration_graph_has_one_complete_head():
    graph = migration_graph(_script())
    assert graph["head_count"] == 1
    assert graph["missing_down_revisions"] == []
    assert graph["duplicate_revision_ids"] == []


def test_postgres_server_version_uses_server_queries():
    version = postgres_server_version(_Engine(("16.14", "160014")))
    assert version.major == 16
    assert version.server_version_num == 160014


def test_schema_revision_missing_from_packaged_chain_fails_closed():
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("app.db.platform_compatibility.inspect", lambda _connection: SimpleNamespace(get_table_names=lambda: ["alembic_version"]))
    with pytest.raises(DatabasePlatformCompatibilityError, match="not present"):
        validate_postgres_platform(_Engine(("16.14", "160014"), ("missing_revision",)), _script())
    monkeypatch.undo()


def test_schema_newer_than_application_fails_closed(monkeypatch):
    script = _script()
    monkeypatch.setattr(script, "iterate_revisions", lambda *_args, **_kwargs: iter([]))
    monkeypatch.setattr("app.db.platform_compatibility.inspect", lambda _connection: SimpleNamespace(get_table_names=lambda: ["alembic_version"]))
    with pytest.raises(DatabasePlatformCompatibilityError, match="newer"):
        validate_postgres_platform(_Engine(("16.14", "160014"), ("future",)), script)
