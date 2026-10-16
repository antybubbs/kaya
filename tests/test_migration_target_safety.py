import importlib.util
from pathlib import Path

import pytest


_SPEC = importlib.util.spec_from_file_location(
    "kaya_test_migrations", Path(__file__).resolve().parents[1] / "scripts" / "kaya_test_migrations.py"
)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(_MODULE)


def test_disposable_sqlite_target_must_be_in_temp_and_test_named(tmp_path):
    good = tmp_path / "kaya-test-migrations.db"
    _MODULE.verify_disposable_url(f"sqlite:///{good.as_posix()}")
    with pytest.raises(ValueError):
        _MODULE.verify_disposable_url("sqlite:////app/data/kaya.db")


def test_postgresql_target_must_be_local_and_test_named():
    _MODULE.verify_disposable_url("postgresql://kaya_test@127.0.0.1/kaya_test")
    with pytest.raises(ValueError):
        _MODULE.verify_disposable_url("postgresql://user@db.example/kaya")
