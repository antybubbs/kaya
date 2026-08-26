from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import app.services.about as about


def _settings(database_url: str, tmp_path: Path):
    return SimpleNamespace(
        database_url=database_url,
        data_dir=str(tmp_path),
        upload_dir=str(tmp_path / "uploads"),
        postgres_backup_dir=str(tmp_path / "backups"),
        app_name="Kaya",
        app_env="test",
        github_repo="example/kaya",
    )


def test_storage_rows_uses_postgresql_database_size_when_supplied(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(about, "get_settings", lambda: _settings("postgresql+psycopg://kaya@db/kaya", tmp_path))

    rows = about.storage_rows(2 * 1024**3)

    assert rows[0] == {"label": "Database", "size": "2.0 GiB"}


def test_storage_rows_keeps_sqlite_file_size_path(tmp_path: Path, monkeypatch):
    database = tmp_path / "kaya.db"
    database.write_bytes(b"sqlite fixture")
    monkeypatch.setattr(about, "get_settings", lambda: _settings(f"sqlite:///{database.as_posix()}", tmp_path))

    assert about.storage_rows()[0] == {"label": "Database", "size": "14 B"}


def test_collect_about_reuses_one_postgresql_size_for_both_storage_surfaces(tmp_path: Path, monkeypatch):
    settings = _settings("postgresql+psycopg://kaya@db/kaya", tmp_path)
    captured: list[int | None] = []
    diagnostics = {"available": True, "database_bytes": 645 * 1024**2}
    monkeypatch.setattr(about, "get_settings", lambda: settings)
    monkeypatch.setattr(about, "database_identity", lambda: {"engine": "PostgreSQL"})
    monkeypatch.setattr(about, "version_status", lambda: {})
    monkeypatch.setattr(about, "package_versions", lambda: [])
    monkeypatch.setattr(about, "module_counts", lambda _db: [])
    monkeypatch.setattr(about, "collect_postgres_diagnostics", lambda *_args: diagnostics)
    monkeypatch.setattr(about, "disk_info", lambda _path: {})
    monkeypatch.setattr(about, "memory_info", lambda: {})
    monkeypatch.setattr(about, "cpu_info", lambda: {})
    monkeypatch.setattr(about, "storage_rows", lambda size=None: captured.append(size) or [{"label": "Database", "size": about.human_bytes(size or 0)}])

    result = about.collect_about(object())

    assert captured == [diagnostics["database_bytes"]]
    assert result["storage_rows"][0]["size"] == "645.0 MiB"
    assert result["postgres_diagnostics"] is diagnostics


def test_collect_about_uses_unavailable_fallback_when_postgresql_size_lookup_fails(tmp_path: Path, monkeypatch):
    settings = _settings("postgresql+psycopg://kaya@db/kaya", tmp_path)
    monkeypatch.setattr(about, "get_settings", lambda: settings)
    monkeypatch.setattr(about, "database_identity", lambda: {"engine": "PostgreSQL"})
    monkeypatch.setattr(about, "version_status", lambda: {})
    monkeypatch.setattr(about, "package_versions", lambda: [])
    monkeypatch.setattr(about, "module_counts", lambda _db: [])
    monkeypatch.setattr(about, "collect_postgres_diagnostics", lambda *_args: (_ for _ in ()).throw(RuntimeError("synthetic lookup failure")))
    monkeypatch.setattr(about, "disk_info", lambda _path: {})
    monkeypatch.setattr(about, "memory_info", lambda: {})
    monkeypatch.setattr(about, "cpu_info", lambda: {})

    result = about.collect_about(object())

    assert result["storage_rows"][0] == {"label": "Database", "size": "unavailable"}
    assert result["postgres_diagnostics"]["available"] is False
