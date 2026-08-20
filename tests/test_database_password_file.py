from __future__ import annotations

import pytest

from app.core import config


@pytest.mark.parametrize("contents", ["", "   \n", "\t\n"])
def test_database_password_file_rejects_empty_or_whitespace(tmp_path, monkeypatch, contents):
    password_file = tmp_path / "postgres-password"
    password_file.write_text(contents, encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://kaya@db.invalid/kaya")
    monkeypatch.setenv("DATABASE_PASSWORD_FILE", str(password_file))
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    config.get_settings.cache_clear()
    try:
        with pytest.raises(config.InvalidConfigurationError, match="DATABASE_PASSWORD_FILE is empty"):
            config.get_settings()
    finally:
        config.get_settings.cache_clear()


def test_database_password_file_rejects_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://kaya@db.invalid/kaya")
    monkeypatch.setenv("DATABASE_PASSWORD_FILE", str(tmp_path / "missing"))
    config.get_settings.cache_clear()
    try:
        with pytest.raises(config.InvalidConfigurationError, match="DATABASE_PASSWORD_FILE could not be read"):
            config.get_settings()
    finally:
        config.get_settings.cache_clear()


def test_database_password_file_rejects_unreadable_file(tmp_path, monkeypatch):
    password_file = tmp_path / "postgres-password"
    password_file.write_text("fake-password\n", encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://kaya@db.invalid/kaya")
    monkeypatch.setenv("DATABASE_PASSWORD_FILE", str(password_file))

    original_read_text = config.Path.read_text

    def denied_read_text(path, *args, **kwargs):
        if path == password_file:
            raise PermissionError("synthetic unreadable password file")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(config.Path, "read_text", denied_read_text)
    config.get_settings.cache_clear()
    try:
        with pytest.raises(config.InvalidConfigurationError, match="DATABASE_PASSWORD_FILE could not be read"):
            config.get_settings()
    finally:
        config.get_settings.cache_clear()


def test_database_password_file_reads_password_without_logging_or_exposing_it(tmp_path, monkeypatch):
    password_file = tmp_path / "postgres-password"
    password_file.write_text("fake-password\n", encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://kaya@db.invalid/kaya")
    monkeypatch.setenv("DATABASE_PASSWORD_FILE", str(password_file))
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    config.get_settings.cache_clear()
    try:
        settings = config.get_settings()
        assert settings.database_url == "postgresql+psycopg://kaya:fake-password@db.invalid/kaya"
    finally:
        config.get_settings.cache_clear()
