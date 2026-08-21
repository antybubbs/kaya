from pathlib import Path

import pytest

from app.core import config
from app.db.phase6_test_hooks import (
    Phase6TestFailpointError,
    hit,
    record,
    validate_configuration,
)


def test_unknown_failpoint_fails_closed(monkeypatch):
    monkeypatch.setenv("KAYA_TEST_MODE", "true")
    monkeypatch.setenv("KAYA_TEST_FAILPOINT", "arbitrary-code")

    with pytest.raises(RuntimeError, match="Unknown Phase 6 test failpoint"):
        validate_configuration()


def test_failpoint_requires_explicit_test_mode(monkeypatch):
    monkeypatch.delenv("KAYA_TEST_MODE", raising=False)
    monkeypatch.setenv("KAYA_TEST_FAILPOINT", "fail_during_copy")

    with pytest.raises(RuntimeError, match="KAYA_TEST_MODE=true"):
        validate_configuration()


def test_failure_failpoint_is_predefined_and_controlled(monkeypatch):
    monkeypatch.setenv("KAYA_TEST_MODE", "true")
    monkeypatch.setenv("KAYA_TEST_FAILPOINT", "fail_during_copy")

    with pytest.raises(Phase6TestFailpointError, match="fail_during_copy"):
        hit("fail_during_copy")


def test_observability_contains_no_row_data(tmp_path: Path, monkeypatch):
    destination = tmp_path / "events.jsonl"
    monkeypatch.setenv("KAYA_TEST_MODE", "true")
    monkeypatch.setenv("KAYA_TEST_OBSERVABILITY_FILE", str(destination))

    record("sqlite.source_capture", fingerprint="a" * 64)

    contents = destination.read_text(encoding="utf-8")
    assert "sqlite.source_capture" in contents
    assert "a" * 64 in contents
    assert "row" not in contents.lower()


def test_database_identity_observation_is_redacted_and_test_only(tmp_path: Path, monkeypatch):
    destination = tmp_path / "observability.jsonl"
    monkeypatch.setenv("KAYA_TEST_MODE", "true")
    monkeypatch.setenv("KAYA_TEST_OBSERVABILITY_FILE", str(destination))

    from app.db.phase6_test_hooks import database_identity

    database_identity("http_request", "kaya")
    contents = destination.read_text(encoding="utf-8")
    assert '"event": "phase12.db.identity"' in contents
    assert '"database_role": "kaya"' in contents


def test_production_configuration_rejects_failpoint(monkeypatch):
    config.get_settings.cache_clear()
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("KAYA_TEST_FAILPOINT", "fail_during_copy")
    monkeypatch.setenv("SECRET_KEY", "synthetic-phase6-test-secret-key-012345678901234567")
    monkeypatch.setenv("ENCRYPTION_KEY", "3mJ8d5fTzqf5O8hF7rN2bQx1cV9yL4uK7sP0wE6aI2o=")

    with pytest.raises(config.InvalidConfigurationError, match="unavailable in production"):
        config.get_settings()
    config.get_settings.cache_clear()
