"""Docker-only post-preflight managed SQLite temp exhaustion regression."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


@pytest.mark.skipif(
    not os.environ.get("KAYA_SQLITE_TEMP_EXHAUSTION_INTEGRATION"),
    reason="run explicitly in the constrained managed-temp Docker environment",
)
def test_managed_temp_exhaustion_fails_safely_and_retries() -> None:
    root = os.environ.get("KAYA_SQLITE_TEMP_EXHAUSTION_ROOT")
    managed_temp = os.environ.get("KAYA_SQLITE_TEMP_EXHAUSTION_PATH")
    if not root or not managed_temp:
        pytest.fail("KAYA_SQLITE_TEMP_EXHAUSTION_ROOT and _PATH are required")
    result = subprocess.run(
        [
            sys.executable,
            "scripts/sqlite_temp_exhaustion_harness.py",
            "--root",
            root,
            "--managed-temp",
            managed_temp,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["preflight"] == "PASS"
    assert evidence["sqlite_loaded_before_import"] is False
    assert evidence["managed_activity_observed"] is True
    assert evidence["filler_started_after_activity"] is True
    assert evidence["failure"]
    assert evidence["tmp_fd_targets"] == []
    assert evidence["source_fingerprint_unchanged"] is True
    assert evidence["quick_check"] == "ok"
    assert evidence["foreign_key_errors"] == 0
    assert evidence["retry_succeeded"] is True
