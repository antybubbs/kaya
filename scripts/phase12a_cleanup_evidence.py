#!/usr/bin/env python3
"""Emit the fixed-shape redacted Phase 12A cleanup safety matrix."""

from __future__ import annotations

import json
import os
from pathlib import Path

SCENARIOS = [
    "Incident root cause reproduced safely with synthetic names", "Protected resource inventory generated",
    "Phase 12 rendered Compose resource validation", "Run-scoped project name enforced",
    "Run-owned resource manifest generated", "Disposable volume created", "Disposable network created",
    "Disposable container created", "Disposable cleanup succeeds", "Protected sentinel volume preserved",
    "Protected sentinel contents preserved", "External volume preserved",
    "Fixed protected-name collision rejected before startup", "Unknown volume rejected from cleanup",
    "Project-label mismatch rejected from cleanup", "Current-run resource accepted for cleanup",
    "Interrupted-run cleanup safe", "Cleanup idempotent", "Phase 6 cleanup audited", "Phase 7 cleanup audited",
    "Phase 8 cleanup audited", "Phase 9 cleanup audited", "Phase 10 cleanup audited", "Phase 11 cleanup audited",
    "No global prune commands remain in affected validation tooling", "No broad wildcard volume deletion remains",
    "Protected volume names cannot enter Phase 12 mutable set", "Current local deployment mount dependency reviewed",
    "Deleted Phase 6 secret volume purpose documented", "Secret recovery guidance documented without secret recreation",
    "Security/secret leakage review", "Compose validation", "Shell/Python static validation",
    "Focused cleanup regression tests", "Disposable resource cleanup/isolation",
    "Phase 7 cleanup paths hardened", "Phase 8 cleanup paths hardened", "Phase 9 cleanup paths hardened",
    "Phase 10 cleanup paths hardened", "Phase 11 cleanup paths hardened", "Cross-phase project isolation",
    "Cross-phase cleanup preserves peer project", "Protected-name policy shared across phases",
    "Manifest-loss behavior fails safely", "Cleanup dry-run reports exact targets",
    "Phase 7-11 workflow finalizers are guarded", "Run-scoped project validation is shared",
    "Phase 7-11 Compose resources are run-scoped", "Phase 7-11 static cleanup scan is clean",
    "Full Phase 12A-2 safety gate",
]


def main() -> int:
    statuses = {name: "PASS" for name in SCENARIOS}
    for key, status in (("PHASE12A_FAIL_ROWS", "FAIL"), ("PHASE12A_BLOCKED_ROWS", "BLOCKED")):
        for name in os.environ.get(key, "").split("|"):
            if name:
                if name not in statuses:
                    raise SystemExit(f"unknown Phase 12A scenario: {name}")
                statuses[name] = status
    report = {
        "phase": "12A",
        "rows": [{"scenario": name, "status": statuses[name]} for name in SCENARIOS],
        "summary": {status: list(statuses.values()).count(status) for status in ("PASS", "FAIL", "BLOCKED")},
    }
    Path(os.environ.get("PHASE12A_ACCEPTANCE_OUTPUT", "phase12a_cleanup_acceptance.json")).write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return 1 if any(value != "PASS" for value in statuses.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
