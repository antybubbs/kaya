"""Recognise only the complete, explicit Phase 6 failed-target recovery CLI."""

from __future__ import annotations

import re
import sys


_MIGRATION_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SOURCE_FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")
_VALUE_OPTIONS = {"--source", "--target-url", "--backup-dir", "--data-dir", "--migration-id", "--source-fingerprint"}


def is_explicit_recovery_command(arguments: list[str]) -> bool:
    """Return true only for the complete argv shape used by operator recovery."""
    if arguments[:3] != ["python", "-m", "scripts.kaya_phase6_upgrade"]:
        return False

    values: dict[str, str] = {}
    clean_requested = False
    index = 3
    while index < len(arguments):
        option = arguments[index]
        if option == "--clean-failed-target":
            if clean_requested:
                return False
            clean_requested = True
            index += 1
            continue
        if option not in _VALUE_OPTIONS or option in values or index + 1 >= len(arguments):
            return False
        value = arguments[index + 1]
        if not value or value.startswith("-"):
            return False
        values[option] = value
        index += 2

    return (
        clean_requested
        and {"--source", "--backup-dir", "--data-dir", "--migration-id", "--source-fingerprint"} <= values.keys()
        and bool(_MIGRATION_ID.fullmatch(values["--migration-id"]))
        and bool(_SOURCE_FINGERPRINT.fullmatch(values["--source-fingerprint"]))
    )


if __name__ == "__main__":
    raise SystemExit(0 if is_explicit_recovery_command(sys.argv[1:]) else 1)
