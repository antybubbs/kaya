"""Recognise only the complete, explicit Phase 6 failed-target recovery CLI."""

from __future__ import annotations

import re
import sys


_MIGRATION_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SOURCE_FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")
_VALUE_OPTIONS = {"--source", "--target-url", "--backup-dir", "--data-dir", "--migration-id", "--source-fingerprint"}
_PRETARGET_OPTION = "--retry-failed-pretarget"
_PHASE6_PREFIX = ["python", "-m", "scripts.kaya_phase6_upgrade"]


def _parse_phase6_arguments(arguments: list[str]) -> tuple[dict[str, str], bool, bool] | None:
    if arguments[:3] != _PHASE6_PREFIX:
        return None
    values: dict[str, str] = {}
    clean_requested = False
    pretarget_requested = False
    index = 3
    while index < len(arguments):
        option = arguments[index]
        if option == "--clean-failed-target":
            if clean_requested:
                return None
            clean_requested = True
            index += 1
            continue
        if option == _PRETARGET_OPTION:
            if pretarget_requested:
                return None
            pretarget_requested = True
            index += 1
            continue
        if option not in _VALUE_OPTIONS or option in values or index + 1 >= len(arguments):
            return None
        value = arguments[index + 1]
        if not value or value.startswith("-"):
            return None
        values[option] = value
        index += 2
    return values, clean_requested, pretarget_requested


def is_phase6_upgrade_command(arguments: list[str]) -> bool:
    """Recognise only the standard, non-recovery Phase 6 upgrade CLI."""
    parsed = _parse_phase6_arguments(arguments)
    if parsed is None:
        return False
    values, clean_requested, _ = parsed
    return (
        not clean_requested
        and {"--source", "--backup-dir", "--data-dir"} <= values.keys()
        and "--migration-id" not in values
        and "--source-fingerprint" not in values
    )


def is_phase6_pretarget_retry_command(arguments: list[str]) -> bool:
    """Recognise the explicit pre-target FAILED retry CLI."""
    parsed = _parse_phase6_arguments(arguments)
    if parsed is None:
        return False
    values, clean_requested, pretarget_requested = parsed
    return (
        not clean_requested
        and pretarget_requested
        and {"--source", "--backup-dir", "--data-dir"} <= values.keys()
        and "--migration-id" not in values
        and "--source-fingerprint" not in values
    )


def is_explicit_recovery_command(arguments: list[str]) -> bool:
    """Return true only for the complete argv shape used by operator recovery."""
    parsed = _parse_phase6_arguments(arguments)
    if parsed is None:
        return False
    values, clean_requested, pretarget_requested = parsed
    return (
        clean_requested
        and not pretarget_requested
        and {"--source", "--backup-dir", "--data-dir", "--migration-id", "--source-fingerprint"} <= values.keys()
        and bool(_MIGRATION_ID.fullmatch(values["--migration-id"]))
        and bool(_SOURCE_FINGERPRINT.fullmatch(values["--source-fingerprint"]))
    )


if __name__ == "__main__":
    raise SystemExit(0 if is_explicit_recovery_command(sys.argv[1:]) else 1)
