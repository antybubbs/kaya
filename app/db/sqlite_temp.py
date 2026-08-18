from __future__ import annotations

import os
import tempfile
from pathlib import Path


SQLITE_TEMP_DIRECTORY_NAME = "sqlite-tmp"


def configure_sqlite_temp_directory(database_path: Path) -> Path:
    database_directory = database_path.resolve().parent
    database_directory.mkdir(parents=True, exist_ok=True)
    temp_directory = database_directory / SQLITE_TEMP_DIRECTORY_NAME
    temp_directory.mkdir(mode=0o700, exist_ok=True)
    temp_directory.chmod(0o700)
    if not temp_directory.is_dir():
        raise RuntimeError(f"SQLite temp path is not a directory: {temp_directory}")
    if os.stat(database_directory).st_dev != os.stat(temp_directory).st_dev:
        raise RuntimeError("SQLite temp directory must share the database filesystem")
    try:
        with tempfile.NamedTemporaryFile(
            dir=temp_directory, prefix=".kaya-write-check-", delete=False
        ) as probe:
            probe.write(b"kaya sqlite temp workspace check\n")
            probe_path = Path(probe.name)
        probe_path.unlink()
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            f"SQLite temp directory is not writable: {temp_directory}"
        ) from exc
    os.environ["SQLITE_TMPDIR"] = str(temp_directory)
    return temp_directory
