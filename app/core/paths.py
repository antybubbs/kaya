"""Stable filesystem locations derived from the installed Kaya package."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "app"
STATIC_DIR = PACKAGE_ROOT / "static"
TEMPLATE_DIR = PACKAGE_ROOT / "templates"
SCRIPT_DIR = PROJECT_ROOT / "scripts"

# These defaults are part of Kaya's existing container volume contract.
DEFAULT_DATA_DIR = Path("/app/data")
DEFAULT_UPLOAD_DIR = Path("/app/uploads")
DEFAULT_RECORDING_DIR = DEFAULT_DATA_DIR / "remote-recordings"

