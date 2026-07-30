from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.formatting import human_bytes
from app.core.paths import PACKAGE_ROOT, PROJECT_ROOT, SCRIPT_DIR, STATIC_DIR, TEMPLATE_DIR
from app.core.templating import templates


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "unknown"),
        (0, "0 B"),
        (999, "999 B"),
        (1000, "1000 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (1024**2, "1.0 MiB"),
        (1024**3, "1.0 GiB"),
        (-1024, "-1.0 KiB"),
    ],
)
def test_human_bytes_boundaries(value, expected):
    assert human_bytes(value) == expected


def test_human_bytes_allows_context_specific_unknown_label():
    assert human_bytes(None, unknown="-") == "-"


def test_resource_paths_do_not_depend_on_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert PROJECT_ROOT.is_absolute()
    assert PACKAGE_ROOT == PROJECT_ROOT / "app"
    assert STATIC_DIR.is_dir()
    assert TEMPLATE_DIR.is_dir()
    assert SCRIPT_DIR.is_dir()
    assert templates.get_template("base.html").name == "base.html"


def test_container_path_defaults_preserve_existing_volume_contract():
    settings = Settings(
        app_env="test",
        encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    )

    assert Path(settings.data_dir) == Path("/app/data")
    assert Path(settings.upload_dir) == Path("/app/uploads")
    assert Path(settings.recording_dir) == Path("/app/data/remote-recordings")
    assert settings.database_url == "sqlite:////app/data/kaya.db"
