from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def migration_script() -> ScriptDirectory:
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[1] / "migrations")
    )
    return ScriptDirectory.from_config(config)


def test_repository_has_one_alembic_head_and_merge_preserves_both_branches():
    script = migration_script()
    assert len(script.get_heads()) == 1
    assert script.get_heads() == ["20260818_01"]
    merge = script.get_revision("20260810_02")
    assert set(merge.down_revision) == {"20260804_03", "20260810_01"}
