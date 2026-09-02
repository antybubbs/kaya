"""Emit the non-sensitive Alembic graph contract for CI and release checks."""

from __future__ import annotations

import json
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from app.db.platform_compatibility import migration_graph


def main() -> int:
    config = Config("alembic.ini")
    config.set_main_option("script_location", str(Path("migrations").resolve()))
    graph = migration_graph(ScriptDirectory.from_config(config))
    Path("phase10_migration_graph.json").write_text(
        json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if graph["head_count"] != 1 or graph["missing_down_revisions"] or graph["duplicate_revision_ids"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
