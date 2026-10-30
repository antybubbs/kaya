"""Run Kaya with test-only SQL statement counting for Stage 2B acceptance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading

from sqlalchemy import event

from app.db.session import engine


_count = 0
_lock = threading.Lock()
_output = Path(os.environ["KAYA_STAGE2B_SQL_COUNT_FILE"]).resolve()


def _write_count() -> None:
    _output.write_text(json.dumps({"statements": _count}) + "\n", encoding="utf-8")


@event.listens_for(engine, "before_cursor_execute")
def _count_statement(*_args) -> None:
    global _count
    with _lock:
        _count += 1
        _write_count()


_write_count()

import uvicorn  # noqa: E402
from app.main import app  # noqa: E402


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ["KAYA_STAGE2B_PORT"]))
