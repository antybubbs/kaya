"""Container health check for the optional flow collector process."""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import datetime, timedelta

from app.db.session import SessionLocal
from app.models.models import TrafficFlowCollectorGlobalState
from app.services.flow_collector import collector_settings


def main() -> int:
    if not collector_settings()["enabled"]:
        return 1
    with SessionLocal() as db:
        state = db.get(TrafficFlowCollectorGlobalState, 1)
        if not state or state.listener_state != "running":
            return 1
        if not state.updated_at or datetime.utcnow() - state.updated_at > timedelta(seconds=15):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
