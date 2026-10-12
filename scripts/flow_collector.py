#!/usr/bin/env python3
"""Run Kaya's optional NetFlow v9/Cisco NSEL collector process."""

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.flow_collector import main


if __name__ == "__main__":
    main()
