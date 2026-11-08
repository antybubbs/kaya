#!/usr/bin/env python3
"""Read-only preflight for one step of the DHCP protocol rollout runbook (PROPOSAL).

    KAYA_HA_REPORT_DATABASE_URL=... python scripts/ha_dhcp_preflight.py --step agent_rollout|agent_rollback|kaya_rollback [--cluster PUBLIC_ID]

Opens the database read-only (as scripts/ha_invariant_report.py does), contacts no node, changes
nothing and never prints the database URL.  Exit code 0 = safe for that step, 1 = blocked (the
blockers are listed), 2 = usage or database error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only DHCP protocol rollout preflight.")
    parser.add_argument("--step", required=True, choices=("agent_rollout", "agent_rollback", "kaya_rollback"))
    parser.add_argument("--cluster", help="cluster public id (default: every Pi-hole cluster)")
    args = parser.parse_args()
    url = os.environ.get("KAYA_HA_REPORT_DATABASE_URL")
    if not url:
        print("Set KAYA_HA_REPORT_DATABASE_URL (kept out of process arguments).", file=sys.stderr)
        return 2
    from sqlalchemy.orm import Session

    from app.models.models import HACluster
    from app.services.ha_dhcp_preflight import preflight
    from scripts.ha_invariant_report import read_only_engine

    try:
        engine = read_only_engine(url)
        with Session(engine) as db:
            query = db.query(HACluster).filter(HACluster.deleted_at.is_(None), HACluster.provider_key == "pihole")
            if args.cluster:
                query = query.filter(HACluster.public_id == args.cluster)
            results = [{"cluster": cluster.name, **preflight(cluster, args.step)} for cluster in query.all()]
            db.rollback()
    except Exception as exc:  # report the failure class only: never a URL or credential
        print(f"Preflight could not read the database ({type(exc).__name__}).", file=sys.stderr)
        return 2
    print(json.dumps(results, indent=2, default=str))
    return 0 if results and all(result["safe"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
