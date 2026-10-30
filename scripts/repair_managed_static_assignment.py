"""Audited one-off repair: make a managed static IP record an asset's current address.

For assets adopted before managed static precedence existed, where an earlier
DHCP-derived assignment stayed current. Every target is verified first; see
``repair_managed_static_assignment``. The default is a dry run inside a
read-only transaction that prints the plan as JSON and changes nothing.
``--execute`` applies the plan in one transaction with a forced audit record.

Example (dry run):
    python scripts/repair_managed_static_assignment.py --asset-id 20 \
        --asset-tag HAL-0020 --mac 02:00:00:00:00:01 --ip 192.0.2.148
"""
from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.models.models import User
from app.services.asset_identity import repair_managed_static_assignment


def main() -> int:
    parser = argparse.ArgumentParser(description="Repair one asset's managed static network assignment (dry run by default).")
    parser.add_argument("--asset-id", type=int, required=True, help="Database id of the hardware asset.")
    parser.add_argument("--asset-tag", required=True, help="Asset tag; must match --asset-id.")
    parser.add_argument("--mac", required=True, help="MAC confirmed for the asset and set on the static record.")
    parser.add_argument("--ip", required=True, help="Managed static IP address.")
    parser.add_argument("--ip-record-id", type=int, default=None, help="Optional IP/VLAN Manager record id to pin.")
    parser.add_argument("--actor-email", default=None, help="Optional active administrator to attribute the audit record to.")
    parser.add_argument("--execute", action="store_true", help="Apply the plan. Without it, nothing is changed.")
    args = parser.parse_args()
    if args.asset_id <= 0 or (args.ip_record_id is not None and args.ip_record_id <= 0):
        raise SystemExit("Identifiers must be positive integers.")
    settings = get_settings()
    connect_args = {}
    if settings.database_url.startswith("postgresql"):
        connect_args = {"options": "-c statement_timeout=15000 -c lock_timeout=5000"}
    engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        with factory() as db:
            if not args.execute and engine.dialect.name == "postgresql":
                db.connection().exec_driver_sql("SET TRANSACTION READ ONLY")
            actor = None
            if args.actor_email:
                actor = db.query(User).filter(User.email == args.actor_email.strip()[:255]).first()
                if actor is None:
                    raise SystemExit("The --actor-email account was not found.")
            result = repair_managed_static_assignment(
                db, asset_id=args.asset_id, asset_tag=args.asset_tag, mac=args.mac, address=args.ip,
                ip_address_id=args.ip_record_id, actor=actor, execute=args.execute,
            )
        print(json.dumps({"dry_run": not args.execute, **result}, indent=2, sort_keys=True))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, PermissionError, RuntimeError) as exc:
        print(f"Repair refused: {exc}", file=sys.stderr)
        raise SystemExit(2)
