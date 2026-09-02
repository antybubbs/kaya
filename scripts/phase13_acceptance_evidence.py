#!/usr/bin/env python3
"""Fail-closed Phase 13 production-readiness acceptance ledger."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

SCENARIOS = {
1:'Fresh production install',2:'Fresh PostgreSQL role topology',3:'Fresh authenticated read/write',4:'Fresh workers start after database preparation',5:'Fresh restart preserves state',6:'Fresh secrets persist safely',7:'SQLite-era production fixture created',8:'SQLite source backup verified',9:'SQLite production upgrade succeeds',10:'SQLite data preserved',11:'SQLite retained source unchanged',12:'No SQLite fallback after cutover',13:'Legacy PostgreSQL production fixture created',14:'Legacy PG pre-role backup verified',15:'Legacy PG role migration succeeds',16:'Legacy PG data preserved',17:'Current PG upgrade is no-op/idempotent',18:'Previous-version image upgrade succeeds',19:'PostgreSQL 16.13 to 16.14 production cycle succeeds',20:'Production scheduled backup works',21:'Documented manual backup works',22:'Documented restore works',23:'Restored Kaya authenticated read/write',24:'Lost-PGDATA recovery succeeds',25:'Bootstrap-secret recovery procedure validated',26:'Application-secret recovery procedure reviewed/validated',27:'PostgreSQL unavailable fails boundedly',28:'Wrong DB credential fails safely',29:'Missing DB secret fails safely',30:'Unsupported PostgreSQL major rejected',31:'Unsupported schema revision rejected',32:'Backup failure prevents destructive upgrade',33:'Interrupted upgrade recovers safely',34:'Disk-pressure failure handled safely',35:'Workers start only after DB preparation',36:'Runtime HTTP DB identity is kaya',37:'Runtime worker DB identity is kaya',38:'Bootstrap role excluded from runtime',39:'Production DB diagnostics correct',40:'No credential leakage in runtime logs/evidence',41:'PostgreSQL not publicly exposed by default',42:'Production healthchecks correct',43:'Restart policy safe/idempotent',44:'Install documentation verified',45:'Upgrade documentation verified',46:'Rollback/recovery boundary documented',47:'Release workflow includes required PG artifacts',48:'Production smoke suite passes',49:'Phase 12 regression remains 63/63',50:'Cleanup/isolation'}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', default='phase13_acceptance.json')
    p.add_argument('--scenario', type=int)
    p.add_argument('--status', choices=('PASS', 'FAIL', 'BLOCKED'))
    p.add_argument('--evidence', default='')
    a = p.parse_args()
    if set(SCENARIOS) != set(range(1, 51)):
        raise SystemExit('invalid registry')
    path = Path(a.output)
    rows = {str(i): {'id': i, 'name': n, 'status': 'BLOCKED', 'evidence': ''} for i, n in SCENARIOS.items()}
    if path.exists():
        old = json.loads(path.read_text(encoding='utf-8'))
        rows.update({str(r['id']): r for r in old.get('rows', []) if int(r.get('id', 0)) in SCENARIOS})
    if a.scenario is not None:
        if a.status is None or a.scenario not in SCENARIOS:
            raise SystemExit('scenario/status required')
        rows[str(a.scenario)] = {'id': a.scenario, 'name': SCENARIOS[a.scenario], 'status': a.status, 'evidence': a.evidence}
    ordered = [rows[str(i)] for i in range(1, 51)]
    counts = {s: sum(r['status'] == s for r in ordered) for s in ('PASS', 'FAIL', 'BLOCKED')}
    doc = {'phase': '13', 'rows': ordered, 'summary': counts, 'status': 'PASS' if counts == {'PASS': 50, 'FAIL': 0, 'BLOCKED': 0} else 'INCOMPLETE'}
    path.write_text(json.dumps(doc, indent=2) + '\n', encoding='utf-8')
    return 0 if doc['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
