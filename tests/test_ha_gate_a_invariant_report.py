"""Gate A: the read-only HA invariant report.

Proves the report flags the incident topology, never writes, and refuses
writes at the database level.  Synthetic data only.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import HACluster
from ha_simulation import hal_like_cluster

SPEC = importlib.util.spec_from_file_location("ha_invariant_report", Path("scripts/ha_invariant_report.py"))
report = importlib.util.module_from_spec(SPEC)
sys.modules["ha_invariant_report"] = report  # dataclasses resolve their module
SPEC.loader.exec_module(report)
POSTGRES_URL = os.environ.get("KAYA_TEST_POSTGRES_URL")


def incident_database(path: Path, *, stale_previous_state: bool = False) -> str:
    url = f"sqlite:///{path.as_posix()}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    sim = hal_like_cluster(db)
    sim.report_both(2)
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_one)
    sim.report(sim.sim_two)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(2)
    if stale_previous_state:
        from app.models.models import HAMaintenanceRun

        db.add(HAMaintenanceRun(cluster_id=sim.cluster.id, operation="REINITIALISE", status="FAILED_SAFE", phase="PAUSED",
                                previous_state_json=json.dumps({"automatic_failover_enabled": True})))
        db.commit()
    db.close()
    engine.dispose()
    return url


def checks_by_code(result: dict) -> dict:
    return {check["code"]: check["status"] for check in result["checks"]}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_report_flags_the_incident_topology_without_changing_the_database(tmp_path, monkeypatch, capsys):
    path = tmp_path / "synthetic-ha.db"
    url = incident_database(path, stale_previous_state=True)
    before = digest(path)
    monkeypatch.setenv("KAYA_HA_REPORT_DATABASE_URL", url)
    code = report.main(["--json"])
    output = capsys.readouterr().out
    assert code == 1
    assert url not in output and str(path) not in output
    [result] = json.loads(output)
    checks = checks_by_code(result)
    assert result["observed"] == {"vip_owners": ["SimPiHole2"], "dhcp_owners": ["SimPiHole1"], "fresh_nodes": ["SimPiHole1", "SimPiHole2"]}
    assert checks["I1_SINGLE_DHCP_SERVER"] == "PASS"
    assert checks["I2_SINGLE_VIP_OWNER"] == "PASS"
    assert checks["I3_VIP_DHCP_ALIGNED"] == "FAIL"
    assert checks["STORED_ACTIVE_MATCHES_SERVICE_OWNER"] == "PASS"  # D1 fixed in P4: the assignment stays with the DHCP owner
    assert checks["AUTHORITY_MATCHES_SERVICE_OWNER"] == "PASS"
    assert checks["D7_STALE_PREVIOUS_STATE_HAZARD"] == "WARN"
    assert "D2_DHCP_OWNER_IN_STANDBY_RECOVERY" not in checks  # D2 fixed in P4: an ownership conflict, not recovery
    assert digest(path) == before


def test_report_issues_only_reads(tmp_path):
    url = incident_database(tmp_path / "synthetic-ha.db")
    engine = report.read_only_engine(url)
    statements = []
    event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, *args: statements.append(statement.lstrip().split()[0].upper()))
    with Session(engine) as session:
        report.build_report(session)
    engine.dispose()
    assert statements and set(statements) <= {"SELECT", "PRAGMA"}


def test_sqlite_report_engine_refuses_writes(tmp_path):
    url = incident_database(tmp_path / "synthetic-ha.db")
    engine = report.read_only_engine(url)
    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.execute(text("UPDATE ha_clusters SET status='HEALTHY'"))
    engine.dispose()


def test_report_requires_an_explicit_database(monkeypatch, capsys):
    monkeypatch.delenv("KAYA_HA_REPORT_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit):
        report.main([])
    with pytest.raises(SystemExit):
        report.main(["--url", "sqlite:///:memory:"])
    capsys.readouterr()


@pytest.mark.skipif(not POSTGRES_URL, reason="KAYA_TEST_POSTGRES_URL is not configured")
def test_postgres_report_engine_refuses_writes_and_reports_one_cluster():
    writer = create_engine(POSTGRES_URL)
    db = Session(writer, expire_on_commit=False)
    sim = hal_like_cluster(db, suffix=uuid4().hex[:8])
    sim.report_both(2)
    cluster_id = sim.cluster.public_id
    db.close()
    engine = report.read_only_engine(POSTGRES_URL)
    try:
        with Session(engine) as session:
            [result] = report.build_report(session, cluster_public_id=cluster_id)
        assert checks_by_code(result)["I3_VIP_DHCP_ALIGNED"] == "PASS"
        with pytest.raises(DBAPIError, match="read-only"):
            with engine.begin() as connection:
                connection.execute(text("UPDATE ha_clusters SET status='ERROR' WHERE public_id=:id"), {"id": cluster_id})
    finally:
        engine.dispose()
        with Session(writer) as cleanup:
            cleanup.delete(cleanup.query(HACluster).filter(HACluster.public_id == cluster_id).one())
            cleanup.commit()
        writer.dispose()
