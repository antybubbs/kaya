"""Unified, read-only HA health assessment.

Proves the assessment is read-only, deterministic, consistent across the
Overview, Reconcile and Diagnostics screens, links only to existing actions
that can succeed, never points the 4 November incident at Reinitialise, and
stays within a bounded number of database statements.  Synthetic data only.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse

import pytest
from sqlalchemy import event
from starlette.requests import Request

from app.main import app
from app.models.models import HAMaintenanceRun, HASyncRun
from app.routers import high_availability as router
from app.services import ha_assessment
from app.services.ha_assessment import APPROVAL_REQUIRED, BLOCKED, SELF_HEALING, TRANSIENT, assess_cluster
from app.services.ha_failover import failover_readiness
from app.services.ha_maintenance import inspect_cluster
from app.services.ha_recovery import recovery_snapshot
from ha_simulation import hal_like_cluster, sqlite_session

def healthy():
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False)
    sim.report_both(2)
    return sim


def incident():
    sim = healthy()
    sim.vrrp.stop("SimPiHole1")
    sim.report(sim.sim_two)
    sim.report(sim.sim_one)
    sim.vrrp.start("SimPiHole1")
    sim.report_both(2)
    return sim


def latched():
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=True)
    sim.report_both(2)
    sim.db.add(HAMaintenanceRun(cluster_id=sim.cluster.id, operation="REINITIALISE", status="FAILED_SAFE", phase="PAUSED",
                                previous_state_json="{}", result_json="{}", requested_by_user_id=sim.admin.id,
                                created_at=datetime.utcnow() - timedelta(hours=1), completed_at=datetime.utcnow() - timedelta(hours=1)))
    sim.db.commit()
    return sim


def partitioned():
    sim = healthy()
    sim.vrrp.partition()
    sim.report_both(2)
    return sim


def drifted():
    sim = healthy()
    plan = {"authority_verified": True, "deletion_count": 0,
            "groups": [{"key": "dns", "label": "DNS settings", "risk": "high"}]}
    sim.db.add(HASyncRun(cluster_id=sim.cluster.id, source_node_id=sim.one.id, target_node_id=sim.two.id,
                         status="PLANNED", plan_json=json.dumps(plan)))
    sim.two.agent_automation_gates_json = json.dumps({"automatic_failover": True, "maintenance_mode": False, "dhcp_managed": True})
    sim.db.commit()
    return sim


def silent():
    sim = healthy()
    sim.two.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=10)
    sim.db.commit()
    return sim


SCENARIOS = {"healthy": healthy, "incident": incident, "latched": latched, "partitioned": partitioned, "drifted": drifted, "silent": silent}


def codes(assessment):
    return {finding.code for finding in assessment.findings}


def by_code(assessment, code):
    return next(finding for finding in assessment.findings if finding.code == code)


# --- content -----------------------------------------------------------------------


def test_healthy_cluster_reports_no_problems():
    sim = healthy()
    assessment = assess_cluster(sim.db, sim.cluster)
    assert assessment.overall == "HEALTHY"
    assert all(finding.severity == "info" for finding in assessment.findings)


def test_4_november_incident_is_explained_blocked_and_never_points_to_reinitialise():
    sim = incident()
    assessment = assess_cluster(sim.db, sim.cluster)
    finding = by_code(assessment, "OWNERSHIP_MISMATCH")
    assert assessment.overall == "CRITICAL"
    assert (finding.severity, finding.disposition, finding.repair) == ("critical", BLOCKED, None)
    observed = dict(finding.observations)
    assert observed["Virtual IP reported by"] == "SimPiHole2" and observed["DHCP served by"] == "SimPiHole1"
    # P6: the dedicated repair is named, with exactly why it is blocked here (agents older than 0.2.15).
    assert "Align service ownership" in finding.no_repair_reason and "0.2.15" in finding.no_repair_reason
    assert not any(item.repair and "REINIT" in item.repair.key for item in assessment.findings)
    assert any(not item.satisfied for item in finding.prerequisites)


def test_maintenance_hold_lists_release_checks_and_never_offers_an_unsafe_release():
    sim = latched()
    finding = by_code(assess_cluster(sim.db, sim.cluster), "MAINTENANCE_HOLD")
    assert finding.prerequisites  # the existing latch-release checks, each met or not
    if all(item.satisfied for item in finding.prerequisites):
        assert finding.disposition == APPROVAL_REQUIRED and finding.repair.key == "RELEASE_HOLD"
    else:
        # Never a release; at most the review-only acknowledgement (P7), which keeps the hold on.
        assert finding.repair is None or finding.repair.key in {"ACKNOWLEDGE_HOLD", "RECONCILE"}
        assert finding.disposition == (APPROVAL_REQUIRED if finding.repair else BLOCKED)


def test_dual_vip_ownership_is_never_automatic():
    sim = partitioned()
    finding = by_code(assess_cluster(sim.db, sim.cluster), "DUPLICATE_VIP")
    assert (finding.disposition, finding.repair) == (BLOCKED, None)


def test_drift_gates_and_silent_agent_findings():
    sim = drifted()
    drift = assess_cluster(sim.db, sim.cluster)
    configuration = by_code(drift, "CONFIGURATION_DRIFT")
    assert configuration.disposition == APPROVAL_REQUIRED and configuration.repair.key == "SYNC_REVIEW"  # high impact
    gates = by_code(drift, "AGENT_GATES_DIFFER")
    assert gates.node == "SimPiHole2" and gates.disposition == TRANSIENT
    quiet = silent()
    stale = by_code(assess_cluster(quiet.db, quiet.cluster), "AGENT_NOT_REPORTING")
    assert (stale.severity, stale.disposition, stale.node) == ("critical", BLOCKED, "SimPiHole2")


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_every_finding_is_complete_and_links_only_to_existing_pages(scenario):
    sim = SCENARIOS[scenario]()
    page_routes = {route.path for route in router.router.routes if "GET" in getattr(route, "methods", set())}
    for finding in assess_cluster(sim.db, sim.cluster).findings:
        assert finding.severity in {"critical", "warning", "info"}
        assert finding.disposition in {TRANSIENT, SELF_HEALING, APPROVAL_REQUIRED, BLOCKED}
        assert finding.title and finding.condition and finding.impact
        if finding.disposition == BLOCKED:
            assert finding.repair is None and finding.no_repair_reason
        if finding.repair is not None:
            path = urlparse(finding.repair.path).path
            template = path.replace(sim.cluster.public_id, "{public_id}")
            assert template in page_routes, (finding.code, path)
            assert finding.repair.service_impact


# --- read-only, deterministic, consistent, bounded ------------------------------------


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_assessment_is_strictly_read_only(scenario):
    sim = SCENARIOS[scenario]()
    engine = sim.db.get_bind()
    statements = []
    listener = lambda conn, cursor, statement, *args: statements.append(statement.lstrip().split()[0].upper())  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        assess_cluster(sim.db, sim.cluster)
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert set(statements) <= {"SELECT", "PRAGMA"}, statements
    assert not sim.db.new and not sim.db.dirty and not sim.db.deleted


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_assessment_is_deterministic_and_ordered(scenario):
    sim = SCENARIOS[scenario]()
    now = datetime.utcnow()
    first, second = assess_cluster(sim.db, sim.cluster, now=now), assess_cluster(sim.db, sim.cluster, now=now)
    assert first.as_dict() == second.as_dict()
    assert [finding.sort_key for finding in first.findings] == sorted(finding.sort_key for finding in first.findings)


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_reusing_a_views_precomputed_checks_gives_the_same_assessment(scenario):
    sim = SCENARIOS[scenario]()
    now = datetime.utcnow()
    recovery = recovery_snapshot(sim.db, sim.cluster, now=now)
    precomputed = assess_cluster(sim.db, sim.cluster, now=now, recovery=recovery,
                                 inspection=inspect_cluster(sim.cluster, now=now, recovery=recovery),
                                 readiness=failover_readiness(sim.cluster, now=now))
    assert precomputed.as_dict() == assess_cluster(sim.db, sim.cluster, now=now).as_dict()


def page_request(path: str) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request({"type": "http", "method": "GET", "scheme": "https", "path": path, "raw_path": path.encode(),
                    "query_string": b"", "headers": [], "client": ("198.51.100.2", 1234),
                    "server": ("kaya.example.com", 443), "session": {"csrf_token": "csrf"}, "app": app}, receive)


@pytest.mark.parametrize("scenario", ["incident", "latched", "drifted"])
def test_overview_reconcile_and_diagnostics_show_identical_findings(scenario, monkeypatch):
    sim = SCENARIOS[scenario]()
    fixed_now = datetime.utcnow()
    produced = {}
    real = ha_assessment.assess_cluster

    def capture(db, cluster, **kwargs):
        kwargs["now"] = fixed_now  # one instant for all three screens
        for key in ("inspection", "recovery", "readiness"):
            kwargs.pop(key, None)
        result = real(db, cluster, **kwargs)
        produced[len(produced)] = result.as_dict()
        return result

    monkeypatch.setattr(router, "assess_cluster", capture)
    monkeypatch.setattr(ha_assessment, "assess_cluster", capture)
    base = f"/high-availability/clusters/{sim.cluster.public_id}"
    pages = {
        "overview": router.cluster_detail(sim.cluster.public_id, page_request(base), db=sim.db, user=sim.admin),
        "reconcile": router.cluster_maintenance(sim.cluster.public_id, page_request(base + "/maintenance"), db=sim.db, user=sim.admin),
        "diagnostics": router.cluster_diagnostics(sim.cluster.public_id, page_request(base + "/diagnostics"), db=sim.db, user=sim.admin),
    }
    assessments = list(produced.values())
    assert len(assessments) >= 3 and all(item == assessments[0] for item in assessments)
    expected = sorted({finding["code"] for finding in assessments[0]["findings"]})
    for name, response in pages.items():
        body = response.body.decode()
        shown = sorted(set(re.findall(r'data-ha-finding="([A-Z_]+)"', body)))
        assert shown == expected, (name, shown, expected)
        assert f'data-ha-assessment-overall="{assessments[0]["overall"].lower()}"' in body


@pytest.mark.parametrize("scenario", ["healthy", "incident"])
def test_assessment_statement_cost_is_bounded(scenario):
    sim = SCENARIOS[scenario]()
    now = datetime.utcnow()
    recovery = recovery_snapshot(sim.db, sim.cluster, now=now)
    inspection = inspect_cluster(sim.cluster, now=now, recovery=recovery)
    readiness = failover_readiness(sim.cluster, now=now)
    sim.db.expire_all()  # a fresh request: nothing preloaded
    engine = sim.db.get_bind()
    statements = []
    listener = lambda *args: statements.append(1)  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        assess_cluster(sim.db, sim.cluster, now=now, inspection=inspection, recovery=recovery, readiness=readiness)
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    print(f"\nASSESSMENT-STATEMENTS {scenario} {len(statements)}")
    assert len(statements) <= 15, len(statements)
