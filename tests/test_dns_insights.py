from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import DNSInsight, DNSProviderConfig
from app.services.dns_insights import (
    BlockingDisabledRule,
    DNSInsightContext,
    DNSInsightThresholds,
    GeneratedInsight,
    HighBlockedRateRule,
    InsightCategory,
    InsightSeverity,
    NetworkVolumeTrendRule,
    NormalisedClient,
    NXDomainSpikeRule,
    ProviderDisconnectedRule,
    _persist_insights,
    calculate_health_score,
)


def context(**overrides):
    values = {
        "provider": SimpleNamespace(id=1, name="Provider 1", last_status="online"),
        "generated_at": datetime(2026, 7, 12, 10, 0),
        "connected": True,
        "connection_message": "Connected",
        "blocking_enabled": True,
        "total_queries": 1000,
        "blocked_queries": 100,
        "failed_queries": 0,
        "active_clients": 1,
        "clients": [],
        "query_rows": [],
        "blocklist_updated_at": None,
        "previous_snapshot": None,
        "last_successful_snapshot_at": None,
        "capabilities": {"status", "stats", "queries"},
    }
    values.update(overrides)
    return DNSInsightContext(**values)


def test_navigation_places_insights_between_dashboard_and_reports():
    template = Path("app/templates/dns_manager.html").read_text(encoding="utf-8")
    dashboard = template.index('tab=dashboard')
    insights = template.index('tab=insights')
    reports = template.index('tab=reports')
    query_log = template.index('tab=query-log')
    assert dashboard < insights < reports < query_log


def test_provider_disconnected_rule_is_critical():
    evaluation = ProviderDisconnectedRule().evaluate(context(connected=False), DNSInsightThresholds())
    assert evaluation.supported is True
    assert evaluation.insights[0].severity == InsightSeverity.CRITICAL


def test_blocking_unsupported_is_skipped_without_conclusion():
    evaluation = BlockingDisabledRule().evaluate(context(blocking_enabled=None), DNSInsightThresholds())
    assert evaluation.supported is False
    assert evaluation.insights == []


def test_blocking_disabled_rule_is_warning():
    evaluation = BlockingDisabledRule().evaluate(context(blocking_enabled=False), DNSInsightThresholds())
    assert evaluation.insights[0].severity == InsightSeverity.WARNING


def test_high_blocked_rate_and_nxdomain_rules_use_minimum_volume():
    client = NormalisedClient("mac", "aa:bb", "client-1", "10.0.0.2", "aa:bb", queries=100, blocked_queries=40, nxdomain_queries=30)
    current = context(clients=[client])
    assert len(HighBlockedRateRule().evaluate(current, DNSInsightThresholds()).insights) == 1
    assert len(NXDomainSpikeRule().evaluate(current, DNSInsightThresholds()).insights) == 1
    client.queries = 3
    assert HighBlockedRateRule().evaluate(current, DNSInsightThresholds()).insights == []
    assert NXDomainSpikeRule().evaluate(current, DNSInsightThresholds()).insights == []


def test_network_volume_change_requires_material_volume_and_change():
    previous = SimpleNamespace(total_queries=1000)
    evaluation = NetworkVolumeTrendRule().evaluate(context(total_queries=1500, previous_snapshot=previous), DNSInsightThresholds())
    assert evaluation.supported is True
    assert evaluation.insights[0].percentage_change == 50


def test_health_score_is_deterministic_and_unsupported_freshness_has_no_deduction():
    provider = SimpleNamespace(last_status="online")
    insight = SimpleNamespace(status="active", severity="warning", rule_key="blocking_disabled")
    result = calculate_health_score(provider, [insight], None)
    assert result.score == 85
    freshness = next(item for item in result.factors if item.label == "Analysis freshness")
    assert freshness.deduction is None


def test_insight_lifecycle_resolves_and_reactivates_without_duplicate():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        provider = DNSProviderConfig(name="Test", provider_type="pihole", base_url="http://example.invalid")
        db.add(provider)
        db.commit()
        current = context(provider=provider)
        generated = GeneratedInsight(
            key="stable-key", rule_key="test_rule", category=InsightCategory.SYSTEM,
            severity=InsightSeverity.WARNING, title="Test", summary="Test summary",
        )
        _persist_insights(db, current, [generated], {"test_rule"})
        db.commit()
        first = db.query(DNSInsight).one()
        first_detected = first.first_detected_at

        _persist_insights(db, current, [], {"test_rule"})
        db.commit()
        assert db.query(DNSInsight).one().status == "resolved"

        _persist_insights(db, current, [generated], {"test_rule"})
        db.commit()
        reactivated = db.query(DNSInsight).one()
        assert reactivated.status == "active"
        assert reactivated.first_detected_at == first_detected
        assert db.query(DNSInsight).count() == 1

