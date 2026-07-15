from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import DNSProviderConfig, RemoteManagerSetting
from app.services import dns_collector, dns_insights
from app.services.dns_providers import DNSProviderResult


def session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def set_settings(factory, **values):
    with factory() as db:
        db.add_all(RemoteManagerSetting(key=key, value=value) for key, value in values.items())
        db.commit()


def add_provider(factory, name, *, enabled=True):
    with factory() as db:
        provider = DNSProviderConfig(
            name=name,
            provider_type="pihole",
            base_url="http://example.invalid",
            is_enabled=enabled,
        )
        db.add(provider)
        db.commit()
        return provider.id


def test_collector_configuration_requires_both_switches_and_bounds_interval():
    factory = session_factory()
    provider_id = add_provider(factory, "Enabled")
    add_provider(factory, "Disabled", enabled=False)
    set_settings(
        factory,
        dns_manager_enabled="1",
        dns_collector_enabled="",
        dns_refresh_interval_seconds="10",
        dns_known_hostnames='["router.home"]',
    )

    with factory() as db:
        assert dns_collector.collector_configuration(db) == (False, 30, [], '["router.home"]')

    with factory() as db:
        row = db.query(RemoteManagerSetting).filter_by(key="dns_collector_enabled").one()
        row.value = "1"
        db.commit()

    with factory() as db:
        assert dns_collector.collector_configuration(db) == (True, 30, [provider_id], '["router.home"]')


def test_collection_pass_processes_each_enabled_provider_and_returns_interval(monkeypatch):
    factory = session_factory()
    first = add_provider(factory, "First")
    second = add_provider(factory, "Second")
    add_provider(factory, "Disabled", enabled=False)
    set_settings(
        factory,
        dns_manager_enabled="1",
        dns_collector_enabled="1",
        dns_refresh_interval_seconds="600",
        dns_known_hostnames='["dns.home"]',
    )
    calls = []

    def fake_analyse(db, provider, *, known_hostnames_raw):
        calls.append((provider.id, known_hostnames_raw, db.is_active))

    monkeypatch.setattr(dns_collector, "analyse_provider", fake_analyse)

    assert dns_collector.run_dns_collection_pass(factory) == 600
    assert calls == [
        (first, '["dns.home"]', True),
        (second, '["dns.home"]', True),
    ]


def test_disabled_collection_pass_does_not_analyse(monkeypatch):
    factory = session_factory()
    add_provider(factory, "Provider")
    set_settings(factory, dns_manager_enabled="", dns_collector_enabled="1")

    def unexpected(*args, **kwargs):
        raise AssertionError("disabled collector must not analyse providers")

    monkeypatch.setattr(dns_collector, "analyse_provider", unexpected)
    assert dns_collector.run_dns_collection_pass(factory) == dns_collector.DISABLED_RECHECK_SECONDS


def test_provider_network_collection_runs_without_an_open_database_transaction(monkeypatch):
    factory = session_factory()
    provider_id = add_provider(factory, "Provider")
    failed_payloads = {
        key: DNSProviderResult(False, "Unavailable")
        for key in ("status", "stats", "history", "clients", "queries", "dhcp", "blocklists")
    }

    with factory() as db:
        provider = db.get(DNSProviderConfig, provider_id)

        def fake_collect(client):
            assert db.in_transaction() is False
            return failed_payloads

        monkeypatch.setattr(dns_insights, "_collect_provider_data", fake_collect)
        result = dns_insights.analyse_provider(db, provider)

        assert result.provider_id == provider_id
        assert db.get(DNSProviderConfig, provider_id).last_status == "error"


def test_dns_admin_exposes_background_collector_controls():
    template = Path("app/templates/settings.html").read_text(encoding="utf-8")
    assert 'name="dns_collector_enabled"' in template
    assert 'name="dns_refresh_interval_seconds"' in template
