import json

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import HACluster, HANode, HAProviderConnection, User
from app.services.dns_providers import DNSProviderResult, PiHoleProvider
from app.services.ha_dns_advertisement import (
    HADNSAdvertisementError,
    cached_dns_advertisement,
    generated_dnsmasq_lines,
    repair_dns_advertisement,
)
from app.services.ha_sync import _sync_snapshot
from app.services.ha_validation import run_live_validation


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def cluster_fixture(db: Session):
    user = User(email="ha-option6@example.invalid", password_hash="x", role="admin", is_active=True)
    cluster = HACluster(
        name="DNS HA",
        provider_key="pihole",
        deployment_mode="DNS_DHCP",
        status="HEALTHY",
        virtual_ip="192.0.2.10",
        prefix_length=24,
        keepalived_status="DEPLOYED",
        created_by=user,
    )
    first_connection = HAProviderConnection(provider_key="pihole", name="First", api_base_url="https://192.0.2.2", encrypted_secret="fake", created_by=user)
    second_connection = HAProviderConnection(provider_key="pihole", name="Second", api_base_url="https://192.0.2.8", encrypted_secret="fake", created_by=user)
    db.add_all([user, cluster, first_connection, second_connection])
    db.flush()
    first = HANode(
        cluster_id=cluster.id,
        display_name="First",
        management_host="192.0.2.2",
        api_base_url=first_connection.api_base_url,
        ha_connection_id=first_connection.id,
        role="ACTIVE",
        desired_role="ACTIVE",
        vip_owned=True,
        dhcp_running=True,
        dns_healthy=True,
    )
    second = HANode(
        cluster_id=cluster.id,
        display_name="Second",
        management_host="192.0.2.8",
        api_base_url=second_connection.api_base_url,
        ha_connection_id=second_connection.id,
        role="STANDBY",
        desired_role="STANDBY",
        vip_owned=False,
        dhcp_running=False,
        dns_healthy=True,
    )
    db.add_all([first, second])
    db.flush()
    cluster.current_active_node_id = first.id
    cluster.authoritative_node_id = first.id
    db.commit()
    return cluster, first, second


class AdvertisementClient:
    configurations = {}
    calls = []
    fail_for = None

    def __init__(self, connection):
        self.connection = connection

    @property
    def key(self):
        return self.connection.base_url

    def get_ha_dhcp_dns_advertisement(self):
        return DNSProviderResult(
            True,
            "loaded",
            {"config": {"misc": {"dnsmasq_lines": list(self.configurations[self.key])}}},
        )

    def apply_ha_dhcp_dns_advertisement(self, lines):
        self.calls.append((self.key, list(lines)))
        if self.fail_for == self.key:
            return DNSProviderResult(False, "synthetic rejection", None)
        self.configurations[self.key] = list(lines)
        return DNSProviderResult(True, "applied", {})

    def get_ha_configuration(self):
        active = self.key.endswith(".2")
        return DNSProviderResult(True, "loaded", {"configuration": {"dhcp": {"config": {"dhcp": {"active": active}}}}})

    def test_connection(self):
        return DNSProviderResult(True, "connected", {})

    def get_version(self):
        return DNSProviderResult(True, "version", {"version": "6.2"})

    def get_status(self):
        return DNSProviderResult(True, "healthy", {})

    def get_dhcp_leases(self):
        return DNSProviderResult(True, "leases", {"leases": []})


def test_option_6_generation_removes_conflicts_and_preserves_unrelated_lines():
    result = generated_dnsmasq_lines(
        [
            "server=1.1.1.1",
            "dhcp-option=3,192.0.2.1",
            "dhcp-option=6,192.0.2.2,192.0.2.2",
            "dhcp-option=option:dns-server,192.0.2.2",
            "dhcp-option=tag:trusted,6,192.0.2.2",
            "dhcp-option-force=6,192.0.2.2",
        ],
        ("192.0.2.10", "192.0.2.8"),
    )
    assert result == [
        "server=1.1.1.1",
        "dhcp-option=3,192.0.2.1",
        "dhcp-option=6,192.0.2.10,192.0.2.8",
    ]


def test_repair_installs_static_vip_first_configuration_on_both_nodes():
    AdvertisementClient.calls = []
    AdvertisementClient.fail_for = None
    AdvertisementClient.configurations = {
        "https://192.0.2.2": ["server=1.1.1.1", "dhcp-option=6,192.0.2.2,192.0.2.2"],
        "https://192.0.2.8": ["dhcp-option=6,192.0.2.8,192.0.2.8"],
    }
    with database() as db:
        cluster, first, second = cluster_fixture(db)
        states = repair_dns_advertisement(
            db,
            cluster,
            client_factory=AdvertisementClient,
            dns_probe=lambda host: (True, "healthy"),
        )
        assert AdvertisementClient.configurations["https://192.0.2.2"] == [
            "server=1.1.1.1",
            "dhcp-option=6,192.0.2.10,192.0.2.8",
        ]
        assert AdvertisementClient.configurations["https://192.0.2.8"] == [
            "dhcp-option=6,192.0.2.10,192.0.2.2",
        ]
        assert [state.matches for state in states] == [True, True]
        assert cached_dns_advertisement(cluster)[0].observed == ("192.0.2.10", "192.0.2.8")
        assert first.vip_owned is True and first.dhcp_running is True
        assert second.vip_owned is False and second.dhcp_running is False
        first.vip_owned, second.vip_owned = False, True
        cluster.current_active_node_id = second.id
        second_state = next(state for state in cached_dns_advertisement(cluster) if state.node_id == second.id)
        assert second_state.expected == ("192.0.2.10", "192.0.2.2")
        assert second_state.matches is True


def test_repair_rolls_back_first_node_if_second_node_rejects_configuration():
    AdvertisementClient.calls = []
    AdvertisementClient.configurations = {
        "https://192.0.2.2": ["dhcp-option=6,192.0.2.2"],
        "https://192.0.2.8": ["dhcp-option=6,192.0.2.8"],
    }
    AdvertisementClient.fail_for = "https://192.0.2.2"
    with database() as db:
        cluster, _, _ = cluster_fixture(db)
        with pytest.raises(HADNSAdvertisementError, match="rejected"):
            repair_dns_advertisement(
                db,
                cluster,
                client_factory=AdvertisementClient,
                dns_probe=lambda host: (True, "healthy"),
            )
        assert AdvertisementClient.configurations["https://192.0.2.8"] == ["dhcp-option=6,192.0.2.8"]
    AdvertisementClient.fail_for = None


def test_ha_owned_advertisement_metadata_is_not_part_of_general_config_sync():
    snapshot = {
        "dhcp": {"config": {"dhcp": {"active": True, "start": "192.0.2.100"}}},
        "_ha_dhcp_dns_advertisement": {"observed": ["192.0.2.10", "192.0.2.8"]},
    }
    assert _sync_snapshot(snapshot) == {"dhcp": {"config": {"dhcp": {"start": "192.0.2.100"}}}}


def test_dns_only_mode_does_not_manage_dhcp_advertisement():
    with database() as db:
        cluster, _, _ = cluster_fixture(db)
        cluster.deployment_mode = "DNS_ONLY"
        db.commit()
        assert cached_dns_advertisement(cluster) == []
        with pytest.raises(HADNSAdvertisementError, match="only managed for DNS \\+ DHCP"):
            repair_dns_advertisement(db, cluster, client_factory=AdvertisementClient)


def test_validation_reports_exact_warning_for_physical_address_advertisement():
    AdvertisementClient.configurations = {
        "https://192.0.2.2": ["dhcp-option=6,192.0.2.2,192.0.2.2"],
        "https://192.0.2.8": ["dhcp-option=6,192.0.2.8,192.0.2.8"],
    }
    with database() as db:
        cluster, _, _ = cluster_fixture(db)
        rows = run_live_validation(
            db,
            cluster,
            client_factory=AdvertisementClient,
            dns_probe=lambda host: (True, "healthy"),
        )
        warnings = [row for row in rows if row.check_key == "dhcp_dns_advertisement"]
        assert len(warnings) == 2
        assert all(row.status == "WARNING" for row in warnings)
        assert all(
            row.summary
            == "DHCP is not advertising the HA DNS configuration. Existing clients may lose DNS during a node failure until their DHCP lease is renewed."
            for row in warnings
        )


def test_pihole_v6_advertisement_patch_uses_single_supported_config_path(monkeypatch):
    client = object.__new__(PiHoleProvider)
    captured = {}
    monkeypatch.setattr(client, "_v6_auth_headers", lambda: {"sid": "fake-session"})

    def request(path, **kwargs):
        captured.update({"path": path, **kwargs})
        return {}

    monkeypatch.setattr(client, "_request_json", request)
    result = client.apply_ha_dhcp_dns_advertisement(["dhcp-option=6,192.0.2.10,192.0.2.8"])
    assert result.ok
    assert captured["path"] == "/api/config/misc/dnsmasq_lines"
    assert captured["method"] == "PATCH"
    assert captured["payload"] == {
        "config": {"misc": {"dnsmasq_lines": ["dhcp-option=6,192.0.2.10,192.0.2.8"]}}
    }
