from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import HACluster, HALeaseReplicationState, HANode, User
from app.schemas.high_availability import HAClusterDraftCreate
from app.services.ha_clusters import HADraftError, create_cluster_draft
from app.services.ha_sync import sync_plan
from app.services.ha_topology import DNS_DHCP, DNS_ONLY, deployment_mode, pihole_manages_dhcp


def database():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return Session(engine)


def draft(**overrides):
    values = {
        "name": "Home DNS",
        "provider_key": "pihole",
        "deployment_mode": DNS_DHCP,
        "gateway_address": "192.168.50.1",
        "virtual_ip": "192.168.50.4",
        "prefix_length": 24,
        "primary": {"name": "Pi-hole A", "api_base_url": "https://192.168.50.2", "secret": "fake-primary-secret", "network_interface": "eth0"},
        "secondary": {"name": "Pi-hole B", "api_base_url": "https://192.168.50.3", "secret": "fake-secondary-secret", "network_interface": "ens18"},
    }
    values.update(overrides)
    return HAClusterDraftCreate(**values)


def test_new_cluster_persists_explicit_topology_without_exposing_credentials():
    with database() as db:
        admin = User(email="topology@example.invalid", password_hash="x", role="admin", is_active=True)
        db.add(admin); db.commit()
        cluster = create_cluster_draft(db, draft(), admin)
        assert cluster.deployment_mode == DNS_DHCP
        assert cluster.gateway_address == "192.168.50.1"
        assert [node.network_interface for node in cluster.nodes] == ["eth0", "ens18"]
        assert all("fake-" not in (node.api_base_url or "") for node in cluster.nodes)


def test_dns_only_requires_a_known_external_dhcp_provider_and_same_network():
    with database() as db:
        admin = User(email="dns-only@example.invalid", password_hash="x", role="admin", is_active=True)
        db.add(admin); db.commit()
        with pytest.raises(HADraftError, match="provides DHCP"):
            create_cluster_draft(db, draft(deployment_mode=DNS_ONLY), admin)
        with pytest.raises(HADraftError, match="same IPv4 network"):
            create_cluster_draft(db, draft(deployment_mode=DNS_ONLY, external_dhcp_provider="router", gateway_address="10.0.0.1"), admin)
    with pytest.raises(ValidationError):
        draft(deployment_mode=DNS_ONLY, external_dhcp_provider="unsupported")


def test_explicit_dns_only_excludes_dhcp_from_sync_but_legacy_clusters_keep_discovery():
    with database() as db:
        cluster = HACluster(name="DNS only", provider_key="pihole", deployment_mode=DNS_ONLY, status="HEALTHY")
        db.add(cluster); db.flush()
        primary = HANode(cluster_id=cluster.id, display_name="A", api_base_url="https://192.168.1.2", role="ACTIVE", desired_role="ACTIVE", configuration_snapshot_json='{"dhcp":{"config":{"dhcp":{"active":true}}},"local_dns":{"hosts":[]}}')
        secondary = HANode(cluster_id=cluster.id, display_name="B", api_base_url="https://192.168.1.3", role="STANDBY", desired_role="STANDBY", configuration_snapshot_json='{"dhcp":{"config":{"dhcp":{"active":false}}},"local_dns":{"hosts":[]}}')
        db.add_all([primary, secondary]); db.flush()
        cluster.authoritative_node_id = primary.id
        db.commit()
        assert sync_plan(cluster)["groups"] == []
        assert pihole_manages_dhcp(cluster) is False

        cluster.deployment_mode = None
        db.add(HALeaseReplicationState(cluster_id=cluster.id, status="PENDING"))
        db.commit()
        assert deployment_mode(cluster) == DNS_DHCP
        assert pihole_manages_dhcp(cluster) is True


def test_guided_ui_and_documentation_cover_both_modes():
    wizard = Path("app/templates/high_availability_cluster_form.html").read_text(encoding="utf-8")
    dashboard = Path("app/templates/high_availability_cluster_detail.html").read_text(encoding="utf-8")
    guide = Path("docs/guides/high-availability.mdx").read_text(encoding="utf-8")
    for text in (wizard, guide):
        assert "DNS only" in text
        assert "DNS + DHCP" in text
    assert "DNS Virtual IP" in wizard
    assert "data-ha-architecture" in wizard
    assert "deployment_mode_label" in dashboard
    assert "not limited to DNS services" in guide
