from datetime import datetime, timedelta
from types import SimpleNamespace

from starlette.requests import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import TrafficFlowCollectorGlobalState, TrafficFlowCollectorState, TrafficMonitoringConfiguration, TrafficSource
import app.routers.admin as admin_router
from app.routers.admin import _network_traffic_admin_status


def test_admin_status_distinguishes_not_detected_from_healthy_and_stale(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        db.add_all([
            TrafficMonitoringConfiguration(id=1, is_enabled=True),
            TrafficSource(id=1, name="Synthetic NSEL", provider_key="cisco_nsel", source_category="flow_export", is_enabled=True, exporter_allowlist_json='["192.0.2.1"]', collector_port=2055),
        ])
        db.commit()
        monkeypatch.setenv("KAYA_FLOW_COLLECTOR_ENABLED", "true")
        monkeypatch.setenv("KAYA_FLOW_COLLECTOR_PORT", "2055")
        monkeypatch.delenv("KAYA_FLOW_COLLECTOR_BIND_ADDRESS", raising=False)
        assert _network_traffic_admin_status(db)["runtime"]["bind_address"] is None
        assert _network_traffic_admin_status(db)["status"] == "not_detected"

        now = datetime.utcnow()
        db.add(TrafficFlowCollectorGlobalState(id=1, listener_state="running", updated_at=now, last_datagram_at=now, packets_received=3))
        db.add(TrafficFlowCollectorState(source_id=1, listener_state="running", updated_at=now, packets_accepted=2))
        db.commit()
        status = _network_traffic_admin_status(db)
        assert status["status"] == "healthy"
        assert status["counters"]["packets_processed"] == 2

        monkeypatch.setenv("KAYA_FLOW_COLLECTOR_ENABLED", "false")
        status = _network_traffic_admin_status(db)
        assert status["status"] == "healthy"
        assert "telemetry is authoritative" in status["status_reason"]

        db.get(TrafficFlowCollectorGlobalState, 1).updated_at = now - timedelta(seconds=60)
        db.commit()
        assert _network_traffic_admin_status(db)["status"] == "unhealthy"


def test_settings_context_includes_network_traffic_status_on_every_render_path(monkeypatch):
    request = Request({
        "type": "http", "method": "GET", "path": "/system/site-administration",
        "headers": [], "query_string": b"", "client": ("127.0.0.1", 1),
        "scheme": "http", "server": ("localhost", 80), "session": {},
    })
    class FakeQuery:
        def filter(self, *args, **kwargs):
            return self

        def count(self):
            return 0

    class FakeDB:
        def query(self, _model):
            return FakeQuery()

    db = FakeDB()
    monkeypatch.setattr(admin_router, "granted_module_keys", lambda _db, _user: {"network_monitor"})
    monkeypatch.setattr(admin_router, "_network_traffic_admin_status", lambda _db: {"global_enabled": False})
    monkeypatch.setattr(admin_router, "load_site_settings", lambda _db: {"timezone_region": "UTC"})
    monkeypatch.setattr(admin_router, "next_asset_tag_preview", lambda _db: "HAL-0001")
    monkeypatch.setattr(admin_router, "wallboard_admin_context", lambda _request, _db: {})
    monkeypatch.setattr(admin_router, "dns_providers_for_admin", lambda _db: [])
    monkeypatch.setattr(admin_router, "ha_dns_clusters_for_admin", lambda _db: [])
    monkeypatch.setattr(admin_router, "vlan_ip_admin_context", lambda _db: {})
    monkeypatch.setattr(admin_router, "security_check_context", lambda _request, _db: {})
    context = admin_router._settings_page_context(
        request, db, SimpleNamespace(role="admin"), settings={"timezone_region": "UTC"}
    )
    assert context["network_traffic_status"] == {"global_enabled": False}
    assert context["module_access"] == {"network_monitor"}
