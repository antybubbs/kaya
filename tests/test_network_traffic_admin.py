from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import TrafficFlowCollectorGlobalState, TrafficFlowCollectorState, TrafficMonitoringConfiguration, TrafficSource
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
        assert _network_traffic_admin_status(db)["status"] == "not_detected"

        now = datetime.utcnow()
        db.add(TrafficFlowCollectorGlobalState(id=1, listener_state="running", updated_at=now, last_datagram_at=now, packets_received=3))
        db.add(TrafficFlowCollectorState(source_id=1, listener_state="running", updated_at=now, packets_accepted=2))
        db.commit()
        status = _network_traffic_admin_status(db)
        assert status["status"] == "healthy"
        assert status["counters"]["packets_processed"] == 2

        db.get(TrafficFlowCollectorGlobalState, 1).updated_at = now - timedelta(seconds=60)
        db.commit()
        assert _network_traffic_admin_status(db)["status"] == "unhealthy"
