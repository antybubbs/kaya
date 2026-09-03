from datetime import datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import IPAddress, NetworkMonitor, NetworkMonitorCheck
from app.routers import ip_addresses


def test_ip_detail_aggregates_monitor_summary_and_bounds_display_checks(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    statements = []
    captured = {}

    @event.listens_for(engine, "before_cursor_execute")
    def capture_sql(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    monkeypatch.setattr(
        ip_addresses.templates,
        "TemplateResponse",
        lambda request, template, context: captured.update(context) or context,
    )
    request = SimpleNamespace(session={}, client=None)
    user = SimpleNamespace(role="viewer")
    now = datetime.utcnow()
    with Session(engine) as db:
        record = IPAddress(address="192.0.2.10", name="Synthetic target")
        db.add(record)
        db.flush()
        monitor = NetworkMonitor(ip_address_id=record.id)
        db.add(monitor)
        db.flush()
        db.add_all(
            [
                NetworkMonitorCheck(
                    monitor_id=monitor.id,
                    status="up" if index % 2 else "down",
                    latency_ms=20 if index % 2 else None,
                    checked_at=now - timedelta(minutes=index),
                )
                for index in range(120)
            ]
        )
        db.commit()

        ip_addresses.detail_ip_address(request, record.id, db, user)

    observations = captured["monitor_observations"]
    assert len(observations["checks"]) == 24
    assert observations["availability"] == 50.0
    assert observations["average_latency"] == 20
    assert any(
        "network_monitor_checks" in statement.lower()
        and "limit" in statement.lower()
        for statement in statements
    )
