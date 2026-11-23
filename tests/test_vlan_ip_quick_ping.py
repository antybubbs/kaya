from types import SimpleNamespace
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import IPAddress
from app.routers import ip_addresses


def _request():
    return SimpleNamespace(
        session={"csrf_token": "synthetic-csrf"},
        client=SimpleNamespace(host="192.0.2.200"),
        headers={},
    )


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def _record(db, address="192.0.2.10"):
    row = IPAddress(address=address, name="Synthetic target")
    db.add(row)
    db.commit()
    return row


def test_quick_ping_returns_explicit_success_metadata(monkeypatch, db):
    row = _record(db)
    monkeypatch.setattr(ip_addresses, "trusted_client_ip", lambda request: "192.0.2.200")
    monkeypatch.setattr(ip_addresses, "ping_ipv4", lambda address, timeout: (True, 12.5, None))
    monkeypatch.setattr(ip_addresses, "write_audit", lambda *args, **kwargs: None)
    ip_addresses._quick_ping_attempts.clear()
    ip_addresses._quick_ping_in_flight.clear()
    response = ip_addresses.ping_ip_address(_request(), row.id, "synthetic-csrf", db, SimpleNamespace(id=7))

    assert response.body
    assert response.media_type == "application/json"
    assert b'"record_id":' in response.body
    assert b'"target":"192.0.2.10"' in response.body
    assert b'"status":"success"' in response.body
    assert b'"latency_ms":12.5' in response.body


def test_quick_ping_distinguishes_no_response_from_execution_error(monkeypatch, db):
    row = _record(db)
    monkeypatch.setattr(ip_addresses, "trusted_client_ip", lambda request: "192.0.2.200")
    monkeypatch.setattr(ip_addresses, "write_audit", lambda *args, **kwargs: None)
    ip_addresses._quick_ping_attempts.clear()
    ip_addresses._quick_ping_in_flight.clear()

    monkeypatch.setattr(ip_addresses, "ping_ipv4", lambda address, timeout: (False, None, "Timed out"))
    response = ip_addresses.ping_ip_address(_request(), row.id, "synthetic-csrf", db, SimpleNamespace(id=8))
    assert b'"status":"no_response"' in response.body

    ip_addresses._quick_ping_attempts.clear()
    monkeypatch.setattr(ip_addresses, "ping_ipv4", lambda address, timeout: (False, None, "Ping command is not installed in the container."))
    response = ip_addresses.ping_ip_address(_request(), row.id, "synthetic-csrf", db, SimpleNamespace(id=8))
    assert b'"status":"error"' in response.body


def test_quick_ping_rejects_missing_csrf_and_rate_excess(monkeypatch, db):
    row = _record(db)
    monkeypatch.setattr(ip_addresses, "trusted_client_ip", lambda request: "192.0.2.200")
    monkeypatch.setattr(ip_addresses, "ping_ipv4", lambda address, timeout: (True, 1, None))
    monkeypatch.setattr(ip_addresses, "write_audit", lambda *args, **kwargs: None)
    ip_addresses._quick_ping_attempts.clear()
    ip_addresses._quick_ping_in_flight.clear()
    request = _request()

    with pytest.raises(HTTPException) as csrf_error:
        ip_addresses.ping_ip_address(request, row.id, "wrong-csrf", db, SimpleNamespace(id=9))
    assert csrf_error.value.status_code == 400

    ip_addresses._quick_ping_in_flight.add(("user:9:ip:192.0.2.200", row.id))
    with pytest.raises(HTTPException) as duplicate_error:
        ip_addresses.ping_ip_address(request, row.id, "synthetic-csrf", db, SimpleNamespace(id=9))
    assert duplicate_error.value.status_code == 409
    ip_addresses._quick_ping_in_flight.clear()

    for _ in range(ip_addresses.QUICK_PING_RATE_LIMIT):
        ip_addresses.ping_ip_address(request, row.id, "synthetic-csrf", db, SimpleNamespace(id=9))
    with pytest.raises(HTTPException) as rate_error:
        ip_addresses.ping_ip_address(request, row.id, "synthetic-csrf", db, SimpleNamespace(id=9))
    assert rate_error.value.status_code == 429


def test_detail_and_table_ping_controls_keep_separate_ui_contracts():
    javascript = Path("app/static/js/ip_addresses.js").read_text(encoding="utf-8")
    stylesheet = Path("app/static/css/app.css").read_text(encoding="utf-8")
    table_template = Path("app/templates/ip_addresses.html").read_text(encoding="utf-8")
    detail_template = Path("app/templates/ip_address_detail.html").read_text(encoding="utf-8")

    assert 'data-ping-card' in detail_template
    assert 'data-ping-message' in detail_template
    assert 'button.textContent = "Pinging..."' in javascript
    assert 'button.textContent = `Up - ${payload.latency_ms}ms`' in javascript
    assert 'data-ping-record-id' in table_template
    assert 'quick-ping-label">Ping' in table_template
    assert 'quick-ping-success' in javascript and 'quick-ping-no-response' in javascript and 'quick-ping-error' in javascript
    assert ".quick-ping-button.quick-ping-success{background:" in stylesheet and "!important" in stylesheet
    assert ".quick-ping-button.quick-ping-no-response{background:" in stylesheet
    assert ".quick-ping-button.quick-ping-error{background:" in stylesheet
