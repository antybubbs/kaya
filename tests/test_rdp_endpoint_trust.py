import asyncio
import json
from datetime import datetime
from pathlib import Path
from threading import Event, Thread

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import AuditLog, IPAddress, RemoteAccess, RemoteManagerSetting, User
from app.routers import remote_manager
from app.services.remote_endpoint_trust import update_remote_endpoint


PIN = f"sha256:{'a' * 64}"


def database(path: Path | None = None):
    engine = create_engine(f"sqlite:///{path.as_posix()}" if path else "sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def seed(db: Session):
    actor = User(email="admin@example.invalid", password_hash="fake-hash", role="admin", is_active=True)
    address = IPAddress(address="192.0.2.40", name="Synthetic RDP")
    remote = RemoteAccess(
        ip_address=address, protocol="rdp", port=3389, is_enabled=True,
        username="synthetic-user", rdp_cert_fingerprints=PIN,
    )
    db.add_all([actor, address, remote])
    db.commit()
    return actor, address, remote


@pytest.mark.parametrize(
    ("reason", "changes", "expected"),
    [
        ("primary_ip_editor", {"address": "192.0.2.41"}, ("192.0.2.41", "rdp", 3389)),
        ("remote_host_editor", {"port": 3390}, ("192.0.2.40", "rdp", 3390)),
        ("remote_host_editor", {"protocol": "ssh", "port": 22}, ("192.0.2.40", "ssh", 22)),
        ("dns_managed_update", {"address": "192.0.2.42"}, ("192.0.2.42", "rdp", 3389)),
        ("dns_automatic_update", {"address": "192.0.2.43"}, ("192.0.2.43", "rdp", 3389)),
    ],
)
def test_every_supported_endpoint_change_invalidates_pin_and_fails_closed(reason, changes, expected):
    with Session(database()) as db:
        actor, address, remote = seed(db)
        assert update_remote_endpoint(
            db, address, remote=remote, actor=actor, audit_ip="198.51.100.2", reason=reason, **changes,
        ) is True
        db.commit()
        assert (address.address, remote.protocol, remote.port) == expected
        assert remote.rdp_cert_fingerprints is None
        assert remote.rdp_trust_invalidated_at is not None
        with pytest.raises(ValueError, match="re-authorized"):
            remote_manager.rdp_certificate_settings(remote)
        audit = db.query(AuditLog).filter_by(action="rdp_certificate_trust_invalidated").one()
        assert audit.user_id == actor.id
        assert audit.ip_address == "198.51.100.2"
        assert PIN not in (audit.detail or "") + (audit.metadata_json or "")
        assert "synthetic-user" not in (audit.detail or "") + (audit.metadata_json or "")
        metadata = json.loads(audit.metadata_json)
        assert metadata["reason"] == reason
        assert metadata["old_endpoint"]["address"] == "192.0.2.40"


def test_same_endpoint_and_non_endpoint_metadata_do_not_invalidate_pin():
    with Session(database()) as db:
        actor, address, remote = seed(db)
        assert update_remote_endpoint(
            db, address, remote=remote, address=address.address, protocol="rdp", port=3389,
            actor=actor, reason="primary_ip_editor",
        ) is False
        remote.display_name = "Renamed only"
        db.commit()
        assert remote.rdp_cert_fingerprints == PIN
        assert remote.rdp_trust_invalidated_at is None
        assert db.query(AuditLog).filter_by(action="rdp_certificate_trust_invalidated").count() == 0


def _candidate(fingerprint=PIN):
    return remote_manager.RdpCertificateCandidate(
        fingerprint=fingerprint, subject="CN=synthetic", issuer="CN=synthetic", self_signed=True,
        not_valid_before=datetime(2020, 1, 1), not_valid_after=datetime(2030, 1, 1), sans=[],
    )


def test_explicit_administrator_reauthorization_clears_block_and_restores_pin(monkeypatch):
    with Session(database()) as db:
        actor, address, remote = seed(db)
        update_remote_endpoint(db, address, remote=remote, address="192.0.2.50", actor=actor, reason="primary_ip_editor")
        db.commit()
        request = remote_manager.Request({
            "type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b"",
            "client": ("198.51.100.2", 1234), "session": {"csrf_token": "csrf"},
        })
        monkeypatch.setattr(remote_manager, "discover_rdp_certificate", lambda *a, **k: _candidate())
        response = remote_manager.trust_remote_rdp_certificate(
            request, remote.id, csrf_token="csrf", rdp_cert_candidate=PIN, rdp_cert_mode="trust",
            rdp_cert_view="settings", db=db, user=actor,
        )
        assert response.status_code == 303
        assert remote.rdp_cert_fingerprints == PIN
        assert remote.rdp_trust_invalidated_at is None
        assert remote.rdp_trust_invalidated_reason is None
        expected_wire_pin = "sha256:" + ":".join(["aa"] * 32)
        assert remote_manager.rdp_certificate_settings(remote)["cert-fingerprints"] == expected_wire_pin


def test_certificate_changed_during_enrolment_refuses_to_persist(monkeypatch):
    with Session(database()) as db:
        actor, address, remote = seed(db)
        remote.rdp_cert_fingerprints = None
        db.commit()
        request = remote_manager.Request({
            "type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b"",
            "client": ("198.51.100.2", 1234), "session": {"csrf_token": "csrf"},
        })
        different = f"sha256:{'b' * 64}"
        monkeypatch.setattr(remote_manager, "discover_rdp_certificate", lambda *a, **k: _candidate(different))
        response = remote_manager.trust_remote_rdp_certificate(
            request, remote.id, csrf_token="csrf", rdp_cert_candidate=PIN, rdp_cert_mode="trust",
            rdp_cert_view="settings", db=db, user=actor,
        )
        assert response.status_code == 409
        assert remote.rdp_cert_fingerprints is None
        audit = db.query(AuditLog).filter_by(action="rdp_certificate_changed_during_enrolment").one()
        assert audit.severity == "critical"
        assert PIN not in (audit.detail or "") + (audit.metadata_json or "")
        assert different not in (audit.detail or "") + (audit.metadata_json or "")


def test_remove_trust_falls_back_to_system_ca():
    with Session(database()) as db:
        actor, address, remote = seed(db)
        request = remote_manager.Request({
            "type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b"",
            "client": ("198.51.100.2", 1234), "session": {"csrf_token": "csrf"},
        })
        response = remote_manager.remove_remote_rdp_certificate_trust(
            request, remote.id, csrf_token="csrf", db=db, user=actor,
        )
        assert response.status_code == 303
        assert remote.rdp_cert_fingerprints is None
        assert remote_manager.rdp_certificate_settings(remote) == {"ignore-cert": False, "cert-tofu": False}


def test_replace_and_keep_previous_preserves_rotation_pin(monkeypatch):
    with Session(database()) as db:
        actor, address, remote = seed(db)
        assert remote.rdp_cert_fingerprints == PIN
        request = remote_manager.Request({
            "type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b"",
            "client": ("198.51.100.2", 1234), "session": {"csrf_token": "csrf"},
        })
        new_pin = f"sha256:{'c' * 64}"
        monkeypatch.setattr(remote_manager, "discover_rdp_certificate", lambda *a, **k: _candidate(new_pin))
        response = remote_manager.trust_remote_rdp_certificate(
            request, remote.id, csrf_token="csrf", rdp_cert_candidate=new_pin, rdp_cert_mode="append",
            rdp_cert_view="settings", db=db, user=actor,
        )
        assert response.status_code == 303
        pins = remote_manager.normalise_rdp_cert_fingerprints(remote.rdp_cert_fingerprints)
        assert pins == [PIN, new_pin]


def test_replace_without_keep_previous_drops_old_pin(monkeypatch):
    with Session(database()) as db:
        actor, address, remote = seed(db)
        request = remote_manager.Request({
            "type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b"",
            "client": ("198.51.100.2", 1234), "session": {"csrf_token": "csrf"},
        })
        new_pin = f"sha256:{'c' * 64}"
        monkeypatch.setattr(remote_manager, "discover_rdp_certificate", lambda *a, **k: _candidate(new_pin))
        response = remote_manager.trust_remote_rdp_certificate(
            request, remote.id, csrf_token="csrf", rdp_cert_candidate=new_pin, rdp_cert_mode="replace",
            rdp_cert_view="settings", db=db, user=actor,
        )
        assert response.status_code == 303
        assert remote_manager.normalise_rdp_cert_fingerprints(remote.rdp_cert_fingerprints) == [new_pin]


def test_discover_never_persists_and_reports_failure(monkeypatch):
    from app.main import app as fastapi_app

    with Session(database()) as db:
        actor, address, remote = seed(db)
        original = remote.rdp_cert_fingerprints
        request = remote_manager.Request({
            "type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b"",
            "client": ("198.51.100.2", 1234), "session": {"csrf_token": "csrf"}, "app": fastapi_app,
        })
        monkeypatch.setattr(remote_manager, "discover_rdp_certificate", lambda *a, **k: _candidate("sha256:" + "d" * 64))
        response = remote_manager.discover_remote_rdp_certificate(
            request, remote.id, csrf_token="csrf", rdp_cert_view="settings", db=db, user=actor,
        )
        assert response.status_code == 200
        assert remote.rdp_cert_fingerprints == original  # discovery never writes

        def raise_error(*_args, **_kwargs):
            raise ValueError("Kaya could not reach the RDP server in time.")

        monkeypatch.setattr(remote_manager, "discover_rdp_certificate", raise_error)
        failed = remote_manager.discover_remote_rdp_certificate(
            request, remote.id, csrf_token="csrf", rdp_cert_view="settings", db=db, user=actor,
        )
        assert failed.status_code == 400
        assert remote.rdp_cert_fingerprints == original
        discovery_audits = db.query(AuditLog).filter_by(action="rdp_certificate_discovered").all()
        assert [audit.severity for audit in discovery_audits] == ["info", "warning"]


def _json_request(payload: dict, *, path="/remote-manager/1/rdp/start"):
    body = json.dumps(payload).encode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return remote_manager.Request(
        {
            "type": "http", "method": "POST", "path": path, "raw_path": path.encode(),
            "query_string": b"", "headers": [(b"content-type", b"application/json")],
            "client": ("198.51.100.2", 1234), "session": {"csrf_token": "csrf"},
        },
        receive,
    )


def test_rdp_start_blocks_and_redirects_on_certificate_mismatch(monkeypatch):
    with Session(database()) as db:
        actor, address, remote = seed(db)
        db.add_all([
            RemoteManagerSetting(key="guacamole_enabled", value="1"),
            RemoteManagerSetting(key="guacd_host", value="127.0.0.1"),
        ])
        db.commit()
        monkeypatch.setattr(
            remote_manager, "discover_rdp_certificate", lambda *a, **k: _candidate(f"sha256:{'e' * 64}")
        )

        def fail_if_called():
            raise AssertionError("must not start the Guacamole bridge when the certificate mismatches")

        monkeypatch.setattr(remote_manager, "start_guacamole_bridge", fail_if_called)
        request = _json_request(
            {"csrf_token": "csrf", "username": "synthetic-user", "password": "clearly-fake"}
        )
        response = asyncio.run(remote_manager.rdp_start(request, remote.id, db=db, user=actor))
        payload = json.loads(response.body)
        assert response.status_code == 409
        assert payload["ok"] is False
        assert payload["certificate_changed"] is True
        assert payload["review_url"] == f"/remote-manager/{remote.id}/rdp/certificate?view=session"
        audit = db.query(AuditLog).filter_by(action="rdp_certificate_mismatch_detected").one()
        assert audit.severity == "critical"


def test_rdp_start_falls_through_when_preflight_discovery_fails(monkeypatch):
    with Session(database()) as db:
        actor, address, remote = seed(db)
        db.add_all([
            RemoteManagerSetting(key="guacamole_enabled", value="1"),
            RemoteManagerSetting(key="guacd_host", value="127.0.0.1"),
        ])
        db.commit()

        def raise_error(*_args, **_kwargs):
            raise ValueError("Kaya could not reach the RDP server in time.")

        monkeypatch.setattr(remote_manager, "discover_rdp_certificate", raise_error)
        started = {"called": False}

        def fake_start_bridge():
            started["called"] = True

        monkeypatch.setattr(remote_manager, "start_guacamole_bridge", fake_start_bridge)
        monkeypatch.setattr(
            remote_manager,
            "create_rdp_guacamole_token",
            lambda *a, **k: (_ for _ in ()).throw(ValueError("no bridge configured in this test")),
        )
        request = _json_request(
            {"csrf_token": "csrf", "username": "synthetic-user", "password": "clearly-fake"}
        )
        response = asyncio.run(remote_manager.rdp_start(request, remote.id, db=db, user=actor))
        # A pre-flight failure must fall through to the normal path, not block it.
        assert started["called"] is True
        assert response.status_code == 400  # from the stubbed create_rdp_guacamole_token failure, not the pre-flight
        payload = json.loads(response.body)
        assert "certificate_changed" not in payload


def test_invalidation_survives_restart_and_never_exposes_new_endpoint_with_old_pin(tmp_path):
    path = tmp_path / "rdp-endpoint.sqlite3"
    engine = database(path)
    with Session(engine) as db:
        actor, address, remote = seed(db)
        remote_id, address_id, actor_id = remote.id, address.id, actor.id

    started = Event()
    finished = Event()

    def writer():
        with Session(engine) as db:
            started.set()
            update_remote_endpoint(
                db, db.get(IPAddress, address_id), remote=db.get(RemoteAccess, remote_id),
                address="192.0.2.60", actor=db.get(User, actor_id), reason="dns_automatic_update",
            )
            db.commit()
            finished.set()

    thread = Thread(target=writer)
    thread.start()
    started.wait(timeout=2)
    while not finished.wait(timeout=0.01):
        with Session(engine) as reader:
            observed_address = reader.get(IPAddress, address_id).address
            observed_pin = reader.get(RemoteAccess, remote_id).rdp_cert_fingerprints
            assert not (observed_address == "192.0.2.60" and observed_pin == PIN)
    thread.join(timeout=2)

    with Session(engine) as restarted:
        address = restarted.get(IPAddress, address_id)
        remote = restarted.get(RemoteAccess, remote_id)
        assert address.address == "192.0.2.60"
        assert remote.rdp_cert_fingerprints is None
        assert remote.rdp_trust_invalidated_at is not None
        with pytest.raises(ValueError):
            remote_manager.rdp_certificate_settings(remote)


def test_all_supported_endpoint_writers_use_central_invalidation_service():
    sources = {
        "app/routers/ip_addresses.py": "update_remote_endpoint(",
        "app/routers/remote_manager.py": "update_remote_endpoint(",
        "app/routers/dns_manager.py": "reason=\"dns_managed_update\"",
        "app/services/dns_clients.py": "reason=\"dns_automatic_update\"",
    }
    for path, marker in sources.items():
        assert marker in Path(path).read_text(encoding="utf-8")
    importer = Path("app/services/importer.py").read_text(encoding="utf-8")
    assert "record.address =" not in importer
