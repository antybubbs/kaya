import json
from pathlib import Path
from threading import Event, Thread

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import AuditLog, IPAddress, RemoteAccess, User
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


def test_explicit_administrator_reauthorization_clears_block_and_restores_pin():
    with Session(database()) as db:
        actor, address, remote = seed(db)
        update_remote_endpoint(db, address, remote=remote, address="192.0.2.50", actor=actor, reason="primary_ip_editor")
        db.commit()
        request = remote_manager.Request({
            "type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b"",
            "client": ("198.51.100.2", 1234), "session": {"csrf_token": "csrf"},
        })
        response = remote_manager.save_rdp_certificate_trust(
            request, remote.id, rdp_cert_fingerprints=PIN, rdp_trust_acknowledged="1",
            csrf_token="csrf", db=db, user=actor,
        )
        assert response.status_code == 303
        assert remote.rdp_cert_fingerprints == PIN
        assert remote.rdp_trust_invalidated_at is None
        assert remote.rdp_trust_invalidated_reason is None
        expected_wire_pin = "sha256:" + ":".join(["aa"] * 32)
        assert remote_manager.rdp_certificate_settings(remote)["cert-fingerprints"] == expected_wire_pin


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
