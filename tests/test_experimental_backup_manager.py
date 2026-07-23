import asyncio
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.db.session import Base
from app.main import app
from app.models.models import AuditLog, BackupJob, BackupRecord, ComputeHost, ComputeInventoryItem, RemoteManagerSetting, User
from app.routers.admin import set_backup_manager_feature
from app.routers.backup_manager import agent_jobs, hash_agent_token, proxmox_backup_jobs, require_backup_user
from app.services.site_settings import get_site_setting


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def request(path: str, values: dict[str, str] | None = None, *, authorization: str = ""):
    body = urlencode(values or {}).encode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    headers = [(b"content-type", b"application/x-www-form-urlencoded"), (b"content-length", str(len(body)).encode())]
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    return Request(
        {
            "type": "http", "method": "POST", "scheme": "https", "path": path,
            "raw_path": path.encode(), "query_string": b"", "headers": headers,
            "client": ("198.51.100.3", 1234), "server": ("kaya.example.com", 443),
            "session": {"csrf_token": "csrf"}, "app": app,
        },
        receive,
    )


def test_backup_manager_is_enabled_by_default_for_existing_installations():
    with database() as db:
        assert get_site_setting(db, "backup_manager_enabled") == "1"


def test_disabled_backup_manager_blocks_ui_and_stops_new_agent_dispatch():
    with database() as db:
        user = User(email="backup-viewer@example.com", password_hash="x", role="viewer", is_active=True)
        token = "agent-test-token"
        host = ComputeHost(name="Docker Agent", platform="docker_agent", base_url="https://docker.invalid", agent_token_hash=hash_agent_token(token))
        db.add_all([user, host, RemoteManagerSetting(key="backup_manager_enabled", value="")]); db.flush()
        queued = BackupJob(host_id=host.id, operation="backup", status="queued")
        db.add(queued); db.commit()
        with pytest.raises(HTTPException) as rejected:
            require_backup_user(request("/infrastructure/backup-manager"), db=db, user=user)
        assert rejected.value.status_code == 404
        response = agent_jobs(request("/infrastructure/backup-manager/api/agent/jobs", authorization=f"Bearer {token}"), db=db)
        assert response == {"ok": True, "jobs": []}
        assert db.get(BackupJob, queued.id).status == "queued"


def test_disable_requires_acknowledgement_and_preserves_backup_data():
    with database() as db:
        admin = User(email="backup-admin@example.com", password_hash="x", role="admin", is_active=True)
        host = ComputeHost(name="Backup host", platform="docker_agent", base_url="https://backup.invalid")
        record = BackupRecord(name="Existing backup", target="/mnt/backups/existing.tar", source_type="manual")
        db.add_all([admin, host, record, RemoteManagerSetting(key="backup_manager_enabled", value="1")]); db.flush()
        job = BackupJob(host_id=host.id, operation="backup", status="running", artifact_path="/mnt/backups/job.enc")
        db.add(job); db.commit()
        record_id, job_id = record.id, job.id

        rejected = asyncio.run(set_backup_manager_feature(
            request("/system/site-administration/experimental-features/backup-manager", {"csrf_token": "csrf", "enabled": "0"}),
            db=db,
            user=admin,
        ))
        assert "backup-acknowledgement-required" in rejected.headers["location"]
        assert get_site_setting(db, "backup_manager_enabled") == "1"

        accepted = asyncio.run(set_backup_manager_feature(
            request("/system/site-administration/experimental-features/backup-manager", {"csrf_token": "csrf", "enabled": "0", "acknowledge_backup_disable": "1"}),
            db=db,
            user=admin,
        ))
        assert "feature_status=disabled" in accepted.headers["location"]
        assert get_site_setting(db, "backup_manager_enabled") == ""
        assert db.get(BackupRecord, record_id).target == "/mnt/backups/existing.tar"
        assert db.get(BackupJob, job_id).artifact_path == "/mnt/backups/job.enc"
        audit = db.query(AuditLog).filter_by(entity="experimental_feature", entity_id="backup_manager").one()
        assert audit.action == "feature_disabled"


def test_backup_manager_uses_shared_beta_and_experimental_feature_ui():
    base = Path("app/templates/base.html").read_text(encoding="utf-8")
    page = Path("app/templates/backup_manager.html").read_text(encoding="utf-8")
    settings = Path("app/templates/settings.html").read_text(encoding="utf-8")
    assert "backup_manager_enabled|default(true)" in base
    assert "Backup Manager is a beta feature" in base
    assert "components/maturity_badge.html" in page
    assert "experimental-features/backup-manager" in settings
    assert "pauses new job dispatch without deleting" in settings


def test_proxmox_backup_jobs_use_comment_as_the_user_friendly_label():
    with database() as db:
        host = ComputeHost(name="PVE test host", platform="proxmox", base_url="https://pve.invalid")
        db.add(host)
        db.flush()
        db.add(
            ComputeInventoryItem(
                host_id=host.id,
                external_id="backup-fake123",
                name="backup-fake123",
                kind="backup",
                status="enabled",
                metadata_json='{"id":"backup-fake123","comment":"  Plex media backup\\n nightly  ","schedule":"01:00"}',
            )
        )
        db.commit()

        jobs = proxmox_backup_jobs(db)

        assert jobs[0]["name"] == "Plex media backup nightly"
        assert jobs[0]["job_id"] == "backup-fake123"


def test_proxmox_backup_jobs_fall_back_to_job_id_without_a_comment():
    with database() as db:
        host = ComputeHost(name="PVE test host", platform="proxmox", base_url="https://pve.invalid")
        db.add(host)
        db.flush()
        db.add(
            ComputeInventoryItem(
                host_id=host.id,
                external_id="backup-fallback456",
                name="backup-fallback456",
                kind="backup",
                status="enabled",
                metadata_json='{"id":"backup-fallback456","comment":"   "}',
            )
        )
        db.commit()

        jobs = proxmox_backup_jobs(db)

        assert jobs[0]["name"] == "backup-fallback456"
        assert jobs[0]["job_id"] is None
