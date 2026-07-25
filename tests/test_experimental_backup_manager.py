import asyncio
import json
from datetime import datetime, timezone
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
from app.services.compute_monitor import (
    proxmox_backup_task_job_id,
    proxmox_backup_task_status,
    proxmox_matching_backup_task,
)
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


def test_proxmox_backup_history_uses_authoritative_job_id_with_overlapping_vmids():
    jobs = [
        {"id": "job-daily-local", "vmid": "100,101", "storage": "local"},
        {"id": "job-daily-pbs", "vmid": "100,102", "storage": "pbs"},
    ]
    tasks = [
        {
            "id": "100",
            "upid": "UPID:pve:latest-unrelated:vzdump:100:root@pam:",
            "starttime": 4000,
            "exitstatus": "OK",
        },
        {
            "id": "100",
            "job-id": "job-daily-local",
            "trigger": "manual",
            "upid": "UPID:pve:manual:vzdump:100:root@pam:",
            "starttime": 3000,
            "exitstatus": "ERROR",
        },
        {
            "id": "100",
            "trigger": "scheduled",
            "upid": "UPID:pve:pbs:vzdump:100:root@pam:",
            "starttime": 2000,
            "exitstatus": "OK",
            "_log": [{"n": 1, "t": "Job 'job-daily-pbs' triggered by schedule 'daily'."}],
        },
        {
            "id": "100",
            "trigger": "scheduled",
            "upid": "UPID:pve:local-old:vzdump:100:root@pam:",
            "starttime": 1000,
            "exitstatus": "OK",
            "_log": [{"n": 1, "t": "Job 'job-daily-local' triggered by schedule 'daily'."}],
        },
    ]

    local_task = proxmox_matching_backup_task(jobs[0], tasks)
    pbs_task = proxmox_matching_backup_task(jobs[1], tasks)

    assert local_task["upid"] == "UPID:pve:manual:vzdump:100:root@pam:"
    assert proxmox_backup_task_status(local_task) == "failed"
    assert pbs_task["upid"] == "UPID:pve:pbs:vzdump:100:root@pam:"
    assert proxmox_backup_task_status(pbs_task) == "successful"


def test_proxmox_backup_history_sorts_actual_execution_timestamp_and_preserves_warning():
    tasks = [
        {"job_id": "job-a", "upid": "UPID:old", "starttime": 100, "exitstatus": "OK"},
        {"backup-job": "job-a", "upid": "UPID:new", "starttime": "300", "status": "stopped", "exitstatus": "WARNINGS: 1"},
        {"backup_job": "job-a", "upid": "UPID:middle", "starttime": 200, "exitstatus": "ERROR"},
    ]

    matched = proxmox_matching_backup_task({"id": "job-a", "vmid": "100"}, tasks)

    assert matched["upid"] == "UPID:new"
    assert proxmox_backup_task_status(matched) == "warning"


def test_proxmox_backup_history_uses_direct_last_run_upid_relationship():
    tasks = [
        {"job-id": "job-a", "upid": "UPID:newest-by-id", "starttime": 300, "exitstatus": "OK"},
        {"upid": "UPID:authoritative", "starttime": 400, "exitstatus": "ERROR"},
    ]

    matched = proxmox_matching_backup_task(
        {"id": "job-a", "last-run-upid": "UPID:authoritative"},
        tasks,
    )

    assert matched["upid"] == "UPID:authoritative"
    assert proxmox_backup_task_status(matched) == "failed"


def test_proxmox_backup_history_recognises_manual_job_id_log_and_no_history():
    manual = {
        "upid": "UPID:manual",
        "starttime": 123,
        "_log": [{"t": "INFO: starting new backup job: vzdump 100 --job-id 'job-manual' --storage local"}],
    }

    assert proxmox_backup_task_job_id(manual) == "job-manual"
    assert proxmox_matching_backup_task({"id": "job-manual"}, [manual]) is manual
    assert proxmox_matching_backup_task({"id": "job-never-ran"}, [manual]) is None
    assert proxmox_backup_task_status(None) is None


def test_proxmox_backup_jobs_display_unknown_without_execution_history():
    with database() as db:
        host = ComputeHost(name="PVE no history", platform="proxmox", base_url="https://pve.invalid")
        db.add(host)
        db.flush()
        db.add(
            ComputeInventoryItem(
                host_id=host.id,
                external_id="job-never-ran",
                name="job-never-ran",
                kind="backup",
                status="enabled",
                metadata_json='{"id":"job-never-ran","last_task":null,"last_status":null}',
            )
        )
        db.commit()

        job = proxmox_backup_jobs(db)[0]

        assert job["last_run_at"] is None
        assert job["last_status"] == "unknown"


def test_proxmox_backup_jobs_use_task_execution_time_not_inventory_refresh_time():
    execution_epoch = int(datetime(2026, 7, 25, 7, 15, tzinfo=timezone.utc).timestamp())
    with database() as db:
        host = ComputeHost(name="PVE timestamp", platform="proxmox", base_url="https://pve.invalid")
        db.add(host)
        db.flush()
        db.add(
            ComputeInventoryItem(
                host_id=host.id,
                external_id="job-timestamp",
                name="job-timestamp",
                kind="backup",
                status="enabled",
                last_seen_at=datetime(2026, 7, 25, 12, 0),
                metadata_json=json.dumps(
                    {
                        "id": "job-timestamp",
                        "last_task": {
                            "upid": "UPID:pve:task",
                            "starttime": execution_epoch,
                            "exitstatus": "OK",
                        },
                        "last_status": "successful",
                    }
                ),
            )
        )
        db.commit()

        job = proxmox_backup_jobs(db)[0]

        assert job["last_run_at"] == datetime(2026, 7, 25, 7, 15)
        assert job["last_run_at"] != datetime(2026, 7, 25, 12, 0)
        assert job["last_status"] == "successful"
