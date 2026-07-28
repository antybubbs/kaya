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
from app.routers.backup_manager import (
    agent_jobs,
    hash_agent_token,
    proxmox_backup_history_warnings,
    proxmox_backup_jobs,
    require_backup_user,
)
from app.services.compute_monitor import (
    proxmox_backup_execution_candidates,
    proxmox_backup_task_match_reason,
    proxmox_backup_task_signature,
    proxmox_backup_task_status,
    proxmox_backup_tasks,
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


def vzdump_task(upid, starttime, vmids, *, storage="local", mode="snapshot", status="OK", node="pve"):
    command = f"INFO: starting new backup job: vzdump {' '.join(str(vmid) for vmid in vmids)} --storage {storage} --mode {mode}"
    return {
        "id": str(vmids[0]) if len(vmids) == 1 else "",
        "upid": upid,
        "node": node,
        "type": "vzdump",
        "starttime": starttime,
        "endtime": starttime + 60,
        "status": status,
        "_log": [{"n": 1, "t": command}],
    }


def test_proxmox_backup_task_signature_parses_raw_vzdump_command():
    task = vzdump_task("UPID:pve:raw", 100, [118, 129, 123], storage="QNAPBU_PVE")

    assert proxmox_backup_task_signature(task) == {
        "node": "pve",
        "storage": "QNAPBU_PVE",
        "mode": "snapshot",
        "vmids": {"118", "129", "123"},
    }


def test_proxmox_backup_history_uses_exact_signature_with_overlapping_vmids():
    jobs = [
        {"id": "job-a", "vmid": "100,101", "storage": "local", "mode": "snapshot", "node": "pve"},
        {"id": "job-b", "vmid": "100,102", "storage": "local", "mode": "snapshot", "node": "pve"},
    ]
    tasks = [
        vzdump_task("UPID:pve:only-overlap", 4000, [100]),
        vzdump_task("UPID:pve:job-a", 3000, [100, 101]),
        vzdump_task("UPID:pve:job-b", 2000, [100, 102]),
    ]

    assert proxmox_matching_backup_task(jobs[0], tasks)["upid"] == "UPID:pve:job-a"
    assert proxmox_matching_backup_task(jobs[1], tasks)["upid"] == "UPID:pve:job-b"
    matched, reason = proxmox_backup_task_match_reason(jobs[0], tasks[0])
    assert matched is False
    assert reason == "VM/CT set differs"


def test_proxmox_backup_history_selects_newest_scheduled_or_manual_execution():
    job = {"id": "job-a", "vmid": "100,101", "storage": "local", "mode": "snapshot"}
    tasks = [
        vzdump_task("UPID:pve:scheduled", 100, [100, 101]),
        vzdump_task("UPID:pve:manual", 300, [100, 101], status="ERROR"),
        vzdump_task("UPID:pve:middle", 200, [100, 101]),
    ]

    matched = proxmox_matching_backup_task(job, tasks)

    assert matched["upid"] == "UPID:pve:manual"
    assert matched["starttime"] == 300
    assert proxmox_backup_task_status(matched) == "failed"


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


def test_proxmox_backup_history_groups_member_tasks_and_aggregates_status():
    job = {"id": "job-group", "vmid": "100,101,102", "storage": "local", "mode": "snapshot"}
    successful = [
        vzdump_task("UPID:pve:100", 100, [100]),
        vzdump_task("UPID:pve:101", 160, [101]),
        vzdump_task("UPID:pve:102", 220, [102]),
    ]
    partial = [
        vzdump_task("UPID:pve:new-100", 1000, [100]),
        vzdump_task("UPID:pve:new-101", 1060, [101], status="ERROR"),
        vzdump_task("UPID:pve:new-102", 1120, [102]),
    ]

    executions = proxmox_backup_execution_candidates(job, successful + partial)
    matched = proxmox_matching_backup_task(job, successful + partial)

    assert len(executions) == 2
    assert proxmox_backup_task_status(executions[0]) == "successful"
    assert matched["starttime"] == 1000
    assert matched["member_upids"] == ["UPID:pve:new-100", "UPID:pve:new-101", "UPID:pve:new-102"]
    assert proxmox_backup_task_status(matched) == "warning"


def test_proxmox_backup_history_does_not_group_tasks_outside_window():
    job = {"vmid": "100,101", "storage": "local", "mode": "snapshot"}
    tasks = [vzdump_task("UPID:100", 100, [100]), vzdump_task("UPID:101", 401, [101])]

    assert proxmox_matching_backup_task(job, tasks) is None
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


def test_proxmox_backup_task_rejection_explains_missing_signature_fields():
    matched, reason = proxmox_backup_task_match_reason(
        {"id": "backup-fake-job", "vmid": "100", "storage": "local", "mode": "snapshot"},
        {"upid": "UPID:pve:fake:vzdump::root@pam:", "id": "", "type": "vzdump"},
    )

    assert matched is False
    assert reason == "task log exposes no storage"


def test_proxmox_backup_tasks_report_node_history_available_when_cluster_endpoint_fails(monkeypatch):
    host = type("Host", (), {"id": 7})()
    task = {
        "upid": "UPID:pve:fake:vzdump::root@pam:",
        "id": "",
        "type": "vzdump",
        "starttime": 100,
        "status": "OK",
        "node": "pve",
    }

    def fake_pve(_host, path):
        if path.startswith("/cluster/tasks"):
            raise RuntimeError("fake unsupported endpoint")
        if path.startswith("/nodes/pve/tasks?"):
            return [task]
        if path.endswith("/log?start=0&limit=50"):
            return [{"t": "INFO: starting new backup job: vzdump 100"}]
        raise AssertionError(path)

    monkeypatch.setattr("app.services.compute_monitor.pve", fake_pve)

    tasks, diagnostics = proxmox_backup_tasks(
        host,
        ["pve"],
        ["backup-fake-job"],
        return_diagnostics=True,
    )

    assert tasks == [task]
    assert diagnostics["task_history_available"] is True
    assert diagnostics["task_logs_available"] is True
    assert diagnostics["warning"] is None


@pytest.mark.parametrize("warning_code", ["task_history_unavailable", "task_logs_unavailable"])
def test_proxmox_backup_history_problem_is_visible_above_table(warning_code):
    with database() as db:
        host = ComputeHost(
            name="PVE warning host",
            platform="proxmox",
            base_url="https://pve.invalid",
            metadata_json=json.dumps({"backup_history": {"warning": warning_code}}),
        )
        db.add(host)
        db.commit()

        warnings = proxmox_backup_history_warnings(db)

        assert warnings[0]["host"] == "PVE warning host"
        assert warnings[0]["detail"]

    page = Path("app/templates/backup_manager.html").read_text(encoding="utf-8")
    assert "Backup execution history unavailable." in page


def test_missing_explicit_job_id_is_not_an_unavailable_warning():
    with database() as db:
        host = ComputeHost(
            name="PVE readable",
            platform="proxmox",
            base_url="https://pve.invalid",
            metadata_json=json.dumps(
                {"backup_history": {"warning": "task_correlation_unavailable"}}
            ),
        )
        db.add(host)
        db.flush()
        db.add(
            ComputeInventoryItem(
                host_id=host.id,
                external_id="backup-fake-job",
                name="backup-fake-job",
                kind="backup",
                status="enabled",
                metadata_json='{"id":"backup-fake-job","last_task":null,"last_status":null}',
            )
        )
        db.commit()

        job = proxmox_backup_jobs(db)[0]

        assert job["last_run_at"] is None
        assert job["last_status"] == "unknown"
        assert proxmox_backup_history_warnings(db) == []


def test_successful_empty_history_is_available_and_jobs_remain_unknown(monkeypatch):
    host = type("Host", (), {"id": 8})()

    def fake_pve(_host, path):
        if path.startswith("/cluster/tasks") or path.startswith("/nodes/pve/tasks?"):
            return []
        raise AssertionError(path)

    monkeypatch.setattr("app.services.compute_monitor.pve", fake_pve)
    tasks, diagnostics = proxmox_backup_tasks(host, ["pve"], ["backup-fake"], return_diagnostics=True)

    assert tasks == []
    assert diagnostics["task_history_available"] is True
    assert diagnostics["warning"] is None


def test_denied_task_history_is_reported_as_unavailable(monkeypatch):
    host = type("Host", (), {"id": 9})()

    def fake_pve(_host, _path):
        raise PermissionError("fake Proxmox task audit denial")

    monkeypatch.setattr("app.services.compute_monitor.pve", fake_pve)
    tasks, diagnostics = proxmox_backup_tasks(host, ["pve"], ["backup-fake"], return_diagnostics=True)

    assert tasks == []
    assert diagnostics["task_history_available"] is False
    assert diagnostics["warning"] == "task_history_unavailable"
