import asyncio
import http.client
import json
import logging
import re
import shlex
import socket
import ssl
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.parse import quote
from urllib.request import Request, urlopen
from app.core.security import decrypt_secret
from app.db.session import SessionLocal
from app.models.models import (
    ComputeEvent,
    ComputeHost,
    ComputeInventoryItem,
    ComputeMetric,
    ComputeWorkload,
)

logger = logging.getLogger(__name__)
PROXMOX_BACKUP_LOG_INSPECTION_LIMIT = 100
PROXMOX_BACKUP_GROUP_WINDOW_SECONDS = 300


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=15)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect(self.path)


def request_json(host, path):
    if host.platform == "docker" and host.base_url.startswith("unix://"):
        c = UnixConnection(host.base_url[7:])
        c.request("GET", path)
        r = c.getresponse()
        data = r.read()
        if r.status >= 400:
            raise RuntimeError(f"Docker API HTTP {r.status}")
        return json.loads(data or b"null")
    headers = {"Accept": "application/json", "User-Agent": "Kaya/ComputeMonitor"}
    if host.platform == "proxmox":
        token = decrypt_secret(host.encrypted_token)
        if not host.token_id or not token or token == "[decryption failed]":
            raise RuntimeError("A valid Proxmox API token is required.")
        headers["Authorization"] = f"PVEAPIToken={host.token_id}={token}"
    context = None
    if host.base_url.startswith("https://"):
        context = (
            ssl.create_default_context()
            if host.verify_tls
            else ssl._create_unverified_context()
        )
    with urlopen(
        Request(host.base_url.rstrip("/") + path, headers=headers),
        timeout=15,
        context=context,
    ) as r:
        return json.loads(r.read() or b"null")


def docker_cpu(stats):
    cur, prev = stats.get("cpu_stats") or {}, stats.get("precpu_stats") or {}
    cpu = (cur.get("cpu_usage") or {}).get("total_usage", 0) - (
        prev.get("cpu_usage") or {}
    ).get("total_usage", 0)
    system = cur.get("system_cpu_usage", 0) - prev.get("system_cpu_usage", 0)
    cpus = cur.get("online_cpus") or 1
    return round(cpu / system * cpus * 100, 2) if cpu > 0 and system > 0 else None


def docker_uptime(started_at):
    if not started_at or str(started_at).startswith("0001-01-01"):
        return None
    try:
        started = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
        now = datetime.now(started.tzinfo) if started.tzinfo else datetime.utcnow()
        return max(0, int((now - started).total_seconds()))
    except (TypeError, ValueError):
        return None


def docker_networks(container, inspect):
    networks = (
        (inspect.get("NetworkSettings") or {}).get("Networks")
        or (container.get("NetworkSettings") or {}).get("Networks")
        or {}
    )
    addresses = []
    compact = {}
    for name, data in networks.items():
        data = data or {}
        network_addresses = []
        for key in ("IPAddress", "GlobalIPv6Address"):
            value = data.get(key)
            if value and value not in network_addresses:
                network_addresses.append(value)
                addresses.append({"address": value, "network": name})
        compact[name] = {
            "addresses": network_addresses,
            "mac_address": data.get("MacAddress"),
        }
    return addresses, compact


def workload_identity(kind, external_id, name):
    if kind == "container" and name:
        return str(name)
    return str(external_id or name)


def reconcile_workload(db, host_id, kind, external_id, name):
    stable_id = workload_identity(kind, external_id, name)
    exact = (
        db.query(ComputeWorkload)
        .filter_by(host_id=host_id, kind=kind, external_id=stable_id)
        .first()
    )
    matches = (
        db.query(ComputeWorkload).filter_by(host_id=host_id, kind=kind, name=name).all()
    )
    row = exact
    if row is None and matches:
        row = max(
            matches,
            key=lambda item: (
                item.status != "missing",
                item.updated_at or item.created_at,
                item.id,
            ),
        )
        row.external_id = stable_id
    created = row is None
    if created:
        row = ComputeWorkload(
            host_id=host_id, kind=kind, external_id=stable_id, name=name
        )
        db.add(row)
        db.flush()
    for duplicate in matches:
        if duplicate.id == row.id:
            continue
        if not row.owner and duplicate.owner:
            row.owner = duplicate.owner
        if not row.backup_policy and duplicate.backup_policy:
            row.backup_policy = duplicate.backup_policy
        db.query(ComputeMetric).filter_by(workload_id=duplicate.id).update(
            {ComputeMetric.workload_id: row.id}, synchronize_session=False
        )
        db.query(ComputeEvent).filter_by(workload_id=duplicate.id).update(
            {ComputeEvent.workload_id: row.id}, synchronize_session=False
        )
        db.delete(duplicate)
    db.flush()
    return row, created


def prune_missing_workloads(db, host_id, now, retention_days=30):
    cutoff = now - timedelta(days=retention_days)
    stale = (
        db.query(ComputeWorkload)
        .filter(
            ComputeWorkload.host_id == host_id,
            ComputeWorkload.status == "missing",
            ComputeWorkload.last_seen_at < cutoff,
        )
        .all()
    )
    for row in stale:
        db.query(ComputeMetric).filter_by(workload_id=row.id).delete(
            synchronize_session=False
        )
        db.query(ComputeEvent).filter_by(workload_id=row.id).delete(
            synchronize_session=False
        )
        db.delete(row)


def record_compute_metrics(db, host, workloads, recorded_at, min_interval_seconds=60):
    """Persist host and workload samples using the normal compute retention cadence."""
    last = (
        db.query(ComputeMetric)
        .filter(
            ComputeMetric.host_id == host.id, ComputeMetric.workload_id.is_(None)
        )
        .order_by(ComputeMetric.recorded_at.desc())
        .first()
    )
    if last and last.recorded_at >= recorded_at - timedelta(seconds=min_interval_seconds):
        return False
    db.add(ComputeMetric(host_id=host.id, cpu_percent=host.cpu_percent, memory_used=host.memory_used, memory_total=host.memory_total, storage_used=host.storage_used, storage_total=host.storage_total, recorded_at=recorded_at))
    for workload in workloads:
        db.add(ComputeMetric(host_id=host.id, workload_id=workload.id, cpu_percent=workload.cpu_percent, memory_used=workload.memory_used, memory_total=workload.memory_total, storage_used=workload.storage_used, storage_total=workload.storage_total, recorded_at=recorded_at))
    return True


def collect_docker(host):
    version = request_json(host, "/version") or {}
    info = request_json(host, "/info") or {}
    containers = request_json(host, "/containers/json?all=1&size=1") or []
    workloads = []
    compose = {}
    for c in containers:
        labels = c.get("Labels") or {}
        project = labels.get("com.docker.compose.project")
        if project:
            compose[project] = {
                "working_dir": labels.get("com.docker.compose.project.working_dir"),
                "config_files": labels.get("com.docker.compose.project.config_files"),
            }
        stats = {}
        inspect = {}
        try:
            inspect = request_json(host, f"/containers/{c.get('Id')}/json") or {}
        except Exception:
            logger.debug(
                "Docker container inspection failed for %s",
                c.get("Id"),
                exc_info=True,
            )
        if c.get("State") == "running":
            try:
                stats = (
                    request_json(host, f"/containers/{c.get('Id')}/stats?stream=false")
                    or {}
                )
            except Exception:
                logger.debug(
                    "Docker container statistics failed for %s",
                    c.get("Id"),
                    exc_info=True,
                )
        mem = stats.get("memory_stats") or {}
        addresses, networks = docker_networks(c, inspect)
        state = inspect.get("State") or {}
        name = (c.get("Names") or [c.get("Id", "")[:12]])[0].lstrip("/")
        workloads.append(
            {
                "external_id": name,
                "name": name,
                "kind": "container",
                "node": host.name,
                "status": c.get("State") or "unknown",
                "cpu_percent": docker_cpu(stats),
                "cpu_total": None,
                "memory_used": mem.get("usage"),
                "memory_total": mem.get("limit"),
                "storage_used": c.get("SizeRw"),
                "storage_total": None,
                "uptime_seconds": (
                    docker_uptime(state.get("StartedAt"))
                    if state.get("Running")
                    else None
                ),
                "tags": project,
                "metadata": {
                    "image": c.get("Image"),
                    "ports": c.get("Ports") or [],
                    "mounts": c.get("Mounts") or [],
                    "summary": c.get("Status"),
                    "ip_addresses": addresses,
                    "networks": networks,
                },
            }
        )
    items = []
    for x in request_json(host, "/images/json") or []:
        items.append(
            {
                "external_id": x.get("Id"),
                "name": (x.get("RepoTags") or ["<untagged>"])[0],
                "kind": "image",
                "status": None,
                "size_bytes": x.get("Size"),
                "metadata": {"tags": x.get("RepoTags") or []},
            }
        )
    for x in request_json(host, "/networks") or []:
        items.append(
            {
                "external_id": x.get("Id") or x.get("Name"),
                "name": x.get("Name"),
                "kind": "network",
                "status": x.get("Scope"),
                "size_bytes": None,
                "metadata": {"driver": x.get("Driver"), "internal": x.get("Internal")},
            }
        )
    for x in (request_json(host, "/volumes") or {}).get("Volumes") or []:
        items.append(
            {
                "external_id": x.get("Name"),
                "name": x.get("Name"),
                "kind": "volume",
                "status": x.get("Scope"),
                "size_bytes": (x.get("UsageData") or {}).get("Size"),
                "metadata": {
                    "driver": x.get("Driver"),
                    "mountpoint": x.get("Mountpoint"),
                },
            }
        )
    for name, meta in compose.items():
        items.append(
            {
                "external_id": name,
                "name": name,
                "kind": "compose",
                "status": "active",
                "size_bytes": None,
                "metadata": meta,
            }
        )
    running = [x for x in workloads if x["status"] == "running"]
    return {
        "version": version.get("Version"),
        "host": {
            "cpu_percent": sum(x.get("cpu_percent") or 0 for x in running),
            "memory_used": sum(x.get("memory_used") or 0 for x in running),
            "memory_total": info.get("MemTotal"),
            "storage_used": None,
            "storage_total": None,
            "metadata": {
                "os": info.get("OperatingSystem"),
                "kernel": info.get("KernelVersion"),
                "cpus": info.get("NCPU"),
            },
        },
        "workloads": workloads,
        "items": items,
    }


def pve(host, path):
    data = request_json(host, "/api2/json" + path)
    return data.get("data") if isinstance(data, dict) else data


def proxmox_guest_addresses(host, node_name, endpoint, guest):
    vmid = guest.get("vmid")
    addresses = []
    if not vmid or guest.get("status") != "running":
        return addresses
    try:
        if endpoint == "qemu":
            result = (
                pve(
                    host, f"/nodes/{node_name}/qemu/{vmid}/agent/network-get-interfaces"
                )
                or {}
            )
            interfaces = result.get("result") if isinstance(result, dict) else result
            for interface in interfaces or []:
                name = interface.get("name")
                for item in interface.get("ip-addresses") or []:
                    value = item.get("ip-address")
                    if value:
                        addresses.append({"address": value, "interface": name})
        else:
            interfaces = pve(host, f"/nodes/{node_name}/lxc/{vmid}/interfaces") or []
            for interface in interfaces:
                name = interface.get("name")
                for key in ("inet", "inet6"):
                    value = interface.get(key)
                    if value:
                        addresses.append(
                            {"address": str(value).split("/")[0], "interface": name}
                        )
    except Exception:
        logger.debug("Guest-agent address discovery failed", exc_info=True)
    return addresses


def proxmox_backup_task_job_id(task):
    """Return an explicit job identifier when a Proxmox version provides one."""
    if not isinstance(task, dict):
        return None
    for key in ("job-id", "job_id", "backup-job", "backup_job"):
        value = task.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()

    log_rows = task.get("_log") or []
    for row in log_rows:
        text = row.get("t") if isinstance(row, dict) else row
        text = str(text or "")
        scheduled = re.search(r"\bJob '([^']+)' triggered by schedule\b", text)
        if scheduled:
            return scheduled.group(1)
        explicit = re.search(
            r"(?:^|\s)--?job-id(?:=|\s+)(?:'([^']+)'|\"([^\"]+)\"|(\S+))", text
        )
        if explicit:
            return next(value for value in explicit.groups() if value)
    return None


def proxmox_backup_task_log(host, task):
    node = str(task.get("node") or "").strip()
    upid = str(task.get("upid") or "").strip()
    if not node or not upid:
        return []
    return (
        pve(
            host,
            f"/nodes/{quote(node,safe='')}/tasks/{quote(upid,safe='')}/log?start=0&limit=50",
        )
        or []
    )


def proxmox_backup_vmids(value):
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = re.split(r"[\s,;]+", str(value).strip())
    return {str(item).strip() for item in values if str(item).strip().isdigit()}


def proxmox_backup_task_signature(task):
    """Parse the non-secret vzdump invocation recorded in the task log."""
    signature = {
        "node": str(task.get("node") or "").strip(),
        "storage": None,
        "mode": None,
        "vmids": set(),
    }
    for row in task.get("_log") or []:
        text = row.get("t") if isinstance(row, dict) else row
        match = re.search(
            r"\bstarting new backup job:\s*vzdump(?:\s+(.*))?$",
            str(text or ""),
            re.IGNORECASE,
        )
        if not match:
            continue
        try:
            tokens = shlex.split(match.group(1) or "", posix=True)
        except ValueError:
            return signature
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token.startswith("--"):
                option, value = (
                    (token[2:].split("=", 1) + [None])[:2]
                    if "=" in token
                    else (token[2:], None)
                )
                if (
                    value is None
                    and index + 1 < len(tokens)
                    and not tokens[index + 1].startswith("--")
                ):
                    index += 1
                    value = tokens[index]
                if option in {"storage", "mode", "node"} and value:
                    signature[option] = str(value).strip()
                elif option in {"vmid", "exclude"} and value and option == "vmid":
                    signature["vmids"].update(proxmox_backup_vmids(value))
            elif token.isdigit():
                signature["vmids"].add(token)
            index += 1
        break
    if not signature["vmids"]:
        signature["vmids"] = proxmox_backup_vmids(task.get("id"))
    return signature


def proxmox_backup_job_signature(job):
    return {
        "node": str(job.get("node") or "").strip(),
        "storage": str(job.get("storage") or "").strip(),
        "mode": str(job.get("mode") or "").strip(),
        "vmids": proxmox_backup_vmids(job.get("_included_vmids") or job.get("vmid")),
    }


def _proxmox_backup_signature_reason(job_signature, task_signature, allow_subset=False):
    if job_signature["node"] and task_signature["node"] != job_signature["node"]:
        return f"node differs ({task_signature['node'] or '-'})"
    if not task_signature["storage"]:
        return "task log exposes no storage"
    if job_signature["storage"] != task_signature["storage"]:
        return f"storage differs ({task_signature['storage']})"
    if job_signature["mode"] and not task_signature["mode"]:
        return "task log exposes no backup mode"
    if job_signature["mode"] and job_signature["mode"] != task_signature["mode"]:
        return f"backup mode differs ({task_signature['mode']})"
    if not job_signature["vmids"]:
        return "configured VM/CT set is unavailable"
    if not task_signature["vmids"]:
        return "task VM/CT set is unavailable"
    if allow_subset and task_signature["vmids"].issubset(job_signature["vmids"]):
        return None
    if task_signature["vmids"] != job_signature["vmids"]:
        return "VM/CT set differs"
    return None


def proxmox_backup_tasks(host, node_names=None, job_ids=None, return_diagnostics=False):
    tasks = []
    seen = set()
    endpoint_successes = 0
    endpoint_failures = 0
    for path in [
        "/cluster/tasks?typefilter=vzdump&limit=500",
        *[
            f"/nodes/{node}/tasks?typefilter=vzdump&limit=500"
            for node in (node_names or [])
        ],
    ]:
        try:
            rows = pve(host, path) or []
            endpoint_successes += 1
        except Exception as exc:
            endpoint_failures += 1
            logger.debug(
                "Proxmox backup task endpoint unavailable host_id=%s path=%s error=%s",
                host.id,
                path,
                type(exc).__name__,
            )
            continue
        for task in rows:
            identity = (
                task.get("upid")
                or f"{task.get('node')}:{task.get('starttime')}:{task.get('type')}:{task.get('id')}"
            )
            if identity in seen:
                continue
            seen.add(identity)
            tasks.append(task)
    tasks = sorted(
        tasks, key=lambda item: int(item.get("starttime") or 0), reverse=True
    )

    for task in tasks:
        logger.debug(
            "Raw Proxmox vzdump task host_id=%s upid=%s id=%s type=%s worker_id=%s "
            "user=%s starttime=%s endtime=%s status=%s node=%s",
            host.id,
            task.get("upid"),
            task.get("id"),
            task.get("type"),
            task.get("worker_id") or task.get("worker-id"),
            task.get("user"),
            task.get("starttime"),
            task.get("endtime"),
            task.get("exitstatus") or task.get("status"),
            task.get("node"),
        )

    log_attempts = 0
    log_successes = 0
    log_failures = 0
    if job_ids:
        for task in tasks[:PROXMOX_BACKUP_LOG_INSPECTION_LIMIT]:
            log_attempts += 1
            try:
                task["_log"] = proxmox_backup_task_log(host, task)
                log_successes += 1
            except Exception as exc:
                log_failures += 1
                logger.debug(
                    "Unable to inspect Proxmox backup task log node=%s upid=%s error=%s",
                    task.get("node"),
                    task.get("upid"),
                    type(exc).__name__,
                )

    diagnostics = {
        "task_history_available": endpoint_successes > 0,
        "task_count": len(tasks),
        "endpoint_failures": endpoint_failures,
        "task_logs_available": log_successes > 0 if log_attempts else None,
        "log_failures": log_failures,
        "log_inspection_truncated": len(tasks) > PROXMOX_BACKUP_LOG_INSPECTION_LIMIT,
        "unmatched_job_ids": [],
    }
    if endpoint_successes == 0:
        diagnostics["state"] = "unavailable"
        diagnostics["warning"] = "task_history_unavailable"
    elif log_attempts and log_successes == 0:
        diagnostics["state"] = "unavailable"
        diagnostics["warning"] = "task_logs_unavailable"
    else:
        diagnostics["state"] = "available"
        diagnostics["warning"] = None
    return (tasks, diagnostics) if return_diagnostics else tasks


def proxmox_backup_task_status(task):
    if not task:
        return None
    status = str(task.get("exitstatus") or task.get("status") or "").strip()
    if not status:
        return "running"
    normalized = status.upper()
    if normalized in {"RUNNING", "ACTIVE"}:
        return "running"
    if normalized == "OK":
        return "successful"
    if "WARN" in normalized or "PARTIAL" in normalized:
        return "warning"
    return "failed"


def proxmox_backup_execution_candidates(
    job, tasks, window_seconds=PROXMOX_BACKUP_GROUP_WINDOW_SECONDS
):
    authoritative_upid = next(
        (
            str(job.get(key)).strip()
            for key in ("last-run-upid", "last_run_upid")
            if job.get(key) is not None and str(job.get(key)).strip()
        ),
        None,
    )
    if authoritative_upid:
        direct = next(
            (
                task
                for task in tasks
                if str(task.get("upid") or "") == authoritative_upid
            ),
            None,
        )
        return [direct] if direct else []
    job_id = str(job.get("id") or "").strip()
    authoritative = [
        task for task in tasks if job_id and proxmox_backup_task_job_id(task) == job_id
    ]
    if authoritative:
        return authoritative
    job_signature = proxmox_backup_job_signature(job)
    exact = []
    members = []
    for task in tasks:
        signature = proxmox_backup_task_signature(task)
        if _proxmox_backup_signature_reason(job_signature, signature) is None:
            exact.append(task)
        elif (
            len(signature["vmids"]) == 1
            and _proxmox_backup_signature_reason(
                job_signature, signature, allow_subset=True
            )
            is None
        ):
            members.append((task, signature))
    groups = []
    members.sort(key=lambda pair: int(pair[0].get("starttime") or 0))
    for task, signature in members:
        started = int(task.get("starttime") or 0)
        current = groups[-1] if groups else None
        if (
            not current
            or started - int(current[0][0].get("starttime") or 0) > window_seconds
        ):
            groups.append([(task, signature)])
        else:
            current.append((task, signature))
    for group in groups:
        if (
            set().union(*(signature["vmids"] for _, signature in group))
            != job_signature["vmids"]
        ):
            continue
        group_tasks = [task for task, _ in group]
        statuses = [proxmox_backup_task_status(task) for task in group_tasks]
        if any(status == "running" for status in statuses):
            aggregate = "RUNNING"
        elif all(status == "successful" for status in statuses):
            aggregate = "OK"
        elif all(status == "failed" for status in statuses):
            aggregate = "ERROR"
        else:
            aggregate = "WARNINGS"
        exact.append(
            {
                "upid": group_tasks[0].get("upid"),
                "member_upids": [task.get("upid") for task in group_tasks],
                "node": group_tasks[0].get("node"),
                "starttime": min(
                    int(task.get("starttime") or 0) for task in group_tasks
                ),
                "endtime": max(
                    int(task.get("endtime") or task.get("starttime") or 0)
                    for task in group_tasks
                ),
                "exitstatus": aggregate,
                "_grouped": True,
            }
        )
    return exact


def proxmox_matching_backup_task(job, tasks):
    return max(
        proxmox_backup_execution_candidates(job, tasks),
        key=lambda item: int(item.get("starttime") or 0),
        default=None,
    )


def proxmox_backup_task_match_reason(job, task):
    job_id = str(job.get("id") or "").strip()
    authoritative_upid = next(
        (
            str(job.get(key)).strip()
            for key in ("last-run-upid", "last_run_upid")
            if job.get(key) is not None and str(job.get(key)).strip()
        ),
        None,
    )
    task_upid = str(task.get("upid") or "")
    if authoritative_upid and task_upid == authoritative_upid:
        return True, "authoritative UPID match"
    task_job_id = proxmox_backup_task_job_id(task)
    if task_job_id and job_id and task_job_id != job_id:
        return False, f"task backup job ID is {task_job_id!r}"
    reason = _proxmox_backup_signature_reason(
        proxmox_backup_job_signature(job), proxmox_backup_task_signature(task)
    )
    if reason:
        return False, reason
    return True, "exact node/storage/mode/VM-CT execution signature"


def collect_proxmox(host):
    version = pve(host, "/version") or {}
    resources = pve(host, "/cluster/resources") or []
    node_names = sorted(
        {x.get("node") for x in resources if x.get("type") == "node" and x.get("node")}
    )
    seen = {
        (
            x.get("type"),
            str(x.get("id") or x.get("vmid") or x.get("node") or x.get("storage")),
        )
        for x in resources
    }
    for node_name in node_names:
        try:
            node_status = pve(host, f"/nodes/{node_name}/status") or {}
            node_row = next(
                (
                    x
                    for x in resources
                    if x.get("type") == "node" and x.get("node") == node_name
                ),
                None,
            )
            if node_row is not None:
                memory = node_status.get("memory") or {}
                rootfs = node_status.get("rootfs") or {}
                cpuinfo = node_status.get("cpuinfo") or {}
                node_row.update(
                    {
                        "cpu": node_status.get("cpu", node_row.get("cpu")),
                        "maxcpu": cpuinfo.get("cpus")
                        or node_status.get("cpuinfo", {}).get("cpus")
                        or node_row.get("maxcpu"),
                        "mem": memory.get("used", node_row.get("mem")),
                        "maxmem": memory.get("total", node_row.get("maxmem")),
                        "disk": rootfs.get("used", node_row.get("disk")),
                        "maxdisk": rootfs.get("total", node_row.get("maxdisk")),
                        "uptime": node_status.get("uptime", node_row.get("uptime")),
                    }
                )
        except Exception:
            logger.debug(
                "Proxmox node detail collection failed for %s",
                node_name,
                exc_info=True,
            )
        for endpoint, kind in (("qemu", "qemu"), ("lxc", "lxc")):
            try:
                for guest in pve(host, f"/nodes/{node_name}/{endpoint}") or []:
                    guest["_ip_addresses"] = proxmox_guest_addresses(
                        host, node_name, endpoint, guest
                    )
                    key = (kind, str(kind) + "/" + str(guest.get("vmid")))
                    existing = next(
                        (
                            item
                            for item in resources
                            if (
                                item.get("type"),
                                str(
                                    item.get("id")
                                    or item.get("vmid")
                                    or item.get("node")
                                    or item.get("storage")
                                ),
                            )
                            == key
                        ),
                        None,
                    )
                    if existing is not None:
                        existing.update(guest)
                    else:
                        guest.update(
                            {
                                "type": kind,
                                "node": node_name,
                                "id": f'{kind}/{guest.get("vmid")}',
                            }
                        )
                        if guest.get("maxcpu") is None:
                            guest["maxcpu"] = guest.get("cpus")
                        resources.append(guest)
                        seen.add(key)
            except Exception:
                logger.debug(
                    "Proxmox %s guest collection failed for %s",
                    kind,
                    node_name,
                    exc_info=True,
                )
        try:
            for storage in pve(host, f"/nodes/{node_name}/storage") or []:
                key = (
                    "storage",
                    "storage/" + str(node_name) + "/" + str(storage.get("storage")),
                )
                if key not in seen:
                    storage.update(
                        {
                            "type": "storage",
                            "node": node_name,
                            "id": f'storage/{node_name}/{storage.get("storage")}',
                            "disk": storage.get("used"),
                            "maxdisk": storage.get("total"),
                            "plugintype": storage.get("type"),
                            "status": (
                                "available" if storage.get("active", 1) else "offline"
                            ),
                        }
                    )
                    resources.append(storage)
                    seen.add(key)
        except Exception:
            logger.debug(
                "Proxmox storage collection failed for %s",
                node_name,
                exc_info=True,
            )
    workloads = []
    items = []
    nodes = []
    for x in resources:
        kind = x.get("type")
        if kind == "node":
            nodes.append(x)
        if kind in {"node", "qemu", "lxc"}:
            workloads.append(
                {
                    "external_id": str(x.get("vmid") or x.get("node") or x.get("id")),
                    "name": x.get("name") or x.get("node") or x.get("id"),
                    "kind": "vm" if kind == "qemu" else kind,
                    "node": x.get("node"),
                    "status": x.get("status") or "unknown",
                    "cpu_percent": round(float(x.get("cpu") or 0) * 100, 2),
                    "cpu_total": float(x.get("maxcpu") or x.get("cpus") or 0),
                    "memory_used": x.get("mem"),
                    "memory_total": x.get("maxmem"),
                    "storage_used": x.get("disk"),
                    "storage_total": x.get("maxdisk"),
                    "uptime_seconds": x.get("uptime"),
                    "tags": x.get("tags"),
                    "metadata": {
                        "id": x.get("id"),
                        "pool": x.get("pool"),
                        "template": x.get("template"),
                        "ip_addresses": x.get("_ip_addresses") or [],
                    },
                }
            )
        elif kind == "storage":
            items.append(
                {
                    "external_id": x.get("id"),
                    "name": x.get("storage") or x.get("id"),
                    "kind": "storage",
                    "status": x.get("status"),
                    "size_bytes": x.get("maxdisk"),
                    "metadata": {
                        "node": x.get("node"),
                        "used": x.get("disk"),
                        "type": x.get("plugintype"),
                    },
                }
            )
    try:
        jobs = pve(host, "/cluster/backup") or []
    except Exception:
        logger.debug("Proxmox backup-job collection failed", exc_info=True)
        jobs = []
    for job in jobs:
        job_id = str(job.get("id") or "").strip()
        if not job_id:
            continue
        try:
            included = (
                pve(host, f"/cluster/backup/{quote(job_id,safe='')}/included_volumes")
                or {}
            )
            job["_included_vmids"] = [
                str(guest.get("id"))
                for guest in included.get("children") or []
                if isinstance(guest, dict) and str(guest.get("id") or "").isdigit()
            ]
        except Exception as exc:
            logger.debug(
                "Unable to read included VM/CT set for Proxmox backup job host_id=%s job_id=%s error=%s",
                host.id,
                job_id,
                type(exc).__name__,
            )
    backup_tasks, backup_history = proxmox_backup_tasks(
        host,
        node_names,
        [job.get("id") for job in jobs if job.get("id") is not None],
        return_diagnostics=True,
    )
    unmatched_job_ids = []
    for x in jobs:
        signature = proxmox_backup_job_signature(x)
        logger.debug(
            "Configured Proxmox backup job host_id=%s job_id=%s node=%s schedule=%s "
            "storage=%s mode=%s vmids=%s",
            host.id,
            x.get("id"),
            signature["node"] or "*",
            x.get("schedule"),
            signature["storage"],
            signature["mode"],
            sorted(signature["vmids"]),
        )
        for candidate in backup_tasks:
            matched, reason = proxmox_backup_task_match_reason(x, candidate)
            logger.debug(
                "Proxmox backup candidate configured_job_id=%s upid=%s type=%s id=%s "
                "worker_id=%s status=%s match_result=%s rejection_reason=%s",
                x.get("id"),
                candidate.get("upid"),
                candidate.get("type"),
                candidate.get("id"),
                candidate.get("worker_id") or candidate.get("worker-id"),
                candidate.get("exitstatus") or candidate.get("status"),
                matched,
                None if matched else reason,
            )
        task = proxmox_matching_backup_task(x, backup_tasks)
        if not task:
            unmatched_job_ids.append(str(x.get("id") or ""))
        if task:
            task = {key: value for key, value in task.items() if key != "_log"}
        task_status = proxmox_backup_task_status(task)
        logger.debug(
            "Proxmox backup correlation host_id=%s proxmox_job_id=%s matched_upid=%s "
            "execution_timestamp=%s status=%s",
            host.id,
            x.get("id"),
            task.get("upid") if task else None,
            task.get("starttime") if task else None,
            task_status or "unknown",
        )
        metadata = {**x, "last_task": task, "last_status": task_status}
        eid = str(
            x.get("id")
            or f"{x.get('storage')}:{x.get('schedule')}:{x.get('vmid','all')}"
        )
        items.append(
            {
                "external_id": eid,
                "name": x.get("id") or f"Backup to {x.get('storage','storage')}",
                "kind": "backup",
                "status": "enabled" if x.get("enabled", 1) else "disabled",
                "size_bytes": None,
                "metadata": metadata,
            }
        )
    backup_history["unmatched_job_ids"] = unmatched_job_ids
    cpu = (
        sum(float(x.get("cpu") or 0) * 100 for x in nodes) / len(nodes)
        if nodes
        else None
    )
    limited = bool(nodes) and not any(x.get("maxmem") for x in nodes)
    warning = (
        "Connected, but the API token cannot read node capacity or guests. Assign PVEAuditor to the API token at / with Propagate enabled."
        if limited
        else None
    )
    return {
        "version": version.get("version"),
        "warning": warning,
        "host": {
            "cpu_percent": round(cpu, 2) if cpu is not None else None,
            "memory_used": sum(x.get("mem") or 0 for x in nodes),
            "memory_total": sum(x.get("maxmem") or 0 for x in nodes),
            "storage_used": sum(x.get("disk") or 0 for x in nodes),
            "storage_total": sum(x.get("maxdisk") or 0 for x in nodes),
            "metadata": {
                "release": version.get("release"),
                "nodes": len(nodes),
                "backup_history": backup_history,
            },
        },
        "workloads": workloads,
        "items": items,
    }


def sync_host(db, host):
    if host.platform == "docker_agent":
        return

    now = datetime.utcnow()
    host_id = host.id
    old_host_status = host.status
    network_host = SimpleNamespace(
        id=host.id,
        name=host.name,
        platform=host.platform,
        base_url=host.base_url,
        token_id=host.token_id,
        encrypted_token=host.encrypted_token,
        verify_tls=host.verify_tls,
    )
    # Collection can span many bounded API calls. End the ORM read transaction
    # and use only the minimal detached connection snapshot during provider I/O.
    db.rollback()
    try:
        result = (
            collect_docker(network_host)
            if network_host.platform == "docker"
            else collect_proxmox(network_host)
        )
        host = db.get(ComputeHost, host_id)
        if host is None or not host.is_enabled:
            return
        snap = result["host"]
        host.status = "online"
        host.version = result.get("version")
        host.last_error = result.get("warning")
        for key in (
            "cpu_percent",
            "memory_used",
            "memory_total",
            "storage_used",
            "storage_total",
        ):
            setattr(host, key, snap.get(key))
        host.metadata_json = json.dumps(snap.get("metadata") or {})
        seen = set()
        for data in result["workloads"]:
            row, created = reconcile_workload(
                db, host.id, data["kind"], data["external_id"], data["name"]
            )
            if created:
                db.add(
                    ComputeEvent(
                        host_id=host.id,
                        workload_id=row.id,
                        event_type="discovered",
                        detail=f"Discovered {data['kind']} {data['name']}",
                    )
                )
            elif row.status != data["status"]:
                db.add(
                    ComputeEvent(
                        host_id=host.id,
                        workload_id=row.id,
                        event_type="state_change",
                        detail=f"{row.name}: {row.status} -> {data['status']}",
                    )
                )
            for key in (
                "name",
                "node",
                "status",
                "cpu_percent",
                "cpu_total",
                "memory_used",
                "memory_total",
                "storage_used",
                "storage_total",
                "uptime_seconds",
                "tags",
            ):
                setattr(row, key, data.get(key))
            row.metadata_json = json.dumps(data.get("metadata") or {})
            row.last_seen_at = now
            row.updated_at = now
            seen.add((row.kind, row.external_id))
        for row in db.query(ComputeWorkload).filter_by(host_id=host.id).all():
            if (row.kind, row.external_id) not in seen and row.status != "missing":
                row.status = "missing"
                db.add(
                    ComputeEvent(
                        host_id=host.id,
                        workload_id=row.id,
                        event_type="missing",
                        detail=f"{row.name} is no longer reported",
                    )
                )
        prune_missing_workloads(db, host.id, now)
        db.query(ComputeInventoryItem).filter_by(host_id=host.id).delete(
            synchronize_session=False
        )
        inventory_seen = set()
        for data in result["items"]:
            key = (data["kind"], data["external_id"])
            if key in inventory_seen:
                continue
            inventory_seen.add(key)
            db.add(
                ComputeInventoryItem(
                    host_id=host.id,
                    external_id=data["external_id"],
                    name=data["name"],
                    kind=data["kind"],
                    status=data.get("status"),
                    size_bytes=data.get("size_bytes"),
                    metadata_json=json.dumps(data.get("metadata") or {}),
                    last_seen_at=now,
                )
            )
        record_compute_metrics(
            db,
            host,
            db.query(ComputeWorkload)
            .filter_by(host_id=host.id)
            .filter(ComputeWorkload.last_seen_at == now)
            .all(),
            now,
        )
        if old_host_status != "online":
            db.add(
                ComputeEvent(
                    host_id=host.id,
                    event_type="host_online",
                    detail=f"{host.name} is online",
                )
            )
    except Exception as exc:
        # A failed flush/statement poisons the SQLAlchemy transaction. Reset
        # it before loading the host for the bounded offline-state update;
        # otherwise the recovery path raises PendingRollbackError and hides
        # the original contention failure.
        db.rollback()
        host = db.get(ComputeHost, host_id)
        if host is None:
            return
        host.status = "offline"
        host.last_error = str(exc)[:2000]
        if old_host_status != "offline":
            db.add(
                ComputeEvent(
                    host_id=host.id,
                    event_type="host_offline",
                    detail=f"{host.name}: {str(exc)[:500]}",
                )
            )
    host.last_synced_at = now
    host.updated_at = now
    db.query(ComputeMetric).filter(
        ComputeMetric.recorded_at < now - timedelta(days=7)
    ).delete(synchronize_session=False)
    db.query(ComputeEvent).filter(
        ComputeEvent.created_at < now - timedelta(days=90)
    ).delete(synchronize_session=False)
    db.commit()


def sync_host_by_id(host_id):
    db = SessionLocal()
    try:
        host = db.get(ComputeHost, host_id)
        if host and host.is_enabled and host.platform != "docker_agent":
            sync_host(db, host)
    except Exception:
        logger.exception("Compute host synchronisation failed for host %s", host_id)
        db.rollback()
    finally:
        db.close()


async def compute_monitor_loop():
    await asyncio.sleep(20)

    while True:
        db = SessionLocal()
        now = datetime.utcnow()
        try:
            ids = [
                h.id
                for h in db.query(ComputeHost).filter_by(is_enabled=True).all()
                if h.platform != "docker_agent"
                and (
                    not h.last_synced_at
                    or h.last_synced_at
                    <= now
                    - timedelta(seconds=max(15, min(h.poll_interval_seconds, 3600)))
                )
            ]
        finally:
            db.close()

        if ids:
            await asyncio.gather(
                *(asyncio.to_thread(sync_host_by_id, i) for i in ids[:3]),
                return_exceptions=True,
            )

        await asyncio.sleep(5)


def compute_summary(db):
    hosts = db.query(ComputeHost).all()
    workloads = (
        db.query(ComputeWorkload)
        .filter(
            ComputeWorkload.kind.in_(["container", "vm", "lxc"]),
            ComputeWorkload.status != "missing",
        )
        .all()
    )
    running = {"running", "up"}
    stopped = {"stopped", "exited", "down"}
    def pct(used, total):
        return (
            round(used / total * 100, 1) if used is not None and total else None
        )
    cpu = [h.cpu_percent for h in hosts if h.cpu_percent is not None]
    mu = sum(h.memory_used or 0 for h in hosts)
    mt = sum(h.memory_total or 0 for h in hosts)
    su = sum(h.storage_used or 0 for h in hosts)
    st = sum(h.storage_total or 0 for h in hosts)
    return {
        "hosts": len(hosts),
        "online_hosts": sum(h.status == "online" for h in hosts),
        "workloads": len(workloads),
        "running": sum(w.status.lower() in running for w in workloads),
        "stopped": sum(w.status.lower() in stopped for w in workloads),
        "warnings": sum(h.status == "offline" for h in hosts)
        + sum(w.status.lower() not in running | stopped for w in workloads),
        "cpu_percent": round(sum(cpu) / len(cpu), 1) if cpu else None,
        "memory_percent": pct(mu, mt),
        "storage_percent": pct(su, st),
        "updated_at": max(
            (h.last_synced_at for h in hosts if h.last_synced_at), default=None
        ),
    }
