import os
import platform
import shutil
import sqlite3
import sys
from importlib import metadata
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.models import AuditLog, CustomField, HardwareAsset, IPAddress, Licence, ManagedListItem, NetworkMonitor, RemoteAccess, User
from app.services.version import version_status

PACKAGE_NAMES = [
    "fastapi",
    "starlette",
    "uvicorn",
    "jinja2",
    "sqlalchemy",
    "pydantic-settings",
    "cryptography",
    "pandas",
    "openpyxl",
    "asyncssh",
    "qrcode",
]


def human_bytes(value: int | None) -> str:
    if value is None:
        return "unknown"
    size = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"


def directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def sqlite_path(database_url: str) -> Path | None:
    if not database_url.startswith("sqlite"):
        return None
    parsed = urlparse(database_url)
    if parsed.path:
        return Path(parsed.path)
    return None


def sqlite_version() -> str:
    try:
        return sqlite3.sqlite_version
    except Exception:
        return "unknown"


def package_versions() -> list[dict[str, str]]:
    rows = [{"name": "Python", "version": platform.python_version()}, {"name": "SQLite", "version": sqlite_version()}]
    for name in PACKAGE_NAMES:
        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError:
            version = "not installed"
        rows.append({"name": name, "version": version})
    return rows


def proc_first_value(path: Path, prefix: str) -> str | None:
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith(prefix):
                return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def memory_info() -> dict[str, str]:
    meminfo = Path("/proc/meminfo")
    total = proc_first_value(meminfo, "MemTotal")
    available = proc_first_value(meminfo, "MemAvailable")
    if not total:
        return {"total": "unknown", "available": "unknown", "used": "unknown"}
    total_kb = int(total.split()[0])
    available_kb = int(available.split()[0]) if available else 0
    used_kb = max(total_kb - available_kb, 0)
    return {
        "total": human_bytes(total_kb * 1024),
        "available": human_bytes(available_kb * 1024),
        "used": human_bytes(used_kb * 1024),
    }


def uptime() -> str:
    try:
        seconds = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        return "unknown"
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def cpu_info() -> dict[str, str | int]:
    model = proc_first_value(Path("/proc/cpuinfo"), "model name") or platform.processor() or "unknown"
    try:
        load_average = " / ".join(f"{value:.2f}" for value in os.getloadavg())
    except (AttributeError, OSError):
        load_average = "unknown"
    return {
        "model": model,
        "architecture": platform.machine() or "unknown",
        "logical_cores": os.cpu_count() or 0,
        "load_average": load_average,
    }


def disk_info(path: Path) -> dict[str, str]:
    target = path if path.exists() else Path("/")
    try:
        total, used, free = shutil.disk_usage(target)
    except OSError:
        return {"total": "unknown", "used": "unknown", "free": "unknown"}
    return {"total": human_bytes(total), "used": human_bytes(used), "free": human_bytes(free)}


def storage_rows() -> list[dict[str, str]]:
    settings = get_settings()
    db_path = sqlite_path(settings.database_url)
    upload_path = Path(settings.upload_dir)
    data_path = db_path.parent if db_path else Path("/app/data")
    static_path = Path("app/static")
    app_path = Path("app")
    rows = [
        {"label": "Database", "size": human_bytes(directory_size(db_path)) if db_path else "external database"},
        {"label": "Uploads", "size": human_bytes(directory_size(upload_path))},
        {"label": "Data directory", "size": human_bytes(directory_size(data_path))},
        {"label": "Static assets", "size": human_bytes(directory_size(static_path))},
        {"label": "Application files", "size": human_bytes(directory_size(app_path))},
    ]
    return rows


def module_counts(db: Session) -> list[dict[str, str | int]]:
    return [
        {"label": "License Keys", "count": db.query(Licence).count()},
        {"label": "IP Addresses", "count": db.query(IPAddress).count()},
        {"label": "Hardware Assets", "count": db.query(HardwareAsset).count()},
        {"label": "Network Monitors", "count": db.query(NetworkMonitor).count()},
        {"label": "Remote Records", "count": db.query(RemoteAccess).count()},
        {"label": "Users", "count": db.query(User).count()},
        {"label": "Custom Fields", "count": db.query(CustomField).count()},
        {"label": "Categories", "count": db.query(ManagedListItem).count()},
        {"label": "Audit Logs", "count": db.query(AuditLog).count()},
    ]


def collect_about(db: Session) -> dict:
    settings = get_settings()
    version = version_status()
    db_path = sqlite_path(settings.database_url)
    data_path = db_path.parent if db_path else Path("/app/data")
    return {
        "version": version,
        "app": {
            "name": settings.app_name,
            "environment": settings.app_env,
            "repository": settings.github_repo,
            "database": "SQLite" if settings.database_url.startswith("sqlite") else "External database",
        },
        "system": {
            "hostname": platform.node() or "unknown",
            "os": f"{platform.system()} {platform.release()}".strip(),
            "platform": platform.platform(),
            "uptime": uptime(),
            "executable": Path(sys.executable).name,
        },
        "cpu": cpu_info(),
        "memory": memory_info(),
        "disk": disk_info(data_path),
        "storage_rows": storage_rows(),
        "packages": package_versions(),
        "module_counts": module_counts(db),
    }
