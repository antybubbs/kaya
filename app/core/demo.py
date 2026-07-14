from pathlib import Path

from app.core.config import get_settings


DEMO_ACCOUNTS = {
    "admin": {"email": "admin@demo.local", "password": "Admin", "role": "admin"},
    "editor": {"email": "editor@demo.local", "password": "Editor", "role": "editor"},
    "viewer": {"email": "viewer@demo.local", "password": "Viewer", "role": "viewer"},
}


def demo_login_email(value: str) -> str:
    clean = value.strip().lower()
    account = DEMO_ACCOUNTS.get(clean)
    return account["email"] if account else clean


def demo_generation() -> str:
    if not get_settings().demo_mode:
        return ""
    try:
        return Path(get_settings().demo_generation_file).read_text(encoding="utf-8").strip()
    except OSError:
        return "initial"


def demo_request_is_blocked(method: str, path: str) -> bool:
    if not get_settings().demo_mode:
        return False

    clean_path = path.rstrip("/") or "/"
    if clean_path.startswith(("/remote-manager/", "/infrastructure/backup-manager/api/agent")):
        return True

    protected_prefixes = (
        "/setup",
        "/profile/",
        "/team/users",
        "/admin/security",
        "/system/site-administration",
        "/remote-manager",
        "/infrastructure/backup-manager",
        "/networking/dns-manager/investigations",
        "/networking/dns-manager/known-hostnames",
        "/networking/dns-manager/blocklists/update",
        "/networking/dns-manager/insights/analyse",
        "/networking/dns-manager/insights/",
    )
    if method.upper() not in {"GET", "HEAD", "OPTIONS"} and path.startswith(protected_prefixes):
        return True

    network_actions = (
        "/security/public-ip",
        "/security/inbound",
        "/ping",
        "/check",
        "/check-now",
        "/refresh",
        "/lookup",
        "/sync",
        "/rdp/start",
        "/agent/checkin",
        "/agent/token",
    )
    if any(path.endswith(action) or action in path for action in network_actions):
        return True

    return False
