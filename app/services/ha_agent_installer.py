import hashlib
from pathlib import Path


AGENT_ROOT = Path(__file__).resolve().parents[2] / "ha_agent"
CURRENT_AGENT_VERSION = "0.2.5"
PUBLIC_AGENT_FILES = frozenset({
    "install.sh",
    "update.sh",
    "uninstall.sh",
    "kaya_ha_agent.py",
    "keepalived_runtime.py",
    "failover_runtime.py",
    "kaya_ha_failover_helper.py",
    "kaya_ha_keepalived_helper.py",
    "kaya_ha_transition.py",
    "check-pihole-dns",
    "kaya-ha-agent.service",
    "kaya-ha-agent.sudoers",
})


def agent_file(name: str) -> bytes:
    if name not in PUBLIC_AGENT_FILES:
        raise FileNotFoundError(name)
    return (AGENT_ROOT / name).read_bytes()


def installer_checksum() -> str:
    return hashlib.sha256(agent_file("install.sh")).hexdigest()


def updater_checksum() -> str:
    return hashlib.sha256(agent_file("update.sh")).hexdigest()


def uninstaller_checksum() -> str:
    return hashlib.sha256(agent_file("uninstall.sh")).hexdigest()


def version_tuple(value: str | None) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(value or "").split("."))
    except ValueError:
        return ()


def agent_version_status(value: str | None) -> str:
    installed = version_tuple(value)
    current = version_tuple(CURRENT_AGENT_VERSION)
    if not installed:
        return "Not reported"
    if installed < current:
        return "Update available"
    if installed > current:
        return "Newer than Kaya"
    return "Up to date"
