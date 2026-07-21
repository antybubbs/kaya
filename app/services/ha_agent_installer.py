import hashlib
from pathlib import Path


AGENT_ROOT = Path(__file__).resolve().parents[2] / "ha_agent"
PUBLIC_AGENT_FILES = frozenset({
    "install.sh",
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
