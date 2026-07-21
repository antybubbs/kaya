import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Callable


HELPER_PATH = "/usr/lib/kaya-ha-agent/kaya_ha_keepalived_helper.py"
FORBIDDEN_CONFIG_MARKERS = (";", "`", "$", "|", "&&", ">", "<", "include ")


class KeepalivedRuntimeError(RuntimeError):
    pass


def command_diagnostic(completed: subprocess.CompletedProcess, limit: int = 700) -> str:
    output = (completed.stderr or "").strip() or (completed.stdout or "").strip()
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    output = " ".join("".join(character for character in output if character.isprintable() or character.isspace()).split())
    return output[:limit]


def atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, 0o600); os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def validate_desired_configuration(action: dict) -> bytes:
    if action.get("action_type") != "KEEPALIVED_APPLY" or action.get("dhcp_transition") != "DISABLED":
        raise KeepalivedRuntimeError("Unsupported or unsafe desired action.")
    content = action.get("configuration")
    checksum = action.get("checksum")
    if not isinstance(content, str) or not content.startswith("# Managed by Kaya High Availability. Do not edit.\n") or len(content.encode()) > 32 * 1024:
        raise KeepalivedRuntimeError("Keepalived configuration is not a valid Kaya-managed document.")
    if any(marker in content for marker in FORBIDDEN_CONFIG_MARKERS):
        raise KeepalivedRuntimeError("Keepalived configuration contains a forbidden directive or shell marker.")
    required = ("global_defs {", "script_user kaya-ha kaya-ha", "enable_script_security", "vrrp_script KAYA_DNS_", "vrrp_instance KAYA_HA_", "state BACKUP", "virtual_router_id ", "virtual_ipaddress {", "notify_master \"/usr/lib/kaya-ha-agent/kaya_ha_transition.py master ", "notify_backup \"/usr/lib/kaya-ha-agent/kaya_ha_transition.py backup ", "notify_fault \"/usr/lib/kaya-ha-agent/kaya_ha_transition.py fault ")
    if any(content.count(marker) != 1 for marker in required):
        raise KeepalivedRuntimeError("Keepalived configuration does not match the fixed Kaya structure.")
    actual = hashlib.sha256(content.encode()).hexdigest()
    if actual != checksum:
        raise KeepalivedRuntimeError("Keepalived configuration checksum verification failed.")
    return content.encode()


def apply_desired_keepalived(state, action: dict, *, runner: Callable = subprocess.run) -> dict:
    generation = int(action.get("generation") or 0)
    current = int(state.get("config_generation", 0))
    if generation < current:
        raise KeepalivedRuntimeError("Rejected stale Keepalived generation.")
    if generation == current and state.get("keepalived_checksum") == action.get("checksum"):
        return {"action_id": action["action_id"], "action_type": "KEEPALIVED_APPLY", "generation": generation, "status": "APPLIED", "checksum": action["checksum"], "backup_reference": state.get("keepalived_backup_reference"), "message": "Keepalived generation was already applied."}
    pending = state.root / "pending-keepalived.conf"
    atomic_bytes(pending, validate_desired_configuration(action))
    try:
        completed = runner(["sudo", "-n", HELPER_PATH, "apply", str(pending)], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KeepalivedRuntimeError("The restricted Keepalived helper could not be executed.") from exc
    try:
        output = json.loads((completed.stdout or "{}").strip())
    except json.JSONDecodeError as exc:
        detail = command_diagnostic(completed)
        raise KeepalivedRuntimeError(
            "The restricted Keepalived helper did not return a valid result."
            + (f" Diagnostic: {detail}" if detail else "")
        ) from exc
    if completed.returncode != 0 or not output.get("ok"):
        return {"action_id": action["action_id"], "action_type": "KEEPALIVED_APPLY", "generation": generation, "status": "FAILED", "checksum": None, "backup_reference": output.get("backup_reference"), "message": str(output.get("message") or "Keepalived validation or activation failed and was rolled back.")[:1000]}
    state.set("config_generation", generation)
    state.set("keepalived_generation", generation)
    state.set("keepalived_checksum", action["checksum"])
    state.set("keepalived_backup_reference", output.get("backup_reference"))
    state.set("keepalived_runtime_state", "RUNNING")
    return {"action_id": action["action_id"], "action_type": "KEEPALIVED_APPLY", "generation": generation, "status": "APPLIED", "checksum": action["checksum"], "backup_reference": output.get("backup_reference"), "message": "Generated Keepalived configuration validated and activated."}


def refresh_vip_state(state, *, runner: Callable = subprocess.run) -> None:
    vip = state.get("desired_virtual_ip")
    if not vip:
        return
    try:
        completed = runner(["sudo", "-n", HELPER_PATH, "status", str(vip).split("/", 1)[0]], capture_output=True, text=True, timeout=10, check=False)
        output = json.loads((completed.stdout or "{}").strip())
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        state.set("keepalived_runtime_state", "UNKNOWN")
        return
    state.set("keepalived_runtime_state", str(output.get("runtime_state") or "UNKNOWN"))
    state.set("vip_owned", bool(output.get("vip_owned")))
