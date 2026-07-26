import hashlib
import json
import re
import subprocess


HELPER = "/usr/lib/kaya-ha-agent/kaya_ha_resolver_helper.py"
CHECKSUM = re.compile(r"^[a-f0-9]{64}$")


class ResolverRuntimeError(ValueError):
    pass


def apply_resolver_action(action, *, runner=subprocess.run):
    vip = str(action.get("virtual_ip") or "")
    interface = str(action.get("network_interface") or "")
    checksum = str(action.get("checksum") or "")
    if action.get("action_type") != "RESOLVER_REPAIR" or not CHECKSUM.fullmatch(checksum):
        raise ResolverRuntimeError("Kaya supplied an invalid resolver repair action.")
    expected = hashlib.sha256(f"{vip}:{interface}:# Managed by Kaya HA\n[Resolve]\nDNS={vip}\nDomains=~.\n".encode()).hexdigest()
    if checksum != expected:
        raise ResolverRuntimeError("The resolver repair checksum did not match the approved action.")
    result = runner(["sudo", "-n", HELPER, "apply", vip, interface, checksum], capture_output=True, text=True, timeout=60, check=False)
    try:
        output = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        output = {}
    return {
        "action_id": action["action_id"], "action_type": "RESOLVER_REPAIR",
        "generation": int(action["generation"]),
        "status": "APPLIED" if result.returncode == 0 and output.get("status") == "applied" else "FAILED",
        "checksum": checksum if result.returncode == 0 else None,
        "backup_reference": output.get("backup_reference"),
        "message": str(output.get("message") or "Resolver repair failed safely.")[:1000],
    }
