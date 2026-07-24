import json, re, subprocess

CHECKSUM = re.compile(r"^[a-f0-9]{64}$")
HELPER = "/usr/lib/kaya-ha-agent/kaya_ha_failover_helper.py"

class FailoverRuntimeError(ValueError): pass

def _run(command): return subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)

def refresh_dhcp_state(state, *, runner=_run):
    result = runner(["sudo", "-n", HELPER, "status"])
    if result.returncode: raise FailoverRuntimeError("Pi-hole DHCP state could not be read.")
    state.set("dhcp_running", bool(json.loads(result.stdout)["dhcp_running"]))

def apply_failover_action(state, action, *, runner=_run):
    action_type, generation, checksum = action.get("action_type"), int(action.get("generation") or 0), action.get("checksum")
    if action_type not in {"DHCP_DEMOTE", "DHCP_PROMOTE"} or generation < 1 or not CHECKSUM.fullmatch(str(checksum or "")):
        raise FailoverRuntimeError("Kaya supplied an invalid DHCP transition action.")
    if action.get("automatic") is not False or generation < int(state.get("failover_generation", 0)):
        raise FailoverRuntimeError("Automatic or stale DHCP transitions are rejected.")
    state.set("failover_generation", generation); state.set("failover_lease_generation", int(action.get("lease_generation") or 0)); state.set("failover_restore_original", bool(action.get("restore_original", False)))
    command = "demote" if action_type == "DHCP_DEMOTE" else "promote"
    result = runner(["sudo", "-n", HELPER, command, str(generation)])
    try: output = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc: raise FailoverRuntimeError("The DHCP helper returned an invalid response.") from exc
    if result.returncode or output.get("status") != "applied": raise FailoverRuntimeError(str(output.get("message") or "The DHCP transition failed."))
    state.set("dhcp_running", bool(output.get("dhcp_running")))
    return {"action_id": action["action_id"], "action_type": action_type, "generation": generation, "status": "APPLIED", "checksum": checksum, "backup_reference": output.get("backup_reference"), "message": "The controlled DHCP transition was applied and verified."}
