import json, re, subprocess
from datetime import datetime, timezone

CHECKSUM = re.compile(r"^[a-f0-9]{64}$")
HELPER = "/usr/lib/kaya-ha-agent/kaya_ha_failover_helper.py"

class FailoverRuntimeError(ValueError): pass

def _run(command): return subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)

def refresh_dhcp_state(state, *, runner=_run):
    result = runner(["sudo", "-n", HELPER, "status"])
    observed_at = datetime.now(timezone.utc).isoformat()
    try:
        status = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        status = {}
    if result.returncode or status.get("observation_status") != "FRESH":
        state.set("dhcp_configured", None)
        state.set("dhcp_listener_active", None)
        state.set("ftl_active", None)
        state.set("dhcp_runtime_state", "UNKNOWN")
        state.set("dhcp_observation_status", "UNAVAILABLE")
        state.set("dhcp_observed_at", observed_at)
        return
    configured = status.get("configured")
    listening = status.get("listening")
    service_active = status.get("service_active")
    runtime_state = str(status.get("runtime_state") or "UNKNOWN")
    if configured not in {True, False} or listening not in {True, False} or service_active not in {True, False} or runtime_state not in {"RUNNING", "STOPPED"}:
        raise FailoverRuntimeError("Pi-hole DHCP state returned invalid evidence.")
    state.set("dhcp_configured", configured)
    state.set("dhcp_listener_active", listening)
    state.set("ftl_active", service_active)
    state.set("dhcp_runtime_state", runtime_state)
    state.set("dhcp_observation_status", "FRESH")
    state.set("dhcp_observed_at", observed_at)
    state.set("dhcp_running", runtime_state == "RUNNING")

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
    state.set("dhcp_configured", output.get("configured"))
    state.set("dhcp_listener_active", output.get("listening"))
    state.set("ftl_active", output.get("service_active"))
    state.set("dhcp_runtime_state", str(output.get("runtime_state") or "UNKNOWN"))
    state.set("dhcp_observation_status", str(output.get("observation_status") or "UNAVAILABLE"))
    state.set("dhcp_observed_at", datetime.now(timezone.utc).isoformat())
    if output.get("dhcp_running") in {True, False}:
        state.set("dhcp_running", output["dhcp_running"])
    return {"action_id": action["action_id"], "action_type": action_type, "generation": generation, "status": "APPLIED", "checksum": checksum, "backup_reference": output.get("backup_reference"), "message": "The controlled DHCP transition was applied and verified."}
