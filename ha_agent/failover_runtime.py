import json
import re
import subprocess
import sys
from datetime import datetime, timezone

CHECKSUM = re.compile(r"^[a-f0-9]{64}$")
HELPER = "/usr/lib/kaya-ha-agent/kaya_ha_failover_helper.py"


class FailoverRuntimeError(ValueError):
    pass


def _run(command):
    return subprocess.run(
        command, capture_output=True, text=True, timeout=60, check=False
    )


def _diagnostic_text(value):
    return " ".join(str(value or "").split())[:500]


def _log_action(event, **details):
    safe = {"component": "kaya-ha-agent", "event": event}
    safe.update({key: value for key, value in details.items() if value is not None})
    print(
        json.dumps(safe, sort_keys=True, separators=(",", ":")),
        file=sys.stderr,
        flush=True,
    )


def refresh_dhcp_state(state, *, runner=_run):
    store = getattr(state, "set_telemetry", state.set)
    result = runner(["sudo", "-n", HELPER, "status"])
    observed_at = datetime.now(timezone.utc).isoformat()
    try:
        status = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        status = {}
    if result.returncode or status.get("observation_status") != "FRESH":
        store("dhcp_configured", None)
        store("dhcp_listener_active", None)
        store("ftl_active", None)
        store("dhcp_runtime_state", "UNKNOWN")
        store("dhcp_observation_status", "UNAVAILABLE")
        store("dhcp_observed_at", observed_at)
        return
    configured = status.get("configured")
    listening = status.get("listening")
    service_active = status.get("service_active")
    runtime_state = str(status.get("runtime_state") or "UNKNOWN")
    if (
        configured not in {True, False}
        or listening not in {True, False}
        or service_active not in {True, False}
        or runtime_state not in {"RUNNING", "STOPPED"}
    ):
        raise FailoverRuntimeError("Pi-hole DHCP state returned invalid evidence.")
    store("dhcp_configured", configured)
    store("dhcp_listener_active", listening)
    store("ftl_active", service_active)
    store("dhcp_runtime_state", runtime_state)
    store("dhcp_observation_status", "FRESH")
    store("dhcp_observed_at", observed_at)
    store("dhcp_running", runtime_state == "RUNNING")


def apply_failover_action(state, action, *, runner=_run):
    action_type, generation, checksum = (
        action.get("action_type"),
        int(action.get("generation") or 0),
        action.get("checksum"),
    )
    if (
        action_type not in {"DHCP_DEMOTE", "DHCP_PROMOTE"}
        or generation < 1
        or not CHECKSUM.fullmatch(str(checksum or ""))
    ):
        raise FailoverRuntimeError("Kaya supplied an invalid DHCP transition action.")
    if action.get("automatic") is not False or generation < int(
        state.get("failover_generation", 0)
    ):
        raise FailoverRuntimeError("Automatic or stale DHCP transitions are rejected.")
    configuration_only = action.get("configuration_only", False)
    if not isinstance(configuration_only, bool) or (
        configuration_only and action_type != "DHCP_PROMOTE"
    ):
        raise FailoverRuntimeError("Kaya supplied an invalid DHCP repair scope.")
    owner_handover_authorised = action.get("owner_handover_authorised", False)
    if not isinstance(owner_handover_authorised, bool):
        raise FailoverRuntimeError(
            "Kaya supplied an invalid DHCP owner-handover authorisation."
        )
    if (
        action_type == "DHCP_DEMOTE"
        and bool(state.get("dhcp_running", False))
        and (
            not owner_handover_authorised
            or not (
                str(action.get("run_id") or "").strip()
                or str(action.get("maintenance_run_id") or "").strip()
            )
        )
    ):
        raise FailoverRuntimeError(
            "Refusing to disable DHCP on the current sole owner without a verified atomic handover."
        )
    if (
        action_type == "DHCP_DEMOTE"
        and state.get("vip_owned") is True
        and state.get("observed_role") == "ACTIVE"
        and not owner_handover_authorised
    ):
        raise FailoverRuntimeError(
            "Rejecting stale DHCP demotion because this node currently owns the VIP."
        )
    if (
        action_type == "DHCP_PROMOTE"
        and (state.get("vip_owned") is not True or state.get("observed_role") != "ACTIVE")
    ):
        raise FailoverRuntimeError(
            "Rejecting stale DHCP promotion because this node no longer owns the VIP."
        )
    _log_action(
        "dhcp_action_received",
        action_type=action_type,
        generation=generation,
        action_id=str(action.get("action_id") or "")[:80],
        configuration_only=configuration_only,
        owner_handover_authorised=owner_handover_authorised,
    )
    state.set("failover_generation", generation)
    state.set("failover_lease_generation", int(action.get("lease_generation") or 0))
    state.set("failover_restore_original", bool(action.get("restore_original", False)))
    state.set("failover_configuration_only", configuration_only)
    command = "demote" if action_type == "DHCP_DEMOTE" else "promote"
    result = runner(["sudo", "-n", HELPER, command, str(generation)])
    _log_action(
        "dhcp_helper_completed",
        action_type=action_type,
        generation=generation,
        return_code=result.returncode,
        stdout=_diagnostic_text(result.stdout),
        stderr=_diagnostic_text(result.stderr),
    )
    try:
        output = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise FailoverRuntimeError(
            f"The DHCP helper returned an invalid response (return code {result.returncode}; stderr: {_diagnostic_text(result.stderr) or 'empty'})."
        ) from exc
    if result.returncode or output.get("status") != "applied":
        raise FailoverRuntimeError(
            f"{str(output.get('message') or 'The DHCP transition failed.')[:500]} "
            f"(return code {result.returncode}; stderr: {_diagnostic_text(result.stderr) or 'empty'})."
        )
    state.set("dhcp_configured", output.get("configured"))
    state.set("dhcp_listener_active", output.get("listening"))
    state.set("ftl_active", output.get("service_active"))
    state.set("dhcp_runtime_state", str(output.get("runtime_state") or "UNKNOWN"))
    state.set(
        "dhcp_observation_status",
        str(output.get("observation_status") or "UNAVAILABLE"),
    )
    state.set("dhcp_observed_at", datetime.now(timezone.utc).isoformat())
    if output.get("dhcp_running") in {True, False}:
        state.set("dhcp_running", output["dhcp_running"])
    message = (
        f"{action_type} executed with return code {result.returncode}; "
        f"dhcp.active={str(output.get('configured')).lower()}, "
        f"FTL active={str(output.get('service_active')).lower()}, "
        f"UDP/67 listening={str(output.get('listening')).lower()}, "
        f"runtime={str(output.get('runtime_state') or 'UNKNOWN')}."
    )
    return {
        "action_id": action["action_id"],
        "action_type": action_type,
        "generation": generation,
        "status": "APPLIED",
        "checksum": checksum,
        "backup_reference": output.get("backup_reference"),
        "message": message,
    }
