import json
import re
import subprocess
import sys
from datetime import datetime, timezone

CHECKSUM = re.compile(r"^[a-f0-9]{64}$")
HELPER = "/usr/lib/kaya-ha-agent/kaya_ha_failover_helper.py"
MAX_EPOCH = 2**31 - 1


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
    # The newest DHCP authority epoch this node has seen (Kaya uses it to detect a restored database).
    store("dhcp_authority_epoch", _epoch_or_none(status.get("authority_epoch")))
    authority_state = status.get("authority_state")
    store("dhcp_authority_state", authority_state if authority_state in {"HELD", "RELEASED", "REVOKED", "VOIDED", "FAILED"} else None)
    store("dhcp_guard_mode", status.get("guard_mode") if status.get("guard_mode") in {"normal", "dns_only"} else None)


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
    authority_epoch = action.get("authority_epoch")
    if action_type == "DHCP_PROMOTE" and (
        not isinstance(authority_epoch, int) or isinstance(authority_epoch, bool) or not 1 <= authority_epoch <= MAX_EPOCH
    ):
        raise FailoverRuntimeError("Kaya supplied no valid DHCP authority for this promotion.")
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
    state.set("failover_authority_epoch", authority_epoch if action_type == "DHCP_PROMOTE" else 0)
    for key, value in _lease_handover(action).items():
        state.set(f"failover_{key}", value)
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


def _epoch_or_none(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_EPOCH else None


def _lease_handover(action):
    """Kaya's lease instruction for a promotion, validated.  Anything unrecognised is a transfer,
    which installs only a verified snapshot (never keeps leases on the strength of bad input)."""
    source = action.get("lease_source")
    return {
        "lease_mode": "continue" if action.get("lease_mode") == "continue" else "transfer",
        "lease_source": source if isinstance(source, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", source) else None,
        "previous_epoch": _epoch_or_none(action.get("previous_epoch")),
        "holder_since": _epoch_or_none(action.get("holder_since")),
    }


def _adopt_if_serving(state, epoch, runner):
    """This node holds authority and already serves DHCP, but its own record does not show the grant
    (authority was established, not promoted): record it.  Never enables or changes DHCP."""
    serving = all(state.get(key) is True for key in ("dhcp_listener_active", "dhcp_running", "dhcp_configured"))
    if not serving or (state.get("dhcp_authority_epoch") == epoch and state.get("dhcp_authority_state") == "HELD"):
        return None
    result = runner(["sudo", "-n", HELPER, "adopt", str(epoch)])
    _log_action("dhcp_authority_adopted", epoch=epoch, return_code=result.returncode,
                stdout=_diagnostic_text(result.stdout), stderr=_diagnostic_text(result.stderr))
    if result.returncode == 0:
        state.set("dhcp_authority_epoch", epoch)
        state.set("dhcp_authority_state", "HELD")
    return None  # never fatal: without the record DHCP still runs; an FTL restart then waits for Kaya


def enforce_dhcp_authority(state, view, *, runner=_run):
    """Release DHCP if this node serves it while Kaya names another holder.  Only ever disables.

    Runs every agent cycle, independent of Keepalived hooks, so a resumed frozen host or a node
    returning from a partition stops serving as soon as it reaches Kaya.  No view (Kaya unreachable,
    or authority not yet established after an upgrade) means no action.
    """
    if not isinstance(view, dict):
        return None
    epoch, holder = view.get("epoch"), view.get("holder")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or not 1 <= epoch <= MAX_EPOCH or not isinstance(holder, bool):
        raise FailoverRuntimeError("Kaya supplied an invalid DHCP authority.")
    if holder:
        return _adopt_if_serving(state, epoch, runner)
    serving = any(state.get(key) is True for key in ("dhcp_listener_active", "dhcp_running", "dhcp_configured"))
    if not serving:
        return None
    result = runner(["sudo", "-n", HELPER, "revoke", str(epoch)])
    _log_action("dhcp_authority_revoked", epoch=epoch, return_code=result.returncode,
                stdout=_diagnostic_text(result.stdout), stderr=_diagnostic_text(result.stderr))
    try:
        output = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        output = {}
    if result.returncode or output.get("status") != "applied":
        raise FailoverRuntimeError("DHCP could not be released after Kaya named another authority holder.")
    if output.get("configured") in {True, False}:
        state.set("dhcp_configured", output["configured"])
    if output.get("listening") in {True, False}:
        state.set("dhcp_listener_active", output["listening"])
    state.set("dhcp_running", False)
    return output
