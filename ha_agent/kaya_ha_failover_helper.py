#!/usr/bin/env python3
"""Root-only, fixed-purpose DHCP transition helper for Kaya HA."""

import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import random
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

STATE_ROOT = Path("/var/lib/kaya-ha-agent")
STATE_DB = STATE_ROOT / "state.sqlite3"
SNAPSHOT = STATE_ROOT / "lease-snapshots/current.json"
LEASE_FILE = Path("/etc/pihole/dhcp.leases")
BACKUP_ROOT = STATE_ROOT / "failover-backups"
LOCK_FILE = STATE_ROOT / "failover.lock"
# This node's view of Kaya's DHCP authority: the newest epoch seen and whether it is held.
# It never enables DHCP by itself.  The only thing it allows is keeping DHCP on across a Pi-hole
# FTL restart in the same boot while this node still holds the Virtual IP (see _may_continue).
AUTHORITY_FILE = STATE_ROOT / "dhcp-authority.json"
MAX_EPOCH = 2**31 - 1
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
# DNS-only fallback: if the boot guard cannot make Pi-hole's own configuration safe, this file
# (read by the FTL drop-in with EnvironmentFile=) forces dhcp.active=false through FTL's
# environment, which takes precedence over pihole.toml.  /run is cleared by every reboot.
GUARD_ENV = Path("/run/kaya-ha-dhcp-guard/ftl.env")
GUARD_ENV_CONTENT = "FTLCONF_dhcp_active=false\nKAYA_HA_DHCP_GUARD=dns-only\n"
ENV_KEY = "FTLCONF_dhcp_active"
GUARD_MARKER = "KAYA_HA_DHCP_GUARD"
HELD_STATES = {"HELD", "VOIDED", "RELEASED"}  # this node served under that epoch (never REVOKED)
PROC_UDP = (Path("/proc/net/udp"), Path("/proc/net/udp6"))
FTL, IP = "/usr/bin/pihole-FTL", "/usr/sbin/ip"
MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)
INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
# Before an automatic promotion: broadcast DHCPDISCOVERs on the Virtual IP interface and refuse
# if any other server offers an address.  A few attempts let a peer that is releasing DHCP finish.
PROBE_WINDOW_SECONDS = 2.0
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


def _state(key, default=None):
    with sqlite3.connect(STATE_DB, timeout=5) as db:
        db.execute("PRAGMA busy_timeout=5000")
        row = db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return json.loads(row[0]) if row else default


def _run(command, extra_env=None):
    # FTL reads FTLCONF_* from its own environment, so pihole-FTL --config must never inherit one:
    # it would report (and refuse to change) the environment's value instead of pihole.toml's.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("FTLCONF_")}
    environment.update(extra_env or {})
    return subprocess.run(
        command, capture_output=True, text=True, timeout=20, check=False, env=environment
    )


def _configured_on_disk(extra_env=None):
    """dhcp.active as pihole-FTL --config reports it (pihole.toml, or ``extra_env`` if given)."""
    command = [FTL, "--config", "dhcp.active"]
    result = _run(command, extra_env) if extra_env else _run(command)
    matches = re.findall(r"\b(true|false)\b", result.stdout.lower())
    if result.returncode or not matches:
        return None
    return matches[-1] == "true"


def _ftl_environment_value():
    """FTLCONF_dhcp_active in the running Pi-hole FTL's own environment.

    Returns (found, value): found is False if FTL is not running or no FTL process sets it.  FTL
    gives its environment precedence over pihole.toml, so this is what the running FTL obeys.
    """
    values = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text(encoding="ascii", errors="replace").strip() != "pihole-FTL":
                continue
            if b"--config" in (entry / "cmdline").read_bytes().split(b"\0"):
                continue  # a short-lived pihole-FTL --config call, not the service
            environ = (entry / "environ").read_bytes().split(b"\0")
        except OSError:
            continue  # the process exited while being inspected
        prefix = ENV_KEY.encode() + b"="
        values.append(next((item[len(prefix):].decode("utf-8", "replace") for item in environ if item.startswith(prefix)), None))
    present = [value for value in values if value is not None]
    if not present:
        return False, None
    return True, present[-1].strip().lower()


def _dhcp_active():
    """The dhcp.active the running FTL obeys: its environment if set there, otherwise pihole.toml.

    Only an exact environment value of "false" counts as off; any other value counts as on, so an
    unfamiliar spelling can never make a serving node look released.
    """
    found, value = _ftl_environment_value()
    if found:
        return value != "false"
    return _configured_on_disk()


def _udp_port_bound(port, paths=None):
    """Read the kernel socket table without invoking a shell or a broad helper."""
    inspected = False
    for path in paths or PROC_UDP:
        try:
            lines = path.read_text(encoding="ascii", errors="strict").splitlines()[1:]
        except (FileNotFoundError, OSError, UnicodeError):
            continue
        inspected = True
        for line in lines:
            fields = line.split()
            if len(fields) < 2:
                continue
            try:
                if int(fields[1].rsplit(":", 1)[1], 16) == port:
                    return True
            except (IndexError, ValueError):
                continue
    return False if inspected else None


def _dhcp_status():
    configured = _dhcp_active()
    service = _run(["systemctl", "is-active", "pihole-FTL"])
    service_active = (
        True if service.returncode == 0 else False if service.returncode == 3 else None
    )
    listening = _udp_port_bound(67)
    available = (
        configured is not None and service_active is not None and listening is not None
    )
    # Configuration intent and runtime ownership are deliberately independent.
    # Pi-hole can continue listening on UDP/67 after dhcp.active drifted false;
    # reporting that real listener as stopped can make a second promotion look
    # safe and is therefore more dangerous than reporting the inconsistency.
    running = bool(service_active and listening) if available else None
    local = _read_authority()
    return {
        # Kaya uses the newest epoch a node has seen to detect a restored (older) coordinator database.
        "authority_epoch": local["epoch"] if local else None,
        "authority_state": str(local.get("state") or "")[:20] if local else None,
        "guard_mode": "dns_only" if GUARD_ENV.exists() else "normal",
        "configured": configured,
        "service_active": service_active,
        "listening": listening,
        "runtime_state": (
            "RUNNING"
            if running is True
            else "STOPPED" if running is False else "UNKNOWN"
        ),
        "observation_status": "FRESH" if available else "UNAVAILABLE",
        "dhcp_running": running,
    }


def _wait_for_dhcp(enabled):
    latest = {}
    for _ in range(20):
        latest = _dhcp_status()
        if latest.get("observation_status") != "FRESH":
            time.sleep(1)
            continue
        # Promotion and demotion have deliberately opposite post-conditions.
        # In particular, an already-running listener must never let promotion
        # succeed while Pi-hole still reports dhcp.active=false.
        ready = (
            latest.get("configured") is True
            and latest.get("service_active") is True
            and latest.get("listening") is True
            and latest.get("runtime_state") == "RUNNING"
            if enabled
            else latest.get("configured") is False
            and latest.get("listening") is False
            and latest.get("runtime_state") == "STOPPED"
        )
        if ready:
            return latest
        time.sleep(1)
    if enabled:
        raise RuntimeError(
            "Pi-hole accepted the DHCP setting but did not start serving on UDP port 67. "
            "Check the standby DHCP range, network interface, Pi-hole FTL log, and host firewall."
        )
    raise RuntimeError(
        "Pi-hole accepted the DHCP setting but UDP port 67 is still in use. "
        "DHCP ownership could not be released safely."
    )


def _set_dhcp(enabled):
    before = _dhcp_status()
    result = _run([FTL, "--config", "dhcp.active", "true" if enabled else "false"])
    immediate = _dhcp_active()
    requested = "true" if enabled else "false"
    observed = (
        "true" if immediate is True else "false" if immediate is False else "unknown"
    )
    if result.returncode:
        raise RuntimeError(
            f"Pi-hole DHCP activation command failed with exit code {result.returncode}; "
            f"requested dhcp.active={requested}, immediately observed dhcp.active={observed}, "
            f"stderr_present={bool(result.stderr.strip())}."
        )
    if immediate is not enabled:
        raise RuntimeError(
            f"Pi-hole DHCP command returned success but dhcp.active remained {observed}; "
            f"requested dhcp.active={requested}, stderr_present={bool(result.stderr.strip())}."
        )
    settled = _wait_for_dhcp(enabled)
    settled["activation_command"] = {
        "return_code": result.returncode,
        "before_configured": before.get("configured"),
        "immediate_configured": immediate,
        "settled_configured": settled.get("configured"),
        "stderr_present": bool(result.stderr.strip()),
    }
    return settled


def _configure_dhcp(enabled):
    """Write FTL's persistent dhcp.active setting and verify it (works whether or not FTL runs)."""
    result = _run([FTL, "--config", "dhcp.active", "true" if enabled else "false"])
    # Read back pihole.toml itself: pihole-FTL --config returns 0 even when it could not write
    # the file (read-only filesystem: "content not updated").
    observed = _configured_on_disk()
    if result.returncode or observed is not enabled:
        raise RuntimeError(
            f"Pi-hole dhcp.active could not be set to {str(enabled).lower()} "
            f"(return code {result.returncode}, observed {observed})."
        )
    return enabled


def _read_authority():
    """The local authority record, or None if absent or unreadable (never treated as a grant)."""
    try:
        value = json.loads(AUTHORITY_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("epoch"), int) or isinstance(value.get("epoch"), bool):
        return None
    return value


def _write_authority(record):
    """Atomic, durable replacement (root-only); raises on any filesystem failure."""
    AUTHORITY_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".dhcp-authority.", dir=AUTHORITY_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, AUTHORITY_FILE)
        directory = os.open(AUTHORITY_FILE.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _boot_id():
    try:
        value = BOOT_ID.read_text(encoding="ascii").strip()
    except OSError:
        return None
    return value if re.fullmatch(r"[0-9a-f-]{36}", value) else None


def _address_present(address):
    """True only if ``address`` is assigned to a local interface right now (unknown counts as no)."""
    result = _run([IP, "-j", "address", "show"])
    if result.returncode:
        return False
    try:
        links = json.loads(result.stdout)
    except ValueError:
        return False
    return any(item.get("local") == address for link in links for item in link.get("addr_info", []))


def _may_continue(local):
    """Whether DHCP may stay on across this Pi-hole FTL start (never enables anything).

    Only a restart of FTL itself, in the same boot, on a node that still holds Kaya's grant and
    still holds the Virtual IP.  That is no more than the node was already doing before FTL
    restarted, so it cannot create a second DHCP server.  A reboot, a release, a revoke, a lost
    Virtual IP, or a missing or unreadable record all end it: then only a fresh grant re-enables DHCP.
    """
    if local is None or local.get("state") != "HELD":
        return False, "this node holds no current DHCP grant"
    boot = _boot_id()
    if boot is None or local.get("boot_id") != boot:
        return False, "the host restarted since DHCP authority was granted"
    vip = str(local.get("vip") or "")
    if not vip or not _address_present(vip):
        return False, "this node no longer holds the Virtual IP"
    return True, "same boot, grant still held, Virtual IP still held"


def _environment_forces_dhcp():
    """Whether anything other than Kaya's own fallback sets FTLCONF_dhcp_active for pihole-FTL.

    True, False, or None if it cannot be determined (treated as True by the caller).
    """
    if os.environ.get(ENV_KEY) is not None and os.environ.get(GUARD_MARKER) is None:
        return True  # our own file was not loaded, so the unit's environment sets it
    try:
        result = _run(["systemctl", "show", "pihole-FTL", "--property=Environment",
                       "--property=EnvironmentFiles", "--property=PassEnvironment"])
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode:
        return None
    name = re.compile(r"(^|[\s\"'])" + ENV_KEY + r"(=|[\s\"']|$)")
    assignment = re.compile(r"^\s*(export\s+)?" + ENV_KEY + r"\s*=", re.M)
    for line in result.stdout.splitlines():
        key, _, value = line.partition("=")
        if key in {"Environment", "PassEnvironment"} and name.search(value):
            return True
        if key == "EnvironmentFiles" and value.strip():
            path = Path(value.strip().rsplit(" (", 1)[0].lstrip("-"))
            if path == GUARD_ENV:
                continue
            try:
                if assignment.search(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except FileNotFoundError:
                continue
            except OSError:
                return None
    return False


def _clear_guard_environment():
    try:
        GUARD_ENV.unlink()
    except FileNotFoundError:
        pass


def _force_off_by_environment():
    """DNS-only fallback: FTL starts with dhcp.active forced false through its environment.

    Raises (so FTL does not start) unless the file is written and read back intact and this FTL
    binary confirms that its environment value overrides pihole.toml.
    """
    directory = GUARD_ENV.parent
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise RuntimeError("The DHCP guard directory is not a directory owned and writable only by root.")
    fd, temporary = tempfile.mkstemp(prefix=".ftl.env.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(GUARD_ENV_CONTENT)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, GUARD_ENV)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if GUARD_ENV.read_text(encoding="ascii") != GUARD_ENV_CONTENT:
        raise RuntimeError("The DHCP guard environment file did not read back intact.")
    if _configured_on_disk({ENV_KEY: "false"}) is not False:
        raise RuntimeError("Pi-hole FTL did not confirm that its environment overrides dhcp.active.")


def _boot_guard():
    """Run by systemd before every Pi-hole FTL start.  Never enables anything.

    1. Continuing authority (same boot, grant held, Virtual IP held): leave DHCP as it is.
    2. Otherwise DHCP is turned off in pihole.toml and verified, and the local grant is voided.
    3. If pihole.toml cannot be made safe (read-only, failed write, dhcp.active set by the unit's
       environment), FTL starts DNS-only with DHCP forced off through its environment.
    4. If even that cannot be confirmed, exit non-zero: systemd does not start FTL.
    """
    try:
        STATE_ROOT.mkdir(parents=True, exist_ok=True)
        lock = LOCK_FILE.open("a+")
        fcntl.flock(lock, fcntl.LOCK_EX)
    except OSError:
        lock = None  # a broken state directory must not stop DHCP being disabled
    try:
        local = _read_authority()
        forced = _environment_forces_dhcp()
        continuing, reason = _may_continue(local)
        if continuing and forced is False:
            _clear_guard_environment()
            print(json.dumps({"status": "applied", "mode": "continuing", "epoch": local["epoch"], "reason": reason}))
            return
        try:
            if forced is not False:
                raise RuntimeError("dhcp.active is set by the pihole-FTL unit's environment" if forced
                                   else "the pihole-FTL unit environment could not be inspected")
            _configure_dhcp(False)
            _clear_guard_environment()
            mode, detail = "dhcp_off", reason
        except Exception as exc:  # any failure to make pihole.toml safe: DNS-only, DHCP forced off
            _force_off_by_environment()  # raises if that cannot be confirmed: FTL does not start
            mode, detail = "dns_only", str(exc)[:300]
        try:
            if local is not None and local.get("state") in {"HELD", "RELEASED", "FAILED"}:
                _write_authority({"epoch": local["epoch"], "state": "VOIDED", "voided_at": _now(), "reason": detail[:200]})
            authority = "voided" if local is not None else "none"
        except OSError:
            authority = "unwritable"  # DHCP is already off; promotion will refuse until this is writable
        print(json.dumps({"status": "applied", "mode": mode, "configured": False, "authority": authority, "reason": detail}))
    finally:
        if lock is not None:
            lock.close()


def _mark_released():
    """After any demotion: this node no longer serves under its grant (best effort; DHCP is off)."""
    local = _read_authority()
    if local is None or local.get("state") != "HELD":
        return
    try:
        _write_authority({"epoch": local["epoch"], "state": "RELEASED", "released_at": _now()})
    except OSError:
        pass  # _may_continue also requires the Virtual IP, which a released node normally lost


def _revoke(epoch):
    """Kaya names another holder: disable DHCP and remember the newer epoch.  Only ever disables."""
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        status = _set_dhcp(False)
        local = _read_authority()
        try:
            _write_authority({"epoch": max(epoch, local["epoch"] if local else 0), "state": "REVOKED", "revoked_at": _now()})
            record = "written"
        except OSError:
            record = "unwritable"
        print(json.dumps({"status": "applied", **status, "authority_record": record}))


def _adopt(epoch):
    """Kaya names this node the holder while it already serves DHCP (authority established from a
    verified topology, without a promotion).  Record the grant so that an FTL restart in this boot keeps
    DHCP, as it would after a promotion.  Never enables, disables or changes DHCP or leases."""
    if epoch < 1 or epoch > MAX_EPOCH:
        raise RuntimeError("Invalid DHCP authority epoch.")
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _check_grant(epoch)
        status = _dhcp_status()
        if GUARD_ENV.exists() or status.get("runtime_state") != "RUNNING" or status.get("configured") is not True:
            raise RuntimeError("Only a node that is already serving DHCP records an adopted grant.")
        if not _owns_vip():
            raise RuntimeError("Only the Virtual IP owner records an adopted grant.")
        _write_authority({"epoch": epoch, "state": "HELD", "adopted_at": _now(), "boot_id": _boot_id(),
                          "vip": str(_state("desired_virtual_ip", "")).split("/", 1)[0]})
        print(json.dumps({"status": "applied", "authority_epoch": epoch, "authority_state": "HELD"}))


def _check_grant(epoch):
    """A promotion needs Kaya's grant, at least as new as anything this node has seen."""
    if epoch < 1 or epoch > MAX_EPOCH:
        raise RuntimeError("Promotion requires a DHCP authority grant from Kaya.")
    local = _read_authority()
    # The same epoch again is accepted only while held, or to retry a promotion that failed under it
    # (the node never served under that grant).  Voided, released or revoked epochs are never reused.
    if local is not None and (epoch < local["epoch"] or (epoch == local["epoch"] and local.get("state") not in {"HELD", "FAILED"})):
        raise RuntimeError(
            f"The DHCP authority grant is stale (epoch {epoch}; this node has already seen epoch {local['epoch']} "
            f"{str(local.get('state') or '').lower()})."
        )


def _owns_vip():
    desired = str(_state("desired_virtual_ip", "")).split("/", 1)[0]
    result = _run([IP, "-j", "address", "show"])
    return bool(
        desired
        and not result.returncode
        and any(
            a.get("local") == desired
            for link in json.loads(result.stdout)
            for a in link.get("addr_info", [])
        )
    )


def _own_addresses():
    result = _run([IP, "-j", "address", "show"])
    if result.returncode:
        raise RuntimeError("local addresses unavailable")
    return {
        a.get("local")
        for link in json.loads(result.stdout)
        for a in link.get("addr_info", [])
        if a.get("family") == "inet" and a.get("local")
    }


def _discover(xid, mac):
    header = (
        bytes([1, 1, 6, 0]) + xid.to_bytes(4, "big") + (0).to_bytes(2, "big") + (0x8000).to_bytes(2, "big")
        + bytes(16) + mac + bytes(10) + bytes(192)
    )
    return header + b"\x63\x82\x53\x63" + bytes([53, 1, 1, 55, 2, 1, 54, 255])


def _offer_server(data, xid, own):
    """The server identifier of a DHCPOFFER answering ``xid`` from another host, else None."""
    if len(data) < 244 or data[0] != 2 or int.from_bytes(data[4:8], "big") != xid or data[236:240] != b"\x63\x82\x53\x63":
        return None
    options, index, kind, server = data[240:], 0, None, None
    while index < len(options) and options[index] != 255:
        if options[index] == 0:
            index += 1
            continue
        if index + 1 >= len(options):
            return None
        code, length = options[index], options[index + 1]
        value = options[index + 2:index + 2 + length]
        if code == 53 and length == 1:
            kind = value[0]
        elif code == 54 and length == 4:
            server = socket.inet_ntoa(value)
        index += 2 + length
    return server if kind == 2 and server and server not in own else None


def _other_dhcp_server(interface):
    """Another DHCP server's address if one answers, False if none does, None if it cannot be determined."""
    if not interface or not INTERFACE.fullmatch(interface):
        return None
    try:
        own = _own_addresses()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            probe.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, interface.encode())
            probe.bind(("0.0.0.0", 68))
            xid = random.SystemRandom().getrandbits(32)
            probe.sendto(_discover(xid, b"\x02" + os.urandom(5)), ("255.255.255.255", 67))
            deadline = time.monotonic() + PROBE_WINDOW_SECONDS
            while (remaining := deadline - time.monotonic()) > 0:
                probe.settimeout(remaining)
                try:
                    data, _ = probe.recvfrom(2048)
                except socket.timeout:
                    break
                server = _offer_server(data, xid, own)
                if server:
                    return server
        return False
    except (OSError, ValueError, RuntimeError):
        return None


def _discovery_veto(interface):
    """Defence in depth only.  Refuse if another DHCP server answers; never treat silence as release.

    Absence of an OFFER does not prove there is no other server (it may ignore unknown clients or
    be filtered); exclusivity comes from Kaya's verified release, not from this check.
    """
    found = _other_dhcp_server(interface)
    if isinstance(found, str):
        raise RuntimeError(
            f"Another DHCP server ({found}) is still answering on the network; promotion refused "
            "so that two DHCP servers never run."
        )
    return "no_offer" if found is False else "unavailable"


def _lease_lines(generation, source=None):
    """The verified staged snapshot as dnsmasq lease lines; raises (nothing is written) otherwise.

    Verified means: at least the generation Kaya named, the payload matches the checksum the agent verified
    against Kaya when staging it (so on-disk corruption or truncation is caught), and, for a
    transfer, it was captured from the previous DHCP holder.
    """
    try:
        document = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("No readable staged lease snapshot; the live lease file was not changed.") from exc
    # Kaya keeps staging newer snapshots of the same holder while a handover runs (every renewal is a
    # new generation), so a newer one is accepted; an older one never is.
    if not isinstance(document, dict) or int(document.get("generation") or 0) < generation:
        raise RuntimeError("The staged lease generation is older than the one Kaya named.")
    payload = document.get("payload")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if not isinstance(payload, dict) or hashlib.sha256(encoded).hexdigest() != document.get("checksum"):
        raise RuntimeError("The staged lease snapshot failed its checksum; the live lease file was not changed.")
    if source and payload.get("source_node_id") != source:
        raise RuntimeError("The staged lease snapshot was not captured from the previous DHCP holder; "
                           "the live lease file was not changed.")
    leases = payload.get("leases")
    if not isinstance(leases, list) or len(leases) > 10000:
        raise RuntimeError("The staged lease snapshot is invalid.")
    lines = []
    for lease in leases:
        address, mac = (
            str(ipaddress.ip_address(str(lease["ip"]))),
            str(lease["hwaddr"]).lower(),
        )
        expires, hostname, client_id = (
            int(lease["expires"]),
            str(lease.get("name") or "*"),
            str(lease.get("clientid") or "*"),
        )
        if (
            not MAC.fullmatch(mac)
            or expires < 0
            or any(c.isspace() for c in hostname + client_id)
        ):
            raise RuntimeError("The staged lease snapshot contains an invalid lease.")
        lines.append(f"{expires} {mac} {address} {hostname} {client_id}\n")
    return "".join(lines)


def _pihole_ownership(path):
    try:
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
        mode |= stat.S_IRUSR | stat.S_IWUSR
        return pwd.getpwnam("pihole").pw_uid, grp.getgrnam("pihole").gr_gid, mode
    except KeyError as exc:
        raise RuntimeError(
            "The Pi-hole service account could not be identified."
        ) from exc


def _atomic_write(path, content, ownership=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    uid, gid, mode = ownership or _pihole_ownership(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, path)  # readers see the old file or the new one, never a partial one
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _backup(generation):
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    target = (
        BACKUP_ROOT
        / f"leases-{generation}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    ownership = _pihole_ownership(LEASE_FILE)
    (
        shutil.copy2(LEASE_FILE, target)
        if LEASE_FILE.exists()
        else target.write_text("", encoding="utf-8")
    )
    os.chown(target, ownership[0], ownership[1])
    os.chmod(target, ownership[2])
    return target, ownership


def _dns_healthy():
    service = _run(["systemctl", "is-active", "pihole-FTL"])
    if service.returncode:
        return False
    query_id = 0x4B41
    packet = (
        __import__("struct").pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        + b"\x02pi\x04hole\x00"
        + __import__("struct").pack("!HH", 1, 1)
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(packet, ("127.0.0.1", 53))
            response, _ = client.recvfrom(512)
        return len(response) >= 12 and int.from_bytes(response[:2], "big") == query_id
    except OSError:
        return False


def _wait_for_dns():
    for _ in range(10):
        if _dns_healthy():
            return
        time.sleep(1)
    raise RuntimeError(
        "Pi-hole FTL did not return to a healthy DNS state after DHCP activation."
    )


def _automatic_allowed(generation):
    return (
        bool(_state("automatic_failover", False))
        and not bool(_state("maintenance_mode", False))
        and bool(_state("dhcp_managed", False))
        and generation == int(_state("keepalived_generation", 0))
    )


def _promotion_fence(generation, automatic):
    """Require current local VRRP authority, not just an old queued action."""
    return (
        (
            _state("keepalived_generation", 0) == generation
            if automatic
            else _state("failover_generation", 0) == generation
        )
        and _state("observed_role") == "ACTIVE"
        and _state("vip_owned", False) is True
        and _state("dns_healthy", False) is True
    )


def main():
    commands = {"status", "boot-guard", "revoke", "adopt", "demote", "promote", "automatic-demote", "automatic-promote"}
    if len(sys.argv) not in (2, 3) or sys.argv[1] not in commands:
        raise SystemExit(
            "usage: helper status|boot-guard|revoke|adopt|demote|promote|automatic-demote|automatic-promote [generation|epoch]"
        )
    if sys.argv[1] == "status":
        print(json.dumps({"status": "ok", **_dhcp_status()}))
        return
    if sys.argv[1] == "boot-guard":
        try:
            _boot_guard()
        except Exception as exc:
            print(json.dumps({"status": "failed", "mode": "blocked", "message": str(exc)[:500]}))
            raise SystemExit(3)  # DHCP could not be confirmed off: the drop-in must not start FTL
        return
    if sys.argv[1] == "adopt":
        _adopt(int(sys.argv[2]))
        return
    if sys.argv[1] == "revoke":
        epoch = int(sys.argv[2])
        if epoch < 1 or epoch > MAX_EPOCH:
            raise RuntimeError("Invalid DHCP authority epoch.")
        _revoke(epoch)
        return
    generation = int(sys.argv[2])
    automatic = sys.argv[1].startswith("automatic-")
    if sys.argv[1] == "automatic-promote":
        # Revised protocol: no node-local promotion.  Kaya promotes only after verified release.
        raise RuntimeError("Node-local DHCP promotion is disabled; Kaya promotes the Virtual IP owner only after verified release.")
    if generation < 1 or (
        not _automatic_allowed(generation)
        if automatic
        else generation != int(_state("failover_generation", 0))
    ):
        raise RuntimeError(
            "The DHCP action generation is stale or automatic failover is not permitted."
        )
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Generation and VRRP state may change while waiting for the lock.
        if automatic:
            if not _automatic_allowed(generation):
                raise RuntimeError("The automatic DHCP action became stale while waiting for the failover lock.")
        elif generation != int(_state("failover_generation", 0)):
            raise RuntimeError("The DHCP action became stale while waiting for the failover lock.")
        if sys.argv[1] in {"demote", "automatic-demote"}:
            status = _set_dhcp(False)
            _mark_released()
            print(json.dumps({"status": "applied", **status}))
            return
        if GUARD_ENV.exists():
            raise RuntimeError(
                "DHCP is forced off for this Pi-hole FTL run because its configuration could not be made safe "
                "when FTL started (DNS-only fallback). Repair /etc/pihole/pihole.toml or the pihole-FTL unit "
                "environment, then restart pihole-FTL."
            )
        authority_epoch = int(_state("failover_authority_epoch", 0) or 0)
        _check_grant(authority_epoch)
        if not _promotion_fence(generation, automatic) or not _owns_vip():
            raise RuntimeError(
                "Promotion requires current local VRRP authority, VIP ownership and healthy DNS."
            )
        discovery = _discovery_veto(str(_state("network_interface", "") or ""))
        if not _promotion_fence(generation, automatic) or not _owns_vip():
            raise RuntimeError("Promotion became stale while checking for another DHCP server.")
        leases, lease_reason = _lease_decision(_read_authority())
        # Record the grant durably before DHCP is enabled; if that fails, DHCP stays off.  The boot
        # and Virtual IP let the boot guard keep DHCP on across an FTL restart, and only that.
        _write_authority({"epoch": authority_epoch, "state": "HELD", "generation": generation, "recorded_at": _now(),
                          "boot_id": _boot_id(), "vip": str(_state("desired_virtual_ip", "")).split("/", 1)[0]})
        configuration_only = (
            bool(_state("failover_configuration_only", False))
            if not automatic
            else False
        )
        if configuration_only:
            # The node already serves DHCP and owns the VIP. Persist only the
            # missing setting; do not back up or replace the live lease file.
            status = _set_dhcp(True)
            _wait_for_dns()
            if not _promotion_fence(generation, automatic) or not _owns_vip():
                # A lost VIP after enabling DHCP is a failed transition, never
                # a successful configuration repair.
                _set_dhcp(False)
                raise RuntimeError(
                    "Promotion was fenced because local VIP ownership changed; DHCP was disabled again."
                )
            print(json.dumps({"status": "applied", **status, "backup_reference": None, "discovery_check": discovery}))
            return
        if _dhcp_status().get("listening") is True:
            # Already serving: never replace live leases.  Persist the setting only (idempotent).
            status = _set_dhcp(True)
            print(json.dumps({"status": "applied", **status, "backup_reference": None, "already_serving": True}))
            return
        backup, ownership = _backup(generation)
        replaced = False
        try:
            if leases == "install":
                content = _lease_lines(int(_state("failover_lease_generation", 0)), _state("failover_lease_source"))
                _atomic_write(LEASE_FILE, content, ownership)
                replaced = True
            status = _set_dhcp(True)
            _wait_for_dns()
            if not _promotion_fence(generation, automatic) or not _owns_vip():
                _set_dhcp(False)
                raise RuntimeError(
                    "Promotion was fenced because local VIP ownership changed; DHCP was disabled again."
                )
        except Exception:
            # Each step independently: DHCP off, the live lease file back exactly as it was, and the
            # grant marked failed so neither continuation nor lease continuity relies on it.
            for step in (lambda: _set_dhcp(False),
                         lambda: replaced and _atomic_write(LEASE_FILE, backup.read_text(encoding="utf-8"), ownership),
                         lambda: _write_authority({"epoch": authority_epoch, "state": "FAILED", "failed_at": _now()})):
                try:
                    step()
                except Exception:
                    pass
            raise
        print(
            json.dumps({"status": "applied", **status, "backup_reference": backup.name, "discovery_check": discovery,
                        "leases": "installed" if replaced else "kept", "lease_reason": lease_reason,
                        "lease_file_present": LEASE_FILE.exists()})
        )


def _lease_decision(local):
    """Keep this node's live lease file, or install the previous holder's verified snapshot.

    The live file is kept only when authority never left this node: Kaya says so (lease mode
    "continue") and this node's own record agrees (it served under an epoch in Kaya's continuous
    run of grants to it, and was never told another node holds authority).  A rollback keeps the
    node's original leases, as before.  Everything else is a transfer.
    """
    if bool(_state("failover_restore_original", False)):
        return "keep", "rollback to this node's original leases"
    if _state("failover_lease_mode") != "continue":
        return "install", "DHCP authority moves to this node"
    if local is None:
        return "keep", "authority continues on this node (no local record to cross-check)"
    since, previous = _state("failover_holder_since"), _state("failover_previous_epoch")
    if local.get("state") not in HELD_STATES:
        return "install", f"this node's record ({str(local.get('state'))[:20].lower()}) does not show it was serving"
    if isinstance(since, int) and isinstance(previous, int) and not since <= local["epoch"] <= previous:
        return "install", "this node's record does not show it served since authority came to it"
    return "keep", "authority continues on this node"


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "failed", "message": str(exc)[:500]}))
        raise SystemExit(1)
