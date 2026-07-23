#!/usr/bin/env python3
"""Root-only, fixed-purpose DHCP transition helper for Kaya HA."""
import fcntl, grp, ipaddress, json, os, pwd, re, shutil, socket, sqlite3, stat, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

STATE_ROOT = Path("/var/lib/kaya-ha-agent")
STATE_DB = STATE_ROOT / "state.sqlite3"
SNAPSHOT = STATE_ROOT / "lease-snapshots/current.json"
LEASE_FILE = Path("/etc/pihole/dhcp.leases")
BACKUP_ROOT = STATE_ROOT / "failover-backups"
LOCK_FILE = STATE_ROOT / "failover.lock"
PROC_UDP = (Path("/proc/net/udp"), Path("/proc/net/udp6"))
FTL, IP = "/usr/bin/pihole-FTL", "/usr/sbin/ip"
MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)

def _state(key, default=None):
    with sqlite3.connect(STATE_DB) as db:
        row = db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return json.loads(row[0]) if row else default

def _run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)

def _dhcp_active():
    result = _run([FTL, "--config", "dhcp.active"])
    matches = re.findall(r"\b(true|false)\b", result.stdout.lower())
    if result.returncode or not matches:
        raise RuntimeError("Pi-hole DHCP state could not be read.")
    return matches[-1] == "true"


def _udp_port_bound(port, paths=None):
    """Read the kernel socket table without invoking a shell or a broad helper."""
    for path in paths or PROC_UDP:
        try:
            lines = path.read_text(encoding="ascii", errors="strict").splitlines()[1:]
        except (FileNotFoundError, OSError, UnicodeError):
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 2:
                continue
            try:
                if int(fields[1].rsplit(":", 1)[1], 16) == port:
                    return True
            except (IndexError, ValueError):
                continue
    return False


def _dhcp_status():
    configured = _dhcp_active()
    service = _run(["systemctl", "is-active", "pihole-FTL"])
    listening = _udp_port_bound(67)
    return {
        "configured": configured,
        "service_active": service.returncode == 0,
        "listening": listening,
        "dhcp_running": configured and service.returncode == 0 and listening,
    }


def _wait_for_dhcp(enabled):
    latest = {}
    for _ in range(20):
        latest = _dhcp_status()
        ready = latest["dhcp_running"] if enabled else not latest["configured"] and not latest["listening"]
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
    result = _run([FTL, "--config", "dhcp.active", "true" if enabled else "false"])
    if result.returncode:
        raise RuntimeError("Pi-hole did not confirm the requested DHCP state.")
    return _wait_for_dhcp(enabled)

def _owns_vip():
    desired = str(_state("desired_virtual_ip", "")).split("/", 1)[0]
    result = _run([IP, "-j", "address", "show"])
    return bool(desired and not result.returncode and any(a.get("local") == desired for link in json.loads(result.stdout) for a in link.get("addr_info", [])))

def _lease_lines(generation):
    document = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    if int(document.get("generation") or 0) != generation:
        raise RuntimeError("The staged lease generation is not current.")
    leases = document.get("payload", {}).get("leases")
    if not isinstance(leases, list) or len(leases) > 10000:
        raise RuntimeError("The staged lease snapshot is invalid.")
    lines = []
    for lease in leases:
        address, mac = str(ipaddress.ip_address(str(lease["ip"]))), str(lease["hwaddr"]).lower()
        expires, hostname, client_id = int(lease["expires"]), str(lease.get("name") or "*"), str(lease.get("clientid") or "*")
        if not MAC.fullmatch(mac) or expires < 0 or any(c.isspace() for c in hostname + client_id):
            raise RuntimeError("The staged lease snapshot contains an invalid lease.")
        lines.append(f"{expires} {mac} {address} {hostname} {client_id}\n")
    return "".join(lines)

def _pihole_ownership(path):
    try:
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
        mode |= stat.S_IRUSR | stat.S_IWUSR
        return pwd.getpwnam("pihole").pw_uid, grp.getgrnam("pihole").gr_gid, mode
    except KeyError as exc:
        raise RuntimeError("The Pi-hole service account could not be identified.") from exc

def _atomic_write(path, content, ownership=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    uid, gid, mode = ownership or _pihole_ownership(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def _backup(generation):
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    target = BACKUP_ROOT / f"leases-{generation}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    ownership = _pihole_ownership(LEASE_FILE)
    shutil.copy2(LEASE_FILE, target) if LEASE_FILE.exists() else target.write_text("", encoding="utf-8")
    os.chown(target, ownership[0], ownership[1]); os.chmod(target, ownership[2])
    return target, ownership

def _dns_healthy():
    service = _run(["systemctl", "is-active", "pihole-FTL"])
    if service.returncode:
        return False
    query_id = 0x4B41
    packet = __import__("struct").pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + b"\x02pi\x04hole\x00" + __import__("struct").pack("!HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2); client.sendto(packet, ("127.0.0.1", 53)); response, _ = client.recvfrom(512)
        return len(response) >= 12 and int.from_bytes(response[:2], "big") == query_id
    except OSError:
        return False

def _wait_for_dns():
    for _ in range(10):
        if _dns_healthy(): return
        time.sleep(1)
    raise RuntimeError("Pi-hole FTL did not return to a healthy DNS state after DHCP activation.")

def _automatic_allowed(generation):
    return (
        bool(_state("automatic_failover", False))
        and not bool(_state("maintenance_mode", False))
        and bool(_state("dhcp_managed", False))
        and generation == int(_state("keepalived_generation", 0))
    )

def main():
    commands = {"status", "demote", "promote", "automatic-demote", "automatic-promote"}
    if len(sys.argv) not in (2, 3) or sys.argv[1] not in commands:
        raise SystemExit("usage: helper status|demote|promote|automatic-demote|automatic-promote [generation]")
    if sys.argv[1] == "status":
        print(json.dumps({"status": "ok", **_dhcp_status()})); return
    generation = int(sys.argv[2])
    automatic = sys.argv[1].startswith("automatic-")
    if generation < 1 or (not _automatic_allowed(generation) if automatic else generation != int(_state("failover_generation", 0))):
        raise RuntimeError("The DHCP action generation is stale or automatic failover is not permitted.")
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if sys.argv[1] in {"demote", "automatic-demote"}:
            _set_dhcp(False); print(json.dumps({"status": "applied", "dhcp_running": False})); return
        if not _owns_vip() or _state("dns_healthy", False) is not True:
            raise RuntimeError("Promotion requires local VIP ownership and healthy DNS.")
        backup, ownership = _backup(generation)
        try:
            restore_original = bool(_state("failover_restore_original", False)) if not automatic else False
            lease_generation = int(_state("failover_lease_generation", 0)) if not automatic else int(_state("lease_generation", 0))
            if not restore_original:
                _atomic_write(LEASE_FILE, _lease_lines(lease_generation), ownership)
            _set_dhcp(True)
            _wait_for_dns()
        except Exception:
            try: _set_dhcp(False); _atomic_write(LEASE_FILE, backup.read_text(encoding="utf-8"), ownership)
            finally: raise
        print(json.dumps({"status": "applied", "dhcp_running": True, "backup_reference": backup.name}))

if __name__ == "__main__":
    try: main()
    except Exception as exc:
        print(json.dumps({"status": "failed", "message": str(exc)[:500]})); raise SystemExit(1)
