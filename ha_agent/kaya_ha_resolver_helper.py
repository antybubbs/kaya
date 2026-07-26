#!/usr/bin/env python3
"""Fixed-purpose systemd-resolved repair for Kaya HA node independence."""

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


DROP_IN = Path("/etc/systemd/resolved.conf.d/90-kaya-ha.conf")
BACKUPS = Path("/var/lib/kaya-ha-agent/resolver-backups")
BASELINE = BACKUPS / "baseline"
INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
CHECKSUM = re.compile(r"^[a-f0-9]{64}$")


def fail(message: str, backup: str | None = None) -> int:
    print(json.dumps({"status": "failed", "message": message[:500], "backup_reference": backup}))
    return 1


def main() -> int:
    if len(sys.argv) != 5 or sys.argv[1] != "apply":
        return 2
    try:
        vip = str(ipaddress.IPv4Address(sys.argv[2]))
    except ipaddress.AddressValueError:
        return fail("The requested HA DNS Virtual IP is invalid.")
    interface, expected = sys.argv[3], sys.argv[4]
    if not INTERFACE.fullmatch(interface) or not CHECKSUM.fullmatch(expected):
        return fail("The requested resolver repair parameters are invalid.")
    content = f"# Managed by Kaya HA\n[Resolve]\nDNS={vip}\nDomains=~.\n"
    if hashlib.sha256(f"{vip}:{interface}:{content}".encode()).hexdigest() != expected:
        return fail("The resolver repair checksum did not match the approved request.")
    try:
        target = str(Path("/etc/resolv.conf").resolve(strict=True))
    except OSError:
        return fail("The host resolver link could not be inspected. No changes were made.")
    if "systemd/resolve" not in target or subprocess.run(["systemctl", "is-active", "--quiet", "systemd-resolved.service"], check=False).returncode:
        return fail("Automatic repair is supported only when systemd-resolved owns /etc/resolv.conf. No changes were made.")

    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not BASELINE.exists():
        if DROP_IN.exists():
            shutil.copy2(DROP_IN, BASELINE)
        else:
            BASELINE.write_text("__ABSENT__\n", encoding="utf-8")
        os.chmod(BASELINE, 0o600)
    reference = hashlib.sha256(os.urandom(32)).hexdigest()[:24]
    backup = BACKUPS / reference
    if DROP_IN.exists():
        shutil.copy2(DROP_IN, backup)
    else:
        backup.write_text("__ABSENT__\n", encoding="utf-8")
    os.chmod(backup, 0o600)
    DROP_IN.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".90-kaya-ha.", dir=DROP_IN.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, DROP_IN)
        restart = subprocess.run(["systemctl", "restart", "systemd-resolved.service"], capture_output=True, timeout=20, check=False)
        check = subprocess.run(["resolvectl", "dns", interface], capture_output=True, text=True, timeout=10, check=False)
        if restart.returncode or check.returncode or vip not in check.stdout.split():
            raise RuntimeError("systemd-resolved did not report the HA DNS Virtual IP after restart.")
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        if backup.read_text(encoding="utf-8", errors="replace").strip() == "__ABSENT__":
            DROP_IN.unlink(missing_ok=True)
        else:
            shutil.copy2(backup, DROP_IN)
        subprocess.run(["systemctl", "restart", "systemd-resolved.service"], capture_output=True, timeout=20, check=False)
        return fail(f"Resolver repair was rolled back: {exc}", reference)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(json.dumps({"status": "applied", "message": "Host resolver now uses the HA DNS Virtual IP.", "backup_reference": reference}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
