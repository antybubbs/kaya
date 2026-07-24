#!/usr/bin/env python3
"""Restricted root helper for Kaya's dedicated Keepalived include."""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SOURCE = Path("/var/lib/kaya-ha-agent/pending-keepalived.conf")
MAIN = Path("/etc/keepalived/keepalived.conf")
TARGET = Path("/etc/keepalived/conf.d/kaya-ha.conf")
BACKUPS = Path("/var/lib/kaya-ha-agent/backups")
INCLUDE = "include /etc/keepalived/conf.d/*.conf"
SAFE_LINES = (
    re.compile(r"# Managed by Kaya High Availability\. Do not edit\."),
    re.compile(r"# cluster=[0-9a-f-]{36} generation=[1-9][0-9]*"),
    re.compile(r"global_defs \{"),
    re.compile(r"script_user kaya-ha kaya-ha"),
    re.compile(r"enable_script_security"),
    re.compile(r"vrrp_script KAYA_DNS_[A-F0-9]{8} \{"),
    re.compile(r"vrrp_instance KAYA_HA_[A-F0-9]{8} \{"),
    re.compile(r"script \"/usr/lib/kaya-ha-agent/check-pihole-dns\""),
    re.compile(r"(?:interval|timeout|fall|rise|advert_int|preempt_delay) [1-9][0-9]*"),
    re.compile(r"state BACKUP"), re.compile(r"nopreempt"),
    re.compile(r"interface [A-Za-z0-9_.:-]{1,80}"),
    re.compile(r"virtual_router_id (?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"),
    re.compile(r"priority (?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])"),
    re.compile(r"(?:virtual_ipaddress|track_script) \{"),
    re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}/(?:[1-9]|[12][0-9]|3[0-2])"),
    re.compile(r"KAYA_DNS_[A-F0-9]{8}"),
    re.compile(r"notify_(?:master|backup|fault) \"/usr/lib/kaya-ha-agent/kaya_ha_transition\.py (?:master|backup|fault) [1-9][0-9]*\""),
    re.compile(r"\}"),
)


def command_diagnostic(completed: subprocess.CompletedProcess, limit: int = 700) -> str:
    """Return bounded, single-line command output suitable for an agent result."""
    output = (completed.stderr or "").strip() or (completed.stdout or "").strip()
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    output = " ".join("".join(character for character in output if character.isprintable() or character.isspace()).split())
    return output[:limit]


def emit(ok: bool, message: str, **extra) -> int:
    print(json.dumps({"ok": ok, "message": message, **extra}, separators=(",", ":")))
    return 0 if ok else 1


def atomic_write(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(argv: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def validate_managed_document(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or any(not any(pattern.fullmatch(line) for pattern in SAFE_LINES) for line in lines):
        return False
    if sum(line.startswith("vrrp_instance ") for line in lines) != 1 or sum(line.startswith("vrrp_script ") for line in lines) != 1:
        return False
    if lines.count("global_defs {") != 1 or lines.count("script_user kaya-ha kaya-ha") != 1 or lines.count("enable_script_security") != 1:
        return False
    if {role: sum(line.startswith(f"notify_{role} ") for line in lines) for role in ("master", "backup", "fault")} != {"master": 1, "backup": 1, "fault": 1}:
        return False
    vip_lines = [line for line in lines if "/" in line and not line.startswith(("script ", "notify_"))]
    if len(vip_lines) != 1:
        return False
    try:
        interface = ipaddress.IPv4Interface(vip_lines[0])
    except ValueError:
        return False
    return interface.ip not in {interface.network.network_address, interface.network.broadcast_address}


def apply(source: str) -> int:
    supplied = Path(source)
    if supplied.resolve() != SOURCE.resolve() or supplied.is_symlink() or not supplied.is_file():
        return emit(False, "The helper accepts only the fixed Kaya pending configuration path.")
    content = supplied.read_bytes()
    if len(content) > 32 * 1024 or not validate_managed_document(content):
        return emit(False, "The pending configuration is not a valid Kaya-managed document.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    BACKUPS.mkdir(parents=True, exist_ok=True); os.chmod(BACKUPS, 0o700)
    reference = f"keepalived-{stamp}"
    target_backup = BACKUPS / f"{reference}.include"
    main_backup = BACKUPS / f"{reference}.main"
    target_existed = TARGET.exists()
    main_existed = MAIN.exists()
    try:
        if target_existed: shutil.copy2(TARGET, target_backup)
        if main_existed: shutil.copy2(MAIN, main_backup)
        atomic_write(TARGET, content)
        main_content = MAIN.read_text(encoding="utf-8") if main_existed else ""
        if INCLUDE not in {line.strip() for line in main_content.splitlines()}:
            main_content = main_content.rstrip() + ("\n\n" if main_content.strip() else "") + INCLUDE + "\n"
            atomic_write(MAIN, main_content.encode())
        validation = command(["keepalived", "--config-test", "-f", str(MAIN)])
        if validation.returncode != 0:
            detail = command_diagnostic(validation)
            raise RuntimeError(
                "Keepalived rejected the generated configuration."
                + (f" Diagnostic: {detail}" if detail else " No diagnostic output was returned.")
            )
        activation = command(["systemctl", "reload", "keepalived"])
        if activation.returncode != 0:
            activation = command(["systemctl", "restart", "keepalived"])
        if activation.returncode != 0:
            detail = command_diagnostic(activation)
            raise RuntimeError(
                "Keepalived could not be reloaded."
                + (f" Diagnostic: {detail}" if detail else " No diagnostic output was returned.")
            )
        return emit(True, "Keepalived configuration validated and activated.", backup_reference=reference)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        try:
            if target_existed and target_backup.exists(): shutil.copy2(target_backup, TARGET)
            elif TARGET.exists(): TARGET.unlink()
            if main_existed and main_backup.exists(): shutil.copy2(main_backup, MAIN)
            elif MAIN.exists(): MAIN.unlink()
            command(["systemctl", "reload", "keepalived"])
        except OSError:
            pass
        return emit(False, str(exc), backup_reference=reference)


def status(vip_text: str) -> int:
    try:
        vip = str(ipaddress.IPv4Address(vip_text))
    except ValueError:
        return emit(False, "Invalid IPv4 address.", runtime_state="UNKNOWN", vip_owned=False)
    try:
        active = command(["systemctl", "is-active", "keepalived"], timeout=5).returncode == 0
        addresses = json.loads(command(["ip", "-j", "address", "show"], timeout=5).stdout or "[]")
        owned = any(item.get("local") == vip for link in addresses for item in link.get("addr_info", []))
        return emit(True, "Keepalived state read.", runtime_state="RUNNING" if active else "STOPPED", vip_owned=owned)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return emit(False, "Keepalived state could not be read.", runtime_state="UNKNOWN", vip_owned=False)


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "apply": return apply(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == "status": return status(sys.argv[2])
    return emit(False, "Unsupported helper operation.")


if __name__ == "__main__":
    raise SystemExit(main())
