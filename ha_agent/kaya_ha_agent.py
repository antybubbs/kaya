#!/usr/bin/env python3
"""Minimal Kaya HA agent transport. It performs no privileged service actions."""

import argparse
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROTOCOL_VERSION = 1
AGENT_VERSION = "0.2.2"


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class State:
    def __init__(self, root: Path):
        self.root = root
        self.config_path = root / "config.json"
        self.key_path = root / "agent.key"
        self.database_path = root / "state.sqlite3"
        root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.database_path)
        self.db.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)")
        self.db.commit()

    def get(self, key: str, default=None):
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key: str, value) -> None:
        self.db.execute("INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
        self.db.commit()

    def queue_event(self, event_type: str, severity: str, message: str) -> str:
        event_id = secrets.token_hex(16)
        payload = {"event_id": event_id, "event_type": event_type, "severity": severity, "message": message, "occurred_at": datetime.now(timezone.utc).isoformat(), "details": {}}
        self.db.execute("INSERT INTO events(event_id,payload,created_at) VALUES(?,?,?)", (event_id, json.dumps(payload), payload["occurred_at"]))
        self.db.commit()
        return event_id

    def queued_events(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM events ORDER BY created_at LIMIT 100")]

    def acknowledge_events(self, event_ids: list[str]) -> None:
        self.db.executemany("DELETE FROM events WHERE event_id = ?", ((item,) for item in event_ids))
        self.db.commit()


def json_request(url: str, method: str, payload: dict | None, headers: dict[str, str] | None = None) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    req = request.Request(url, data=body if method != "GET" else None, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    with request.urlopen(req, timeout=15) as response:
        return json.loads(response.read() or b"{}")


def private_key(state: State) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(state.key_path.read_bytes())


def signed_request(state: State, method: str, path: str, payload: dict | None = None) -> dict:
    config = json.loads(state.config_path.read_text(encoding="utf-8"))
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    timestamp = str(int(time.time()))
    request_id = secrets.token_hex(16)
    canonical = "\n".join((method, path, request_id, timestamp, hashlib.sha256(body).hexdigest())).encode()
    headers = {
        "X-Kaya-Agent-ID": config["agent_id"],
        "X-Kaya-Agent-Timestamp": timestamp,
        "X-Kaya-Agent-Request-ID": request_id,
        "X-Kaya-Agent-Signature": encoded(private_key(state).sign(canonical)),
        "X-Kaya-Agent-Protocol": str(PROTOCOL_VERSION),
    }
    return json_request(config["kaya_url"].rstrip("/") + path, method, payload, headers)


def register(state: State, args) -> None:
    token = args.token
    if args.token_stdin:
        token = sys.stdin.readline().rstrip("\r\n")
    if not token:
        raise ValueError("A registration token is required.")
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public_bytes = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    response = json_request(args.kaya_url.rstrip("/") + "/api/ha/agent/v1/register", "POST", {"cluster_id": args.cluster_id, "node_id": args.node_id, "bootstrap_token": token, "public_key": encoded(public_bytes), "agent_version": args.agent_version, "protocol_version": PROTOCOL_VERSION})
    atomic_bytes(state.key_path, private_bytes)
    atomic_json(state.config_path, {"agent_id": response["agent_id"], "cluster_id": response["cluster_id"], "node_id": response["node_id"], "kaya_url": args.kaya_url.rstrip("/"), "agent_version": args.agent_version})
    state.set("observed_role", "STANDBY")
    state.set("observed_generation", 0)
    print(f"Registered agent {response['agent_id']}")


def reconcile_desired(state: State, desired: dict, *, helper_runner=None) -> None:
    current = int(state.get("last_valid_cluster_generation", 0))
    incoming = int(desired["cluster_generation"])
    if incoming < current:
        state.queue_event("stale_generation_rejected", "warning", "Rejected desired state with an older cluster generation.")
        return
    state.set("last_valid_cluster_generation", incoming)
    state.set("observed_generation", incoming)
    state.set("desired_role", desired["desired_role"])
    state.set("desired_virtual_ip", desired.get("virtual_ip"))
    state.set("role_generation", int(desired.get("role_generation") or 0))
    state.set("automatic_failover", bool(desired.get("automatic_failover", False)))
    state.set("maintenance_mode", bool(desired.get("maintenance_mode", False)))
    state.set("dhcp_managed", bool(desired.get("dhcp_managed", False)))
    state.set("peer_host", desired.get("peer_host"))
    state.set("network_interface", desired.get("network_interface"))
    state.set("automatic_hold_down_seconds", max(5, min(60, int(desired.get("automatic_hold_down_seconds") or 10))))
    state.set("last_kaya_contact", datetime.now(timezone.utc).isoformat())
    action = desired.get("keepalived")
    if action:
        try:
            try:
                from .keepalived_runtime import KeepalivedRuntimeError, apply_desired_keepalived
            except ImportError:
                from keepalived_runtime import KeepalivedRuntimeError, apply_desired_keepalived
            kwargs = {"runner": helper_runner} if helper_runner is not None else {}
            result = apply_desired_keepalived(state, action, **kwargs)
        except KeepalivedRuntimeError as exc:
            result = {"action_id": action.get("action_id", "invalid"), "action_type": "KEEPALIVED_APPLY", "generation": int(action.get("generation") or 0), "status": "FAILED", "checksum": None, "backup_reference": None, "message": str(exc)[:1000]}
        state.set("pending_action_result", result)
    lease_action = desired.get("lease_snapshot")
    if lease_action:
        generation = int(lease_action.get("generation") or 0)
        result = {"action_id": lease_action.get("action_id", "invalid"), "action_type": "LEASE_SNAPSHOT_STAGE", "generation": generation, "status": "FAILED", "checksum": None, "backup_reference": None, "message": "Lease snapshot staging failed."}
        try:
            response = signed_request(state, "GET", str(lease_action["snapshot_path"]))
            payload = response.get("payload")
            if not isinstance(payload, dict) or not isinstance(payload.get("leases"), list):
                raise ValueError("Kaya returned an invalid lease snapshot.")
            encoded_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            checksum = hashlib.sha256(encoded_payload).hexdigest()
            if checksum != lease_action.get("checksum") or checksum != response.get("checksum"):
                raise ValueError("Lease snapshot checksum verification failed.")
            if int(response.get("generation") or 0) != generation:
                raise ValueError("Lease snapshot generation verification failed.")
            snapshot_path = state.root / "lease-snapshots" / "current.json"
            atomic_json(snapshot_path, response)
            state.set("lease_generation", generation)
            result.update({"status": "APPLIED", "checksum": checksum, "backup_reference": f"lease-generation-{generation}", "message": "Validated lease snapshot staged locally; DHCP was not changed."})
        except Exception as exc:
            result["message"] = str(exc)[:1000]
        state.set("pending_lease_action_result", result)
    failover_action = desired.get("failover")
    if failover_action:
        pending = state.get("pending_failover_action_result")
        if pending and pending.get("action_id") == failover_action.get("action_id"):
            return
        try:
            try:
                from .failover_runtime import FailoverRuntimeError, apply_failover_action
            except ImportError:
                from failover_runtime import FailoverRuntimeError, apply_failover_action
            kwargs = {"runner": helper_runner} if helper_runner is not None else {}
            result = apply_failover_action(state, failover_action, **kwargs)
        except FailoverRuntimeError as exc:
            result = {"action_id": failover_action.get("action_id", "invalid"), "action_type": failover_action.get("action_type", "DHCP_DEMOTE"), "generation": int(failover_action.get("generation") or 0), "status": "FAILED", "checksum": failover_action.get("checksum"), "backup_reference": None, "message": str(exc)[:1000]}
        state.set("pending_failover_action_result", result)


def run_once(state: State) -> None:
    config = json.loads(state.config_path.read_text(encoding="utf-8"))
    try:
        try:
            from .keepalived_runtime import refresh_vip_state
        except ImportError:
            from keepalived_runtime import refresh_vip_state
        refresh_vip_state(state)
    except Exception:
        state.set("keepalived_runtime_state", "UNKNOWN")
    try:
        try:
            from .failover_runtime import refresh_dhcp_state
        except ImportError:
            from failover_runtime import refresh_dhcp_state
        refresh_dhcp_state(state)
    except Exception:
        pass
    try:
        check = subprocess.run(["/usr/lib/kaya-ha-agent/check-pihole-dns", "--observe"], capture_output=True, timeout=10, check=False)
        state.set("dns_healthy", check.returncode == 0)
    except (OSError, subprocess.SubprocessError):
        state.set("dns_healthy", False)
    peer_host = str(state.get("peer_host", "") or "").strip()
    if peer_host:
        try:
            peer = subprocess.run(["/usr/bin/ping", "-c", "1", "-W", "1", peer_host], capture_output=True, timeout=3, check=False)
            state.set("peer_reachable", peer.returncode == 0)
        except (OSError, subprocess.SubprocessError):
            state.set("peer_reachable", False)
    heartbeat = {"observed_role": state.get("observed_role", "STANDBY"), "observed_generation": int(state.get("observed_generation", 0)), "vip_owned": bool(state.get("vip_owned", False)), "dhcp_running": bool(state.get("dhcp_running", False)), "dns_healthy": bool(state.get("dns_healthy", False)), "peer_reachable": bool(state.get("peer_reachable", False)), "lease_generation": int(state.get("lease_generation", 0)), "config_generation": int(state.get("config_generation", 0)), "agent_version": AGENT_VERSION, "keepalived_runtime_state": state.get("keepalived_runtime_state", "UNKNOWN")}
    response = signed_request(state, "POST", "/api/ha/agent/v1/heartbeat", heartbeat)
    reconcile_desired(state, response["desired"])
    action_result = state.get("pending_action_result")
    if action_result:
        signed_request(state, "POST", "/api/ha/agent/v1/action-result", action_result)
        state.set("pending_action_result", None)
    lease_action_result = state.get("pending_lease_action_result")
    if lease_action_result:
        signed_request(state, "POST", "/api/ha/agent/v1/action-result", lease_action_result)
        state.set("pending_lease_action_result", None)
    failover_action_result = state.get("pending_failover_action_result")
    if failover_action_result:
        signed_request(state, "POST", "/api/ha/agent/v1/action-result", failover_action_result)
        state.set("pending_failover_action_result", None)
    queued = state.queued_events()
    if queued:
        signed_request(state, "POST", "/api/ha/agent/v1/events", {"events": queued})
        state.acknowledge_events([item["event_id"] for item in queued])


def main() -> None:
    parser = argparse.ArgumentParser(description="Kaya High Availability agent transport")
    parser.add_argument("--state-dir", default="/var/lib/kaya-ha-agent")
    commands = parser.add_subparsers(dest="command", required=True)
    registration = commands.add_parser("register")
    registration.add_argument("--kaya-url", required=True)
    registration.add_argument("--cluster-id", required=True)
    registration.add_argument("--node-id", required=True)
    token_source = registration.add_mutually_exclusive_group(required=True)
    token_source.add_argument("--token")
    token_source.add_argument("--token-stdin", action="store_true")
    registration.add_argument("--agent-version", default=AGENT_VERSION)
    event_parser = commands.add_parser("event")
    event_parser.add_argument("event_type")
    event_parser.add_argument("message")
    event_parser.add_argument("--severity", choices=("info", "warning", "error", "critical"), default="info")
    commands.add_parser("once")
    daemon = commands.add_parser("run")
    daemon.add_argument("--interval", type=int, default=15)
    args = parser.parse_args()
    state = State(Path(args.state_dir))
    if args.command == "register":
        register(state, args)
    elif args.command == "event":
        print(state.queue_event(args.event_type, args.severity, args.message))
    elif args.command == "once":
        run_once(state)
    else:
        while True:
            try:
                run_once(state)
            except (error.URLError, TimeoutError, ValueError, KeyError) as exc:
                state.set("last_error", type(exc).__name__)
            time.sleep(max(5, args.interval))


if __name__ == "__main__":
    main()
