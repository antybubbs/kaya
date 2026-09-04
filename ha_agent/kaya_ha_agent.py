#!/usr/bin/env python3
"""Minimal Kaya HA agent transport. It performs no privileged service actions."""

import argparse
import base64
import hashlib
import json
import ssl
import os
import secrets
import socket
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
AGENT_VERSION = "0.2.14"
SQLITE_BUSY_ATTEMPTS = 6
SQLITE_BUSY_TIMEOUT_MS = 5000

ICMP_AVAILABLE = "AVAILABLE"
ICMP_NO_REPLY = "NO_REPLY"
ICMP_UNAVAILABLE = "UNAVAILABLE"


class AgentRequestError(ValueError):
    """A safely reportable agent transport failure without request secrets."""

    def __init__(self, reason: str, message: str, *, status: int | None = None):
        super().__init__(message)
        self.reason = reason
        self.status = status


class TransientStateBusy(RuntimeError):
    """A bounded SQLite contention failure, distinct from corruption."""


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
        self.telemetry_deferred = False
        root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.database_path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
        self.db.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)")
        self.db.commit()

    @staticmethod
    def _busy(exc: sqlite3.OperationalError) -> bool:
        message = str(exc).lower()
        return "locked" in message or "busy" in message

    def _run(self, operation, *, transient_ok: bool = False):
        for attempt in range(SQLITE_BUSY_ATTEMPTS):
            try:
                return operation()
            except sqlite3.OperationalError as exc:
                self.db.rollback()
                if not self._busy(exc):
                    raise
                if attempt + 1 < SQLITE_BUSY_ATTEMPTS:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                if transient_ok:
                    self.telemetry_deferred = True
                    print("Kaya HA agent state update deferred: sqlite_busy", file=sys.stderr, flush=True)
                    return None
                raise TransientStateBusy("Agent state is temporarily busy.") from None

    def get(self, key: str, default=None):
        row = self._run(lambda: self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone())
        return json.loads(row[0]) if row else default

    def set(self, key: str, value) -> None:
        def write():
            self.db.execute("INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
            self.db.commit()
            return True
        self._run(write)

    def set_telemetry(self, key: str, value) -> bool:
        """Best-effort observation storage; contention must not terminate the agent."""
        def write():
            self.db.execute("INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
            self.db.commit()
            return True
        return bool(self._run(write, transient_ok=True))

    def queue_event(self, event_type: str, severity: str, message: str) -> str:
        event_id = secrets.token_hex(16)
        payload = {"event_id": event_id, "event_type": event_type, "severity": severity, "message": message, "occurred_at": datetime.now(timezone.utc).isoformat(), "details": {}}
        def write():
            self.db.execute("INSERT INTO events(event_id,payload,created_at) VALUES(?,?,?)", (event_id, json.dumps(payload), payload["occurred_at"]))
            self.db.commit()
        self._run(write)
        return event_id

    def queued_events(self) -> list[dict]:
        rows = self._run(lambda: self.db.execute("SELECT payload FROM events ORDER BY created_at LIMIT 100").fetchall())
        return [json.loads(row[0]) for row in rows]

    def acknowledge_events(self, event_ids: list[str]) -> None:
        def write():
            self.db.executemany("DELETE FROM events WHERE event_id = ?", ((item,) for item in event_ids))
            self.db.commit()
        self._run(write)


def observe_host_resolver(interface: str | None) -> tuple[str, list[str], str]:
    """Return manager, effective nameservers and bounded observation status."""
    resolv_conf = Path("/etc/resolv.conf")
    nameservers: list[str] = []
    try:
        for line in resolv_conf.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() == "nameserver":
                try:
                    nameservers.append(str(__import__("ipaddress").ip_address(parts[1].split("%", 1)[0])))
                except ValueError:
                    continue
    except OSError:
        return "UNKNOWN", [], "UNAVAILABLE"

    manager = "STATIC"
    try:
        target = str(resolv_conf.resolve(strict=False))
    except OSError:
        target = ""
    if "systemd/resolve" in target or any(value.startswith("127.0.0.5") for value in nameservers):
        manager = "SYSTEMD_RESOLVED"
        command = ["/usr/bin/resolvectl", "dns"] + ([interface] if interface else [])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
            if result.returncode == 0:
                resolved: list[str] = []
                for token in result.stdout.replace("(", " ").replace(")", " ").split():
                    try:
                        resolved.append(str(__import__("ipaddress").ip_address(token.split("%", 1)[0])))
                    except ValueError:
                        continue
                if resolved:
                    nameservers = resolved
        except (OSError, subprocess.SubprocessError):
            pass
    elif Path("/run/NetworkManager").exists():
        manager = "NETWORK_MANAGER"
    elif Path("/etc/netplan").exists():
        manager = "NETPLAN"
    return manager, list(dict.fromkeys(nameservers))[:8], "FRESH"


def json_request(url: str, method: str, payload: dict | None, headers: dict[str, str] | None = None) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    req = request.Request(url, data=body if method != "GET" else None, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with request.urlopen(req, timeout=15) as response:
            return json.loads(response.read() or b"{}")
    except error.HTTPError as exc:
        if exc.code in {307, 308}:
            raise AgentRequestError(
                "redirect_rejected",
                "Kaya redirected the signed agent request. Generate a new command from the HTTPS Kaya page and try again.",
                status=exc.code,
            ) from None
        reason = {
            400: "request_invalid",
            401: "authentication_rejected",
            404: "endpoint_not_found",
            409: "request_conflict",
            413: "payload_rejected",
            426: "protocol_rejected",
            429: "rate_limited",
        }.get(exc.code, "server_error" if exc.code >= 500 else "http_rejected")
        raise AgentRequestError(reason, f"Kaya rejected the agent request with HTTP {exc.code}.", status=exc.code) from None
    except error.URLError as exc:
        cause = exc.reason
        if isinstance(cause, ssl.SSLCertVerificationError):
            reason, message = "tls_verification_failed", "Kaya's TLS certificate could not be verified."
        elif isinstance(cause, socket.gaierror):
            reason, message = "name_resolution_failed", "The Kaya host name could not be resolved."
        elif isinstance(cause, ConnectionRefusedError):
            reason, message = "connection_refused", "Kaya refused the agent connection."
        elif isinstance(cause, TimeoutError):
            reason, message = "connection_timeout", "The Kaya agent request timed out."
        else:
            reason, message = "connection_unavailable", "Kaya could not be reached."
        raise AgentRequestError(reason, message) from None


def report_transport_failure(state: State, operation: str, exc: Exception) -> None:
    reason = exc.reason if isinstance(exc, AgentRequestError) else type(exc).__name__.lower()
    safe = {"operation": operation, "reason": reason, "at": datetime.now(timezone.utc).isoformat()}
    if isinstance(exc, AgentRequestError) and exc.status is not None:
        safe["http_status"] = exc.status
    state.set_telemetry("last_error", safe)
    print(f"Kaya HA agent {operation} failed: {reason}", file=sys.stderr, flush=True)


def submit_pending(state: State, key: str, operation: str) -> bool:
    payload = state.get(key)
    if not payload:
        return True
    try:
        signed_request(state, "POST", "/api/ha/agent/v1/action-result", payload)
    except (AgentRequestError, TimeoutError, ValueError, KeyError) as exc:
        report_transport_failure(state, operation, exc)
        return False
    state.set(key, None)
    return True


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


def probe_icmp(peer_host: str, *, runner=subprocess.run) -> tuple[bool | None, str]:
    """Run the fixed ICMP probe without treating local execution failure as peer failure."""
    try:
        result = runner(
            ["/usr/bin/ping", "-c", "1", "-W", "1", peer_host],
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None, ICMP_UNAVAILABLE
    if result.returncode == 0:
        return True, ICMP_AVAILABLE
    if result.returncode == 1:
        return False, ICMP_NO_REPLY
    return None, ICMP_UNAVAILABLE


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
    # The server's recovery gate uses observed_generation as the node's
    # acknowledgement of the role generation.  Keep the cluster-generation
    # replay guard separate: a configuration update can be accepted without
    # changing ownership, while a verified failover can advance role_generation
    # without advancing cluster_generation.  Never move either local marker
    # backwards when a late desired-state response arrives.
    incoming_role_generation = int(desired.get("role_generation") or 0)
    state.set(
        "observed_generation",
        max(int(state.get("observed_generation", 0)), incoming_role_generation),
    )
    state.set("desired_role", desired["desired_role"])
    state.set("desired_virtual_ip", desired.get("virtual_ip"))
    state.set(
        "role_generation",
        max(int(state.get("role_generation", 0)), incoming_role_generation),
    )
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
    resolver_action = desired.get("resolver_repair")
    if resolver_action:
        pending = state.get("pending_resolver_action_result")
        if pending and pending.get("action_id") == resolver_action.get("action_id"):
            return
        try:
            try:
                from .resolver_runtime import apply_resolver_action
            except ImportError:
                from resolver_runtime import apply_resolver_action
            kwargs = {"runner": helper_runner} if helper_runner is not None else {}
            result = apply_resolver_action(resolver_action, **kwargs)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            result = {"action_id": resolver_action.get("action_id", "invalid"), "action_type": "RESOLVER_REPAIR", "generation": int(resolver_action.get("generation") or 0), "status": "FAILED", "checksum": None, "backup_reference": None, "message": str(exc)[:1000]}
        state.set("pending_resolver_action_result", result)


def run_once(state: State) -> None:
    state.telemetry_deferred = False
    _config = json.loads(state.config_path.read_text(encoding="utf-8"))
    try:
        try:
            from .keepalived_runtime import refresh_vip_state
        except ImportError:
            from keepalived_runtime import refresh_vip_state
        refresh_vip_state(state)
    except Exception:
        state.set_telemetry("keepalived_runtime_state", "UNKNOWN")
    try:
        try:
            from .failover_runtime import refresh_dhcp_state
        except ImportError:
            from failover_runtime import refresh_dhcp_state
        refresh_dhcp_state(state)
    except Exception:
        state.set_telemetry("dhcp_configured", None)
        state.set_telemetry("dhcp_listener_active", None)
        state.set_telemetry("ftl_active", None)
        state.set_telemetry("dhcp_runtime_state", "UNKNOWN")
        state.set_telemetry("dhcp_observation_status", "UNAVAILABLE")
        state.set_telemetry("dhcp_observed_at", datetime.now(timezone.utc).isoformat())
    try:
        check = subprocess.run(["/usr/lib/kaya-ha-agent/check-pihole-dns", "--observe"], capture_output=True, timeout=10, check=False)
        state.set_telemetry("dns_healthy", check.returncode == 0)
    except (OSError, subprocess.SubprocessError):
        state.set_telemetry("dns_healthy", False)
    peer_host = str(state.get("peer_host", "") or "").strip()
    if peer_host:
        peer_reachable, icmp_probe_status = probe_icmp(peer_host)
        state.set_telemetry("peer_reachable", peer_reachable)
        state.set_telemetry("peer_icmp_probe_status", icmp_probe_status)
        try:
            with socket.create_connection((peer_host, 53), timeout=2):
                state.set_telemetry("peer_dns_reachable", True)
        except OSError:
            state.set_telemetry("peer_dns_reachable", False)
    else:
        state.set_telemetry("peer_reachable", None)
        state.set_telemetry("peer_icmp_probe_status", None)
        state.set_telemetry("peer_dns_reachable", None)
    resolver_manager, resolver_nameservers, resolver_status = observe_host_resolver(state.get("network_interface"))
    state.set_telemetry("resolver_manager", resolver_manager)
    state.set_telemetry("resolver_nameservers", resolver_nameservers)
    state.set_telemetry("resolver_observation_status", resolver_status)
    if state.telemetry_deferred:
        return
    report_sequence = int(state.get("report_sequence", 0)) + 1
    if not state.set_telemetry("report_sequence", report_sequence):
        return
    heartbeat = {"report_sequence": report_sequence, "reported_at": datetime.now(timezone.utc).isoformat(), "observed_role": state.get("observed_role", "STANDBY"), "observed_generation": int(state.get("observed_generation", 0)), "vip_owned": bool(state.get("vip_owned", False)), "dhcp_running": bool(state.get("dhcp_running", False)), "dhcp_configured": state.get("dhcp_configured"), "dhcp_listener_active": state.get("dhcp_listener_active"), "ftl_active": state.get("ftl_active"), "dhcp_runtime_state": state.get("dhcp_runtime_state", "UNKNOWN"), "dhcp_observation_status": state.get("dhcp_observation_status", "UNAVAILABLE"), "dhcp_observed_at": state.get("dhcp_observed_at"), "dns_healthy": bool(state.get("dns_healthy", False)), "peer_reachable": state.get("peer_reachable"), "peer_icmp_probe_status": state.get("peer_icmp_probe_status"), "peer_dns_reachable": state.get("peer_dns_reachable"), "resolver_manager": state.get("resolver_manager", "UNKNOWN"), "resolver_nameservers": state.get("resolver_nameservers", []), "resolver_observation_status": state.get("resolver_observation_status", "UNAVAILABLE"), "lease_generation": int(state.get("lease_generation", 0)), "config_generation": int(state.get("config_generation", 0)), "agent_version": AGENT_VERSION, "keepalived_runtime_state": state.get("keepalived_runtime_state", "UNKNOWN")}
    response = signed_request(state, "POST", "/api/ha/agent/v1/heartbeat", heartbeat)
    if response.get("accepted") is False:
        reason = str(response.get("reason") or "report_rejected")[:80]
        report_transport_failure(state, "heartbeat acceptance", AgentRequestError(f"report_{reason}", "Kaya did not accept the runtime observation."))

    # Local failover evidence is authoritative, generation-bound safety proof.
    # Deliver it before optional action results so one obsolete/rejected result
    # cannot indefinitely hide a successful failover from Kaya.
    queued = state.queued_events()
    if queued:
        try:
            signed_request(state, "POST", "/api/ha/agent/v1/events", {"events": queued})
        except (AgentRequestError, TimeoutError, ValueError, KeyError) as exc:
            report_transport_failure(state, "event delivery", exc)
        else:
            state.acknowledge_events([item["event_id"] for item in queued])

    reconcile_desired(state, response["desired"])
    submit_pending(state, "pending_action_result", "Keepalived result delivery")
    submit_pending(state, "pending_lease_action_result", "lease result delivery")
    submit_pending(state, "pending_failover_action_result", "failover result delivery")
    submit_pending(state, "pending_resolver_action_result", "resolver repair result delivery")


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
        try:
            register(state, args)
        except (error.URLError, TimeoutError, ValueError, KeyError) as exc:
            raise SystemExit(f"Kaya HA agent registration failed: {exc}") from None
    elif args.command == "event":
        print(state.queue_event(args.event_type, args.severity, args.message))
    elif args.command == "once":
        run_once(state)
    else:
        while True:
            try:
                run_once(state)
            except (error.URLError, TimeoutError, ValueError, KeyError, TransientStateBusy) as exc:
                report_transport_failure(state, "heartbeat", exc)
            time.sleep(max(5, args.interval))


if __name__ == "__main__":
    main()
