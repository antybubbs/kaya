import logging
import os
import socket
import subprocess
import threading
import time

from app.core.config import get_settings
from app.core.paths import SCRIPT_DIR
from app.db.session import SessionLocal
from app.models.models import RemoteManagerSetting

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 30008
BRIDGE_READY_TIMEOUT_SECONDS = 10.0
BRIDGE_POLL_INTERVAL_SECONDS = 0.05
_process: subprocess.Popen | None = None
_startup_lock = threading.RLock()
logger = logging.getLogger(__name__)


class GuacamoleBridgeError(RuntimeError):
    """The local Guacamole WebSocket bridge could not become ready."""


def is_guacamole_bridge_ready() -> bool:
    """Return whether the local bridge is accepting TCP connections."""
    try:
        with socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=0.25):
            return True
    except OSError:
        return False


def wait_for_guacamole_bridge_ready(
    process: subprocess.Popen,
    *,
    timeout: float = BRIDGE_READY_TIMEOUT_SECONDS,
) -> float:
    """Wait for the child process and listener, returning startup milliseconds."""
    started = time.monotonic()
    deadline = started + timeout
    while True:
        return_code = process.poll()
        if return_code is not None:
            raise GuacamoleBridgeError(
                f"Guacamole bridge exited during startup (code {return_code})."
            )
        if is_guacamole_bridge_ready():
            return (time.monotonic() - started) * 1000
        if time.monotonic() >= deadline:
            raise GuacamoleBridgeError(
                f"Guacamole bridge did not become ready within {timeout:.1f} seconds."
            )
        time.sleep(BRIDGE_POLL_INTERVAL_SECONDS)


def _remote_settings() -> dict[str, str]:
    values = {"guacamole_enabled": "0", "guacd_host": "", "guacd_port": "4822"}
    db = SessionLocal()
    try:
        for row in db.query(RemoteManagerSetting).all():
            if row.key in values:
                values[row.key] = row.value or ""
    finally:
        db.close()
    app_settings = get_settings()
    if app_settings.guacd_host:
        values["guacamole_enabled"] = "1"
        values["guacd_host"] = app_settings.guacd_host
    if app_settings.guacd_port:
        values["guacd_port"] = str(app_settings.guacd_port)
    return values


def stop_guacamole_bridge() -> None:
    global _process
    with _startup_lock:
        if not _process:
            return
        if _process.poll() is None:
            try:
                _process.terminate()
                _process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                logger.warning(
                    "Guacamole bridge did not stop cleanly; forcing termination",
                    exc_info=True,
                )
                try:
                    _process.kill()
                except OSError:
                    logger.exception("Unable to force-stop the Guacamole bridge")
        _process = None


def start_guacamole_bridge() -> None:
    global _process
    with _startup_lock:
        settings = _remote_settings()
        if settings.get("guacamole_enabled") != "1" or not settings.get("guacd_host", "").strip():
            stop_guacamole_bridge()
            return
        if _process and _process.poll() is None:
            try:
                startup_ms = wait_for_guacamole_bridge_ready(_process)
            except GuacamoleBridgeError:
                raise
            logger.debug("Guacamole bridge already running and ready startup_ms=%.1f", startup_ms)
            return
        app_settings = get_settings()
        env = os.environ.copy()
        env.update(
            {
                "GUACAMOLE_WS_PORT": str(BRIDGE_PORT),
                "GUACD_HOST": settings["guacd_host"].strip(),
                "GUACD_PORT": settings.get("guacd_port", "4822"),
                "SECRET_KEY": app_settings.secret_key,
                "ENCRYPTION_KEY": app_settings.encryption_key,
            }
        )
        script = SCRIPT_DIR / "guacamole-server.cjs"
        _process = subprocess.Popen(["node", str(script)], env=env)
        process = _process
        logger.info("Guacamole bridge starting pid=%s", process.pid)
        try:
            startup_ms = wait_for_guacamole_bridge_ready(process)
        except GuacamoleBridgeError:
            if process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    logger.warning("Guacamole bridge cleanup after startup failure was incomplete")
            _process = None
            logger.error("Guacamole bridge failed to become ready", exc_info=True)
            raise
        logger.info(
            "Guacamole bridge ready host=%s port=%s startup_ms=%.1f",
            BRIDGE_HOST,
            BRIDGE_PORT,
            startup_ms,
        )


def restart_guacamole_bridge() -> None:
    stop_guacamole_bridge()
    start_guacamole_bridge()
