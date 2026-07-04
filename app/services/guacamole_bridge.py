import os
import signal
import subprocess
from pathlib import Path

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.models import RemoteManagerSetting

BRIDGE_PORT = "30008"
_process: subprocess.Popen | None = None


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
    if not _process:
        return
    if _process.poll() is None:
        try:
            _process.terminate()
            _process.wait(timeout=5)
        except Exception:
            try:
                os.kill(_process.pid, signal.SIGKILL)
            except Exception:
                pass
    _process = None


def start_guacamole_bridge() -> None:
    global _process
    settings = _remote_settings()
    if settings.get("guacamole_enabled") != "1" or not settings.get("guacd_host", "").strip():
        stop_guacamole_bridge()
        return
    if _process and _process.poll() is None:
        return
    app_settings = get_settings()
    env = os.environ.copy()
    env.update(
        {
            "GUACAMOLE_WS_PORT": BRIDGE_PORT,
            "GUACD_HOST": settings["guacd_host"].strip(),
            "GUACD_PORT": settings.get("guacd_port", "4822"),
            "SECRET_KEY": app_settings.secret_key,
            "ENCRYPTION_KEY": app_settings.encryption_key,
        }
    )
    script = Path("/app/scripts/guacamole-server.cjs")
    if not script.exists():
        script = Path("scripts/guacamole-server.cjs")
    _process = subprocess.Popen(["node", str(script)], env=env)


def restart_guacamole_bridge() -> None:
    stop_guacamole_bridge()
    start_guacamole_bridge()
