import os
import subprocess
from pathlib import Path


_process: subprocess.Popen | None = None


def stop_homelab_remote_service() -> None:
    global _process
    if not _process:
        return
    if _process.poll() is None:
        _process.terminate()
        try:
            _process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _process.kill()
    _process = None


def start_homelab_remote_service() -> None:
    global _process
    if _process and _process.poll() is None:
        return

    script = Path("/app/scripts/homelab-remote-manager.cjs")
    if not script.exists():
        script = Path("scripts/homelab-remote-manager.cjs")
    if not script.exists():
        return

    env = os.environ.copy()
    env.setdefault("HOMELAB_REMOTE_WS_HOST", "127.0.0.1")
    env.setdefault("HOMELAB_REMOTE_WS_PORT", "30009")
    _process = subprocess.Popen(["node", str(script)], env=env)
