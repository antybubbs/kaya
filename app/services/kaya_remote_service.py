import os
import subprocess

from app.core.paths import SCRIPT_DIR


_process: subprocess.Popen | None = None


def stop_kaya_remote_service() -> None:
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


def start_kaya_remote_service() -> None:
    global _process
    if _process and _process.poll() is None:
        return

    script = SCRIPT_DIR / "kaya-remote-manager.cjs"
    if not script.exists():
        return

    env = os.environ.copy()
    env.setdefault("KAYA_REMOTE_WS_HOST", os.environ.get("HOMELAB_REMOTE_WS_HOST", "127.0.0.1"))
    env.setdefault("KAYA_REMOTE_WS_PORT", os.environ.get("HOMELAB_REMOTE_WS_PORT", "30009"))
    _process = subprocess.Popen(["node", str(script)], env=env)
