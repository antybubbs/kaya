from pathlib import Path


ROOT = Path(__file__).parents[1]
BRIDGE = (ROOT / "app/services/guacamole_bridge.py").read_text(encoding="utf-8")
ROUTER = (ROOT / "app/routers/remote_manager.py").read_text(encoding="utf-8")
LOGGING = (ROOT / "app/core/logging.py").read_text(encoding="utf-8")


def test_bridge_readiness_is_listener_based_and_bounded():
    assert "socket.create_connection((BRIDGE_HOST, BRIDGE_PORT)" in BRIDGE
    assert "time.monotonic()" in BRIDGE
    assert "process.poll()" in BRIDGE
    assert "BRIDGE_READY_TIMEOUT_SECONDS = 10.0" in BRIDGE
    assert "time.sleep(BRIDGE_POLL_INTERVAL_SECONDS)" in BRIDGE


def test_startup_is_serialised_and_waits_after_spawn():
    assert "threading.RLock()" in BRIDGE
    assert "_startup_lock" in BRIDGE
    assert "_process = subprocess.Popen" in BRIDGE
    assert "Guacamole bridge process could not be started." in BRIDGE
    assert "startup_ms = wait_for_guacamole_bridge_ready(process)" in BRIDGE
    assert 'logger.info("Guacamole bridge starting pid=%s", process.pid)' in BRIDGE
    assert '"Guacamole bridge ready host=%s port=%s startup_ms=%.1f"' in BRIDGE


def test_rdp_start_and_websocket_require_bridge_readiness():
    assert "await run_in_threadpool(start_guacamole_bridge)" in ROUTER
    assert "Guacamole bridge is not ready. The RDP session was not started." in ROUTER
    assert "await run_in_threadpool(is_guacamole_bridge_ready)" in ROUTER
    assert "Kaya's Guacamole bridge is not ready. Try starting the RDP session again." in ROUTER


def test_rdp_websocket_access_logs_redact_session_tokens():
    assert 'path.startswith("/remote-manager/") and "/rdp/ws?" in path' in LOGGING
    assert 'clean[2] = path.split("?", 1)[0] + "?[redacted]"' in LOGGING
    assert 'detail=f"RDP connection failed for {remote_label_text} ({remote_address}:{remote_port}); Kaya\'s Guacamole bridge rejected the tunnel"' in ROUTER
    assert 'guac_instruction("error", "Kaya\'s Guacamole bridge could not open the RDP tunnel."' in ROUTER
    assert 'detail=f"RDP connection failed for {remote_label_text} ({remote_address}:{remote_port}): {exc}"' not in ROUTER
