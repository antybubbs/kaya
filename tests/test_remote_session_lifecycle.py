from pathlib import Path


ROOT = Path(__file__).parents[1]
REMOTE_JS = (ROOT / "app/static/js/remote_session.js").read_text(encoding="utf-8")
REMOTE_ROUTER = (ROOT / "app/routers/remote_manager.py").read_text(encoding="utf-8")
REMOTE_TEMPLATE = (ROOT / "app/templates/_remote_session_panel.html").read_text(encoding="utf-8")
SSH_SERVICE = (ROOT / "scripts/kaya-remote-manager.cjs").read_text(encoding="utf-8")


def test_ssh_login_requires_backend_session_readiness():
    submit = REMOTE_JS.split('passwordForm.addEventListener("submit"', 1)[1]

    assert "let sessionReady = false;" in REMOTE_JS
    assert '"type": "ready"' in REMOTE_ROUTER
    assert REMOTE_ROUTER.index('await websockets.connect("ws://127.0.0.1:30009"') < REMOTE_ROUTER.index('await websocket.send_json({"type": "ready"')
    assert "if (!sessionReady || !socket || socket.readyState !== WebSocket.OPEN) return;" in submit
    assert "openSessionSocket();" in REMOTE_JS
    assert REMOTE_TEMPLATE.count('<button type="submit" disabled>Start SSH session</button>') == 1


def test_first_login_sends_one_password_bearing_request_after_ready():
    submit = REMOTE_JS.split('passwordForm.addEventListener("submit"', 1)[1]

    assert submit.count('sendTerminalMessage("connectToHost"') == 1
    assert 'message.type === "ready"' in REMOTE_JS
    assert 'password: sessionPassword' in submit
    assert 'new WebSocket(wsUrl)' not in submit


def test_session_setup_failure_is_distinct_from_target_ssh_failure():
    assert '"type": "session_error"' in REMOTE_ROUTER
    assert 'Remote Manager session could not be established.' in REMOTE_JS
    assert 'SSH connection refused by the target host.' in SSH_SERVICE
    assert 'SSH authentication failed. Check the username and password.' in SSH_SERVICE


def test_remote_password_is_not_logged_or_written_to_audit_messages():
    websocket_code = REMOTE_ROUTER[REMOTE_ROUTER.find("async def ssh_websocket"):]
    assert 'logger.warning("Remote Manager SSH upstream session could not be established (%s)", type(exc).__name__)' in websocket_code
    assert "password" not in websocket_code.split("logger.warning", 1)[1].split("\n", 1)[0].lower()
    assert "sessionPassword" not in REMOTE_ROUTER
    assert "console.log" not in REMOTE_JS
