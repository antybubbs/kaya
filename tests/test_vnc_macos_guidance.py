import asyncio
import json
import logging
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import websockets
from jinja2 import Environment, FileSystemLoader

from app.core.security import decrypt_secret
from app.models.models import IPAddress, RemoteAccess
from app.routers import remote_manager

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_TOKEN = "synthetic-session-token-not-real"
SYNTHETIC_PASSWORD = "synthetic-vnc-password"
SYNTHETIC_USERNAME = "synthetic-mac-user"
MACOS_HELP = "macOS Screen Sharing requires the Mac account short username and password."
READY_MESSAGE = "0.,37.$00000000-0000-0000-0000-000000000000;"


def _render_panel(protocol: str) -> str:
    environment = Environment(loader=FileSystemLoader(ROOT / "app" / "templates"), autoescape=True)
    remote = SimpleNamespace(
        id=1, protocol=protocol, username=None, rdp_trust_invalidated_at=None,
        ip_address=SimpleNamespace(address="192.0.2.90"),
    )
    return environment.get_template("_remote_session_panel.html").render(
        remote=remote,
        user=SimpleNamespace(role="editor"),
        request=SimpleNamespace(scope={}),
        settings={"guacamole_enabled": "1", "guacd_host": "guacd", "guacd_port": "4822"},
        remote_settings={"terminal": {}, "vnc": {}, "rdp": {}},
        csrf_token="synthetic-csrf",
        ssh_host_key_ready=True,
    )


def test_vnc_username_remains_optional_in_ui_and_token():
    html = _render_panel("vnc")
    form = html.split('class="remote-credential-form rdp-credential-form"', 1)[1].split("</form>", 1)[0]
    assert "Username (optional)" in form
    username_input = form.split('name="rdp_username"', 1)[1].split(">", 1)[0]
    assert "required" not in username_input

    token = remote_manager.create_guacamole_token(
        SimpleNamespace(ip_address=SimpleNamespace(address="192.0.2.90"), port=5900),
        "vnc", "", SYNTHETIC_PASSWORD, 1280, 720, 96, "", {},
    )
    assert json.loads(decrypt_secret(token))["connection"]["settings"]["username"] == ""


def test_vnc_start_does_not_require_a_username():
    router = (ROOT / "app" / "routers" / "remote_manager.py").read_text(encoding="utf-8")
    vnc_start = router.split("async def vnc_start", 1)[1].split("\n@router.", 1)[0]
    assert "if not password:" in vnc_start
    assert "not username" not in vnc_start


def test_macos_guidance_renders_only_for_vnc():
    vnc_html = _render_panel("vnc")
    assert "Username is optional for many VNC servers." in vnc_html
    assert MACOS_HELP in vnc_html
    assert vnc_html.count("data-vnc-username-help") == 1
    for protocol in ("rdp", "ssh"):
        html = _render_panel(protocol)
        assert "data-vnc-username-help" not in html
        assert "macOS" not in html


def test_vnc_tunnel_closed_before_display_maps_to_actionable_error():
    progress = remote_manager.GuacamoleTunnelProgress()
    progress.observe(READY_MESSAGE)
    progress.observe("3.nop;")
    instruction = remote_manager.vnc_stall_error_instruction("vnc", progress, 1011)
    assert instruction == remote_manager.guac_instruction(
        "error", remote_manager.VNC_AUTH_STALL_MESSAGE, remote_manager.GUACAMOLE_STATUS_UPSTREAM_TIMEOUT,
    )
    assert "If this is a Mac using Screen Sharing" in remote_manager.VNC_AUTH_STALL_MESSAGE


def test_vnc_stall_mapping_handles_instructions_split_across_messages():
    progress = remote_manager.GuacamoleTunnelProgress()
    progress.observe("4.sy")
    progress.observe("nc,13.1700000000000;")
    assert progress.display_ready
    assert remote_manager.vnc_stall_error_instruction("vnc", progress, 1011) is None


@pytest.mark.parametrize(
    ("messages", "close_code"),
    [
        ([READY_MESSAGE, "4.size,1.0,4.1280,3.720;4.sync,13.1700000000000;"], 1011),
        ([READY_MESSAGE, "5.error,18.Aborted. See logs.,3.519;"], 1011),
        ([READY_MESSAGE], 1000),
        ([READY_MESSAGE], None),
    ],
)
def test_vnc_stall_mapping_leaves_other_outcomes_unchanged(messages, close_code):
    progress = remote_manager.GuacamoleTunnelProgress()
    for message in messages:
        progress.observe(message)
    assert remote_manager.vnc_stall_error_instruction("vnc", progress, close_code) is None


@pytest.mark.parametrize("protocol", ["rdp", "ssh"])
def test_non_vnc_inactivity_is_not_remapped(protocol):
    progress = remote_manager.GuacamoleTunnelProgress()
    progress.observe(READY_MESSAGE)
    assert remote_manager.vnc_stall_error_instruction(protocol, progress, 1011) is None


def test_ssh_websocket_does_not_use_graphical_stall_mapping():
    router = (ROOT / "app" / "routers" / "remote_manager.py").read_text(encoding="utf-8")
    ssh_handler = router.split("async def ssh_websocket", 1)[1].split("async def _guacamole_websocket", 1)[0]
    assert "vnc_stall_error_instruction" not in ssh_handler
    assert "VNC_AUTH_STALL_MESSAGE" not in ssh_handler


class _FakeUpstream:
    def __init__(self, messages, close_code):
        self._messages = list(messages)
        self.close_code = close_code

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._messages:
            raise StopAsyncIteration
        return self._messages.pop(0)

    async def close(self):
        return None


class _FakeBrowser:
    def __init__(self):
        self.query_params = {"token": SYNTHETIC_TOKEN, "width": "1280", "height": "720"}
        self.client = SimpleNamespace(host="203.0.113.10")
        self.sent: list[str] = []

    async def accept(self, subprotocol=None):
        return None

    async def send_text(self, text):
        self.sent.append(text)

    async def send_bytes(self, data):
        self.sent.append(data.decode("utf-8"))

    async def receive(self):
        await asyncio.sleep(3600)

    async def close(self, code=1000):
        return None


def _run_proxy(monkeypatch, protocol, upstream_messages, close_code):
    remote = RemoteAccess(
        id=1, ip_address=IPAddress(address="192.0.2.90", name="Synthetic"),
        protocol=protocol, port=5900 if protocol == "vnc" else 3389, is_enabled=True,
    )
    user = SimpleNamespace(id=7)

    class _FakeDb:
        def get(self, model, _identifier):
            return remote if model is RemoteAccess else user

        def close(self):
            return None

    async def fake_connect(url, **_kwargs):
        assert SYNTHETIC_PASSWORD not in url
        return _FakeUpstream(upstream_messages, close_code)

    monkeypatch.setattr(remote_manager, "SessionLocal", _FakeDb)
    monkeypatch.setattr(remote_manager, "websocket_origin_allowed", lambda *_args: True)
    monkeypatch.setattr(remote_manager, "authenticated_websocket_user", lambda *_args: user)
    monkeypatch.setattr(remote_manager, "cleanup_rdp_tokens", lambda: None)
    monkeypatch.setattr(remote_manager, "settings_map", lambda _db: {})
    monkeypatch.setattr(remote_manager, "is_guacamole_bridge_ready", lambda: True)
    monkeypatch.setattr(remote_manager, "write_audit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(remote_manager, "remote_label", lambda _row: "Synthetic host")
    monkeypatch.setattr(websockets, "connect", fake_connect)
    monkeypatch.setitem(
        remote_manager.guacamole_tokens, SYNTHETIC_TOKEN,
        remote_manager.GuacamoleSessionToken(remote_id=1, user_id=7, protocol=protocol, created_at=time.time()),
    )
    browser = _FakeBrowser()
    asyncio.run(remote_manager._guacamole_websocket(browser, 1, protocol))
    return browser


def test_vnc_proxy_surfaces_stall_error_without_leaking_secrets(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=remote_manager.logger.name)
    browser = _run_proxy(monkeypatch, "vnc", [READY_MESSAGE], 1011)
    assert browser.sent[0] == READY_MESSAGE
    assert browser.sent[-1] == remote_manager.guac_instruction(
        "error", remote_manager.VNC_AUTH_STALL_MESSAGE, remote_manager.GUACAMOLE_STATUS_UPSTREAM_TIMEOUT,
    )
    assert "closed before the first display frame" in caplog.text
    for secret in (SYNTHETIC_TOKEN, SYNTHETIC_PASSWORD, SYNTHETIC_USERNAME):
        assert secret not in caplog.text
        assert all(secret not in message for message in browser.sent)


def test_rdp_proxy_inactivity_close_is_unchanged(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=remote_manager.logger.name)
    browser = _run_proxy(monkeypatch, "rdp", [READY_MESSAGE], 1011)
    assert browser.sent == [READY_MESSAGE]
    assert "closed before the first display frame" not in caplog.text


def test_vnc_proxy_after_first_frame_is_unchanged(monkeypatch):
    frame = "4.sync,13.1700000000000;"
    browser = _run_proxy(monkeypatch, "vnc", [READY_MESSAGE, frame], 1011)
    assert browser.sent == [READY_MESSAGE, frame]
