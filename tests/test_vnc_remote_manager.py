import json

from app.core.security import decrypt_secret
from app.models.models import IPAddress, RemoteAccess
from app.routers import remote_manager


def _vnc_remote():
    address = IPAddress(address="192.0.2.90", name="Synthetic VNC")
    return RemoteAccess(ip_address=address, protocol="vnc", port=5900, is_enabled=True)


def test_vnc_protocol_and_default_port_are_supported():
    assert remote_manager.clean_protocol("vnc") == "vnc"
    assert remote_manager.default_port("vnc") == 5900
    assert remote_manager.clean_port(5901, "vnc") == 5901
    assert remote_manager.clean_port(0, "vnc") == 5900


def test_vnc_token_contains_server_side_connection_settings_only():
    token = remote_manager.create_guacamole_token(
        _vnc_remote(), "vnc", "", "synthetic-vnc-password", 1280, 720, 96, "",
        {"vnc_read_only": "1", "vnc_clipboard": "0", "vnc_cursor": "remote", "vnc_resize_method": "display-update"},
    )
    payload = json.loads(decrypt_secret(token))
    settings = payload["connection"]["settings"]
    assert payload["connection"]["type"] == "vnc"
    assert settings["hostname"] == "192.0.2.90"
    assert settings["port"] == 5900
    assert settings["username"] == ""
    assert settings["password"] == "synthetic-vnc-password"
    assert settings["read-only"] is True
    assert settings["disable-copy"] is True
    assert settings["disable-paste"] is True
    assert token not in json.dumps(settings)


def test_graphical_recording_rules_include_vnc_without_changing_ssh():
    assert remote_manager.recording_extension("video/webm", "rdp") == ".webm"
    assert remote_manager.recording_extension("video/webm", "vnc") == ".webm"
    assert remote_manager.recording_extension("text/plain", "ssh") == ".txt"
