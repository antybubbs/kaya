import json
from datetime import datetime

import pytest

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


def test_vnc_interactive_token_disables_guacamole_read_only():
    token = remote_manager.create_guacamole_token(
        _vnc_remote(), "vnc", "", "synthetic-vnc-password", 1280, 720, 96, "",
        {"vnc_read_only": "0", "vnc_clipboard": "1", "vnc_cursor": "remote", "vnc_resize_method": "display-update"},
    )
    payload = json.loads(decrypt_secret(token))
    assert payload["connection"]["settings"]["read-only"] is False
    assert payload["connection"]["settings"]["disable-copy"] is False
    assert payload["connection"]["settings"]["disable-paste"] is False


def test_graphical_recording_rules_include_vnc_without_changing_ssh():
    assert remote_manager.recording_extension("video/webm", "rdp") == ".webm"
    assert remote_manager.recording_extension("video/webm", "vnc") == ".webm"
    assert remote_manager.recording_extension("text/plain", "ssh") == ".txt"


def test_rdp_certificate_trust_is_ignored_for_non_rdp_protocols():
    remote = _vnc_remote()
    remote.rdp_cert_fingerprints = f"sha256:{'a' * 64}"
    remote.rdp_trust_invalidated_at = datetime.utcnow()

    remote.protocol = "rdp"
    with pytest.raises(ValueError, match="re-authorized"):
        remote_manager.rdp_certificate_settings(remote)

    remote.protocol = "vnc"
    assert remote_manager.rdp_certificate_settings(remote) == {"ignore-cert": False, "cert-tofu": False}
    assert remote_manager.rdp_pin_count(remote) == 0
    vnc_token = remote_manager.create_guacamole_token(
        remote, "vnc", "", "synthetic-vnc-password", 1280, 720, 96, "", {},
    )
    assert vnc_token

    remote.protocol = "ssh"
    assert remote_manager.rdp_certificate_settings(remote) == {"ignore-cert": False, "cert-tofu": False}
    assert remote_manager.rdp_pin_count(remote) == 0


def test_protocol_switch_back_to_rdp_restores_existing_trust_policy():
    remote = _vnc_remote()
    remote.rdp_cert_fingerprints = f"sha256:{'b' * 64}"
    remote.rdp_trust_invalidated_at = datetime.utcnow()
    remote.protocol = "vnc"
    assert remote_manager.rdp_pin_count(remote) == 0
    remote.protocol = "rdp"
    with pytest.raises(ValueError, match="re-authorized"):
        remote_manager.rdp_certificate_settings(remote)


def test_certificate_warning_template_is_protocol_guarded():
    panel = open("app/templates/_remote_session_panel.html", encoding="utf-8").read()
    settings = open("app/templates/remote_host_settings.html", encoding="utf-8").read()
    assert "remote.protocol == 'rdp' and remote.rdp_trust_invalidated_at" in panel
    assert "{% if remote.protocol == 'rdp' %}" in settings
    assert "rdp_trust_invalidated_at = None" not in open("app/routers/remote_manager.py", encoding="utf-8").read().split("def save_remote_host_settings", 1)[1].split("def _rdp_certificate_discover_response", 1)[0]


def test_vnc_input_mode_is_server_authoritative_and_ui_scoped_to_vnc():
    router = open("app/routers/remote_manager.py", encoding="utf-8").read()
    panel = open("app/templates/_remote_session_panel.html", encoding="utf-8").read()
    settings = open("app/templates/remote_host_settings.html", encoding="utf-8").read()
    client = open("app/static/js/remote_rdp.js", encoding="utf-8").read()
    workspace = open("app/static/js/remote_workspace.js", encoding="utf-8").read()
    assert 'payload.get("read_only")' in router
    assert 'payload.get("mode_change_from")' in router
    assert 'audit_action = "mode_changed"' in router
    assert '"read-only": protocol_settings.get("vnc_read_only"' in router
    assert 'data-vnc-read-only=' in panel
    assert "Default VNC mode" in settings
    assert 'protocol === "vnc"' in client
    assert 'event.data.type === "kaya:remote-input-mode"' in client
    assert 'inputEnabled: inputEnabled()' in client
    assert 'tab.protocol === "vnc"' in workspace
    assert 'type: "kaya:remote-input-mode"' in workspace
    assert 'inputMode: pending.inputMode' in workspace
    assert "      inputMode,\n" in client
    assert "mode_change_from: inputModeChangeFrom" in client


def test_vnc_view_only_suppresses_input_and_keys_but_recording_state_remains_available():
    client = open("app/static/js/remote_rdp.js", encoding="utf-8").read()
    keys = open("app/static/js/remote_keys.js", encoding="utf-8").read()
    assert "if (!inputEnabled()) return;" in client
    assert "if (!inputEnabled()) return false;" in client
    assert "inputEnabled: inputEnabled()" in keys or "inputEnabled = true" in keys
    assert "available = Boolean(window.MediaRecorder) && recordingEnabled && connected && displayReady" in client


def test_protocol_availability_and_vnc_enforcement_are_allowlisted():
    assert remote_manager.SETTINGS["ssh_enabled"] == "1"
    assert remote_manager.SETTINGS["rdp_enabled"] == "1"
    assert remote_manager.SETTINGS["vnc_enabled"] == "1"
    assert remote_manager.protocol_enabled("ssh", {})
    assert not remote_manager.protocol_enabled("rdp", {"rdp_enabled": "0"})
    assert not remote_manager.protocol_enabled("vnc", {"vnc_enabled": "0"})
    assert remote_manager.clean_global_setting("vnc_input_mode_enforcement", "live") == "live"
    assert remote_manager.clean_global_setting("vnc_input_mode_enforcement", "unsafe") == "guacamole"


def test_protocol_gates_cover_sessions_starts_and_guacamole_websocket():
    router = open("app/routers/remote_manager.py", encoding="utf-8").read()
    panel = open("app/templates/_remote_session_panel.html", encoding="utf-8").read()
    client = open("app/static/js/remote_rdp.js", encoding="utf-8").read()
    assert "require_enabled_protocol(row, settings)" in router
    assert "if not protocol_enabled(protocol, settings)" in router
    assert "data-vnc-input-enforcement" in panel
    assert "inputModeEnforcement" in client
