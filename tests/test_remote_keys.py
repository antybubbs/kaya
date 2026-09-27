from pathlib import Path
import subprocess


ROOT = Path(__file__).parents[1]
KEYS_JS = (ROOT / "app/static/js/remote_keys.js").read_text(encoding="utf-8")
WORKSPACE_JS = (ROOT / "app/static/js/remote_workspace.js").read_text(encoding="utf-8")
RDP_JS = (ROOT / "app/static/js/remote_rdp.js").read_text(encoding="utf-8")
REMOTE_CSS = (ROOT / "app/static/css/remote.css").read_text(encoding="utf-8")
PANEL_TEMPLATE = (ROOT / "app/templates/remote_session_panel.html").read_text(encoding="utf-8")
REMOTE_TEMPLATE = (ROOT / "app/templates/_remote_session_panel.html").read_text(encoding="utf-8")


def test_special_key_menu_is_graphical_only_and_keeps_required_order():
    assert "remote.protocol in ['rdp', 'vnc']" in PANEL_TEMPLATE
    assert 'remote.protocol == \'ssh\'' in REMOTE_TEMPLATE
    expected = [
        '"ctrl-alt-delete"',
        '"ctrl-alt-backspace"',
        '"alt-tab"',
        '"alt-f4"',
        '"ctrl-shift-escape"',
        '"windows"',
        '"windows-r"',
    ]
    positions = [KEYS_JS.index(item) for item in expected]
    assert positions == sorted(positions)
    assert '"Ctrl + Delete"' not in KEYS_JS
    assert '"Ctrl + Alt + Delete"' in KEYS_JS


def test_key_dispatch_releases_reverse_order_and_refocuses_display():
    assert "client.sendKeyEvent(1, keysym)" in KEYS_JS
    assert "for (let index = pressed.length - 1; index >= 0; index -= 1)" in KEYS_JS
    assert "client.sendKeyEvent(0, pressed[index])" in KEYS_JS
    assert "finally" in KEYS_JS
    assert "Continue releasing the remaining keys" in KEYS_JS
    assert "displayElement.focus({ preventScroll: true })" in KEYS_JS
    assert "markActivity();" in KEYS_JS
    assert 'type: "kaya:remote-key-sequence"' in WORKSPACE_JS
    assert 'event.data.type === "kaya:remote-key-sequence"' in RDP_JS


def test_key_dispatch_runtime_order_release_focus_activity_and_disconnected_noop():
    script = f"""
const fs = require('fs');
const vm = require('vm');
const context = {{ window: {{ }} }};
vm.runInNewContext(fs.readFileSync({str(ROOT / 'app/static/js/remote_keys.js')!r}, 'utf8'), context);
const events = [];
let activity = 0;
let focused = 0;
const client = {{ sendKeyEvent: (pressed, keysym) => events.push([pressed, keysym]) }};
const displayElement = {{ focus: () => {{ focused += 1; }} }};
const sent = context.window.KayaRemoteKeys.sendKeySequence({{
  client, connected: true, displayReady: true, displayElement,
  markActivity: () => {{ activity += 1; }}, id: 'alt-tab'
}});
if (!sent || JSON.stringify(events) !== JSON.stringify([[1, 65513], [1, 65289], [0, 65289], [0, 65513]])) process.exit(1);
if (focused !== 1 || activity !== 2) process.exit(2);
if (context.window.KayaRemoteKeys.sendKeySequence({{
  client, connected: false, displayReady: true, displayElement,
  markActivity: () => {{ activity += 1; }}, id: 'alt-tab'
}})) process.exit(3);
"""
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr or result.stdout


def test_key_dispatch_is_noop_until_graphical_session_is_ready():
    assert "!client || !connected || !displayReady || !displayElement" in KEYS_JS
    assert "graphicalConnected: connected && displayReady" in RDP_JS
    assert "keysToggle.disabled = !tab.graphicalConnected" in WORKSPACE_JS
    assert "keyButton.disabled = !tab.graphicalConnected" in WORKSPACE_JS


def test_menu_supports_selection_escape_and_outside_close():
    assert 'keysList.hidden = true' in WORKSPACE_JS
    assert 'event.key === "Escape"' in WORKSPACE_JS
    assert 'menu.parentElement.contains(event.target)' in WORKSPACE_JS


def test_keys_menu_uses_toolbar_overlay_layer_without_changing_display_containment():
    assert ".remote-tabbar{" in REMOTE_CSS
    assert "position:relative" in REMOTE_CSS[REMOTE_CSS.index(".remote-tabbar{"):REMOTE_CSS.index(".remote-tabbar{") + 260]
    assert "z-index:2" in REMOTE_CSS[REMOTE_CSS.index(".remote-tabbar{"):REMOTE_CSS.index(".remote-tabbar{") + 260]
    assert ".remote-tabbar .remote-keys-list{left:auto;position:fixed;right:auto;top:auto}" in REMOTE_CSS
    assert ".remote-popout-tabbar{" in REMOTE_CSS
    assert "position:relative" in REMOTE_CSS[REMOTE_CSS.index(".remote-popout-tabbar{"):REMOTE_CSS.index(".remote-popout-tabbar{") + 260]
    assert ".remote-session-frame{background:#050706;border:0;border-radius:0;display:grid;height:100%;min-height:0;overflow:hidden;position:relative}" in REMOTE_CSS
    assert ".rdp-display{align-items:center;display:flex;height:100%;justify-content:center;min-height:0;overflow:hidden;position:relative;width:100%}" in REMOTE_CSS
