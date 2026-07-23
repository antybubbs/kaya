import asyncio
import base64
import hashlib
import json
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlparse
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload
from starlette import status

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import encrypt_secret
from app.db.session import SessionLocal, get_db
from app.models.models import RemoteAccess, RemoteManagerSetting, RemoteSessionRecording, User
from app.routers.auth import require_admin, require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.guacamole_bridge import restart_guacamole_bridge, start_guacamole_bridge
from app.services.site_settings import get_site_setting
from app.services.sessions import active_user_session

router = APIRouter(prefix="/remote-manager", dependencies=[Depends(require_module_access("remote_manager"))])
templates = Jinja2Templates(directory="app/templates")
PROTOCOLS = {"ssh", "rdp"}
SETTINGS = {
    "guacamole_enabled": "0",
    "split_screen_enabled": "1",
    "guacd_host": "",
    "guacd_port": "4822",
    "session_idle_timeout_minutes": "0",
    "recording_mode": "manual",
    "recording_categories": "",
    "recording_pause_idle_minutes": "5",
    "terminal_theme": "kaya",
    "terminal_font_family": "Caskaydia Cove Nerd Font Mono",
    "terminal_font_size": "14",
    "terminal_cursor_style": "bar",
    "terminal_letter_spacing": "0",
    "terminal_line_height": "1",
    "terminal_bell_style": "none",
    "terminal_backspace_mode": "normal",
    "terminal_cursor_blink": "1",
    "terminal_right_click_selects_word": "0",
    "terminal_syntax_highlighting": "1",
    "terminal_scrollback": "10000",
    "rdp_disable_audio": "0",
    "rdp_enable_audio_input": "0",
    "rdp_enable_wallpaper": "1",
    "rdp_enable_theming": "0",
    "rdp_enable_font_smoothing": "1",
    "rdp_enable_full_window_drag": "0",
    "rdp_enable_desktop_composition": "0",
    "rdp_enable_menu_animations": "0",
    "rdp_disable_bitmap_caching": "0",
    "rdp_disable_offscreen_caching": "0",
    "rdp_disable_glyph_caching": "0",
    # The GFX pipeline can stall on lossy/high-latency VPN paths. The classic
    # bitmap pipeline is the safer default and still supports bitmap caching.
    "rdp_enable_gfx": "0",
    "rdp_resize_method": "display-update",
    "rdp_enable_printing": "0",
    "rdp_enable_drive": "0",
}
TERMINAL_SETTING_KEYS = [key for key in SETTINGS if key.startswith("terminal_")]
RDP_SETTING_KEYS = [key for key in SETTINGS if key.startswith("rdp_")]
SETTING_KEYS = set(SETTINGS)
DEFAULT_RDP_TOKEN_TTL_MINUTES = 10
GUACAMOLE_LITE_URL = "ws://127.0.0.1:30008"
RECORDING_ROOT = Path("/app/data/remote-recordings")


@dataclass
class RDPSessionToken:
    remote_id: int
    user_id: int
    created_at: float


rdp_tokens: dict[str, RDPSessionToken] = {}




def remote_label(row: RemoteAccess) -> str:
    if row.display_name:
        return row.display_name
    if row.ip_address and row.ip_address.name:
        return row.ip_address.name
    return row.ip_address.address if row.ip_address else "Remote host"


def clean_protocol(value: str) -> str:
    value = value.lower().strip()
    return value if value in PROTOCOLS else "ssh"


def default_port(protocol: str) -> int:
    return 3389 if protocol == "rdp" else 22


def clean_port(value: int, protocol: str) -> int:
    if 1 <= value <= 65535:
        return value
    return default_port(protocol)


def clean_dimension(value: int, default: int, minimum: int, maximum: int) -> int:
    if minimum <= value <= maximum:
        return value
    return default


def int_payload(payload: dict, key: str, default: int) -> int:
    try:
        return int(payload.get(key) or default)
    except (TypeError, ValueError):
        return default


def clean_bool_text(value: str) -> str:
    return "1" if str(value) in {"1", "true", "on", "yes"} else "0"


def clean_choice(value: str, allowed: set[str], default: str) -> str:
    value = str(value or "").strip()
    return value if value in allowed else default


def clean_recording_categories(value: str) -> str:
    parts = [part.strip() for part in str(value or "").replace("\r", "\n").replace(",", "\n").split("\n")]
    return "\n".join(dict.fromkeys(part for part in parts if part))


def recording_category_set(value: str) -> set[str]:
    return {part.strip().casefold() for part in str(value or "").replace("\r", "\n").replace(",", "\n").split("\n") if part.strip()}


def remote_category(row: RemoteAccess) -> str:
    return (row.ip_address.category if row.ip_address and row.ip_address.category else "Uncategorised").strip() or "Uncategorised"


def recording_auto_enabled(row: RemoteAccess, settings: dict[str, str]) -> bool:
    mode = settings.get("recording_mode", SETTINGS["recording_mode"])
    if mode == "all":
        return True
    if mode == "categories":
        return remote_category(row).casefold() in recording_category_set(settings.get("recording_categories", ""))
    return False


def recording_controls_enabled(settings: dict[str, str]) -> bool:
    return settings.get("recording_mode", SETTINGS["recording_mode"]) != "off"


def recording_extension(content_type: str, protocol: str) -> str:
    if content_type.startswith("video/webm") or protocol == "rdp":
        return ".webm"
    return ".txt"


async def stream_recording_upload(file: UploadFile, path: Path) -> int:
    app_settings = get_settings()
    max_bytes = max(1, int(app_settings.max_recording_upload_mb)) * 1024 * 1024
    min_free_bytes = max(0, int(app_settings.min_recording_free_mb)) * 1024 * 1024
    probe_path = RECORDING_ROOT if RECORDING_ROOT.exists() else RECORDING_ROOT.parent
    available_bytes = max(0, shutil.disk_usage(probe_path).free - min_free_bytes)
    partial_path = path.with_suffix(f"{path.suffix}.part")
    total = 0
    try:
        with partial_path.open("xb") as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Recording is larger than the {app_settings.max_recording_upload_mb} MB limit",
                    )
                if total > available_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                        detail="Not enough free storage to save this recording",
                    )
                handle.write(chunk)
        if total == 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Recording is empty")
        partial_path.replace(path)
        return total
    except Exception:
        try:
            partial_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def recording_path(recording: RemoteSessionRecording) -> Path:
    return RECORDING_ROOT / recording.stored_filename


def recording_download_name(recording: RemoteSessionRecording, extension: str) -> str:
    started = recording.started_at or recording.created_at or datetime.utcnow()
    label = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in recording.remote_label.lower()).strip("-")
    return f"{started:%Y%m%d-%H%M}-{label or 'remote-session'}-{recording.protocol}.{extension}"


def safe_recording_file(recording: RemoteSessionRecording) -> Path:
    path = recording_path(recording)
    try:
        path.relative_to(RECORDING_ROOT)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording file not found")
    return path


def parse_client_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return datetime.utcnow()


def clean_int_text(value: str, default: int, minimum: int, maximum: int) -> str:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return str(clean_dimension(parsed, default, minimum, maximum))


def clean_float_text(value: str, default: float, minimum: float, maximum: float) -> str:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    parsed = max(minimum, min(maximum, parsed))
    return f"{parsed:g}"


def clean_global_setting(key: str, value: str) -> str:
    if key in {
        "split_screen_enabled",
        "terminal_cursor_blink",
        "terminal_right_click_selects_word",
        "terminal_syntax_highlighting",
        "rdp_disable_audio",
        "rdp_enable_audio_input",
        "rdp_enable_wallpaper",
        "rdp_enable_theming",
        "rdp_enable_font_smoothing",
        "rdp_enable_full_window_drag",
        "rdp_enable_desktop_composition",
        "rdp_enable_menu_animations",
        "rdp_disable_bitmap_caching",
        "rdp_disable_offscreen_caching",
        "rdp_disable_glyph_caching",
        "rdp_enable_gfx",
        "rdp_enable_printing",
        "rdp_enable_drive",
    }:
        return clean_bool_text(value)
    if key == "terminal_font_size":
        return clean_int_text(value, 14, 8, 28)
    if key == "session_idle_timeout_minutes":
        return clean_int_text(value, 0, 0, 1440)
    if key == "recording_mode":
        return clean_choice(value, {"off", "manual", "all", "categories"}, SETTINGS[key])
    if key == "recording_categories":
        return clean_recording_categories(value)
    if key == "recording_pause_idle_minutes":
        return clean_int_text(value, 5, 0, 1440)
    if key == "terminal_letter_spacing":
        return clean_int_text(value, 0, 0, 4)
    if key == "terminal_scrollback":
        return clean_int_text(value, 10000, 1000, 100000)
    if key == "rdp_resize_method":
        return clean_choice(value, {"display-update", "reconnect"}, SETTINGS[key])
    if key == "terminal_line_height":
        return clean_float_text(value, 1, 0.8, 2)
    if key == "terminal_theme":
        legacy_themes = {
            "termix": "kaya",
            "termixDark": "kayaDark",
            "termixLight": "kayaLight",
            "homelab": "kaya",
            "homelabDark": "kayaDark",
            "homelabLight": "kayaLight",
            "night-owl": "nightOwl",
            "one-dark": "oneDark",
            "gruvbox": "gruvboxDark",
            "solarized-dark": "solarizedDark",
        }
        value = legacy_themes.get(value, value)
        return clean_choice(value, {"kaya", "kayaDark", "kayaLight", "dracula", "monokai", "nord", "gruvboxDark", "gruvboxLight", "solarizedDark", "solarizedLight", "oneDark", "tokyoNight", "ayuDark", "materialTheme", "palenight", "oceanicNext", "nightOwl", "synthwave84", "cobalt2", "snazzy", "atomOneDark", "catppuccinMocha"}, SETTINGS[key])
    if key == "terminal_cursor_style":
        return clean_choice(value, {"bar", "block", "underline"}, SETTINGS[key])
    if key == "terminal_bell_style":
        return clean_choice(value, {"none", "sound", "visual"}, SETTINGS[key])
    if key == "terminal_backspace_mode":
        return clean_choice(value, {"normal", "bs"}, SETTINGS[key])
    return str(value or "").strip()


def decode_settings_blob(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    try:
        payload = json.loads(value)
    except (TypeError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(key): str(val) for key, val in payload.items() if val is not None}


def encode_settings_blob(values: dict[str, str]) -> str | None:
    clean_values = {key: value for key, value in values.items() if value != ""}
    if not clean_values:
        return None
    return json.dumps(clean_values, separators=(",", ":"), sort_keys=True)


def effective_remote_settings(row: RemoteAccess, global_settings: dict[str, str]) -> dict[str, dict[str, str]]:
    terminal = {key: global_settings.get(key, SETTINGS[key]) for key in TERMINAL_SETTING_KEYS}
    rdp = {key: global_settings.get(key, SETTINGS[key]) for key in RDP_SETTING_KEYS}
    terminal.update({key: clean_global_setting(key, value) for key, value in decode_settings_blob(row.terminal_settings).items() if key in terminal})
    rdp.update({key: clean_global_setting(key, value) for key, value in decode_settings_blob(row.rdp_settings).items() if key in rdp})
    return {"terminal": terminal, "rdp": rdp}


def remote_override_settings(form, keys: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in keys:
        value = str(form.get(f"override_{key}", ""))
        if value != "":
            values[key] = clean_global_setting(key, value)
    return values


def remote_host_settings_context(row: RemoteAccess, db: Session) -> dict:
    terminal_overrides = decode_settings_blob(row.terminal_settings)
    rdp_overrides = decode_settings_blob(row.rdp_settings)
    return {
        "remote": row,
        "remote_label": remote_label(row),
        "remote_defaults": settings_map(db),
        "remote_terminal_overrides": {
            key: clean_global_setting(key, value)
            for key, value in terminal_overrides.items()
            if key in TERMINAL_SETTING_KEYS
        },
        "remote_rdp_overrides": {
            key: clean_global_setting(key, value)
            for key, value in rdp_overrides.items()
            if key in RDP_SETTING_KEYS
        },
    }


def settings_map(db: Session) -> dict[str, str]:
    values = SETTINGS.copy()
    for row in db.query(RemoteManagerSetting).all():
        if row.key in SETTING_KEYS:
            values[row.key] = clean_global_setting(row.key, row.value or "")
    app_settings = get_settings()
    env_guacd_host = getattr(app_settings, "guacd_host", "")
    env_guacd_port = getattr(app_settings, "guacd_port", "")
    if env_guacd_host:
        values["guacamole_enabled"] = "1"
        values["guacd_host"] = env_guacd_host
    if env_guacd_port:
        values["guacd_port"] = str(env_guacd_port)
    for key in ("split_screen_enabled", "recording_mode", "recording_categories", "recording_pause_idle_minutes", *TERMINAL_SETTING_KEYS, *RDP_SETTING_KEYS):
        values[key] = clean_global_setting(key, values.get(key, SETTINGS[key]))
    return values


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == key).first()
    if not row:
        row = RemoteManagerSetting(key=key)
        db.add(row)
    row.value = value


def cleanup_rdp_tokens() -> None:
    now = time.time()
    expired = [token for token, session in rdp_tokens.items() if now - session.created_at > rdp_token_ttl_seconds()]
    for token in expired:
        rdp_tokens.pop(token, None)


def rdp_token_ttl_seconds() -> int:
    db = SessionLocal()
    try:
        minutes = int(get_site_setting(db, "rdp_token_ttl_minutes") or DEFAULT_RDP_TOKEN_TTL_MINUTES)
    except ValueError:
        minutes = DEFAULT_RDP_TOKEN_TTL_MINUTES
    finally:
        db.close()
    return max(5, min(minutes, 60)) * 60


def guac_element(value: object) -> str:
    text = str(value)
    return f"{len(text)}.{text}"


def guac_instruction(opcode: str, *args: object) -> str:
    return ",".join([guac_element(opcode), *(guac_element(arg) for arg in args)]) + ";"


class GuacParser:
    def __init__(self) -> None:
        self.buffer = ""
        self.elements: list[str] = []
        self.offset = 0
        self.element_end = -1

    def receive(self, data: str) -> list[tuple[str, list[str]]]:
        self.buffer += data
        instructions: list[tuple[str, list[str]]] = []
        while True:
            if self.element_end >= self.offset:
                element = self.buffer[self.offset:self.element_end]
                terminator = self.buffer[self.element_end:self.element_end + 1]
                if not terminator:
                    break
                self.elements.append(element)
                self.offset = self.element_end + 1
                self.element_end = -1
                if terminator == ";":
                    opcode = self.elements[0]
                    instructions.append((opcode, self.elements[1:]))
                    self.elements = []
                elif terminator != ",":
                    raise ValueError("Invalid Guacamole instruction terminator")
            dot = self.buffer.find(".", self.offset)
            if dot == -1:
                break
            raw_length = self.buffer[self.offset:dot]
            if not raw_length.isdigit():
                raise ValueError("Invalid Guacamole element length")
            length = int(raw_length)
            start = dot + 1
            end = start + length
            if len(self.buffer) <= end:
                break
            self.offset = start
            self.element_end = end
        if self.offset > 4096:
            consumed = self.offset
            self.buffer = self.buffer[self.offset:]
            self.offset = 0
            if self.element_end >= 0:
                self.element_end -= consumed
        return instructions


async def read_guac_instruction(reader: asyncio.StreamReader) -> tuple[str, list[str]]:
    parser = GuacParser()
    while True:
        data = await reader.read(1)
        if not data:
            raise ConnectionError("guacd closed the connection during handshake")
        instructions = parser.receive(data.decode("utf-8", errors="strict"))
        if instructions:
            return instructions[0]


def encrypt_guacamole_token(token_object: dict[str, object]) -> str:
    plaintext = json.dumps(token_object, separators=(",", ":")).encode("utf-8")
    return encrypt_secret(plaintext.decode("utf-8"))


def create_rdp_guacamole_token(row: RemoteAccess, username: str, password: str, width: int, height: int, dpi: int, timezone: str, rdp_settings: dict[str, str]) -> str:
    def enabled(key: str) -> bool:
        return rdp_settings.get(key, SETTINGS[key]) == "1"

    return encrypt_guacamole_token(
        {
            "connection": {
                "type": "rdp",
                "settings": {
                    "hostname": row.ip_address.address,
                    "port": row.port,
                    "username": username,
                    "password": password,
                    "width": width,
                    "height": height,
                    "dpi": dpi,
                    "timezone": timezone,
                    "security": "any",
                    "ignore-cert": True,
                    "disable-audio": enabled("rdp_disable_audio"),
                    "enable-audio-input": enabled("rdp_enable_audio_input"),
                    "enable-wallpaper": enabled("rdp_enable_wallpaper"),
                    "enable-theming": enabled("rdp_enable_theming"),
                    "enable-font-smoothing": enabled("rdp_enable_font_smoothing"),
                    "enable-full-window-drag": enabled("rdp_enable_full_window_drag"),
                    "enable-desktop-composition": enabled("rdp_enable_desktop_composition"),
                    "enable-menu-animations": enabled("rdp_enable_menu_animations"),
                    "disable-bitmap-caching": enabled("rdp_disable_bitmap_caching"),
                    "disable-offscreen-caching": enabled("rdp_disable_offscreen_caching"),
                    "disable-glyph-caching": enabled("rdp_disable_glyph_caching"),
                    "enable-gfx": enabled("rdp_enable_gfx"),
                    "enable-printing": enabled("rdp_enable_printing"),
                    "enable-drive": enabled("rdp_enable_drive"),
                    "resize-method": rdp_settings.get("rdp_resize_method", SETTINGS["rdp_resize_method"]),
                },
            }
        }
    )


def require_remote_session(db: Session, remote_id: int) -> RemoteAccess:
    row = db.get(RemoteAccess, remote_id)
    if not row or not row.is_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote access entry not found")
    return row


def authenticated_websocket_user(db: Session, websocket: WebSocket) -> User | None:
    if not hasattr(websocket, "session"):
        return None
    user_id = websocket.session.get("user_id")
    session_id = websocket.session.get("session_id")
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first() if user_id else None
    app_session = active_user_session(db, session_id, user.id if user else None)
    if not user or not app_session:
        return None
    app_session.last_seen_at = datetime.utcnow()
    db.commit()
    return user


def scan_ssh_host_key(row: RemoteAccess) -> str:
    if row.protocol != "ssh":
        raise ValueError("SSH host-key enrolment is only available for SSH connections.")
    scanner = shutil.which("ssh-keyscan")
    if not scanner:
        raise ValueError("SSH host-key scanning is unavailable in this Kaya image.")
    try:
        result = subprocess.run(
            [scanner, "-T", "5", "-p", str(row.port), row.ip_address.address],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Kaya could not retrieve the SSH host key. Confirm the address, port, and SSH service.") from exc
    candidates: list[tuple[int, str]] = []
    preference = {"ssh-ed25519": 0, "ecdsa-sha2-nistp256": 1, "ecdsa-sha2-nistp384": 2, "ecdsa-sha2-nistp521": 3, "ssh-rsa": 4}
    for line in result.stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3 or parts[1] not in preference:
            continue
        try:
            key_bytes = base64.b64decode(parts[2], validate=True)
        except (ValueError, TypeError):
            continue
        digest = base64.b64encode(hashlib.sha256(key_bytes).digest()).decode("ascii").rstrip("=")
        candidates.append((preference[parts[1]], f"{parts[1]} SHA256:{digest}"))
    if not candidates:
        raise ValueError("The SSH service did not provide a supported host key.")
    return min(candidates, key=lambda item: item[0])[1]


def websocket_origin_allowed(websocket: WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    if not origin:
        return False
    parsed = urlparse(origin)
    origin_host = parsed.hostname or ""
    request_host = websocket.headers.get("host", "").split(":", 1)[0]
    allowed_hosts = {request_host, "localhost", "127.0.0.1", "::1"}
    app_settings = get_settings()
    base_host = urlparse(app_settings.base_url).hostname
    if base_host:
        allowed_hosts.add(base_host)
    allowed_hosts.update(host.strip() for host in app_settings.allowed_hosts.split(",") if host.strip())
    for allowed_host in allowed_hosts:
        normalized = allowed_host.split(":", 1)[0].lower()
        if normalized.startswith("*.") and origin_host.lower().endswith(normalized[1:]):
            return True
        if origin_host.lower() == normalized:
            return True
    return False


async def tcp_check(host: str, port: int, timeout: float = 5) -> tuple[bool, str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True, "reachable"
    except Exception as exc:
        return False, str(exc)


@router.get("")
def remote_list(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    demo_mode = get_settings().demo_mode
    rows = [] if demo_mode else db.query(RemoteAccess).filter(RemoteAccess.is_enabled == True).options(selectinload(RemoteAccess.ip_address)).order_by(RemoteAccess.protocol.asc(), RemoteAccess.display_name.asc(), RemoteAccess.id.asc()).all()
    settings = settings_map(db)
    return templates.TemplateResponse(request, "remote_manager.html", {"user": user, "rows": rows, "remote_label": remote_label, "remote_manager_locked": demo_mode, "split_screen_enabled": settings.get("split_screen_enabled", "1") == "1", **csrf_context(request)})


@router.get("/settings")
def remote_settings(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    return RedirectResponse("/system/site-administration?tab=module-remote-manager", status_code=303)


@router.post("/settings")
async def save_remote_settings(request: Request, csrf_token: str = Form(...), guacamole_enabled: str = Form(""), guacd_host: str = Form("", max_length=255), guacd_port: int = Form(4822), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    form = await request.form()
    set_setting(db, "guacamole_enabled", "1" if guacamole_enabled else "0")
    set_setting(db, "split_screen_enabled", "1" if form.get("split_screen_enabled") else "0")
    set_setting(db, "guacd_host", guacd_host.strip())
    set_setting(db, "guacd_port", str(clean_port(guacd_port, "rdp")))
    set_setting(db, "session_idle_timeout_minutes", clean_global_setting("session_idle_timeout_minutes", str(form.get("session_idle_timeout_minutes", "0"))))
    set_setting(db, "recording_mode", clean_global_setting("recording_mode", str(form.get("recording_mode", "manual"))))
    set_setting(db, "recording_categories", clean_global_setting("recording_categories", str(form.get("recording_categories", ""))))
    set_setting(db, "recording_pause_idle_minutes", clean_global_setting("recording_pause_idle_minutes", str(form.get("recording_pause_idle_minutes", "5"))))
    for key in TERMINAL_SETTING_KEYS + RDP_SETTING_KEYS:
        set_setting(db, key, clean_global_setting(key, str(form.get(key, ""))))
    db.commit()
    restart_guacamole_bridge()
    write_audit(db, user, "update", "remote_manager_settings", ip_address=request.client.host if request.client else None, detail="Updated Remote Manager settings")
    return RedirectResponse("/system/site-administration?tab=module-remote-manager", status_code=303)


@router.get("/recordings")
def recording_list(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    rows = (
        db.query(RemoteSessionRecording)
        .options(selectinload(RemoteSessionRecording.user), selectinload(RemoteSessionRecording.remote))
        .order_by(RemoteSessionRecording.started_at.desc(), RemoteSessionRecording.id.desc())
        .limit(250)
        .all()
    )
    return templates.TemplateResponse(request, "remote_recordings.html", {"user": user, "recordings": rows, **csrf_context(request)})


@router.get("/recordings/{recording_id}")
def recording_detail(request: Request, recording_id: int, db: Session = Depends(get_db), user=Depends(require_admin)):
    row = db.get(RemoteSessionRecording, recording_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
    transcript = None
    path = safe_recording_file(row)
    if (row.content_type or "").startswith("text/") and path.exists():
        transcript = path.read_text(encoding="utf-8", errors="replace")
    write_audit(db, user, "playback", "remote_session_recording", entity_id=str(row.id), ip_address=request.client.host if request.client else None, detail=f"Opened recording playback for {row.remote_label}")
    return templates.TemplateResponse(request, "remote_recording_detail.html", {"user": user, "recording": row, "transcript": transcript, **csrf_context(request)})


@router.get("/recordings/{recording_id}/download.mp4")
def recording_download_mp4(request: Request, recording_id: int, db: Session = Depends(get_db), user=Depends(require_admin)):
    row = db.get(RemoteSessionRecording, recording_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
    if not (row.content_type or "").startswith("video/"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only video recordings can be downloaded as MP4")
    source = safe_recording_file(row)
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="MP4 export is unavailable because ffmpeg is not installed")
    target = source.with_suffix(".mp4")
    if not target.exists() or target.stat().st_mtime < source.stat().st_mtime:
        try:
            subprocess.run(
                [
                    ffmpeg,
                    "-y",
                    "-i",
                    str(source),
                    "-c:v",
                    "libx264",
                    "-preset",
                    "veryfast",
                    "-pix_fmt",
                    "yuv420p",
                    "-movflags",
                    "+faststart",
                    "-an",
                    str(target),
                ],
                check=True,
                capture_output=True,
                timeout=300,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            if target.exists():
                target.unlink()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"MP4 export failed: {exc}") from exc
    write_audit(db, user, "export", "remote_session_recording", entity_id=str(row.id), ip_address=request.client.host if request.client else None, detail=f"Downloaded MP4 recording for {row.remote_label}")
    return FileResponse(target, media_type="video/mp4", filename=recording_download_name(row, "mp4"))


@router.get("/recordings/{recording_id}/media")
def recording_media(request: Request, recording_id: int, db: Session = Depends(get_db), user=Depends(require_admin)):
    row = db.get(RemoteSessionRecording, recording_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
    path = safe_recording_file(row)
    write_audit(db, user, "playback", "remote_session_recording", entity_id=str(row.id), ip_address=request.client.host if request.client else None, detail=f"Streamed recording media for {row.remote_label}")
    return FileResponse(path, media_type=row.content_type or "application/octet-stream", filename=row.original_filename or path.name)


@router.post("/recordings/{recording_id}/delete")
def delete_recording(request: Request, recording_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    row = db.get(RemoteSessionRecording, recording_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
    label = row.remote_label
    path = recording_path(row)
    try:
        path.relative_to(RECORDING_ROOT)
    except ValueError:
        path = None
    if path and path.exists() and path.is_file():
        path.unlink()
        mp4_path = path.with_suffix(".mp4")
        if mp4_path.exists() and mp4_path.is_file():
            mp4_path.unlink()
    db.delete(row)
    db.commit()
    write_audit(db, user, "delete", "remote_session_recording", entity_id=str(recording_id), ip_address=request.client.host if request.client else None, detail=f"Deleted recording for {label}")
    return RedirectResponse("/remote-manager/recordings", status_code=303)


@router.get("/{remote_id}/session")
def remote_session(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = require_remote_session(db, remote_id)
    rows = db.query(RemoteAccess).filter(RemoteAccess.is_enabled == True).options(selectinload(RemoteAccess.ip_address)).order_by(RemoteAccess.protocol.asc(), RemoteAccess.display_name.asc(), RemoteAccess.id.asc()).all()
    settings = settings_map(db)
    remote_settings = effective_remote_settings(row, settings)
    title = remote_label(row)
    return templates.TemplateResponse(request, "remote_session.html", {"user": user, "remote": row, "rows": rows, "remote_label": title, "remote_label_fn": remote_label, "settings": settings, "remote_settings": remote_settings, "recording_enabled": recording_controls_enabled(settings), "recording_auto_enabled": recording_auto_enabled(row, settings), "remote_category": remote_category(row), **csrf_context(request)})


@router.get("/{remote_id}/settings")
def remote_host_settings(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    row = db.get(RemoteAccess, remote_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote access entry not found")
    return templates.TemplateResponse(
        request,
        "remote_host_settings.html",
        {"user": user, **remote_host_settings_context(row, db), **csrf_context(request)},
    )


@router.post("/{remote_id}/settings")
async def save_remote_host_settings(request: Request, remote_id: int, csrf_token: str = Form(...), remote_display_name: str = Form("", max_length=255), remote_protocol: str = Form("ssh"), remote_port: int = Form(22), remote_username: str = Form("", max_length=120), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(RemoteAccess, remote_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote access entry not found")
    form = await request.form()
    row.display_name = remote_display_name.strip() or None
    row.is_enabled = bool(form.get("remote_enabled"))
    previous_protocol = row.protocol
    previous_port = row.port
    row.protocol = clean_protocol(remote_protocol)
    row.port = clean_port(remote_port, row.protocol)
    if row.protocol != previous_protocol or row.port != previous_port:
        row.host_key_fingerprint = None
    row.username = remote_username.strip() or None
    row.terminal_settings = encode_settings_blob(remote_override_settings(form, TERMINAL_SETTING_KEYS))
    row.rdp_settings = encode_settings_blob(remote_override_settings(form, RDP_SETTING_KEYS))
    db.commit()
    write_audit(db, user, "update", "remote_access", entity_id=str(row.id), ip_address=request.client.host if request.client else None, detail=f"Updated Remote Manager settings for {remote_label(row)}")
    return RedirectResponse("/remote-manager", status_code=303)


@router.post("/{remote_id}/ssh/host-key/scan")
async def scan_remote_host_key(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    row = db.get(RemoteAccess, remote_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote access entry not found")
    try:
        candidate = scan_ssh_host_key(row)
        error = None
    except ValueError as exc:
        candidate = None
        error = str(exc)
    write_audit(
        db,
        user,
        "scan_host_key",
        "remote_access",
        entity_id=str(row.id),
        ip_address=request.client.host if request.client else None,
        detail=f"Scanned SSH host key for {remote_label(row)}; key was not trusted automatically",
        severity="warning" if error else "info",
    )
    return templates.TemplateResponse(
        request,
        "remote_host_settings.html",
        {
            "user": user,
            **remote_host_settings_context(row, db),
            "host_key_candidate": candidate,
            "host_key_error": error,
            **csrf_context(request),
        },
        status_code=400 if error else 200,
    )


@router.post("/{remote_id}/ssh/host-key/trust")
async def trust_remote_host_key(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    row = db.get(RemoteAccess, remote_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote access entry not found")
    candidate = str(form.get("host_key_candidate") or "").strip()
    if str(form.get("confirm_host_key") or "") != "1":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Confirm that you verified the SSH fingerprint.")
    try:
        current = scan_ssh_host_key(row)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if not candidate or not secrets.compare_digest(candidate, current):
        write_audit(
            db,
            user,
            "host_key_changed_during_enrolment",
            "remote_access",
            entity_id=str(row.id),
            ip_address=request.client.host if request.client else None,
            detail=f"SSH host key changed while enrolling {remote_label(row)}",
            severity="critical",
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The SSH host key changed after it was scanned. Nothing was trusted.")
    previous = row.host_key_fingerprint
    row.host_key_fingerprint = current
    db.commit()
    write_audit(
        db,
        user,
        "trust_host_key",
        "remote_access",
        entity_id=str(row.id),
        ip_address=request.client.host if request.client else None,
        detail=f"{'Replaced' if previous else 'Enrolled'} verified SSH host key for {remote_label(row)}",
        severity="warning" if previous and previous != current else "info",
    )
    return RedirectResponse(f"/remote-manager/{row.id}/settings?host_key_trusted=1", status_code=303)


@router.post("/{remote_id}/delete")
def delete_remote_host(request: Request, remote_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(RemoteAccess, remote_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote access entry not found")
    label = remote_label(row)
    db.query(RemoteSessionRecording).filter(RemoteSessionRecording.remote_access_id == row.id).update(
        {RemoteSessionRecording.remote_access_id: None}, synchronize_session=False
    )
    db.delete(row)
    db.commit()
    write_audit(db, user, "delete", "remote_access", entity_id=str(remote_id), ip_address=request.client.host if request.client else None, detail=label)
    return RedirectResponse("/remote-manager", status_code=303)


@router.get("/{remote_id}/panel")
def remote_session_panel(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = require_remote_session(db, remote_id)
    settings = settings_map(db)
    remote_settings = effective_remote_settings(row, settings)
    title = remote_label(row)
    return templates.TemplateResponse(request, "remote_session_panel.html", {"user": user, "remote": row, "remote_label": title, "settings": settings, "remote_settings": remote_settings, "recording_enabled": recording_controls_enabled(settings), "recording_auto_enabled": recording_auto_enabled(row, settings), "remote_category": remote_category(row), **csrf_context(request)})


@router.post("/{remote_id}/recordings/upload")
async def upload_recording(
    request: Request,
    remote_id: int,
    csrf_token: str = Form(...),
    protocol: str = Form(...),
    trigger: str = Form("manual"),
    started_at: str = Form(""),
    ended_at: str = Form(""),
    duration_seconds: float = Form(0),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    validate_csrf_token(request, csrf_token)
    row = require_remote_session(db, remote_id)
    settings = settings_map(db)
    if not recording_controls_enabled(settings):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Session recording is disabled")
    clean_trigger = clean_choice(trigger, {"manual", "auto"}, "manual")
    if clean_trigger == "auto" and not recording_auto_enabled(row, settings):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Auto recording is not enabled for this host")
    clean_protocol = protocol.lower().strip()
    if clean_protocol != row.protocol:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Recording protocol does not match remote host")
    content_type = (file.content_type or "application/octet-stream").split(";", 1)[0].strip().lower()
    if content_type not in {"video/webm", "text/plain", "application/json", "application/octet-stream"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported recording type")
    if row.protocol == "rdp" and content_type not in {"video/webm", "application/octet-stream"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="RDP recordings must be WebM video")
    if row.protocol == "ssh" and content_type not in {"text/plain", "application/json", "application/octet-stream"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SSH recordings must be text")

    now = datetime.utcnow()
    folder = Path(f"{now:%Y/%m}")
    target_dir = RECORDING_ROOT / folder
    target_dir.mkdir(parents=True, exist_ok=True)
    extension = recording_extension(content_type, row.protocol)
    stored_name = str(folder / f"{uuid4().hex}{extension}").replace("\\", "/")
    path = RECORDING_ROOT / stored_name
    size_bytes = await stream_recording_upload(file, path)

    recording = RemoteSessionRecording(
        remote_access_id=row.id,
        user_id=user.id,
        remote_label=remote_label(row),
        remote_address=row.ip_address.address if row.ip_address else None,
        protocol=row.protocol,
        category=remote_category(row),
        trigger=clean_trigger,
        status="complete",
        stored_filename=stored_name,
        original_filename=(file.filename or "")[:255] or None,
        content_type="video/webm" if row.protocol == "rdp" else "text/plain",
        size_bytes=size_bytes,
        duration_seconds=max(0, float(duration_seconds or 0)),
        started_at=parse_client_datetime(started_at),
        ended_at=parse_client_datetime(ended_at),
    )
    db.add(recording)
    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise HTTPException(status_code=status.HTTP_507_INSUFFICIENT_STORAGE, detail="Recording could not be saved") from exc
    write_audit(db, user, "start", "remote_session_recording", entity_id=str(recording.id), ip_address=request.client.host if request.client else None, detail=f"{row.protocol.upper()} recording started for {remote_label(row)}")
    write_audit(db, user, "stop", "remote_session_recording", entity_id=str(recording.id), ip_address=request.client.host if request.client else None, detail=f"{row.protocol.upper()} recording stopped for {remote_label(row)}")
    write_audit(db, user, "record", "remote_session_recording", entity_id=str(recording.id), ip_address=request.client.host if request.client else None, detail=f"Saved {row.protocol.upper()} recording for {remote_label(row)}")
    return JSONResponse({"ok": True, "recording_id": recording.id})


@router.post("/{remote_id}/rdp/check")
async def rdp_check(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    payload = await request.json()
    validate_csrf_token(request, str(payload.get("csrf_token", "")))
    row = require_remote_session(db, remote_id)
    if row.protocol != "rdp":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Remote entry is not configured for RDP")
    settings = settings_map(db)
    logs = []
    logs.append(f"Starting RDP pre-flight for {row.ip_address.address}:{row.port}.")
    if not payload.get("username"):
        logs.append("No username was provided.")
    if not payload.get("password"):
        logs.append("No password was provided. It is not stored by Kaya.")
    if settings.get("guacamole_enabled") != "1":
        logs.append("Guacamole is disabled in Remote Manager Settings.")
        return JSONResponse({"ok": False, "logs": logs})
    guacd_host = settings.get("guacd_host", "").strip()
    if not guacd_host:
        logs.append("No guacd host is configured.")
        return JSONResponse({"ok": False, "logs": logs})
    try:
        raw_guacd_port = int(settings.get("guacd_port") or 4822)
    except ValueError:
        raw_guacd_port = 4822
    guacd_port = clean_port(raw_guacd_port, "rdp")
    logs.append(f"Checking guacd at {guacd_host}:{guacd_port}.")
    guacd_ok, guacd_result = await tcp_check(guacd_host, guacd_port)
    logs.append(f"guacd check: {guacd_result}.")
    logs.append(f"Checking target RDP port at {row.ip_address.address}:{row.port}.")
    target_ok, target_result = await tcp_check(row.ip_address.address, row.port)
    logs.append(f"target RDP check: {target_result}.")
    if guacd_ok and target_ok:
        logs.append("Pre-flight checks passed. Browser RDP display transport is the next piece to wire in.")
    else:
        logs.append("Pre-flight checks failed. Fix the failed network check before the browser RDP display can connect.")
    return JSONResponse({"ok": guacd_ok and target_ok, "logs": logs})


@router.post("/{remote_id}/rdp/start")
async def rdp_start(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    payload = await request.json()
    validate_csrf_token(request, str(payload.get("csrf_token", "")))
    row = require_remote_session(db, remote_id)
    if row.protocol != "rdp":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Remote entry is not configured for RDP")
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    if not username or not password:
        return JSONResponse({"ok": False, "logs": ["Username and password are required for RDP."]}, status_code=400)
    settings = settings_map(db)
    remote_settings = effective_remote_settings(row, settings)
    logs = [f"Preparing RDP session for {row.ip_address.address}:{row.port}."]
    if settings.get("guacamole_enabled") != "1" or not settings.get("guacd_host", "").strip():
        logs.append("Guacamole is not enabled or guacd is not configured.")
        return JSONResponse({"ok": False, "logs": logs}, status_code=400)
    start_guacamole_bridge()
    cleanup_rdp_tokens()
    width = clean_dimension(int_payload(payload, "width", 1280), 1280, 640, 7680)
    height = clean_dimension(int_payload(payload, "height", 720), 720, 480, 4320)
    dpi = clean_dimension(int_payload(payload, "dpi", 96), 96, 72, 240)
    timezone = str(payload.get("timezone", ""))[:80]
    token = create_rdp_guacamole_token(row, username, password, width, height, dpi, timezone, remote_settings["rdp"])
    now = time.time()
    rdp_tokens[token] = RDPSessionToken(
        remote_id=row.id,
        user_id=user.id,
        created_at=now,
    )
    write_audit(
        db,
        user,
        "start",
        "remote_rdp_session",
        entity_id=str(row.id),
        ip_address=request.client.host if request.client else None,
        detail=f"Prepared RDP session for {remote_label(row)} ({row.ip_address.address}:{row.port}) as {username}",
    )
    logs.append("Session token created. Opening browser display tunnel.")
    return JSONResponse({"ok": True, "token": token, "logs": logs})


@router.websocket("/{remote_id}/ssh/ws")
async def ssh_websocket(websocket: WebSocket, remote_id: int):
    if get_settings().demo_mode:
        await websocket.close(code=1008, reason="Remote connections are disabled in the public demo")
        return
    if not websocket_origin_allowed(websocket):
        await websocket.close(code=1008)
        return
    db = SessionLocal()
    try:
        user = authenticated_websocket_user(db, websocket)
        if not user:
            await websocket.close(code=1008)
            return
        remote = db.get(RemoteAccess, remote_id)
        if not remote or not remote.is_enabled or remote.protocol != "ssh" or not remote.username:
            await websocket.close(code=1008)
            return
        if not remote.host_key_fingerprint or " " not in remote.host_key_fingerprint:
            await websocket.close(code=1008, reason="SSH host key is not enrolled")
            return
        host = remote.ip_address.address
        port = remote.port
        username = remote.username
        host_key_algorithm, host_key_fingerprint = remote.host_key_fingerprint.split(" ", 1)
    finally:
        db.close()
    await websocket.accept()
    upstream = None
    try:
        payload = await websocket.receive_json()
        if payload.get("type") == "connectToHost":
            connect_data = payload.get("data") or {}
        else:
            connect_data = payload
        password = connect_data.get("password", "")
        if not password:
            await websocket.send_json({"type": "error", "message": "Password is required."})
            await websocket.close(code=1008)
            return
        try:
            cols = clean_dimension(int_payload(connect_data, "cols", 120), 120, 40, 500)
            rows = clean_dimension(int_payload(connect_data, "rows", 34), 34, 10, 200)
            import websockets

            upstream = await websockets.connect("ws://127.0.0.1:30009", open_timeout=10)
            await upstream.send(json.dumps({
                "type": "connectToHost",
                "data": {
                    "host": host,
                    "port": port,
                    "username": username,
                    "password": password,
                    "cols": cols,
                    "rows": rows,
                    "hostKeyAlgorithm": host_key_algorithm,
                    "hostKeyFingerprint": host_key_fingerprint,
                },
            }))
        except Exception as exc:
            await websocket.send_json({"type": "error", "message": f"SSH connection failed: {exc}"})
            await websocket.close(code=1011)
            return

        async def read_loop():
            try:
                while True:
                    message = await upstream.recv()
                    await websocket.send_text(message)
            except Exception:
                pass

        async def write_loop():
            try:
                while True:
                    payload = await websocket.receive_json()
                    await upstream.send(json.dumps(payload))
            except WebSocketDisconnect:
                pass

        tasks = {asyncio.create_task(read_loop()), asyncio.create_task(write_loop())}
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            if not task.done():
                task.cancel()
    finally:
        if upstream:
            try:
                await upstream.close()
            except Exception:
                pass


@router.websocket("/{remote_id}/rdp/ws")
async def rdp_websocket(websocket: WebSocket, remote_id: int):
    if get_settings().demo_mode:
        await websocket.close(code=1008, reason="Remote connections are disabled in the public demo")
        return
    if not websocket_origin_allowed(websocket):
        await websocket.close(code=1008)
        return
    token = websocket.query_params.get("token", "")
    db = SessionLocal()
    remote_label_text = "Remote host"
    remote_address = ""
    remote_port = 3389
    try:
        user = authenticated_websocket_user(db, websocket)
        if not user:
            await websocket.close(code=1008)
            return
        cleanup_rdp_tokens()
        session = rdp_tokens.get(token)
        if not session or session.user_id != user.id or session.remote_id != remote_id:
            await websocket.close(code=1008)
            return
        remote = db.get(RemoteAccess, remote_id)
        if not remote or not remote.is_enabled or remote.protocol != "rdp":
            await websocket.close(code=1008)
            return
        remote_label_text = remote_label(remote)
        remote_address = remote.ip_address.address
        remote_port = remote.port
    finally:
        db.close()

    await websocket.accept(subprotocol="guacamole")
    upstream = None
    connected = False
    try:
        import websockets

        upstream_params = {"token": token}
        width = websocket.query_params.get("width")
        height = websocket.query_params.get("height")
        if width:
            upstream_params["width"] = width
        if height:
            upstream_params["height"] = height
        upstream_url = f"{GUACAMOLE_LITE_URL}?{urlencode(upstream_params)}"
        try:
            upstream = await websockets.connect(upstream_url, subprotocols=["guacamole"], open_timeout=10)
            if websocket.query_params.get("handoff") == "1":
                rdp_tokens.pop(token, None)
        except Exception as exc:
            audit_db = SessionLocal()
            try:
                audit_user = audit_db.get(User, user.id)
                write_audit(
                    audit_db,
                    audit_user,
                    "error",
                    "remote_rdp_session",
                    entity_id=str(remote_id),
                    ip_address=websocket.client.host if websocket.client else None,
                    detail=f"RDP connection failed for {remote_label_text} ({remote_address}:{remote_port}): {exc}",
                )
            finally:
                audit_db.close()
            await websocket.send_text(guac_instruction("error", f"RDP connection failed: {exc}", 512))
            await websocket.close(code=1011)
            return
        audit_db = SessionLocal()
        try:
            audit_user = audit_db.get(User, user.id)
            write_audit(
                audit_db,
                audit_user,
                "connect",
                "remote_rdp_session",
                entity_id=str(remote_id),
                ip_address=websocket.client.host if websocket.client else None,
                detail=f"RDP session connected for {remote_label_text} ({remote_address}:{remote_port})",
            )
        finally:
            audit_db.close()
        connected = True

        async def upstream_to_browser():
            try:
                async for message in upstream:
                    if isinstance(message, bytes):
                        await websocket.send_bytes(message)
                    else:
                        await websocket.send_text(message)
            except Exception:
                pass

        async def browser_to_upstream():
            try:
                while True:
                    message = await websocket.receive()
                    if message.get("text") is not None:
                        await upstream.send(message["text"])
                    elif message.get("bytes") is not None:
                        await upstream.send(message["bytes"])
                    else:
                        break
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        tasks = {asyncio.create_task(upstream_to_browser()), asyncio.create_task(browser_to_upstream())}
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            if not task.done():
                task.cancel()
    finally:
        if upstream:
            try:
                await upstream.close()
            except Exception:
                pass
        if connected:
            audit_db = SessionLocal()
            try:
                audit_user = audit_db.get(User, user.id)
                write_audit(
                    audit_db,
                    audit_user,
                    "disconnect",
                    "remote_rdp_session",
                    entity_id=str(remote_id),
                    ip_address=websocket.client.host if websocket.client else None,
                    detail=f"RDP session disconnected for {remote_label_text} ({remote_address}:{remote_port})",
                )
            finally:
                audit_db.close()
