import asyncio
import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import SessionLocal, get_db
from app.models.models import RemoteAccess, RemoteManagerSetting, User
from app.routers.auth import require_admin, require_user
from app.services.audit import write_audit
from app.services.guacamole_bridge import restart_guacamole_bridge

router = APIRouter(prefix="/remote-manager")
templates = Jinja2Templates(directory="app/templates")
PROTOCOLS = {"ssh", "rdp"}
SETTINGS = {
    "guacamole_enabled": "0",
    "guacd_host": "",
    "guacd_port": "4822",
}
RDP_TOKEN_TTL_SECONDS = 60
GUACAMOLE_LITE_URL = "ws://127.0.0.1:30008"


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


def fingerprint_for(host_key) -> str:
    return host_key.get_fingerprint("sha256")


def settings_map(db: Session) -> dict[str, str]:
    values = SETTINGS.copy()
    for row in db.query(RemoteManagerSetting).all():
        if row.key in values:
            values[row.key] = row.value or ""
    app_settings = get_settings()
    env_guacd_host = getattr(app_settings, "guacd_host", "")
    env_guacd_port = getattr(app_settings, "guacd_port", "")
    if env_guacd_host:
        values["guacamole_enabled"] = "1"
        values["guacd_host"] = env_guacd_host
    if env_guacd_port:
        values["guacd_port"] = str(env_guacd_port)
    return values


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == key).first()
    if not row:
        row = RemoteManagerSetting(key=key)
        db.add(row)
    row.value = value


def cleanup_rdp_tokens() -> None:
    now = time.time()
    expired = [token for token, session in rdp_tokens.items() if now - session.created_at > RDP_TOKEN_TTL_SECONDS]
    for token in expired:
        rdp_tokens.pop(token, None)


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


def guacamole_key() -> bytes:
    app_settings = get_settings()
    return hashlib.sha256(f"{app_settings.secret_key}_guacamole".encode("utf-8")).digest()


def encrypt_guacamole_token(token_object: dict[str, object]) -> str:
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    plaintext = json.dumps(token_object, separators=(",", ":")).encode("utf-8")
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(guacamole_key()), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    payload = {
        "iv": base64.b64encode(iv).decode("ascii"),
        "value": base64.b64encode(encrypted).decode("ascii"),
    }
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")


def create_rdp_guacamole_token(row: RemoteAccess, username: str, password: str, width: int, height: int, dpi: int, timezone: str) -> str:
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
                    "enable-wallpaper": False,
                    "enable-font-smoothing": True,
                    "enable-desktop-composition": False,
                    "disable-audio": False,
                    "enable-drive": False,
                    "resize-method": "display-update",
                },
            }
        }
    )


def require_remote_session(db: Session, remote_id: int) -> RemoteAccess:
    row = db.get(RemoteAccess, remote_id)
    if not row or not row.is_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote access entry not found")
    return row


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
    rows = db.query(RemoteAccess).filter(RemoteAccess.is_enabled == True).order_by(RemoteAccess.protocol.asc(), RemoteAccess.display_name.asc(), RemoteAccess.id.asc()).all()
    return templates.TemplateResponse(request, "remote_manager.html", {"user": user, "rows": rows, "remote_label": remote_label, **csrf_context(request)})


@router.get("/settings")
def remote_settings(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    return templates.TemplateResponse(request, "remote_manager_settings.html", {"user": user, "settings": settings_map(db), "message": None, **csrf_context(request)})


@router.post("/settings")
def save_remote_settings(request: Request, csrf_token: str = Form(...), guacamole_enabled: str = Form(""), guacd_host: str = Form("", max_length=255), guacd_port: int = Form(4822), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    set_setting(db, "guacamole_enabled", "1" if guacamole_enabled else "0")
    set_setting(db, "guacd_host", guacd_host.strip())
    set_setting(db, "guacd_port", str(clean_port(guacd_port, "rdp")))
    db.commit()
    restart_guacamole_bridge()
    write_audit(db, user, "update", "remote_manager_settings", ip_address=request.client.host if request.client else None, detail="Updated Remote Manager settings")
    return templates.TemplateResponse(request, "remote_manager_settings.html", {"user": user, "settings": settings_map(db), "message": "Settings saved.", **csrf_context(request)})


@router.get("/{remote_id}/session")
def remote_session(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = require_remote_session(db, remote_id)
    rows = db.query(RemoteAccess).filter(RemoteAccess.is_enabled == True).order_by(RemoteAccess.protocol.asc(), RemoteAccess.display_name.asc(), RemoteAccess.id.asc()).all()
    settings = settings_map(db)
    title = remote_label(row)
    return templates.TemplateResponse(request, "remote_session.html", {"user": user, "remote": row, "rows": rows, "remote_label": title, "remote_label_fn": remote_label, "settings": settings, **csrf_context(request)})


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
        logs.append("No password was provided. It is not stored by HomeLab.")
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
    logs = [f"Preparing RDP session for {row.ip_address.address}:{row.port}."]
    if settings.get("guacamole_enabled") != "1" or not settings.get("guacd_host", "").strip():
        logs.append("Guacamole is not enabled or guacd is not configured.")
        return JSONResponse({"ok": False, "logs": logs}, status_code=400)
    cleanup_rdp_tokens()
    width = clean_dimension(int_payload(payload, "width", 1280), 1280, 640, 7680)
    height = clean_dimension(int_payload(payload, "height", 720), 720, 480, 4320)
    dpi = clean_dimension(int_payload(payload, "dpi", 96), 96, 72, 240)
    timezone = str(payload.get("timezone", ""))[:80]
    token = create_rdp_guacamole_token(row, username, password, width, height, dpi, timezone)
    rdp_tokens[token] = RDPSessionToken(
        remote_id=row.id,
        user_id=user.id,
        created_at=time.time(),
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
    user_id = websocket.session.get("user_id") if hasattr(websocket, "session") else None
    if not user_id:
        await websocket.close(code=1008)
        return
    db = SessionLocal()
    try:
        remote = db.get(RemoteAccess, remote_id)
        if not remote or not remote.is_enabled or remote.protocol != "ssh" or not remote.username:
            await websocket.close(code=1008)
            return
        host = remote.ip_address.address
        port = remote.port
        username = remote.username
        expected_fingerprint = remote.host_key_fingerprint
    finally:
        db.close()
    await websocket.accept()
    client = None
    try:
        payload = await websocket.receive_json()
        password = payload.get("password", "")
        if not password:
            await websocket.send_text("\r\nPassword is required.\r\n")
            await websocket.close(code=1008)
            return
        try:
            import asyncssh

            client = await asyncio.wait_for(
                asyncssh.connect(host, port=port, username=username, password=password, known_hosts=None),
                timeout=10,
            )
            current_fingerprint = fingerprint_for(client.get_server_host_key())
            if expected_fingerprint and expected_fingerprint != current_fingerprint:
                client.close()
                await client.wait_closed()
                await websocket.send_text("\r\nSSH host key fingerprint has changed. Connection refused.\r\n")
                await websocket.close(code=1011)
                return
            if not expected_fingerprint:
                update_db = SessionLocal()
                try:
                    update_row = update_db.get(RemoteAccess, remote_id)
                    if update_row and not update_row.host_key_fingerprint:
                        update_row.host_key_fingerprint = current_fingerprint
                        update_db.commit()
                finally:
                    update_db.close()
            process = await client.create_process(term_type="xterm-256color", term_size=(160, 48))

            async def apply_terminal_theme():
                await asyncio.sleep(1.2)
                try:
                    process.stdin.write(
                        "export TERM=xterm-256color COLORTERM=truecolor; "
                        "export PS1='\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '; "
                        "export PROMPT='%F{green}%n@%m%f:%F{blue}%~%f%# '; "
                        "alias ls='ls --color=auto' 2>/dev/null; "
                        "alias grep='grep --color=auto' 2>/dev/null; "
                        "clear\n"
                    )
                except Exception:
                    pass

            asyncio.create_task(apply_terminal_theme())
        except Exception as exc:
            await websocket.send_text(f"\r\nSSH connection failed: {exc}\r\n")
            await websocket.close(code=1011)
            return

        async def read_loop():
            try:
                while True:
                    data = await process.stdout.read(4096)
                    if not data:
                        break
                    await websocket.send_text(data)
            except Exception:
                pass

        async def write_loop():
            try:
                while True:
                    text = await websocket.receive_text()
                    if text.startswith("\x00resize:"):
                        try:
                            _, cols, rows = text.split(":", 2)
                            process.change_terminal_size(int(cols), int(rows))
                        except Exception:
                            pass
                        continue
                    process.stdin.write(text)
            except WebSocketDisconnect:
                pass

        tasks = {asyncio.create_task(read_loop()), asyncio.create_task(write_loop())}
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            if not task.done():
                task.cancel()
    finally:
        if client:
            try:
                client.close()
                await client.wait_closed()
            except Exception:
                pass


@router.websocket("/{remote_id}/rdp/ws")
async def rdp_websocket(websocket: WebSocket, remote_id: int):
    user_id = websocket.session.get("user_id") if hasattr(websocket, "session") else None
    if not user_id:
        await websocket.close(code=1008)
        return
    token = websocket.query_params.get("token", "")
    cleanup_rdp_tokens()
    session = rdp_tokens.pop(token, None)
    if not session or session.user_id != user_id or session.remote_id != remote_id:
        await websocket.close(code=1008)
        return
    db = SessionLocal()
    remote_label_text = "Remote host"
    remote_address = ""
    remote_port = 3389
    try:
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

        upstream_url = f"{GUACAMOLE_LITE_URL}?{urlencode({'token': token})}"
        try:
            upstream = await websockets.connect(upstream_url, subprotocols=["guacamole"], open_timeout=10)
        except Exception as exc:
            audit_db = SessionLocal()
            try:
                audit_user = audit_db.get(User, user_id)
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
            audit_user = audit_db.get(User, user_id)
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
                audit_user = audit_db.get(User, user_id)
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
