import asyncio

from fastapi import APIRouter, Depends, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import SessionLocal, get_db
from app.models.models import RemoteAccess, RemoteManagerSetting
from app.routers.auth import require_admin, require_user
from app.services.audit import write_audit

router = APIRouter(prefix="/remote-manager")
templates = Jinja2Templates(directory="app/templates")
PROTOCOLS = {"ssh", "rdp"}
SETTINGS = {
    "guacamole_enabled": "0",
    "guacd_host": "",
    "guacd_port": "4822",
}


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


def fingerprint_for(host_key) -> str:
    return host_key.get_fingerprint("sha256")


def settings_map(db: Session) -> dict[str, str]:
    values = SETTINGS.copy()
    for row in db.query(RemoteManagerSetting).all():
        if row.key in values:
            values[row.key] = row.value or ""
    return values


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == key).first()
    if not row:
        row = RemoteManagerSetting(key=key)
        db.add(row)
    row.value = value


def require_remote_session(db: Session, remote_id: int) -> RemoteAccess:
    row = db.get(RemoteAccess, remote_id)
    if not row or not row.is_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote access entry not found")
    return row


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
    write_audit(db, user, "update", "remote_manager_settings", ip_address=request.client.host if request.client else None, detail="Updated Remote Manager settings")
    return templates.TemplateResponse(request, "remote_manager_settings.html", {"user": user, "settings": settings_map(db), "message": "Settings saved.", **csrf_context(request)})


@router.get("/{remote_id}/session")
def remote_session(request: Request, remote_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = require_remote_session(db, remote_id)
    settings = settings_map(db)
    title = remote_label(row)
    return templates.TemplateResponse(request, "remote_session.html", {"user": user, "remote": row, "remote_label": title, "settings": settings, **csrf_context(request)})


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
