import re
from pathlib import Path
from types import SimpleNamespace

import fastapi
import pydantic
import pytest
import starlette
from fastapi import Depends, FastAPI, File, Form, Request, UploadFile, WebSocket
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware
from starlette.websockets import WebSocketDisconnect

from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import hash_password
from app.db.session import Base, get_db
from app.models.models import User
from app.routers import auth as auth_router
from app.routers.auth import require_admin, require_editor, require_module_access, require_user
from app.routers.remote_manager import websocket_origin_allowed
from app.services.client_ip import TrustedProxyMiddleware, client_ip
from app.services.modules import grant_all_registered_modules
from app.services.site_settings import host_is_allowed


MALFORMED_HOSTS = (
    "testserver/login?next=",
    "testserver/static/?asset=",
    "user@testserver",
)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        admin = User(
            email="admin@example.test",
            password_hash=hash_password("fake-admin-password"),
            role="admin",
            is_active=True,
        )
        viewer = User(
            email="viewer@example.test",
            password_hash=hash_password("fake-viewer-password"),
            role="viewer",
            is_active=True,
        )
        session.add_all([admin, viewer])
        session.flush()
        grant_all_registered_modules(session, admin)
        session.commit()
        yield session
    finally:
        session.close()


@pytest.fixture(params=("direct", "trusted_proxy"))
def deployment(request, db, tmp_path, monkeypatch):
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "probe.txt").write_text("public-static-probe", encoding="utf-8")

    # Keep authentication policy deterministic and use only clearly fake data.
    monkeypatch.setattr(auth_router, "settings", SimpleNamespace(demo_mode=False))

    app = FastAPI()
    app.state.demo_mode = False
    app.state.demo_reset_schedule = "03:00 UTC"
    app.include_router(auth_router.router)

    @app.get("/manifest.webmanifest", name="manifest", include_in_schema=False)
    def manifest():
        return JSONResponse({"name": "Kaya security regression"})

    @app.exception_handler(PermissionError)
    async def permission_denied(request: Request, _exc: PermissionError):
        if request.session.get("user_id"):
            return PlainTextResponse("Forbidden", status_code=403)
        return RedirectResponse("/login", status_code=303)

    # This deliberately matches Kaya's path-sensitive host gate. The BadHost
    # payload used to make request.url.path look public/static even though the
    # ASGI router was dispatching a protected path.
    @app.middleware("http")
    async def kaya_host_gate(request: Request, call_next):
        if not request.url.path.startswith("/static/") and not host_is_allowed(
            request.headers.get("host", ""), ["testserver"]
        ):
            return PlainTextResponse("Invalid host header", status_code=400)
        return await call_next(request)

    @app.get("/protected")
    def protected(request: Request, user=Depends(require_user)):
        return {
            "user_id": user.id,
            "path": request.url.path,
            "scheme": request.url.scheme,
            "client_ip": client_ip(request),
        }

    @app.get("/admin-only")
    def admin_only(user=Depends(require_admin)):
        return {"role": user.role}

    @app.get("/vault")
    def vault(user=Depends(require_module_access("secret_vault"))):
        return {"user_id": user.id}

    @app.get("/csrf")
    def csrf(request: Request, _user=Depends(require_user)):
        return csrf_context(request, include_version=False)

    @app.post("/mutate")
    def mutate(request: Request, csrf_token: str = Form(...), _user=Depends(require_editor)):
        validate_csrf_token(request, csrf_token)
        return {"changed": True}

    @app.get("/redirect")
    def redirect(_user=Depends(require_user)):
        return RedirectResponse("/protected", status_code=303)

    @app.post("/upload")
    async def upload(
        request: Request,
        csrf_token: str = Form(...),
        document: UploadFile = File(...),
        _user=Depends(require_editor),
    ):
        validate_csrf_token(request, csrf_token)
        content = await document.read()
        return {"filename": document.filename, "size": len(content)}

    @app.websocket("/ws")
    async def websocket_route(
        websocket: WebSocket,
        _user=Depends(require_module_access("remote_manager")),
    ):
        if not websocket_origin_allowed(websocket):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        await websocket.send_json({"authenticated": True})
        await websocket.close()

    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    app.dependency_overrides[get_db] = lambda: db
    app.add_middleware(SessionMiddleware, secret_key="fake-session-secret-at-least-32-bytes")
    app.add_middleware(TrustedProxyMiddleware, trusted_proxies="127.0.0.1")

    if request.param == "direct":
        client = TestClient(app, base_url="http://testserver", client=("192.0.2.40", 41000))
        forwarded_headers = {
            "X-Forwarded-For": "198.51.100.90",
            "X-Forwarded-Proto": "https",
        }
        expected_ip = "192.0.2.40"
        expected_scheme = "http"
    else:
        client = TestClient(app, base_url="http://testserver", client=("127.0.0.1", 41000))
        forwarded_headers = {
            "X-Forwarded-For": "198.51.100.90, 127.0.0.1",
            "X-Forwarded-Proto": "https",
        }
        expected_ip = "198.51.100.90"
        expected_scheme = "https"

    with client:
        yield SimpleNamespace(
            client=client,
            forwarded_headers=forwarded_headers,
            expected_ip=expected_ip,
            expected_scheme=expected_scheme,
            mode=request.param,
        )


def login(client: TestClient, email: str, password: str, headers=None):
    login_page = client.get("/login", headers=headers)
    assert login_page.status_code == 200
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
    assert csrf
    return client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": csrf.group(1)},
        headers=headers,
        follow_redirects=False,
    )


def test_dependency_pins_select_the_patched_compatible_stack():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").splitlines()
    assert "fastapi==0.136.3" in requirements
    assert "starlette==1.3.1" in requirements
    assert "httpx==0.28.1" in requirements
    assert "httpx2==2.9.1" in requirements
    assert "uvicorn[standard]==0.34.0" in requirements
    assert "pydantic-settings==2.14.2" in requirements
    assert fastapi.__version__ == "0.136.3"
    assert starlette.__version__ == "1.3.1"
    assert pydantic.VERSION.startswith("2.")


def test_malformed_host_cannot_poison_starlette_request_path():
    app = FastAPI()

    @app.get("/protected")
    def protected(request: Request):
        return {"path": request.url.path, "hostname": request.url.hostname}

    with TestClient(app, base_url="http://testserver") as client:
        for malformed_host in MALFORMED_HOSTS:
            response = client.get("/protected", headers={"Host": malformed_host})
            assert response.status_code == 200
            assert response.json()["path"] == "/protected"
            assert response.json()["hostname"] == "testserver"


def test_login_session_authentication_logout_and_proxy_identity(deployment):
    client = deployment.client
    headers = deployment.forwarded_headers
    unauthenticated = client.get("/protected", headers=headers, follow_redirects=False)
    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/login"

    signed_in = login(client, "admin@example.test", "fake-admin-password", headers)
    assert signed_in.status_code == 303
    assert signed_in.headers["location"] == "/dashboard"

    protected = client.get("/protected", headers=headers)
    assert protected.status_code == 200
    assert protected.json()["path"] == "/protected"
    assert protected.json()["client_ip"] == deployment.expected_ip
    assert protected.json()["scheme"] == deployment.expected_scheme

    csrf = client.get("/csrf", headers=headers).json()["csrf_token"]
    assert client.post("/logout", data={"csrf_token": "wrong"}, headers=headers).status_code == 400
    logged_out = client.post(
        "/logout", data={"csrf_token": csrf}, headers=headers, follow_redirects=False
    )
    assert logged_out.status_code == 303
    assert logged_out.headers["location"].startswith("/login")
    assert client.get("/protected", headers=headers, follow_redirects=False).status_code == 303


def test_role_module_csrf_redirect_static_and_upload_controls(deployment):
    client = deployment.client
    headers = deployment.forwarded_headers
    assert login(client, "viewer@example.test", "fake-viewer-password", headers).status_code == 303
    assert client.get("/protected", headers=headers).status_code == 200
    assert client.get("/admin-only", headers=headers).status_code == 403
    assert client.get("/vault", headers=headers).status_code == 403

    viewer_csrf = client.get("/csrf", headers=headers).json()["csrf_token"]
    assert client.post("/mutate", data={"csrf_token": viewer_csrf}, headers=headers).status_code == 403
    client.cookies.clear()

    assert login(client, "admin@example.test", "fake-admin-password", headers).status_code == 303
    csrf = client.get("/csrf", headers=headers).json()["csrf_token"]
    assert client.get("/admin-only", headers=headers).status_code == 200
    assert client.get("/vault", headers=headers).status_code == 200
    assert client.post("/mutate", data={"csrf_token": "wrong"}, headers=headers).status_code == 400
    assert client.post("/mutate", data={"csrf_token": csrf}, headers=headers).json() == {"changed": True}

    redirected = client.get("/redirect", headers=headers, follow_redirects=False)
    assert redirected.status_code == 303
    assert redirected.headers["location"] == "/protected"
    assert client.get(redirected.headers["location"], headers=headers).status_code == 200
    assert client.get("/static/probe.txt", headers=headers).text == "public-static-probe"
    assert client.get("/static/../requirements.txt", headers=headers).status_code == 404

    denied_upload = client.post(
        "/upload",
        data={"csrf_token": "wrong"},
        files={"document": ("fake.txt", b"synthetic upload")},
        headers=headers,
    )
    assert denied_upload.status_code == 400
    uploaded = client.post(
        "/upload",
        data={"csrf_token": csrf},
        files={"document": ("fake.txt", b"synthetic upload")},
        headers=headers,
    )
    assert uploaded.json() == {"filename": "fake.txt", "size": 16}


def test_malformed_host_cannot_bypass_route_security(deployment):
    client = deployment.client
    proxy_headers = deployment.forwarded_headers
    for malformed_host in MALFORMED_HOSTS:
        headers = {**proxy_headers, "Host": malformed_host}
        for path in ("/protected", "/admin-only", "/vault", "/mutate", "/upload"):
            response = client.get(path, headers=headers, follow_redirects=False)
            assert response.status_code == 400
            assert response.text == "Invalid host header"

    assert login(client, "viewer@example.test", "fake-viewer-password", proxy_headers).status_code == 303
    for malformed_host in MALFORMED_HOSTS:
        headers = {**proxy_headers, "Host": malformed_host}
        assert client.get("/admin-only", headers=headers).status_code == 400
        assert client.get("/vault", headers=headers).status_code == 400


def test_websocket_authentication_module_access_and_host_handling(deployment):
    client = deployment.client
    headers = {**deployment.forwarded_headers, "Origin": "http://testserver"}
    with pytest.raises(WebSocketDisconnect) as unauthenticated:
        with client.websocket_connect("/ws", headers=headers):
            pass
    assert unauthenticated.value.code == 1008

    assert login(client, "viewer@example.test", "fake-viewer-password", deployment.forwarded_headers).status_code == 303
    with pytest.raises(WebSocketDisconnect) as module_denied:
        with client.websocket_connect("/ws", headers=headers):
            pass
    assert module_denied.value.code == 1008
    client.cookies.clear()

    assert login(client, "admin@example.test", "fake-admin-password", deployment.forwarded_headers).status_code == 303
    with client.websocket_connect("/ws", headers=headers) as websocket:
        assert websocket.receive_json() == {"authenticated": True}

    malformed_headers = {
        **deployment.forwarded_headers,
        "Host": "testserver/login?next=",
        "Origin": "http://testserver",
    }
    with pytest.raises(WebSocketDisconnect) as malformed:
        with client.websocket_connect("/ws", headers=malformed_headers):
            pass
    assert malformed.value.code == 1008
