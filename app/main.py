from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.security import hash_password
from app.db.session import Base, engine, SessionLocal
from app.models.models import User
from app.routers import auth, dashboard, licences, admin

settings = get_settings()
app = FastAPI(title=settings.app_name, docs_url=None if settings.app_env == "production" else "/docs")

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    https_only=settings.session_cookie_secure,
    same_site="lax",
    max_age=60 * 60 * 8,
)

@app.exception_handler(PermissionError)
async def permission_handler(request: Request, exc: PermissionError):
    return RedirectResponse("/login", status_code=303)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return response

Path("/app/uploads").mkdir(parents=True, exist_ok=True)
Path("/app/data").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


def bootstrap():
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == settings.admin_email).first()
        if not admin:
            db.add(User(email=settings.admin_email, password_hash=hash_password(settings.admin_password), role="admin"))
            db.commit()
    finally:
        db.close()


@app.on_event("startup")
async def on_startup():
    bootstrap()


app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(licences.router)
app.include_router(admin.router)

@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}

@app.get("/")
def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")
