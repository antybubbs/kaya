import secrets
import time
from fastapi import HTTPException, Request, status
from app.services.version import version_status

CSRF_SESSION_KEY = "csrf_token"
ASSET_VERSION = str(int(time.time()))


def csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def csrf_context(request: Request, include_version: bool = True) -> dict[str, object]:
    context: dict[str, object] = {"csrf_token": csrf_token(request), "asset_version": ASSET_VERSION}
    if include_version:
        context["version_status"] = version_status()
    return context


def validate_csrf_token(request: Request, submitted_token: str | None) -> None:
    expected_token = request.session.get(CSRF_SESSION_KEY)
    if not expected_token or not submitted_token or not secrets.compare_digest(expected_token, submitted_token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid form token")
