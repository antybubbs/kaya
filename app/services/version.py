import json
import re
import threading
import time
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen
from app.core.config import get_settings

# This setting is linked to the environment variable displayed.
CACHE_SECONDS = get_settings().version_check_interval_seconds


@dataclass
class VersionCache:
    checked_at: float = 0
    latest_version: str | None = None
    release_url: str | None = None


_cache = VersionCache()
_cache_lock = threading.Lock()
_refreshing = False
SHA_PATTERN = re.compile(r"^[0-9a-f]{7,40}$")
DEV_PATTERN = re.compile(r"^dev\d+\.\d+\.\d+$", re.IGNORECASE)


def normalize_version(version: str) -> tuple[int, ...]:
    clean = version.strip().lower().removeprefix("v")
    parts: list[int] = []
    for part in clean.split("."):
        digits = ""
        for char in part:
            if not char.isdigit():
                break
            digits += char
        if digits:
            parts.append(int(digits))
    return tuple(parts)


def display_version(version: str) -> str:
    if DEV_PATTERN.match(version.strip()):
        return version.strip()
    if SHA_PATTERN.match(version.strip().lower()):
        return "dev build"
    return version


def _fetch_latest_release() -> tuple[str | None, str | None]:
    settings = get_settings()
    request = Request(
        f"https://api.github.com/repos/{settings.github_repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "HomeLab"},
    )
    try:
        with urlopen(request, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, TimeoutError, URLError, ValueError):
        return None, None
    return data.get("tag_name"), data.get("html_url")


def _refresh_latest_release() -> None:
    global _refreshing
    latest, release_url = _fetch_latest_release()
    with _cache_lock:
        _cache.checked_at = time.monotonic()
        _cache.latest_version = latest
        _cache.release_url = release_url
        _refreshing = False


def latest_release() -> tuple[str | None, str | None]:
    global _refreshing
    now = time.monotonic()
    with _cache_lock:
        latest = _cache.latest_version
        release_url = _cache.release_url
        checked_at = _cache.checked_at
        if now - checked_at < CACHE_SECONDS:
            return latest, release_url
        if not _refreshing:
            _refreshing = True
            threading.Thread(target=_refresh_latest_release, daemon=True).start()
        return _cache.latest_version, _cache.release_url


def version_status() -> dict[str, str | bool | None]:
    settings = get_settings()
    installed = settings.app_version
    is_dev = bool(DEV_PATTERN.match(installed.strip()) or SHA_PATTERN.match(installed.strip().lower()))
    latest, release_url = latest_release()
    update_available = False
    if latest and is_dev:
        update_available = True
    elif latest and normalize_version(latest) and normalize_version(installed):
        update_available = normalize_version(latest) > normalize_version(installed)
    release_url = release_url or f"https://github.com/{settings.github_repo}/releases/latest"
    return {
        "installed": installed,
        "installed_display": display_version(installed),
        "is_dev": is_dev,
        "latest": latest,
        "release_url": release_url,
        "update_available": update_available,
    }
