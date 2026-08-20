"""Authenticated synthetic HTTP smoke test for Phase 7 runtime CI."""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


BASE = os.environ.get("PHASE7D_HTTP_BASE", "http://127.0.0.1:18087").rstrip("/")
EMAIL = "synthetic@example.invalid"
PASSWORD = "synthetic-admin-password"
ROUTE_SUCCESS_STATUSES = frozenset({200, 303, 307})


def route_status_is_acceptable(status: int) -> bool:
    """Accept successful pages and the app's intentional route redirects."""
    return status in ROUTE_SUCCESS_STATUSES


def dns_client_detail_path(client_id: str) -> str:
    """Build a detail path only from a discovered positive database ID."""
    if not client_id.isdecimal() or int(client_id) < 1:
        raise ValueError(f"invalid discovered DNS client ID: {client_id!r}")
    return f"/networking/dns-manager/clients/{client_id}"


class Client:
    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar()
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, *_args, **_kwargs):
                return None

        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect()
        )

    def request(self, method: str, path: str, data: dict | None = None, headers: dict | None = None):
        headers = headers or {}
        if data is None:
            encoded = None
        elif headers.get("Content-Type") == "application/json":
            encoded = json.dumps(data).encode()
        else:
            encoded = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(BASE + path, data=encoded, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=15) as response:
                return response.status, response.geturl(), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.geturl(), exc.read().decode("utf-8", "replace")

    @staticmethod
    def csrf(body: str) -> str:
        match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        if not match:
            raise AssertionError("CSRF token missing")
        return match.group(1)

    def expect(self, method: str, path: str, expected: set[int], **kwargs):
        status, url, body = self.request(method, path, **kwargs)
        if status not in expected:
            raise AssertionError(f"{method} {path}: expected {expected}, got {status} ({url})")
        return status, url, body

    def setup_if_needed(self) -> None:
        setup_token = os.environ.get("KAYA_SETUP_TOKEN", "")
        status, _, body = self.request("GET", "/setup")
        if status not in {200, 303}:
            raise AssertionError(f"GET /setup returned {status}")
        if not setup_token:
            return
        csrf = self.csrf(body)
        self.expect(
            "POST",
            "/setup",
            {303},
            data={
                "first_name": "Synthetic",
                "last_name": "Administrator",
                "email": EMAIL,
                "password": PASSWORD,
                "confirm_password": PASSWORD,
                "setup_token": setup_token,
                "csrf_token": csrf,
            },
        )

    def login(self) -> None:
        _, _, body = self.expect("GET", "/login", {200, 303})
        csrf = self.csrf(body) if 'name="csrf_token"' in body else None
        if csrf is None:
            _, _, body = self.expect("GET", "/login", {200})
            csrf = self.csrf(body)
        self.expect("POST", "/login", {303}, data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf})


def main() -> None:
    client = Client()
    client.expect("GET", "/healthz", {200})
    client.setup_if_needed()
    client.login()
    routes = [
        "/dashboard",
        "/networking/dns-manager/clients",
        "/infrastructure/vm-docker-manager",
        "/high-availability",
        "/infrastructure/asset-manager",
        "/notifications",
        "/system/audit-logs",
        "/system/about",
    ]
    dns_client_id = os.environ.get("KAYA_DNS_CLIENT_ID", "").strip()
    if dns_client_id:
        routes.insert(2, dns_client_detail_path(dns_client_id))
    for route in routes:
        status, url, _body = client.request("GET", route)
        if not route_status_is_acceptable(status):
            raise AssertionError(
                f"GET {route}: expected {set(ROUTE_SUCCESS_STATUSES)}, got {status} ({url})"
            )
    _, _, dashboard = client.expect("GET", "/dashboard", {200})
    csrf = client.csrf(dashboard)
    client.expect(
        "PUT",
        "/api/dashboard/preferences",
        {200, 303},
        data={"layout": "{}"},
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
    )
    client.expect(
        "POST",
        "/infrastructure/asset-manager/new",
        {303},
        data={
            "name": "Phase 7D synthetic asset",
            "category": "Network",
            "asset_status": "In use",
            "csrf_token": csrf,
        },
    )
    status, _, _ = client.request(
        "PUT",
        "/api/dashboard/preferences",
        data={"layout": {}},
        headers={"Content-Type": "application/json"},
    )
    if status not in {400, 403}:
        raise AssertionError(f"missing CSRF was accepted: {status}")
    invalid = Client()
    _, _, invalid_login = invalid.expect("GET", "/login", {200})
    invalid_csrf = invalid.csrf(invalid_login)
    invalid_status, _, _ = invalid.request(
        "POST",
        "/login",
        data={"email": EMAIL, "password": "wrong-synthetic-password", "csrf_token": invalid_csrf},
    )
    if invalid_status not in {400, 401}:
        raise AssertionError(f"invalid login returned unexpected status: {invalid_status}")
    print("phase7d authenticated HTTP smoke passed")


if __name__ == "__main__":
    main()
