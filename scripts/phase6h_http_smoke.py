"""Disposable authenticated HTTP acceptance client for Phase 6H."""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


BASE = os.environ.get("PHASE6H_HTTP_BASE", "http://kaya-phase6-upgrade:8080").rstrip("/")


class Client:
    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method: str, path: str, data: dict | None = None, headers: dict | None = None):
        if data is None:
            encoded = None
        elif headers and headers.get("Content-Type") == "application/json":
            encoded = json.dumps(data).encode()
        else:
            encoded = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(BASE + path, data=encoded, headers=headers or {}, method=method)
        try:
            with self.opener.open(request, timeout=15) as response:
                return response.status, response.geturl(), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.geturl(), exc.read().decode("utf-8", "replace")

    @staticmethod
    def token(body: str) -> str:
        match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        if not match:
            raise RuntimeError("CSRF token missing")
        return match.group(1)

    def login(self, password: str = "synthetic-admin-password") -> tuple[int, str]:
        status, url, body = self.request("GET", "/login")
        token = self.token(body)
        status, url, _ = self.request(
            "POST", "/login", {"email": "synthetic@example.invalid", "password": password, "csrf_token": token}
        )
        return status, url


def main() -> None:
    client = Client()
    status, url, body = client.request("GET", "/login")
    print("login-page", status, bool(re.search(r"name=\"csrf_token\"", body)))
    print("valid-login", *client.login())
    routes = [
        "/healthz",
        "/dashboard",
        "/networking/dns-manager/clients",
        "/networking/dns-manager/clients/1",
        "/infrastructure/vm-docker-manager",
        "/infrastructure/vm-docker-manager/hosts/1",
        "/high-availability",
        "/high-availability/clusters/00000000-0000-0000-0000-000000000001",
        "/infrastructure/asset-manager",
        "/infrastructure/asset-manager/1",
        "/notifications",
        "/system/audit-logs",
        "/system/about",
    ]
    for path in routes:
        status, url, body = client.request("GET", path)
        print("route", path, status, len(body), url)

    status, _, body = client.request("GET", "/dashboard")
    csrf = client.token(body)
    status, url, _ = client.request(
        "PUT", "/api/dashboard/preferences", {"layout": "{}"}, {"X-CSRF-Token": csrf, "Content-Type": "application/json"}
    )
    print("dashboard-write", status, url)
    fields = {"name": "Phase 6H HTTP asset", "category": "Network", "asset_status": "In use", "csrf_token": csrf}
    status, url, body = client.request("POST", "/infrastructure/asset-manager/new", fields)
    print("asset-create", status, url)
    asset_id = re.search(r"/infrastructure/asset-manager/(\d+)", url).group(1)
    fields.update({"name": "Phase 6H HTTP asset updated", "asset_tag": "", "csrf_token": csrf})
    status, url, _ = client.request("POST", f"/infrastructure/asset-manager/{asset_id}/edit", fields)
    print("asset-update", status, url, "asset_id", asset_id)
    status, url, _ = client.request("POST", "/networking/dns-manager/clients/1/update", {"friendly_name": "Phase 6H client", "notes": "synthetic HTTP write", "csrf_token": csrf})
    print("dns-write", status, url)
    status, url, _ = client.request("POST", "/api/notifications/2/read", headers={"X-CSRF-Token": csrf})
    print("notification-write", status, url)
    status, _, _ = client.request("PUT", "/api/dashboard/preferences", {"layout": {}}, {"Content-Type": "application/json"})
    print("missing-csrf", status)
    invalid = Client()
    status, url = invalid.login("wrong-synthetic-password")
    print("invalid-login", status, url)
    status, url, _ = client.request("POST", "/logout", {"csrf_token": csrf})
    print("logout", status, url)
    status, url, _ = client.request("GET", "/dashboard")
    print("post-logout-dashboard", status, url)


if __name__ == "__main__":
    main()
