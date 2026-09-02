"""Perform authenticated writes continuously for the Phase 8 backup overlap test."""

from __future__ import annotations

import json
import os
import time

from phase7d_http_smoke import Client, EMAIL, PASSWORD


def main() -> None:
    client = Client()
    _, _, login = client.expect("GET", "/login", {200})
    client.expect(
        "POST",
        "/login",
        {303},
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": client.csrf(login)},
    )
    started = time.time()
    writes = 0
    while time.time() - started < float(os.environ.get("PHASE8_WRITE_SECONDS", "15")):
        _, _, dashboard = client.expect("GET", "/dashboard", {200})
        client.expect(
            "PUT",
            "/api/dashboard/preferences",
            {200, 303},
            data={"layout": json.dumps({"phase8_live_write": writes})},
            headers={"X-CSRF-Token": client.csrf(dashboard), "Content-Type": "application/json"},
        )
        writes += 1
    print(f"live-write-started={started:.3f} live-write-finished={time.time():.3f} writes={writes}")


if __name__ == "__main__":
    main()
