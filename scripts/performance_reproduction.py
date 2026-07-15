"""Authenticated 50-cycle navigation stability check for a running Kaya instance."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import statistics
import time
import urllib.parse
import urllib.request


ROUTES = (
    "/dashboard",
    "/infrastructure/asset-manager",
    "/networking/vlan-ip-manager",
    "/documentation/runbook-manager",
    "/remote-manager",
    "/system/audit-logs",
    "/system/site-administration",
)


def process_resources(pid: int | None) -> dict[str, int | None]:
    if not pid:
        return {"rss_bytes": None, "threads": None, "open_file_descriptors": None}
    result = {"rss_bytes": None, "threads": None, "open_file_descriptors": None}
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    result["rss_bytes"] = int(line.split()[1]) * 1024
                elif line.startswith("Threads:"):
                    result["threads"] = int(line.split()[1])
        result["open_file_descriptors"] = len(os.listdir(f"/proc/{pid}/fd"))
    except (OSError, ValueError, IndexError):
        pass
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--email", required=True)
    parser.add_argument("--cycles", type=int, default=50)
    parser.add_argument("--process-pid", type=int)
    args = parser.parse_args()
    password = os.environ.get("KAYA_BENCHMARK_PASSWORD")
    if not password:
        parser.error("Set KAYA_BENCHMARK_PASSWORD instead of putting a password on the command line.")

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base_url = args.base_url.rstrip("/")

    def request(path: str) -> tuple[float, bytes]:
        started = time.perf_counter()
        with opener.open(base_url + path, timeout=30) as response:
            body = response.read()
            if response.status != 200:
                raise RuntimeError(f"{path} returned HTTP {response.status}")
        return (time.perf_counter() - started) * 1000, body

    _, login_body = request("/login")
    match = re.search(rb'name="csrf_token" value="([^"]+)"', login_body)
    if not match:
        raise RuntimeError("The login page did not contain a CSRF token.")
    form = urllib.parse.urlencode(
        {"email": args.email, "password": password, "csrf_token": match.group(1).decode()}
    ).encode()
    with opener.open(urllib.request.Request(base_url + "/login", data=form, method="POST"), timeout=30) as response:
        response.read()

    before = process_resources(args.process_pid)
    timings = {route: [] for route in ROUTES}
    for _ in range(max(50, args.cycles)):
        for route in ROUTES:
            duration_ms, _ = request(route)
            timings[route].append(duration_ms)
    after = process_resources(args.process_pid)

    routes = {}
    stable = True
    for route, samples in timings.items():
        first = statistics.median(samples[:5])
        last = statistics.median(samples[-5:])
        stable = stable and last <= max(first * 1.5, first + 50)
        routes[route] = {
            "first_5_median_ms": round(first, 2),
            "last_5_median_ms": round(last, 2),
            "median_ms": round(statistics.median(samples), 2),
            "max_ms": round(max(samples), 2),
        }
    result = {"cycles": max(50, args.cycles), "stable": stable, "resources_before": before, "resources_after": after, "routes": routes}
    print(json.dumps(result, indent=2))
    return 0 if stable else 1


if __name__ == "__main__":
    raise SystemExit(main())
