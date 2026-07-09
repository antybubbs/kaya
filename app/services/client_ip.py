from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import re
from typing import Iterable

from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send


FORWARDED_HEADER_NAMES = {
    b"forwarded",
    b"x-forwarded-for",
    b"x-forwarded-host",
    b"x-forwarded-port",
    b"x-forwarded-proto",
    b"x-real-ip",
    b"cf-connecting-ip",
}


@dataclass(frozen=True)
class ClientIPDetails:
    client_ip: str | None
    immediate_ip: str | None
    forwarded_for: str | None
    trusted_proxy: bool
    trusted_proxy_config: str
    source: str


def split_trusted_proxies(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def validate_trusted_proxies(value: str) -> list[str]:
    errors = []
    for entry in split_trusted_proxies(value):
        if entry == "*":
            continue
        try:
            ip_network(entry, strict=False)
        except ValueError:
            errors.append(entry)
    return errors


def ip_is_trusted(value: str | None, trusted_proxies: str) -> bool:
    if not value:
        return False
    try:
        address = ip_address(value)
    except ValueError:
        return False
    for entry in split_trusted_proxies(trusted_proxies):
        if entry == "*":
            return True
        try:
            if address in ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def _clean_ip(value: str) -> str | None:
    candidate = value.strip().strip('"')
    if candidate.lower() == "unknown" or candidate.startswith("_"):
        return None
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    elif candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            candidate = host
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None


def _forwarded_chain(headers: dict[bytes, bytes]) -> tuple[list[str], str | None, str]:
    x_forwarded_for = headers.get(b"x-forwarded-for", b"").decode("latin-1").strip()
    if x_forwarded_for:
        return (
            [clean for item in x_forwarded_for.split(",") if (clean := _clean_ip(item))],
            x_forwarded_for,
            "X-Forwarded-For",
        )

    forwarded = headers.get(b"forwarded", b"").decode("latin-1").strip()
    if forwarded:
        values = []
        for item in forwarded.split(","):
            match = re.search(r"(?:^|;)\s*for=([^;]+)", item, flags=re.IGNORECASE)
            if match and (clean := _clean_ip(match.group(1))):
                values.append(clean)
        return values, forwarded, "Forwarded"

    for name, label in ((b"x-real-ip", "X-Real-IP"), (b"cf-connecting-ip", "CF-Connecting-IP")):
        raw = headers.get(name, b"").decode("latin-1").strip()
        if raw:
            clean = _clean_ip(raw)
            return ([clean] if clean else []), raw, label
    return [], None, "socket"


def _original_client(chain: Iterable[str], trusted_proxies: str) -> str | None:
    values = list(chain)
    for candidate in reversed(values):
        if not ip_is_trusted(candidate, trusted_proxies):
            return candidate
    return values[0] if values else None


def inspect_client_ip(scope: Scope, trusted_proxies: str) -> ClientIPDetails:
    immediate_ip = str(scope.get("client")[0]) if scope.get("client") else None
    headers = {name.lower(): value for name, value in scope.get("headers", [])}
    chain, forwarded_value, source = _forwarded_chain(headers)
    trusted_proxy = ip_is_trusted(immediate_ip, trusted_proxies)
    client_ip = _original_client(chain, trusted_proxies) if trusted_proxy and chain else immediate_ip
    return ClientIPDetails(
        client_ip=client_ip,
        immediate_ip=immediate_ip,
        forwarded_for=forwarded_value,
        trusted_proxy=trusted_proxy,
        trusted_proxy_config=trusted_proxies,
        source=source if trusted_proxy and chain else "socket",
    )


def client_ip_details(connection: HTTPConnection) -> ClientIPDetails:
    details = getattr(connection.state, "client_ip_details", None)
    if details:
        return details
    from app.core.config import get_settings

    return inspect_client_ip(connection.scope, get_settings().forwarded_allow_ips)


def client_ip(connection: HTTPConnection) -> str | None:
    return client_ip_details(connection).client_ip


class TrustedProxyMiddleware:
    def __init__(self, app: ASGIApp, trusted_proxies: str) -> None:
        self.app = app
        self.trusted_proxies = trusted_proxies

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        scope = dict(scope)
        details = inspect_client_ip(scope, self.trusted_proxies)
        scope.setdefault("state", {})["client_ip_details"] = details

        if details.trusted_proxy:
            if details.client_ip and scope.get("client"):
                scope["client"] = (details.client_ip, scope["client"][1])
            headers = {name.lower(): value for name, value in scope.get("headers", [])}
            forwarded_proto = headers.get(b"x-forwarded-proto", b"").decode("latin-1").split(",", 1)[0].strip()
            if forwarded_proto in {"http", "https", "ws", "wss"}:
                scope["scheme"] = forwarded_proto
        else:
            # Downstream code cannot accidentally trust spoofed forwarding metadata.
            scope["headers"] = [
                (name, value)
                for name, value in scope.get("headers", [])
                if name.lower() not in FORWARDED_HEADER_NAMES
            ]

        await self.app(scope, receive, send)
