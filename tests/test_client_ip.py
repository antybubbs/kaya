from starlette.requests import Request

from app.services.audit import begin_request_context, end_request_context, write_audit
from app.services.client_ip import client_ip, inspect_client_ip
from app.services.sessions import request_ip as session_request_ip


def make_request(immediate_ip: str, forwarded_for: str | None, trusted: str) -> Request:
    headers = []
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode("ascii")))
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": (immediate_ip, 12345),
        "server": ("kaya", 8080),
        "state": {},
    }
    scope["state"]["client_ip_details"] = inspect_client_ip(scope, trusted)
    return Request(scope)


def test_direct_request_with_spoofed_x_forwarded_for_is_ignored():
    request = make_request("192.168.1.50", "203.0.113.8", "127.0.0.1")

    assert client_ip(request) == "192.168.1.50"
    assert request.state.client_ip_details.trusted_proxy is False


def test_trusted_proxy_request_uses_original_client_ip():
    request = make_request("172.20.0.4", "198.51.100.25, 172.20.0.3", "172.20.0.0/16")

    assert client_ip(request) == "198.51.100.25"
    assert request.state.client_ip_details.trusted_proxy is True
    assert request.state.client_ip_details.source == "X-Forwarded-For"


def test_untrusted_proxy_request_uses_immediate_proxy_ip():
    request = make_request("172.21.0.4", "198.51.100.25", "172.20.0.0/16")

    assert client_ip(request) == "172.21.0.4"
    assert request.state.client_ip_details.trusted_proxy is False


class RecordingSession:
    def __init__(self):
        self.row = None

    def add(self, row):
        self.row = row

    def commit(self):
        pass

    def rollback(self):
        pass


def test_sessions_and_audit_logs_use_the_same_client_ip():
    request = make_request("172.20.0.4", "198.51.100.25", "172.20.0.0/16")
    expected = session_request_ip(request)
    db = RecordingSession()
    token, _ = begin_request_context(
        request_id="test",
        method="POST",
        path="/login",
        ip_address=client_ip(request),
    )
    try:
        row = write_audit(db, None, "login", "user")
    finally:
        end_request_context(token)

    assert expected == "198.51.100.25"
    assert row.ip_address == expected
