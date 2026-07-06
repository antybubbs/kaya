from __future__ import annotations

import json
import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.core.security import decrypt_secret
from app.models.models import DNSProviderConfig


class DNSProviderError(RuntimeError):
    pass


@dataclass
class DNSProviderResult:
    ok: bool
    message: str
    data: dict[str, Any] | list[dict[str, Any]] | None = None


class DNSProvider(ABC):
    def __init__(self, config: DNSProviderConfig):
        self.config = config

    @abstractmethod
    def test_connection(self) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def get_status(self) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def get_statistics(self) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def get_clients(self) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def get_query_log(self, *, limit: int = 100) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def get_local_dns_records(self) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def get_dhcp_leases(self) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def get_blocklists(self) -> DNSProviderResult:
        raise NotImplementedError


class PiHoleProvider(DNSProvider):
    def _base_url(self) -> str:
        return self.config.base_url.rstrip("/")

    def _secret(self) -> str:
        return decrypt_secret(self.config.encrypted_secret or "").strip()

    def _ssl_context(self):
        if self.config.ssl_verify:
            return None
        return ssl._create_unverified_context()

    def _request_json(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        body = None
        request_headers = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        url = f"{self._base_url()}{path}"
        request = Request(url, data=body, method=method, headers=request_headers)
        try:
            with urlopen(
                request,
                timeout=max(1, min(int(self.config.timeout_seconds or 10), 60)),
                context=self._ssl_context(),
            ) as response:
                raw = response.read().decode("utf-8")
        except HTTPError as exc:
            raise DNSProviderError(f"Pi-hole returned HTTP {exc.code}.") from exc
        except URLError as exc:
            raise DNSProviderError(f"Could not reach Pi-hole: {exc.reason}.") from exc
        except TimeoutError as exc:
            raise DNSProviderError("Connection to Pi-hole timed out.") from exc
        except OSError as exc:
            raise DNSProviderError(f"Connection to Pi-hole failed: {exc}.") from exc
        try:
            parsed = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise DNSProviderError("Pi-hole returned an invalid JSON response.") from exc
        return parsed if isinstance(parsed, dict) else {"data": parsed}

    def _auth_headers(self) -> dict[str, str]:
        secret = self._secret()
        if not secret:
            return {}
        if self.config.auth_method == "api_token":
            return {"X-FTL-SID": secret}
        try:
            data = self._request_json("/api/auth", method="POST", payload={"password": secret})
        except DNSProviderError:
            return {}
        session = data.get("session") if isinstance(data.get("session"), dict) else data
        sid = session.get("sid") if isinstance(session, dict) else None
        return {"X-FTL-SID": sid} if sid else {}

    def _legacy_api(self, params: dict[str, Any]) -> dict[str, Any]:
        secret = self._secret()
        if secret:
            params = {**params, "auth": secret}
        return self._request_json(f"/admin/api.php?{urlencode(params)}")

    def _safe(self, label: str, func) -> DNSProviderResult:
        try:
            return func()
        except DNSProviderError as exc:
            return DNSProviderResult(False, str(exc), None)
        except Exception:
            return DNSProviderResult(False, f"{label} is unavailable from this Pi-hole API.", None)

    def test_connection(self) -> DNSProviderResult:
        result = self.get_statistics()
        if result.ok:
            return DNSProviderResult(True, "Pi-hole connection test passed.", result.data)
        return result

    def get_status(self) -> DNSProviderResult:
        def run():
            headers = self._auth_headers()
            try:
                data = self._request_json("/api/info/system", headers=headers)
            except DNSProviderError:
                data = self._legacy_api({"status": ""})
            return DNSProviderResult(True, "Pi-hole status loaded.", data)

        return self._safe("Status", run)

    def get_statistics(self) -> DNSProviderResult:
        def run():
            headers = self._auth_headers()
            try:
                data = self._request_json("/api/stats/summary", headers=headers)
            except DNSProviderError:
                data = self._legacy_api({"summaryRaw": ""})
            return DNSProviderResult(True, "Pi-hole statistics loaded.", data)

        return self._safe("Statistics", run)

    def get_clients(self) -> DNSProviderResult:
        def run():
            headers = self._auth_headers()
            try:
                data = self._request_json("/api/network/devices", headers=headers)
            except DNSProviderError:
                data = self._legacy_api({"getQuerySources": ""})
            return DNSProviderResult(True, "Pi-hole clients loaded.", data)

        return self._safe("Clients", run)

    def get_query_log(self, *, limit: int = 100) -> DNSProviderResult:
        def run():
            headers = self._auth_headers()
            try:
                data = self._request_json(f"/api/queries?length={max(1, min(limit, 500))}", headers=headers)
            except DNSProviderError:
                data = self._legacy_api({"getAllQueries": "", "limit": max(1, min(limit, 500))})
            return DNSProviderResult(True, "Pi-hole query log loaded.", data)

        return self._safe("Query log", run)

    def get_local_dns_records(self) -> DNSProviderResult:
        def run():
            data = self._request_json("/api/config/dns/hosts", headers=self._auth_headers())
            return DNSProviderResult(True, "Pi-hole local DNS records loaded.", data)

        return self._safe("Local DNS", run)

    def get_dhcp_leases(self) -> DNSProviderResult:
        def run():
            data = self._request_json("/api/dhcp/leases", headers=self._auth_headers())
            return DNSProviderResult(True, "Pi-hole DHCP leases loaded.", data)

        return self._safe("DHCP", run)

    def get_blocklists(self) -> DNSProviderResult:
        def run():
            data = self._request_json("/api/lists", headers=self._auth_headers())
            return DNSProviderResult(True, "Pi-hole blocklists loaded.", data)

        return self._safe("Blocklists", run)


def provider_for(config: DNSProviderConfig) -> DNSProvider:
    if config.provider_type == "pihole":
        return PiHoleProvider(config)
    raise DNSProviderError(f"Unsupported DNS provider type: {config.provider_type}")
