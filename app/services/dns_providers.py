from __future__ import annotations

import json
import hashlib
import ssl
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from app.core.security import decrypt_secret
from app.models.models import DNSProviderConfig


class DNSProviderError(RuntimeError):
    pass


class PiHoleHTTPError(DNSProviderError):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(message)


@dataclass
class DNSProviderResult:
    ok: bool
    message: str
    data: dict[str, Any] | list[dict[str, Any]] | None = None


_PIHOLE_SESSION_CACHE: dict[str, dict[str, Any]] = {}
_PIHOLE_SESSION_LOCK = threading.Lock()
_PIHOLE_DEFAULT_SESSION_SECONDS = 20 * 60


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
    def get_history(self) -> DNSProviderResult:
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
    def __init__(self, config: DNSProviderConfig):
        super().__init__(config)
        self._sid: str | None = None

    def _base_url(self) -> str:
        return self.config.base_url.rstrip("/")

    def _secret(self) -> str:
        return decrypt_secret(self.config.encrypted_secret or "").strip()

    def _session_cache_key(self, secret: str) -> str:
        secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
        return f"{self.config.id}:{self._base_url()}:{self.config.auth_method}:{secret_hash}"

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
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace").strip()
            except Exception:
                detail = ""
            message = f"Pi-hole returned HTTP {exc.code}."
            if exc.code == 429:
                message = "Pi-hole API seats are currently exhausted. Kaya will reuse one API session once a seat is available; wait for an existing Pi-hole session to expire, then refresh."
            if detail:
                try:
                    parsed = json.loads(detail)
                    if isinstance(parsed, dict):
                        api_error = parsed.get("error") or parsed.get("message")
                        if isinstance(api_error, dict):
                            api_error = api_error.get("message") or api_error.get("detail")
                        if api_error and exc.code != 429:
                            message = f"Pi-hole returned HTTP {exc.code}: {api_error}"
                except json.JSONDecodeError:
                    if len(detail) < 180 and exc.code != 429:
                        message = f"Pi-hole returned HTTP {exc.code}: {detail}"
            raise PiHoleHTTPError(exc.code, message) from exc
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

    def _v6_auth_headers(self) -> dict[str, str]:
        secret = self._secret()
        if not secret:
            return {}
        if self.config.auth_method == "api_token":
            raise DNSProviderError("Configured for legacy Pi-hole API token authentication.")
        cache_key = self._session_cache_key(secret)
        now = time.time()
        with _PIHOLE_SESSION_LOCK:
            cached = _PIHOLE_SESSION_CACHE.get(cache_key)
            if cached and cached.get("sid") and float(cached.get("expires_at") or 0) > now:
                self._sid = str(cached["sid"])
                return {"X-FTL-SID": self._sid}
            if self._sid:
                return {"X-FTL-SID": self._sid}
            data = self._request_json("/api/auth", method="POST", payload={"password": secret})
            session = data.get("session") if isinstance(data.get("session"), dict) else data
            sid = session.get("sid") if isinstance(session, dict) else None
            if not sid:
                raise DNSProviderError("Pi-hole authentication did not return a session.")
            validity = session.get("validity") if isinstance(session, dict) else None
            try:
                ttl = max(60, min(int(validity), 24 * 60 * 60)) if validity else _PIHOLE_DEFAULT_SESSION_SECONDS
            except (TypeError, ValueError):
                ttl = _PIHOLE_DEFAULT_SESSION_SECONDS
            self._sid = sid
            _PIHOLE_SESSION_CACHE[cache_key] = {
                "sid": self._sid,
                "expires_at": now + max(30, ttl - 30),
            }
        return {"X-FTL-SID": self._sid}

    def _clear_cached_sid(self) -> None:
        secret = self._secret()
        if not secret or self.config.auth_method == "api_token":
            self._sid = None
            return
        with _PIHOLE_SESSION_LOCK:
            _PIHOLE_SESSION_CACHE.pop(self._session_cache_key(secret), None)
        self._sid = None

    def _v6_request_json(self, path: str) -> dict[str, Any]:
        try:
            return self._request_json(path, headers=self._v6_auth_headers())
        except PiHoleHTTPError as exc:
            if exc.status_code in {401, 403} and self._sid:
                self._clear_cached_sid()
                return self._request_json(path, headers=self._v6_auth_headers())
            raise

    def _legacy_api(self, params: dict[str, Any]) -> dict[str, Any]:
        secret = self._secret()
        if secret:
            params = {**params, "auth": secret}
        query_parts = []
        for key, value in params.items():
            if value == "":
                query_parts.append(quote(str(key)))
            else:
                query_parts.append(urlencode({key: value}))
        return self._request_json(f"/admin/api.php?{'&'.join(query_parts)}")

    def _v6_or_legacy(self, v6_path: str, legacy_params: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._v6_request_json(v6_path)
        except PiHoleHTTPError as exc:
            if exc.status_code not in {400, 401, 403, 404}:
                raise
            try:
                return self._legacy_api(legacy_params)
            except DNSProviderError:
                if exc.status_code in {401, 403}:
                    raise DNSProviderError("Pi-hole authentication failed. Check the authentication method and credential.") from exc
                raise
        except DNSProviderError:
            return self._legacy_api(legacy_params)

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
            data = self._v6_or_legacy("/api/info/system", {"status": ""})
            return DNSProviderResult(True, "Pi-hole status loaded.", data)

        return self._safe("Status", run)

    def get_statistics(self) -> DNSProviderResult:
        def run():
            data = self._v6_or_legacy("/api/stats/summary", {"summaryRaw": ""})
            return DNSProviderResult(True, "Pi-hole statistics loaded.", data)

        return self._safe("Statistics", run)

    def get_history(self) -> DNSProviderResult:
        def run():
            data: dict[str, Any] = {}
            try:
                data["queries"] = self._v6_or_legacy("/api/history", {"overTimeData10mins": ""})
            except DNSProviderError as exc:
                data["queries_error"] = str(exc)
            try:
                data["clients"] = self._legacy_api({"getQuerySources": ""})
            except DNSProviderError:
                try:
                    data["clients"] = self._legacy_api({"getClientNames": ""})
                except DNSProviderError as exc:
                    data["clients_error"] = str(exc)
            if not data or ("queries_error" in data and "clients_error" in data):
                raise DNSProviderError("Pi-hole history data is unavailable from this API.")
            return DNSProviderResult(True, "Pi-hole history loaded.", data)

        return self._safe("History", run)

    def get_clients(self) -> DNSProviderResult:
        def run():
            data = self._v6_or_legacy("/api/network/devices", {"getQuerySources": ""})
            return DNSProviderResult(True, "Pi-hole clients loaded.", data)

        return self._safe("Clients", run)

    def get_query_log(self, *, limit: int = 100) -> DNSProviderResult:
        def run():
            data = self._v6_or_legacy(
                f"/api/queries?length={max(1, min(limit, 500))}",
                {"getAllQueries": "", "limit": max(1, min(limit, 500))},
            )
            return DNSProviderResult(True, "Pi-hole query log loaded.", data)

        return self._safe("Query log", run)

    def get_local_dns_records(self) -> DNSProviderResult:
        def run():
            data = self._v6_request_json("/api/config/dns/hosts")
            return DNSProviderResult(True, "Pi-hole local DNS records loaded.", data)

        return self._safe("Local DNS", run)

    def get_dhcp_leases(self) -> DNSProviderResult:
        def run():
            data = self._v6_request_json("/api/dhcp/leases")
            return DNSProviderResult(True, "Pi-hole DHCP leases loaded.", data)

        return self._safe("DHCP", run)

    def get_blocklists(self) -> DNSProviderResult:
        def run():
            data = self._v6_request_json("/api/lists")
            return DNSProviderResult(True, "Pi-hole blocklists loaded.", data)

        return self._safe("Blocklists", run)


def provider_for(config: DNSProviderConfig) -> DNSProvider:
    if config.provider_type == "pihole":
        return PiHoleProvider(config)
    raise DNSProviderError(f"Unsupported DNS provider type: {config.provider_type}")
