from __future__ import annotations

import json
import hashlib
import ssl
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from app.core.performance import external_call

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

    @abstractmethod
    def get_version(self) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def get_ha_configuration(self) -> DNSProviderResult:
        raise NotImplementedError

    @abstractmethod
    def update_blocklists(self) -> DNSProviderResult:
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
        timeout_seconds: int | None = None,
        allow_non_json: bool = False,
    ) -> dict[str, Any]:
        body = None
        request_headers = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        url = f"{self._base_url()}{path}"
        request = Request(url, data=body, method=method, headers=request_headers)
        try:
            with external_call():
                with urlopen(
                    request,
                    timeout=max(1, min(int(timeout_seconds or self.config.timeout_seconds or 10), 120)),
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
            if allow_non_json:
                return {"output": raw.strip()}
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

    def _v6_request_json(self, path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            return self._request_json(path, method=method, payload=payload, headers=self._v6_auth_headers())
        except PiHoleHTTPError as exc:
            if exc.status_code in {401, 403} and self._sid:
                self._clear_cached_sid()
                return self._request_json(path, method=method, payload=payload, headers=self._v6_auth_headers())
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

    def get_version(self) -> DNSProviderResult:
        def run():
            data = self._v6_or_legacy("/api/info/version", {"versions": ""})
            return DNSProviderResult(True, "Pi-hole version loaded.", data)

        return self._safe("Version", run)

    def get_ha_configuration(self) -> DNSProviderResult:
        """Load only read-only configuration surfaces used by HA comparison."""
        endpoints = {
            "groups": "/api/groups",
            "clients": "/api/clients",
            "local_dns": "/api/config/dns/hosts",
            "cname": "/api/config/dns/cnameRecords",
            "upstream_dns": "/api/config/dns",
            "dhcp": "/api/config/dhcp",
        }

        def run():
            configuration: dict[str, Any] = {}
            unavailable: dict[str, str] = {}
            filtering: dict[str, Any] = {}
            for name, path in {"lists": "/api/lists", "domains": "/api/domains"}.items():
                try:
                    filtering[name] = self._v6_request_json(path)
                except DNSProviderError as exc:
                    unavailable[f"filtering_{name}"] = str(exc)
            if filtering:
                configuration["filtering"] = filtering
            for group, path in endpoints.items():
                try:
                    configuration[group] = self._v6_request_json(path)
                except DNSProviderError as exc:
                    unavailable[group] = str(exc)
            if not configuration:
                raise DNSProviderError("Pi-hole configuration endpoints are unavailable or authentication failed.")
            return DNSProviderResult(
                True,
                "Pi-hole configuration loaded for read-only comparison.",
                {"configuration": configuration, "unavailable": unavailable},
            )

        return self._safe("Configuration", run)

    def apply_ha_configuration_group(self, group: str, value: Any) -> DNSProviderResult:
        """Apply one allowlisted Pi-hole v6 configuration group.

        Collection resources need item-by-item conflict handling and are therefore
        deliberately not accepted by this configuration-patch method.
        """
        paths = {
            "local_dns": "/api/config/dns/hosts",
            "cname": "/api/config/dns/cnameRecords",
            "upstream_dns": "/api/config/dns",
            "dhcp": "/api/config/dhcp",
        }
        path = paths.get(group)
        if path is None:
            return DNSProviderResult(False, f"{group} requires collection reconciliation and cannot be patched safely.", None)

        def run():
            if not isinstance(value, dict) or not isinstance(value.get("config"), dict):
                raise DNSProviderError(f"The {group} snapshot has no writable Pi-hole configuration payload.")
            payload = {"config": value["config"]}
            data = self._request_json(path, method="PATCH", payload=payload, headers=self._v6_auth_headers())
            return DNSProviderResult(True, f"Pi-hole {group.replace('_', ' ')} configuration applied.", data)

        return self._safe("Configuration update", run)

    @staticmethod
    def _collection(value: Any, key: str) -> list[dict[str, Any]]:
        if isinstance(value, dict):
            rows = value.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        return []

    def reconcile_ha_collections(self, source: dict[str, Any], *, allow_deletions: bool) -> DNSProviderResult:
        """Reconcile Pi-hole v6 groups, subscribed lists, domains, and clients."""
        def run():
            current_result = self.get_ha_configuration()
            if not current_result.ok or not isinstance(current_result.data, dict):
                raise DNSProviderError(current_result.message)
            current = current_result.data.get("configuration")
            if not isinstance(current, dict):
                raise DNSProviderError("Pi-hole returned no collection configuration.")

            source_groups = self._collection(source.get("groups"), "groups")
            target_groups = self._collection(current.get("groups"), "groups")
            source_group_names = {int(row.get("id")): str(row.get("name")) for row in source_groups if row.get("id") is not None and row.get("name")}

            def mutate(path: str, method: str, payload: dict[str, Any] | None = None):
                return self._v6_request_json(path, method=method, payload=payload)

            source_by_name = {str(row.get("name")): row for row in source_groups if row.get("name")}
            target_by_name = {str(row.get("name")): row for row in target_groups if row.get("name")}
            for name, row in source_by_name.items():
                payload = {"name": name, "comment": row.get("comment") or "", "enabled": bool(row.get("enabled", True))}
                if name in target_by_name:
                    mutate(f"/api/groups/{quote(name, safe='')}", "PUT", payload)
                else:
                    mutate("/api/groups", "POST", {**payload, "name": [name]})
            extras = sorted(set(target_by_name) - set(source_by_name) - {"Default"})
            if extras and not allow_deletions:
                raise DNSProviderError("The plan contains group deletions which were not explicitly confirmed.")
            for name in extras:
                mutate(f"/api/groups/{quote(name, safe='')}", "DELETE")

            refreshed_groups = self._v6_request_json("/api/groups")
            target_group_ids = {str(row.get("name")): int(row.get("id")) for row in self._collection(refreshed_groups, "groups") if row.get("id") is not None and row.get("name")}

            def mapped_groups(row: dict[str, Any]) -> list[int]:
                names = [source_group_names.get(int(group_id)) for group_id in row.get("groups", []) if str(group_id).isdigit()]
                return sorted(target_group_ids[name] for name in names if name in target_group_ids)

            source_filtering = source.get("filtering") if isinstance(source.get("filtering"), dict) else {}
            target_filtering = current.get("filtering") if isinstance(current.get("filtering"), dict) else {}
            source_lists = self._collection(source_filtering.get("lists"), "lists")
            target_lists = self._collection(target_filtering.get("lists"), "lists")
            list_key = lambda row: (str(row.get("address") or ""), str(row.get("type") or "block"))
            source_lists_by_key = {list_key(row): row for row in source_lists if row.get("address")}
            target_lists_by_key = {list_key(row): row for row in target_lists if row.get("address")}
            for (address, list_type), row in source_lists_by_key.items():
                payload = {"comment": row.get("comment") or "", "enabled": bool(row.get("enabled", True)), "groups": mapped_groups(row), "type": list_type}
                if (address, list_type) in target_lists_by_key:
                    mutate(f"/api/lists/{quote(address, safe='')}?type={quote(list_type, safe='')}", "PUT", payload)
                else:
                    mutate(f"/api/lists?type={quote(list_type, safe='')}", "POST", {"address": [address], "comment": payload["comment"], "groups": payload["groups"]})
            list_extras = sorted(set(target_lists_by_key) - set(source_lists_by_key))
            if list_extras and not allow_deletions:
                raise DNSProviderError("The plan contains subscribed-list deletions which were not explicitly confirmed.")
            for address, list_type in list_extras:
                mutate(f"/api/lists/{quote(address, safe='')}?type={quote(list_type, safe='')}", "DELETE")

            source_domains = self._collection(source_filtering.get("domains"), "domains")
            target_domains = self._collection(target_filtering.get("domains"), "domains")
            domain_key = lambda row: (str(row.get("domain") or ""), str(row.get("type") or "allow"), str(row.get("kind") or "exact"))
            source_domains_by_key = {domain_key(row): row for row in source_domains if row.get("domain")}
            target_domains_by_key = {domain_key(row): row for row in target_domains if row.get("domain")}
            for (domain, domain_type, kind), row in source_domains_by_key.items():
                payload = {"comment": row.get("comment") or "", "enabled": bool(row.get("enabled", True)), "groups": mapped_groups(row), "type": domain_type, "kind": kind}
                path = f"/api/domains/{quote(domain_type, safe='')}/{quote(kind, safe='')}/{quote(domain, safe='')}"
                if (domain, domain_type, kind) in target_domains_by_key:
                    mutate(path, "PUT", payload)
                else:
                    mutate(f"/api/domains/{quote(domain_type, safe='')}/{quote(kind, safe='')}", "POST", {**payload, "domain": [domain]})
            domain_extras = sorted(set(target_domains_by_key) - set(source_domains_by_key))
            if domain_extras and not allow_deletions:
                raise DNSProviderError("The plan contains domain deletions which were not explicitly confirmed.")
            for domain, domain_type, kind in domain_extras:
                mutate(f"/api/domains/{quote(domain_type, safe='')}/{quote(kind, safe='')}/{quote(domain, safe='')}", "DELETE")

            source_clients = self._collection(source.get("clients"), "clients")
            target_clients = self._collection(current.get("clients"), "clients")
            source_clients_by_key = {str(row.get("client")): row for row in source_clients if row.get("client")}
            target_clients_by_key = {str(row.get("client")): row for row in target_clients if row.get("client")}
            for client, row in source_clients_by_key.items():
                payload = {"comment": row.get("comment") or "", "groups": mapped_groups(row)}
                if client in target_clients_by_key:
                    mutate(f"/api/clients/{quote(client, safe='')}", "PUT", payload)
                else:
                    mutate("/api/clients", "POST", {**payload, "client": [client]})
            client_extras = sorted(set(target_clients_by_key) - set(source_clients_by_key))
            if client_extras and not allow_deletions:
                raise DNSProviderError("The plan contains client deletions which were not explicitly confirmed.")
            for client in client_extras:
                mutate(f"/api/clients/{quote(client, safe='')}", "DELETE")
            return DNSProviderResult(True, "Pi-hole collection configuration reconciled.", {})

        return self._safe("Collection reconciliation", run)

    def update_blocklists(self) -> DNSProviderResult:
        def run():
            data = self._request_json(
                "/api/action/gravity",
                method="POST",
                payload={},
                headers=self._v6_auth_headers(),
                timeout_seconds=120,
                allow_non_json=True,
            )
            return DNSProviderResult(True, "Pi-hole blocklists updated successfully.", data)

        return self._safe("Blocklist update", run)


class HAPiHoleProvider(DNSProvider):
    """Expose a Pi-hole HA cluster as one logical DNS Manager provider.

    Provider history remains attached to ``self.config.id``. Only live API calls are
    routed to the node which currently owns the VIP; Kaya is never in the DNS or
    DHCP packet path.
    """

    def _active_provider(self) -> PiHoleProvider:
        cluster = self.config.ha_cluster
        if cluster is None or cluster.deleted_at is not None:
            raise DNSProviderError("The linked Kaya HA Pi-hole cluster is unavailable.")
        owners = [
            node for node in cluster.nodes
            if node.vip_owned and node.keepalived_runtime_state == "RUNNING" and node.dns_healthy is not False
        ]
        if len(owners) != 1 or cluster.current_active_node_id != owners[0].id:
            raise DNSProviderError("Kaya cannot safely identify one current Pi-hole VIP owner. Check the HA cluster before retrying.")
        node = owners[0]
        source = node.integration if node.integration is not None else node.ha_connection
        if source is None or getattr(source, "deleted_at", None) is not None:
            raise DNSProviderError("The active HA node has no usable management connection.")
        node_config = SimpleNamespace(
            id=f"ha-dns-{self.config.id}-node-{node.id}",
            base_url=source.base_url if node.integration is not None else source.api_base_url,
            auth_method=source.auth_method,
            encrypted_secret=source.encrypted_secret,
            ssl_verify=source.ssl_verify,
            timeout_seconds=source.timeout_seconds,
        )
        return PiHoleProvider(node_config)

    def _call(self, method: str, *args, **kwargs) -> DNSProviderResult:
        try:
            return getattr(self._active_provider(), method)(*args, **kwargs)
        except DNSProviderError as exc:
            return DNSProviderResult(False, str(exc), None)

    def test_connection(self): return self._call("test_connection")
    def get_status(self): return self._call("get_status")
    def get_statistics(self): return self._call("get_statistics")
    def get_history(self): return self._call("get_history")
    def get_clients(self): return self._call("get_clients")
    def get_query_log(self, *, limit: int = 100): return self._call("get_query_log", limit=limit)
    def get_local_dns_records(self): return self._call("get_local_dns_records")
    def get_dhcp_leases(self): return self._call("get_dhcp_leases")
    def get_blocklists(self): return self._call("get_blocklists")
    def get_version(self): return self._call("get_version")
    def get_ha_configuration(self): return self._call("get_ha_configuration")
    def update_blocklists(self): return self._call("update_blocklists")


def provider_for(config: DNSProviderConfig) -> DNSProvider:
    if config.provider_type == "pihole":
        if config.ha_cluster_id is not None:
            return HAPiHoleProvider(config)
        return PiHoleProvider(config)
    raise DNSProviderError(f"Unsupported DNS provider type: {config.provider_type}")
