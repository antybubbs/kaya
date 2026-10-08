"""SNMPv3 IF-MIB provider and counter normalization for Network Traffic."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.security import decrypt_secret
from app.models.models import TrafficSource
from app.services.network_traffic import validate_destination

IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_COUNTER_DISCONTINUITY = "1.3.6.1.2.1.31.1.1.1.19"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"


class SNMPProviderError(RuntimeError):
    def __init__(self, category: str, message: str = "SNMP polling failed"):
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class InterfaceSnapshot:
    interface_index: int
    interface_key: str
    display_name: str
    description: str | None
    oper_status: int | None
    admin_status: int | None
    speed_bps: int | None
    inbound_octets: int | None
    outbound_octets: int | None
    counter_bits: int
    discontinuity_ticks: int | None
    device_uptime_ticks: int | None


@dataclass(frozen=True)
class RateResult:
    bits_per_second: int | None
    baseline: bool = False
    reset: bool = False
    wrapped: bool = False
    rejected: bool = False


def _oid_tuple(value: Any) -> tuple[int, ...]:
    if hasattr(value, "asTuple"):
        return tuple(int(item) for item in value.asTuple())
    text = str(value).strip().lstrip(".")
    return tuple(int(item) for item in text.split("."))


def _value_int(value: Any) -> int | None:
    try:
        if value is None or "nosuch" in str(value).lower() or "no such" in str(value).lower():
            return None
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _value_text(value: Any) -> str:
    try:
        return value.prettyPrint()
    except AttributeError:
        return str(value)


def _column_index(oid: Any, root: str) -> int | None:
    parts = _oid_tuple(oid)
    prefix = _oid_tuple(root)
    if len(parts) != len(prefix) + 1 or parts[: len(prefix)] != prefix:
        return None
    return parts[-1]


def calculate_rate(
    previous: int | None,
    current: int | None,
    elapsed_seconds: float,
    *,
    counter_bits: int = 64,
    interface_speed_bps: int | None = None,
    reset_detected: bool = False,
) -> RateResult:
    """Calculate a counter rate without turning resets or bad samples into traffic."""
    if previous is None or current is None:
        return RateResult(None, baseline=True)
    if elapsed_seconds <= 0 or previous < 0 or current < 0 or counter_bits not in {32, 64}:
        return RateResult(None, rejected=True)
    if reset_detected:
        return RateResult(None, reset=True)
    wrapped = False
    if current < previous:
        maximum = (1 << counter_bits) - 1
        if previous >= int(maximum * 0.75) and current <= int(maximum * 0.25):
            delta = maximum - previous + current + 1
            wrapped = True
        else:
            return RateResult(None, reset=True)
    else:
        delta = current - previous
    rate = int((delta * 8) / elapsed_seconds)
    if interface_speed_bps and interface_speed_bps > 0 and rate > int(interface_speed_bps * 1.25):
        return RateResult(None, wrapped=wrapped, rejected=True)
    return RateResult(rate, wrapped=wrapped)


def calculate_counter_rates(
    previous: InterfaceSnapshot | None,
    current: InterfaceSnapshot,
    elapsed_seconds: float,
) -> tuple[RateResult, RateResult]:
    restarted = bool(
        previous
        and previous.device_uptime_ticks is not None
        and current.device_uptime_ticks is not None
        and current.device_uptime_ticks < previous.device_uptime_ticks
    )
    discontinuity = bool(
        previous
        and previous.discontinuity_ticks is not None
        and current.discontinuity_ticks is not None
        and current.discontinuity_ticks != previous.discontinuity_ticks
    )
    reset = restarted or discontinuity
    return (
        calculate_rate(previous.inbound_octets if previous else None, current.inbound_octets, elapsed_seconds, counter_bits=current.counter_bits, interface_speed_bps=current.speed_bps, reset_detected=reset),
        calculate_rate(previous.outbound_octets if previous else None, current.outbound_octets, elapsed_seconds, counter_bits=current.counter_bits, interface_speed_bps=current.speed_bps, reset_detected=reset),
    )


def _protocols(auth: str | None, privacy: str | None) -> tuple[Any, Any]:
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            USM_AUTH_HMAC96_SHA,
            USM_AUTH_HMAC192_SHA256,
            USM_AUTH_HMAC256_SHA384,
            USM_AUTH_HMAC384_SHA512,
            USM_PRIV_CFB128_AES,
            USM_PRIV_CFB192_AES,
            USM_PRIV_CFB256_AES,
        )
    except ImportError as exc:
        raise SNMPProviderError("configuration_error", "SNMP provider dependency is unavailable") from exc
    auth_map = {"SHA": USM_AUTH_HMAC96_SHA, "SHA-256": USM_AUTH_HMAC192_SHA256, "SHA-384": USM_AUTH_HMAC256_SHA384, "SHA-512": USM_AUTH_HMAC384_SHA512}
    privacy_map = {"AES128": USM_PRIV_CFB128_AES, "AES192": USM_PRIV_CFB192_AES, "AES256": USM_PRIV_CFB256_AES}
    if auth not in auth_map or privacy not in privacy_map:
        raise SNMPProviderError("configuration_error", "SNMPv3 authentication and privacy protocols are required")
    return auth_map[auth], privacy_map[privacy]


class SNMPv3Provider:
    """Read-only IF-MIB provider. ``walk_column`` is injectable for fixture tests."""

    def __init__(self, *, timeout_seconds: float = 5.0, retries: int = 1):
        self.timeout_seconds = max(0.5, min(float(timeout_seconds), 30.0))
        self.retries = max(0, min(int(retries), 2))

    def _credentials(self, source: TrafficSource):
        if not source.destination_ip or not source.security_name or validate_destination(source.destination_ip) is None:
            raise SNMPProviderError("configuration_error", "SNMP source is incomplete")
        auth = decrypt_secret(source.encrypted_snmp_authentication)
        privacy = decrypt_secret(source.encrypted_snmp_privacy)
        if not auth or not privacy or auth == "[decryption failed]" or privacy == "[decryption failed]":
            raise SNMPProviderError("configuration_error", "SNMP source credentials are unavailable")
        auth_protocol, privacy_protocol = _protocols(source.snmp_auth_protocol, source.snmp_privacy_protocol)
        try:
            from pysnmp.hlapi.v3arch.asyncio import UsmUserData
            return UsmUserData(source.security_name, authKey=auth, privKey=privacy, authProtocol=auth_protocol, privProtocol=privacy_protocol)
        except ImportError as exc:
            raise SNMPProviderError("configuration_error", "SNMP provider dependency is unavailable") from exc

    async def walk_column(self, source: TrafficSource, root: str) -> dict[int, Any]:
        try:
            from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, bulk_cmd
        except ImportError as exc:
            raise SNMPProviderError("configuration_error", "SNMP provider dependency is unavailable") from exc
        engine = SnmpEngine()
        try:
            target = await UdpTransportTarget.create((source.destination_ip, source.destination_port), timeout=self.timeout_seconds, retries=self.retries)
            result: dict[int, Any] = {}
            cursor = root
            requests = 0
            while True:
                requests += 1
                if requests > 2048:
                    raise SNMPProviderError("device_unavailable", "SNMP table walk exceeded its safety limit")
                error_indication, error_status, error_index, rows = await bulk_cmd(engine, self._credentials(source), target, ContextData(), 0, 25, ObjectType(ObjectIdentity(cursor)))
                if error_indication:
                    text = str(error_indication).lower()
                    category = "authentication_failure" if "authoriz" in text or "authentication" in text else "timeout" if "timeout" in text else "device_unavailable"
                    raise SNMPProviderError(category)
                if error_status:
                    status_text = str(error_status).lower()
                    category = "unsupported" if any(item in status_text for item in ("nosuch", "no such", "endofmib")) else "device_unavailable"
                    raise SNMPProviderError(category)
                reached_end = True
                last_oid = None
                # PySNMP 7.1 returns a flat tuple of ObjectType var-binds
                # from bulk_cmd (older releases commonly returned rows).
                for oid, value in rows:
                    index = _column_index(oid, root)
                    if index is None:
                        reached_end = True
                        continue
                    result[index] = value
                    last_oid = _oid_tuple(oid)
                    reached_end = False
                if reached_end or last_oid is None:
                    break
                next_cursor = ".".join(str(item) for item in last_oid)
                if _oid_tuple(next_cursor) <= _oid_tuple(cursor):
                    break
                cursor = next_cursor
            return result
        except SNMPProviderError:
            raise
        except (asyncio.TimeoutError, TimeoutError):
            raise SNMPProviderError("timeout") from None
        except OSError:
            raise SNMPProviderError("device_unavailable") from None
        finally:
            try:
                engine.close_dispatcher()
            except Exception:
                pass

    async def discover_interfaces(self, source: TrafficSource) -> list[InterfaceSnapshot]:
        roots = [IF_DESCR, IF_NAME, IF_SPEED, IF_HIGH_SPEED, IF_ADMIN_STATUS, IF_OPER_STATUS, IF_HC_IN_OCTETS, IF_HC_OUT_OCTETS, IF_IN_OCTETS, IF_OUT_OCTETS, IF_COUNTER_DISCONTINUITY]
        optional = {IF_NAME, IF_HIGH_SPEED, IF_HC_IN_OCTETS, IF_HC_OUT_OCTETS, IF_COUNTER_DISCONTINUITY}

        async def read(root: str) -> dict[int, Any]:
            try:
                return await self.walk_column(source, root)
            except SNMPProviderError as exc:
                if root in optional and exc.category == "unsupported":
                    return {}
                raise

        columns = await asyncio.gather(*(read(root) for root in roots))
        values = dict(zip(roots, columns))
        try:
            uptime = await self.get_scalar(source, SYS_UPTIME)
        except SNMPProviderError as exc:
            if exc.category == "unsupported":
                uptime = None
            else:
                raise
        indexes = sorted(set(values[IF_DESCR]) | set(values[IF_NAME]) | set(values[IF_HC_IN_OCTETS]) | set(values[IF_HC_OUT_OCTETS]) | set(values[IF_IN_OCTETS]) | set(values[IF_OUT_OCTETS]))
        result = []
        for index in indexes:
            name = _value_text(values[IF_NAME].get(index) or values[IF_DESCR].get(index) or f"ifIndex {index}")
            high_in = _value_int(values[IF_HC_IN_OCTETS].get(index))
            high_out = _value_int(values[IF_HC_OUT_OCTETS].get(index))
            high_speed_mbps = _value_int(values[IF_HIGH_SPEED].get(index))
            speed = high_speed_mbps * 1_000_000 if high_speed_mbps and high_speed_mbps > 0 else _value_int(values[IF_SPEED].get(index))
            result.append(InterfaceSnapshot(index, f"ifIndex:{index}", name[:255], _value_text(values[IF_DESCR].get(index)) if values[IF_DESCR].get(index) is not None else None, _value_int(values[IF_OPER_STATUS].get(index)), _value_int(values[IF_ADMIN_STATUS].get(index)), speed, high_in if high_in is not None else _value_int(values[IF_IN_OCTETS].get(index)), high_out if high_out is not None else _value_int(values[IF_OUT_OCTETS].get(index)), 64 if high_in is not None or high_out is not None else 32, _value_int(values[IF_COUNTER_DISCONTINUITY].get(index)), uptime))
        return result

    async def get_scalar(self, source: TrafficSource, oid: str) -> int | None:
        try:
            from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, get_cmd
        except ImportError as exc:
            raise SNMPProviderError("configuration_error", "SNMP provider dependency is unavailable") from exc
        engine = SnmpEngine()
        try:
            target = await UdpTransportTarget.create((source.destination_ip, source.destination_port), timeout=self.timeout_seconds, retries=self.retries)
            indication, status, index, var_binds = await get_cmd(engine, self._credentials(source), target, ContextData(), ObjectType(ObjectIdentity(oid)))
            if indication:
                raise SNMPProviderError("timeout" if "timeout" in str(indication).lower() else "device_unavailable")
            if status:
                status_text = str(status).lower()
                raise SNMPProviderError("unsupported" if any(item in status_text for item in ("nosuch", "no such")) else "device_unavailable")
            return _value_int(var_binds[0][1]) if var_binds else None
        except SNMPProviderError:
            raise
        except (asyncio.TimeoutError, TimeoutError):
            raise SNMPProviderError("timeout") from None
        except OSError:
            raise SNMPProviderError("device_unavailable") from None
        finally:
            try:
                engine.close_dispatcher()
            except Exception:
                pass

    async def test_connection(self, source: TrafficSource) -> list[InterfaceSnapshot]:
        return await self.discover_interfaces(source)
