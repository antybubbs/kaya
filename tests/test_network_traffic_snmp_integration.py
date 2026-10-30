"""Real PySNMP 7.1.30 SNMPv3 integration coverage.

The fixture uses a local PySNMP command responder with USM authPriv.  It is
deliberately not a mock of the manager API: the production provider sends and
receives encrypted UDP SNMPv3 packets.
"""
from __future__ import annotations

import asyncio
import threading

import pytest

from app.core.security import encrypt_secret
from app.models.models import TrafficSource
from app.services import network_traffic_snmp as provider_module
from app.services.network_traffic_snmp import IF_DESCR, SNMPProviderError, SNMPv3Provider, _value_int
from app.services.network_traffic_poller import discover_source_interfaces


def _start_agent(port: int):
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import cmdrsp, context
    from pysnmp.proto.rfc1902 import Counter64, Gauge32, Integer32, OctetString, TimeTicks

    snmp_engine = engine.SnmpEngine()
    config.add_transport(snmp_engine, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", port)))
    config.add_v3_user(
        snmp_engine,
        "integration-user",
        config.USM_AUTH_HMAC96_SHA,
        "authpass1",
        config.USM_PRIV_CFB128_AES,
        "privpass1",
    )
    config.add_vacm_user(snmp_engine, 3, "integration-user", "authPriv", (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))

    mib_builder = snmp_engine.get_mib_builder()
    MibScalar, MibScalarInstance = mib_builder.import_symbols("SNMPv2-SMI", "MibScalar", "MibScalarInstance")

    def add_column(oid: tuple[int, ...], syntax, value):
        mib_builder.export_symbols(
            "__STAGE2-INTEGRATION",
            MibScalar(oid, syntax.clone()),
            MibScalarInstance(oid, (1,), syntax.clone(value)),
        )

    add_column((1, 3, 6, 1, 2, 1, 2, 2, 1, 1), Integer32(), 1)
    add_column((1, 3, 6, 1, 2, 1, 2, 2, 1, 2), OctetString(), "WAN-Test")
    add_column((1, 3, 6, 1, 2, 1, 2, 2, 1, 5), Gauge32(), 1_000_000_000)
    add_column((1, 3, 6, 1, 2, 1, 2, 2, 1, 7), Integer32(), 1)
    add_column((1, 3, 6, 1, 2, 1, 2, 2, 1, 8), Integer32(), 1)
    add_column((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1), OctetString(), "WAN-Test")
    add_column((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6), Counter64(), 10_000)
    add_column((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10), Counter64(), 20_000)
    add_column((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15), Gauge32(), 1000)
    add_column((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 19), TimeTicks(), 50)

    snmp_context = context.SnmpContext(snmp_engine)
    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
    cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)
    snmp_engine.transport_dispatcher.job_started(1)
    ready = threading.Event()
    agent_loop = asyncio.get_event_loop()

    def run():
        asyncio.set_event_loop(agent_loop)
        ready.set()
        snmp_engine.open_dispatcher()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    ready.wait(timeout=2)
    return snmp_engine, thread


def test_real_pysnmp_v3_auth_priv_discovery(monkeypatch):
    # Loopback is correctly rejected by production SSRF policy. The local
    # agent is isolated to this test, so only this fixture permits its address.
    monkeypatch.setattr(provider_module, "validate_destination", lambda value: value)
    port = 11619
    agent_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(agent_loop)
    agent, thread = _start_agent(port)
    try:
        source = TrafficSource(
            destination_ip="127.0.0.1",
            destination_port=port,
            security_name="integration-user",
            encrypted_snmp_authentication=encrypt_secret("authpass1"),
            encrypted_snmp_privacy=encrypt_secret("privpass1"),
            snmp_auth_protocol="SHA",
            snmp_privacy_protocol="AES128",
        )
        snapshots = asyncio.run(asyncio.wait_for(SNMPv3Provider(timeout_seconds=2, retries=0).discover_interfaces(source), timeout=20))
        assert len(snapshots) == 1
        assert snapshots[0].interface_key == "ifIndex:1"
        assert snapshots[0].inbound_octets == 10_000
        assert snapshots[0].outbound_octets == 20_000
        assert snapshots[0].counter_bits == 64
        assert snapshots[0].speed_bps == 1_000_000_000
        probe = SNMPv3Provider(timeout_seconds=2, retries=0)
        probe_calls = []

        async def scalar_probe(probe_source, oid):
            probe_calls.append(oid)
            return 123

        probe.get_scalar = scalar_probe
        probe.discover_interfaces = lambda _source: (_ for _ in ()).throw(AssertionError("connection test must not walk interfaces"))
        assert asyncio.run(probe.test_connection(source)) is None
        assert probe_calls == [provider_module.SYS_UPTIME]
    finally:
        agent.close_dispatcher()
        thread.join(timeout=2)
        agent_loop.close()
        asyncio.set_event_loop(None)


def test_connection_test_does_not_start_interface_discovery():
    provider = SNMPv3Provider(timeout_seconds=1, retries=0)
    calls = []

    async def scalar_probe(source, oid):
        calls.append((source, oid))
        return 1

    provider.get_scalar = scalar_probe
    provider.discover_interfaces = lambda _source: (_ for _ in ()).throw(AssertionError("unexpected interface walk"))
    source = TrafficSource(destination_ip="192.0.2.1", destination_port=161, security_name="fake")
    assert asyncio.run(provider.test_connection(source)) is None
    assert calls[0][1] == provider_module.SYS_UPTIME


def test_discovery_timeout_is_converted_to_controlled_provider_error():
    class SlowProvider:
        async def discover_interfaces(self, source):
            await asyncio.sleep(2.1)
            return []

    with pytest.raises(SNMPProviderError, match="did not respond"):
        asyncio.run(discover_source_interfaces(None, TrafficSource(id=1, polling_interval_seconds=5), provider=SlowProvider()))


def test_discovery_cancellation_is_not_converted_to_success():
    class CancelledProvider:
        async def discover_interfaces(self, source):
            raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(discover_source_interfaces(None, TrafficSource(id=1, polling_interval_seconds=5), provider=CancelledProvider()))


def test_required_column_failure_is_preserved_and_malformed_values_are_safe():
    class FailingProvider(SNMPv3Provider):
        async def walk_column(self, source, root):
            if root == IF_DESCR:
                raise SNMPProviderError("malformed_response")
            return {}

    with pytest.raises(SNMPProviderError, match="invalid response"):
        asyncio.run(FailingProvider().discover_interfaces(TrafficSource(id=1)))
    assert _value_int(object()) is None
