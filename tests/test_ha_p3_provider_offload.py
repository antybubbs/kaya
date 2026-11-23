"""The seven HA administrator requests that call Pi-hole never block the event loop.

Covered handlers: test connection, validate, plan synchronisation, apply
synchronisation, DHCP lease reconciliation, DHCP DNS-advertisement repair and
controlled failover start.

Each test drives the real route coroutine against a file-backed SQLite
database (WAL, as in production) with a synthetic, deliberately slow Pi-hole.
Unrelated page requests and agent heartbeats run concurrently through the
shared thread pool, as FastAPI runs them.  The tests prove:

* every Pi-hole call runs in a worker thread, never on the event loop;
* the event loop, heartbeats and pages keep responding while Pi-hole is slow;
* no database connection is held while a Pi-hole call is in progress;
* concurrent requests are bounded and cannot repeat or interleave service
  writes; and
* CSRF failures still stop a request before Pi-hole is contacted.

No network is used: Pi-hole and the UDP DNS probe are synthetic.  All data is
clearly fake.
"""

from __future__ import annotations

import ast
import asyncio
import gc
import json
import struct
import threading
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

from app.core.security import encrypt_secret
from app.db.session import Base, configure_sqlite_connection
from app.main import app
from app.models.models import (
    AuditLog,
    HAMaintenanceRun,
    HAFailoverRun,
    HAHealthCheck,
    HALeaseSnapshot,
    HANode,
    HAProviderConnection,
    HASyncRun,
    User,
)
from app.routers import ha_agent_api
from app.routers import high_availability as router
from app.services import ha_validation
from app.services.dns_providers import DNSProviderResult, PiHoleProvider
from app.services.ha_coordination import cluster_coordination
from app.services.ha_sync import HAStaleSyncPlanError, create_live_sync_plan
from ha_simulation import NODE_ONE_IP, NODE_TWO_IP, VIP, hal_like_cluster, heartbeat_for

SLOW = 0.5  # seconds per synthetic Pi-hole call
# One Pi-hole call run on the event loop shows as a loop gap of at least SLOW.
# Below that, gaps come from thread scheduling (GIL hand-off) while many worker
# threads are busy; measured up to ~0.19 s under the heaviest load here.
# Garbage collection is paused while measuring: a full collection stops every
# thread for a time that grows with the heap (0.1 s alone, ~0.7 s late in a
# full-suite run), which is unrelated to the handlers under test.
GAP_LIMIT = 0.3
RESPONSIVE_LIMIT = SLOW  # heartbeats and pages must never wait for a Pi-hole call
SYNTHETIC_SECRET = "synthetic-app-password-not-real"

HANDLERS = (
    "test_connection",
    "validate",
    "plan",
    "apply",
    "lease_reconcile",
    "dns_repair",
    "failover_start",
)
ROUTE_FUNCTIONS = {
    "test_connection": "test_cluster_connection",
    "validate": "validate_cluster",
    "plan": "plan_cluster_synchronisation",
    "apply": "apply_cluster_synchronisation",
    "lease_reconcile": "reconcile_cluster_dhcp",
    "dns_repair": "repair_cluster_dhcp_dns_advertisement",
    "failover_start": "start_cluster_failover",
}
CURRENT_REQUEST: ContextVar[str | None] = ContextVar("p3_current_request", default=None)
WRITE_METHODS = {"apply_ha_configuration_group", "reconcile_ha_collections", "apply_ha_dhcp_dns_advertisement"}


# --- synthetic Pi-hole ------------------------------------------------------------


@dataclass
class Call:
    method: str
    node: str
    thread: int
    checked_out: int
    started: float
    ended: float = 0.0
    request: str | None = None
    open_request_transactions: int = 0


@dataclass
class FakePiHole:
    """Stateful, slow stand-in for both Pi-hole nodes, keyed by API base URL."""

    engine: object
    delay: float = SLOW
    calls: list[Call] = field(default_factory=list)
    state: dict[str, dict] = field(default_factory=dict)
    lines: dict[str, list[str]] = field(default_factory=dict)
    guard: threading.Lock = field(default_factory=threading.Lock)
    request_sessions: list = field(default_factory=list)

    def call(self, provider: PiHoleProvider, method: str, result: Callable[[str], DNSProviderResult]) -> DNSProviderResult:
        node = provider.config.base_url
        record = Call(method, node, threading.get_ident(), self.engine.pool.checkedout(), time.perf_counter(),
                      request=CURRENT_REQUEST.get())
        time.sleep(self.delay)
        with self.guard:
            value = result(node)
            record.ended = time.perf_counter()
            # Request sessions with an open transaction (each holds a pooled connection).
            record.open_request_transactions = sum(1 for db in list(self.request_sessions) if db.in_transaction())
            self.calls.append(record)
        return value

    def writes(self) -> list[Call]:
        return [call for call in self.calls if call.method in WRITE_METHODS]

    def install(self, monkeypatch) -> None:
        def ok(data=None, message="ok"):
            return lambda node: DNSProviderResult(True, message, data(node) if callable(data) else (data or {}))

        def configuration(node):
            return {"configuration": json.loads(json.dumps(self.state[node])), "unavailable": {}}

        def apply_group(node, key, value):
            self.state[node][key] = value
            return DNSProviderResult(True, "applied", {})

        def apply_lines(node, lines):
            self.lines[node] = list(lines)
            return DNSProviderResult(True, "applied", {})

        methods = {
            "test_connection": lambda self_, *a, **k: self.call(self_, "test_connection", ok(message="Pi-hole connection test passed.")),
            "get_version": lambda self_, *a, **k: self.call(self_, "get_version", ok({"version": {"core": {"local": {"version": "v6.0"}}}})),
            "get_status": lambda self_, *a, **k: self.call(self_, "get_status", ok({"blocking": "enabled"})),
            "get_ha_configuration": lambda self_, *a, **k: self.call(self_, "get_ha_configuration", ok(configuration)),
            "get_dhcp_leases": lambda self_, *a, **k: self.call(self_, "get_dhcp_leases", ok({"leases": []})),
            "get_ha_dhcp_dns_advertisement": lambda self_, *a, **k: self.call(
                self_, "get_ha_dhcp_dns_advertisement", ok(lambda node: {"dnsmasq_lines": list(self.lines[node])})),
            "apply_ha_dhcp_dns_advertisement": lambda self_, lines, *a, **k: self.call(
                self_, "apply_ha_dhcp_dns_advertisement", lambda node: apply_lines(node, lines)),
            "apply_ha_configuration_group": lambda self_, key, value, *a, **k: self.call(
                self_, "apply_ha_configuration_group", lambda node: apply_group(node, key, value)),
            "reconcile_ha_collections": lambda self_, *a, **k: self.call(
                self_, "reconcile_ha_collections", ok(message="reconciled")),
        }
        for name, method in methods.items():
            monkeypatch.setattr(PiHoleProvider, name, method)

        fake = self

        class FakeDNSSocket:  # answers the read-only UDP/53 probe without any network
            def __init__(self, *args):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, value):
                pass

            def sendto(self, payload, address):
                time.sleep(fake.delay / 3)

            def recvfrom(self, size):
                return struct.pack("!H", 0x4B41) + b"\0" * 10, ("192.0.2.1", 53)

        monkeypatch.setattr(ha_validation, "socket", SimpleNamespace(
            SOCK_DGRAM=2, socket=FakeDNSSocket,
            getaddrinfo=lambda host, port, type=None: [(2, 2, 17, "", (host, port))]))


# --- environment ------------------------------------------------------------------


def dhcp_group(active: bool) -> dict:
    return {"config": {"dhcp": {"active": active, "start": "192.0.2.100", "end": "192.0.2.200", "hosts": []}}}


@dataclass
class Env:
    engine: object
    factory: sessionmaker
    sim: object
    pihole: FakePiHole
    cluster_public_id: str
    cluster_name: str
    admin_id: int
    one_id: int
    two_id: int
    two_public_id: str
    sync_run_id: str = ""
    sessions: list = field(default_factory=list)

    def session(self):
        db = self.factory()
        self.sessions.append(db)
        self.pihole.request_sessions.append(db)
        return db

    def close(self):
        for db in self.sessions:
            db.close()

    def request_form(self, name: str, *, csrf: str = "csrf") -> tuple[str, dict]:
        base = f"/high-availability/clusters/{self.cluster_public_id}"
        forms = {
            "test_connection": ("/high-availability/clusters/test-connection", {
                "provider_key": "pihole", "node": "primary", "primary_name": "Draft primary",
                "primary_api_base_url": "https://draft-primary.invalid", "primary_secret": SYNTHETIC_SECRET}),
            "validate": (f"{base}/validate", {}),
            "plan": (f"{base}/synchronisation/plan", {}),
            "apply": (f"{base}/synchronisation/apply", {"sync_run_id": self.sync_run_id, "acknowledge_authority": "1"}),
            "lease_reconcile": (f"{base}/dhcp/reconcile", {}),
            "dns_repair": (f"{base}/dhcp-dns-advertisement/repair", {"acknowledge_reload": "1"}),
            "failover_start": (f"{base}/testing/start", {
                "target_node_id": self.two_public_id, "cluster_name": self.cluster_name, "acknowledge_interruption": "1"}),
        }
        path, values = forms[name]
        return path, {"csrf_token": csrf, **values}

    async def call(self, name: str, *, csrf: str = "csrf"):
        """Invoke the real route coroutine with a fresh request session, as FastAPI does.

        The session is closed when the request ends, as ``get_db`` does.
        """
        path, values = self.request_form(name, csrf=csrf)
        db = self.session()
        try:
            user = await run_in_threadpool(db.get, User, self.admin_id)
            function = getattr(router, ROUTE_FUNCTIONS[name])
            request = form_request(path, values)
            if name == "test_connection":
                return await function(request, db=db, user=user)
            return await function(self.cluster_public_id, request, db=db, user=user)
        finally:
            await run_in_threadpool(db.close)

    def heartbeat_once(self) -> None:
        """The real (synchronous) agent heartbeat route, run in the shared pool as FastAPI does."""
        db = self.factory()
        try:
            node = db.get(HANode, self.two_id)
            ha_agent_api.heartbeat(heartbeat_for(self.sim.sim_two), db=db, agent=SimpleNamespace(node=node))
        finally:
            db.close()

    def page_once(self) -> None:
        """An unrelated page: the real cluster overview."""
        db = self.factory()
        try:
            user = db.get(User, self.admin_id)
            path = f"/high-availability/clusters/{self.cluster_public_id}"
            response = router.cluster_detail(self.cluster_public_id, page_request(path), db=db, user=user)
            assert response.status_code == 200
        finally:
            db.close()


def form_request(path: str, values: dict[str, str]) -> Request:
    body = urlencode(values).encode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({
        "type": "http", "method": "POST", "scheme": "https", "path": path, "raw_path": path.encode(),
        "query_string": b"", "client": ("198.51.100.2", 1234), "server": ("kaya.example.com", 443),
        "headers": [(b"content-type", b"application/x-www-form-urlencoded"), (b"content-length", str(len(body)).encode())],
        "session": {"csrf_token": "csrf"}, "app": app,
    }, receive)


def page_request(path: str) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request({
        "type": "http", "method": "GET", "scheme": "https", "path": path, "raw_path": path.encode(),
        "query_string": b"", "headers": [], "client": ("198.51.100.2", 1234),
        "server": ("kaya.example.com", 443), "session": {"csrf_token": "csrf"}, "app": app,
    }, receive)


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'kaya-p3.db'}", connect_args={"check_same_thread": False, "timeout": 5})
    event.listen(engine, "connect", configure_sqlite_connection)
    Base.metadata.create_all(engine)
    pihole = FakePiHole(engine)
    pihole.install(monkeypatch)

    setup = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    sim = hal_like_cluster(setup, maintenance_mode=False, suffix="p3")
    for node in (sim.one, sim.two):
        connection = HAProviderConnection(provider_key="pihole", name=f"{node.display_name} synthetic", api_base_url=node.api_base_url,
                                          encrypted_secret=encrypt_secret(SYNTHETIC_SECRET), ssl_verify=False, timeout_seconds=10)
        setup.add(connection)
        setup.flush()
        node.ha_connection_id = connection.id
        active = node.id == sim.one.id
        pihole.state[node.api_base_url] = {
            "local_dns": {"config": {"dns": {"hosts": ["one.example.test,192.0.2.50"] if active else []}}},
            "dhcp": dhcp_group(active),
        }
        pihole.lines[node.api_base_url] = ["log-queries=extra"]
        node.configuration_snapshot_json = json.dumps(pihole.state[node.api_base_url], sort_keys=True)
    pihole.state["https://draft-primary.invalid"] = {}
    setup.commit()
    sim.report_both(2)
    environment = Env(engine, sessionmaker(bind=engine, autoflush=False), sim, pihole, sim.cluster.public_id, sim.cluster.name,
                      sim.admin.id, sim.one.id, sim.two.id, sim.two.public_id)
    # A reviewed plan for the apply handler, made with Pi-hole fast.
    pihole.delay = 0
    plan_db = environment.session()
    run = create_live_sync_plan(plan_db, plan_db.get(type(sim.cluster), sim.cluster.id), plan_db.get(User, sim.admin.id))
    assert run.status == "PLANNED", run.plan_json
    environment.sync_run_id = run.public_id
    plan_db.close()
    setup.close()
    pihole.calls.clear()
    pihole.delay = SLOW
    try:
        yield environment
    finally:
        environment.close()
        engine.dispose()


async def under_load(env: Env, coroutine) -> dict:
    """Run ``coroutine`` while measuring loop gaps, heartbeat and page latency."""
    gaps: list[float] = []
    heartbeats: list[float] = []
    pages: list[float] = []
    done = asyncio.Event()

    async def ticker():
        last = time.perf_counter()
        while not done.is_set():
            await asyncio.sleep(0.01)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    async def repeat(operation, samples):
        while not done.is_set():
            started = time.perf_counter()
            await run_in_threadpool(operation)
            samples.append(time.perf_counter() - started)
            await asyncio.sleep(0.05)

    gc.collect()
    collecting = gc.isenabled()
    gc.disable()
    tasks = [asyncio.create_task(ticker()), asyncio.create_task(repeat(env.heartbeat_once, heartbeats)),
             asyncio.create_task(repeat(env.page_once, pages))]
    await asyncio.sleep(0.05)
    started = time.perf_counter()
    try:
        result = await coroutine
    finally:
        elapsed = time.perf_counter() - started
        done.set()
        await asyncio.gather(*tasks)
        if collecting:
            gc.enable()
    return {"result": result, "elapsed": elapsed, "gap": max(gaps), "heartbeats": heartbeats, "pages": pages}


# --- static: every handler is addressed, not moved elsewhere -----------------------


PIHOLE_ENTRY_POINTS = {
    "test_draft_node_connection", "run_live_validation", "create_live_sync_plan", "execute_sync",
    "reconcile_cluster_leases", "inspect_lease_plan", "repair_dns_advertisement", "start_controlled_failover",
}


def test_no_async_ha_handler_calls_pihole_work_directly():
    """Every Pi-hole entry point is reached only from synchronous worker functions."""
    tree = ast.parse(Path("app/routers/high_availability.py").read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            called = {item.func.id for item in ast.walk(node) if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)}
            if called & PIHOLE_ENTRY_POINTS:
                offenders.append(node.name)
    assert offenders == []
    handlers = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef)}
    for name in ROUTE_FUNCTIONS.values():
        names = {item.id for item in ast.walk(handlers[name]) if isinstance(item, ast.Name)}
        assert "run_provider_operation" in names, name


# --- runtime: the event loop, heartbeats and pages stay responsive ---------------------


EXPECTED_STATUS = {
    "test_connection": 200,
    "validate": 303,
    "plan": 303,
    "apply": 303,
    "lease_reconcile": 303,
    "dns_repair": 303,
    "failover_start": 303,
}


@pytest.mark.parametrize("name", HANDLERS)
def test_slow_pihole_does_not_stall_event_loop_heartbeats_or_pages(env, name):
    loop_thread = {}

    async def scenario():
        loop_thread["id"] = threading.get_ident()
        return await under_load(env, env.call(name))

    measured = asyncio.run(scenario())
    response = measured["result"]
    calls = env.pihole.calls
    print(f"\nP3-OFFLOAD {name}: status={response.status_code} pihole_calls={len(calls)} elapsed={measured['elapsed']:.2f}s "
          f"loop_gap_max={measured['gap'] * 1000:.0f}ms heartbeat_max={max(measured['heartbeats']) * 1000:.0f}ms "
          f"page_max={max(measured['pages']) * 1000:.0f}ms heartbeats={len(measured['heartbeats'])} pages={len(measured['pages'])}")
    assert response.status_code == EXPECTED_STATUS[name], getattr(response, "body", b"")[:400]
    assert calls, "the slow Pi-hole path must be exercised"
    assert measured["elapsed"] >= SLOW
    assert all(call.thread != loop_thread["id"] for call in calls)
    assert measured["gap"] < GAP_LIMIT
    assert len(measured["heartbeats"]) >= 2 and max(measured["heartbeats"]) < RESPONSIVE_LIMIT
    assert len(measured["pages"]) >= 1 and max(measured["pages"]) < RESPONSIVE_LIMIT * 2


def test_the_harness_detects_the_previous_inline_behaviour(env):
    """Control: the same validation work run inline on the loop (the pre-change handler shape) stalls it."""
    async def inline():
        db = env.session()
        path, _ = env.request_form("validate")
        return router._validate_cluster_work(form_request(path, {}), db, db.get(User, env.admin_id), env.cluster_public_id)

    measured = asyncio.run(under_load(env, inline()))
    assert measured["gap"] >= SLOW * 0.8


@pytest.mark.parametrize("name", HANDLERS)
def test_no_database_connection_is_held_during_pihole_calls(env, name):
    async def scenario():
        return await env.call(name)

    response = asyncio.run(scenario())
    assert response.status_code == EXPECTED_STATUS[name]
    assert env.pihole.calls
    held = [(call.method, call.checked_out) for call in env.pihole.calls if call.checked_out]
    assert held == [], held


# --- bounded concurrency ---------------------------------------------------------


def test_concurrent_requests_are_bounded_and_queue_without_threads_or_connections(env):
    async def scenario():
        requests = [env.call("test_connection") for _ in range(router.HA_PROVIDER_OPERATION_LIMIT * 3)]
        return await under_load(env, asyncio.gather(*requests))

    measured = asyncio.run(scenario())
    assert all(response.status_code == 200 for response in measured["result"])
    calls = sorted(env.pihole.calls, key=lambda call: call.started)
    peak = max(sum(1 for other in calls if other.started <= call.started < other.ended) for call in calls)
    print(f"\nP3-BOUNDED requests={len(calls)} peak_concurrent_pihole={peak} elapsed={measured['elapsed']:.2f}s "
          f"heartbeat_max={max(measured['heartbeats']) * 1000:.0f}ms loop_gap_max={measured['gap'] * 1000:.0f}ms")
    # Queued requests released their transaction before waiting: at most the
    # running requests (never the queued ones) can be in a database phase.
    open_transactions = max(call.open_request_transactions for call in calls)
    print(f"P3-BOUNDED max_open_request_transactions={open_transactions} of {len(measured['result'])} requests")
    assert peak <= router.HA_PROVIDER_OPERATION_LIMIT
    assert open_transactions <= router.HA_PROVIDER_OPERATION_LIMIT
    assert measured["gap"] < GAP_LIMIT
    assert max(measured["heartbeats"]) < RESPONSIVE_LIMIT


# --- no repeated or interleaved service writes under concurrency ---------------------


def run_concurrently(env: Env, name: str, count: int) -> list:
    async def one(index: int):
        CURRENT_REQUEST.set(f"{name}-{index}")
        try:
            return await env.call(name)
        except HTTPException as exc:
            return exc

    async def scenario():
        return await asyncio.gather(*(one(index) for index in range(count)))

    return asyncio.run(scenario())


def status(item) -> int:
    return item.status_code


def test_concurrent_applies_of_one_plan_write_to_pihole_once(env):
    results = run_concurrently(env, "apply", 4)
    statuses = sorted(status(item) for item in results)
    writes = [(call.node, call.method) for call in env.pihole.writes()]
    assert statuses.count(303) == 1, statuses
    assert writes == [("https://simpihole2.invalid", "apply_ha_configuration_group")], writes
    db = env.session()
    assert db.query(HASyncRun).filter(HASyncRun.public_id == env.sync_run_id).one().status == "SUCCEEDED"


def test_concurrent_dns_advertisement_repairs_never_interleave_pihole_writes(env):
    results = run_concurrently(env, "dns_repair", 3)
    assert 303 in [status(item) for item in results]
    windows: dict[str, list[float]] = {}
    for call in env.pihole.calls:
        window = windows.setdefault(call.request, [call.started, call.ended])
        window[0], window[1] = min(window[0], call.started), max(window[1], call.ended)
    ordered = sorted(windows.values())
    assert all(earlier[1] <= later[0] for earlier, later in zip(ordered, ordered[1:])), ordered
    assert env.pihole.lines["https://simpihole1.invalid"] == ["log-queries=extra", f"dhcp-option=6,{VIP},{NODE_TWO_IP}"]
    assert env.pihole.lines["https://simpihole2.invalid"] == ["log-queries=extra", f"dhcp-option=6,{VIP},{NODE_ONE_IP}"]


def test_concurrent_failover_starts_create_one_operation(env):
    results = run_concurrently(env, "failover_start", 3)
    db = env.session()
    runs = db.query(HAFailoverRun).count()
    assert runs == 1, [status(item) for item in results]
    assert sorted(status(item) for item in results).count(303) == 1


def test_concurrent_lease_reconciliations_queue_one_snapshot(env):
    db = env.session()
    before = db.query(HALeaseSnapshot).count()
    results = run_concurrently(env, "lease_reconcile", 3)
    assert all(status(item) in {303, 409} for item in results)
    assert db.query(HALeaseSnapshot).count() - before == 1


def test_concurrent_validations_run_once(env):
    results = run_concurrently(env, "validate", 3)
    statuses = sorted(status(item) for item in results)
    assert statuses == [303, 409, 409], statuses
    assert len({call.request for call in env.pihole.calls}) == 1
    db = env.session()
    checks = db.query(HAHealthCheck).filter(HAHealthCheck.node_id.isnot(None)).count()
    assert checks and checks == len({(row.node_id, row.check_key) for row in db.query(HAHealthCheck).all() if row.node_id})


# --- authorisation and CSRF are unchanged ---------------------------------------------


@pytest.mark.parametrize("name", HANDLERS)
def test_invalid_csrf_is_rejected_before_any_pihole_call(env, name):
    async def scenario():
        return await env.call(name, csrf="forged-token")

    with pytest.raises(HTTPException) as raised:
        asyncio.run(scenario())
    assert raised.value.status_code == 400
    assert env.pihole.calls == []


ROLE_DEPENDENCY = {
    "test_connection": "require_ha_admin",
    "validate": "require_ha_editor",
    "plan": "require_ha_editor",
    "apply": "require_ha_admin",
    "lease_reconcile": "require_ha_admin",
    "dns_repair": "require_ha_admin",
    "failover_start": "require_ha_admin",
}


@pytest.mark.parametrize("name", HANDLERS)
def test_role_and_module_dependencies_are_unchanged(name):
    route = next(item for item in router.router.routes if getattr(item, "endpoint", None) is getattr(router, ROUTE_FUNCTIONS[name]))
    assert route.methods == {"POST"}
    dependencies = {dependency.call.__name__ for dependency in route.dependant.dependencies if dependency.call}
    assert ROLE_DEPENDENCY[name] in dependencies
    assert "get_db" in dependencies
    assert any(getattr(item.dependency, "__name__", "") == "dependency" for item in router.router.dependencies)


# --- P3 close-out: stale-plan error path ---------------------------------------------


def test_stale_plan_error_path_audits_the_cluster_and_refreshes_the_plan(env, monkeypatch):
    """Regression: this path referred to a plan variable that is not set when planning fails."""
    real = router.create_live_sync_plan
    attempts = []

    def stale_then_real(db, cluster, user, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise HAStaleSyncPlanError(["local_dns"])
        return real(db, cluster, user, **kwargs)

    monkeypatch.setattr(router, "create_live_sync_plan", stale_then_real)
    env.pihole.delay = 0
    response = asyncio.run(env.call("plan"))
    assert response.status_code == 200
    assert b"A fresh plan is ready below" in response.body
    db = env.session()
    stale = db.query(AuditLog).filter_by(entity="ha_configuration_sync", action="stale").one()
    assert stale.entity_id == env.cluster_public_id
    assert db.query(AuditLog).filter_by(entity="ha_configuration_sync", action="planned").count() == 1


def test_stale_plan_with_failed_refresh_reports_both_errors(env, monkeypatch):
    def always_stale(db, cluster, user, **kwargs):
        raise HAStaleSyncPlanError(["local_dns"])

    monkeypatch.setattr(router, "create_live_sync_plan", always_stale)
    response = asyncio.run(env.call("plan"))
    assert response.status_code == 409
    assert b"could not create a replacement plan" in response.body


# --- P3 close-out: busy (409) responses explain and never retry -----------------------


class HeldLock:
    """Hold the cluster's coordination lock from another thread, as a running operation would."""

    def __init__(self, env: Env, operation: str):
        self.env, self.operation = env, operation
        self.ready, self.release = threading.Event(), threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        db = self.env.factory()
        try:
            with cluster_coordination(db, self.env.sim.cluster.id, operation=self.operation) as acquired:
                assert acquired
                self.ready.set()
                self.release.wait(10)
        finally:
            db.close()

    def __enter__(self):
        self.thread.start()
        assert self.ready.wait(5)
        return self

    def __exit__(self, *args):
        self.release.set()
        self.thread.join(5)


def busy_body(exc: HTTPException) -> str:
    assert isinstance(exc, router.HAClusterBusy) and exc.status_code == 409
    return exc.response.body.decode()


def assert_safe_busy_page(body: str, cluster_public_id: str, refresh_suffix: str) -> None:
    section = body[body.index('data-ha-busy='):body.index("</section>", body.index('data-ha-busy='))]
    assert "Another operation is running on this cluster" in section
    assert "nothing was changed" in section and "does not repeat it automatically" in section
    assert f'href="/high-availability/clusters/{cluster_public_id}{refresh_suffix}"' in section
    assert "<form" not in section  # a refresh link (GET) only; never a resubmission
    assert 'http-equiv="refresh"' not in body.lower()


@pytest.mark.parametrize(("name", "suffix", "writes_pihole"), [
    ("apply", "/synchronisation", True),
    ("dns_repair", "", True),
    ("lease_reconcile", "/dhcp", False),
    ("failover_start", "/testing", False),
])
def test_busy_cluster_returns_an_explanatory_409_and_changes_nothing(env, monkeypatch, name, suffix, writes_pihole):
    monkeypatch.setattr(router, "HA_PROVIDER_COORDINATION_WAIT_SECONDS", 0.2)
    env.pihole.delay = 0
    with HeldLock(env, "advance_failover"):
        with pytest.raises(HTTPException) as raised:
            asyncio.run(env.call(name))
    body = busy_body(raised.value)
    assert 'data-ha-busy="advance_failover"' in body
    assert "Kaya is advancing a controlled failover or failback" in body
    assert_safe_busy_page(body, env.cluster_public_id, suffix)
    assert env.pihole.writes() == []
    db = env.session()
    assert db.query(HAFailoverRun).count() == 0
    if name == "apply":
        assert db.query(HASyncRun).filter(HASyncRun.public_id == env.sync_run_id).one().status == "PLANNED"


def test_duplicate_validation_busy_page_names_the_running_operation(env):
    with router.single_flight("validation", env.sim.cluster.id):
        with pytest.raises(HTTPException) as raised:
            asyncio.run(env.call("validate"))
    body = busy_body(raised.value)
    assert "A live validation of this cluster is running" in body
    assert_safe_busy_page(body, env.cluster_public_id, "/validation")
    assert env.pihole.calls == []


def test_maintenance_in_progress_busy_page_links_to_maintenance(env):
    db = env.session()
    db.add(HAMaintenanceRun(cluster_id=env.sim.cluster.id, operation="REINITIALISE", status="RUNNING", phase="PREPARING",
                            previous_state_json="{}", result_json="{}", requested_by_user_id=env.admin_id))
    db.commit()
    with pytest.raises(HTTPException) as raised:
        asyncio.run(env.call("plan"))
    body = busy_body(raised.value)
    assert 'data-ha-busy="maintenance"' in body and "Cluster maintenance (reinitialise) is in progress" in body
    assert f'href="/high-availability/clusters/{env.cluster_public_id}/maintenance"' in body
    assert_safe_busy_page(body, env.cluster_public_id, "/synchronisation")
    assert env.pihole.calls == []


def test_application_returns_the_rendered_busy_page():
    from app.main import ha_cluster_busy_handler

    marker = object()
    exc = router.HAClusterBusy(marker, "busy")
    assert app.exception_handlers[router.HAClusterBusy] is ha_cluster_busy_handler
    assert asyncio.run(ha_cluster_busy_handler(page_request("/"), exc)) is marker
