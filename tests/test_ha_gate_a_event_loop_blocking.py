"""Gate A: event-loop blocking by synchronous HA work inside ``async def`` paths.

Each test runs the real coroutine next to a 10 ms ticker on one event loop.
Synchronous work that the coroutine performs without yielding shows up as a
ticker gap.  The slow dependency is a synthetic ``time.sleep`` standing in for
Pi-hole HTTP calls or a database pool wait; no network or database is used.

The AST inventory is an analysis aid: it lists ``async def`` handlers that use
a synchronous SQLAlchemy session and never hand work to a thread.
"""

from __future__ import annotations

import ast
import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

from fastapi import HTTPException

BLOCK_SECONDS = 0.4
ALLOWED_GAP_SECONDS = 0.15
HA_SOURCES = ("app/routers/high_availability.py", "app/routers/ha_agent_api.py", "app/services/ha_agents.py")


async def max_loop_gap(coroutine) -> float:
    gaps: list[float] = []
    done = asyncio.Event()

    async def ticker():
        last = time.perf_counter()
        while not done.is_set():
            await asyncio.sleep(0.01)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    task = asyncio.create_task(ticker())
    await asyncio.sleep(0.03)
    try:
        await coroutine
    except HTTPException:
        pass
    finally:
        done.set()
        await task
    return max(gaps)


def blocking_async_handlers() -> list[str]:
    found = []
    for source in HA_SOURCES:
        tree = ast.parse(Path(source).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            names = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
            attributes = {item.attr for item in ast.walk(node) if isinstance(item, ast.Attribute)}
            uses_session = "db" in names
            offloads = bool({"run_in_threadpool", "to_thread", "run_sync", "run_provider_operation"} & (names | attributes))
            if uses_session and not offloads:
                found.append(f"{source}:{node.lineno}:{node.name}")
    return found


def test_inventory_records_current_blocking_async_handlers():
    """Analysis baseline (not a pass/fail judgement of each handler).

    Gate A found 28 async handlers using a synchronous session without
    offloading.  P2B moved the D15/D16 paths (maintenance advance and agent
    authentication) to the thread pool, and the next phase moved the seven
    handlers that call Pi-hole; none of them may reappear.  require_agent
    is still listed by this static heuristic because it passes ``db`` to an
    awaitable that does the offloading itself.
    """
    found = blocking_async_handlers()
    names = {item.rsplit(":", 1)[1] for item in found}
    assert not {"advance_cluster_maintenance", "_authenticate_agent_request"} & names
    assert not {
        "test_cluster_connection", "validate_cluster", "plan_cluster_synchronisation",
        "apply_cluster_synchronisation", "reconcile_cluster_dhcp",
        "repair_cluster_dhcp_dns_advertisement", "start_cluster_failover",
    } & names
    assert len(found) < 28
    print(f"\nGATE-A async handlers using a sync session without offload: {len(found)}")
    for item in found:
        print("  ", item)


def test_ticker_harness_detects_a_blocking_call():
    async def blocking():
        time.sleep(BLOCK_SECONDS)

    assert asyncio.run(max_loop_gap(blocking())) >= BLOCK_SECONDS * 0.8


def test_ticker_harness_accepts_offloaded_work():
    async def offloaded():
        await asyncio.to_thread(time.sleep, BLOCK_SECONDS)

    assert asyncio.run(max_loop_gap(offloaded())) < ALLOWED_GAP_SECONDS


def test_d15_maintenance_advance_handler_does_not_block_event_loop(monkeypatch):
    """Fixed in P2B: the route signals the coordinator and waits in the thread pool."""
    from app.routers import high_availability as router

    run = SimpleNamespace(operation="REINITIALISE", status="RUNNING")
    cluster = SimpleNamespace(id=1, public_id="synthetic-cluster")

    class Query:
        def filter(self, *args):
            return self

        def first(self):
            return run

    monkeypatch.setattr(router, "cluster_or_404", lambda db, public_id: cluster)
    monkeypatch.setattr(router, "validate_csrf_token", lambda request, token: None)
    monkeypatch.setattr(router.ha_evaluation_queue, "request_and_wait", lambda cluster_id, timeout: time.sleep(BLOCK_SECONDS))

    async def form():
        return {"csrf_token": "synthetic"}

    request = SimpleNamespace(form=form)
    db = SimpleNamespace(query=lambda model: Query())
    coroutine = router.advance_cluster_maintenance("synthetic-cluster", "synthetic-run", request, db=db, user=None)
    assert asyncio.run(max_loop_gap(coroutine)) < ALLOWED_GAP_SECONDS


def test_d16_agent_authentication_does_not_block_event_loop():
    """Fixed in P2B: identity, replay and rate checks run in the thread pool."""
    from app.services.ha_agents import AGENT_PROTOCOL_VERSION, _authenticate_agent_request

    class Query:
        def filter(self, *args):
            return self

        def first(self):
            time.sleep(BLOCK_SECONDS)  # stands in for a pool_timeout wait
            return None

    headers = {
        "x-kaya-agent-id": "synthetic-agent",
        "x-kaya-agent-timestamp": str(int(time.time())),
        "x-kaya-agent-request-id": "synthetic-request-0001",
        "x-kaya-agent-signature": "c3ludGhldGlj",
        "x-kaya-agent-protocol": str(AGENT_PROTOCOL_VERSION),
    }
    request = SimpleNamespace(headers=headers)
    db = SimpleNamespace(query=lambda *args: Query())
    assert asyncio.run(max_loop_gap(_authenticate_agent_request(request, db))) < ALLOWED_GAP_SECONDS
