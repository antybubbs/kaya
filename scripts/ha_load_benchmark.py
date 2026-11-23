"""Repeatable HA load benchmark (synthetic data, disposable PostgreSQL only).

Drives the real agent API router over ASGI with Ed25519-signed heartbeats from
several two-node clusters, alongside the HA watchdog/coordinator, simulated
maintenance with slow synthetic Pi-hole calls, and a lightweight "site" request
standing in for page loads.  Measures, per phase:
  * heartbeat latency (p50/p95/max) and site request latency,
  * SQL statements by workload (heartbeat request, site, background),
  * watchdog/coordinator pass count and duration,
  * connection-pool occupancy and saturation,
  * event-loop lag (a 10 ms ticker).
Works against both the pre-P2B and P2B trees.  Never contacts a network host.

Usage (inside the test container):  python scripts/ha_load_benchmark.py --url "$KAYA_TEST_POSTGRES_URL"
Creates and drops its own schema; refuses any non-local database.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextvars
import functools
import hashlib
import json
import sys
import threading
import time
from uuid import uuid4

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from fastapi import Depends, FastAPI, Request  # noqa: E402
from sqlalchemy import create_engine, event, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.session import Base, get_db  # noqa: E402
from app.models.models import HACluster, HAAgentCredential, RemoteManagerSetting  # noqa: E402
from app.routers import ha_agent_api  # noqa: E402
from app.services import ha_maintenance, ha_watchdog  # noqa: E402
from app.services.ha_maintenance import start_reinitialisation  # noqa: E402
from ha_simulation import hal_like_cluster, heartbeat_for  # noqa: E402

WORKLOAD = contextvars.ContextVar("workload", default="background")
PHASES = ("steady", "mismatch", "maintenance")


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.statements: dict[str, int] = {}
            self.heartbeat_ms: list[float] = []
            self.ping_ms: list[float] = []
            self.lag_ms: list[float] = []
            self.passes: list[float] = []
            self.pool_samples: list[int] = []
            self.errors: dict[str, int] = {}

    def statement(self):
        key = WORKLOAD.get()
        with self.lock:
            self.statements[key] = self.statements.get(key, 0) + 1

    def error(self, kind: str):
        with self.lock:
            self.errors[kind] = self.errors.get(kind, 0) + 1


def pct(values, p):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))], 1)


def summary(metrics: Metrics, pool_limit: int, duration: float) -> dict:
    heartbeats = len(metrics.heartbeat_ms)
    statements = dict(metrics.statements)
    total = sum(statements.values())
    return {
        "heartbeats": heartbeats,
        "heartbeat_ms": {"p50": pct(metrics.heartbeat_ms, 50), "p95": pct(metrics.heartbeat_ms, 95), "max": pct(metrics.heartbeat_ms, 100)},
        "site_ms": {"p50": pct(metrics.ping_ms, 50), "p95": pct(metrics.ping_ms, 95), "max": pct(metrics.ping_ms, 100)},
        "event_loop_lag_ms": {"p95": pct(metrics.lag_ms, 95), "max": pct(metrics.lag_ms, 100)},
        "statements": statements,
        "statements_per_heartbeat_request": round(statements.get("heartbeat", 0) / heartbeats, 1) if heartbeats else None,
        "background_statements_per_second": round(statements.get("background", 0) / duration, 1),
        "total_statements_excluding_site_per_heartbeat": round((total - statements.get("site", 0)) / heartbeats, 1) if heartbeats else None,
        "coordinator_passes": len(metrics.passes),
        "coordinator_pass_ms": {"p50": pct(metrics.passes, 50), "p95": pct(metrics.passes, 95), "max": pct(metrics.passes, 100)},
        "coordinator_busy_fraction": round(sum(metrics.passes) / 1000 / duration, 3),
        "pool_checked_out": {"p95": pct(metrics.pool_samples, 95), "max": max(metrics.pool_samples or [0]), "limit": pool_limit,
                             "saturated_fraction": round(sum(1 for v in metrics.pool_samples if v >= pool_limit) / max(1, len(metrics.pool_samples)), 3)},
        "errors": dict(metrics.errors),
    }


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--clusters", type=int, default=4)
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between heartbeats per node (compressed from 15 s)")
    parser.add_argument("--phase-seconds", type=float, default=20.0)
    parser.add_argument("--pihole-latency", type=float, default=0.3)
    args = parser.parse_args()
    from sqlalchemy.engine import make_url

    target = make_url(args.url)
    # Disposable local test databases only (same rule as kaya_test_migrations.py);
    # the URL itself is never printed.
    if target.get_backend_name() != "postgresql" or target.host not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("ha_load_benchmark: refusing a non-local or non-PostgreSQL database; use a disposable local test database.")

    schema = f"kaya_bench_{uuid4().hex[:10]}"
    admin = create_engine(args.url)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(args.url, connect_args={"options": f"-c search_path={schema}"}, pool_size=5, max_overflow=5, pool_timeout=10)
    pool_limit = 10
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    metrics = Metrics()
    event.listen(engine, "before_cursor_execute", lambda *a, **k: metrics.statement())

    # --- synthetic clusters with real Ed25519 agent identities --------------------
    db = factory(expire_on_commit=False)
    db.add(RemoteManagerSetting(key="high_availability_enabled", value="1"))
    db.commit()
    agents = []
    for index in range(args.clusters):
        sim = hal_like_cluster(db, maintenance_mode=False, suffix=f"bench{index}-{uuid4().hex[:6]}")
        sim.cluster.virtual_ip = f"192.0.2.{100 + index}"  # the VIP must be unique per active cluster
        db.commit()
        sim.report_both(2)
        for node, sim_node in ((sim.one, sim.sim_one), (sim.two, sim.sim_two)):
            key = Ed25519PrivateKey.generate()
            credential = db.query(HAAgentCredential).filter(HAAgentCredential.node_id == node.id).one()
            credential.public_key = b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            agents.append({"agent_id": credential.agent_id, "key": key, "sim": sim_node, "cluster": index})
        sim.cluster_index = index
        agents[-1]["simcluster"] = agents[-2]["simcluster"] = sim
    db.commit()
    cluster_ids = [agent["simcluster"].cluster.id for agent in agents[::2]]
    db.close()

    # --- application under test --------------------------------------------------
    def bench_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()

    @app.middleware("http")
    async def tag(request: Request, call_next):
        token = WORKLOAD.set("heartbeat" if request.url.path.endswith("/heartbeat") else "site" if request.url.path.startswith("/bench/ping") else "other")
        try:
            return await call_next(request)
        finally:
            WORKLOAD.reset(token)

    app.include_router(ha_agent_api.router)
    app.dependency_overrides[get_db] = bench_db

    @app.get("/bench/ping")
    def ping(session=Depends(bench_db)):
        session.execute(text("SELECT 1"))
        return {"clusters": session.query(HACluster).count()}

    # --- coordinator / watchdog with the bench session factory -------------------
    def timed(fn):
        @functools.wraps(fn)
        def inner(*a, **k):
            started = time.perf_counter()
            try:
                return fn(*a, **k)
            finally:
                with metrics.lock:
                    metrics.passes.append((time.perf_counter() - started) * 1000)
        return inner

    ha_watchdog.STARTUP_DELAY_SECONDS = 0
    if hasattr(ha_watchdog, "ha_coordinator_loop"):  # P2B
        ha_watchdog.evaluate_signalled = timed(ha_watchdog.evaluate_signalled)
        ha_watchdog.run_ha_watchdog_pass = timed(ha_watchdog.run_ha_watchdog_pass)
        coordinator = asyncio.create_task(ha_watchdog.ha_coordinator_loop(session_factory=factory))
        mode = "p2b-coordinator"
    else:
        ha_watchdog.run_ha_watchdog_pass = timed(functools.partial(ha_watchdog.run_ha_watchdog_pass, session_factory=factory))
        coordinator = asyncio.create_task(ha_watchdog.ha_watchdog_loop())
        mode = "pre-p2b-inline"

    # Synthetic slow Pi-hole for maintenance backups; nothing leaves the process.
    def slow_live_configuration(node):
        time.sleep(args.pihole_latency)
        return None, {"dns": {"upstreams": ["192.0.2.53"]}}

    ha_maintenance._live_configuration = slow_live_configuration

    stop = asyncio.Event()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://kaya.invalid")

    async def ticker():
        while not stop.is_set():
            started = time.perf_counter()
            await asyncio.sleep(0.01)
            with metrics.lock:
                metrics.lag_ms.append(max(0.0, (time.perf_counter() - started) * 1000 - 10))

    async def pool_sampler():
        while not stop.is_set():
            with metrics.lock:
                metrics.pool_samples.append(engine.pool.checkedout())
            await asyncio.sleep(0.01)

    async def agent_loop(agent, offset):
        await asyncio.sleep(offset)
        while not stop.is_set():
            payload = heartbeat_for(agent["sim"]).model_dump(mode="json")
            body = json.dumps(payload, separators=(",", ":")).encode()
            path = "/api/ha/agent/v1/heartbeat"
            request_id = uuid4().hex
            stamp = str(int(time.time()))
            canonical = "\n".join(("POST", path, request_id, stamp, hashlib.sha256(body).hexdigest())).encode()
            headers = {"content-type": "application/json", "x-kaya-agent-id": agent["agent_id"], "x-kaya-agent-timestamp": stamp,
                       "x-kaya-agent-request-id": request_id, "x-kaya-agent-signature": b64(agent["key"].sign(canonical)),
                       "x-kaya-agent-protocol": "1"}
            started = time.perf_counter()
            try:
                response = await client.post(path, content=body, headers=headers)
                if response.status_code != 200:
                    metrics.error(f"heartbeat_{response.status_code}")
            except Exception as exc:  # noqa: BLE001
                metrics.error(type(exc).__name__)
            with metrics.lock:
                metrics.heartbeat_ms.append((time.perf_counter() - started) * 1000)
            await asyncio.sleep(args.interval)

    async def site_loop():
        while not stop.is_set():
            started = time.perf_counter()
            try:
                response = await client.get("/bench/ping")
                if response.status_code != 200:
                    metrics.error(f"site_{response.status_code}")
            except Exception as exc:  # noqa: BLE001
                metrics.error(type(exc).__name__)
            with metrics.lock:
                metrics.ping_ms.append((time.perf_counter() - started) * 1000)
            await asyncio.sleep(0.05)

    def set_split(simcluster, split: bool):
        simcluster.vrrp.stop("SimPiHole1") if split else simcluster.vrrp.stop("SimPiHole2")
        simcluster.vrrp.start("SimPiHole1") if split else simcluster.vrrp.start("SimPiHole2")

    def start_maintenance(cluster_id):
        session = factory()
        try:
            cluster = session.get(HACluster, cluster_id)
            if any(run.status == "RUNNING" for run in cluster.maintenance_runs):
                return
            nodes = sorted(cluster.nodes, key=lambda node: node.id)
            start_reinitialisation(session, cluster, _admin(session), desired_active=nodes[0], authority=nodes[0], acknowledged=True)
        except Exception as exc:  # noqa: BLE001
            metrics.error("maintenance_start_" + type(exc).__name__)
        finally:
            session.close()

    def _admin(session):
        from app.models.models import User
        return session.query(User).filter(User.role == "admin").first()

    tasks = [asyncio.create_task(ticker()), asyncio.create_task(pool_sampler()), asyncio.create_task(site_loop())]
    tasks += [asyncio.create_task(agent_loop(agent, index * args.interval / len(agents))) for index, agent in enumerate(agents)]
    results = {"mode": mode, "clusters": args.clusters, "nodes": len(agents), "heartbeat_interval_s": args.interval, "phase_seconds": args.phase_seconds}
    await asyncio.sleep(3)  # warm-up
    for phase in PHASES:
        if phase == "mismatch":
            for agent in agents[::2][: max(1, args.clusters // 2)]:
                set_split(agent["simcluster"], True)
        if phase == "maintenance":
            # Cluster 0 stays split so each REINITIALISE runs backups (slow synthetic
            # Pi-hole reads) and then fails safe at lease staging; the rest recover.
            for agent in agents[2::2][: max(0, args.clusters // 2 - 1)]:
                set_split(agent["simcluster"], False)
        metrics.reset()
        started = time.perf_counter()
        deadline = started + args.phase_seconds
        while time.perf_counter() < deadline:
            if phase == "maintenance":
                await asyncio.to_thread(start_maintenance, cluster_ids[0])
            await asyncio.sleep(2)
        results[phase] = summary(metrics, pool_limit, time.perf_counter() - started)
        try:
            from app.services import ha_evaluation_queue
            counters = ha_evaluation_queue.counters()
            results[phase]["coordinator_waits"] = counters["waits"] - getattr(main, "_waits", 0)
            results[phase]["coordinator_wait_timeouts"] = counters["wait_timeouts"] - getattr(main, "_timeouts", 0)
            main._waits, main._timeouts = counters["waits"], counters["wait_timeouts"]
        except ImportError:
            pass
    stop.set()
    for task in tasks:
        task.cancel()
    coordinator.cancel()
    await asyncio.gather(*tasks, coordinator, return_exceptions=True)
    await client.aclose()
    engine.dispose()
    with admin.begin() as connection:
        connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    admin.dispose()
    print("HA-LOAD-BENCHMARK " + json.dumps(results, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
