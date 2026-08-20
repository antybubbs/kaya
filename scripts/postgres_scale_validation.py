"""Generate and measure a deterministic, disposable PostgreSQL Kaya workload."""

from __future__ import annotations

import argparse
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


def _sqlalchemy_url(database_url: str) -> str:
    return make_url(database_url).set(drivername="postgresql").render_as_string(
        hide_password=False
    )


def _timed(connection, statement: str) -> tuple[float, list]:
    started = time.perf_counter()
    rows = connection.execute(text(statement)).mappings().all()
    return time.perf_counter() - started, rows


def _insert_seed_data(connection, clients: int) -> tuple[int, int, int]:
    connection.execute(text("DELETE FROM audit_logs WHERE action LIKE 'scale.%'"))
    connection.execute(text("DELETE FROM app_sessions WHERE session_id LIKE 'scale-%'"))
    connection.execute(text("DELETE FROM dns_client_traffic_events"))
    connection.execute(text("DELETE FROM dns_recognised_devices"))
    connection.execute(text("DELETE FROM dns_providers"))
    provider_id = connection.execute(
        text(
            "INSERT INTO dns_providers "
            "(name, provider_type, base_url, auth_method, ssl_verify, timeout_seconds, is_enabled, created_at, updated_at) "
            "VALUES ('Scale Test DNS', 'pihole', 'https://dns.invalid', 'password', TRUE, 10, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id"
        )
    ).scalar_one()
    user_id = connection.execute(
        text(
            "INSERT INTO users (email, role, is_active, totp_enabled, authentication_type, is_break_glass, role_source, created_at, updated_at) "
            "VALUES ('scale-user@example.invalid', 'viewer', TRUE, FALSE, 'local', FALSE, 'local', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
            "ON CONFLICT (email) DO UPDATE SET updated_at = EXCLUDED.updated_at RETURNING id"
        )
    ).scalar_one()
    connection.execute(
        text(
            "INSERT INTO dns_recognised_devices "
            "(provider_id, logical_provider_key, identity_key, identity_type, identity_value, hostname, current_ip, "
            "mac_address, provider_type, is_known, is_ignored, is_suppressed, query_count, blocked_query_count, observation_count, "
            "first_seen_at, last_seen_at, created_at, updated_at) "
            "SELECT :provider_id, 'scale-provider', 'mac-' || g, 'mac', md5('mac-' || g), "
            "'client-' || g || '.example.invalid', '10.20.' || ((g / 256) % 256) || '.' || (g % 256), "
            "md5('mac-address-' || g), "
            "'pihole', FALSE, FALSE, FALSE, 0, 0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP "
            "FROM generate_series(1, :clients) AS source(g)"
        ),
        {"clients": clients, "provider_id": provider_id},
    )
    client_start_id = connection.execute(text("SELECT min(id) FROM dns_recognised_devices")).scalar_one()
    return provider_id, user_id, client_start_id


def _insert_scale_data(connection, provider_id: int, user_id: int, client_start_id: int, traffic_rows: int, metric_rows: int, audit_rows: int) -> None:
    connection.execute(
        text(
            "INSERT INTO dns_client_traffic_events "
            "(dns_client_id, provider_id, event_key, client_ip, domain, query_type, status, reply_type, reply_time_ms, "
            "upstream, is_blocked, observed_at, created_at) "
            "SELECT :client_start_id + ((g - 1) % 3000), :provider_id, md5(g::text), '10.20.' || (((g - 1) % 3000) / 256) || '.' || (((g - 1) % 3000) % 256), "
            "'www-' || (g % 10000) || '.example.invalid', 'A', 'NOERROR', 'A', (g % 40)::double precision, '10.0.0.1', "
            "(g % 10 = 0), CURRENT_TIMESTAMP - ((g % 2160)::text || ' minutes')::interval, CURRENT_TIMESTAMP "
            "FROM generate_series(1, :rows) AS source(g)"
        ),
        {"rows": traffic_rows, "provider_id": provider_id, "client_start_id": client_start_id},
    )
    connection.execute(
        text(
            "INSERT INTO compute_hosts "
            "(name, platform, base_url, verify_tls, is_enabled, poll_interval_seconds, status, created_at, updated_at) "
            "VALUES ('scale-compute-1', 'linux', 'https://compute.invalid', TRUE, TRUE, 30, 'online', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
    )
    connection.execute(
        text(
            "INSERT INTO compute_metrics "
            "(host_id, cpu_percent, memory_used, memory_total, storage_used, storage_total, recorded_at) "
            "SELECT 1, (g % 100)::double precision, 1000000000 + g, 16000000000, 50000000000 + g, 100000000000, "
            "CURRENT_TIMESTAMP - ((g % 4320)::text || ' minutes')::interval "
            "FROM generate_series(1, :rows) AS source(g)"
        ),
        {"rows": metric_rows},
    )
    connection.execute(
        text(
            "INSERT INTO audit_logs "
            "(user_id, action, entity, entity_id, detail, category, severity, status_code, capture_tier, created_at) "
            "SELECT :user_id, 'scale.test', 'dns_client', (g % 3000)::text, 'synthetic scale validation event', 'activity', 'info', 200, 'standard', "
            "CURRENT_TIMESTAMP - ((g % 2160)::text || ' minutes')::interval "
            "FROM generate_series(1, :rows) AS source(g)"
        ),
        {"rows": audit_rows, "user_id": user_id},
    )
    connection.execute(
        text(
            "INSERT INTO app_sessions "
            "(session_id, user_id, ip_address, user_agent, created_at, last_seen_at) "
            "SELECT 'scale-' || md5(g::text), :user_id, '192.0.2.' || (g % 250), 'Kaya scale test', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP "
            "FROM generate_series(1, 1000) AS source(g)"
        ),
        {"user_id": user_id},
    )
    connection.execute(
        text(
            "INSERT INTO notification_events "
            "(event_type, module, category, severity, title, message, metadata_json, created_at) "
            "SELECT 'scale.test', 'system', 'scale', 'info', 'Synthetic event', 'Synthetic notification', '{}', CURRENT_TIMESTAMP "
            "FROM generate_series(1, 1000)"
        )
    )


def _explain(connection, name: str, statement: str) -> dict:
    rows = connection.execute(text(f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {statement}")).scalar_one()
    plan = rows[0] if isinstance(rows, list) else rows
    return {
        "name": name,
        "planning_ms": plan.get("Planning Time"),
        "execution_ms": plan.get("Execution Time"),
        "plan": plan.get("Plan", {}).get("Node Type"),
        "index": plan.get("Plan", {}).get("Index Name"),
        "raw": plan,
    }


def _run_concurrent_workload(engine, workers: int, operations: int, client_start_id: int) -> dict:
    errors: list[str] = []
    started = time.perf_counter()
    with engine.connect() as connection:
        deadlocks_before = connection.execute(
            text("SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()")
        ).scalar_one()

    def operation(index: int) -> None:
        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO audit_logs (user_id, action, entity, detail, category, severity, status_code, capture_tier, created_at) "
                        "VALUES (1, 'scale.concurrent', 'workload', 'synthetic concurrent event', 'activity', 'info', 200, 'standard', CURRENT_TIMESTAMP)"
                    )
                )
                connection.execute(
                    text(
                        "SELECT id FROM dns_client_traffic_events WHERE dns_client_id = :client_id "
                        "ORDER BY observed_at DESC, id DESC LIMIT 20"
                    ),
                        {"client_id": client_start_id + (index % 3000)},
                ).all()
        except Exception as exc:  # pragma: no cover - reported by the harness
            errors.append(type(exc).__name__)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(operation, index) for index in range(operations)]
        for future in as_completed(futures):
            future.result()
    with engine.connect() as connection:
        activity = connection.execute(
            text(
                "SELECT count(*) AS active_connections, "
                "count(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_transaction "
                "FROM pg_stat_activity WHERE datname = current_database()"
            )
        ).mappings().one()
        deadlocks_after = connection.execute(
            text("SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()")
        ).scalar_one()
    return {
        "workers": workers,
        "operations": operations,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "errors": errors,
        "deadlocks": deadlocks_after - deadlocks_before,
        "activity": dict(activity),
        "pool_checked_out": engine.pool.checkedout(),
        "pool_overflow": engine.pool.overflow(),
    }


def _run_retention_workload(engine, batch_size: int = 10_000) -> dict:
    started = time.perf_counter()
    deleted = 0
    batches = 0
    while True:
        with engine.begin() as connection:
            count = connection.execute(
                text(
                    "DELETE FROM dns_client_traffic_events "
                    "WHERE id IN (SELECT id FROM dns_client_traffic_events "
                    "WHERE observed_at < CURRENT_TIMESTAMP - interval '2000 minutes' "
                    "ORDER BY id LIMIT :batch_size)"
                ),
                {"batch_size": batch_size},
            ).rowcount
        deleted += count
        batches += 1
        if count < batch_size:
            break
    with engine.connect() as connection:
        stats = connection.execute(
            text(
                "SELECT n_live_tup, n_dead_tup, last_autovacuum, last_autoanalyze "
                "FROM pg_stat_user_tables WHERE relname = 'dns_client_traffic_events'"
            )
        ).mappings().one()
    return {
        "deleted_rows": deleted,
        "batches": batches,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "table_stats_after": dict(stats),
    }


def run(database_url: str, *, traffic_rows: int, clients: int, metric_rows: int, audit_rows: int, workers: int, operations: int) -> dict:
    password_file = os.environ.get("DATABASE_PASSWORD_FILE", "")
    if password_file:
        password = Path(password_file).read_text(encoding="utf-8").strip()
        database_url = database_url.replace("postgresql+psycopg://kaya@", f"postgresql+psycopg://kaya:{password}@", 1)
    engine = create_engine(
        database_url,
        pool_size=5,
        max_overflow=5,
        pool_pre_ping=True,
        pool_recycle=1800,
    )
    started = time.perf_counter()
    with engine.begin() as connection:
        provider_id, user_id, client_start_id = _insert_seed_data(connection, clients)
        _insert_scale_data(connection, provider_id, user_id, client_start_id, traffic_rows, metric_rows, audit_rows)
        connection.execute(text("ANALYZE"))
    generation_seconds = time.perf_counter() - started
    queries = [
        ("dns_recent_traffic", f"SELECT id, domain, observed_at FROM dns_client_traffic_events WHERE dns_client_id = {client_start_id} ORDER BY observed_at DESC, id DESC LIMIT 50"),
        ("dns_history", f"SELECT id, domain, is_blocked, observed_at FROM dns_client_traffic_events WHERE dns_client_id = {client_start_id} ORDER BY observed_at DESC, id DESC LIMIT 1000"),
        ("dns_count", f"SELECT count(*) FROM dns_client_traffic_events WHERE dns_client_id = {client_start_id} AND observed_at >= CURRENT_TIMESTAMP - interval '30 days'"),
        ("dns_top_domains", f"SELECT domain, count(*) FROM dns_client_traffic_events WHERE dns_client_id = {client_start_id} GROUP BY domain ORDER BY count(*) DESC, domain LIMIT 10"),
        ("compute_history", "SELECT recorded_at, cpu_percent, memory_used FROM compute_metrics WHERE host_id = 1 ORDER BY recorded_at DESC LIMIT 200"),
        ("audit_listing", "SELECT id, action, entity, created_at FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 100"),
        ("session_lookup", "SELECT id, session_id, last_seen_at FROM app_sessions WHERE user_id = 1 AND ended_at IS NULL ORDER BY last_seen_at DESC"),
        ("notification_count", "SELECT count(*) FROM notification_events WHERE resolved_at IS NULL"),
        ("asset_lookup", "SELECT id, name, status FROM hardware_assets ORDER BY updated_at DESC LIMIT 50"),
        ("ha_heartbeat_lookup", "SELECT id, request_id, request_timestamp FROM ha_agent_requests ORDER BY request_timestamp DESC LIMIT 50"),
    ]
    with engine.connect() as connection:
        plans = [_explain(connection, name, statement) for name, statement in queries]
        sizes = connection.execute(
            text(
                "SELECT relname, n_live_tup, pg_total_relation_size(relid) AS bytes "
                "FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 20"
            )
        ).mappings().all()
        indexes = connection.execute(
            text(
                "SELECT indexrelname, relname, pg_relation_size(indexrelid) AS bytes "
                "FROM pg_stat_user_indexes ORDER BY pg_relation_size(indexrelid) DESC LIMIT 30"
            )
        ).mappings().all()
        total_bytes = connection.execute(text("SELECT pg_database_size(current_database())")).scalar_one()
    concurrency = _run_concurrent_workload(engine, workers, operations, client_start_id)
    retention = _run_retention_workload(engine)
    with engine.begin() as connection:
        connection.execute(text("ANALYZE dns_client_traffic_events"))
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "traffic_rows": traffic_rows,
        "clients": clients,
        "metric_rows": metric_rows,
        "audit_rows": audit_rows,
        "generation_seconds": round(generation_seconds, 3),
        "database_bytes": total_bytes,
        "largest_tables": [dict(row) for row in sizes],
        "largest_indexes": [dict(row) for row in indexes],
        "query_plans": plans,
        "concurrency": concurrency,
        "retention": retention,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--traffic-rows", type=int, default=1_200_000)
    parser.add_argument("--clients", type=int, default=3_000)
    parser.add_argument("--metric-rows", type=int, default=100_000)
    parser.add_argument("--audit-rows", type=int, default=100_000)
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--operations", type=int, default=100)
    parser.add_argument("--output", type=Path, default=Path("postgres-scale-report.json"))
    arguments = parser.parse_args()
    if not arguments.database_url:
        raise SystemExit("--database-url or DATABASE_URL is required")
    report = run(
        arguments.database_url,
        traffic_rows=arguments.traffic_rows,
        clients=arguments.clients,
        metric_rows=arguments.metric_rows,
        audit_rows=arguments.audit_rows,
        workers=arguments.workers,
        operations=arguments.operations,
    )
    arguments.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    compact = {key: value for key, value in report.items() if key not in {"query_plans", "largest_tables", "largest_indexes"}}
    compact["query_summaries"] = [
        {key: plan[key] for key in ("name", "planning_ms", "execution_ms", "plan", "index")}
        for plan in report["query_plans"]
    ]
    compact["largest_tables"] = report["largest_tables"][:10]
    compact["largest_indexes"] = report["largest_indexes"][:10]
    print(json.dumps(compact, indent=2, default=str))


if __name__ == "__main__":
    main()
