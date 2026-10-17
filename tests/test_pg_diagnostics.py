from pathlib import Path

import scripts.collect_pg_diagnostics as collector


def test_collector_bounds_window_and_omits_sensitive_activity_fields(monkeypatch):
    class FakeConnection:
        def execute(self, statement):
            sql = str(statement)
            if "pg_stat_activity" in sql and "GROUP BY" not in sql:
                return type("Result", (), {"mappings": lambda self: type("Mappings", (), {"one": lambda self: {"active_sessions": 1}})()})()
            if "pg_stat_activity" in sql:
                return type("Result", (), {"mappings": lambda self: type("Mappings", (), {"all": lambda self: []})()})()
            if "pg_locks" in sql:
                return type("Result", (), {"mappings": lambda self: type("Mappings", (), {"all": lambda self: []})()})()
            if "pg_stat_database" in sql:
                return type("Result", (), {"mappings": lambda self: type("Mappings", (), {"one": lambda self: {"connections": 1}})()})()
            return type("Result", (), {"scalar_one": lambda self: False})()

    class FakeEngine:
        def connect(self):
            return self

        def __enter__(self):
            return FakeConnection()

        def __exit__(self, *_args):
            return False

        def dispose(self):
            pass

    monkeypatch.setattr(collector, "create_engine", lambda *args, **kwargs: FakeEngine())
    monkeypatch.setattr(collector.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(collector.time, "monotonic", iter([0, 1, 1, 31]).__next__)

    report = collector.collect("postgresql+psycopg://kaya@db.invalid/kaya", seconds=999, interval=999)

    assert report["duration_seconds"] == collector.MAX_SECONDS
    assert report["interval_seconds"] == collector.MAX_INTERVAL_SECONDS
    assert report["sample_count"] == 2
    assert "query" not in report["samples"][0]["activity"]
    assert "client_addr" not in report["samples"][0]["activity"]


def test_collector_source_does_not_select_query_text_or_parameters():
    source = Path(collector.__file__).read_text(encoding="utf-8")

    assert "query,\n" not in source
    assert "query_start" in source
    assert "pg_stat_statements" in source
