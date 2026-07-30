from pathlib import Path

import yaml


def test_compose_healthcheck_allows_migration_grace_without_hiding_failures():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    healthcheck = services["kaya"]["healthcheck"]

    assert healthcheck["test"][0] == "CMD-SHELL"
    command = healthcheck["test"][1]
    assert "http://127.0.0.1:8080/healthz" in command
    assert ".status == 200" in command
    assert ">/dev/null 2>&1" in command
    assert healthcheck["start_period"] == "120s"
    assert healthcheck["interval"] == "15s"
    assert healthcheck["timeout"] == "5s"
    assert healthcheck["retries"] == 5


def test_secure_send_still_waits_for_kaya_health():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))

    dependency = compose["services"]["secure-send-gateway"]["depends_on"]["kaya"]

    assert dependency["condition"] == "service_healthy"
