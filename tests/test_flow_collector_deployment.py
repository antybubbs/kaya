from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_flow_collector_compose_uses_module_entrypoint_and_runtime_healthcheck():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'command: ["python", "-m", "scripts.flow_collector"]' in compose
    assert "set -a && . /app/data/.runtime.env && set +a && python -m scripts.flow_collector_health" in compose
    assert "${KAYA_UPLOAD_DIR:-./uploads}:/app/uploads" in compose
