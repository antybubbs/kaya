from pathlib import Path

from app.core.config import Settings


def test_demo_configuration_is_not_part_of_the_product():
    assert "demo_mode" not in Settings.model_fields
    assert "demo_reset_schedule" not in Settings.model_fields
    assert "demo_generation_file" not in Settings.model_fields


def test_demo_runtime_and_deployment_assets_are_removed():
    removed = (
        Path("app/core/demo.py"),
        Path("app/static/css/demo.css"),
        Path("docker-compose.demo.yml"),
        Path("scripts/seed_demo.py"),
        Path("demo/reset-demo.sh"),
    )
    assert all(not path.exists() for path in removed)


def test_production_runtime_has_no_demo_switch_or_middleware():
    sources = [
        Path("app/main.py").read_text(encoding="utf-8"),
        Path("docker-entrypoint.sh").read_text(encoding="utf-8"),
        Path("docker-compose.yml").read_text(encoding="utf-8"),
    ]
    combined = "\n".join(sources)
    assert "DEMO_MODE" not in combined
    assert "protect_public_demo" not in combined
    assert "demo_request_is_blocked" not in combined


def test_production_templates_have_no_shared_demo_interface():
    templates = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("app/templates").glob("*.html")
    )
    assert "request.app.state.demo_mode" not in templates
    assert "demo_accounts" not in templates
    assert "Public demo" not in templates
