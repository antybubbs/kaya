from pathlib import Path

TEMPLATE = Path("app/templates/hardware_asset_detail.html")
SCRIPT = Path("app/static/js/asset_history_charts.js")


def test_asset_history_series_render_as_time_series_charts_not_row_per_bucket_lists():
    template = TEMPLATE.read_text(encoding="utf-8")
    # The unstyled one-row-per-bucket markup stretched the History tab to page length.
    assert "asset-history-bars" not in template
    assert "asset-history-bar" not in template
    assert "{% for point in asset_reporting.uptime.history %}" not in template
    for kind, source in (("traffic", "traffic"), ("dns", "dns"), ("uptime", "uptime")):
        assert (
            f'<div class="asset-history-chart" data-asset-history-chart="{kind}" '
            f"data-asset-history-points='{{{{ asset_reporting.{source}.history|tojson|forceescape }}}}' role=\"img\""
        ) in template
    assert '<script src="/static/vendor/echarts/echarts.min.js?v=6.1.0" defer></script>' in template
    assert '<script src="/static/js/asset_history_charts.js?v={{ asset_version }}" defer></script>' in template


def test_asset_history_chart_script_draws_left_to_right_lines_for_every_kind():
    script = SCRIPT.read_text(encoding="utf-8")
    assert 'document.querySelectorAll("[data-asset-history-chart]")' in script
    assert 'JSON.parse(element.dataset.assetHistoryPoints || "[]")' in script
    assert 'type: "time"' in script
    assert 'type: "line"' in script
    assert "connectNulls: false" in script
    assert "innerHTML" not in script
    for kind in ("traffic:", "dns:", "uptime:"):
        assert kind in script
    for field in ('"download_bytes"', '"upload_bytes"', '"queries"', '"blocked"', '"availability"', '"latency_ms"'):
        assert field in script
