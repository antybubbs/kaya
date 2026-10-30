from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_template(name):
    return (ROOT / "app" / "templates" / name).read_text(encoding="utf-8")


def test_monitoring_navigation_uses_uptime_without_moving_network_traffic():
    base = read_template("base.html")
    monitoring = base[base.index('data-sidebar-menu="monitoring"'):]
    monitoring = monitoring[:monitoring.index('data-sidebar-menu="documentation"')]
    assert ">Uptime</span>" in monitoring
    assert ">Network Traffic</span>" in monitoring
    assert monitoring.index(">Uptime</span>") < monitoring.index(">Network Traffic</span>")
    assert 'data-sidebar-menu="networking"' in base
    networking = base[base.index('data-sidebar-menu="networking"'):base.index('data-sidebar-menu="high-availability"')]
    assert ">VLAN/IP Manager</span>" in networking
    assert ">DNS Manager</span>" in networking
    assert ">Domain Manager</span>" in networking
    assert ">Uptime</span>" not in networking


def test_uptime_labels_change_only_the_presentation_layer():
    page = read_template("network_monitor.html")
    detail = read_template("network_monitor_detail.html")
    ip_detail = read_template("ip_address_detail.html")
    ip_form = read_template("ip_address_form.html")
    assert "<h1>Uptime</h1>" in page
    assert "Monitor device availability, response times, packet loss and outages." in page
    assert "Uptime navigation" in page
    assert ">Uptime</a>" in detail
    assert "Interactive Uptime performance history" in detail
    assert "Uptime {% if monitor and monitor.is_enabled %}" in ip_detail
    assert "Show in Uptime" in ip_form


def test_legacy_routes_and_module_key_remain_unchanged():
    modules = (ROOT / "app" / "services" / "modules.py").read_text(encoding="utf-8")
    router = (ROOT / "app" / "routers" / "network_monitor.py").read_text(encoding="utf-8")
    assert 'Module("network_monitor", "Uptime", ("/networking/ip-wan-monitor",))' in modules
    assert 'APIRouter(prefix="/networking/ip-wan-monitor"' in router
    assert 'APIRouter(prefix="/monitoring/ip-wan-monitor/wallboard")' in router


def test_network_traffic_documentation_marks_future_device_reporting_as_unimplemented():
    doc = (ROOT / "docs" / "network-traffic-monitoring.md").read_text(encoding="utf-8")
    assert "## Approved future requirements" in doc
    assert "not implemented capabilities" in doc
    assert "future NetFlow/NSEL collection and attribution stages" in doc
