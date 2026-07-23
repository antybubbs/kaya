from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_module_navigation_uses_shared_tab_component():
    templates = {
        "network_monitor_detail.html": "module-tabs detail-tabs",
        "dns_manager.html": "module-tabs dns-manager-tabs",
        "ip_addresses.html": "module-tabs section-gap vlan-ip-view-tabs",
        "compute_manager.html": "module-tabs compute-tabs",
        "remote_manager_settings.html": "module-tabs remote-manager-settings-tabs",
        "categories.html": "module-tabs",
        "custom_fields.html": "module-tabs",
        "import.html": "module-tabs",
    }
    for name, expected in templates.items():
        content = (ROOT / "app" / "templates" / name).read_text(encoding="utf-8")
        assert expected in content, f"{name} must use the shared module tab bar"


def test_shared_tabs_do_not_restore_the_orange_bottom_border():
    css = (ROOT / "app" / "static" / "css" / "kaya.css").read_text(encoding="utf-8")
    shared = css[css.index("/* Shared module navigation."):]
    assert ".module-tabs" in shared
    assert "box-shadow:none!important" in shared
    assert "overflow-x:auto" in shared


def test_monitor_dns_shortcut_uses_the_clients_tab_route():
    content = (ROOT / "app" / "templates" / "network_monitor_detail.html").read_text(encoding="utf-8")
    assert "/networking/dns-manager?tab=clients&amp;client_q=" in content
    assert "/networking/dns-manager/clients?q=" not in content


def test_shared_tables_are_compact_without_clipping_data():
    css = (ROOT / "app" / "static" / "css" / "kaya.css").read_text(encoding="utf-8")
    compact = css[css.index("/* Compact, lossless table treatment"):]
    assert "white-space:nowrap" in compact
    assert "padding:7px 11px!important" in compact
    assert "text-overflow:clip" in compact
    assert "overflow-x:auto" in compact
    assert "overflow:hidden" not in compact


def test_dns_query_log_table_settings_aligns_to_panel_right_edge():
    css = (ROOT / "app" / "static" / "css" / "kaya.css").read_text(encoding="utf-8")
    query_log = css[css.index("/* DNS Manager query log interactions */"):]
    assert ".dns-query-log-panel>.table-toolbar{" in query_log
    assert "grid-column:2;" in query_log
    assert "justify-self:end;" in query_log
    assert "width:max-content;" in query_log
    assert ".dns-query-log-panel>.table-scroll{" in query_log
    assert "grid-column:1 / -1;" in query_log
