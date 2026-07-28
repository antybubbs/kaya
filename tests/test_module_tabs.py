from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]


def test_registered_modules_use_shared_navigation_component():
    templates = [
        "backup_manager.html", "compute_manager.html", "dashboard.html", "dns_manager.html",
        "domain_manager.html", "hardware_assets.html", "ip_addresses.html", "licences.html",
        "network_monitor.html", "rack_manager.html", "secret_vault.html",
        "secure_send.html", "_high_availability_nav.html", "_runbook_nav.html",
    ]
    for name in templates:
        content = (ROOT / "app" / "templates" / name).read_text(encoding="utf-8")
        assert "module_navigation(" in content, f"{name} must use the shared module navigation component"


def test_remote_manager_uses_the_documented_workspace_exception():
    content = (ROOT / "app" / "templates" / "remote_manager.html").read_text(encoding="utf-8")
    host_rail = (ROOT / "app" / "templates" / "_remote_host_rail.html").read_text(encoding="utf-8")
    styles = (ROOT / "app" / "static" / "css" / "remote.css").read_text(encoding="utf-8")
    assert "module_navigation(" not in content
    assert "remote-manager-hero" not in content
    assert '<div class="remote-workspace"' in content
    assert "module-remote-manager" not in content
    assert 'class="remote-host-header"' in host_rail
    assert 'href="/remote-manager/settings"' in host_rail
    assert "user.role == 'admin'" in host_rail
    assert "remote-host-settings-link" in styles
    assert ".remote-manager-hero" not in styles


def test_remote_manager_settings_link_is_server_rendered_for_admins_only():
    environment = Environment(loader=FileSystemLoader(ROOT / "app" / "templates"), autoescape=True)
    template = environment.get_template("_remote_host_rail.html")

    admin_html = template.render(user=SimpleNamespace(role="admin"), rows=[])
    viewer_html = template.render(user=SimpleNamespace(role="viewer"), rows=[])

    assert 'href="/remote-manager/settings"' in admin_html
    assert ">Settings<" in admin_html
    assert 'href="/remote-manager/settings"' not in viewer_html


def test_runbook_hero_uses_standard_search_without_create_actions():
    content = (ROOT / "app" / "templates" / "runbooks.html").read_text(encoding="utf-8")
    hero = content[:content.index("</section>")]
    assert 'class="search list-search"' in hero
    assert 'placeholder="Search runbooks..."' in hero
    assert ">Import<" not in hero
    assert "+ New Runbook" not in hero


def test_nested_and_data_management_tabs_keep_shared_tab_styling():
    templates = {
        "network_monitor_detail.html": "module-tabs detail-tabs",
        "remote_manager_settings.html": "module-tabs remote-manager-settings-tabs",
        "categories.html": "module-tabs",
        "import.html": "module-tabs",
    }
    for name, expected in templates.items():
        content = (ROOT / "app" / "templates" / name).read_text(encoding="utf-8")
        assert expected in content


def test_categories_and_custom_fields_are_contextual_module_navigation_items():
    supported = {
        "hardware_assets.html": "hardware_assets",
        "ip_addresses.html": "ip_addresses",
        "licences.html": "licences",
    }
    for name, module in supported.items():
        content = (ROOT / "app" / "templates" / name).read_text(encoding="utf-8")
        assert "user.role == 'admin'" in content
        assert f"/data/categories?module={module}" in content
        assert f"/data/custom-fields?module={module}" in content

    for name in ("categories.html", "custom_fields.html"):
        content = (ROOT / "app" / "templates" / name).read_text(encoding="utf-8")
        assert "module_navigation(" in content
        for module in supported.values():
            assert f"/data/categories?module={module}" in content
            assert f"/data/custom-fields?module={module}" in content


def test_single_category_list_does_not_render_a_redundant_navigation_bar():
    content = (ROOT / "app" / "templates" / "categories.html").read_text(encoding="utf-8")
    assert "{% if lists|length > 1 %}" in content
    assert 'aria-label="Managed list types"' in content


def test_contextual_administration_is_not_duplicated_globally():
    base = (ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    admin = (ROOT / "app" / "templates" / "admin.html").read_text(encoding="utf-8")
    settings = (ROOT / "app" / "templates" / "settings.html").read_text(encoding="utf-8")
    assert 'href="/data/categories' not in base
    assert 'href="/data/custom-fields' not in base
    assert 'href="/data/categories' not in admin
    assert 'href="/data/custom-fields' not in admin
    assert '<header><span>Categories</span></header>' not in settings


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
    template = (ROOT / "app" / "templates" / "dns_manager.html").read_text(encoding="utf-8")
    script = (ROOT / "app" / "static" / "js" / "tables.js").read_text(encoding="utf-8")
    query_log = css[css.index("/* DNS Manager query log interactions */"):]
    assert 'class="dns-query-log-controls" data-table-toolbar-host' in template
    assert 'parent.querySelector(":scope > [data-table-toolbar-host]")' in script
    assert ".dns-query-log-controls>.table-toolbar{" in query_log
    assert "margin-left:auto;" in query_log
    assert ".dns-query-log-panel>.table-scroll{" in query_log
    assert "grid-column:1 / -1;" in query_log
