from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]


def render_navigation(role: str) -> str:
    environment = Environment(
        loader=FileSystemLoader(ROOT / "app" / "templates"),
        autoescape=select_autoescape(["html"]),
    )
    template = environment.get_template("components/module_navigation.html")
    module = template.make_module({"user": SimpleNamespace(role=role)})
    return str(module.module_navigation(
        "Example navigation",
        [
            {"label": "Overview", "url": "/example", "active": True},
            {"label": "Clients", "url": "/example?view=clients", "active": False, "badge": 144, "badge_label": "clients"},
        ],
        "/system/site-administration?tab=module-example",
    ))


def test_shared_navigation_is_semantic_accessible_and_badge_aware():
    html = render_navigation("admin")
    assert '<nav class="module-nav module-tabs" aria-label="Example navigation">' in html
    assert 'aria-current="page"' in html
    assert 'aria-label="144 clients"' in html
    assert '<span>Settings</span>' in html


def test_settings_link_is_omitted_server_side_for_non_admin_roles():
    for role in ("editor", "viewer"):
        html = render_navigation(role)
        assert "module-nav__actions" not in html
        assert "site-administration" not in html


def test_contextual_administration_items_are_omitted_for_editor_and_viewer_roles():
    environment = Environment(
        loader=FileSystemLoader(ROOT / "app" / "templates"),
        autoescape=select_autoescape(["html"]),
    )
    template = environment.get_template("components/module_navigation.html")
    for role in ("admin", "editor", "viewer"):
        module = template.make_module({"user": SimpleNamespace(role=role)})
        html = str(module.module_navigation("Example navigation", [
            {"label": "Overview", "url": "/example", "active": True},
            {"label": "Categories", "url": "/data/categories?module=example", "visible": role == "admin"},
            {"label": "Custom Fields", "url": "/data/custom-fields?module=example", "visible": role == "admin"},
        ]))
        assert ("Categories" in html) is (role == "admin")
        assert ("Custom Fields" in html) is (role == "admin")


def test_shared_navigation_styles_keep_settings_separate_and_mobile_reachable():
    css = (ROOT / "app" / "static" / "css" / "kaya.css").read_text(encoding="utf-8")
    assert ".module-nav__pages" in css
    assert "overflow-x:auto" in css
    assert ".module-nav__actions" in css
    assert "margin-left:auto" in css
    assert ":focus-visible" in css
    active_rule = css[css.index(".module-nav__pages>a.active"):css.index(".module-nav__pages>a:focus-visible")]
    assert "box-shadow:none" in active_rule
    assert "inset 0 -2px" not in active_rule
