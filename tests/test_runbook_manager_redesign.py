from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.db.session import Base
from app.main import app
from app.models.models import RunbookPage, RunbookSpace, User
from app.routers.runbooks import clean_tags, import_page, markdown_to_html, new_page, runbook_home, runbooks_page, spaces_page, tags_page, templates_page, validate_page_relationships


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def request(path="/documentation/runbook-manager"):
    return Request({"type": "http", "method": "GET", "scheme": "https", "path": path, "raw_path": path.encode(), "query_string": b"", "headers": [], "client": ("127.0.0.1", 1234), "server": ("kaya.test", 443), "session": {"csrf_token": "csrf"}, "app": app})


def test_tag_normalisation_merges_case_and_spacing_duplicates():
    assert clean_tags(" Docker, docker,  DOCKER , Network ") == "Docker, Network"


def test_parent_page_must_belong_to_selected_space_and_cycles_are_rejected():
    with database() as db:
        first = RunbookSpace(name="First")
        second = RunbookSpace(name="Second")
        db.add_all([first, second]); db.flush()
        parent = RunbookPage(title="Parent", slug="parent", space_id=first.id)
        child = RunbookPage(title="Child", slug="child", space_id=first.id, parent=parent)
        db.add_all([parent, child]); db.commit()
        validate_page_relationships(db, first.id, parent.id, child.id)
        with pytest.raises(HTTPException, match="selected space"):
            validate_page_relationships(db, second.id, parent.id, child.id)
        with pytest.raises(HTTPException, match="children"):
            validate_page_relationships(db, first.id, child.id, parent.id)


def test_markdown_toolbar_formats_render_in_server_preview():
    rendered = markdown_to_html("> Important\n\n- [x] Complete\n\n---")
    assert "<blockquote>Important</blockquote>" in rendered
    assert 'type="checkbox" disabled checked' in rendered
    assert "<hr>" in rendered


def test_dashboard_and_editor_expose_requested_navigation_and_workspace_controls():
    home = Path("app/templates/runbooks.html").read_text(encoding="utf-8")
    nav = Path("app/templates/_runbook_nav.html").read_text(encoding="utf-8")
    editor = Path("app/templates/runbook_form.html").read_text(encoding="utf-8")
    script = Path("app/static/js/runbooks.js").read_text(encoding="utf-8")
    stylesheet = Path("app/static/css/app.css").read_text(encoding="utf-8")
    for item in ("Overview", "Runbooks", "Spaces", "Tags", "Templates", "Import"):
        assert item in nav
    for item in ("Total Runbooks", "Updated This Week", "Most Used", "Popular Tags", "Needs Review"):
        assert item in home
    for item in ('data-editor-mode="editor"', 'data-editor-mode="split"', 'data-editor-mode="preview"', "data-runbook-tag-control", "data-runbook-save-state"):
        assert item in editor
    assert "kaya.runbook.editor.mode" in script
    assert "beforeunload" in script
    assert "Draft saved locally" in script
    assert "calc(100vh - 300px)" in stylesheet


def test_view_tracking_uses_additive_fields_with_safe_migration_guards():
    model = Path("app/models/models.py").read_text(encoding="utf-8")
    migration = Path("app/main.py").read_text(encoding="utf-8")
    assert "view_count: Mapped[int]" in model
    assert "last_viewed_at: Mapped[datetime | None]" in model
    assert 'if "view_count" not in runbook_page_columns' in migration
    assert 'if "last_viewed_at" not in runbook_page_columns' in migration


def test_redesigned_runbook_pages_render_with_empty_and_populated_data():
    with database() as db:
        user = User(email="editor@example.com", password_hash="x", role="editor", is_active=True)
        space = RunbookSpace(name="Network", description="Network operations")
        db.add_all([user, space]); db.flush()
        db.add(RunbookPage(title="VPN recovery", slug="vpn-recovery", summary="Restore the VPN", body="# Recover", tags="VPN, Network", is_pinned=True, view_count=3, space_id=space.id, created_by_id=user.id, updated_by_id=user.id))
        db.commit()
        responses = [
            runbook_home(request(), q="", space=None, tag="", tab="recent", db=db, user=user),
            runbooks_page(request("/documentation/runbook-manager/runbooks"), q="", space=None, tag="", db=db, user=user),
            spaces_page(request("/documentation/runbook-manager/spaces"), db=db, user=user),
            tags_page(request("/documentation/runbook-manager/tags"), db=db, user=user),
            templates_page(request("/documentation/runbook-manager/templates"), user=user),
            import_page(request("/documentation/runbook-manager/import"), db=db, user=user),
            new_page(request("/documentation/runbook-manager/new"), template="incident-response", space=space.id, db=db, user=user),
        ]
        assert all(response.status_code == 200 for response in responses)
        assert b"VPN recovery" in responses[0].body
        assert b'data-runbook-view-button="tiles"' in responses[1].body
        assert b'data-table-key="runbook-library"' in responses[1].body
        assert b"Network operations" in responses[2].body
        assert b"Incident response" in responses[-1].body
