"""Coverage for the shared table-export pattern extended to previously-paginated tables.

These tables truncate their on-screen listing at a fixed row cap (see each router's
`.limit(...)` call), which means the client-side DOM export in app/static/js/tables.js
would silently omit rows beyond that cap. Each of these routers now exposes a
`/export` endpoint that reuses the same filters against the full, uncapped queryset.
"""
from datetime import datetime
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.core.security import encrypt_secret
from app.db.session import Base
from app.models.models import (
    ComputeHost,
    ComputeWorkload,
    DomainRecord,
    HardwareAsset,
    IPAddress,
    Licence,
    RemoteSessionRecording,
    RunbookPage,
    User,
)
from app.routers.compute_manager import export_workloads_table
from app.routers.domain_manager import export_domains_table
from app.routers.hardware_assets import export_assets_table
from app.routers.ip_addresses import export_ip_addresses_table
from app.routers.licences import export_licences_table
from app.routers.remote_manager import export_recordings_table
from app.routers.runbooks import export_runbooks_table


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def fake_request(path="/x"):
    return Request({
        "type": "http", "method": "GET", "scheme": "https", "path": path,
        "raw_path": path.encode(), "query_string": b"", "headers": [],
        "client": ("192.0.2.20", 1234), "server": ("kaya.example.test", 443),
    })


def viewer(db):
    row = User(email="viewer@example.test", password_hash="x", role="viewer", is_active=True)
    db.add(row)
    db.commit()
    return row


def admin(db):
    row = User(email="admin@example.test", password_hash="x", role="admin", is_active=True)
    db.add(row)
    db.commit()
    return row


def read_streamed(response) -> bytes:
    import asyncio

    async def collect():
        return b"".join([chunk async for chunk in response.body_iterator])

    return asyncio.run(collect())


def test_hardware_asset_export_returns_full_filtered_set_beyond_display_cap(db):
    user = viewer(db)
    for index in range(520):
        db.add(HardwareAsset(name=f"Asset {index:04d}", category="Server", status="In use"))
    db.add(HardwareAsset(name="Formula Row", category="Server", status="=2+2"))
    db.commit()
    response = export_assets_table(fake_request(), q="", category="", format="csv", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8-sig")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 522  # header + 520 plain rows + 1 formula row
    assert "'=2+2" in text  # formula-injection guarded, not raw "=2+2"


def test_hardware_asset_export_rejects_unknown_columns_and_formats(db):
    user = viewer(db)
    db.add(HardwareAsset(name="Asset", category="Server", status="In use"))
    db.commit()
    with pytest.raises(HTTPException):
        export_assets_table(fake_request(), q="", category="", format="pdf", columns="", filters="", db=db, user=user)
    with pytest.raises(HTTPException):
        export_assets_table(fake_request(), q="", category="", format="csv", columns="name,notes", filters="", db=db, user=user)


def test_hardware_asset_export_applies_search_filter(db):
    user = viewer(db)
    db.add(HardwareAsset(name="Rack Switch", category="Network", status="In use"))
    db.add(HardwareAsset(name="Laptop", category="Endpoint", status="In use"))
    db.commit()
    response = export_assets_table(fake_request(), q="switch", category="", format="text", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8")
    assert "Rack Switch" in text and "Laptop" not in text


def test_hardware_asset_export_of_empty_result_still_returns_headers(db):
    user = viewer(db)
    response = export_assets_table(fake_request(), q="no-such-asset", category="", format="csv", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8-sig")
    lines = [line for line in text.splitlines() if line]
    assert lines == ["Asset Tag,Name,Category,Status,Location,Warranty"]


def test_licence_export_never_exposes_the_raw_encrypted_or_decrypted_key(db):
    user = viewer(db)
    db.add(Licence(product="Design Suite", encrypted_product_key=encrypt_secret("SUPER-SECRET-KEY-12345"), licence_type="Perpetual", seats=5))
    db.commit()
    response = export_licences_table(fake_request(), q="", licence_type="", format="csv", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8-sig")
    assert "SUPER-SECRET-KEY-12345" not in text
    assert "Design Suite" in text


def test_ip_address_export_rejects_unknown_resource_and_respects_view_filters(db):
    user = viewer(db)
    with pytest.raises(HTTPException):
        export_ip_addresses_table("not-a-real-resource", fake_request(), db=db, user=user)
    for index in range(510):
        db.add(IPAddress(address=f"10.{index // 250}.{index % 250}.1", name=f"host-{index}", assignment_type="Static"))
    db.commit()
    response = export_ip_addresses_table("managed", fake_request(), q="", category="", vlan_id="", format="csv", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8-sig")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 511  # header + all 510 rows, not capped at 500


def test_domain_export_bypasses_the_five_hundred_row_display_cap(db):
    user = viewer(db)
    for index in range(510):
        db.add(DomainRecord(name=f"example-{index}.test"))
    db.commit()
    response = export_domains_table(fake_request(), q="", format="csv", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8-sig")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 511


def test_compute_workload_export_respects_view_and_search_filters(db):
    user = viewer(db)
    host = ComputeHost(name="hv-01", platform="proxmox", base_url="https://hv-01.example.test:8006")
    db.add(host)
    db.flush()
    db.add(ComputeWorkload(host_id=host.id, external_id="100", name="web-01", kind="container", status="running", owner="ops"))
    db.add(ComputeWorkload(host_id=host.id, external_id="101", name="db-01", kind="vm", status="running", owner="ops"))
    db.commit()
    response = export_workloads_table(fake_request(), q="", view="docker", format="csv", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8-sig")
    assert "web-01" in text and "db-01" not in text


def test_runbook_export_never_includes_the_raw_body_html(db):
    user = viewer(db)
    db.add(RunbookPage(title="Restart the router", slug="restart-the-router", summary="Short summary", body="<h1>Do not export this</h1>", tags="network"))
    db.commit()
    response = export_runbooks_table(fake_request(), q="", space=None, tag="", format="csv", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8-sig")
    assert "Do not export this" not in text
    assert "Restart the router" in text


def test_recording_export_requires_admin_dependency_and_omits_download_path(db):
    user = admin(db)
    row = User(email="recorded-user@example.test", password_hash="x", role="viewer", is_active=True)
    db.add(row)
    db.flush()
    db.add(RemoteSessionRecording(
        user_id=row.id, remote_label="db-01", protocol="ssh", category="maintenance",
        stored_filename="rec.cast", size_bytes=2048, duration_seconds=61.4,
        started_at=datetime(2026, 1, 1, 9, 0, 0),
    ))
    db.commit()
    response = export_recordings_table(fake_request(), format="csv", columns="", filters="", db=db, user=user)
    text = read_streamed(response).decode("utf-8-sig")
    assert "db-01" in text and "recorded-user@example.test" in text
    assert "rec.cast" not in text  # storage path never exposed
    source = (ROOT / "app/routers/remote_manager.py").read_text(encoding="utf-8")
    export_block = source[source.index("def export_recordings_table"):source.index("def export_recordings_table") + 400]
    assert "Depends(require_admin)" in export_block


def test_new_export_templates_wire_the_shared_toolbar_endpoints():
    hardware = (ROOT / "app/templates/hardware_assets.html").read_text(encoding="utf-8")
    licences = (ROOT / "app/templates/licences.html").read_text(encoding="utf-8")
    ip_addresses = (ROOT / "app/templates/ip_addresses.html").read_text(encoding="utf-8")
    domains = (ROOT / "app/templates/domain_manager.html").read_text(encoding="utf-8")
    compute = (ROOT / "app/templates/compute_manager.html").read_text(encoding="utf-8")
    runbooks = (ROOT / "app/templates/runbook_index.html").read_text(encoding="utf-8")
    recordings = (ROOT / "app/templates/remote_recordings.html").read_text(encoding="utf-8")
    assert 'data-export-url="/infrastructure/asset-manager/export"' in hardware
    assert 'data-export-url="/security/license-keys/export"' in licences
    assert 'data-export-url="/networking/vlan-ip-manager/export/managed"' in ip_addresses
    assert 'data-export-url="/networking/vlan-ip-manager/export/observed"' in ip_addresses
    assert 'data-export-url="/networking/vlan-ip-manager/export/leases"' in ip_addresses
    assert 'data-export-url="/networking/domain-manager/export"' in domains
    assert 'data-export-url="/infrastructure/vm-docker-manager/export"' in compute
    assert 'data-export-url="/documentation/runbook-manager/runbooks/export"' in runbooks
    assert 'data-export-url="/remote-manager/recordings/export"' in recordings


def test_export_icon_is_an_inline_svg_that_inherits_theme_colour_not_an_emoji():
    script = (ROOT / "app/static/js/tables.js").read_text(encoding="utf-8")
    css = (ROOT / "app/static/css/app.css").read_text(encoding="utf-8")
    kaya_css = (ROOT / "app/static/css/kaya.css").read_text(encoding="utf-8")
    assert "⇩" not in script  # the old emoji glyph must be gone
    assert 'class="table-export-icon"' in script
    assert ".table-export-icon{" in css and "stroke:currentColor" in css
    assert "html[data-kaya-theme=command] .table-export-panel" in kaya_css
