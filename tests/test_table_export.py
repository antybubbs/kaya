from datetime import date
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.services.table_export import (
    _encoded_lines,
    csv_safe,
    safe_export_filename,
    validate_export_columns,
    validate_export_filters,
    validate_export_format,
)


ROOT = Path(__file__).resolve().parents[1]


def exported(headers, rows, export_format="csv"):
    return b"".join(_encoded_lines(headers, rows, export_format))


def test_csv_export_is_utf8_excel_compatible_escaped_and_formula_safe():
    payload = exported(
        ["Name", "Notes"],
        [["Málaga", 'comma, quote " and\nline'], ["=2+2", "+447700900000"]],
    )
    assert payload.startswith(b"\xef\xbb\xbf")
    text = payload.decode("utf-8-sig")
    assert '"comma, quote "" and\nline"' in text
    assert "'=2+2" in text and "'+447700900000" in text
    assert csv_safe("ordinary-value") == "ordinary-value"


def test_text_export_has_headers_tabs_crlf_and_no_object_markers():
    text = exported(["Name", "Value"], [["Café", None], ["line\nbreak", "ok"]], "text").decode()
    assert text == "Name\tValue\r\nCafé\t\r\nline break\tok\r\n"
    assert "null" not in text and "[object Object]" not in text


def test_export_format_columns_and_filename_are_allowlisted():
    assert validate_export_format("CSV") == "csv"
    assert validate_export_columns("name,status", ["name", "status", "owner"]) == ["name", "status"]
    assert validate_export_filters('{"name":"  CAFÉ "}', ["name", "status"]) == {"name": "café"}
    assert safe_export_filename("IP Addresses / Primary", "csv", date(2026, 8, 3)) == "kaya-ip-addresses-primary-2026-08-03.csv"
    with pytest.raises(HTTPException):
        validate_export_format("json")
    with pytest.raises(HTTPException):
        validate_export_columns("name,password_hash", ["name", "status"])
    with pytest.raises(HTTPException):
        validate_export_columns("name,name", ["name"])
    with pytest.raises(HTTPException):
        validate_export_filters('{"password":"secret"}', ["name"])


def test_shared_table_export_ui_is_reusable_accessible_and_precedes_settings():
    script = (ROOT / "app/static/js/tables.js").read_text(encoding="utf-8")
    css = (ROOT / "app/static/css/app.css").read_text(encoding="utf-8")
    responsive = (ROOT / "app/static/css/responsive.css").read_text(encoding="utf-8")
    assert 'toolbar.insertBefore(exportMenu, settings)' in script
    assert 'Export as CSV' in script and 'Export as Text' in script
    assert 'aria-label="Export table"' in script and 'role="menuitem"' in script
    assert 'ArrowDown' in script and 'ArrowUp' in script and 'event.key === "Escape"' in script
    assert 'menu.dataset.loading === "true"' in script and 'button.disabled = true' in script
    assert 'hiddenColumns.has(key)' in script and 'data.exportUrl' not in script
    assert 'safeCsvValue' in script and 'startsWith' not in script[script.index("function safeCsvValue"):script.index("function delimitedContent")]
    assert '.table-export' in css and 'html[data-theme=light] .table-export-panel' in css
    assert '.table-export-panel' in responsive and 'position:fixed' in responsive


def test_sensitive_tables_are_excluded_and_server_tables_use_approved_endpoints():
    script = (ROOT / "app/static/js/tables.js").read_text(encoding="utf-8")
    vault = (ROOT / "app/templates/secret_vault.html").read_text(encoding="utf-8")
    users = (ROOT / "app/templates/users.html").read_text(encoding="utf-8")
    audit = (ROOT / "app/templates/audit.html").read_text(encoding="utf-8")
    monitor = (ROOT / "app/templates/network_monitor_detail.html").read_text(encoding="utf-8")
    assert 'key === "secret-vault-items"' in script and 'secure-send-table' in script
    assert 'data-table-key="secret-vault-items"' in vault
    assert 'data-export-url="/team/users/export"' in users
    assert 'data-export-url="/system/audit-logs/export"' in audit
    assert 'data-export-url="/networking/ip-wan-monitor/{{ monitor.id }}/performance.csv"' in monitor
