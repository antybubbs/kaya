from app.services.site_settings import (
    frame_ancestor_directive,
    host_is_allowed,
    validate_allowed_hosts,
)


def test_allowed_host_validation_accepts_supported_entries():
    value = "kaya.example.com\n*.example.com\n192.168.1.10\n2001:db8::1\n[::1]"
    assert validate_allowed_hosts(value) == []


def test_allowed_host_validation_reports_each_bad_entry_with_its_line():
    errors = validate_allowed_hosts("http://example.com\nexample\nabc%%")
    assert [error["line"] for error in errors] == [1, 2, 3]
    assert "without http://" in errors[0]["message"]
    assert "fully qualified" in errors[1]["message"]
    assert "letters, numbers and hyphens" in errors[2]["message"]


def test_allowed_host_validation_preserves_comma_separated_compatibility():
    assert validate_allowed_hosts("kaya.example.com, 10.0.0.5") == []


def test_host_matching_accepts_a_valid_port_and_normalises_case():
    assert host_is_allowed("KAYA.EXAMPLE.COM:443", ["kaya.example.com"])


def test_host_matching_rejects_malformed_ports_and_suffix_lookalikes():
    assert not host_is_allowed("kaya.example.com:bad", ["kaya.example.com"])
    assert not host_is_allowed("kaya.example.com.evil.invalid", ["*.example.com"])
    assert not host_is_allowed("evil-example.com", ["example.com"])


def test_application_framing_policy_is_closed_for_legacy_settings():
    assert frame_ancestor_directive({}) == "'none'"
    assert frame_ancestor_directive({"csp_frame_ancestors": "self"}) == "'none'"
    assert frame_ancestor_directive({"csp_frame_ancestors": "custom"}) == "'none'"
