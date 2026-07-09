from app.services.site_settings import validate_allowed_hosts


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
