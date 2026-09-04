import pytest

from app.core.config import get_settings
from app.main import security_txt


def test_security_txt_is_inactive_without_a_configured_contact(monkeypatch):
    monkeypatch.setattr(get_settings(), "security_contact", "")
    with pytest.raises(Exception) as exc_info:
        security_txt()
    assert exc_info.value.status_code == 404


def test_security_txt_publishes_only_a_configured_contact(monkeypatch):
    monkeypatch.setattr(get_settings(), "security_contact", "mailto:security@example.invalid")
    response = security_txt()
    assert response.status_code == 200
    assert response.body == b"Contact: mailto:security@example.invalid\n"


@pytest.mark.parametrize("value", ["http://security.example", "mailto:a\nB@example.invalid", "not-a-uri"])
def test_security_txt_rejects_unsafe_or_unsupported_contact(monkeypatch, value):
    monkeypatch.setattr(get_settings(), "security_contact", value)
    with pytest.raises(Exception) as exc_info:
        security_txt()
    assert exc_info.value.status_code == 404
