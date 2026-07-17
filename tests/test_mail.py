from pathlib import Path

import app.services.mail as mail_service
from app.services.site_settings import DEFAULT_SITE_SETTINGS


class FakeSMTP:
    sent = []
    envelopes = []

    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def starttls(self):
        pass

    def login(self, *_args):
        pass

    def send_message(self, message, *, from_addr=None, to_addrs=None):
        self.sent.append(message)
        self.envelopes.append((from_addr, to_addrs))


def configure_mail(monkeypatch, *, branding: str):
    values = {
        "smtp_enabled": "1",
        "smtp_host": "smtp.example.test",
        "smtp_from_email": "kaya@example.test",
        "smtp_port": "587",
        "smtp_username": "",
        "smtp_password": "",
        "smtp_use_tls": "",
        "smtp_use_ssl": "",
        "smtp_from_name": "Kaya",
        "email_include_branding": branding,
        "app_name": "Kaya",
    }
    FakeSMTP.sent.clear()
    FakeSMTP.envelopes.clear()
    monkeypatch.setattr(mail_service, "get_site_settings", lambda *_args, **_kwargs: values)
    monkeypatch.setattr(mail_service, "get_site_setting", lambda _db, key: values.get(key, ""))
    monkeypatch.setattr(mail_service, "decrypt_secret", lambda value: value)
    monkeypatch.setattr(mail_service.smtplib, "SMTP", FakeSMTP)


def test_branded_email_embeds_compact_logo_and_keeps_plain_text(monkeypatch):
    configure_mail(monkeypatch, branding="1")
    url = "https://send.example.test/opaque-token"
    mail_service.send_mail(
        object(),
        "recipient@example.test",
        "Secure package",
        f"Hello Recipient,\n\nOpen secure package:\n{url}",
        action_url=url,
        action_label="Open secure package",
    )
    message = FakeSMTP.sent[0]
    content_types = [part.get_content_type() for part in message.walk()]
    assert "text/plain" in content_types and "text/html" in content_types and "image/png" in content_types
    assert url in message.get_body(preferencelist=("plain",)).get_content()
    html = message.get_body(preferencelist=("html",)).get_content()
    assert 'cid:kaya-email-logo' in html
    assert 'width="36" height="36"' in html
    assert "Open secure package" in html and url in html
    logo = next(part for part in message.walk() if part.get_content_type() == "image/png")
    assert logo.get_content_disposition() == "inline"
    assert logo["Content-ID"] == "<kaya-email-logo>"
    assert logo.get_filename() is None
    assert message["Date"] and message["Message-ID"].endswith("@example.test>")
    assert FakeSMTP.envelopes == [("kaya@example.test", ["recipient@example.test"])]


def test_email_branding_can_be_disabled(monkeypatch):
    configure_mail(monkeypatch, branding="")
    mail_service.send_mail(object(), "recipient@example.test", "Subject", "Plain body")
    message = FakeSMTP.sent[0]
    assert message.get_content_type() == "text/plain"
    assert not message.is_multipart()


def test_secure_send_template_and_branding_settings_are_available():
    assert DEFAULT_SITE_SETTINGS["email_include_branding"] == "1"
    assert "{secure_link}" in DEFAULT_SITE_SETTINGS["email_template_secure_send_body"]
    root = Path(__file__).parents[1]
    settings_template = (root / "app" / "templates" / "settings.html").read_text(encoding="utf-8")
    secure_send_router = (root / "app" / "routers" / "secure_send.py").read_text(encoding="utf-8")
    assert "email_template_secure_send_subject" in settings_template
    assert "email_template_secure_send_body" in settings_template
    assert "email_include_branding" in settings_template
    assert 'formaction="/system/site-administration/test-email"' in settings_template
    assert "Send test email" in settings_template
    assert "action_url=url" in secure_send_router
    assert "{pin}" not in DEFAULT_SITE_SETTINGS["email_template_secure_send_body"].lower()
    assert "{passphrase}" not in DEFAULT_SITE_SETTINGS["email_template_secure_send_body"].lower()
