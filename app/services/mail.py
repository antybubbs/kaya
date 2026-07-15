import smtplib
from email.message import EmailMessage

from sqlalchemy.orm import Session

from app.core.security import decrypt_secret
from app.core.performance import external_call
from app.services.site_settings import get_site_setting, get_site_settings


class MailConfigurationError(RuntimeError):
    pass


class SafeTemplateValues(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def setting_enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def render_email_template(template: str, **values: str) -> str:
    return (template or "").format_map(SafeTemplateValues(values))


def send_mail(db: Session, to_email: str, subject: str, body: str) -> None:
    get_site_settings(db, {
        "smtp_enabled", "smtp_host", "smtp_from_email", "smtp_port", "smtp_username",
        "smtp_password", "smtp_use_tls", "smtp_use_ssl", "smtp_from_name",
    })
    if not setting_enabled(get_site_setting(db, "smtp_enabled")):
        raise MailConfigurationError("SMTP mail is not enabled.")

    host = get_site_setting(db, "smtp_host").strip()
    from_email = get_site_setting(db, "smtp_from_email").strip()
    if not host or not from_email:
        raise MailConfigurationError("SMTP host and from email are required.")

    port = int(get_site_setting(db, "smtp_port") or "587")
    username = get_site_setting(db, "smtp_username").strip()
    password = decrypt_secret(get_site_setting(db, "smtp_password")).strip()
    use_tls = setting_enabled(get_site_setting(db, "smtp_use_tls"))
    use_ssl = setting_enabled(get_site_setting(db, "smtp_use_ssl"))
    from_name = get_site_setting(db, "smtp_from_name").strip()
    from_header = f"{from_name} <{from_email}>" if from_name else from_email

    message = EmailMessage()
    message["To"] = to_email
    message["From"] = from_header
    message["Subject"] = subject
    message.set_content(body)

    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with external_call():
        with smtp_class(host, port, timeout=15) as smtp:
            if use_tls and not use_ssl:
                smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
