import smtplib
from html import escape
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.security import decrypt_secret
from app.core.performance import external_call
from app.core.branding import APP_BRAND_NAME
from app.services.site_settings import get_site_setting, get_site_settings


EMAIL_LOGO_PATH = Path(__file__).parents[1] / "static" / "brand" / "kaya-favicon-192-transparent.png"
EMAIL_LOGO_CID = "kaya-email-logo"


class MailConfigurationError(RuntimeError):
    pass


class SafeTemplateValues(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def setting_enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def render_email_template(template: str, **values: str) -> str:
    return (template or "").format_map(SafeTemplateValues(values))


def branded_email_html(
    body: str,
    *,
    app_name: str = APP_BRAND_NAME,
    action_url: str | None = None,
    action_label: str | None = None,
    include_logo: bool = True,
) -> str:
    """Build conservative, client-compatible email HTML from a plain-text body."""
    safe_body = escape(body or "")
    if action_url and action_label:
        safe_url = escape(action_url, quote=True)
        safe_action = (
            f'<a href="{safe_url}" style="background:#ff8a00;border-radius:6px;color:#17110a;'
            f'display:inline-block;font-weight:700;padding:11px 18px;text-decoration:none">'
            f'{escape(action_label)}</a>'
        )
        safe_body = safe_body.replace(escape(action_url), safe_action)
    safe_body = safe_body.replace("\n", "<br>\n")
    logo = (
        f'<img src="cid:{EMAIL_LOGO_CID}" width="36" height="36" alt="" '
        'style="border:0;display:block;height:36px;width:36px">'
        if include_logo else ""
    )
    return (
        '<!doctype html><html><body style="background:#f3f4f6;margin:0;padding:24px">'
        '<table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr><td align="center">'
        '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
        'style="background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;max-width:600px">'
        '<tr><td style="border-bottom:1px solid #e5e7eb;padding:16px 22px">'
        '<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
        f'<td style="padding-right:{"11px" if include_logo else "0"}">{logo}</td>'
        f'<td style="color:#111827;font-family:Arial,sans-serif;font-size:17px;font-weight:700">{escape(app_name)}</td>'
        '</tr></table></td></tr>'
        f'<tr><td style="color:#1f2937;font-family:Arial,sans-serif;font-size:14px;line-height:1.65;padding:24px 22px">{safe_body}</td></tr>'
        '<tr><td style="border-top:1px solid #e5e7eb;color:#6b7280;font-family:Arial,sans-serif;'
        'font-size:11px;padding:13px 22px">This is an automated secure notification.</td></tr>'
        '</table></td></tr></table></body></html>'
    )


def send_mail(
    db: Session,
    to_email: str,
    subject: str,
    body: str,
    *,
    action_url: str | None = None,
    action_label: str | None = None,
) -> None:
    get_site_settings(db, {
        "smtp_enabled", "smtp_host", "smtp_from_email", "smtp_port", "smtp_username",
        "smtp_password", "smtp_use_tls", "smtp_use_ssl", "smtp_from_name",
        "email_include_branding", "app_name",
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
    _, parsed_from = parseaddr(from_email)
    if parsed_from.casefold() != from_email.casefold() or "@" not in parsed_from:
        raise MailConfigurationError("SMTP from email is not a valid mailbox address.")
    message_id_domain = parsed_from.rsplit("@", 1)[1].lower()

    message = EmailMessage()
    message["To"] = to_email
    message["From"] = from_header
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=message_id_domain)
    message.set_content(body)
    if setting_enabled(get_site_setting(db, "email_include_branding")):
        include_logo = EMAIL_LOGO_PATH.is_file()
        message.add_alternative(
            branded_email_html(
                body,
                app_name=get_site_setting(db, "app_name").strip() or APP_BRAND_NAME,
                action_url=action_url,
                action_label=action_label,
                include_logo=include_logo,
            ),
            subtype="html",
        )
        if include_logo:
            message.get_payload()[-1].add_related(
                EMAIL_LOGO_PATH.read_bytes(),
                maintype="image",
                subtype="png",
                cid=f"<{EMAIL_LOGO_CID}>",
                disposition="inline",
            )

    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with external_call():
        with smtp_class(host, port, timeout=15) as smtp:
            if use_tls and not use_ssl:
                smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.send_message(message, from_addr=from_email, to_addrs=[to_email])
