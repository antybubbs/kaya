from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.models import ExternalIdentity, OIDCProvider, User
from app.services.site_settings import get_site_settings


AUTHENTICATION_MODES = {"local_only", "local_and_oidc", "oidc_preferred", "oidc_required"}


@dataclass(frozen=True)
class AuthenticationPolicy:
    authentication_mode: str
    oidc_available: bool
    oidc_button_label: str
    show_local_login: bool
    auto_redirect_oidc: bool
    provider_display_name: str | None
    local_login_disabled: bool
    provider: OIDCProvider | None

    @property
    def show_oidc_login(self) -> bool:
        return self.oidc_available and self.authentication_mode != "local_only"


def get_authentication_policy(db: Session) -> AuthenticationPolicy:
    values = get_site_settings(
        db,
        {
            "authentication_mode",
            "oidc_button_label",
            "oidc_auto_redirect_required",
            "oidc_show_local_preferred",
        },
    )
    mode = values["authentication_mode"]
    if mode not in AUTHENTICATION_MODES:
        mode = "local_only"
    provider = db.query(OIDCProvider).filter_by(is_enabled=True).order_by(OIDCProvider.id.asc()).first()
    show_local = mode in {"local_only", "local_and_oidc"} or (
        mode == "oidc_preferred" and values["oidc_show_local_preferred"] == "1"
    )
    oidc_available = provider is not None
    return AuthenticationPolicy(
        authentication_mode=mode,
        oidc_available=oidc_available,
        oidc_button_label=values["oidc_button_label"] or "Sign in with SSO",
        show_local_login=show_local,
        auto_redirect_oidc=(
            mode == "oidc_required"
            and oidc_available
            and values["oidc_auto_redirect_required"] == "1"
        ),
        provider_display_name=provider.name if provider else None,
        local_login_disabled=not show_local,
        provider=provider,
    )


def normal_local_login_allowed(db: Session) -> bool:
    return get_authentication_policy(db).show_local_login


def should_show_local_login(db: Session) -> bool:
    return normal_local_login_allowed(db)


def should_show_oidc_login(db: Session) -> bool:
    return get_authentication_policy(db).show_oidc_login


def should_auto_redirect_to_oidc(db: Session) -> bool:
    return get_authentication_policy(db).auto_redirect_oidc


def oidc_only_readiness(db: Session, current_admin: User | None = None, *, emergency_enabled: bool | None = None) -> dict:
    configured_provider = db.query(OIDCProvider).order_by(OIDCProvider.id.asc()).first()
    provider = db.query(OIDCProvider).filter_by(is_enabled=True).order_by(OIDCProvider.id.asc()).first()
    configured = configured_provider is not None
    break_glass = db.query(User).filter(
        User.role == "admin",
        User.is_active == True,  # noqa: E712
        User.is_break_glass == True,  # noqa: E712
        User.password_hash.isnot(None),
    ).first()
    linked = bool(
        provider
        and current_admin
        and db.query(ExternalIdentity).filter_by(provider_id=provider.id, user_id=current_admin.id).first()
    )
    if emergency_enabled is None:
        emergency_enabled = get_site_settings(db, {"oidc_emergency_local_enabled"})["oidc_emergency_local_enabled"] == "1"
    checks = [
        {"key": "provider_configured", "label": "Provider configured", "passed": configured, "help": "Save an OIDC provider configuration."},
        {"key": "provider_enabled", "label": "Provider enabled", "passed": provider is not None, "help": "Enable the OIDC provider."},
        {"key": "discovery", "label": "Discovery test completed", "passed": bool(provider and provider.discovery_status == "ok"), "help": "Run the provider configuration test successfully."},
        {"key": "test_login", "label": "Real OIDC login tested", "passed": bool(provider and provider.test_login_succeeded_at), "help": "Complete the real OIDC test-login flow."},
        {"key": "current_admin_linked", "label": "Current administrator linked", "passed": linked, "help": "Link and test your current administrator account with this provider."},
        {"key": "break_glass", "label": "Break-glass administrator available", "passed": bool(break_glass), "help": "Mark an active administrator with a local password as break glass."},
        {"key": "emergency_enabled", "label": "Emergency local login enabled", "passed": bool(emergency_enabled), "help": "Keep emergency local login enabled."},
    ]
    return {"checks": checks, "ready": all(check["passed"] for check in checks), "provider": provider, "break_glass": break_glass}
