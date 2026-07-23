from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import ExternalIdentity, OIDCProvider, RemoteManagerSetting, User
from app.services.authentication_policy import get_authentication_policy, oidc_only_readiness


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def set_setting(db, key, value):
    row = db.query(RemoteManagerSetting).filter_by(key=key).first()
    if row:
        row.value = value
    else:
        db.add(RemoteManagerSetting(key=key, value=value))
    db.commit()


def test_policy_context_is_consistent_for_preferred_and_required_modes():
    with database() as db:
        db.add(OIDCProvider(name="Authentik", issuer="https://id.example.com", client_id="kaya", is_enabled=True))
        db.commit()
        set_setting(db, "authentication_mode", "oidc_preferred")
        set_setting(db, "oidc_show_local_preferred", "")
        preferred = get_authentication_policy(db)
        assert preferred.show_oidc_login is True
        assert preferred.show_local_login is False
        assert preferred.local_login_disabled is True
        assert preferred.provider_display_name == "Authentik"

        set_setting(db, "authentication_mode", "oidc_required")
        set_setting(db, "oidc_auto_redirect_required", "")
        required = get_authentication_policy(db)
        assert required.show_local_login is False
        assert required.auto_redirect_oidc is False


def test_oidc_only_readiness_is_bound_to_active_provider_and_current_admin():
    with database() as db:
        admin = User(email="admin@example.com", password_hash="hash", role="admin", is_active=True, is_break_glass=True)
        provider = OIDCProvider(
            name="Authentik", issuer="https://id.example.com", client_id="kaya", is_enabled=True,
            discovery_status="ok", test_login_succeeded_at=datetime.utcnow(),
        )
        db.add_all([admin, provider]); db.flush()
        db.add(ExternalIdentity(user_id=admin.id, provider_id=provider.id, issuer=provider.issuer, subject="admin", link_method="self_service"))
        db.commit()
        readiness = oidc_only_readiness(db, admin, emergency_enabled=True)
        assert readiness["ready"] is True

        provider.is_enabled = False
        db.commit()
        readiness = oidc_only_readiness(db, admin, emergency_enabled=True)
        assert readiness["ready"] is False
        checks = {item["key"]: item["passed"] for item in readiness["checks"]}
        assert checks["provider_configured"] is True
        assert checks["provider_enabled"] is False
