from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import base64

import pytest
from authlib.jose import JsonWebKey, JsonWebToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import OIDCProvider, RemoteManagerSetting
from app.services.oidc_client import PRIVILEGED_AUTH_TIME_CLOCK_SKEW_SECONDS, OIDCFlowError, consume_transaction, create_transaction, provider_logout_redirect, safe_return_path, validate_id_token
from app.services.oidc_discovery import OIDCDiscoveryError, normalise_issuer, validate_metadata
from app.services.oidc_role_mapping import claim_groups, claim_value, email_is_allowed, mapped_role
from app.services.site_settings import oidc_form_action_source
from app.core.logging import SensitiveAuthenticationLogFilter
import logging


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def provider(db, **values):
    row = OIDCProvider(name="Test", issuer="https://id.example.com", client_id="kaya", encrypted_client_secret="saved", **values)
    db.add(row)
    db.commit()
    return row


def valid_metadata(**changes):
    value = {
        "issuer": "https://id.example.com",
        "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token",
        "jwks_uri": "https://id.example.com/jwks",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }
    value.update(changes)
    return value


def signing_material():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = JsonWebKey.import_key(private_pem, {"kid": "test-key"}).as_dict(is_private=False)
    return private_pem, {"keys": [public]}


def token(private_pem, **changes):
    now = int(datetime.utcnow().timestamp())
    claims = {"iss": "https://id.example.com", "aud": "kaya", "sub": "subject-1", "exp": now + 300, "iat": now, "nonce": "nonce-1"}
    claims.update(changes)
    return JsonWebToken(["RS256"]).encode({"alg": "RS256", "kid": "test-key"}, claims, private_pem).decode()


def test_discovery_rejects_unsafe_issuer_and_incomplete_or_mismatched_metadata(monkeypatch):
    with pytest.raises(OIDCDiscoveryError):
        normalise_issuer("https://user:password@id.example.com")
    with pytest.raises(OIDCDiscoveryError):
        normalise_issuer("http://id.example.com")
    monkeypatch.setattr("app.services.oidc_discovery._validate_resolved_host", lambda hostname: None)
    with pytest.raises(OIDCDiscoveryError, match="does not match"):
        validate_metadata("https://id.example.com", valid_metadata(issuer="https://other.example.com"))
    with pytest.raises(OIDCDiscoveryError, match="token_endpoint"):
        validate_metadata("https://id.example.com", valid_metadata(token_endpoint=None))
    assert validate_metadata("https://id.example.com", valid_metadata())["pkce"] == "ok"


def test_server_side_transaction_validates_state_once_and_rejects_replay():
    with database() as db:
        row_provider = provider(db)
        _, opaque, state, _, _ = create_transaction(db, row_provider, return_path="https://evil.example/")
        row = consume_transaction(db, opaque, state)
        assert row.return_path == "/dashboard"
        with pytest.raises(OIDCFlowError) as reused:
            consume_transaction(db, opaque, state)
        assert reused.value.category == "invalid_state"


def test_transaction_rejects_wrong_state_and_expiry():
    with database() as db:
        row_provider = provider(db)
        row, opaque, state, _, _ = create_transaction(db, row_provider)
        with pytest.raises(OIDCFlowError):
            consume_transaction(db, opaque, "wrong")
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
        with pytest.raises(OIDCFlowError):
            consume_transaction(db, opaque, state)


def test_transaction_pairing_and_restart_preserve_single_use(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'state-restart.sqlite3').as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        row_provider = provider(db)
        _, first_opaque, first_state, _, _ = create_transaction(db, row_provider)
        _, second_opaque, second_state, _, _ = create_transaction(db, row_provider)
        with pytest.raises(OIDCFlowError):
            consume_transaction(db, first_opaque, second_state)
        consume_transaction(db, first_opaque, first_state)
    with Session(engine) as restarted:
        with pytest.raises(OIDCFlowError):
            consume_transaction(restarted, first_opaque, first_state)
        assert consume_transaction(restarted, second_opaque, second_state).used_at is not None


def test_two_concurrent_state_consumers_have_exactly_one_winner(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'state-race.sqlite3').as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        row_provider = provider(db)
        _, opaque, state, _, _ = create_transaction(db, row_provider)

    def attempt():
        with Session(engine) as db:
            try:
                consume_transaction(db, opaque, state)
                return "won"
            except OIDCFlowError:
                return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _value: attempt(), range(2)))
    assert sorted(results) == ["rejected", "won"]


def test_exception_after_state_consumption_cannot_restore_callback(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'state-crash.sqlite3').as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        row_provider = provider(db)
        _, opaque, state, _, _ = create_transaction(db, row_provider)
        consume_transaction(db, opaque, state)
        with pytest.raises(RuntimeError):
            raise RuntimeError("synthetic post-consumption failure")
    with Session(engine) as recovered:
        with pytest.raises(OIDCFlowError):
            consume_transaction(recovered, opaque, state)


def test_state_update_is_reusable_only_when_database_commit_rolls_back(monkeypatch):
    with database() as db:
        row_provider = provider(db)
        _, opaque, state, _, _ = create_transaction(db, row_provider)
        original_commit = db.commit

        def fail_commit():
            raise RuntimeError("synthetic commit failure")

        monkeypatch.setattr(db, "commit", fail_commit)
        with pytest.raises(OIDCFlowError) as failure:
            consume_transaction(db, opaque, state)
        assert failure.value.category == "invalid_state"
        monkeypatch.setattr(db, "commit", original_commit)
        assert consume_transaction(db, opaque, state).used_at is not None


@pytest.mark.parametrize("value", ["https://evil.example/x", "//evil.example/x", "javascript:alert(1)", "\\evil"])
def test_return_path_rejects_open_redirects(value):
    assert safe_return_path(value) == "/dashboard"
    assert safe_return_path("/networking/dns-manager?tab=clients") == "/networking/dns-manager?tab=clients"


def test_id_token_validation_accepts_valid_asymmetric_token():
    private, jwks = signing_material()
    row_provider = OIDCProvider(issuer="https://id.example.com", client_id="kaya")
    claims = validate_id_token(token(private), jwks, valid_metadata(), row_provider, nonce="nonce-1")
    assert claims["sub"] == "subject-1"


def test_privileged_id_token_requires_recent_signed_auth_time():
    private, jwks = signing_material()
    row_provider = OIDCProvider(issuer="https://id.example.com", client_id="kaya")
    started_at = datetime.now(timezone.utc)
    recent = int(started_at.timestamp())
    claims = validate_id_token(
        token(private, auth_time=recent), jwks, valid_metadata(), row_provider,
        nonce="nonce-1", required_auth_time_after=started_at,
    )
    assert claims["auth_time"] == recent


@pytest.mark.parametrize("auth_time", [None, "recent", -1, True])
def test_privileged_id_token_rejects_missing_or_malformed_auth_time(auth_time):
    private, jwks = signing_material()
    row_provider = OIDCProvider(issuer="https://id.example.com", client_id="kaya")
    started_at = datetime.now(timezone.utc)
    changes = {} if auth_time is None else {"auth_time": auth_time}
    with pytest.raises(OIDCFlowError) as failure:
        validate_id_token(
            token(private, **changes), jwks, valid_metadata(), row_provider,
            nonce="nonce-1", required_auth_time_after=started_at,
        )
    assert failure.value.category == "invalid_auth_time"
    assert str(failure.value) == "Single sign-on could not be completed."


def test_privileged_auth_time_rejects_stale_session_even_with_fresh_iat_and_prompt():
    private, jwks = signing_material()
    row_provider = OIDCProvider(issuer="https://id.example.com", client_id="kaya")
    started_at = datetime.now(timezone.utc)
    stale = int((started_at - timedelta(seconds=PRIVILEGED_AUTH_TIME_CLOCK_SKEW_SECONDS + 1)).timestamp())
    with pytest.raises(OIDCFlowError) as failure:
        validate_id_token(
            token(private, iat=int(started_at.timestamp()), auth_time=stale),
            jwks, valid_metadata(), row_provider, nonce="nonce-1", required_auth_time_after=started_at,
        )
    assert failure.value.category == "invalid_auth_time"


def test_privileged_auth_time_future_tolerance_is_narrow_and_explicit():
    private, jwks = signing_material()
    row_provider = OIDCProvider(issuer="https://id.example.com", client_id="kaya")
    started_at = datetime.now(timezone.utc)
    within_skew = int((started_at + timedelta(seconds=PRIVILEGED_AUTH_TIME_CLOCK_SKEW_SECONDS - 5)).timestamp())
    validate_id_token(
        token(private, auth_time=within_skew), jwks, valid_metadata(), row_provider,
        nonce="nonce-1", required_auth_time_after=started_at,
    )
    outside_skew = int((datetime.now(timezone.utc) + timedelta(seconds=PRIVILEGED_AUTH_TIME_CLOCK_SKEW_SECONDS + 5)).timestamp())
    with pytest.raises(OIDCFlowError) as failure:
        validate_id_token(
            token(private, auth_time=outside_skew), jwks, valid_metadata(), row_provider,
            nonce="nonce-1", required_auth_time_after=started_at,
        )
    assert failure.value.category == "invalid_auth_time"


def test_tampering_signed_auth_time_invalidates_token():
    private, jwks = signing_material()
    row_provider = OIDCProvider(issuer="https://id.example.com", client_id="kaya")
    started_at = datetime.now(timezone.utc)
    signed = token(private, auth_time=int(started_at.timestamp()))
    header, payload, signature = signed.split(".")
    replacement = base64.urlsafe_b64encode(b'{"auth_time":1}').rstrip(b"=").decode()
    with pytest.raises(OIDCFlowError) as failure:
        validate_id_token(
            f"{header}.{replacement}.{signature}", jwks, valid_metadata(), row_provider,
            nonce="nonce-1", required_auth_time_after=started_at,
        )
    assert failure.value.category == "invalid_id_token"


@pytest.mark.parametrize(
    ("change", "nonce"),
    [({"iss": "https://other.example.com"}, "nonce-1"), ({"aud": "other"}, "nonce-1"), ({"exp": 1}, "nonce-1"), ({}, "wrong")],
)
def test_id_token_validation_rejects_wrong_issuer_audience_expiry_and_nonce(change, nonce):
    private, jwks = signing_material()
    row_provider = OIDCProvider(issuer="https://id.example.com", client_id="kaya")
    with pytest.raises(OIDCFlowError) as failure:
        validate_id_token(token(private, **change), jwks, valid_metadata(), row_provider, nonce=nonce)
    assert failure.value.category == "invalid_id_token"


def test_id_token_rejects_unknown_key_and_unsigned_algorithm():
    private, _ = signing_material()
    _, other_jwks = signing_material()
    row_provider = OIDCProvider(issuer="https://id.example.com", client_id="kaya")
    with pytest.raises(OIDCFlowError):
        validate_id_token(token(private), other_jwks, valid_metadata(), row_provider, nonce="nonce-1")
    unsigned = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIn0."
    with pytest.raises(OIDCFlowError):
        validate_id_token(unsigned, {"keys": []}, valid_metadata(), row_provider, nonce="nonce-1")


def test_nested_claims_domains_and_highest_role_mapping():
    row_provider = OIDCProvider(
        allowed_email_domains="Example.com",
        group_claim="realm_access.roles",
        role_mappings_json='[{"group":"Users","role":"viewer"},{"group":"Operators","role":"editor"},{"group":"Admins","role":"admin"}]',
        group_matching_case_sensitive=False,
    )
    claims = {"realm_access": {"roles": ["users", "ADMINS"]}}
    assert claim_value(claims, "realm_access.roles") == ["users", "ADMINS"]
    assert claim_groups(claims, row_provider.group_claim) == ["users", "ADMINS"]
    assert mapped_role(row_provider, ["users", "ADMINS"]) == "admin"
    assert email_is_allowed(row_provider, "person@example.com") is True
    assert email_is_allowed(row_provider, "person@fakeexample.com") is False


@pytest.mark.parametrize("path", [
    "/auth/oidc/callback?code=secret-code&state=value",
    "/auth/oidc/link/invitation?token=secret-code",
])
def test_oidc_credential_query_values_are_redacted_from_access_log(path):
    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d', ("client", "GET", path, "1.1", 303), None)
    SensitiveAuthenticationLogFilter().filter(record)
    assert "secret-code" not in record.getMessage()
    assert "?[redacted]" in record.getMessage()


def test_provider_logout_uses_id_token_hint_and_safe_local_return(monkeypatch):
    monkeypatch.setattr("app.services.oidc_client.validate_outbound_url", lambda value: value)
    with database() as db:
        row_provider = provider(db, is_enabled=True, end_session_on_logout=True)
        row_provider.metadata_json = '{"end_session_endpoint":"https://id.example.com/logout"}'
        db.add(RemoteManagerSetting(key="base_url", value="https://kaya.example.com"))
        db.add(RemoteManagerSetting(key="oidc_post_logout_path", value="https://evil.example.com/redirect"))
        db.commit()

        redirect = provider_logout_redirect(db, id_token_hint="header.payload.signature")

        assert redirect.startswith("https://id.example.com/logout?")
        assert "id_token_hint=header.payload.signature" in redirect
        assert "post_logout_redirect_uri=https%3A%2F%2Fkaya.example.com%2Flogin%3Flogged_out%3D1" in redirect


def test_csp_form_action_allows_only_enabled_provider_authorization_origin():
    with database() as db:
        row_provider = provider(db, is_enabled=True)
        row_provider.metadata_json = '{"authorization_endpoint":"https://auth.example.com/application/o/authorize/"}'
        db.commit()
        assert oidc_form_action_source(db) == "https://auth.example.com"

        row_provider.metadata_json = '{"authorization_endpoint":"https://auth.example.com/authorize/?unsafe=1"}'
        row_provider.issuer = "https://issuer.example.com/application/o/kaya/"
        db.commit()
        assert oidc_form_action_source(db) == "https://issuer.example.com"
