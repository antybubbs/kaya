import json
from email_validator import EmailNotValidError, validate_email

from app.models.models import OIDCProvider


ROLE_RANK = {"viewer": 1, "editor": 2, "admin": 3}


def claim_value(claims: dict, path: str):
    value = claims
    for part in (path or "").split("."):
        if not part or not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def claim_text(claims: dict, path: str) -> str | None:
    value = claim_value(claims, path)
    if isinstance(value, (str, int, float, bool)):
        clean = str(value).strip()
        return clean[:1000] or None
    return None


def claim_bool(claims: dict, path: str) -> bool:
    value = claim_value(claims, path)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def claim_groups(claims: dict, path: str) -> list[str]:
    value = claim_value(claims, path)
    if isinstance(value, str):
        return [value.strip()[:255]] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip()[:255] for item in value[:100] if isinstance(item, (str, int)) and str(item).strip()]
    return []


def normalise_email(value: str | None) -> str | None:
    try:
        return validate_email(value or "", check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        return None


def allowed_domains(provider: OIDCProvider) -> set[str]:
    return {
        item.strip().lower().lstrip("@")
        for item in (provider.allowed_email_domains or "").replace(",", "\n").splitlines()
        if item.strip()
    }


def email_is_allowed(provider: OIDCProvider, email: str) -> bool:
    domains = allowed_domains(provider)
    return not domains or email.rsplit("@", 1)[-1].lower() in domains


def role_mappings(provider: OIDCProvider) -> list[dict]:
    try:
        rows = json.loads(provider.role_mappings_json or "[]")
    except (TypeError, ValueError):
        return []
    return [row for row in rows if isinstance(row, dict) and row.get("role") in ROLE_RANK and str(row.get("group") or "").strip()]


def mapped_role(provider: OIDCProvider, groups: list[str]) -> str | None:
    candidates = []
    compared_groups = groups if provider.group_matching_case_sensitive else [group.casefold() for group in groups]
    for row in role_mappings(provider):
        expected = str(row["group"]).strip()
        if not provider.group_matching_case_sensitive:
            expected = expected.casefold()
        if expected in compared_groups:
            candidates.append(row["role"])
    return max(candidates, key=ROLE_RANK.get) if candidates else None


def initial_role(provider: OIDCProvider, groups: list[str]) -> str:
    return mapped_role(provider, groups) or (provider.default_role if provider.default_role in ROLE_RANK else "viewer")
