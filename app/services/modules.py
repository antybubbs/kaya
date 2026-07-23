"""Central registry and request-scoped per-user module access service."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import User, UserModulePermission
from app.core.config import get_settings
from app.services.site_settings import get_site_setting


@dataclass(frozen=True)
class Module:
    key: str
    label: str
    path_prefixes: tuple[str, ...]
    enabled_setting: str | None = None
    enabled_default: bool = True


# Stable keys are persisted. Labels and routes may evolve without rewriting grants.
MODULES = (
    Module("asset_manager", "Asset Manager", ("/infrastructure/asset-manager",)),
    Module("backup_manager", "Backup Manager", ("/infrastructure/backup-manager",), "backup_manager_enabled"),
    Module("compute_manager", "VM/Docker Manager", ("/infrastructure/vm-docker-manager",)),
    Module("dashboard", "Dashboard", ("/dashboard", "/api/dashboard")),
    Module("dns_manager", "DNS Manager", ("/networking/dns-manager",), "dns_manager_enabled", False),
    Module("domain_manager", "Domain Manager", ("/networking/domain-manager",)),
    Module("high_availability", "High Availability", ("/high-availability",), "high_availability_enabled", False),
    Module("licence_manager", "License Keys", ("/security/license-keys",)),
    Module("network_monitor", "IP/WAN Monitor", ("/networking/ip-wan-monitor",)),
    Module("rack_manager", "Rack Manager", ("/infrastructure/rack-manager",)),
    Module("remote_manager", "Remote Manager", ("/remote-manager",)),
    Module("runbooks", "Runbook Manager", ("/documentation/runbook-manager",)),
    Module("secret_vault", "Secret Vault", ("/security/secret-vault",)),
    Module("secure_send", "Secure Send", ("/security/secure-send",), "secure_send_enabled"),
    Module("vlan_ip_manager", "VLAN/IP Manager", ("/networking/vlan-ip-manager",)),
)
MODULE_BY_KEY = {module.key: module for module in MODULES}
MODULE_KEYS = frozenset(MODULE_BY_KEY)
MODULE_ACCESS_EXEMPT_PATHS = frozenset({
    # Compute agents authenticate with their own per-host token, not a browser user.
    "/infrastructure/vm-docker-manager/api/agent/checkin",
})
LANDING_ORDER = (
    "dashboard", "secret_vault", "runbooks", "remote_manager", "vlan_ip_manager",
    "dns_manager", "asset_manager", "compute_manager", "rack_manager",
    "network_monitor", "domain_manager", "backup_manager", "licence_manager",
    "secure_send", "high_availability",
)


def module_is_enabled(db: Session, module: Module) -> bool:
    if module.key == "secure_send" and get_settings().demo_mode:
        return False
    if not module.enabled_setting:
        return module.enabled_default
    value = get_site_setting(db, module.enabled_setting)
    return value == "1" if value != "" else module.enabled_default


def enabled_modules(db: Session) -> tuple[Module, ...]:
    return tuple(sorted(
        (module for module in MODULES if module_is_enabled(db, module)),
        key=lambda module: module.label.casefold(),
    ))


def enabled_module_keys(db: Session) -> frozenset[str]:
    return frozenset(module.key for module in enabled_modules(db))


def module_for_path(path: str) -> Module | None:
    normalised = path.rstrip("/") or "/"
    matches = (
        module
        for module in MODULES
        if any(normalised == prefix or normalised.startswith(prefix + "/") for prefix in module.path_prefixes)
    )
    return next(matches, None)


def accessible_module_keys(db: Session, user: User) -> frozenset[str]:
    cached = getattr(user, "_accessible_module_keys", None)
    if cached is not None:
        return cached
    granted = frozenset(
        key
        for (key,) in db.query(UserModulePermission.module_key)
        .filter(
            UserModulePermission.user_id == user.id,
            UserModulePermission.allowed.is_(True),
            UserModulePermission.module_key.in_(MODULE_KEYS),
        )
        .all()
    )
    result = granted & enabled_module_keys(db)
    user._accessible_module_keys = result
    return result


def has_module_access(db: Session, user: User | None, module_key: str) -> bool:
    return bool(
        user
        and user.is_active
        and module_key in MODULE_BY_KEY
        and module_key in accessible_module_keys(db, user)
    )


def module_landing_url(db: Session, user: User) -> str:
    allowed = accessible_module_keys(db, user)
    for key in LANDING_ORDER:
        if key in allowed:
            return MODULE_BY_KEY[key].path_prefixes[0]
    return "/profile"


def replace_module_access(
    db: Session,
    target: User,
    selected_keys: set[str],
    actor: User,
) -> tuple[set[str], set[str]]:
    unknown = selected_keys - MODULE_KEYS
    if unknown:
        raise ValueError("One or more selected modules are invalid.")
    enabled = enabled_module_keys(db)
    selected = selected_keys & enabled
    rows = {row.module_key: row for row in db.query(UserModulePermission).filter_by(user_id=target.id).all()}
    before = {key for key, row in rows.items() if row.allowed and key in enabled}
    now = datetime.utcnow()
    for key in before - selected:
        rows[key].allowed = False
        rows[key].updated_at = now
    for key in selected - before:
        row = rows.get(key)
        if row:
            row.allowed = True
            row.created_by = actor.id
            row.updated_at = now
        else:
            db.add(UserModulePermission(user_id=target.id, module_key=key, allowed=True, created_by=actor.id))
    target._accessible_module_keys = frozenset(selected)
    return selected - before, before - selected


def grant_all_enabled_modules(db: Session, target: User, actor: User | None = None) -> None:
    actor = actor or target
    replace_module_access(db, target, set(enabled_module_keys(db)), actor)


def grant_all_registered_modules(db: Session, target: User, actor: User | None = None) -> None:
    actor = actor or target
    existing = {
        row.module_key: row
        for row in db.query(UserModulePermission).filter_by(user_id=target.id).all()
    }
    for key in MODULE_KEYS:
        row = existing.get(key)
        if row:
            row.allowed = True
            row.created_by = actor.id
            row.updated_at = datetime.utcnow()
        else:
            db.add(UserModulePermission(user_id=target.id, module_key=key, allowed=True, created_by=actor.id))
    target._accessible_module_keys = None


def module_access_counts(db: Session, users: list[User]) -> dict[int, int]:
    enabled = enabled_module_keys(db)
    if not users or not enabled:
        return {user.id: 0 for user in users}
    rows = (
        db.query(UserModulePermission.user_id, UserModulePermission.module_key)
        .filter(
            UserModulePermission.user_id.in_([user.id for user in users]),
            UserModulePermission.allowed.is_(True),
            UserModulePermission.module_key.in_(enabled),
        )
        .all()
    )
    counts = {user.id: 0 for user in users}
    for user_id, _ in rows:
        counts[user_id] += 1
    return counts


def filter_search_results(db: Session, user: User, results: list[dict]) -> list[dict]:
    """Data-minimising hook for current or future global-search providers."""
    allowed = accessible_module_keys(db, user)
    return [result for result in results if result.get("module_key") in allowed]
