from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import logging
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.models.models import DNSInsight, DNSProviderConfig, DNSStatisticsSnapshot, User
from app.services.dns_insights import DEFAULT_THRESHOLDS, SEVERITY_LABELS
from app.services.site_settings import get_site_setting


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DNSFeaturedInsightSummary:
    id: int
    severity: str
    severity_label: str
    title: str
    summary: str
    target: str


@dataclass(frozen=True)
class DNSDashboardSummary:
    configured: bool
    provider_id: int | None
    provider_name: str | None
    provider_status: str
    provider_status_label: str
    last_updated_at: datetime | None
    queries_today: int | None
    blocked_queries_today: int | None
    blocked_percentage: float | None
    active_clients_24h: int | None
    critical_insight_count: int
    warning_insight_count: int
    featured_insight: DNSFeaturedInsightSummary | None
    dashboard_target: str
    settings_target: str
    reports_target: str
    blocked_target: str
    clients_target: str
    attention_target: str
    error: bool = False

    @property
    def attention_count(self) -> int:
        return self.critical_insight_count + self.warning_insight_count


def _selected_provider(db: Session) -> DNSProviderConfig | None:
    providers = (
        db.query(DNSProviderConfig)
        .filter(DNSProviderConfig.is_enabled == True)  # noqa: E712
        .order_by(DNSProviderConfig.name.asc())
        .all()
    )
    preferred = (get_site_setting(db, "dns_default_provider_id") or "").strip()
    if preferred.isdigit():
        selected = next((provider for provider in providers if provider.id == int(preferred)), None)
        if selected:
            return selected
    return providers[0] if providers else None


def _site_timezone(db: Session) -> ZoneInfo:
    name = (get_site_setting(db, "timezone_region") or "UTC").strip()
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def _snapshot_local_date(value: datetime, zone: ZoneInfo):
    aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return aware.astimezone(zone).date()


def _client_identities_24h(db: Session, provider_id: int, now: datetime) -> int | None:
    rows = (
        db.query(DNSStatisticsSnapshot.client_aggregates_json)
        .filter(
            DNSStatisticsSnapshot.provider_id == provider_id,
            DNSStatisticsSnapshot.provider_connected == True,  # noqa: E712
            DNSStatisticsSnapshot.period_end >= now - timedelta(hours=24),
        )
        .order_by(DNSStatisticsSnapshot.period_end.desc())
        .limit(25)
        .all()
    )
    if not rows:
        return None
    identities: set[str] = set()
    supported = False
    for (raw,) in rows:
        if not raw:
            continue
        try:
            values = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(values, dict):
            supported = True
            identities.update(str(key) for key in values if str(key).strip())
    return len(identities) if supported else None


def get_featured_dns_insight(db: Session, provider_id: int) -> DNSFeaturedInsightSummary | None:
    severity_rank = case(
        (DNSInsight.severity == "critical", 0),
        (DNSInsight.severity == "warning", 1),
        (DNSInsight.severity == "information", 2),
        else_=3,
    )
    actionable_rank = case((DNSInsight.action_type.is_not(None), 0), else_=1)
    insight = (
        db.query(DNSInsight)
        .filter(
            DNSInsight.provider_id == provider_id,
            DNSInsight.status == "active",
            DNSInsight.dismissed_at.is_(None),
            DNSInsight.acknowledged_at.is_(None),
        )
        .order_by(severity_rank.asc(), DNSInsight.last_detected_at.desc(), actionable_rank.asc(), DNSInsight.id.desc())
        .first()
    )
    if not insight:
        return None
    return DNSFeaturedInsightSummary(
        id=insight.id,
        severity=insight.severity,
        severity_label=SEVERITY_LABELS.get(insight.severity, insight.severity.title()),
        title=insight.title,
        summary=insight.summary,
        target=f"/networking/dns-manager?tab=insights&insight_status=active#dns-insight-{insight.id}",
    )


def _provider_status(provider: DNSProviderConfig, snapshot: DNSStatisticsSnapshot | None, now: datetime) -> tuple[str, str]:
    if provider.last_status == "error":
        return "disconnected", "Disconnected"
    if not snapshot:
        return ("degraded", "Degraded") if provider.last_status == "online" else ("disconnected", "Disconnected")
    if now - snapshot.period_end > timedelta(hours=DEFAULT_THRESHOLDS.provider_stale_hours):
        return "stale", "Data stale"
    capabilities: set[str] = set()
    try:
        raw_capabilities = json.loads(snapshot.capabilities_json or "[]")
        if isinstance(raw_capabilities, list):
            capabilities = {str(value) for value in raw_capabilities}
    except (TypeError, ValueError):
        pass
    if provider.last_status != "online":
        return "degraded", "Degraded"
    if capabilities and not {"stats", "queries", "clients"}.issubset(capabilities):
        return "degraded", "Degraded"
    return "connected", "Connected"


def _empty_summary(*, error: bool = False) -> DNSDashboardSummary:
    return DNSDashboardSummary(
        configured=False,
        provider_id=None,
        provider_name=None,
        provider_status="not_configured" if not error else "unavailable",
        provider_status_label="Not configured" if not error else "Unavailable",
        last_updated_at=None,
        queries_today=None,
        blocked_queries_today=None,
        blocked_percentage=None,
        active_clients_24h=None,
        critical_insight_count=0,
        warning_insight_count=0,
        featured_insight=None,
        dashboard_target="/networking/dns-manager",
        settings_target="/system/site-administration?tab=module-dns-manager",
        reports_target="/networking/dns-manager?tab=reports",
        blocked_target="/networking/dns-manager?tab=query-log",
        clients_target="/networking/dns-manager?tab=clients",
        attention_target="/networking/dns-manager?tab=insights&insight_status=active&insight_severity=attention",
        error=error,
    )


def get_dns_dashboard_summary(db: Session, user: User) -> DNSDashboardSummary:
    del user  # Dashboard and DNS Manager currently share the same authenticated-view permission.
    try:
        provider = _selected_provider(db)
        if not provider:
            return _empty_summary()
        latest = (
            db.query(DNSStatisticsSnapshot)
            .filter(DNSStatisticsSnapshot.provider_id == provider.id, DNSStatisticsSnapshot.provider_connected == True)  # noqa: E712
            .order_by(DNSStatisticsSnapshot.period_end.desc())
            .first()
        )
        now = datetime.utcnow()
        status, status_label = _provider_status(provider, latest, now)
        queries_today = blocked_today = None
        blocked_percentage = None
        site_zone = _site_timezone(db)
        if latest and _snapshot_local_date(latest.period_end, site_zone) == datetime.now(site_zone).date():
            queries_today = latest.total_queries
            blocked_today = latest.blocked_queries
            if queries_today is not None and blocked_today is not None and queries_today > 0:
                blocked_percentage = blocked_today / queries_today * 100
            elif queries_today == 0 and blocked_today is not None:
                blocked_percentage = 0.0
        counts = dict(
            db.query(DNSInsight.severity, func.count(DNSInsight.id))
            .filter(
                DNSInsight.provider_id == provider.id,
                DNSInsight.status == "active",
                DNSInsight.acknowledged_at.is_(None),
                DNSInsight.dismissed_at.is_(None),
                DNSInsight.severity.in_(["critical", "warning"]),
            )
            .group_by(DNSInsight.severity)
            .all()
        )
        return DNSDashboardSummary(
            configured=True,
            provider_id=provider.id,
            provider_name=provider.name,
            provider_status=status,
            provider_status_label=status_label,
            last_updated_at=latest.period_end if latest else None,
            queries_today=queries_today,
            blocked_queries_today=blocked_today,
            blocked_percentage=blocked_percentage,
            active_clients_24h=_client_identities_24h(db, provider.id, now),
            critical_insight_count=int(counts.get("critical", 0)),
            warning_insight_count=int(counts.get("warning", 0)),
            featured_insight=get_featured_dns_insight(db, provider.id),
            dashboard_target="/networking/dns-manager",
            settings_target="/system/site-administration?tab=module-dns-manager",
            reports_target="/networking/dns-manager?tab=reports",
            blocked_target="/networking/dns-manager?tab=query-log",
            clients_target="/networking/dns-manager?tab=clients",
            attention_target="/networking/dns-manager?tab=insights&insight_status=active&insight_severity=attention",
        )
    except Exception:
        logger.exception("Unable to build DNS dashboard summary")
        return _empty_summary(error=True)
