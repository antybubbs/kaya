"""Periodic DNS provider collection independent of web request rendering."""

from __future__ import annotations

import asyncio
import logging
import threading
from time import monotonic

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.models import DNSProviderConfig
from app.services.dns_insights import AnalysisAlreadyRunning, analyse_provider
from app.services.site_settings import get_site_settings
from app.services.dns_clients import prune_client_history, reconcile_managed_matches


logger = logging.getLogger(__name__)
STARTUP_DELAY_SECONDS = 15
DISABLED_RECHECK_SECONDS = 30
MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 86400
_pass_lock = threading.Lock()


def collector_configuration(db: Session) -> tuple[bool, int, list[int], str]:
    values = get_site_settings(
        db,
        {
            "dns_manager_enabled",
            "dns_collector_enabled",
            "dns_refresh_interval_seconds",
            "dns_known_hostnames",
        },
    )
    try:
        interval = max(
            MIN_INTERVAL_SECONDS,
            min(int(values["dns_refresh_interval_seconds"] or "300"), MAX_INTERVAL_SECONDS),
        )
    except (TypeError, ValueError):
        interval = 300
    enabled = values["dns_manager_enabled"] == "1" and values["dns_collector_enabled"] == "1"
    provider_ids = []
    if enabled:
        provider_ids = [
            row.id
            for row in db.query(DNSProviderConfig.id)
            .filter(DNSProviderConfig.is_enabled == True)  # noqa: E712
            .order_by(DNSProviderConfig.id.asc())
        ]
    return enabled, interval, provider_ids, values["dns_known_hostnames"] or "[]"


def collect_provider(provider_id: int, known_hostnames_raw: str, session_factory=SessionLocal) -> None:
    db = session_factory()
    try:
        provider = db.get(DNSProviderConfig, provider_id)
        if not provider or not provider.is_enabled:
            return
        analyse_provider(db, provider, known_hostnames_raw=known_hostnames_raw)
    except AnalysisAlreadyRunning:
        logger.info("DNS collection skipped because analysis is already running", extra={"provider_id": provider_id})
    except Exception:
        db.rollback()
        logger.exception("DNS background collection failed", extra={"provider_id": provider_id})
    finally:
        db.close()


def run_dns_collection_pass(session_factory=SessionLocal) -> int:
    """Collect every enabled provider once and return the next check delay."""
    if not _pass_lock.acquire(blocking=False):
        return DISABLED_RECHECK_SECONDS
    try:
        db = session_factory()
        try:
            enabled, interval, provider_ids, known_hostnames_raw = collector_configuration(db)
        finally:
            db.close()
        if not enabled:
            return DISABLED_RECHECK_SECONDS
        for provider_id in provider_ids:
            collect_provider(provider_id, known_hostnames_raw, session_factory)
        maintenance_db = session_factory()
        try:
            reconcile_managed_matches(maintenance_db)
            prune_client_history(maintenance_db)
        finally:
            maintenance_db.close()
        return interval
    finally:
        _pass_lock.release()


async def dns_collector_loop() -> None:
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        started = monotonic()
        delay = await asyncio.to_thread(run_dns_collection_pass)
        await asyncio.sleep(max(1, delay - (monotonic() - started)))
