"""Data Integrity audit runs, persistent findings and their lifecycle.

Audits are read-only: checks run in short read transactions and only the
module's own run and finding tables are written. A finding has a stable key;
repeated audits update it instead of creating duplicates. It becomes Resolved
only when a complete check (or a targeted re-check) no longer detects it, and
an ignored or resolved finding reopens when its evidence changes or the
problem returns. Visibility follows the administrator's existing module
grants: a finding type is shown only to administrators who can open every
module it describes.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import logging
from time import monotonic

from sqlalchemy import case, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.models import (
    DataIntegrityFinding,
    DataIntegrityFindingEvent,
    DataIntegrityRun,
    RemoteManagerSetting,
    User,
)
from app.services.asset_identity import _normalise_evidence, _normalise_ip
from app.services.audit import write_audit
from app.services.data_integrity_checks import (
    CATEGORY_LABELS,
    CHECK_SET_VERSION,
    CHECKS,
    FINDING_TYPES,
    SEVERITY_RANK,
    Detection,
    _bounded,
    _hash,
    detect_subject,
)
from app.services.modules import accessible_module_keys
from app.services.notification_outbox import enqueue_notification
from app.services.site_settings import get_site_settings

logger = logging.getLogger(__name__)

STATUSES = ("open", "needs_review", "resolved", "ignored")
ACTIVE_STATUSES = ("open", "needs_review")
STATUS_LABELS = {"open": "Open", "needs_review": "Needs review", "resolved": "Resolved", "ignored": "Ignored"}
AUDIT_SLOT = "audit"
STALE_AFTER = timedelta(minutes=10)
PERSIST_BATCH = 200
MAX_EVIDENCE_CHARS = 60_000
PAGE_SIZES = (25, 50, 100)
MAX_EXPORT_ROWS = 5000
SCHEDULE_CHOICES = {"0": "Disabled", "6": "Every 6 hours", "12": "Every 12 hours", "24": "Daily", "168": "Weekly"}
SORTS = {"severity", "detected", "first_detected", "status", "type"}
LOOP_SECONDS = 15
STARTUP_DELAY_SECONDS = 45
NOTIFICATION_EVENT = "system.data_integrity.critical_findings"
NOTIFICATION_ROUTE = "/data/data-integrity"


class AuditAlreadyRunning(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.utcnow()  # noqa: DTZ003 - Kaya stores naive UTC


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _loads(value: str | None, fallback):
    try:
        return json.loads(value) if value else fallback
    except (TypeError, ValueError):
        return fallback


def finding_subject(finding: DataIntegrityFinding) -> str:
    return str(_loads(finding.evidence_json, {}).get("subject") or "")


def finding_evidence(finding: DataIntegrityFinding) -> dict:
    return _loads(finding.evidence_json, {})


# ------------------------------------------------------------- visibility


def visible_types(db: Session, user: User | None) -> list[str]:
    """Finding types this administrator may see: every module they describe must be accessible."""
    if not user or not user.is_active or user.role != "admin":
        return []
    access = accessible_module_keys(db, user)
    return [key for key, definition in FINDING_TYPES.items() if set(definition.modules) <= access]


def visible_finding(db: Session, user: User | None, finding_id: int) -> DataIntegrityFinding | None:
    finding = db.get(DataIntegrityFinding, finding_id)
    if finding is None or finding.finding_type not in visible_types(db, user):
        return None
    return finding


# ------------------------------------------------------------- events and audit


def record_event(db: Session, finding: DataIntegrityFinding, event: str, *, run_id: int | None = None, actor: User | None = None, detail: dict | None = None) -> None:
    text = _json(detail or {})
    db.add(DataIntegrityFindingEvent(
        finding_id=finding.id, run_id=run_id, event=event[:40], actor_id=actor.id if actor else None,
        detail_json=text if len(text) <= 4000 else _json({"truncated": True}),
    ))


def audit_or_fail(db: Session, actor: User | None, action: str, entity_id: str, detail: str, metadata: dict) -> None:
    """Write a mandatory audit record in the caller's transaction, or abort it."""
    if write_audit(db, actor, action, "data_integrity_finding", entity_id, detail=detail, metadata=metadata, force=True, commit=False) is None:
        raise RuntimeError("The Data Integrity action could not be audited.")


# ------------------------------------------------------------- finding lifecycle


def _evidence_json(detection: Detection) -> str:
    text = _json({"subject": detection.subject, **detection.evidence})
    if len(text) > MAX_EVIDENCE_CHARS:
        text = _json({"subject": detection.subject, "truncated": True, "note": "Evidence exceeded the stored size; re-run the check to inspect it."})
    return text


def apply_detection(db: Session, finding: DataIntegrityFinding | None, detection: Detection, *, run: DataIntegrityRun | None, now: datetime) -> tuple[DataIntegrityFinding | None, str | None]:
    """Create or update the logical finding for a detection; return (finding, outcome)."""
    definition = detection.definition
    initial = detection.status or definition.initial_status
    fields = {
        "finding_type": detection.finding_type,
        "category": definition.category,
        "severity": detection.severity or definition.severity,
        "required_modules": ",".join(definition.modules),
        "title": detection.title[:255],
        "affected_label": detection.affected_label[:255] or detection.title[:255],
        "search_text": detection.search_text(),
        "asset_id": detection.asset_id,
        "mac": (detection.mac or None) and detection.mac[:17],
        "ip_address": (detection.ip_address or None) and detection.ip_address[:80],
        "hostname": (detection.hostname or None) and detection.hostname[:255],
        "evidence_json": _evidence_json(detection),
        "repairable": bool(detection.repairable and definition.actions),
        "bulk_repairable": bool(detection.bulk_repairable and definition.bulk_action and detection.repairable),
        "last_detected_at": now,
    }
    run_id = run.id if run else None
    if finding is None:
        finding = DataIntegrityFinding(
            finding_key=detection.key, status=initial, first_detected_at=now, evidence_fingerprint=detection.fingerprint,
            last_run_id=run_id, created_at=now, updated_at=now, **fields,
        )
        db.add(finding)
        db.flush()
        record_event(db, finding, "detected", run_id=run_id, detail={"fingerprint": detection.fingerprint})
        return finding, "new"
    run_started = run.started_at if run else None
    # A scan that began before an administrator resolved or ignored the finding
    # saw the earlier state; it must not undo the newer decision.
    if run_started and finding.status == "resolved" and finding.resolved_at and finding.resolved_at >= run_started:
        return finding, None
    if run_started and finding.status == "ignored" and finding.ignored_at and finding.ignored_at >= run_started:
        return finding, None
    changed = finding.evidence_fingerprint != detection.fingerprint
    previous = finding.status
    for name, value in fields.items():
        setattr(finding, name, value)
    if run_id is not None:
        finding.last_run_id = run_id
    outcome = None
    if previous == "resolved":
        finding.status = initial
        finding.reopened_count = (finding.reopened_count or 0) + 1
        record_event(db, finding, "reopened", run_id=run_id, detail={"reason": "detected_again", "previous_resolution": finding.resolution})
        finding.resolved_at = finding.resolved_run_id = finding.resolution = None
        outcome = "reopened"
    elif previous == "ignored":
        if detection.fingerprint != finding.ignored_fingerprint:
            record_event(db, finding, "reopened", run_id=run_id, detail={"reason": "evidence_changed", "ignore_reason": finding.ignore_reason})
            finding.status = "needs_review"
            finding.reopened_count = (finding.reopened_count or 0) + 1
            finding.ignored_by = finding.ignored_at = finding.ignore_reason = finding.ignored_fingerprint = None
            outcome = "reopened"
    else:
        finding.status = initial
        if changed:
            record_event(db, finding, "evidence_changed", run_id=run_id, detail={"fingerprint": detection.fingerprint})
    finding.evidence_fingerprint = detection.fingerprint
    finding.updated_at = now
    return finding, outcome


def resolve_finding(db: Session, finding: DataIntegrityFinding, *, now: datetime, resolution: str, run_id: int | None = None, actor: User | None = None) -> bool:
    if finding.status == "resolved":
        return False
    finding.status = "resolved"
    finding.resolved_at = now
    finding.resolved_run_id = run_id
    finding.resolution = resolution[:60]
    finding.updated_at = now
    record_event(db, finding, "resolved", run_id=run_id, actor=actor, detail={"resolution": resolution})
    return True


def revalidate_finding(db: Session, finding: DataIntegrityFinding, *, actor: User | None = None, now: datetime | None = None, resolution: str = "verified_absent") -> dict:
    """Re-run the finding's check for its subject and update the finding (caller commits)."""
    now = now or _now()
    detection = detect_subject(db, finding.finding_type, finding_subject(finding), now=now)
    if detection is None:
        resolve_finding(db, finding, now=now, resolution=resolution, actor=actor)
        return {"detected": False, "status": finding.status}
    _finding, outcome = apply_detection(db, finding, detection, run=None, now=now)
    return {"detected": True, "status": finding.status, "outcome": outcome, "fingerprint": detection.fingerprint}


def _clean_reason(value: str | None) -> str:
    text = " ".join(str(value or "").split())
    if not 5 <= len(text) <= 500:
        raise ValueError("Give a reason of 5 to 500 characters.")
    return text


def ignore_finding(db: Session, finding: DataIntegrityFinding, actor: User, reason: str, *, event: str = "ignored", now: datetime | None = None) -> dict:
    """Ignore (or acknowledge) a finding against its current evidence. Commits."""
    now = now or _now()
    reason = _clean_reason(reason)
    state = revalidate_finding(db, finding, actor=actor, now=now)
    if not state["detected"]:
        audit_or_fail(db, actor, "data_integrity_revalidate", str(finding.id), "Finding no longer detected", {"finding_id": finding.id, "finding_type": finding.finding_type})
        db.commit()
        return {"status": finding.status, "message": "The finding is no longer detected, so it was resolved instead."}
    if finding.status == "ignored" and finding.ignored_fingerprint == finding.evidence_fingerprint:
        db.rollback()
        return {"status": "ignored", "message": "The finding is already ignored for this evidence."}
    finding.status = "ignored"
    finding.ignored_by = actor.id
    finding.ignored_at = now
    finding.ignore_reason = reason
    finding.ignored_fingerprint = finding.evidence_fingerprint
    finding.updated_at = now
    record_event(db, finding, event, actor=actor, detail={"reason": reason, "fingerprint": finding.evidence_fingerprint})
    audit_or_fail(db, actor, f"data_integrity_{event}", str(finding.id), f"Finding {event}", {"finding_id": finding.id, "finding_type": finding.finding_type})
    db.commit()
    return {"status": "ignored", "message": "Finding retained as reviewed." if event != "ignored" else "Finding ignored."}


def reopen_finding(db: Session, finding: DataIntegrityFinding, actor: User, *, now: datetime | None = None) -> dict:
    now = now or _now()
    if finding.status != "ignored":
        raise ValueError("Only an ignored finding can be reopened.")
    record_event(db, finding, "reopened", actor=actor, detail={"reason": "administrator", "ignore_reason": finding.ignore_reason})
    finding.status = FINDING_TYPES[finding.finding_type].initial_status
    finding.ignored_by = finding.ignored_at = finding.ignore_reason = finding.ignored_fingerprint = None
    finding.reopened_count = (finding.reopened_count or 0) + 1
    state = revalidate_finding(db, finding, actor=actor, now=now)
    audit_or_fail(db, actor, "data_integrity_reopen", str(finding.id), "Finding reopened", {"finding_id": finding.id, "finding_type": finding.finding_type})
    db.commit()
    return {"status": finding.status, "message": "Finding reopened." if state["detected"] else "Finding reopened, then resolved: it is no longer detected."}


# ------------------------------------------------------------- audit runs


def recover_stale_runs(db: Session, *, now: datetime | None = None) -> int:
    """Mark queued or running audits without a recent heartbeat as interrupted."""
    now = now or _now()
    changed = 0
    for run in db.query(DataIntegrityRun).filter(DataIntegrityRun.active_slot.isnot(None)).limit(10).all():
        last = run.heartbeat_at or run.started_at or run.queued_at
        if last and last < now - STALE_AFTER:
            run.status = "interrupted"
            run.active_slot = None
            run.completed_at = now
            run.errors_json = _json([*_loads(run.errors_json, []), {"check": None, "error": "interrupted", "detail": "The audit stopped reporting progress and was marked interrupted."}])
            changed += 1
    if changed:
        db.commit()
    return changed


def queue_audit(db: Session, user: User | None, *, trigger: str = "manual", now: datetime | None = None) -> DataIntegrityRun:
    """Queue one full audit. Only one audit may be queued or running at a time."""
    if trigger not in {"manual", "scheduled"}:
        raise ValueError("Unsupported audit trigger.")
    now = now or _now()
    recover_stale_runs(db, now=now)
    run = DataIntegrityRun(
        trigger=trigger, initiated_by=user.id if user else None, status="queued", active_slot=AUDIT_SLOT,
        check_set_version=CHECK_SET_VERSION, queued_at=now, progress_total=len(CHECKS),
    )
    db.add(run)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise AuditAlreadyRunning("An audit is already queued or running.") from exc
    if write_audit(db, user, "data_integrity_audit_requested", "data_integrity_run", str(run.id), detail=f"{trigger.title()} Data Integrity audit queued",
                   metadata={"trigger": trigger, "run_uuid": run.run_uuid}, force=True, commit=False) is None:
        db.rollback()
        raise RuntimeError("The audit request could not be audited.")
    db.commit()
    return run


def claim_queued_run(db: Session, *, now: datetime | None = None) -> int | None:
    now = now or _now()
    row = db.query(DataIntegrityRun.id).filter(DataIntegrityRun.status == "queued").order_by(DataIntegrityRun.id.asc()).first()
    if row is None:
        db.rollback()
        return None
    claimed = db.query(DataIntegrityRun).filter(DataIntegrityRun.id == row.id, DataIntegrityRun.status == "queued").update(
        {DataIntegrityRun.status: "running", DataIntegrityRun.started_at: now, DataIntegrityRun.heartbeat_at: now}, synchronize_session=False,
    )
    db.commit()
    return row.id if claimed else None


def _heartbeat(session_factory, run_id: int, done: int) -> bool:
    with session_factory() as db:
        updated = db.query(DataIntegrityRun).filter(DataIntegrityRun.id == run_id, DataIntegrityRun.status == "running").update(
            {DataIntegrityRun.progress_done: done, DataIntegrityRun.heartbeat_at: _now()}, synchronize_session=False,
        )
        db.commit()
        return bool(updated)


def _type_counts(db: Session, statuses, *, severity: str | None = None) -> dict[str, int]:
    query = db.query(DataIntegrityFinding.finding_type, func.count(DataIntegrityFinding.id)).filter(DataIntegrityFinding.status.in_(statuses))
    if severity:
        query = query.filter(DataIntegrityFinding.severity == severity)
    return {key: count for key, count in query.group_by(DataIntegrityFinding.finding_type)}


def _notify_critical(db: Session, run: DataIntegrityRun) -> int:
    if get_site_settings(db, {"data_integrity_notify_critical"})["data_integrity_notify_critical"] != "1":
        return 0
    rows = db.query(DataIntegrityFinding).filter(
        DataIntegrityFinding.status.in_(ACTIVE_STATUSES),
        DataIntegrityFinding.severity == "critical",
        DataIntegrityFinding.last_run_id == run.id,
        or_(DataIntegrityFinding.notified_fingerprint.is_(None), DataIntegrityFinding.notified_fingerprint != DataIntegrityFinding.evidence_fingerprint),
    ).order_by(DataIntegrityFinding.id.asc()).limit(500).all()
    if not rows:
        return 0
    key = _hash(sorted((row.finding_key, row.evidence_fingerprint) for row in rows))
    enqueue_notification(
        db,
        event_type_id=NOTIFICATION_EVENT,
        title=f"{len(rows)} new or changed critical data integrity finding{'s' if len(rows) != 1 else ''}",
        message="A Data Integrity audit found new or changed critical inconsistencies. Review them under Data Management → Data Integrity.",
        target_route=NOTIFICATION_ROUTE,
        source_entity_type="data_integrity_run",
        source_entity_id=run.id,
        deduplication_key=f"data-integrity:{key[:48]}",
        severity="critical",
        metadata={"run_id": run.id, "finding_count": len(rows)},
    )
    for row in rows:
        row.notified_fingerprint = row.evidence_fingerprint
    return len(rows)


def execute_run(run_id: int, session_factory=SessionLocal, *, limit: int | None = None) -> str:
    """Execute a claimed audit run. Checks are read-only; only Data Integrity tables are written."""
    started = monotonic()
    with session_factory() as db:
        run = db.get(DataIntegrityRun, run_id)
        if run is None or run.status != "running":
            return "skipped"
        now = run.started_at or _now()
        db.rollback()
    results, errors, examined = {}, [], 0
    bound = _bounded(limit)
    try:
        with session_factory() as reader:
            for index, (finding_type, check) in enumerate(CHECKS.items(), start=1):
                try:
                    result = check(reader, now, bound, None)
                    results[finding_type] = result
                    examined += result.examined
                    if result.truncated:
                        errors.append({"check": finding_type, "error": "truncated", "detail": f"Stopped at {bound} records; the rest were not evaluated."})
                except Exception as exc:  # one failing check must not hide the others
                    logger.exception("data_integrity.check_failed check=%s run_id=%s", finding_type, run_id)
                    errors.append({"check": finding_type, "error": type(exc).__name__, "detail": "The check failed; its findings were not updated."})
                finally:
                    reader.rollback()  # end the read transaction between checks
                if not _heartbeat(session_factory, run_id, index):
                    return "abandoned"
        with session_factory() as db:
            run = db.get(DataIntegrityRun, run_id)
            if run is None or run.status != "running":
                return "abandoned"
            detections = [detection for result in results.values() for detection in result.detections]
            counters = {"new": 0, "reopened": 0, "resolved": 0}
            by_type = {"new": {}, "reopened": {}, "resolved": {}}
            for start in range(0, len(detections), PERSIST_BATCH):
                batch = detections[start:start + PERSIST_BATCH]
                existing = {row.finding_key: row for row in db.query(DataIntegrityFinding).filter(
                    DataIntegrityFinding.finding_key.in_([detection.key for detection in batch])
                )}
                for detection in batch:
                    finding, outcome = apply_detection(db, existing.get(detection.key), detection, run=run, now=now)
                    if outcome in counters:
                        counters[outcome] += 1
                        by_type[outcome][detection.finding_type] = by_type[outcome].get(detection.finding_type, 0) + 1
                    if finding is not None:
                        existing[detection.key] = finding
                run.heartbeat_at = _now()
                db.commit()
            detected_keys = {detection.key for detection in detections}
            for finding_type, result in results.items():
                if result.truncated:
                    continue  # absence beyond the limit is not evidence of resolution
                last_id = 0
                while True:
                    stale = db.query(DataIntegrityFinding).filter(
                        DataIntegrityFinding.finding_type == finding_type,
                        DataIntegrityFinding.status.in_((*ACTIVE_STATUSES, "ignored")),
                        DataIntegrityFinding.last_detected_at < now,
                        DataIntegrityFinding.id > last_id,
                    ).order_by(DataIntegrityFinding.id.asc()).limit(PERSIST_BATCH).all()
                    if not stale:
                        break
                    last_id = stale[-1].id
                    for finding in stale:
                        if finding.finding_key in detected_keys or (finding.ignored_at and finding.ignored_at >= now):
                            continue  # still present, or decided after this scan began
                        resolve_finding(db, finding, now=_now(), resolution="not_detected", run_id=run.id)
                        counters["resolved"] += 1
                        by_type["resolved"][finding_type] = by_type["resolved"].get(finding_type, 0) + 1
                    db.commit()
            active = _type_counts(db, ACTIVE_STATUSES)
            critical = _type_counts(db, ACTIVE_STATUSES, severity="critical")
            run.findings_total = len(detections)
            run.records_examined = examined
            run.new_count, run.reopened_count, run.resolved_count = counters["new"], counters["reopened"], counters["resolved"]
            run.open_count = sum(active.values())
            run.critical_count = sum(critical.values())
            run.counts_json = _json({
                "active_by_type": active, "critical_by_type": critical,
                "new_by_type": by_type["new"], "reopened_by_type": by_type["reopened"], "resolved_by_type": by_type["resolved"],
            })
            run.errors_json = _json(errors)
            _notify_critical(db, run)
            run.status = "completed" if not errors else "incomplete"
            run.active_slot = None
            run.completed_at = _now()
            run.progress_done = len(CHECKS)
            run.duration_ms = int((monotonic() - started) * 1000)
            db.commit()
            return run.status
    except Exception:
        logger.exception("data_integrity.run_failed run_id=%s", run_id)
        with session_factory() as db:
            run = db.get(DataIntegrityRun, run_id)
            if run is not None and run.active_slot is not None:
                run.status = "failed"
                run.active_slot = None
                run.completed_at = _now()
                run.duration_ms = int((monotonic() - started) * 1000)
                run.errors_json = _json([*errors, {"check": None, "error": "failed", "detail": "The audit could not be completed; its results are not a complete assessment."}])
                db.commit()
        return "failed"


# ------------------------------------------------------------- scheduling


def schedule_settings(db: Session) -> dict:
    values = get_site_settings(db, {"data_integrity_schedule_hours", "data_integrity_notify_critical"})
    hours = values["data_integrity_schedule_hours"] if values["data_integrity_schedule_hours"] in SCHEDULE_CHOICES else "24"
    return {"schedule_hours": hours, "notify_critical": values["data_integrity_notify_critical"] == "1", "choices": SCHEDULE_CHOICES}


def update_schedule(db: Session, actor: User, *, schedule_hours: str, notify_critical: bool) -> dict:
    if schedule_hours not in SCHEDULE_CHOICES:
        raise ValueError("Choose a supported audit schedule.")
    before = schedule_settings(db)
    for key, value in (("data_integrity_schedule_hours", schedule_hours), ("data_integrity_notify_critical", "1" if notify_critical else "0")):
        row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == key).first()
        if row is None:
            db.add(RemoteManagerSetting(key=key, value=value))
        else:
            row.value = value
    if write_audit(db, actor, "data_integrity_schedule_updated", "site_setting", "data_integrity", detail="Updated Data Integrity audit schedule",
                   metadata={"schedule_hours_before": before["schedule_hours"], "schedule_hours": schedule_hours, "notify_critical": notify_critical},
                   force=True, commit=False) is None:
        db.rollback()
        raise RuntimeError("The schedule change could not be audited.")
    db.commit()
    db.info.pop("site_settings", None)
    return schedule_settings(db)


def scheduled_audit_due(db: Session, *, now: datetime | None = None) -> bool:
    now = now or _now()
    hours = int(schedule_settings(db)["schedule_hours"])
    if hours <= 0:
        return False
    latest = db.query(func.max(DataIntegrityRun.queued_at)).scalar()
    return latest is None or latest <= now - timedelta(hours=hours)


def run_data_integrity_pass(session_factory=SessionLocal) -> int:
    """One worker pass: recover stale runs, queue a due scheduled audit, execute queued audits."""
    with session_factory() as db:
        recover_stale_runs(db)
        if scheduled_audit_due(db):
            try:
                queue_audit(db, None, trigger="scheduled")
            except AuditAlreadyRunning:
                pass
    with session_factory() as db:
        run_id = claim_queued_run(db)
    if run_id is not None:
        execute_run(run_id, session_factory)
    return LOOP_SECONDS


async def data_integrity_loop() -> None:
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        started = monotonic()
        try:
            delay = await asyncio.to_thread(run_data_integrity_pass)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Data Integrity worker pass failed; retrying")
            delay = LOOP_SECONDS * 4
        await asyncio.sleep(max(1, delay - (monotonic() - started)))


# ------------------------------------------------------------- queries for the frontend


@dataclass(frozen=True)
class FindingFilters:
    severity: str = ""
    category: str = ""
    finding_type: str = ""
    status: str = "active"
    asset: str = ""
    mac: str = ""
    ip: str = ""
    hostname: str = ""
    q: str = ""
    sort: str = "severity"
    direction: str = "desc"

    @classmethod
    def from_values(cls, values) -> FindingFilters:
        def clean(name: str, maximum: int = 120) -> str:
            return " ".join(str(values.get(name) or "").split())[:maximum]
        severity = clean("severity")
        category = clean("category")
        finding_type = clean("finding_type")
        status = clean("status") or "active"
        sort = clean("sort") or "severity"
        direction = clean("direction") or "desc"
        return cls(
            severity=severity if severity in SEVERITY_RANK else "",
            category=category if category in CATEGORY_LABELS else "",
            finding_type=finding_type if finding_type in FINDING_TYPES else "",
            status=status if status in (*STATUSES, "active", "all") else "active",
            asset=clean("asset"), mac=clean("mac", 40), ip=clean("ip", 80), hostname=clean("hostname", 255), q=clean("q", 255),
            sort=sort if sort in SORTS else "severity",
            direction=direction if direction in {"asc", "desc"} else "desc",
        )

    def query_values(self) -> dict[str, str]:
        return {key: value for key, value in self.__dict__.items() if value}


def finding_query(db: Session, user: User, filters: FindingFilters):
    types = visible_types(db, user)
    query = db.query(DataIntegrityFinding).filter(DataIntegrityFinding.finding_type.in_(types or ["-"]))
    if filters.status == "active":
        query = query.filter(DataIntegrityFinding.status.in_(ACTIVE_STATUSES))
    elif filters.status != "all":
        query = query.filter(DataIntegrityFinding.status == filters.status)
    if filters.severity:
        query = query.filter(DataIntegrityFinding.severity == filters.severity)
    if filters.category:
        query = query.filter(DataIntegrityFinding.category == filters.category)
    if filters.finding_type:
        query = query.filter(DataIntegrityFinding.finding_type == filters.finding_type)
    if filters.mac:
        try:
            mac = _normalise_evidence("mac", filters.mac)
        except ValueError:
            mac = filters.mac.casefold()
        query = query.filter(or_(DataIntegrityFinding.mac == mac, DataIntegrityFinding.search_text.contains(mac, autoescape=True)))
    if filters.ip:
        try:
            address = _normalise_ip(filters.ip)[0]
        except ValueError:
            address = filters.ip.casefold()
        query = query.filter(or_(DataIntegrityFinding.ip_address == address, DataIntegrityFinding.search_text.contains(address, autoescape=True)))
    for value in (filters.asset, filters.hostname, filters.q):
        if value:
            query = query.filter(DataIntegrityFinding.search_text.contains(value.casefold(), autoescape=True))
    rank = case((DataIntegrityFinding.severity == "critical", 3), (DataIntegrityFinding.severity == "warning", 2), else_=1)
    status_rank = case((DataIntegrityFinding.status == "needs_review", 0), (DataIntegrityFinding.status == "open", 1), (DataIntegrityFinding.status == "ignored", 2), else_=3)
    column = {
        "severity": rank, "detected": DataIntegrityFinding.last_detected_at, "first_detected": DataIntegrityFinding.first_detected_at,
        "status": status_rank, "type": DataIntegrityFinding.finding_type,
    }[filters.sort]
    ordered = column.desc() if filters.direction == "desc" else column.asc()
    return query.order_by(ordered, DataIntegrityFinding.last_detected_at.desc(), DataIntegrityFinding.id.desc())


def finding_row(finding: DataIntegrityFinding) -> dict:
    definition = FINDING_TYPES[finding.finding_type]
    return {
        "id": finding.id,
        "finding_type": finding.finding_type,
        "type_label": definition.label,
        "category": finding.category,
        "category_label": CATEGORY_LABELS.get(finding.category, finding.category),
        "severity": finding.severity,
        "status": finding.status,
        "status_label": STATUS_LABELS.get(finding.status, finding.status),
        "title": finding.title,
        "affected_label": finding.affected_label,
        "first_detected_at": finding.first_detected_at,
        "last_detected_at": finding.last_detected_at,
        "resolved_at": finding.resolved_at,
        "repairable": finding.repairable,
        "bulk_repairable": finding.bulk_repairable and finding.status in ACTIVE_STATUSES,
        "reopened_count": finding.reopened_count or 0,
    }


def list_findings(db: Session, user: User, filters: FindingFilters, *, page: int = 1, per_page: int = 25) -> dict:
    per_page = per_page if per_page in PAGE_SIZES else 25
    query = finding_query(db, user, filters)
    total = query.order_by(None).count()
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(int(page or 1), pages))
    rows = query.offset((page - 1) * per_page).limit(per_page).all()
    return {"rows": [finding_row(row) for row in rows], "total": total, "page": page, "pages": pages, "per_page": per_page}


def _run_payload(run: DataIntegrityRun | None) -> dict | None:
    if run is None:
        return None
    return {
        "id": run.id, "run_uuid": run.run_uuid, "trigger": run.trigger, "status": run.status, "initiated_by": run.initiated_by,
        "queued_at": run.queued_at, "started_at": run.started_at, "completed_at": run.completed_at, "duration_ms": run.duration_ms,
        "progress_done": run.progress_done, "progress_total": run.progress_total or len(CHECKS),
        "records_examined": run.records_examined, "findings_total": run.findings_total, "check_set_version": run.check_set_version,
        "errors": _loads(run.errors_json, []),
    }


def summary(db: Session, user: User, *, now: datetime | None = None) -> dict:
    now = now or _now()
    types = visible_types(db, user)
    counts = {"critical": 0, "warning": 0, "needs_review": 0, "resolved": 0, "ignored": 0, "active": 0}
    for status, severity, count in db.query(DataIntegrityFinding.status, DataIntegrityFinding.severity, func.count(DataIntegrityFinding.id)).filter(
        DataIntegrityFinding.finding_type.in_(types or ["-"])
    ).group_by(DataIntegrityFinding.status, DataIntegrityFinding.severity):
        if status in ACTIVE_STATUSES:
            counts["active"] += count
            if severity in ("critical", "warning"):
                counts[severity] += count
        if status in ("needs_review", "resolved", "ignored"):
            counts[status] += count
    latest = db.query(DataIntegrityRun).filter(DataIntegrityRun.status.in_(("completed", "incomplete"))).order_by(DataIntegrityRun.completed_at.desc(), DataIntegrityRun.id.desc()).first()
    active = db.query(DataIntegrityRun).filter(DataIntegrityRun.active_slot.isnot(None)).order_by(DataIntegrityRun.id.desc()).first()
    last_finished = db.query(DataIntegrityRun).filter(DataIntegrityRun.status.in_(("completed", "incomplete", "failed", "interrupted"))).order_by(DataIntegrityRun.id.desc()).first()
    hours = int(schedule_settings(db)["schedule_hours"]) or 24
    if latest is None:
        freshness = "never"
    elif last_finished is not None and last_finished.status in ("failed", "interrupted") and last_finished.id > latest.id:
        freshness = "failed"
    elif latest.status == "incomplete":
        freshness = "incomplete"
    elif latest.completed_at and latest.completed_at < now - timedelta(hours=hours + 1):
        freshness = "stale"
    else:
        freshness = "current"
    return {"counts": counts, "latest": _run_payload(latest), "active": _run_payload(active), "last_finished": _run_payload(last_finished), "freshness": freshness}


def history(db: Session, user: User, *, limit: int = 30) -> dict:
    """Recent runs with trend counts restricted to the administrator's visible finding types."""
    types = set(visible_types(db, user))
    runs = db.query(DataIntegrityRun).order_by(DataIntegrityRun.id.desc()).limit(max(1, min(limit, 100))).all()
    rows = []
    for run in runs:
        counts = _loads(run.counts_json, {})

        def total(name: str, counts=counts) -> int:
            return sum(value for key, value in (counts.get(name) or {}).items() if key in types)

        by_category: dict[str, int] = {}
        for key, value in (counts.get("active_by_type") or {}).items():
            if key in types:
                category = FINDING_TYPES[key].category
                by_category[category] = by_category.get(category, 0) + value
        rows.append({
            **_run_payload(run),
            "open": total("active_by_type"), "critical": total("critical_by_type"), "new": total("new_by_type"),
            "resolved": total("resolved_by_type"), "reopened": total("reopened_by_type"), "by_category": by_category,
        })
    return {"runs": rows}


EXPORT_COLUMNS = (
    ("id", "Finding ID"), ("severity", "Severity"), ("category_label", "Module"), ("type_label", "Finding"), ("title", "Detail"),
    ("affected_label", "Affected record"), ("status_label", "Status"), ("first_detected_at", "First detected (UTC)"),
    ("last_detected_at", "Last detected (UTC)"), ("resolved_at", "Resolved (UTC)"), ("repairable", "Repairable"),
)


def export_findings(db: Session, user: User, filters: FindingFilters) -> list[DataIntegrityFinding]:
    return finding_query(db, user, filters).limit(MAX_EXPORT_ROWS).all()


def export_record(finding: DataIntegrityFinding) -> dict:
    row = finding_row(finding)
    evidence = finding_evidence(finding)
    return {
        **{key: (value.isoformat() if isinstance(value, datetime) else value) for key, value in row.items()},
        "mac": finding.mac, "ip_address": finding.ip_address, "hostname": finding.hostname, "asset_id": finding.asset_id,
        "resolution": finding.resolution, "ignore_reason": finding.ignore_reason, "evidence": evidence,
    }
