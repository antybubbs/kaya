import asyncio
import json
from datetime import date, datetime, timedelta

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.models import DomainRecord, DomainRecordHistory, RemoteManagerSetting
from app.services.domain_lookup import lookup_domain


POLL_CADENCE_KEY = "domain_poll_cadence"
POLL_CADENCES = {"daily": 1, "weekly": 7, "monthly": 30}
DEFAULT_POLL_CADENCE = "weekly"
LOOP_INTERVAL_SECONDS = 300
STARTUP_DELAY_SECONDS = 60
MAX_CONCURRENT_POLLS = 3
MAX_DOMAINS_PER_PASS = 25

DISCOVERED_FIELDS = {
    "registrar": "Registrar",
    "dns_provider": "DNS Provider",
    "status": "Status",
    "expires_at": "Expiry",
    "nameservers": "Nameservers",
    "dns_records": "DNS Records",
}


def get_poll_cadence(db: Session) -> str:
    row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == POLL_CADENCE_KEY).first()
    value = row.value if row else None
    return value if value in POLL_CADENCES else DEFAULT_POLL_CADENCE


def set_poll_cadence(db: Session, cadence: str) -> None:
    if cadence not in POLL_CADENCES:
        raise ValueError("Choose Daily, Weekly, or Monthly.")
    row = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key == POLL_CADENCE_KEY).first()
    if row:
        row.value = cadence
        row.updated_at = datetime.utcnow()
    else:
        db.add(RemoteManagerSetting(key=POLL_CADENCE_KEY, value=cadence))
    db.commit()


def _json_value(value, fallback):
    if value in (None, ""):
        return fallback
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return fallback
    return value


def _serializable(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value

def _canonical_list(values) -> list[str]:
    return sorted({str(value).strip() for value in (values or []) if str(value).strip()})


def _canonical_status(value: str | None) -> str | None:
    if not value:
        return None
    statuses = sorted({item.strip() for item in value.split(",") if item.strip()})
    return ", ".join(statuses) or None


def _canonical_dns(records, previous) -> dict[str, list[str]]:
    result = {}
    previous = previous if isinstance(previous, dict) else {}
    for record_type, values in (records or {}).items():
        values = values if isinstance(values, list) else []
        if any(str(value).startswith("Lookup failed:") for value in values):
            result[record_type] = _canonical_list(previous.get(record_type, []))
        else:
            result[record_type] = _canonical_list(values)
    return result



def discovered_snapshot(record: DomainRecord) -> dict:
    return {
        "registrar": record.lookup_registrar,
        "dns_provider": record.lookup_dns_provider,
        "status": _canonical_status(record.lookup_status),
        "expires_at": _serializable(record.lookup_expires_at),
        "nameservers": _canonical_list(_json_value(record.lookup_nameservers, [])),
        "dns_records": _canonical_dns(_json_value(record.dns_records, {}), {}),
    }


def lookup_snapshot(data: dict, previous: dict) -> dict:
    error = data.get("lookup_error") or ""
    registration_failed = "Registration lookup unavailable" in error
    dns_failed = "DNS lookup failed" in error
    snapshot = {
        "registrar": data.get("registrar"),
        "dns_provider": data.get("dns_provider"),
        "status": _canonical_status(data.get("status")),
        "expires_at": _serializable(data.get("expires_at")),
        "nameservers": _canonical_list(data.get("nameservers")),
        "dns_records": _canonical_dns(data.get("dns_records"), previous["dns_records"]),
    }
    if registration_failed:
        for field in ("registrar", "status", "expires_at"):
            snapshot[field] = previous[field]
    if dns_failed:
        for field in ("dns_provider", "nameservers", "dns_records"):
            snapshot[field] = previous[field]
    if any(str(value).startswith("Lookup failed:") for value in (data.get("nameservers") or [])):
        snapshot["dns_provider"] = previous["dns_provider"]
        snapshot["nameservers"] = previous["nameservers"]
    return snapshot


def compare_snapshots(before: dict, after: dict) -> list[dict]:
    return [
        {"field": field, "label": label, "before": before[field], "after": after[field]}
        for field, label in DISCOVERED_FIELDS.items()
        if before[field] != after[field]
    ]


def apply_snapshot(record: DomainRecord, snapshot: dict, data: dict) -> None:
    record.lookup_registrar = snapshot["registrar"]
    record.lookup_dns_provider = snapshot["dns_provider"]
    record.lookup_status = snapshot["status"]
    record.lookup_expires_at = datetime.fromisoformat(snapshot["expires_at"]) if snapshot["expires_at"] else None
    record.lookup_nameservers = json.dumps(snapshot["nameservers"])
    record.dns_records = json.dumps(snapshot["dns_records"])
    record.lookup_error = data.get("lookup_error")
    record.last_lookup_at = data.get("last_lookup_at") or datetime.utcnow()
    record.updated_at = datetime.utcnow()


def poll_domain(db: Session, record: DomainRecord, source: str = "scheduled") -> list[dict]:
    record_id = record.id
    domain_name = record.name
    had_baseline = record.last_lookup_at is not None
    before = discovered_snapshot(record)
    # The lookup can involve several bounded network calls. Release SQLite's
    # reader before crossing that boundary, then re-check that the row exists.
    db.rollback()
    data = lookup_domain(domain_name)
    record = db.get(DomainRecord, record_id)
    if record is None:
        return []
    after = lookup_snapshot(data, before)
    changes = compare_snapshots(before, after) if had_baseline else []
    apply_snapshot(record, after, data)
    if changes:
        db.add(DomainRecordHistory(
            domain_id=record.id,
            domain_name=record.name,
            source=source,
            changes=json.dumps(changes),
            checked_at=record.last_lookup_at,
        ))
    db.commit()
    return changes


def due_domain_ids(db: Session) -> list[int]:
    cutoff = datetime.utcnow() - timedelta(days=POLL_CADENCES[get_poll_cadence(db)])
    rows = db.query(DomainRecord.id).filter(
        (DomainRecord.last_lookup_at.is_(None)) | (DomainRecord.last_lookup_at <= cutoff)
    ).order_by(DomainRecord.last_lookup_at.asc()).limit(MAX_DOMAINS_PER_PASS).all()
    return [row.id for row in rows]


def poll_domain_by_id(domain_id: int) -> None:
    db = SessionLocal()
    try:
        record = db.get(DomainRecord, domain_id)
        if record:
            poll_domain(db, record, source="scheduled")
    except Exception:
        db.rollback()
    finally:
        db.close()


async def domain_poll_loop() -> None:
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        db = SessionLocal()
        try:
            domain_ids = due_domain_ids(db)
        finally:
            db.close()
        if domain_ids:
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_POLLS)

            async def checked_domain(domain_id: int) -> None:
                async with semaphore:
                    await asyncio.to_thread(poll_domain_by_id, domain_id)

            await asyncio.gather(*(checked_domain(domain_id) for domain_id in domain_ids))
        await asyncio.sleep(LOOP_INTERVAL_SECONDS)
