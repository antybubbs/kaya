import re

from sqlalchemy.orm import Session

from app.models.models import HardwareAsset, HardwareAssetTagSequence, RemoteManagerSetting

SETTING_DEFAULTS = {
    "asset_tags_auto_generate": "0",
    "asset_tags_prefix": "HAL",
    "asset_tags_separator": "-",
    "asset_tags_padding": "4",
    "asset_tags_start_number": "1",
}
PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}$")
SEPARATOR_RE = re.compile(r"^(?:[-/_ ]?)$")
MAX_TAG_LENGTH = 120


def asset_tag_settings(db: Session) -> dict[str, str]:
    values = SETTING_DEFAULTS.copy()
    rows = db.query(RemoteManagerSetting).filter(RemoteManagerSetting.key.in_(values)).all()
    for row in rows:
        values[row.key] = row.value or values[row.key]
    return values


def validate_asset_tag_settings(values: dict[str, str]) -> tuple[dict[str, str], str | None]:
    auto = "1" if values.get("asset_tags_auto_generate") == "1" else ""
    prefix = str(values.get("asset_tags_prefix", "")).strip()
    separator = str(values.get("asset_tags_separator", ""))
    if prefix and not PREFIX_RE.fullmatch(prefix):
        return {}, "Asset Tag prefix must use up to 40 letters, numbers, spaces, dots, hyphens, or underscores."
    if not SEPARATOR_RE.fullmatch(separator):
        return {}, "Asset Tag separator must be blank, -, /, _, or a space."
    try:
        padding = int(values.get("asset_tags_padding", "4"))
        start = int(values.get("asset_tags_start_number", "1"))
    except (TypeError, ValueError):
        return {}, "Asset Tag padding and starting number must be valid positive numbers."
    if not 1 <= padding <= 12:
        return {}, "Asset Tag padding must be between 1 and 12 digits."
    if start < 1:
        return {}, "Asset Tag starting number must be at least 1."
    if len(f"{prefix}{separator}{start:0{padding}d}") > MAX_TAG_LENGTH:
        return {}, "The generated Asset Tag would be too long."
    return {
        "asset_tags_auto_generate": auto,
        "asset_tags_prefix": prefix,
        "asset_tags_separator": separator,
        "asset_tags_padding": str(padding),
        "asset_tags_start_number": str(start),
    }, None


def asset_tag_pattern(settings: dict[str, str]) -> re.Pattern[str]:
    prefix = re.escape(settings["asset_tags_prefix"])
    separator = re.escape(settings["asset_tags_separator"])
    return re.compile(rf"^{prefix}{separator}(\d+)$")


def _sequence(db: Session, *, lock: bool = False) -> HardwareAssetTagSequence:
    query = db.query(HardwareAssetTagSequence).filter(HardwareAssetTagSequence.id == 1)
    if lock:
        query = query.with_for_update()
    sequence = query.first()
    if sequence is None:
        sequence = HardwareAssetTagSequence(id=1, next_number=1)
        db.add(sequence)
        db.flush()
    return sequence


def _matching_highest(db: Session, settings: dict[str, str]) -> int:
    pattern = asset_tag_pattern(settings)
    highest = 0
    for (asset_tag,) in db.query(HardwareAsset.asset_tag).filter(HardwareAsset.asset_tag.is_not(None)).all():
        match = pattern.fullmatch(asset_tag or "")
        if match:
            highest = max(highest, int(match.group(1)))
    return highest


def synchronise_asset_tag_sequence(db: Session, settings: dict[str, str]) -> None:
    sequence = _sequence(db, lock=True)
    minimum = max(int(settings["asset_tags_start_number"]), _matching_highest(db, settings) + 1)
    sequence.next_number = max(sequence.next_number, minimum)


def next_asset_tag_preview(db: Session) -> str:
    settings = asset_tag_settings(db)
    sequence = _sequence(db)
    next_number = max(
        sequence.next_number,
        int(settings["asset_tags_start_number"]),
        _matching_highest(db, settings) + 1,
    )
    return f"{settings['asset_tags_prefix']}{settings['asset_tags_separator']}{next_number:0>{int(settings['asset_tags_padding'])}}"


def allocate_asset_tag(db: Session, manual_tag: str | None) -> str | None:
    settings = asset_tag_settings(db)
    clean_manual = (manual_tag or "").strip() or None
    if clean_manual:
        if len(clean_manual) > MAX_TAG_LENGTH or any(ord(char) < 32 for char in clean_manual):
            raise ValueError("Asset Tag is invalid.")
        synchronise_asset_tag_sequence(db, settings)
        pattern = asset_tag_pattern(settings)
        match = pattern.fullmatch(clean_manual)
        if match:
            sequence = _sequence(db, lock=True)
            sequence.next_number = max(sequence.next_number, int(match.group(1)) + 1)
            db.flush()
        return clean_manual
    if settings["asset_tags_auto_generate"] != "1":
        return None
    synchronise_asset_tag_sequence(db, settings)
    sequence = _sequence(db, lock=True)
    number = sequence.next_number
    sequence.next_number += 1
    db.flush()
    tag = f"{settings['asset_tags_prefix']}{settings['asset_tags_separator']}{number:0>{int(settings['asset_tags_padding'])}}"
    if len(tag) > MAX_TAG_LENGTH:
        raise ValueError("Generated Asset Tag is too long.")
    return tag
