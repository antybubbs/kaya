import re
from sqlalchemy.orm import Session
from app.models.models import CustomField, CustomFieldValue

FIELD_TYPES = {
    "text": "Text input",
    "textarea": "Large text box",
    "radio": "Radio buttons",
    "select": "Drop-down list",
}


def make_field_key(label: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")
    return key or "custom_field"


def option_list(field: CustomField) -> list[str]:
    return [line.strip() for line in (field.options or "").splitlines() if line.strip()]


def active_fields(db: Session, module: str) -> list[CustomField]:
    return db.query(CustomField).filter(CustomField.module == module, CustomField.is_active == True).order_by(CustomField.sort_order.asc(), CustomField.label.asc()).all()


def field_values(db: Session, module: str, entity_type: str, entity_id: int) -> dict[int, str]:
    fields = active_fields(db, module)
    rows = db.query(CustomFieldValue).filter(CustomFieldValue.entity_type == entity_type, CustomFieldValue.entity_id == entity_id).all()
    values = {row.field_id: row.value or "" for row in rows}
    return {field.id: values.get(field.id, "") for field in fields}


def save_custom_values(db: Session, fields: list[CustomField], form, entity_type: str, entity_id: int):
    for field in fields:
        raw_value = str(form.get(f"custom_{field.id}", "")).strip()
        if field.field_type in {"radio", "select"}:
            allowed = option_list(field)
            value = raw_value if raw_value in allowed else ""
        else:
            value = raw_value
        row = db.query(CustomFieldValue).filter(CustomFieldValue.field_id == field.id, CustomFieldValue.entity_type == entity_type, CustomFieldValue.entity_id == entity_id).first()
        if not row:
            row = CustomFieldValue(field_id=field.id, entity_type=entity_type, entity_id=entity_id)
            db.add(row)
        row.value = value or None


def validate_custom_values(fields: list[CustomField], form) -> str | None:
    for field in fields:
        value = str(form.get(f"custom_{field.id}", "")).strip()
        if field.is_required and not value:
            return f"{field.label} is required."
        if value and field.field_type in {"radio", "select"} and value not in option_list(field):
            return f"{field.label} has an invalid value."
    return None
