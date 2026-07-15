import csv
import io
from sqlalchemy.orm import Session
from app.core.security import decrypt_secret
from app.models.models import CustomField, CustomFieldValue, IPAddress, Licence


def export_licences_csv(db: Session) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    custom_fields = db.query(CustomField).filter(CustomField.module == "licences", CustomField.is_active == True).order_by(CustomField.sort_order.asc(), CustomField.label.asc()).all()
    writer.writerow([
        "License ID",
        "Parent Program",
        "Product",
        "Product Key",
        "Type",
        "MAK Activations-Used/Available",
        "Seats",
        "OSA Status",
        "Notes",
    ] + [f"Custom: {field.label}" for field in custom_fields])
    for row in db.query(Licence).order_by(Licence.product.asc()).all():
        values = db.query(CustomFieldValue).filter(CustomFieldValue.entity_type == "licence", CustomFieldValue.entity_id == row.id).all()
        value_map = {value.field_id: value.value or "" for value in values}
        writer.writerow([
            row.licence_id or "",
            row.parent_program or "",
            row.product,
            decrypt_secret(row.encrypted_product_key),
            row.licence_type or "",
            row.activations or "",
            row.seats or "",
            row.osa_status or "",
            row.notes or "",
        ] + [value_map.get(field.id, "") for field in custom_fields])
    return output.getvalue()


def export_ip_addresses_csv(db: Session) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    custom_fields = db.query(CustomField).filter(CustomField.module == "ip_addresses", CustomField.is_active == True).order_by(CustomField.sort_order.asc(), CustomField.label.asc()).all()
    writer.writerow([
        "IP Address",
        "VLAN",
        "Category",
        "MAC Address",
        "Name",
        "Description",
        "Static/Dynamic",
        "Notes",
    ] + [f"Custom: {field.label}" for field in custom_fields])
    for row in db.query(IPAddress).order_by(IPAddress.address.asc()).all():
        values = db.query(CustomFieldValue).filter(CustomFieldValue.entity_type == "ip_address", CustomFieldValue.entity_id == row.id).all()
        value_map = {value.field_id: value.value or "" for value in values}
        writer.writerow([
            row.address,
            row.vlan.name if row.vlan else "",
            row.category or "",
            row.mac_address or "",
            row.name or "",
            row.description or "",
            row.assignment_type,
            row.notes or "",
        ] + [value_map.get(field.id, "") for field in custom_fields])
    return output.getvalue()
