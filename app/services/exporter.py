import csv
import io
from sqlalchemy.orm import Session
from app.core.security import decrypt_secret
from app.models.models import IPAddress, Licence


def export_licences_csv(db: Session) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "License ID",
        "Parent Program",
        "Organization",
        "Product",
        "Product Key",
        "Type",
        "MAK Activations-Used/Available",
        "Seats",
        "OSA Status",
        "Notes",
    ])
    for row in db.query(Licence).order_by(Licence.product.asc()).all():
        writer.writerow([
            row.licence_id or "",
            row.parent_program or "",
            row.organisation or "",
            row.product,
            decrypt_secret(row.encrypted_product_key),
            row.licence_type or "",
            row.activations or "",
            row.seats or "",
            row.osa_status or "",
            row.notes or "",
        ])
    return output.getvalue()


def export_ip_addresses_csv(db: Session) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP Address",
        "Name",
        "Description",
        "Static/Dynamic",
        "Notes",
    ])
    for row in db.query(IPAddress).order_by(IPAddress.address.asc()).all():
        writer.writerow([
            row.address,
            row.name or "",
            row.description or "",
            row.assignment_type,
            row.notes or "",
        ])
    return output.getvalue()
