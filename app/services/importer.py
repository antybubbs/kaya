import pandas as pd
from sqlalchemy.orm import Session
from app.core.security import encrypt_secret
from app.models.models import Licence, User
from app.services.audit import write_audit


def clean(value):
    if pd.isna(value):
        return None
    text = str(value).strip()
    return text if text and text.lower() != "nan" else None


def to_int(value):
    try:
        if pd.isna(value):
            return None
        return int(float(value))
    except Exception:
        return None


def import_csv(db: Session, user: User, path: str, ip_address: str | None = None) -> int:
    df = pd.read_csv(path)
    count = 0
    for _, row in df.iterrows():
        product = clean(row.get("Product"))
        product_key = clean(row.get("Product Key"))
        if not product or not product_key:
            continue
        licence = Licence(
            licence_id=clean(row.get("License ID")),
            parent_program=clean(row.get("Parent Program")),
            organisation=clean(row.get("Organization")),
            product=product,
            vendor="Microsoft",
            encrypted_product_key=encrypt_secret(product_key),
            licence_type=clean(row.get("Type")),
            activations=clean(row.get("MAK Activations-Used/Available")),
            seats=to_int(row.get("Seats")),
            osa_status=clean(row.get("OSA Status")),
        )
        db.add(licence)
        count += 1
    db.commit()
    write_audit(db, user, "import", "licence", detail=f"Imported {count} licence records", ip_address=ip_address)
    return count
