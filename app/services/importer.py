from ipaddress import ip_address as parse_ip_address
import pandas as pd
from sqlalchemy.orm import Session
from app.core.config import InvalidConfigurationError
from app.core.security import encrypt_secret
from app.models.models import IPAddress, Licence, User
from app.services.audit import write_audit


class ImportCSVError(RuntimeError):
    pass


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


def clean_ip_address(value):
    text = clean(value)
    if not text:
        return None
    try:
        return str(parse_ip_address(text))
    except ValueError as exc:
        raise ImportCSVError(f"Invalid IP address: {text}") from exc


def import_csv(db: Session, user: User, path: str, ip_address: str | None = None) -> int:
    try:
        df = pd.read_csv(path)
    except Exception as exc:
        raise ImportCSVError("The uploaded file could not be read as a CSV.") from exc

    required_columns = {"Product", "Product Key"}
    missing_columns = sorted(required_columns - set(df.columns))
    if missing_columns:
        raise ImportCSVError("Missing required CSV columns: " + ", ".join(missing_columns))

    count = 0
    try:
        for _, row in df.iterrows():
            product = clean(row.get("Product"))
            product_key = clean(row.get("Product Key"))
            if not product or not product_key:
                continue
            licence_id = clean(row.get("License ID"))
            organisation = clean(row.get("Organization"))
            licence = None
            if licence_id:
                licence = db.query(Licence).filter(Licence.licence_id == licence_id).first()
            if not licence:
                licence = db.query(Licence).filter(Licence.product == product, Licence.organisation == organisation).first()
            if not licence:
                licence = Licence(product=product, encrypted_product_key=encrypt_secret(product_key))
                db.add(licence)
            licence.licence_id = licence_id
            licence.parent_program = clean(row.get("Parent Program"))
            licence.organisation = organisation
            licence.product = product
            licence.vendor = clean(row.get("Vendor")) or "Microsoft"
            licence.encrypted_product_key = encrypt_secret(product_key)
            licence.licence_type = clean(row.get("Type"))
            licence.activations = clean(row.get("MAK Activations-Used/Available"))
            licence.seats = to_int(row.get("Seats"))
            licence.osa_status = clean(row.get("OSA Status"))
            licence.notes = clean(row.get("Notes"))
            count += 1
        db.commit()
    except InvalidConfigurationError as exc:
        db.rollback()
        raise ImportCSVError(str(exc)) from exc
    except Exception as exc:
        db.rollback()
        raise ImportCSVError("The CSV import failed before records could be saved.") from exc

    write_audit(db, user, "import", "licence", detail=f"Imported or updated {count} licence records", ip_address=ip_address)
    return count


def import_ip_addresses_csv(db: Session, user: User, path: str, ip_address: str | None = None) -> int:
    try:
        df = pd.read_csv(path)
    except Exception as exc:
        raise ImportCSVError("The uploaded file could not be read as a CSV.") from exc

    required_columns = {"IP Address"}
    missing_columns = sorted(required_columns - set(df.columns))
    if missing_columns:
        raise ImportCSVError("Missing required CSV columns: " + ", ".join(missing_columns))

    count = 0
    try:
        for _, row in df.iterrows():
            address = clean_ip_address(row.get("IP Address"))
            if not address:
                continue
            record = db.query(IPAddress).filter(IPAddress.address == address).first()
            if not record:
                record = IPAddress(address=address)
                db.add(record)
            assignment_type = clean(row.get("Static/Dynamic")) or clean(row.get("Assignment Type")) or "Static"
            record.name = clean(row.get("Name"))
            record.description = clean(row.get("Description"))
            record.assignment_type = assignment_type if assignment_type in {"Static", "Dynamic"} else "Static"
            record.notes = clean(row.get("Notes"))
            count += 1
        db.commit()
    except ImportCSVError:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise ImportCSVError("The CSV import failed before records could be saved.") from exc

    write_audit(db, user, "import", "ip_address", detail=f"Imported or updated {count} IP address records", ip_address=ip_address)
    return count
