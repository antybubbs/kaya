from sqlalchemy.orm import Session
from app.models.models import ManagedListItem

MANAGED_LIST_MODULES = {"hardware_assets": "Hardware Assets", "ip_addresses": "IP Addresses", "licences": "License Keys"}
MANAGED_LISTS = {
    "hardware_assets": {
        "category": "Category",
        "location": "Location",
        "status": "Status",
    },
    "ip_addresses": {
        "category": "Category",
    },
    "licences": {
        "licence_type": "License Type",
    }
}

DEFAULT_ITEMS = {
    ("hardware_assets", "category"): ["Server", "Desktop", "Laptop", "Network", "Storage", "Peripheral", "Other"],
    ("hardware_assets", "location"): ["Rack", "Office", "Living Room", "Storage", "Other"],
    ("hardware_assets", "status"): ["In use", "Ready", "Repair", "Retired", "Missing"],
    ("ip_addresses", "category"): ["Infrastructure", "Servers", "Clients", "IoT", "Guest", "Reserved", "Other"],
    ("licences", "licence_type"): ["Retail", "OEM", "Volume", "Subscription", "Trial", "Other"],
}


def list_label(module: str, list_key: str) -> str:
    return MANAGED_LISTS.get(module, {}).get(list_key, list_key)


def active_values(db: Session, module: str, list_key: str) -> list[str]:
    rows = db.query(ManagedListItem).filter(
        ManagedListItem.module == module,
        ManagedListItem.list_key == list_key,
        ManagedListItem.is_active == True,
    ).order_by(ManagedListItem.sort_order.asc(), ManagedListItem.value.asc()).all()
    return [row.value for row in rows]


def list_values(db: Session, module: str) -> dict[str, list[str]]:
    return {list_key: active_values(db, module, list_key) for list_key in MANAGED_LISTS.get(module, {})}


def seed_default_lists(db: Session):
    for (module, list_key), values in DEFAULT_ITEMS.items():
        for index, value in enumerate(values):
            exists = db.query(ManagedListItem).filter(
                ManagedListItem.module == module,
                ManagedListItem.list_key == list_key,
                ManagedListItem.value == value,
            ).first()
            if not exists:
                db.add(ManagedListItem(module=module, list_key=list_key, value=value, is_active=True, sort_order=index))
