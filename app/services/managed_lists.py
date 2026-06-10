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
