from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import VLAN, User, VaultSession
from app.services.modules import grant_all_registered_modules


def initialise_application_defaults(
    db: Session, *, module_permissions_existed: bool
) -> None:
    if not module_permissions_existed:
        for existing_user in db.query(User).all():
            grant_all_registered_modules(db, existing_user)
    db.query(VaultSession).filter(VaultSession.revoked_at.is_(None)).update(
        {VaultSession.revoked_at: datetime.utcnow()},  # noqa: DTZ003
        synchronize_session=False,
    )
    if db.query(VLAN).filter(VLAN.name == "VLAN 1").first() is None:
        db.add(VLAN(name="VLAN 1"))
    db.commit()
