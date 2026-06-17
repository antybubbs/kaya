from sqlalchemy.orm import Session
from app.models.models import AuditLog, User

#A messy audit display to check bits and bobs.
def write_audit(db: Session, user: User | None, action: str, entity: str, entity_id: str | None = None, ip_address: str | None = None, detail: str | None = None):
    db.add(AuditLog(user_id=user.id if user else None, action=action, entity=entity, entity_id=entity_id, ip_address=ip_address, detail=detail))
    db.commit()
