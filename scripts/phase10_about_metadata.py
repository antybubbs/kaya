from sqlalchemy.orm import Session

from app.db.session import engine
from app.services.about import collect_about
from current_alembic_head import current_head


with Session(engine) as db:
    diagnostics = collect_about(db)["postgres_diagnostics"]

assert diagnostics["compatibility_state"] == "compatible"
expected_head = current_head()
assert diagnostics["current_alembic_revision"] == expected_head
assert diagnostics["expected_alembic_head"] == expected_head
