from sqlalchemy.orm import Session

from app.db.session import engine
from app.services.about import collect_about


with Session(engine) as db:
    diagnostics = collect_about(db)["postgres_diagnostics"]

assert diagnostics["compatibility_state"] == "compatible"
assert diagnostics["current_alembic_revision"] == "20260818_02"
assert diagnostics["expected_alembic_head"] == "20260818_02"
