from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from tests.fixtures.stage2b_acceptance import seed_stage2b_acceptance


def test_stage2b_fixture_is_complete_and_deterministic():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        counts = seed_stage2b_acceptance(db)
        assert counts["sources"] == 2
        assert counts["observations"] == 60
        assert counts["assets"] == 13
        assert counts["device_aggregates"] == 2
