from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.models import HardwareAsset, HardwareAssetTagSequence, RemoteManagerSetting
from app.services.asset_tags import allocate_asset_tag, next_asset_tag_preview, validate_asset_tag_settings


def set_setting(db, key, value):
    db.add(RemoteManagerSetting(key=key, value=value))


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    set_setting(session, "asset_tags_auto_generate", "1")
    set_setting(session, "asset_tags_prefix", "HAL")
    set_setting(session, "asset_tags_separator", "-")
    set_setting(session, "asset_tags_padding", "4")
    set_setting(session, "asset_tags_start_number", "1")
    session.add(HardwareAssetTagSequence(id=1, next_number=1))
    session.commit()
    yield session
    session.close()


def test_generation_and_preview_do_not_consume_number(db):
    assert next_asset_tag_preview(db) == "HAL-0001"
    assert allocate_asset_tag(db, None) == "HAL-0001"
    db.commit()
    assert allocate_asset_tag(db, None) == "HAL-0002"


def test_deleted_numbers_are_not_reused_and_matching_manual_tags_advance(db):
    first = HardwareAsset(asset_tag=allocate_asset_tag(db, None), name="First")
    db.add(first)
    db.commit()
    db.delete(first)
    db.commit()
    assert allocate_asset_tag(db, None) == "HAL-0002"
    assert allocate_asset_tag(db, "SWITCH-CORE-01") == "SWITCH-CORE-01"
    assert allocate_asset_tag(db, "HAL-0100") == "HAL-0100"
    assert allocate_asset_tag(db, None) == "HAL-0101"


def test_settings_are_strictly_validated():
    values, error = validate_asset_tag_settings(
        {
            "asset_tags_auto_generate": "1",
            "asset_tags_prefix": "HAL",
            "asset_tags_separator": "-",
            "asset_tags_padding": "13",
            "asset_tags_start_number": "1",
        }
    )
    assert values == {}
    assert error


def test_concurrent_allocations_are_unique(tmp_path):
    database = tmp_path / "asset-tags.db"
    engine = create_engine(
        f"sqlite:///{database}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory.begin() as session:
        for key, value in {
            "asset_tags_auto_generate": "1",
            "asset_tags_prefix": "HAL",
            "asset_tags_separator": "-",
            "asset_tags_padding": "4",
            "asset_tags_start_number": "1",
        }.items():
            set_setting(session, key, value)
        session.add(HardwareAssetTagSequence(id=1, next_number=1))

    def create_one(index):
        for _ in range(3):
            session = factory()
            try:
                tag = allocate_asset_tag(session, None)
                session.add(HardwareAsset(asset_tag=tag, name=f"Asset {index}"))
                session.commit()
                return tag
            except OperationalError:
                session.rollback()
            finally:
                session.close()
        pytest.fail("SQLite allocator remained locked after retries")

    with ThreadPoolExecutor(max_workers=2) as executor:
        tags = list(executor.map(create_one, range(2)))
    assert len(set(tags)) == 2
