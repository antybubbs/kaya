"""Suite-wide test isolation.  Test infrastructure only; no production code."""

from __future__ import annotations

import pytest

from app.db.session import Base
import app.models.models  # noqa: F401  (registers every table on Base.metadata)

# SQLAlchemy's create_all() on PostgreSQL adds foreign keys that form cycles
# (dns_providers -> ha_clusters -> ha_nodes) with ALTER, and does so by setting
# a "_create_rule" on those shared ForeignKeyConstraint objects.  That change
# persists on the global metadata, so any later SQLite create_all() silently
# omits the foreign keys.  Record the original rules once and put them back
# after every test so PostgreSQL tests cannot change other tests' schemas.
_ORIGINAL_CREATE_RULES = {
    constraint: constraint._create_rule
    for table in Base.metadata.tables.values()
    for constraint in table.foreign_key_constraints
}


@pytest.fixture(autouse=True)
def _restore_shared_metadata_create_rules():
    yield
    from app.services import ha_evaluation_queue

    ha_evaluation_queue.reset()  # signalled clusters must not leak between tests
    for constraint, rule in _ORIGINAL_CREATE_RULES.items():
        if constraint._create_rule is not rule:
            constraint._create_rule = rule
