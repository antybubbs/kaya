"""Targeted lease-snapshot lookups must match the former collection scans.

All data is synthetic: documentation-range addresses and locally
administered MACs. PostgreSQL cases run only when KAYA_TEST_POSTGRES_URL
points at a disposable test database; they use an isolated schema.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, insert, inspect, text
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import DetachedInstanceError

from app.core.security import encrypt_secret
from app.db.session import Base
from app.models.models import HACluster, HALeaseReplicationState, HALeaseSnapshot, HANode, HAProviderConnection
from app.schemas.high_availability import HAAgentActionResult
from app.services.ha_agents import desired_state, record_action_result
from app.services.ha_leases import (
    HALeaseError,
    desired_lease_action,
    latest_snapshot_summary,
    record_lease_stage_result,
    snapshot_for_agent,
)


POSTGRES_URL = os.environ.get("KAYA_TEST_POSTGRES_URL")
FAKE_PAYLOAD = json.dumps({"version": 1, "leases": [{"expires": 2000000000, "hwaddr": "02:00:00:00:00:01", "ip": "192.0.2.20", "name": "fake-device", "clientid": ""}]})


@pytest.fixture(params=["sqlite", "postgresql"])
def engine(request):
    if request.param == "sqlite":
        engine = create_engine("sqlite:///:memory:")

        @event.listens_for(engine, "connect")
        def foreign_keys(connection, record):
            connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(engine)
        yield engine
        engine.dispose()
        return
    if not POSTGRES_URL:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    schema = f"kaya_c1_{uuid4().hex[:10]}"
    admin = create_engine(POSTGRES_URL)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(POSTGRES_URL, connect_args={"options": f"-c search_path={schema}"})
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def loaded_snapshots():
    """Strong references to every HALeaseSnapshot row materialised by the ORM."""
    loaded: list[HALeaseSnapshot] = []

    def record(target, context):
        loaded.append(target)

    event.listen(HALeaseSnapshot, "load", record)
    yield loaded
    event.remove(HALeaseSnapshot, "load", record)


@pytest.fixture
def statements(engine):
    seen: list[str] = []

    @event.listens_for(engine, "before_cursor_execute")
    def record(conn, cursor, statement, parameters, context, executemany):
        seen.append(statement)

    yield seen
    event.remove(engine, "before_cursor_execute", record)


def make_cluster(db: Session) -> tuple[int, int, int]:
    suffix = uuid4().hex[:8]
    cluster = HACluster(name=f"Synthetic pair {suffix}", provider_key="pihole", status="HEALTHY", virtual_ip="192.0.2.53", prefix_length=24)
    one = HAProviderConnection(provider_key="pihole", name=f"One {suffix}", api_base_url=f"https://one-{suffix}.invalid")
    two = HAProviderConnection(provider_key="pihole", name=f"Two {suffix}", api_base_url=f"https://two-{suffix}.invalid")
    db.add_all([cluster, one, two])
    db.flush()
    now = datetime.utcnow()
    primary = HANode(cluster_id=cluster.id, display_name="One", api_base_url=one.api_base_url, ha_connection_id=one.id, role="ACTIVE", desired_role="ACTIVE",
                     last_heartbeat_at=now, dhcp_observed_at=now, dhcp_observation_status="FRESH", observed_role="ACTIVE", vip_owned=True,
                     dns_healthy=True, dhcp_configured=True, dhcp_listener_active=True, ftl_active=True, dhcp_runtime_state="RUNNING")
    standby = HANode(cluster_id=cluster.id, display_name="Two", api_base_url=two.api_base_url, ha_connection_id=two.id, role="STANDBY", desired_role="STANDBY",
                     last_heartbeat_at=now, dhcp_observed_at=now, dhcp_observation_status="FRESH", observed_role="STANDBY", vip_owned=False,
                     dns_healthy=True, dhcp_configured=False, dhcp_listener_active=False, ftl_active=True, dhcp_runtime_state="STOPPED")
    db.add_all([primary, standby])
    db.flush()
    cluster.authoritative_node_id = primary.id
    db.commit()
    return cluster.id, primary.id, standby.id


def seed(db: Session, cluster_id: int, source_id: int, target_id: int, *, generations, snapshot_status=lambda generation: "STAGED",
         state_status: str | None = "PENDING", desired: int | None = None, state_target: int | None = None) -> None:
    encrypted = encrypt_secret(FAKE_PAYLOAD)
    rows = [
        {
            "public_id": str(uuid4()), "cluster_id": cluster_id, "source_node_id": source_id, "target_node_id": target_id,
            "generation": generation, "checksum": hashlib.sha256(f"{cluster_id}:{generation}".encode()).hexdigest(),
            "encrypted_payload": encrypted, "lease_count": 1, "status": snapshot_status(generation),
            "validation_summary_json": json.dumps({"range": "192.0.2.10-192.0.2.200", "reservation_count": 1}),
            "created_at": datetime(2026, 11, 2), "staged_at": None,
        }
        for generation in generations
    ]
    if rows:
        db.execute(insert(HALeaseSnapshot), rows)
    if state_status is not None:
        db.add(HALeaseReplicationState(cluster_id=cluster_id, source_node_id=source_id, target_node_id=state_target or target_id,
                                       status=state_status, desired_generation=desired or 0, applied_generation=max(0, (desired or 1) - 1)))
    db.commit()


# Verbatim pre-C1 behaviour, used as the reference oracle.
def legacy_desired_lease_action(cluster, node):
    state = cluster.lease_replication
    if state is None or state.status != "PENDING" or state.target_node_id != node.id:
        return None
    snapshot = next((item for item in cluster.lease_snapshots if item.generation == state.desired_generation), None)
    if snapshot is None or snapshot.status != "PENDING":
        return None
    return {"action_id": f"lease:{cluster.public_id}:{node.public_id}:{snapshot.generation}:{snapshot.checksum[:12]}", "action_type": "LEASE_SNAPSHOT_STAGE", "generation": snapshot.generation, "checksum": snapshot.checksum, "snapshot_path": f"/api/ha/agent/v1/lease-snapshot/{snapshot.generation}"}


def legacy_latest_snapshot_summary(cluster):
    if not cluster.lease_snapshots:
        return None
    snapshot = max(cluster.lease_snapshots, key=lambda item: item.generation)
    validation = json.loads(snapshot.validation_summary_json or "{}")
    return {"generation": snapshot.generation, "status": snapshot.status, "checksum": snapshot.checksum[:12], "lease_count": snapshot.lease_count, "created_at": snapshot.created_at, "staged_at": snapshot.staged_at, "reservation_count": validation.get("reservation_count", 0), "range": validation.get("range")}


def outcome(function, *args):
    try:
        return ("ok", function(*args))
    except HALeaseError as exc:
        return ("error", str(exc))


def legacy_snapshot_for_agent(node, generation):
    from app.core.security import decrypt_secret
    state = node.cluster.lease_replication
    if state is None or state.target_node_id != node.id or state.desired_generation != generation:
        raise HALeaseError("This lease snapshot is not assigned to this node.")
    snapshot = next((item for item in node.cluster.lease_snapshots if item.generation == generation), None)
    if snapshot is None or snapshot.status != "PENDING":
        raise HALeaseError("The requested lease snapshot is unavailable.")
    return {"generation": snapshot.generation, "checksum": snapshot.checksum, "payload": json.loads(decrypt_secret(snapshot.encrypted_payload))}


STATE_CASES = [
    # (state_status, desired, snapshot status for the desired generation, state targets standby)
    (None, None, "PENDING", True),
    ("PENDING", 3, "PENDING", True),
    ("PENDING", 3, "STAGED", True),
    ("PENDING", 3, "FAILED", True),
    ("PENDING", 9, "PENDING", True),     # desired generation missing
    ("PENDING", 3, "PENDING", False),    # state targets the active node
    ("CURRENT", 3, "STAGED", True),
    ("BLOCKED", 3, "PENDING", True),
    ("ERROR", 3, "FAILED", True),
    ("NOT_APPLICABLE", 0, "PENDING", True),
]


@pytest.mark.parametrize("state_status, desired, desired_status, targets_standby", STATE_CASES)
def test_targeted_lookups_match_legacy_collection_scans(engine, state_status, desired, desired_status, targets_standby):
    with Session(engine) as db:
        cluster_id, primary_id, standby_id = make_cluster(db)
        seed(db, cluster_id, primary_id, standby_id, generations=range(1, 6),
             snapshot_status=lambda generation: desired_status if generation == desired else "STAGED",
             state_status=state_status, desired=desired, state_target=standby_id if targets_standby else primary_id)
    for generation in (0, 1, 3, 5, 9):
        with Session(engine) as new_db, Session(engine) as old_db:
            new_cluster, old_cluster = new_db.get(HACluster, cluster_id), old_db.get(HACluster, cluster_id)
            for node_id in (primary_id, standby_id):
                new_node, old_node = new_db.get(HANode, node_id), old_db.get(HANode, node_id)
                assert desired_lease_action(new_cluster, new_node) == legacy_desired_lease_action(old_cluster, old_node)
                assert outcome(snapshot_for_agent, new_node, generation) == outcome(legacy_snapshot_for_agent, old_node, generation)
            assert latest_snapshot_summary(new_cluster) == legacy_latest_snapshot_summary(old_cluster)


def test_no_snapshots_and_missing_generations(engine):
    with Session(engine) as db:
        cluster_id, primary_id, standby_id = make_cluster(db)
        cluster, standby = db.get(HACluster, cluster_id), db.get(HANode, standby_id)
        assert latest_snapshot_summary(cluster) is None
        seed(db, cluster_id, primary_id, standby_id, generations=[], state_status="PENDING", desired=4)
        db.expire_all()
        assert desired_lease_action(cluster, standby) is None
        with pytest.raises(HALeaseError, match="unavailable"):
            snapshot_for_agent(standby, 4)
        with pytest.raises(HALeaseError, match="checksum does not match"):
            record_lease_stage_result(db, standby, generation=4, checksum="0" * 64, status="APPLIED", message="synthetic")


def test_target_and_generation_validation_is_preserved(engine):
    with Session(engine) as db:
        cluster_id, primary_id, standby_id = make_cluster(db)
        seed(db, cluster_id, primary_id, standby_id, generations=[1, 2], snapshot_status=lambda generation: "PENDING", desired=2)
        primary, standby = db.get(HANode, primary_id), db.get(HANode, standby_id)
        with pytest.raises(HALeaseError, match="not assigned to this node"):
            snapshot_for_agent(primary, 2)
        with pytest.raises(HALeaseError, match="not assigned to this node"):
            snapshot_for_agent(standby, 1)
        for node, generation in ((primary, 2), (standby, 1), (standby, 3)):
            with pytest.raises(HALeaseError, match="current desired generation"):
                record_lease_stage_result(db, node, generation=generation, checksum=None, status="FAILED", message="synthetic")
        assert snapshot_for_agent(standby, 2)["generation"] == 2


def test_checksum_mismatch_is_rejected_without_state_change(engine):
    with Session(engine) as db:
        cluster_id, primary_id, standby_id = make_cluster(db)
        seed(db, cluster_id, primary_id, standby_id, generations=[1], snapshot_status=lambda generation: "PENDING", desired=1)
        standby = db.get(HANode, standby_id)
        with pytest.raises(HALeaseError, match="checksum does not match"):
            record_lease_stage_result(db, standby, generation=1, checksum="f" * 64, status="APPLIED", message="synthetic")
        db.rollback()
        snapshot = db.query(HALeaseSnapshot).filter_by(cluster_id=cluster_id, generation=1).one()
        state = db.get(HACluster, cluster_id).lease_replication
        assert (snapshot.status, state.status, state.applied_generation) == ("PENDING", "PENDING", 0)


def test_metadata_lookups_do_not_load_encrypted_payloads(engine, statements, loaded_snapshots):
    with Session(engine) as db:
        cluster_id, primary_id, standby_id = make_cluster(db)
        seed(db, cluster_id, primary_id, standby_id, generations=[1, 2, 3], snapshot_status=lambda generation: "PENDING", desired=3)
    with Session(engine) as db:
        cluster, standby = db.get(HACluster, cluster_id), db.get(HANode, standby_id)
        statements.clear()
        assert desired_lease_action(cluster, standby)["generation"] == 3
        assert latest_snapshot_summary(cluster)["generation"] == 3
        assert [item.generation for item in loaded_snapshots] == [3]
        assert "encrypted_payload" in inspect(loaded_snapshots[0]).unloaded
        assert not any("encrypted_payload" in statement for statement in statements if "ha_lease_snapshots" in statement)
        # The one function that serves the payload still loads it.
        assert snapshot_for_agent(standby, 3)["payload"]["leases"][0]["ip"] == "192.0.2.20"


def test_large_history_is_never_materialised_on_production_entry_points(engine, statements, loaded_snapshots):
    with Session(engine) as db:
        cluster_id, primary_id, standby_id = make_cluster(db)
        seed(db, cluster_id, primary_id, standby_id, generations=range(1, 2001),
             snapshot_status=lambda generation: "PENDING" if generation == 2000 else "STAGED", desired=2000)
    with Session(engine) as db:
        cluster, standby = db.get(HACluster, cluster_id), db.get(HANode, standby_id)
        statements.clear()
        action = desired_state(standby)["lease_snapshot"]           # heartbeat path
        assert snapshot_for_agent(standby, 2000)["generation"] == 2000  # lease-snapshot route
        latest_snapshot_summary(cluster)                             # diagnostics / DHCP page
        result = HAAgentActionResult(action_id=action["action_id"], action_type="LEASE_SNAPSHOT_STAGE", generation=2000, status="APPLIED",
                                     checksum=action["checksum"], backup_reference="lease-generation-2000", message="synthetic stage")
        record_action_result(db, standby, result)                    # action-result route
        assert "lease_snapshots" not in cluster.__dict__
        # Only the requested generation is ever materialised, never the 2,000-row history.
        assert {item.generation for item in loaded_snapshots} == {2000}
        assert len(loaded_snapshots) <= 4
        snapshot_selects = [statement for statement in statements if statement.lstrip().upper().startswith("SELECT") and "FROM ha_lease_snapshots" in statement]
        # Every snapshot SELECT is bounded: a generation predicate, LIMIT, or a
        # primary-key refresh of an already-selected row after commit.
        bounded = ("ha_lease_snapshots.generation = ", "LIMIT", "WHERE ha_lease_snapshots.id = ")
        assert snapshot_selects and all(any(marker in statement for marker in bounded) for statement in snapshot_selects)
        assert not any("WHERE ? = ha_lease_snapshots.cluster_id" in statement or "WHERE %(param_1)s = ha_lease_snapshots.cluster_id" in statement for statement in statements)


def test_session_identity_and_update_persistence(engine):
    with Session(engine) as db:
        cluster_id, primary_id, standby_id = make_cluster(db)
        seed(db, cluster_id, primary_id, standby_id, generations=[1, 2], snapshot_status=lambda generation: "PENDING", desired=2)
    with Session(engine) as db:
        cluster, standby = db.get(HACluster, cluster_id), db.get(HANode, standby_id)
        expected = desired_lease_action(cluster, standby)
        first = db.query(HALeaseSnapshot).filter_by(cluster_id=cluster_id, generation=2).one()
        record_lease_stage_result(db, standby, generation=2, checksum=expected["checksum"], status="APPLIED", message="synthetic")
        assert first.status == "STAGED" and first.staged_at is not None
        db.commit()
    with Session(engine) as db:
        snapshot = db.query(HALeaseSnapshot).filter_by(cluster_id=cluster_id, generation=2).one()
        state = db.get(HACluster, cluster_id).lease_replication
        assert (snapshot.status, state.status, state.applied_generation, db.get(HANode, standby_id).lease_generation) == ("STAGED", "CURRENT", 2, 2)
        assert db.query(HALeaseSnapshot).filter_by(cluster_id=cluster_id, generation=1).one().status == "PENDING"


def test_detached_objects_never_query_and_match_legacy(engine, statements):
    with Session(engine) as db:
        cluster_id, primary_id, standby_id = make_cluster(db)
        seed(db, cluster_id, primary_id, standby_id, generations=[1, 2], snapshot_status=lambda generation: "PENDING", desired=2)
    with Session(engine) as db:
        cluster = db.get(HACluster, cluster_id)
        standby = db.get(HANode, standby_id)
        _ = (cluster.lease_replication, list(cluster.lease_snapshots), standby.cluster, [item.encrypted_payload for item in cluster.lease_snapshots])
        db.expunge_all()
    statements.clear()
    assert desired_lease_action(cluster, standby) == legacy_desired_lease_action(cluster, standby)
    assert latest_snapshot_summary(cluster) == legacy_latest_snapshot_summary(cluster)
    assert snapshot_for_agent(standby, 2) == legacy_snapshot_for_agent(standby, 2)
    assert statements == []
    with Session(engine) as db:
        unloaded = db.get(HACluster, cluster_id)
        _ = unloaded.lease_replication
        db.expunge_all()
    statements.clear()
    with pytest.raises(DetachedInstanceError):
        legacy_latest_snapshot_summary(unloaded)
    with pytest.raises(DetachedInstanceError):
        latest_snapshot_summary(unloaded)
    assert statements == []
