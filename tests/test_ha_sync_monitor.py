from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import Base
from app.models.models import HACluster, HANode, HASyncRun, User
from app.services import ha_sync_monitor


def monitor_database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        user = User(email="monitor@example.com", password_hash="x", role="admin", is_active=True)
        cluster = HACluster(name="HA DNS", provider_key="pihole", status="HEALTHY", virtual_ip="192.0.2.53", keepalived_status="DEPLOYED", created_by=user)
        db.add_all([user, cluster]); db.flush()
        source = HANode(cluster_id=cluster.id, display_name="Primary", api_base_url="http://one.invalid", role="ACTIVE", desired_role="ACTIVE")
        target = HANode(cluster_id=cluster.id, display_name="Standby", api_base_url="http://two.invalid", role="STANDBY", desired_role="STANDBY")
        db.add_all([source, target]); db.flush()
        cluster.authoritative_node_id = source.id
        cluster.current_active_node_id = source.id
        db.commit()
    return factory


def test_monitor_runs_due_read_only_comparison(monkeypatch):
    factory = monitor_database()
    checked = []
    monkeypatch.setattr(ha_sync_monitor, "get_site_setting", lambda db, key: "1")
    monkeypatch.setattr(ha_sync_monitor, "create_live_sync_plan", lambda db, cluster: checked.append(cluster.public_id))

    ha_sync_monitor.run_ha_sync_monitor_pass(factory)

    assert len(checked) == 1


def test_monitor_does_not_repeat_a_recent_check(monkeypatch):
    factory = monitor_database()
    with factory() as db:
        cluster = db.query(HACluster).one()
        source, target = cluster.nodes
        db.add(HASyncRun(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="IN_SYNC", plan_json='{"groups":[]}', completed_at=datetime.utcnow()))
        db.commit()
    checked = []
    monkeypatch.setattr(ha_sync_monitor, "get_site_setting", lambda db, key: "1")
    monkeypatch.setattr(ha_sync_monitor, "create_live_sync_plan", lambda db, cluster: checked.append(cluster.public_id))

    ha_sync_monitor.run_ha_sync_monitor_pass(factory)

    assert checked == []


def test_opted_in_monitor_applies_safe_drift_from_current_vip_owner(monkeypatch):
    factory = monitor_database()
    with factory() as db:
        cluster = db.query(HACluster).one()
        cluster.automatic_sync_enabled = True
        db.commit()
    applied = []

    def create_plan(db, cluster):
        source = next(node for node in cluster.nodes if node.id == cluster.authoritative_node_id)
        target = next(node for node in cluster.nodes if node.id != source.id)
        run = HASyncRun(cluster_id=cluster.id, source_node_id=source.id, target_node_id=target.id, status="PLANNED", plan_json='{"blocked_groups":[],"deletion_count":0,"groups":[{"key":"local_dns"}]}')
        db.add(run); db.commit(); db.refresh(run)
        return run

    def apply_plan(db, cluster, run, *, allow_deletions):
        applied.append((run.source_node_id, run.target_node_id, allow_deletions))
        run.status = "SUCCEEDED"
        run.completed_at = datetime.utcnow()
        db.commit()
        return run

    monkeypatch.setattr(ha_sync_monitor, "get_site_setting", lambda db, key: "1")
    monkeypatch.setattr(ha_sync_monitor, "create_live_sync_plan", create_plan)
    monkeypatch.setattr(ha_sync_monitor, "execute_sync", apply_plan)

    ha_sync_monitor.run_ha_sync_monitor_pass(factory)

    assert len(applied) == 1
    assert applied[0][2] is False
