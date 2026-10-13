"""Command centre dashboard: real-source panels, empty states and preference validation."""

import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    DashboardPreference,
    IPAddress,
    NetworkMonitor,
    NetworkMonitorCheck,
    NetworkMonitorOutage,
    RemoteAccess,
    TrafficDeviceAggregate,
    TrafficDeviceMonitoring,
    User,
    UserModulePermission,
    VLAN,
)
from app.services import dashboard as dashboard_service
from app.services.dashboard import default_layout, normalise_layout, preferences, save_preferences, snapshot
from app.services.dashboard_panels import clear_uptime_cache, traffic_panel, uptime_panel, vlan_rates
from app.services.modules import grant_all_registered_modules

NOW = datetime(2026, 10, 13, 12, 0, 0)


@pytest.fixture()
def db():
    clear_uptime_cache()
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    clear_uptime_cache()


def make_user(db, email="viewer@example.test", role="viewer"):
    item = User(email=email, password_hash="x", role=role, is_active=True, created_at=datetime.utcnow())
    db.add(item)
    db.flush()
    grant_all_registered_modules(db, item)
    db.commit()
    return item


def make_monitor(db, name, address, created_at=NOW - timedelta(days=60), **fields):
    ip = IPAddress(address=address, name=name)
    db.add(ip)
    db.flush()
    monitor = NetworkMonitor(ip_address_id=ip.id, display_name=name, created_at=created_at, **fields)
    db.add(monitor)
    db.flush()
    return monitor


def check(db, monitor, at, status="up", health=None):
    db.add(NetworkMonitorCheck(monitor_id=monitor.id, status=status, health_state=health, checked_at=at))


# ----------------------------------------------------------------- preferences


def test_new_default_layout_places_panels_in_spec_order_and_zones(db):
    account = make_user(db, role="admin")
    rows = default_layout(db, account)["widgets"]
    enabled = [(row["key"], row["zone"]) for row in sorted(rows, key=lambda row: row["position"]) if row["enabled"]]
    assert enabled == [
        ("network_traffic", "main"),
        ("uptime", "main"),
        ("module_overview", "main"),
        ("attention_required", "rail"),
        ("infrastructure_summary", "rail"),
    ]


def test_layout_rejects_invalid_zone(db):
    account = make_user(db)
    layout = default_layout(db, account)
    layout["widgets"][0]["zone"] = "sidebar"
    with pytest.raises(ValueError, match="zone"):
        normalise_layout(db, account, layout)


@pytest.mark.parametrize("hidden", [["1"], [True], [0], [-4], [2**40], "1,2", [1] * 501])
def test_uptime_selection_rejects_malformed_values(db, hidden):
    account = make_user(db)
    layout = default_layout(db, account)
    layout["uptime_hidden"] = hidden
    with pytest.raises(ValueError, match="uptime"):
        normalise_layout(db, account, layout)


def test_uptime_selection_persists_per_user_and_deduplicates(db):
    first = make_user(db)
    second = make_user(db, "second@example.test")
    layout = default_layout(db, first)
    layout["uptime_hidden"] = [7, 7, 3]
    save_preferences(db, first, layout)
    assert preferences(db, first)["uptime_hidden"] == [7, 3]
    assert preferences(db, second)["uptime_hidden"] == []


def test_version_one_layout_falls_back_to_new_defaults(db):
    account = make_user(db)
    legacy = {"version": 1, "monitor_mode": False, "widgets": [{"key": "dns_summary", "enabled": True, "position": 1, "width": "large"}]}
    db.add(DashboardPreference(user_id=account.id, preference_version=1, layout_json=json.dumps(legacy)))
    db.commit()
    assert preferences(db, account) == default_layout(db, account)


def test_snapshot_rejects_unsupported_traffic_range(db):
    account = make_user(db)
    with pytest.raises(ValueError):
        snapshot(db, account, traffic_range="6h")


# ----------------------------------------------------------------- traffic


def test_traffic_without_source_returns_only_empty_states(db):
    result = traffic_panel(db, report_range="24h", allowed_modules=frozenset({"vlan_ip_manager"}), dns_blocked_percentage=None, now=NOW)
    assert result["configured"] is False
    for key in ("inbound_bps", "outbound_bps", "peak_bps", "transferred_bytes", "dns_blocked_percentage", "vlans"):
        assert result[key] is None
    assert result["points"] == []


def _device(db, vlan, address, enabled=True):
    ip = IPAddress(address=address, vlan_id=vlan.id)
    db.add(ip)
    db.flush()
    db.add(TrafficDeviceMonitoring(ip_address_id=ip.id, is_enabled=enabled, status="enabled" if enabled else "disabled"))
    return ip


def _usage(db, ip, start, direction, amount):
    db.add(TrafficDeviceAggregate(period_id=1, ip_address_id=ip.id, source_id=1, bucket_start=start, bucket_seconds=300, direction=direction, bytes_total=amount))


def test_vlan_rates_use_latest_complete_bucket_of_opted_in_devices(db):
    servers, guest, quiet = VLAN(name="Servers"), VLAN(name="Guest"), VLAN(name="Quiet")
    db.add_all([servers, guest, quiet])
    db.flush()
    server = _device(db, servers, "198.51.100.10")
    guest_device = _device(db, guest, "198.51.100.20")
    hidden = _device(db, guest, "198.51.100.30", enabled=False)
    complete = NOW - timedelta(minutes=10)
    in_progress = NOW - timedelta(minutes=2)
    _usage(db, server, complete, "download", 3_000_000)
    _usage(db, server, complete, "upload", 750_000)
    _usage(db, guest_device, complete, "download", 375_000)
    _usage(db, hidden, complete, "download", 99_000_000)
    _usage(db, server, in_progress, "download", 50_000_000)
    db.commit()

    result = vlan_rates(db, NOW)

    tiles = {tile["name"]: tile for tile in result["tiles"]}
    assert tiles["Servers"]["bps"] == 100_000  # 3.75 MB * 8 / 300 s
    assert tiles["Guest"]["bps"] == 10_000  # opted-out device excluded
    assert tiles["Quiet"]["bps"] is None and tiles["Quiet"]["share"] == 0
    assert tiles["Servers"]["share"] == 100 and tiles["Guest"]["share"] == 10
    assert result["total"] == 3


def test_vlan_rates_ignore_stale_buckets(db):
    vlan = VLAN(name="Servers")
    db.add(vlan)
    db.flush()
    device = _device(db, vlan, "198.51.100.10")
    _usage(db, device, NOW - timedelta(hours=3), "download", 3_000_000)
    db.commit()
    assert vlan_rates(db, NOW)["tiles"][0]["bps"] is None


# ----------------------------------------------------------------- uptime


def test_uptime_strip_and_percentages_come_from_check_history(db):
    healthy = make_monitor(db, "Alpha host", "192.0.2.10", last_status="up")
    flaky = make_monitor(db, "Beta service", "192.0.2.11", last_status="up", check_type="tcp")
    today = datetime(NOW.year, NOW.month, NOW.day)
    for _ in range(4):
        check(db, healthy, today + timedelta(hours=1))
    check(db, flaky, today - timedelta(days=1) + timedelta(hours=2), status="down")
    check(db, flaky, today - timedelta(days=1) + timedelta(hours=3))
    check(db, flaky, today - timedelta(days=2) + timedelta(hours=2), health="warning")
    db.add(NetworkMonitorOutage(monitor_id=flaky.id, started_at=today - timedelta(days=1, hours=-2), ended_at=today - timedelta(days=1, hours=-3), incident_type="offline"))
    db.commit()

    result = uptime_panel(db, hidden_ids=[], now=NOW)

    rows = {row["name"]: row for row in result["rows"]}
    assert rows["Alpha host"]["percent"] == "100%" and rows["Alpha host"]["perfect"] is True
    assert rows["Alpha host"]["days"][-1] == "operational"
    assert rows["Alpha host"]["days"][:-1] == ["none"] * 29
    assert rows["Beta service"]["percent"] == "66.67%"
    assert rows["Beta service"]["days"][-2] == "outage"
    assert rows["Beta service"]["days"][-3] == "degraded"
    assert result["incidents"] == 1
    assert result["overall"] == "85.71%"
    assert {host["kind"] for host in result["hosts"]} == {"ICMP", "TCP"}
    assert "1 outage days" in rows["Beta service"]["aria"]


def test_uptime_selection_limits_rows_and_summary(db):
    shown = make_monitor(db, "Alpha host", "192.0.2.10", last_status="up")
    hidden = make_monitor(db, "Beta host", "192.0.2.11", last_status="down")
    check(db, shown, NOW - timedelta(hours=1))
    check(db, hidden, NOW - timedelta(hours=1), status="down")
    db.commit()

    result = uptime_panel(db, hidden_ids=[hidden.id], now=NOW)

    assert [row["name"] for row in result["rows"]] == ["Alpha host"]
    assert result["shown_count"] == 1 and result["total"] == 2
    assert result["overall"] == "100%"
    assert {host["name"]: host["on"] for host in result["hosts"]} == {"Alpha host": True, "Beta host": False}


def test_uptime_with_nothing_selected_has_no_invented_summary(db):
    monitor = make_monitor(db, "Alpha host", "192.0.2.10", last_status="up")
    db.commit()
    result = uptime_panel(db, hidden_ids=[monitor.id], now=NOW)
    assert result["rows"] == []
    assert result["overall"] is None and result["incidents"] is None and result["longest_uptime"] is None


def test_longest_uptime_measures_from_last_offline_recovery(db):
    monitor = make_monitor(db, "Alpha host", "192.0.2.10", last_status="up", created_at=NOW - timedelta(days=90))
    db.add(NetworkMonitorOutage(monitor_id=monitor.id, started_at=NOW - timedelta(days=3), ended_at=NOW - timedelta(days=2, hours=6), incident_type="offline"))
    db.commit()
    assert uptime_panel(db, hidden_ids=[], now=NOW)["longest_uptime"] == "2d 6h"


def test_uptime_interval_reports_real_monitor_intervals(db):
    make_monitor(db, "Alpha host", "192.0.2.10", interval_seconds=60)
    make_monitor(db, "Beta host", "192.0.2.11", interval_seconds=300)
    db.commit()
    assert uptime_panel(db, hidden_ids=[], now=NOW)["interval_seconds"] == [60, 300]


def test_uptime_panel_requires_uptime_module_access(db):
    account = make_user(db)
    db.query(UserModulePermission).filter_by(user_id=account.id, module_key="network_monitor").update({"allowed": False})
    db.commit()
    account._accessible_module_keys = None
    keys = {item["key"] for item in dashboard_service.registry(db, account)}
    assert "uptime" not in keys and "network_traffic" not in keys


# ----------------------------------------------------------------- module cards


def test_module_cards_render_unavailable_for_unauthorised_sections(db):
    account = make_user(db)
    db.query(UserModulePermission).filter(
        UserModulePermission.user_id == account.id,
        UserModulePermission.module_key.in_(["vlan_ip_manager", "network_monitor"]),
    ).update({"allowed": False}, synchronize_session=False)
    db.commit()
    account._accessible_module_keys = None
    cards = {card["key"]: card for card in dashboard_service._build(db, account, "module_overview")["cards"]}
    rows = {row["label"]: row["value"] for row in cards["networking"]["rows"]}
    assert rows["IP addresses"] is None and rows["VLANs"] is None and rows["Domains"] == 0
    remote = {row["label"]: row["value"] for row in cards["remote_manager"]["rows"]}
    assert remote["Offline"] is None


def test_remote_offline_uses_uptime_state_of_the_same_ip_record(db):
    account = make_user(db)
    down = make_monitor(db, "Gateway", "192.0.2.1", last_status="down")
    up = make_monitor(db, "Server", "192.0.2.2", last_status="up")
    db.add_all([
        RemoteAccess(ip_address_id=down.ip_address_id, protocol="ssh", is_enabled=True),
        RemoteAccess(ip_address_id=up.ip_address_id, protocol="rdp", is_enabled=True),
    ])
    db.commit()
    cards = {card["key"]: card for card in dashboard_service._build(db, account, "module_overview")["cards"]}
    remote = {row["label"]: row for row in cards["remote_manager"]["rows"]}
    assert remote["Targets"]["value"] == 2
    assert remote["Offline"]["value"] == 1 and remote["Offline"]["tone"] == "warn"
    assert cards["remote_manager"]["state"] == "warn"


def test_empty_installation_reports_no_fabricated_values(db):
    account = make_user(db, role="admin")
    data = snapshot(db, account)["widgets"]
    assert all(widget["status"] == "ok" for widget in data.values())
    traffic = data["network_traffic"]["data"]
    assert traffic["configured"] is False and traffic["points"] == []
    uptime = data["uptime"]["data"]
    assert uptime["rows"] == [] and uptime["overall"] is None
    infra = data["infrastructure_summary"]["data"]
    assert infra["cpu_percent"] is None and infra["memory_percent"] is None
    assert data["attention_required"]["data"]["items"] == []
    runbooks = next(card for card in data["module_overview"]["data"]["cards"] if card["key"] == "runbooks")
    assert {row["label"]: row["value"] for row in runbooks["rows"]}["Most recent"] is None
