"""P1 regression tests: REINITIALISE must not leak state from failures or history.

Covers D5 (authority), D6 (configuration baselines) and D7 (automatic failover
restored from stale saved state) beyond the Gate A reproductions.  Synthetic
data only; Pi-hole reads are replaced by the Gate A ``offline_pihole`` fixture.
"""

from __future__ import annotations

import json

import pytest

from app.models.models import HAMaintenanceRun
from app.services.ha_maintenance import _fail_safe, advance_reinitialisation, start_reinitialisation
from ha_simulation import hal_like_cluster, sqlite_session
from test_ha_gate_a_maintenance_defects import drive, offline_pihole, split_cluster  # noqa: F401  (fixture)


def healthy(*, automatic_failover: bool, automatic_sync: bool = False):
    sim = hal_like_cluster(sqlite_session(), maintenance_mode=False, automatic_failover=automatic_failover)
    sim.cluster.automatic_sync_enabled = automatic_sync
    sim.db.commit()
    sim.report_both(2)
    return sim


def fail_first_run(sim) -> HAMaintenanceRun:
    """A REINITIALISE that fails safe straight away, leaving the latch held."""
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True)
    _fail_safe(sim.db, run, "Synthetic failure for regression testing.")
    assert sim.cluster.maintenance_mode is True and sim.cluster.automatic_failover_enabled is False
    return run


def progress(run: HAMaintenanceRun) -> list[str]:
    return json.loads(run.result_json or "{}").get("progress") or []


def test_fresh_reinitialise_still_restores_automatic_failover_that_was_on_at_start():
    sim = healthy(automatic_failover=True, automatic_sync=True)
    run = drive(sim, start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True))
    assert run.status == "SUCCEEDED"
    assert sim.cluster.automatic_failover_enabled is True
    assert sim.cluster.automatic_sync_enabled is True


def test_retry_under_held_latch_keeps_sync_settings_but_leaves_automatic_failover_off():
    sim = healthy(automatic_failover=True, automatic_sync=True)
    failed = fail_first_run(sim)
    run = drive(sim, start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True))
    assert run.status == "SUCCEEDED"
    assert sim.cluster.automatic_failover_enabled is False
    assert sim.cluster.automatic_sync_enabled is True  # carried from the latch-holding run
    previous = json.loads(run.previous_state_json)
    assert previous["inherited_from_maintenance_run_id"] == failed.public_id
    assert previous["automatic_failover_review_required"] is True
    assert any("Automatic failover was left disabled" in row for row in progress(run))


def test_released_latch_is_not_inherited_by_a_later_reinitialise():
    sim = healthy(automatic_failover=True, automatic_sync=True)
    fail_first_run(sim)
    sim.cluster.maintenance_mode = False  # as release_maintenance_latch leaves it
    sim.cluster.automatic_sync_enabled = False
    sim.db.commit()
    run = drive(sim, start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True))
    assert run.status == "SUCCEEDED"
    assert "inherited_from_maintenance_run_id" not in json.loads(run.previous_state_json)
    assert (sim.cluster.automatic_failover_enabled, sim.cluster.automatic_sync_enabled) == (False, False)


def test_malformed_saved_state_falls_back_to_current_settings():
    sim = healthy(automatic_failover=True)
    failed = fail_first_run(sim)
    failed.previous_state_json = "[not-a-state-object]"
    sim.db.commit()
    run = drive(sim, start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.one, acknowledged=True))
    assert run.status == "SUCCEEDED"
    assert sim.cluster.automatic_failover_enabled is False


def _through_backups(sim, run, monkeypatch):
    # Only the explicit calls below may advance the run; the coordinator, which
    # evaluates each simulated heartbeat, would otherwise advance it past the backups.
    monkeypatch.setattr("app.services.ha_watchdog.advance_reinitialisation", lambda db, run: run)
    for _ in range(2):  # WAITING_FOR_REPORTS -> BACKING_UP -> SYNCHRONISING
        sim.report_both()
        advance_reinitialisation(sim.db, run)
    assert run.phase == "SYNCHRONISING", (run.phase, run.error_redacted)


@pytest.mark.usefixtures("offline_pihole")
def test_failed_run_restores_only_baselines_that_still_hold_what_it_wrote(monkeypatch):
    sim = split_cluster()
    sim.one.configuration_checksum, sim.two.configuration_checksum = "a" * 64, "b" * 64
    sim.one.configuration_snapshot_json = sim.two.configuration_snapshot_json = '{"dns":{}}'
    sim.db.commit()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.two, acknowledged=True)
    _through_backups(sim, run, monkeypatch)
    assert sim.cluster.authoritative_node_id == sim.two.id  # written during BACKING_UP, as before
    sim.two.configuration_checksum = "c" * 64  # a later verified change to the target
    sim.db.commit()
    _fail_safe(sim.db, run, "Synthetic failure after backups.")
    assert sim.cluster.authoritative_node_id == sim.one.id
    assert sim.one.configuration_checksum == "a" * 64 and sim.one.configuration_snapshot_json == '{"dns":{}}'
    assert sim.two.configuration_checksum == "c" * 64


@pytest.mark.usefixtures("offline_pihole")
def test_failed_run_does_not_override_authority_changed_by_another_writer(monkeypatch):
    sim = split_cluster()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.two, acknowledged=True)
    _through_backups(sim, run, monkeypatch)
    sim.cluster.authoritative_node_id = None  # some other verified decision since the backup
    sim.db.commit()
    _fail_safe(sim.db, run, "Synthetic failure after backups.")
    assert sim.cluster.authoritative_node_id is None


@pytest.mark.usefixtures("offline_pihole")
def test_runs_created_before_p1_keep_their_previous_failure_behaviour(monkeypatch):
    sim = split_cluster()
    run = start_reinitialisation(sim.db, sim.cluster, sim.admin, desired_active=sim.one, authority=sim.two, acknowledged=True)
    legacy = json.loads(run.previous_state_json)
    legacy.pop("restore_on_failure")
    run.previous_state_json = json.dumps(legacy)
    sim.db.commit()
    _through_backups(sim, run, monkeypatch)
    _fail_safe(sim.db, run, "Synthetic failure after backups.")
    assert sim.cluster.authoritative_node_id == sim.two.id  # unchanged legacy behaviour; no guessing
