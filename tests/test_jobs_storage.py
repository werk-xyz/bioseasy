# SPDX-License-Identifier: GPL-3.0-or-later
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from bioseasy import db, storage
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine
from bioseasy.jobs import JobManager, sweep_orphan_runs

PHONE = DEMO_DEVICES[0]


@pytest.fixture
def connect(tmp_path):
    path = tmp_path / "app.db"
    with closing(db.connect(path)) as c:
        db.migrate(c)
        c.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (PHONE.udid, PHONE.name))
    return lambda: db.connect(path)


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "backups"
    path.mkdir()
    return path


def _wait(jobs, udid, timeout=10):
    deadline = time.monotonic() + timeout
    while jobs.state(udid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert jobs.state(udid) is None, "job did not finish"


def _last_run(connect):
    with closing(connect()) as conn:
        return dict(conn.execute("SELECT status, message FROM runs ORDER BY id DESC LIMIT 1").fetchone())


def test_storage_check_detects_unmounted_volume(root):
    root_id = storage.initialise(root)
    assert storage.check(root, root_id, 0).ok
    assert storage.check(root, root_id, 0).hardlinks is True
    (root / storage.MARKER).unlink()
    assert "Marker file missing: is the volume mounted?" in storage.check(root, root_id, 0).problems
    assert not storage.check(root / "nope", root_id, 0).ok


def test_backup_run_succeeds_and_emits_events(connect, root):
    root_id = storage.initialise(root)
    events = []
    jobs = JobManager(
        connect,
        DemoEngine(step_seconds=0),
        root,
        lambda: storage.check(root, root_id, 0),
        on_event=lambda e, u, m: events.append(e),
    )
    jobs.start(PHONE.udid, "manual")
    _wait(jobs, PHONE.udid)
    assert _last_run(connect)["status"] == "succeeded"
    assert events == ["waiting_for_passcode", "succeeded"]


def test_successful_backup_is_logged_and_fills_model_and_ios_version(connect, root, caplog):
    root_id = storage.initialise(root)
    jobs = JobManager(connect, DemoEngine(step_seconds=0), root, lambda: storage.check(root, root_id, 0))
    with caplog.at_level("INFO", logger="bioseasy.jobs"):
        jobs.start(PHONE.udid, "manual")
        _wait(jobs, PHONE.udid)
    assert f"backup of {PHONE.udid[:8]} ended succeeded" in caplog.text
    with closing(connect()) as conn:
        row = conn.execute("SELECT product_type, os_version FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert (row["product_type"], row["os_version"]) == (PHONE.product_type, PHONE.os_version)


def test_successful_backup_marks_pair_used_at(connect, root):
    """The "backup start" trigger for devices.pair_used_at (db.py, status.py): once the demo
    engine's (simulated) lockdown session with the stored pair record succeeds - reaches
    TRANSFERRING - JobManager must persist it, the same as Pmd3Engine would for a real device."""
    root_id = storage.initialise(root)
    with closing(connect()) as conn:
        assert (
            conn.execute("SELECT pair_used_at FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()["pair_used_at"]
            is None
        )

    marked = []

    def mark_pair_used(udid: str) -> None:
        marked.append(udid)
        with closing(connect()) as conn:
            conn.execute(
                "UPDATE devices SET pair_used_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE udid = ?", (udid,)
            )

    jobs = JobManager(
        connect,
        DemoEngine(step_seconds=0),
        root,
        lambda: storage.check(root, root_id, 0),
        mark_pair_used=mark_pair_used,
    )
    jobs.start(PHONE.udid, "manual")
    _wait(jobs, PHONE.udid)

    assert marked == [PHONE.udid]
    with closing(connect()) as conn:
        row = conn.execute("SELECT pair_used_at FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["pair_used_at"] is not None and row["pair_used_at"].endswith("Z")


def test_backup_refused_when_storage_check_fails(connect, root):
    jobs = JobManager(connect, DemoEngine(step_seconds=0), root, lambda: storage.check(root, "x", 0))
    jobs.start(PHONE.udid, "manual")
    _wait(jobs, PHONE.udid)
    run = _last_run(connect)
    assert run["status"] == "failed" and run["message"].startswith("Storage check failed")
    assert not (root / PHONE.udid).exists()


def test_storage_check_failure_calls_notify_storage_failed(connect, root):
    """The free-space guard already blocked the backup (see the test above); this proves the
    admin notification hook (runtime.py's notify_storage_failed, throttled to once per day per
    volume there) actually fires, with the same message the run was recorded with."""
    messages = []
    jobs = JobManager(
        connect,
        DemoEngine(step_seconds=0),
        root,
        lambda: storage.check(root, "x", 0),
        notify_storage_failed=messages.append,
    )
    jobs.start(PHONE.udid, "manual")
    _wait(jobs, PHONE.udid)
    assert len(messages) == 1
    assert messages[0].startswith("Storage check failed")
    assert messages[0] == _last_run(connect)["message"]


def test_successful_backup_does_not_call_notify_storage_failed(connect, root):
    root_id = storage.initialise(root)
    messages = []
    jobs = JobManager(
        connect,
        DemoEngine(step_seconds=0),
        root,
        lambda: storage.check(root, root_id, 0),
        notify_storage_failed=messages.append,
    )
    jobs.start(PHONE.udid, "manual")
    _wait(jobs, PHONE.udid)
    assert messages == []


def test_engine_failure_is_recorded(connect, root):
    root_id = storage.initialise(root)
    engine = DemoEngine(step_seconds=0, fail_udids=frozenset({PHONE.udid}))
    jobs = JobManager(connect, engine, root, lambda: storage.check(root, root_id, 0))
    jobs.start(PHONE.udid, "manual")
    _wait(jobs, PHONE.udid)
    assert _last_run(connect) == {"status": "failed", "message": "Connection to the device was lost"}


def test_schema_applies_and_is_idempotent(tmp_path):
    with closing(db.connect(tmp_path / "m.db")) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        assert db.migrate(conn) == db.SCHEMA_VERSION
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}
        assert {"window_start", "window_end", "only_when_charging", "last_nudge_at"} <= cols


def test_second_manager_instance_cannot_start_a_second_run_for_the_same_device(connect, root):
    # Simulates two processes (e.g. two worker consumers) racing to start the same device: only
    # one JobManager instance's in-memory dict can ever know about the other's run, so the real
    # guard has to be the database's partial unique index (db.py: runs_one_running).
    root_id = storage.initialise(root)
    engine = DemoEngine(step_seconds=1)
    first = JobManager(connect, engine, root, lambda: storage.check(root, root_id, 0))
    second = JobManager(connect, engine, root, lambda: storage.check(root, root_id, 0))
    state1 = first.start(PHONE.udid, "manual")
    state2 = second.start(PHONE.udid, "manual")
    assert state1.run_id == state2.run_id
    with closing(connect()) as conn:
        rows = conn.execute("SELECT id FROM runs WHERE udid = ? AND status = 'running'", (PHONE.udid,)).fetchall()
    assert len(rows) == 1
    # Only "first" spawned the worker thread; "second" must not think it owns this run.
    assert second.state(PHONE.udid) is None
    _wait(first, PHONE.udid)


def test_sweep_orphan_runs_fails_stale_or_unregistered_workers_but_not_fresh_ones(tmp_path):
    with closing(db.connect(tmp_path / "sweep.db")) as conn:
        db.migrate(conn)
        for udid in ("stale-device", "fresh-device", "unknown-device"):
            conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (udid, udid))
        now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
        old = (now - timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        recent = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.execute("INSERT INTO workers (id, heartbeat_at) VALUES ('dead', ?)", (old,))
        conn.execute("INSERT INTO workers (id, heartbeat_at) VALUES ('alive', ?)", (recent,))
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, worker_id, heartbeat_at) "
            "VALUES ('stale-device', 'manual', ?, 'running', 'dead', ?)",
            (old, old),
        )
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, worker_id, heartbeat_at) "
            "VALUES ('fresh-device', 'manual', ?, 'running', 'alive', ?)",
            (recent, recent),
        )
        # 'ghost' never registered in the workers table at all: the "worker_id is unknown" case.
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, worker_id, heartbeat_at) "
            "VALUES ('unknown-device', 'manual', ?, 'running', 'ghost', ?)",
            (recent, recent),
        )
        swept = sweep_orphan_runs(conn, now)
        assert swept == 2
        rows = {r["udid"]: (r["status"], r["message"]) for r in conn.execute("SELECT udid, status, message FROM runs")}
    assert rows["stale-device"] == ("failed", "Worker restarted during the backup")
    assert rows["unknown-device"] == ("failed", "Worker restarted during the backup")
    assert rows["fresh-device"][0] == "running"


def test_heartbeat_thread_writes_to_the_workers_table(connect, root):
    jobs = JobManager(
        connect, DemoEngine(step_seconds=0), root, lambda: storage.check(root, "x", 0), worker_id="test-worker"
    )
    jobs.start_heartbeat()
    try:
        with closing(connect()) as conn:
            row = conn.execute("SELECT heartbeat_at FROM workers WHERE id = ?", ("test-worker",)).fetchone()
        assert row is not None
    finally:
        jobs.stop_heartbeat()


def test_retention_removing_a_snapshot_also_drops_its_stored_verification(connect, root):
    """apply_retention (snapshots.py) rmtree's a pruned generation's directory but has no
    database connection to clean up after itself; snapshot_verifications is keyed only by
    (udid, snapshot_name), with no foreign key to anything that tracks whether the snapshot
    still exists on disk, so a stale row would otherwise sit there forever, one per generation
    ever verified over the device's whole lifetime. jobs.JobManager._snapshot is the one real
    caller of apply_retention and is the only place with both the removed paths and a
    connection, so that is where the cleanup belongs."""
    from bioseasy import defaults as backup_defaults
    from bioseasy import snapshots, verify
    from bioseasy.snapshots import RetentionPolicy

    live = root / PHONE.udid
    (live / "Manifest.db").parent.mkdir(parents=True, exist_ok=True)
    (live / "Manifest.db").write_bytes(b"v1")
    root_id = storage.initialise(root)

    keep_one = backup_defaults.GlobalDefaults(
        window_start=backup_defaults.DEFAULT_WINDOW_START,
        window_end=backup_defaults.DEFAULT_WINDOW_END,
        only_when_charging=backup_defaults.DEFAULT_ONLY_WHEN_CHARGING,
        interval_hours=backup_defaults.DEFAULT_INTERVAL_HOURS,
        overdue_days=backup_defaults.DEFAULT_OVERDUE_DAYS,
        retention=RetentionPolicy(keep_last=1),
        free_space_threshold_gb=backup_defaults.DEFAULT_FREE_SPACE_THRESHOLD_GB,
        notice_lead_minutes=backup_defaults.DEFAULT_NOTICE_LEAD_MINUTES,
    )
    jobs = JobManager(
        connect, DemoEngine(step_seconds=0), root, lambda: storage.check(root, root_id, 0), lambda: keep_one
    )

    # Three generations, a verification result stored for each - as the real tick would after
    # deep-verifying them (verify.save_result), keyed by the same snapshot directory names
    # apply_retention will look at.
    # Backdated, not offset into the future: _snapshot below takes one more generation with the
    # real current time, which must sort after all three of these or its own name collides with
    # one of them.
    made = [
        snapshots.take(root, PHONE.udid, datetime.now(UTC) - timedelta(minutes=3 - i), hardlinks=True).name
        for i in range(3)
    ]
    with closing(connect()) as conn:
        for name in made:
            verify.save_result(conn, PHONE.udid, name, verify.VerifyResult("verified", 1, 1, 0), datetime.now(UTC))
        stored_before = {r["snapshot_name"] for r in conn.execute("SELECT snapshot_name FROM snapshot_verifications")}
    assert stored_before == set(made)

    # keep_last=1: retention removes generations, exactly as a real backup's own cleanup step
    # would (_snapshot always takes one more, current, generation first, then applies retention).
    jobs._snapshot(PHONE.udid, storage.check(root, root_id, 0))

    remaining_on_disk = {s.path.name for s in snapshots.list_snapshots(root, PHONE.udid)}
    removed = set(made) - remaining_on_disk
    assert removed, "sanity: retention did not actually prune any of the pre-made generations"
    with closing(connect()) as conn:
        stored_after = {r["snapshot_name"] for r in conn.execute("SELECT snapshot_name FROM snapshot_verifications")}
    orphaned = removed & stored_after
    assert not orphaned, f"orphaned verification rows for already-deleted snapshots: {orphaned}"
    assert (set(made) & remaining_on_disk) <= stored_after  # a still-present generation keeps its row


def test_effective_policy_uses_device_override_over_server_default(connect, root):
    from bioseasy import defaults as backup_defaults
    from bioseasy.snapshots import RetentionPolicy

    retention = RetentionPolicy(keep_last=3, keep_daily=7, keep_weekly=4, keep_monthly=6, keep_yearly=0)
    global_defaults = backup_defaults.GlobalDefaults(
        window_start=backup_defaults.DEFAULT_WINDOW_START,
        window_end=backup_defaults.DEFAULT_WINDOW_END,
        only_when_charging=backup_defaults.DEFAULT_ONLY_WHEN_CHARGING,
        interval_hours=backup_defaults.DEFAULT_INTERVAL_HOURS,
        overdue_days=backup_defaults.DEFAULT_OVERDUE_DAYS,
        retention=retention,
        free_space_threshold_gb=backup_defaults.DEFAULT_FREE_SPACE_THRESHOLD_GB,
        notice_lead_minutes=backup_defaults.DEFAULT_NOTICE_LEAD_MINUTES,
    )
    jobs = JobManager(
        connect, DemoEngine(step_seconds=0), root, lambda: storage.check(root, "x", 0), lambda: global_defaults, UTC
    )

    # No override yet: every column is NULL, so the server defaults apply outright.
    assert jobs._effective_policy(PHONE.udid) == retention

    with closing(connect()) as conn:
        conn.execute("UPDATE devices SET keep_last = 1, keep_yearly = 5 WHERE udid = ?", (PHONE.udid,))
    resolved = jobs._effective_policy(PHONE.udid)
    assert resolved == RetentionPolicy(keep_last=1, keep_daily=7, keep_weekly=4, keep_monthly=6, keep_yearly=5)


def test_unconfirmed_backup_is_not_a_failure(connect, root):
    root_id = storage.initialise(root)
    events = []
    engine = DemoEngine(step_seconds=0, unconfirmed_udids=frozenset({PHONE.udid}))
    jobs = JobManager(
        connect, engine, root, lambda: storage.check(root, root_id, 0), on_event=lambda e, u, m: events.append(e)
    )
    jobs.start(PHONE.udid, "manual")
    _wait(jobs, PHONE.udid)
    assert _last_run(connect)["status"] == "not_confirmed"
    assert events == ["waiting_for_passcode", "not_confirmed"]
