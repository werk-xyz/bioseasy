# SPDX-License-Identifier: GPL-3.0-or-later
"""tasks.build(rt) wires one Huey instance and its task functions to a Runtime.

Each test builds its own Runtime from a tmp_path Settings, the same way app.py's create_app and
__init__.py's _worker do, so tests need no env-var monkeypatching or module reloading to get an
isolated queue and database.
"""

import sys
import time
from contextlib import closing
from datetime import UTC, datetime

import pytest
from fixtures import write_realistic_backup
from huey import SqliteHuey

import bioseasy
from bioseasy import db, runtime, snapshots, storage, tasks, ticker, verify
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES

PHONE = DEMO_DEVICES[0]
TABLET = DEMO_DEVICES[1]


@pytest.fixture
def built(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=5)
    rt = runtime.build(settings, worker_id="test-worker")
    built_tasks = tasks.build(rt)
    # Huey 3.4.0 (huey/api.py): Huey.enqueue() checks self._immediate and calls self.execute(task)
    # directly instead of writing to storage, so a task runs synchronously here without a
    # consumer; with the default immediate_use_memory=True the immediate setter also swaps
    # SqliteHuey's storage for an in-memory one.
    built_tasks.huey.immediate = True
    root_id = storage.initialise(root)
    with closing(rt.connect()) as conn:
        db.migrate(conn)
        conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (PHONE.udid, PHONE.name))
        conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (TABLET.udid, TABLET.name))
        db.set_setting(conn, "backup_root_id", root_id)
    return rt, built_tasks


def _wait_for_completion(rt, udid, timeout=10):
    deadline = time.monotonic() + timeout
    while rt.jobs.state(udid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert rt.jobs.state(udid) is None, "backup did not finish"


def test_backup_device_runs_the_same_jobmanager_code_path_to_completion(built):
    rt, built_tasks = built
    # backup_device only calls JobManager.start(), which itself hands the work to its own
    # thread; huey's immediate mode makes the *task* run synchronously, not the backup.
    built_tasks.backup_device(PHONE.udid, "manual")
    _wait_for_completion(rt, PHONE.udid)
    with closing(rt.connect()) as conn:
        row = conn.execute("SELECT status FROM runs WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["status"] == "succeeded"


def test_discover_now_returns_the_demo_devices_and_persists_them(built):
    rt, built_tasks = built
    result = built_tasks.discover_now()
    assert PHONE.udid in result.get()
    with closing(rt.connect()) as conn:
        row = conn.execute("SELECT paired FROM seen_devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row is not None and row["paired"] == 1


def test_pair_device_marks_the_device_as_paired(built):
    rt, built_tasks = built
    before = {d.udid: d.paired for d in rt.engine.discover()}
    assert before[TABLET.udid] is False
    built_tasks.pair_device(TABLET.udid)
    after = {d.udid: d.paired for d in rt.engine.discover()}
    assert after[TABLET.udid] is True


_FIXED_TICK_TIME = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)


def _fix_ticker_clock(monkeypatch, at: datetime) -> None:
    # The periodic task calls Ticker.tick() without a time, so it reads datetime.now. The global
    # default window is 20:00-23:00 (defaults.py); inside it the scheduler starts a backup instead
    # of owing a nudge, which made this test red every evening.
    class _Fixed(datetime):
        @classmethod
        def now(cls, tz=None):
            return at.astimezone(tz) if tz else at.replace(tzinfo=None)

    # tasks.tick reads the clock itself and hands it to Ticker.tick, so both modules need it.
    monkeypatch.setattr(tasks, "datetime", _Fixed)
    monkeypatch.setattr(ticker, "datetime", _Fixed)


def test_tick_is_registered_and_runs_the_scheduler(built, monkeypatch):
    _fix_ticker_clock(monkeypatch, _FIXED_TICK_TIME)
    rt, built_tasks = built
    assert built_tasks.tick is not None, "tick should be built when schedule_minutes > 0"
    with closing(rt.connect()) as conn:
        before = conn.execute("SELECT last_nudge_at FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert before["last_nudge_at"] is None
    built_tasks.tick().get()
    # PHONE has no scheduling window and has never backed up, so scheduler.decide() cannot start
    # a backup but does owe it a reminder; last_nudge_at only changes if tick() genuinely ran the
    # real Ticker (with its database writes), not a stub.
    with closing(rt.connect()) as conn:
        after = conn.execute("SELECT last_nudge_at FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert after["last_nudge_at"] is not None


def test_tick_enqueues_deep_verification_instead_of_running_it_inline(tmp_path):
    """The defect this fix addresses: `_verify_due` used to call verify.run_and_save directly,
    walking Manifest.db on the tick's own thread. Proven here with a real (non-immediate) Huey
    and no consumer running: a tick that has a generation due for verification must enqueue
    exactly one verify_snapshot task and return, leaving nothing executed and no result saved -
    the opposite would mean the walk still happened on the calling thread.
    """
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=5)
    rt = runtime.build(settings, worker_id="test-worker")
    built_tasks = tasks.build(rt)  # huey.immediate left False: nothing may run synchronously here
    root_id = storage.initialise(root)
    with closing(rt.connect()) as conn:
        db.migrate(conn)
        conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (PHONE.udid, PHONE.name))
        db.set_setting(conn, "backup_root_id", root_id)
    write_realistic_backup(root / PHONE.udid, PHONE, encrypted=False)
    snapshots.take(root, PHONE.udid, datetime(2026, 9, 1, tzinfo=UTC), hardlinks=False)

    enqueued = []
    original_enqueue = built_tasks.huey.enqueue

    def spy(task):
        enqueued.append(task)
        return original_enqueue(task)

    built_tasks.huey.enqueue = spy

    rt.ticker.tick(datetime(2026, 9, 15, tzinfo=UTC))

    assert len(enqueued) == 1
    assert enqueued[0].name == "verify_snapshot"
    with closing(rt.connect()) as conn:
        # Enqueued, not executed: no consumer ever ran, so nothing landed in the database yet.
        assert verify.load_results(conn, PHONE.udid) == {}


def test_check_for_update_is_registered_and_is_a_noop_while_the_checker_is_off(built):
    """The update checker is off by default, so the task must not make a network
    call at all; see test_update_check.py for the gating logic itself."""
    from bioseasy import update_check

    rt, built_tasks = built
    assert built_tasks.check_for_update is not None
    with closing(rt.connect()) as conn:
        assert update_check.last_result(conn) is None
    built_tasks.check_for_update().get()
    with closing(rt.connect()) as conn:
        # Still nothing: should_check() returns False (repo unset), so run_check() never ran.
        assert update_check.last_result(conn) is None


def test_tick_is_not_built_when_scheduling_is_off(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    rt = runtime.build(settings, worker_id="test-worker")
    assert tasks.build(rt).tick is None


def test_worker_subcommand_dispatches_to_worker(monkeypatch):
    called = []
    monkeypatch.setattr(bioseasy, "_worker", lambda: called.append(True))
    monkeypatch.setattr(sys, "argv", ["bioseasy", "worker"])
    bioseasy.main()
    assert called == [True]


def test_worker_migrates_sweeps_orphans_and_runs_the_consumer(tmp_path, monkeypatch):
    # No huey.immediate here: this checks the CLI wiring itself (migrate, sweep, heartbeat,
    # consumer.run), not task execution, so the real (fake) consumer's run() must be called.
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    monkeypatch.setenv("BIOSEASY_DATA_DIR", str(data))
    monkeypatch.setenv("BIOSEASY_BACKUP_ROOT", str(root))
    monkeypatch.setenv("BIOSEASY_ENGINE", "demo")
    monkeypatch.setenv("BIOSEASY_SECRET_KEY", "test-secret")

    # A stale running row from before this "restart": proves _worker() itself calls
    # sweep_orphan_runs on startup.
    with closing(db.connect(data / "bioseasy.db")) as conn:
        db.migrate(conn)
        conn.execute("INSERT INTO devices (udid, name) VALUES ('stale', 'Stale')")
        stale = "2020-01-01T00:00:00Z"
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, worker_id, heartbeat_at) "
            "VALUES ('stale', 'manual', ?, 'running', 'dead', ?)",
            (stale, stale),
        )

    ran = []

    class FakeConsumer:
        def run(self) -> None:
            ran.append(True)

    # _worker() builds its own Tasks internally (tasks.build), so there is no module-level huey
    # instance left to monkeypatch beforehand; patching the class method reaches whichever
    # instance _worker() ends up constructing.
    monkeypatch.setattr(SqliteHuey, "create_consumer", lambda self, **kw: FakeConsumer())

    bioseasy._worker()

    assert ran == [True]
    with closing(db.connect(data / "bioseasy.db")) as conn:
        row = conn.execute("SELECT status, message FROM runs WHERE udid = 'stale'").fetchone()
    assert row["status"] == "failed"
    assert row["message"] == "Worker restarted during the backup"


def test_compute_dir_size_task_writes_the_result_to_the_cache(built):
    rt, built_tasks = built
    live = rt.settings.backup_root / PHONE.udid
    live.mkdir(exist_ok=True)
    (live / "a.bin").write_bytes(b"x" * 30)
    (live / "b.bin").write_bytes(b"y" * 20)

    built_tasks.compute_dir_size(PHONE.udid)

    with closing(rt.connect()) as conn:
        row = conn.execute("SELECT * FROM dir_sizes WHERE path = ?", (PHONE.udid,)).fetchone()
    assert row["bytes"] == 50
    assert row["files"] == 2
    assert row["state"] == "done"
