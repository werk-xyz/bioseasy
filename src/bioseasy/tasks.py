# SPDX-License-Identifier: GPL-3.0-or-later
"""Huey tasks that run backups, discovery, pairing and the schedule tick.

`build(rt)` constructs one Huey instance bound to `rt` and registers every task on it, instead of
a module-level singleton built from `config.load()`: the web process (app.py, only ever
enqueuing) and the worker process (`bioseasy worker`, __init__.py, consuming) each call this with
their own Runtime, so a test's own Settings (create_app(settings, engine)) is what the web
process's tasks actually run against, not whatever the real environment happens to hold. In
production both processes are still pointed at the same queue file, because both are ultimately
built from the same BIOSEASY_* environment (config.load()).

The queue lives in its own SQLite file, `<data_dir>/queue.db`, separate from bioseasy.db: huey's
SqliteHuey storage uses WAL and `BEGIN EXCLUSIVE` for its own bookkeeping (huey/storage.py,
checked against the installed huey 3.4.0), which must never contend with the app's own tables.

Tests: set the returned `Tasks.huey.immediate = True` to run a task synchronously, in-process,
without a separate consumer. Checked against huey 3.4.0 (huey/api.py): `Huey.enqueue()` checks
`self._immediate` and calls `self.execute(task)` directly instead of writing to storage when it
is set; with the default `immediate_use_memory=True` the `immediate` setter also swaps the
storage backend for an in-memory one, so immediate mode never touches queue.db.
"""

from __future__ import annotations

import importlib.metadata
import logging
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from huey import SqliteHuey, crontab

from . import activity, browse, runtime, snapshots, update_check, verify
from .discovery import discover_and_refresh
from .runtime import Runtime
from .ticker import acquire_tick_lease

log = logging.getLogger("bioseasy")


@dataclass
class Tasks:
    huey: SqliteHuey
    backup_device: Callable[[str, str, int | None], None]
    discover_now: Callable[[], list]
    pair_device: Callable[[str], None]
    enable_wifi_step: Callable[[str], None]
    netcheck_step: Callable[[str], None]
    detect_setup_step: Callable[[str], None]
    compute_dir_size: Callable[[str], None]
    # (udid, snapshot_name); enqueued by the device page's "Verify" button (app.py).
    verify_snapshot: Callable[[str, str], None]
    # None when settings.schedule_minutes <= 0 (ticking off, config.py); otherwise the periodic
    # task itself, callable directly the way a test drives it without a real consumer.
    tick: Callable[[], None] | None
    # Always registered (unlike tick): update_check.should_check is the actual on/off switch
    # (GITHUB_REPO set and the admin's own toggle), checked inside the task itself rather than at
    # registration time, so flipping the Settings toggle takes effect without restarting the
    # worker. Callable directly in tests, same as tick.
    check_for_update: Callable[[], None]


def build(rt: Runtime) -> Tasks:
    """Build one Huey instance and its tasks, bound to `rt`. Call once per process (app.py's
    create_app, and __init__.py's _worker) - the queue file lives at
    `rt.settings.data_dir / "queue.db"`.
    """
    huey = SqliteHuey("bioseasy", filename=str(rt.settings.data_dir / "queue.db"))

    @huey.task()
    def backup_device(udid: str, trigger: str, run_id: int | None = None) -> None:
        """Enqueued by the web route (app.py); runs the actual backup through JobManager here in
        the worker. JobManager.start() already returns as soon as the run is recorded and its own
        thread is under way, so this task completes quickly regardless of how long the backup
        itself takes; progress and the terminal state are read back from the runs row (jobs.py),
        not from this task's result.

        `run_id`, when given, is a `runs` row the web route already inserted synchronously
        (runtime.mark_backup_starting) before enqueueing this task, so the request's own response
        can show the running state at once; JobManager.start claims that row instead of
        inserting a new one. Other callers (the schedule tick, ticker.py; the Shortcuts API,
        api.py) still pass none and get the previous behaviour.
        """
        rt.jobs.start(udid, trigger, run_id=run_id)

    @huey.task()
    def discover_now() -> list[str]:
        """Refresh device discovery now instead of waiting for the next tick: enqueued by the Add
        page's "Scan now" button (app.py). Returns the UDIDs seen."""
        with activity.track(rt.connect, "discovery"):
            return [d.udid for d in discover_and_refresh(rt.connect, rt.engine, rt.mark_pair_used)]

    @huey.task()
    def pair_device(udid: str) -> None:
        """Enqueued by "Pair and add" (app.py); records the outcome in the pairings row that the
        Add page polls with htmx. See runtime.run_pairing."""
        runtime.run_pairing(rt, udid)

    @huey.task()
    def enable_wifi_step(udid: str) -> None:
        """Enqueued by the setup wizard's Wi-Fi step (app.py). See runtime.run_wifi_enable.

        There is no equivalent task for the encryption step: that one holds a password and must
        never reach queue.db, so it always runs as a plain thread in the web process instead
        (see runtime.run_encryption_enable).
        """
        runtime.run_wifi_enable(rt, udid)

    @huey.task()
    def netcheck_step(udid: str) -> None:
        """Enqueued by the connectivity check button on the setup wizard and the device settings
        page (app.py). See runtime.run_netcheck. Unlike the encryption step, this holds no
        password or pair record content, so it is allowed to run through Huey like every other
        device operation that must not block a request."""
        runtime.run_netcheck(rt, udid)

    @huey.task()
    def detect_setup_step(udid: str) -> None:
        """Enqueued when a device is (re-)added or its setup page is opened with an open step
        (app.py). See runtime.run_setup_detect. Holds no password or pair record content, so
        like netcheck_step it is allowed to run through Huey."""
        runtime.run_setup_detect(rt, udid)

    @huey.task()
    def compute_dir_size(rel_path: str) -> None:
        """Enqueued by the storage browse "Recalculate" button (app.py). Walking a whole snapshot
        tree can take a while, so this always runs in the worker, never in the request."""
        with activity.track(rt.connect, "storage_size"):
            browse.run_compute(rt.connect, rt.settings.backup_root, rel_path)

    @huey.task()
    def verify_snapshot(udid: str, name: str) -> None:
        """Enqueued by the device page's "Verify" button (app.py). Resolves the snapshot path
        itself from the current on-disk list rather than trusting a path carried on the queue, the
        same reason app.py's own snapshot_pin route re-checks a name against list_snapshots before
        building a path. A generation that vanished between the click and this task running (e.g.
        pruned by retention) is simply skipped, not an error."""
        for snap in snapshots.list_snapshots(rt.settings.backup_root, udid):
            if snap.path.name == name:
                verify.run_and_save(rt.connect, snap.path, udid, name)
                return
        log.warning("verify_snapshot: generation %s for device %s no longer exists", name, udid[:8])

    # Wired here, after the task exists, rather than passed into Ticker's constructor: rt.ticker
    # is built by runtime.build() before this function (and the Huey task it registers) exists at
    # all, so the tick can only be handed a way to enqueue deep verification as a second step.
    # Called from both processes that call tasks.build (the web process's create_app and the
    # worker's _worker in __init__.py) - harmless in the web process, which never calls
    # rt.ticker.tick() itself.
    rt.ticker.enqueue_verify = verify_snapshot

    # The tick runs every minute regardless of settings.schedule_minutes: scheduler.decide()
    # judges "due" from each device's own last-success timestamp, not from how often tick()
    # itself is called, so a shorter cadence than schedule_minutes is only more responsive, never
    # wrong. The tick_lease (ticker.acquire_tick_lease) is what actually keeps ticks
    # settings.schedule_minutes apart and stops an accidental second worker from double-ticking.
    # Registering this here is harmless in the web process: a periodic task only ever fires while
    # a consumer's own scheduler thread is running, and the web process never starts one.
    tick = None
    if rt.settings.schedule_minutes > 0:

        @huey.periodic_task(crontab(minute="*"))
        def tick() -> None:
            now = datetime.now(UTC)
            with closing(rt.connect()) as conn:
                acquired = acquire_tick_lease(conn, now, timedelta(minutes=rt.settings.schedule_minutes))
            if not acquired:
                return
            rt.ticker.tick(now)

    # Runs on the same "every minute, gated inside" shape as tick above; update_check.should_check
    # is what actually keeps real checks a day apart (and off entirely unless an admin opted in
    # and GITHUB_REPO is set), so a missed or delayed periodic tick never causes an extra request.
    current_version = importlib.metadata.version("bioseasy")

    @huey.periodic_task(crontab(minute="*"))
    def check_for_update() -> None:
        with closing(rt.connect()) as conn:
            if update_check.should_check(conn):
                # No udid: activity.for_owner's INNER JOIN therefore never shows this to a member,
                # which is right - asking GitHub for a version is an installation-wide action.
                with activity.track(rt.connect, "update_check"):
                    update_check.run_check(conn, current_version)

    return Tasks(
        huey,
        backup_device,
        discover_now,
        pair_device,
        enable_wifi_step,
        netcheck_step,
        detect_setup_step,
        compute_dir_size,
        verify_snapshot,
        tick,
        check_for_update,
    )
