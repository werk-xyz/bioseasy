# SPDX-License-Identifier: GPL-3.0-or-later
"""Carries out the schedule: every few minutes, find reachable devices, start due backups and
send at most one reminder per period.

The rules live in scheduler.decide; this module only gathers its inputs and acts on the result,
so the rules stay testable without threads, clocks or devices.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

from . import activity, scheduler, snapshots, storage, verify
from . import defaults as backup_defaults
from .discovery import refresh_seen_devices
from .engine.base import Engine
from .jobs import JobManager, sweep_orphan_runs

log = logging.getLogger(__name__)
SIGHTINGS_KEPT = timedelta(days=30)
# How long completed-tick rows are kept (reachability.py's "N of M checks"); same retention as
# sightings, so a device's 7-day reachability window is always covered.
TICKS_KEPT = timedelta(days=30)

Alert = Callable[[str, str, str], None]  # (event, udid, detail)
# Alert only hands the message to runtime.notify_event, which sends off this thread; it returns
# before delivery is known - notify.send() gets its own explicit timeout.
# The last_nudge_at / last_overdue_alert_at / last_window_notice_at writes below therefore record
# only that an attempt was made, at this instant - they are the retry-cooldown clock, never a
# claim that the alert arrived. Whether it actually arrived is recorded separately, asynchronously,
# by notify_event itself once notify.send() returns (devices.last_alert_ok/last_alert_error/
# last_alert_at). A timestamp that means "the user was told" is only
# written when the telling actually happened.


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def acquire_tick_lease(conn: sqlite3.Connection, now: datetime, interval: timedelta) -> bool:
    """True if the caller may run the tick now; False if another worker already ticked within
    `interval`. Guards against an accidental second worker double-ticking:
    the Huey periodic task runs every minute (tasks.py), so without this lease two worker
    processes - or one worker restarted moments after the last tick - would both run the full
    schedule at once.

    UPDATE cannot create the 'tick_lease' row (db.py's SCHEMA inserts it once, up front), so a
    missing row here is a bug in the schema, not a case to handle.
    """
    cur = conn.execute(
        "UPDATE settings SET value = ? WHERE key = 'tick_lease' AND value < ?",
        (_iso(now), _iso(now - interval)),
    )
    return cur.rowcount > 0


class Ticker:
    def __init__(
        self,
        connect: Callable[[], sqlite3.Connection],
        engine: Engine,
        jobs: JobManager,
        alert: Alert,
        tz: tzinfo,
        backup_root: Path | None = None,
        storage_check: Callable[[], storage.StorageCheck] | None = None,
        mark_pair_used: Callable[[str], None] | None = None,
        enqueue_verify: Callable[[str, str], None] | None = None,
        on_tick: Callable[[], None] | None = None,
    ):
        self._connect = connect
        self._engine = engine
        self._jobs = jobs
        self._alert = alert
        self._tz = tz
        self._mark_pair_used = mark_pair_used or (lambda _: None)
        # Fired once at the end of every tick, regardless of what the schedule decided (unlike
        # `alert`, which only fires for an overdue/due nudge): runtime.py's MQTT publisher uses
        # this so device ages stay fresh in Home Assistant even when nothing else happened. Must
        # never raise into tick() - see the try/except around its call at the end of tick() below.
        self._on_tick = on_tick
        # Both None in every existing caller that does not care about deep verification (most of
        # tests/test_ticker.py): deep verification is then simply skipped, never run against a
        # root that was never configured for it.
        self._root = backup_root
        self._storage_check = storage_check
        # (udid, snapshot_name) -> enqueues tasks.py's verify_snapshot Huey task. Left settable
        # after construction (runtime.build's public `enqueue_verify` attribute below), not only
        # through this constructor kwarg: runtime.build() creates the Ticker before tasks.build()
        # exists to create the Huey task it must call, so the wiring for the production Ticker is
        # necessarily a second step (tasks.build assigns `rt.ticker.enqueue_verify`). Tests that
        # want deep verification to actually happen pass it here directly instead.
        self.enqueue_verify = enqueue_verify

    def _charging(self, udid: str) -> bool | None:
        """The device's current charging state, or None if it cannot be determined right now.

        Only called when a device would otherwise start (see tick() below): a charging probe is
        its own device round trip, and most ticks have nothing due, so this keeps a tick with
        several configured devices from talking to every one of them every few minutes.
        """
        try:
            return self._engine.charging_state(udid, on_pair_used=self._mark_pair_used)
        except Exception:
            log.exception("charging state check failed for %s", udid[:8])
            return None

    def tick(self, now: datetime | None = None) -> dict[str, scheduler.Decision]:
        now = now or datetime.now(UTC)
        try:
            seen = {d.udid: d for d in self._engine.discover(on_pair_used=self._mark_pair_used)}
        except Exception:
            # A broken network or mDNS must not also silence the overdue reminders.
            log.exception("device discovery failed")
            seen = {}

        decisions: dict[str, scheduler.Decision] = {}
        with closing(self._connect()) as conn:
            # A worker that crashed or restarted between ticks must not leave a run stuck as
            # 'running' forever; see jobs.sweep_orphan_runs.
            swept = sweep_orphan_runs(conn, now)
            if swept:
                log.warning("tick: failed %d run(s) left running by a worker that did not come back", swept)
            activity.sweep_stale(conn, now)
            # Every reachable device, known or not: the Add page reads seen_devices instead of
            # calling engine.discover() itself, so an unregistered device still needs to show up
            # here between explicit "Scan now" actions.
            if seen:
                refresh_seen_devices(conn, list(seen.values()), _iso(now))
            known = {row["udid"] for row in conn.execute("SELECT udid FROM devices")}
            for udid, device in seen.items():
                if udid in known:
                    conn.execute(
                        "INSERT INTO sightings (udid, seen_at, transport) VALUES (?, ?, ?)",
                        (udid, _iso(now), device.transport.value),
                    )
            conn.execute("DELETE FROM sightings WHERE seen_at < ?", (_iso(now - SIGHTINGS_KEPT),))

            # Recorded once per completed tick, regardless of what it found, so reachability.py
            # can count exactly how many checks ran on a given day instead of estimating it from
            # settings.schedule_minutes.
            conn.execute("INSERT INTO ticks (tick_at) VALUES (?)", (_iso(now),))
            conn.execute("DELETE FROM ticks WHERE tick_at < ?", (_iso(now - TICKS_KEPT),))

            defaults = backup_defaults.get_global_defaults(conn)
            for view in scheduler.load_views(conn, set(self._jobs.running()), defaults):
                try:
                    charging: bool | None = None
                    if view.only_when_charging:
                        # Optimistic pass first: only probe the device's real charging state when
                        # every other condition (due, reachable, inside the window, not cooling
                        # down) already says this would start - otherwise the probe cannot change
                        # the outcome and is skipped.
                        optimistic = scheduler.decide(
                            view,
                            now,
                            self._tz,
                            reachable=view.udid in seen,
                            charging=True,
                            notice_lead_minutes=defaults.notice_lead_minutes,
                        )
                        if optimistic.start_backup:
                            charging = self._charging(view.udid)
                    decision = scheduler.decide(
                        view,
                        now,
                        self._tz,
                        reachable=view.udid in seen,
                        charging=charging,
                        notice_lead_minutes=defaults.notice_lead_minutes,
                    )
                except ValueError:
                    log.warning("device %s has an invalid time window, skipped", view.udid)
                    continue
                decisions[view.udid] = decision
                if decision.start_backup:
                    self._jobs.start(view.udid, "schedule")
                if decision.overdue:
                    self._alert("overdue", view.udid, decision.reason)
                    conn.execute("UPDATE devices SET last_overdue_alert_at = ? WHERE udid = ?", (_iso(now), view.udid))
                if decision.nudge:
                    self._alert("due", view.udid, decision.reason)
                    conn.execute("UPDATE devices SET last_nudge_at = ? WHERE udid = ?", (_iso(now), view.udid))
                if decision.notice:
                    notice_id = scheduler.window_notice_identity(view.window_start, now, self._tz)
                    minutes = max(0, round((notice_id - now).total_seconds() / 60))
                    self._alert("upcoming", view.udid, str(minutes))
                    conn.execute(
                        "UPDATE devices SET last_window_notice_at = ? WHERE udid = ?", (_iso(notice_id), view.udid)
                    )
            self._verify_due(conn, now)
        if self._on_tick is not None:
            try:
                self._on_tick()
            except Exception:
                log.exception("tick: on_tick hook failed")
        return decisions

    def _verify_due(self, conn: sqlite3.Connection, now: datetime) -> None:
        """Pick at most one generation per device per DEEP_VERIFY_INTERVAL to deep-verify, oldest-
        unverified snapshot first, deliberately on demand and on a slow schedule rather than
        after every backup, and enqueue it as its own Huey task
        (tasks.verify_snapshot) rather than running verify.run_and_save here.

        Deliberately never calls run_and_save directly: that walks Manifest.db row by row with a
        filesystem stat per listed file, unbounded and without a timeout, and the worker consumer
        runs with a single thread (__init__.py). Run inline, that walk would occupy the tick's own
        thread for its whole duration - the next tick (so scheduled backups, nudges and overdue
        alerts), "Back up now", discovery, the connectivity check and pairing would all wait
        behind it. Enqueuing instead lets the tick return quickly and lets the verification
        compete for the worker thread like every other task, instead of owning it outright.

        Off entirely when this Ticker was built without a backup root (most tests), and off for
        this tick when the storage check fails - a broken or unmounted volume is not worth reading
        Manifest.db against. Also off when nothing has wired `enqueue_verify` (should not happen
        once tasks.build has run; see the constructor's docstring) - deep verification is then
        simply skipped, the same as when there is no backup root at all.
        """
        if self._root is None:
            return
        if self.enqueue_verify is None:
            return
        if self._storage_check is not None and not self._storage_check().ok:
            return
        for row in conn.execute("SELECT udid FROM devices"):
            udid = row["udid"]
            # A verification for this device is already registered as running (activities table,
            # kind "verify") - most likely the one a previous tick enqueued and the worker has not
            # finished yet. Skip it this tick rather than picking (and re-enqueuing) the same
            # never-checked generation again before its result is saved.
            if activity.is_running(conn, "verify", udid, now):
                continue
            last = verify.last_checked_at(conn, udid)
            if last is not None and now - last < verify.DEEP_VERIFY_INTERVAL:
                continue
            snaps = snapshots.list_snapshots(self._root, udid)
            target = verify.pick_snapshot(snaps, verify.load_results(conn, udid))
            if target is None:
                continue
            try:
                self.enqueue_verify(udid, target.path.name)
            except Exception:
                log.exception("failed to enqueue deep verification of %s", udid[:8])
