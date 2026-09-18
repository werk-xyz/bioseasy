# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs backups in worker threads, one per device, and records every run in the database.

A run counts as succeeded only when the backup on disk reads as complete afterwards; the
engine returning without an error is not enough.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

from . import activity, discovery, inventory, snapshots, storage, verify
from . import defaults as backup_defaults
from .engine.base import Engine, EngineError, NotConfirmedError, Phase, Progress, Transport
from .snapshots import RETENTION_FIELDS, RetentionPolicy

log = logging.getLogger(__name__)

# JobManager writes progress to the run row at most this often; the terminal state (_finish) is
# always written regardless of this throttle.
PROGRESS_WRITE_INTERVAL = 1.0
# How often the process running jobs proves it is still alive, in the workers table.
HEARTBEAT_INTERVAL = 10.0
# A running run whose worker has not heartbeat for this long (or whose worker_id was never
# registered at all) is orphaned: the worker that started it is gone, most likely restarted or
# crashed mid-backup. Comfortably above HEARTBEAT_INTERVAL so one missed write is not enough to
# fail a run that is still very much alive.
ORPHAN_THRESHOLD = timedelta(seconds=60)
# Module-level singleton so it can serve as a mutable-looking default argument (ruff B008)
# without constructing a GlobalDefaults on every JobManager() call; only used by tests and ad hoc
# callers that do not care about retention - runtime.py always passes its own global_defaults,
# which reads the admin-configured values from the settings table (defaults.py).
_FALLBACK_GLOBAL_DEFAULTS = backup_defaults.GlobalDefaults(
    window_start=backup_defaults.DEFAULT_WINDOW_START,
    window_end=backup_defaults.DEFAULT_WINDOW_END,
    only_when_charging=backup_defaults.DEFAULT_ONLY_WHEN_CHARGING,
    interval_hours=backup_defaults.DEFAULT_INTERVAL_HOURS,
    overdue_days=backup_defaults.DEFAULT_OVERDUE_DAYS,
    retention=RetentionPolicy(keep_last=3, keep_daily=7, keep_weekly=4, keep_monthly=6),
    free_space_threshold_gb=backup_defaults.DEFAULT_FREE_SPACE_THRESHOLD_GB,
    notice_lead_minutes=backup_defaults.DEFAULT_NOTICE_LEAD_MINUTES,
)
_RETENTION_COLUMNS = ", ".join(RETENTION_FIELDS)  # fixed constant, never user input


@dataclass(frozen=True)
class JobState:
    udid: str
    run_id: int
    phase: str
    percent: float | None = None
    message: str = ""


EventHook = Callable[[str, str, str], None]  # (event, udid, message)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sweep_orphan_runs(conn: sqlite3.Connection, now: datetime | None = None) -> int:
    """Fail every 'running' row whose worker is gone or has not proven it is still alive.

    Call this on startup and on every scheduler tick (see app.py's lifespan and ticker.py), so a
    worker that crashed or was restarted mid-backup never leaves its run stuck as 'running'
    forever - which would also block a new backup for that device through the runs_one_running
    index (db.py). Returns how many runs were failed.
    """
    now = now or datetime.now(UTC)
    stale_before = (now - ORPHAN_THRESHOLD).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur = conn.execute(
        """
        UPDATE runs SET status = 'failed', finished_at = ?, message = 'Worker restarted during the backup'
        WHERE status = 'running' AND (
            worker_id IS NULL
            OR worker_id NOT IN (SELECT id FROM workers)
            OR worker_id IN (SELECT id FROM workers WHERE heartbeat_at < ?)
        )
        """,
        (_now(), stale_before),
    )
    return cur.rowcount


class JobManager:
    def __init__(
        self,
        connect: Callable[[], sqlite3.Connection],
        engine: Engine,
        backup_root: Path,
        storage_check: Callable[[], storage.StorageCheck],
        global_defaults: Callable[[], backup_defaults.GlobalDefaults] = lambda: _FALLBACK_GLOBAL_DEFAULTS,
        tz: tzinfo = UTC,
        on_event: EventHook | None = None,
        worker_id: str | None = None,
        mark_pair_used: Callable[[str], None] | None = None,
        notify_storage_failed: Callable[[str], None] | None = None,
        mark_setup_confirmed: Callable[[str, Transport | None, bool], None] | None = None,
    ):
        # A connection per write: sqlite3 connections must not be shared between request
        # handlers and worker threads.
        self._connect = connect
        self._engine = engine
        self._root = backup_root
        self._storage_check = storage_check
        self._global_defaults = global_defaults
        self._tz = tz
        self._on_event = on_event or (lambda *_: None)
        self._mark_pair_used = mark_pair_used or (lambda _: None)
        self._notify_storage_failed = notify_storage_failed or (lambda _: None)
        # A succeeded run is itself evidence for the setup wizard's Wi-Fi and encryption steps
        # (docs/setup.md, "Adding a device again"); called from _run below once a run is about
        # to be recorded 'succeeded', never for a failed or cancelled one.
        self._mark_setup_confirmed = mark_setup_confirmed or (lambda *_: None)
        self._lock = threading.Lock()
        self._states: dict[str, JobState] = {}
        # Last time (time.monotonic()) the progress columns were written for a udid, so the
        # write is throttled to PROGRESS_WRITE_INTERVAL regardless of how often the engine calls
        # the progress callback.
        self._last_write: dict[str, float] = {}
        # The activity.track set_phase callable for the udid currently backing up, so _progress
        # can push the same phase text into the activities table the run row already carries -
        # set only while _run's own `with activity.track(...)` block is open.
        self._activity_phase: dict[str, activity.ActivityHandle] = {}
        # Identifies this process in the workers table, and is stamped on every run it starts,
        # so sweep_orphan_runs can tell a run's worker apart from every other process (including
        # a previous instance of this same process before a restart).
        self.worker_id = worker_id or uuid.uuid4().hex
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None

    def state(self, udid: str) -> JobState | None:
        with self._lock:
            return self._states.get(udid)

    def running(self) -> dict[str, JobState]:
        with self._lock:
            return dict(self._states)

    def start(self, udid: str, trigger: str, *, run_id: int | None = None) -> JobState:
        """Start a backup unless one is already running for this device.

        `run_id`, when given, is a `runs` row already inserted by the caller - the web route's
        mark_backup_starting (runtime.py), which writes it synchronously before this task is
        even enqueued so the request's own response can show the running state at once instead
        of waiting for a worker to dequeue the task. This method then only has to claim it (stamp
        this process's worker_id so sweep_orphan_runs can tell it apart) and spawn the thread
        that actually runs the backup - it never inserts a second row for the same call.
        """
        with self._lock:
            if udid in self._states:
                return self._states[udid]
            if run_id is not None:
                with closing(self._connect()) as conn:
                    conn.execute(
                        "UPDATE runs SET worker_id = ?, heartbeat_at = ? WHERE id = ?",
                        (self.worker_id, _now(), run_id),
                    )
                state = JobState(udid, run_id, "starting")
            else:
                with closing(self._connect()) as conn:
                    try:
                        cur = conn.execute(
                            "INSERT INTO runs (udid, trigger, started_at, status, phase, worker_id, heartbeat_at) "
                            "VALUES (?, ?, ?, 'running', 'starting', ?, ?)",
                            (udid, trigger, _now(), self.worker_id, _now()),
                        )
                    except sqlite3.IntegrityError:
                        # runs_one_running already holds a running row for this device: another
                        # process (a second worker, or the same device backing up through a
                        # different JobManager instance) got there first. Report that run's state
                        # without adopting it into self._states - this manager did not spawn its
                        # worker thread and must never be the one to decide it has finished.
                        row = conn.execute(
                            "SELECT * FROM runs WHERE udid = ? AND status = 'running'", (udid,)
                        ).fetchone()
                        return JobState(
                            udid, row["id"], row["phase"] or "starting", row["percent"], row["progress_message"] or ""
                        )
                state = JobState(udid, cur.lastrowid, "starting")
            self._states[udid] = state
        threading.Thread(target=self._run, args=(state,), name=f"backup-{udid}", daemon=True).start()
        return state

    def _write_progress(self, state: JobState) -> None:
        # Also refreshes this run's own heartbeat_at: a per-run liveness stamp alongside the
        # worker-level one in the workers table, updated on the same throttle as progress itself.
        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE runs SET phase = ?, percent = ?, progress_message = ?, heartbeat_at = ? WHERE id = ?",
                (state.phase, state.percent, state.message, _now(), state.run_id),
            )

    def _write_heartbeat(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "INSERT INTO workers (id, heartbeat_at) VALUES (?, ?) "
                "ON CONFLICT(id) DO UPDATE SET heartbeat_at = excluded.heartbeat_at",
                (self.worker_id, _now()),
            )

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.is_set():
            try:
                self._write_heartbeat()
            except Exception:
                log.exception("worker heartbeat failed")
            self._heartbeat_stop.wait(HEARTBEAT_INTERVAL)

    def start_heartbeat(self) -> None:
        """Write an immediate heartbeat, then keep it alive every HEARTBEAT_INTERVAL seconds
        from a daemon thread, so sweep_orphan_runs can tell this worker is still up."""
        self._write_heartbeat()
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, name="worker-heartbeat", daemon=True)
        self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()

    def _progress(self, udid: str, progress: Progress) -> None:
        with self._lock:
            current = self._states.get(udid)
            if current is None:
                return
            state = replace(current, phase=progress.phase.value, percent=progress.percent, message=progress.message)
            self._states[udid] = state
        now = time.monotonic()
        if now - self._last_write.get(udid, 0.0) >= PROGRESS_WRITE_INTERVAL:
            self._last_write[udid] = now
            self._write_progress(state)
            set_phase = self._activity_phase.get(udid)
            if set_phase is not None:
                # Same words a real device kind would get from app.py's phase_text, without the
                # "iPhone"/"iPad" noun this module has no reason to know: readable in the
                # activity popover regardless of which device is running.
                set_phase(state.phase.replace("_", " ").capitalize() if state.phase else "")
        if progress.phase is Phase.WAITING_FOR_PASSCODE:
            self._on_event("waiting_for_passcode", udid, progress.message)

    def _finish(self, state: JobState, status: str, message: str) -> None:
        if status != "succeeded":
            # Every unsuccessful run reaches the container log too, not only the UI: a failed
            # real-device step must not show nothing in the log. The message is the UI text.
            log.warning("backup of %s ended %s: %s", state.udid[:8], status, message)
        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE runs SET status = ?, finished_at = ?, message = ? WHERE id = ?",
                (status, _now(), message, state.run_id),
            )
        with self._lock:
            self._states.pop(state.udid, None)
        self._last_write.pop(state.udid, None)
        # The run's own status (succeeded/failed/not_confirmed) is the activity's outcome too;
        # told explicitly because _run returns rather than raising on a failed/not-confirmed
        # backup, so activity.track's own exception-based default would otherwise record
        # "succeeded" for those (activity.py, _PhaseHandle).
        set_phase = self._activity_phase.pop(state.udid, None)
        if set_phase is not None:
            set_phase.set_outcome(status, message or None)
        # The event name is the run status, so alerts can tell "nobody confirmed" from "broken".
        self._on_event(status, state.udid, message)

    def _effective_policy(self, udid: str) -> RetentionPolicy:
        retention_defaults = self._global_defaults().retention
        with closing(self._connect()) as conn:
            row = conn.execute(
                f"SELECT {_RETENTION_COLUMNS} FROM devices WHERE udid = ?",  # noqa: S608 - fixed constant, not user input
                (udid,),
            ).fetchone()
        if row is None:
            return retention_defaults
        return snapshots.resolve_policy(row, retention_defaults)

    def _snapshot(self, udid: str, check: storage.StorageCheck) -> None:
        hardlinks = check.hardlinks is True
        # Without hard links every generation is a full copy, so keep only the latest one
        # regardless of the device's configured retention policy.
        policy = self._effective_policy(udid) if hardlinks else RetentionPolicy(keep_last=1)
        with activity.track(self._connect, "cleanup", udid=udid):
            snapshots.take(self._root, udid, datetime.now(UTC), hardlinks)
            removed = snapshots.apply_retention(self._root, udid, policy, self._tz, datetime.now(UTC))
            if removed:
                with closing(self._connect()) as conn:
                    verify.delete_results(conn, udid, [path.name for path in removed])

    def _run(self, state: JobState) -> None:
        # Filled in by on_transport, at most once, as soon as the engine knows which transport
        # the connection actually used (engine/base.py's TransportCallback) - a plain list
        # instead of a local variable so the on_transport closure below can append to it without
        # a `nonlocal` declaration.
        transport_seen: list[Transport] = []
        try:
            with activity.track(self._connect, "backup", udid=state.udid) as set_phase:
                self._activity_phase[state.udid] = set_phase
                check = self._storage_check()
                if not check.ok:
                    message = "Storage check failed: " + "; ".join(check.problems)
                    self._finish(state, "failed", message)
                    self._notify_storage_failed(message)
                    return
                self._engine.backup(
                    state.udid,
                    self._root,
                    lambda p: self._progress(state.udid, p),
                    self._mark_pair_used,
                    on_transport=transport_seen.append,
                )
                result = inventory.read_backup(self._root / state.udid, with_size=False)
                if not result.complete:
                    self._finish(state, "failed", "Backup incomplete: " + "; ".join(result.problems))
                    return
                try:
                    self._snapshot(state.udid, check)
                except snapshots.SnapshotError as exc:
                    self._finish(state, "failed", f"Snapshot failed: {exc}")
                    return
                with closing(self._connect()) as conn:
                    discovery.fill_device_identity(
                        conn, state.udid, result.product_type, result.os_version, result.device_name
                    )
                # A run that actually transferred data over Wi-Fi, or whose finished backup
                # reads IsEncrypted=True, is itself proof for the setup wizard's Wi-Fi and
                # encryption steps - see runtime.mark_setup_confirmed_from_backup. Only ever
                # reached for a run about to be recorded 'succeeded', below.
                self._mark_setup_confirmed(
                    state.udid, transport_seen[-1] if transport_seen else None, result.encrypted is True
                )
                # Failures were logged, success was not, so the container log alone could not tell
                # a finished run from a silent one.
                log.info(
                    "backup of %s ended succeeded: encrypted=%s, %s iOS %s",
                    state.udid[:8],
                    result.encrypted,
                    result.product_type,
                    result.os_version,
                )
                self._finish(state, "succeeded", "")
        except NotConfirmedError as exc:
            self._finish(state, "not_confirmed", str(exc))
        except EngineError as exc:
            self._finish(state, "failed", str(exc))
        except Exception:  # a crash must end as a recorded failure, never as a stuck "running"
            log.exception("backup of %s crashed", state.udid)
            self._finish(state, "failed", "Internal error, see the container log")
