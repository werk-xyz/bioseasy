# SPDX-License-Identifier: GPL-3.0-or-later
"""Cross-process registry of running background activity, for the header's activity indicator.

Web and worker are separate processes (Huey worker), so a job running in one is invisible to the
other except through the database - the same problem `runs` and `workers` already solve for
backups (jobs.py). Every task
and the one web-thread step that never goes through Huey (runtime.run_encryption_enable) register
themselves here for the duration of their work, through the `track` context manager, so the shape
(a heartbeat, and cleanup even after a crash) is the same everywhere.

Scoping follows status.py: `for_owner` and `for_admin` apply the visibility rule in the SQL query
itself, not by filtering a full list afterwards, so a route that forgets a filter cannot hand out
another user's device activity. An activity with no device (a discovery scan, a storage-root size
recalculation) belongs to no owner and is INNER-JOINed away for `for_owner`, never shown to a
member - those are admin-only actions to begin with.

A finished activity is kept around for a short while (FINISHED_RETENTION) so the header can show
"it just finished" instead of the entry simply vanishing. `outcome`/`detail`/`finished_at`
(SCHEMA_VERSION 12; db.py's `_migrate_11_to_12`) carry that: NULL outcome means still running,
set once by `track` on the way out. `phase` keeps meaning only the running phase text - it is
never touched after that point, so a finished row's last phase stays whatever it was, unread by
anything here.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta

log = logging.getLogger("bioseasy")

# An entry whose heartbeat is older than this is treated as crashed - the process that registered
# it is gone - and excluded by for_owner/for_admin, the same margin and reasoning as
# jobs.ORPHAN_THRESHOLD for a 'running' run.
STALE_AFTER = timedelta(seconds=60)
HEARTBEAT_INTERVAL = 10.0

# How long a finished activity stays visible to for_owner_finished/for_admin_finished after it
# ends: a check mark for a while, picked 10 minutes so a slow page reload still catches it.
FINISHED_RETENTION = timedelta(minutes=10)

# What `track`'s caller (or, failing that, an uncaught exception) may report as the result -
# matches the CHECK constraint on activities.outcome (db.py) and jobs.py's run status values.
OUTCOMES = ("succeeded", "failed", "not_confirmed")

OUTCOME_LABELS: dict[str, str] = {
    "succeeded": "succeeded",
    "failed": "failed",
    "not_confirmed": "not confirmed",
}

# Every kind this registry is meant to carry. `restore` is still unbuilt - bioseasy guides a
# restore rather than performing one - and is kept here as the one list a future task registers
# against, instead of each call site inventing its own string. `connectivity_check` and
# `update_check` were in the same position before this: both features existed, but neither
# registered anything, so a check that runs in the worker never showed up in the header popover.
KINDS = (
    "backup",
    "discovery",
    "pairing",
    "storage_size",
    "cleanup",
    "password_check",
    "wifi_enable",
    "encryption_enable",
    "password_change",
    "connectivity_check",
    "setup_detect",
    "update_check",
    "restore",
    "verify",
)

KIND_LABELS: dict[str, str] = {
    "backup": "Backup",
    "discovery": "Scanning for devices",
    "pairing": "Pairing",
    "storage_size": "Calculating storage size",
    "cleanup": "Cleaning up old snapshots",
    "password_check": "Checking backup password",
    "wifi_enable": "Turning on Wi-Fi backups",
    "encryption_enable": "Turning on backup encryption",
    "password_change": "Changing backup password",
    "connectivity_check": "Checking connectivity",
    "setup_detect": "Checking the device's current setup",
    "update_check": "Checking for updates",
    "restore": "Restoring",
    "verify": "Verifying backup generation",
}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stale_before(now: datetime | None) -> str:
    now = now or datetime.now(UTC)
    return (now - STALE_AFTER).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finished_before(now: datetime | None) -> str:
    now = now or datetime.now(UTC)
    return (now - FINISHED_RETENTION).strftime("%Y-%m-%dT%H:%M:%SZ")


class ActivityHandle:
    """Returned by `track` in place of a bare `set_phase` callable: calling it still sets the
    running phase text exactly as before (every existing call site does `set_phase(text)`), and
    `.set_outcome(...)` is the one addition a caller may use to report a definite result even
    though the `with` block itself returns normally - jobs.py's backup run is the reason this
    exists: it records "failed" or "not_confirmed" on the run row and returns rather than
    raising, so `track` alone (exception-or-not) cannot tell success from failure for it."""

    def __init__(self, set_phase: Callable[[str], None], set_outcome: Callable[[str, str | None], None]) -> None:
        self._set_phase = set_phase
        self.set_outcome = set_outcome

    def __call__(self, text: str) -> None:
        self._set_phase(text)


@contextmanager
def track(
    connect: Callable[[], sqlite3.Connection],
    kind: str,
    *,
    udid: str | None = None,
    phase: str | None = None,
    snapshot_name: str | None = None,
) -> Iterator[ActivityHandle]:
    """Register one running activity for the lifetime of the `with` block.

    Yields a handle: call it directly as `set_phase(text)` to update what it is doing without
    re-registering, and `handle.set_outcome(outcome, detail=None)` to report a definite result
    when the block itself will not tell `track` (see ActivityHandle). A heartbeat thread keeps the
    row alive every HEARTBEAT_INTERVAL seconds for as long as the block runs.

    `snapshot_name` (SCHEMA_VERSION 16) identifies the backup generation this activity is about -
    passed by verify.run_and_save so the generations table can mark the one row actually being
    verified right now (app.py's generations_context, running_snapshot_names below). Left None
    for every other kind, which has no single generation to point at.

    On the way out - including when the block raises - the row is never deleted immediately: its
    outcome/detail/finished_at columns are filled in (`for_owner_finished`/`for_admin_finished`
    can show it for FINISHED_RETENTION), and `for_owner`/`for_admin` (the running queries)
    immediately stop returning it. The outcome is whatever `set_outcome` last reported; failing
    that, "failed" if the block raised and "succeeded" if it returned normally. A hard process
    kill instead leaves the row running-shaped (outcome still NULL) for `for_owner`/`for_admin`
    to age out by heartbeat, and eventually for `sweep_stale` to delete - the same shape as
    jobs.sweep_orphan_runs.
    """
    activity_id = uuid.uuid4().hex
    state = {"phase": phase}
    outcome_state: dict[str, str | None] = {"outcome": None, "detail": None}
    stop = threading.Event()

    def _write() -> None:
        with closing(connect()) as conn:
            conn.execute(
                "INSERT INTO activities (id, kind, udid, phase, snapshot_name, started_at, heartbeat_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET phase = excluded.phase, heartbeat_at = excluded.heartbeat_at",
                (activity_id, kind, udid, state["phase"], snapshot_name, _now(), _now()),
            )

    def set_phase(text: str) -> None:
        state["phase"] = text
        try:
            _write()
        except Exception:
            log.exception("activity phase update failed for %s", kind)

    def set_outcome(outcome: str, detail: str | None = None) -> None:
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown activity outcome: {outcome!r}")
        outcome_state["outcome"] = outcome
        # Kept short: this ends up in a toast and a popover list, not a log file.
        outcome_state["detail"] = detail[:200] if detail else None

    handle = ActivityHandle(set_phase, set_outcome)

    def _heartbeat_loop() -> None:
        while not stop.wait(HEARTBEAT_INTERVAL):
            try:
                _write()
            except Exception:
                log.exception("activity heartbeat failed for %s", kind)

    _write()
    thread = threading.Thread(target=_heartbeat_loop, name=f"activity-{kind}", daemon=True)
    thread.start()
    raised = False
    try:
        yield handle
    except Exception as exc:
        raised = True
        if outcome_state["outcome"] is None:
            outcome_state["detail"] = str(exc)[:200]
        raise
    finally:
        stop.set()
        thread.join(timeout=2.0)
        outcome = outcome_state["outcome"] or ("failed" if raised else "succeeded")
        try:
            with closing(connect()) as conn:
                conn.execute(
                    "UPDATE activities SET outcome = ?, detail = ?, finished_at = ?, heartbeat_at = ? WHERE id = ?",
                    (outcome, outcome_state["detail"], _now(), _now(), activity_id),
                )
        except Exception:
            log.exception("could not record activity outcome for %s", kind)


_SELECT = """
    SELECT a.id, a.kind, a.udid, a.phase, a.started_at, a.heartbeat_at, a.outcome, a.detail, a.finished_at,
           d.name AS device_name
    FROM activities a
"""

_RUNNING_WHERE = "a.outcome IS NULL AND a.heartbeat_at >= ?"
_FINISHED_WHERE = "a.outcome IS NOT NULL AND a.finished_at >= ?"


def for_admin(conn: sqlite3.Connection, now: datetime | None = None) -> list[sqlite3.Row]:
    return conn.execute(
        _SELECT + f" LEFT JOIN devices d ON d.udid = a.udid WHERE {_RUNNING_WHERE} ORDER BY a.started_at",
        (_stale_before(now),),
    ).fetchall()


def for_owner(conn: sqlite3.Connection, owner_id: int, now: datetime | None = None) -> list[sqlite3.Row]:
    # An INNER join: an activity with no device (udid IS NULL, e.g. a discovery scan or a storage
    # size recalculation - both admin-only actions) never matches and is never shown to a member.
    return conn.execute(
        _SELECT + f" JOIN devices d ON d.udid = a.udid WHERE d.owner_id = ? AND {_RUNNING_WHERE} ORDER BY a.started_at",
        (owner_id, _stale_before(now)),
    ).fetchall()


def for_admin_finished(conn: sqlite3.Connection, now: datetime | None = None) -> list[sqlite3.Row]:
    return conn.execute(
        _SELECT + f" LEFT JOIN devices d ON d.udid = a.udid WHERE {_FINISHED_WHERE} ORDER BY a.finished_at DESC",
        (_finished_before(now),),
    ).fetchall()


def for_owner_finished(conn: sqlite3.Connection, owner_id: int, now: datetime | None = None) -> list[sqlite3.Row]:
    return conn.execute(
        _SELECT + f" JOIN devices d ON d.udid = a.udid WHERE d.owner_id = ? AND {_FINISHED_WHERE} "
        "ORDER BY a.finished_at DESC",
        (owner_id, _finished_before(now)),
    ).fetchall()


def is_running(conn: sqlite3.Connection, kind: str, udid: str, now: datetime | None = None) -> bool:
    """True if an activity of this `kind` for this `udid` is currently registered as running (a
    fresh heartbeat, outcome still NULL) - used by ticker._verify_due to avoid enqueuing a second
    deep verification for a device whose previous one has not finished yet. A stale row (worker
    killed mid-run, heartbeat older than STALE_AFTER) reads as not running, the same cutoff
    for_owner/for_admin already use, so a genuinely abandoned verification does not block the
    schedule forever - the next tick simply tries again.
    """
    row = conn.execute(
        f"SELECT 1 FROM activities a WHERE a.kind = ? AND a.udid = ? AND {_RUNNING_WHERE} LIMIT 1",  # noqa: S608
        (kind, udid, _stale_before(now)),
    ).fetchone()
    return row is not None


def running_snapshot_names(conn: sqlite3.Connection, kind: str, udid: str, now: datetime | None = None) -> set[str]:
    """`snapshot_name` of every activity of this `kind` for this device currently registered as
    running (same running definition as `is_running`) - used by app.py's generations_context to
    mark the row of the generation actually being verified right now, not just the device as a
    whole (the header's activity indicator already covers that). Normally at most one name, since
    ticker._verify_due's own is_running guard stops a second verification from being enqueued
    while one is still running, but the on-demand "Verify" button can still start a second one
    alongside it, so this returns a set rather than assuming a single result."""
    rows = conn.execute(
        f"SELECT snapshot_name FROM activities a WHERE a.kind = ? AND a.udid = ? "  # noqa: S608
        f"AND a.snapshot_name IS NOT NULL AND {_RUNNING_WHERE}",
        (kind, udid, _stale_before(now)),
    ).fetchall()
    return {row["snapshot_name"] for row in rows}


def sweep_stale(conn: sqlite3.Connection, now: datetime | None = None) -> int:
    """Delete every activity row that is done aging: a still-"running" row whose heartbeat is
    older than STALE_AFTER (a process that was killed rather than finishing normally never
    reaches `track`'s own cleanup), or a finished row older than FINISHED_RETENTION. Call this on
    startup and on every scheduler tick, the same as jobs.sweep_orphan_runs; returns how many rows
    were removed. Never required for correctness of for_owner/for_admin/for_owner_finished/
    for_admin_finished, which already filter by heartbeat_at/finished_at themselves - only for
    keeping the table from growing forever.
    """
    cur = conn.execute(
        f"DELETE FROM activities AS a WHERE ({_FINISHED_WHERE.replace('>=', '<')}) "  # noqa: S608 - fixed constant
        f"OR ({_RUNNING_WHERE.replace('>=', '<')})",
        (_finished_before(now), _stale_before(now)),
    )
    return cur.rowcount


def running_for(rows: list[sqlite3.Row], now: datetime | None = None) -> list[dict]:
    """`for_owner`/`for_admin` rows turned into the small, UI-ready shape the popover renders:
    label, device name if any, phase, and how long it has been running."""
    now = now or datetime.now(UTC)
    result = []
    for row in rows:
        started = datetime.fromisoformat(row["started_at"].replace("Z", "+00:00"))
        result.append(
            {
                "kind": row["kind"],
                "label": KIND_LABELS.get(row["kind"], row["kind"]),
                "device_name": row["device_name"],
                "phase": row["phase"],
                "running_for_seconds": max(0.0, (now - started).total_seconds()),
            }
        )
    return result


def finished_for(rows: list[sqlite3.Row], now: datetime | None = None) -> list[dict]:
    """`for_owner_finished`/`for_admin_finished` rows turned into the small, UI-ready shape the
    popover's "Recently finished" section renders: label, device name if any, outcome word,
    optional short detail (a failure reason), and how long ago it finished."""
    now = now or datetime.now(UTC)
    result = []
    for row in rows:
        finished = datetime.fromisoformat(row["finished_at"].replace("Z", "+00:00"))
        result.append(
            {
                "kind": row["kind"],
                "label": KIND_LABELS.get(row["kind"], row["kind"]),
                "device_name": row["device_name"],
                "outcome": row["outcome"],
                "outcome_label": OUTCOME_LABELS.get(row["outcome"], row["outcome"]),
                "detail": row["detail"],
                "finished_ago_seconds": max(0.0, (now - finished).total_seconds()),
            }
        )
    return result


def latest_event(running_rows: list[sqlite3.Row], finished_rows: list[sqlite3.Row]) -> dict[str, str] | None:
    """The single most recent thing that happened among what this caller (owner- or
    admin-scoped, same rows as running_for/finished_for) can see: a job starting, or one ending
    with an outcome. Used by the header fragment to carry a small "did anything new happen"
    marker (`id`) plus its toast text (`text`) - the toast script only compares `id` against what
    it last saw, so this never needs to expose a full event log, only the latest one. Returns
    None when nothing is running and nothing finished recently."""
    candidates: list[dict[str, str]] = []
    for row in running_rows:
        who = KIND_LABELS.get(row["kind"], row["kind"])
        if row["device_name"]:
            who = f"{who} of {row['device_name']}"
        candidates.append(
            {
                "time": row["started_at"],
                "id": f"{row['id']}:started:{row['started_at']}",
                "text": f"{who} started",
            }
        )
    for row in finished_rows:
        outcome, detail = row["outcome"], row["detail"]
        who = KIND_LABELS.get(row["kind"], row["kind"])
        if row["device_name"]:
            who = f"{who} of {row['device_name']}"
        if outcome == "succeeded":
            text = f"{who} finished"
        elif outcome == "failed":
            text = f"{who} failed" + (f": {detail}" if detail else "")
        else:
            text = f"{who} not confirmed" + (f": {detail}" if detail else "")
        candidates.append(
            {
                "time": row["finished_at"],
                "id": f"{row['id']}:{outcome}:{row['finished_at']}",
                "text": text,
            }
        )
    if not candidates:
        return None
    latest = max(candidates, key=lambda c: c["time"])
    return {"id": latest["id"], "text": latest["text"]}
