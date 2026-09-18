# SPDX-License-Identifier: GPL-3.0-or-later
"""Deep verification of one backup generation: does every file Manifest.db lists actually exist.

`status.py`'s completeness signal is `Status.plist`'s `SnapshotState == "finished"` alone (see
`inventory.py`) - written by the device once it believes the transfer finished, never checked
against what actually landed on disk. This module is the second, independent check: read
`Manifest.db`'s `Files` table (fileID -> `<fileID[:2]>/<fileID>`,
the same layout `bioseasy.demo_backup` and pymobiledevice3's own client use) and confirm each listed
payload file exists in the snapshot directory. It runs on demand and on a slow schedule
(`ticker.py`), never after every backup - a full walk is too slow for that.

An encrypted backup's `Manifest.db` needs the backup password to be meaningfully checked; this
module never asks for or stores one (the same rule password_check.py
follows). For an encrypted backup only what is checkable without the password is checked and the
result is reported honestly as "not checked", never folded into "verified" or "missing".
"""

from __future__ import annotations

import json
import logging
import plistlib
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from . import activity

log = logging.getLogger("bioseasy")

Outcome = Literal["verified", "missing", "not_checked"]

# First N missing fileIDs kept per result - enough to point an operator at the problem without
# growing the stored row unbounded for a backup missing thousands of files.
MAX_MISSING_EXAMPLES = 20

# "a slow schedule rather than after every backup": at most one generation per
# device gets picked by the tick per this interval.
DEEP_VERIFY_INTERVAL = timedelta(days=7)

# One enormous backup must not occupy the worker's single thread for hours:
# Manifest.db can list hundreds of thousands of files, each checked with its own stat() syscall,
# and nothing else queued behind this task - the next tick, "Back up now", discovery, the
# connectivity check, pairing - gets to run until this one finishes or times out. 10 minutes is
# generous given the slow schedule (a "slow schedule" already means this device is at most
# checked weekly, so there is no rush to finish in seconds) while still bounding the worst case to
# something an operator can see happen and understand, rather than an open-ended wait. A run that
# hits the budget is simply reported as not_checked/missing (never verified) with how far it got;
# the next scheduled run starts the same generation over from the beginning - there is no partial
# resume state to maintain.
VERIFY_TIME_BUDGET = timedelta(minutes=10)

# The real device-written format marks a Files row 2 for a domain directory entry, which carries
# no payload of its own - only ever a grouping node for the paths under it. 1 is a regular file, 4
# a symlink; both are checked for an on-disk payload like any other listed entry.
DIRECTORY_FLAG = 2

# Top-level names that are backup metadata, not payload, so they are not counted as "payload files
# on disk" for the encrypted, password-less check (mirrors mobilebackup2.py's BACKUP_METADATA_FILES,
# see bioseasy.demo_backup's docstring).
_METADATA_NAMES = frozenset(
    {"Manifest.db", "Manifest.db-shm", "Manifest.db-wal", "Info.plist", "Status.plist", "Manifest.plist"}
)


@dataclass(frozen=True)
class VerifyResult:
    outcome: Outcome
    listed: int = 0
    present: int = 0
    missing: int = 0
    missing_fileids: tuple[str, ...] = field(default_factory=tuple)
    # Human-readable detail: the reason for "not_checked", empty otherwise. Never a password or
    # any other secret - built only from counts and fixed strings.
    detail: str = ""

    @property
    def summary(self) -> str:
        if self.outcome == "verified":
            return f"Verified: {self.present} of {self.listed} files present"
        if self.outcome == "missing":
            return f"Missing {self.missing} of {self.listed} listed files"
        return f"Not checked: {self.detail}"


def _load_plist(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        with path.open("rb") as fh:
            data = plistlib.load(fh)
    except (plistlib.InvalidFileException, ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _payload_file_count(snapshot_dir: Path) -> int:
    """Regular files anywhere under `snapshot_dir` except the top-level metadata files - the one
    thing that can still be counted about an encrypted backup without its password."""
    count = 0
    for entry in snapshot_dir.rglob("*"):
        try:
            if entry.is_file() and not entry.is_symlink() and entry.name not in _METADATA_NAMES:
                count += 1
        except OSError:
            continue
    return count


def verify_snapshot(snapshot_dir: Path, *, deadline: float | None = None) -> VerifyResult:
    """Verify one snapshot directory. Never loads the whole Files table into memory at once - the
    cursor is iterated row by row, which matters for a backup with hundreds of thousands of files.

    `deadline`, when given, is a `time.monotonic()` value: the row loop stops checking further
    files once it is reached, rather than running unbounded (run_and_save passes
    `time.monotonic() + VERIFY_TIME_BUDGET.total_seconds()`). None (every existing test, and every
    call site that does not care) means no budget - kept as a separate parameter rather than
    folded into run_and_save alone so the pure walk stays testable without a real clock.
    """
    manifest = _load_plist(snapshot_dir / "Manifest.plist")
    if manifest is None:
        return VerifyResult("not_checked", detail="Manifest.plist missing or unreadable")

    db_path = snapshot_dir / "Manifest.db"
    db_nonempty = db_path.is_file() and db_path.stat().st_size > 0

    if manifest.get("IsEncrypted"):
        parts = []
        if not (snapshot_dir / "Info.plist").is_file():
            parts.append("Info.plist missing")
        if not (snapshot_dir / "Status.plist").is_file():
            parts.append("Status.plist missing")
        parts.append("Manifest.db present and non-empty" if db_nonempty else "Manifest.db missing or empty")
        parts.append(f"{_payload_file_count(snapshot_dir)} payload file(s) on disk")
        return VerifyResult("not_checked", detail="encrypted (needs the backup password); " + "; ".join(parts))

    if not db_nonempty:
        return VerifyResult("not_checked", detail="Manifest.db missing or empty")

    listed = present = missing = 0
    missing_ids: list[str] = []
    stopped_early = False
    try:
        # Read-only URI connection: this module only ever reads Manifest.db, never writes it.
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            # A rough total for the "stopped after the budget" detail line below - approximate on
            # purpose ("about N"): it counts every row, including the domain-directory entries the
            # loop itself skips, but a single COUNT(*) is cheap next to the stat()-per-file walk
            # and close enough to tell an operator how much of a huge backup was actually covered.
            try:
                total_row_count = conn.execute("SELECT COUNT(*) FROM Files").fetchone()[0]
            except sqlite3.DatabaseError:
                total_row_count = None
            cur = conn.execute("SELECT fileID, flags FROM Files")
            for row in cur:
                if deadline is not None and time.monotonic() >= deadline:
                    stopped_early = True
                    break
                flags = row["flags"]
                if flags is not None and int(flags) == DIRECTORY_FLAG:
                    continue  # a domain directory entry: no payload file to check for it
                listed += 1
                file_id = row["fileID"]
                if (snapshot_dir / file_id[:2] / file_id).is_file():
                    present += 1
                else:
                    missing += 1
                    if len(missing_ids) < MAX_MISSING_EXAMPLES:
                        missing_ids.append(file_id)
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        log.warning("verify: Manifest.db at %s unreadable (%s)", snapshot_dir, exc.__class__.__name__)
        return VerifyResult("not_checked", detail=f"Manifest.db unreadable: {exc.__class__.__name__}")

    if stopped_early:
        # Never "verified" for a walk that was cut short - only what was actually checked can back
        # that claim. A file already confirmed missing before the stop is real evidence though, so
        # it is still reported as "missing" rather than downgraded to "not checked"; only a clean-
        # so-far stop falls back to "not_checked" with the detail line.
        checked = present + missing
        total_desc = f"about {total_row_count}" if total_row_count is not None else "an unknown number of"
        missing_desc = "none missing so far" if missing == 0 else f"{missing} missing so far"
        detail = f"stopped after the time budget, {checked} of {total_desc} files checked, {missing_desc}"
        outcome: Outcome = "missing" if missing else "not_checked"
        return VerifyResult(outcome, listed, present, missing, tuple(missing_ids), detail)

    outcome = "verified" if missing == 0 else "missing"
    return VerifyResult(outcome, listed, present, missing, tuple(missing_ids))


def save_result(
    conn: sqlite3.Connection, udid: str, snapshot_name: str, result: VerifyResult, checked_at: datetime
) -> None:
    conn.execute(
        "INSERT INTO snapshot_verifications "
        "(udid, snapshot_name, outcome, listed, present, missing, missing_fileids_json, detail, checked_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(udid, snapshot_name) DO UPDATE SET "
        "outcome = excluded.outcome, listed = excluded.listed, present = excluded.present, "
        "missing = excluded.missing, missing_fileids_json = excluded.missing_fileids_json, "
        "detail = excluded.detail, checked_at = excluded.checked_at",
        (
            udid,
            snapshot_name,
            result.outcome,
            result.listed,
            result.present,
            result.missing,
            json.dumps(list(result.missing_fileids)),
            result.detail,
            checked_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )


def delete_results(conn: sqlite3.Connection, udid: str, snapshot_names: list[str]) -> None:
    """Drop stored verification results for snapshots that no longer exist on disk.

    Retention (snapshots.apply_retention) removes a snapshot's directory but has no database
    connection of its own to also clean up here, so this table otherwise grows one row per
    generation ever verified for the lifetime of a device, long after the generation itself was
    pruned - called from jobs.py right after retention reports which snapshots it removed.
    """
    if not snapshot_names:
        return
    conn.executemany(
        "DELETE FROM snapshot_verifications WHERE udid = ? AND snapshot_name = ?",
        [(udid, name) for name in snapshot_names],
    )


def load_results(conn: sqlite3.Connection, udid: str) -> dict[str, sqlite3.Row]:
    """Every stored verification result for one device, keyed by snapshot directory name."""
    rows = conn.execute("SELECT * FROM snapshot_verifications WHERE udid = ?", (udid,)).fetchall()
    return {row["snapshot_name"]: row for row in rows}


def last_checked_at(conn: sqlite3.Connection, udid: str) -> datetime | None:
    """When this device's most recently checked generation was checked, or None if it has never
    had one - used by the tick to space verification runs at least DEEP_VERIFY_INTERVAL apart."""
    row = conn.execute("SELECT MAX(checked_at) AS m FROM snapshot_verifications WHERE udid = ?", (udid,)).fetchone()
    if row is None or row["m"] is None:
        return None
    return datetime.strptime(row["m"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def pick_snapshot(snaps: list, results: dict[str, sqlite3.Row]):
    """The snapshot the schedule should verify next: oldest-unverified first. A snapshot with no
    result row at all outranks every snapshot that already has one, regardless of how old that
    one's `checked_at` is; among snapshots that do have a result, the one checked longest ago
    comes first. `snaps` is `snapshots.list_snapshots`'s own return shape (has `.path`); returns
    None only when `snaps` is empty."""
    if not snaps:
        return None

    def key(snap):
        row = results.get(snap.path.name)
        # Group 0 (never checked) always sorts before group 1 (checked before): the second tuple
        # element is only ever compared within its own group, so it may differ in type between
        # them - the snapshot's own age for group 0, its last check time for group 1.
        return (0, snap.taken_at) if row is None else (1, row["checked_at"])

    return min(snaps, key=key)


def run_and_save(
    connect: Callable[[], sqlite3.Connection], snapshot_dir: Path, udid: str, snapshot_name: str
) -> VerifyResult:
    """Verify one snapshot and persist the result, tracked in `activities` for the header's
    activity indicator for as long as it runs. Always runs in the worker (tasks.py's Huey task, or
    the tick calling this directly since the tick itself already runs in the worker) - never on a
    request thread, to stay streaming-friendly for large backups."""
    with activity.track(connect, "verify", udid=udid, snapshot_name=snapshot_name):
        deadline = time.monotonic() + VERIFY_TIME_BUDGET.total_seconds()
        result = verify_snapshot(snapshot_dir, deadline=deadline)
        with closing(connect()) as conn:
            save_result(conn, udid, snapshot_name, result, datetime.now(UTC))
    return result
