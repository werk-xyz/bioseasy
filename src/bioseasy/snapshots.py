# SPDX-License-Identifier: GPL-3.0-or-later
"""Backup generations (snapshots) and their retention.

A snapshot is a copy of the live backup directory taken with `rsync -a --link-dest=<previous
snapshot>`, so unchanged files across generations share one inode instead of being duplicated on
disk. Snapshots are only ever linked against an older snapshot, never against the live backup
directory: the engine rewrites live files in place with `open(path, "wb")`, which truncates the
file and would corrupt every hard-linked copy that shares its inode.

Retention (`RetentionPolicy`, `plan_retention`, `apply_retention`) mirrors restic's `forget`
command: https://restic.readthedocs.io/en/stable/060_forget.html.
- "keep the last n snapshots" (`--keep-last`) keeps the n newest outright.
- For `--keep-daily`/`--keep-weekly`/`--keep-monthly`/`--keep-yearly`, restic looks at "the last n
  days/weeks/months/years which have a snapshot" and keeps "only the last snapshot in each of the
  n most recent" such periods - so an empty period is skipped rather than counted.
- "Weeks are Monday 00:00 to Sunday 23:59, days 00:00 to 23:59" - i.e. calendar/ISO-week
  boundaries in whatever timezone the caller buckets in, not relative to when the command runs.
- "A snapshot is kept if it is kept by any of the policies" - the rules are ORed.
restic itself has no "always keep the newest/pinned snapshot" rule; that is bioseasy's own
addition on top.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from pathlib import Path

log = logging.getLogger(__name__)

TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"


class SnapshotError(Exception):
    """A snapshot could not be taken, listed, pinned, or pruned."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    taken_at: datetime
    pinned: bool


def _snapshots_dir(root: Path, udid: str) -> Path:
    return root / ".bioseasy" / "snapshots" / udid


def _marker(snapshots_dir: Path, name: str) -> Path:
    return snapshots_dir / f"{name}.pinned"


def _partial(snapshots_dir: Path, name: str) -> Path:
    return snapshots_dir / f"{name}.partial"


def _format_timestamp(now: datetime) -> str:
    return now.astimezone(UTC).strftime(TIMESTAMP_FORMAT)


def _tail(text: str, lines: int = 20) -> str:
    stripped = text.strip()
    if not stripped:
        return "(rsync produced no error output)"
    return "\n".join(stripped.splitlines()[-lines:])


def take(root: Path, udid: str, now: datetime, hardlinks: bool) -> Path:
    """Copy the live backup into a new, timestamped snapshot.

    Uses `rsync -a --delete` so a snapshot never keeps files the live backup has since dropped.
    When `hardlinks` is true and an earlier snapshot exists, `--link-dest` points at that earlier
    snapshot only, never at the live directory (see the module docstring for why).
    """
    live = root / udid
    snapshots_dir = _snapshots_dir(root, udid)
    snapshots_dir.mkdir(parents=True, exist_ok=True)

    name = _format_timestamp(now)
    target = snapshots_dir / name
    partial = _partial(snapshots_dir, name)
    if partial.exists():
        # Leftover from a run that crashed before the rename; start clean rather than let rsync
        # merge into a half-written directory.
        shutil.rmtree(partial, ignore_errors=True)

    previous = list_snapshots(root, udid)
    cmd = ["rsync", "-a", "--delete"]
    if hardlinks and previous:
        cmd.append(f"--link-dest={previous[0].path}")
    cmd += [f"{live}{os.sep}", f"{partial}{os.sep}"]

    try:
        # Argument list, never a shell string: rsync's own arguments cannot inject a command.
        proc = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603, S607
    except FileNotFoundError as exc:
        raise SnapshotError("rsync is not installed; install the rsync package to use snapshots") from exc

    if proc.returncode != 0:
        shutil.rmtree(partial, ignore_errors=True)
        raise SnapshotError(f"rsync failed (exit {proc.returncode}): {_tail(proc.stderr)}")

    partial.rename(target)
    return target


def list_snapshots(root: Path, udid: str) -> list[Snapshot]:
    """All snapshots for a device, newest first. Ignores partial dirs and pin markers."""
    snapshots_dir = _snapshots_dir(root, udid)
    if not snapshots_dir.is_dir():
        return []
    found: list[Snapshot] = []
    for entry in snapshots_dir.iterdir():
        if not entry.is_dir() or entry.name.endswith(".partial"):
            continue
        try:
            taken_at = datetime.strptime(entry.name, TIMESTAMP_FORMAT).replace(tzinfo=UTC)
        except ValueError:
            continue  # not a snapshot directory we created
        pinned = _marker(snapshots_dir, entry.name).is_file()
        found.append(Snapshot(entry, taken_at, pinned))
    found.sort(key=lambda s: s.taken_at, reverse=True)
    return found


def pin(root: Path, udid: str, name: str, pinned: bool) -> None:
    """Set or clear the pin marker for one snapshot.

    The marker is a sibling file rather than something written inside the snapshot, so a pinned
    snapshot stays byte-for-byte the clean Finder-format copy rsync produced.
    """
    snapshots_dir = _snapshots_dir(root, udid)
    if not (snapshots_dir / name).is_dir():
        raise SnapshotError(f"Snapshot {name} does not exist")
    marker = _marker(snapshots_dir, name)
    if pinned:
        marker.touch()
    else:
        marker.unlink(missing_ok=True)


RETENTION_FIELDS = ("keep_last", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly")


@dataclass(frozen=True)
class RetentionPolicy:
    """How many generations to keep. See the module docstring for the restic-derived semantics."""

    keep_last: int = 0
    keep_daily: int = 0
    keep_weekly: int = 0
    keep_monthly: int = 0
    keep_yearly: int = 0


def retention_error(policy: RetentionPolicy) -> str | None:
    """None if the policy is usable, else a human-readable problem: a policy that keeps nothing
    would silently delete every unpinned generation on the next backup."""
    if all(getattr(policy, field) == 0 for field in RETENTION_FIELDS):
        return "At least one retention rule must be greater than 0"
    return None


def resolve_policy(overrides: Mapping[str, int | None], defaults: RetentionPolicy) -> RetentionPolicy:
    """Layer a device's per-field overrides onto the server defaults; NULL/None means "use the
    default" for that field. `overrides` must carry all of RETENTION_FIELDS (a devices row, or a
    dict built from posted form values)."""
    values = {
        field: overrides[field] if overrides[field] is not None else getattr(defaults, field)
        for field in RETENTION_FIELDS
    }
    return RetentionPolicy(**values)


def _bucket_key(taken_at: datetime, tz: tzinfo, period: str) -> tuple[int, ...]:
    local = taken_at.astimezone(tz)
    if period == "daily":
        return (local.year, local.month, local.day)
    if period == "weekly":
        iso_year, iso_week, _ = local.isocalendar()
        return (iso_year, iso_week)
    if period == "monthly":
        return (local.year, local.month)
    return (local.year,)  # yearly


def plan_retention(
    snaps: list[Snapshot], policy: RetentionPolicy, tz: tzinfo, now: datetime | None = None
) -> list[tuple[Snapshot, list[str]]]:
    """Which rule(s) of `policy` keep each snapshot; an empty list means it would be removed.

    Pure and side-effect free - `apply_retention` is the only caller that actually deletes
    anything, so this is also what a settings-page preview and the "Kept by" column call.
    `snaps` must be newest-first, as `list_snapshots` returns them. `now` is accepted for
    symmetry with restic's own forget policy and for deterministic tests, but every rule here
    buckets purely from each snapshot's own `taken_at`, never relative to `now`.
    """
    del now
    if not snaps:
        return []
    reasons: list[list[str]] = [[] for _ in snaps]
    for i, snap in enumerate(snaps):
        if snap.pinned:
            reasons[i].append("pinned")
    if policy.keep_last > 0:
        for i in range(min(policy.keep_last, len(snaps))):
            reasons[i].append("latest")
    for period, count in (
        ("daily", policy.keep_daily),
        ("weekly", policy.keep_weekly),
        ("monthly", policy.keep_monthly),
        ("yearly", policy.keep_yearly),
    ):
        if count <= 0:
            continue
        seen: set[tuple[int, ...]] = set()
        kept = 0
        for i, snap in enumerate(snaps):  # newest first: the first snapshot seen per bucket wins
            if kept >= count:
                break
            key = _bucket_key(snap.taken_at, tz, period)
            if key in seen:
                continue
            seen.add(key)
            reasons[i].append(period)
            kept += 1
    # The newest snapshot is always kept, but only labelled "newest" when no rule already keeps
    # it - with the default policy (keep_last >= 1) that is "latest" in the common case, so the
    # "Kept by" column stays as short as restic's own reasoning rather than always saying both.
    if not reasons[0]:
        reasons[0].append("newest")
    return list(zip(snaps, reasons, strict=True))


def apply_retention(root: Path, udid: str, policy: RetentionPolicy, tz: tzinfo, now: datetime) -> list[Path]:
    """Remove every snapshot `plan_retention` would not keep under `policy`."""
    snaps = list_snapshots(root, udid)
    if not snaps:
        return []
    removed: list[Path] = []
    for snap, reasons in plan_retention(snaps, policy, tz, now):
        if reasons:
            continue
        shutil.rmtree(snap.path)
        _marker(snap.path.parent, snap.path.name).unlink(missing_ok=True)
        removed.append(snap.path)
        # Without this line a removed generation was only visible as a missing directory, e.g.
        # after a fourth backup of the day dropped the first one by keep_last.
        log.info(
            "retention removed snapshot %s of %s: no rule keeps it (%s)",
            snap.path.name,
            udid[:8],
            ", ".join(f"{name}={getattr(policy, name)}" for name in RETENTION_FIELDS),
        )
    return removed


def disk_usage(paths: list[Path]) -> int:
    """Total bytes across the given directories, counting each inode only once."""
    seen: set[tuple[int, int]] = set()
    total = 0
    for base in paths:
        files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file() and not p.is_symlink()]
        for file in files:
            try:
                st = file.stat()
            except OSError:
                continue
            key = (st.st_dev, st.st_ino)
            if key in seen:
                continue
            seen.add(key)
            total += st.st_size
    return total
