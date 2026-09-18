# SPDX-License-Identifier: GPL-3.0-or-later
"""Checks that the backup root is the volume the user configured, and fit to write to.

The marker file matters most: if a NAS share is not mounted, the path still exists inside the
container and a backup would silently fill the container's own disk.
"""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

MARKER = Path(".bioseasy") / "root-id"
MOUNTINFO_PATH = Path("/proc/self/mountinfo")

# How long a disk_usage_cached() result is reused before shutil.disk_usage runs again. The header
# renders on every page load, so this keeps a slow or unmounted network share from turning every
# page into a stat() call; still 5s fresh enough that "free" the storage page fetches directly
# and the header rarely disagree by more than one page load.
DISK_USAGE_CACHE_SECONDS = 5.0


@dataclass(frozen=True)
class DiskUsage:
    free_bytes: int
    total_bytes: int


class DiskUsageCache:
    """Caches shutil.disk_usage(root) briefly, one entry per process.

    None means "unavailable" (root does not exist, or disk_usage raised OSError - an unmounted
    network share behaves exactly like that): the header must show "Storage unavailable", never a
    fabricated 0 free of 0 total.
    """

    def __init__(self, ttl_seconds: float = DISK_USAGE_CACHE_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._cached_at: float | None = None
        self._value: DiskUsage | None = None

    def get(self, root: Path, *, now: float | None = None) -> DiskUsage | None:
        now = time.monotonic() if now is None else now
        if self._cached_at is not None and now - self._cached_at < self._ttl:
            return self._value
        try:
            usage = shutil.disk_usage(root) if root.is_dir() else None
        except OSError:
            usage = None
        self._value = DiskUsage(usage.free, usage.total) if usage is not None else None
        self._cached_at = now
        return self._value


def read_mountinfo() -> str | None:
    """The one non-pure step for mountinfo.py's parser: None on anything but Linux, or when the
    file cannot be read for any other reason (permissions, a container runtime that hides it)."""
    try:
        return MOUNTINFO_PATH.read_text()
    except OSError:
        return None


@dataclass(frozen=True)
class StorageCheck:
    path: Path
    problems: tuple[str, ...] = field(default_factory=tuple)
    free_bytes: int | None = None
    total_bytes: int | None = None
    hardlinks: bool | None = None

    @property
    def ok(self) -> bool:
        return not self.problems


def initialise(root: Path) -> str:
    """Write the marker once, when the user confirms this root. Returns its id."""
    marker = root / MARKER
    if marker.is_file():
        return marker.read_text().strip()
    marker.parent.mkdir(parents=True, exist_ok=True)
    root_id = secrets.token_hex(8)
    marker.write_text(root_id)
    return root_id


def _probe_write_and_links(root: Path) -> tuple[bool, bool]:
    work = root / MARKER.parent
    try:
        with tempfile.TemporaryDirectory(dir=work, prefix=".probe-") as tmp:
            source = Path(tmp) / "a"
            source.write_bytes(b"probe")
            try:
                os.link(source, Path(tmp) / "b")
                return True, True
            except OSError:
                return True, False
    except OSError:
        return False, False


def check(root: Path, expected_id: str | None, min_free_bytes: int) -> StorageCheck:
    if not root.is_dir():
        return StorageCheck(root, ("Backup root does not exist",))
    problems: list[str] = []
    marker = root / MARKER
    if expected_id is None:
        problems.append("Backup root is not initialised yet")
    elif not marker.is_file():
        problems.append("Marker file missing: is the volume mounted?")
    elif marker.read_text().strip() != expected_id:
        problems.append("Marker belongs to a different backup root")

    usage = shutil.disk_usage(root)
    if usage.free < min_free_bytes:
        problems.append(f"Less than {min_free_bytes // 2**30} GiB free")

    writable, hardlinks = (False, None)
    if marker.parent.is_dir():
        writable, hardlinks = _probe_write_and_links(root)
        if not writable:
            problems.append("Backup root is not writable")
    return StorageCheck(root, tuple(problems), usage.free, usage.total, hardlinks)
