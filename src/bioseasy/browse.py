# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only, admin-only listing of the backup root (the storage browse view), and the
background directory-size cache behind it.

This handles sensitive backup data end to end, so every path coming from a request is resolved
and validated here before it ever reaches the filesystem (see `resolve_within_root`); nothing in
this module ever opens a file's contents or offers one for download, only names, sizes, mtimes
and counts.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_within_root(root: Path, rel_path: str | None) -> Path | None:
    """The requested relative path, resolved and validated against `root`.

    None means "reject": an absolute path, a ".." segment, a path that runs through a symlink
    at any component - never resolved past that point, so a symlink partway through never gets
    to decide what "inside the root" means, only the final target does - or a target that does
    not exist or is not a directory. The caller turns None into a 404, never 403 and never a
    stack trace, so a path outside the root is indistinguishable from one that was never there.
    """
    root = root.resolve()
    if rel_path is None:
        rel_path = ""
    if "\x00" in rel_path or rel_path.startswith("/"):
        return None
    parts: list[str] = []
    for part in rel_path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            return None
        if not current.exists():
            return None
    if not current.is_dir():
        return None
    return current


def relative_path(root: Path, target: Path) -> str:
    """`target`'s path relative to `root`, as a "/"-joined string; "" for `root` itself."""
    rel = target.resolve().relative_to(root.resolve())
    return "" if str(rel) == "." else rel.as_posix()


@dataclass(frozen=True)
class Entry:
    name: str
    rel_path: str
    is_dir: bool
    size_bytes: int | None  # set for files only; a directory's size comes from the size cache
    mtime: datetime
    item_count: int | None  # direct children only, directories only; None for a symlinked dir


def list_directory(target: Path, target_rel: str) -> list[Entry]:
    """One level of `target` (whose own root-relative path is `target_rel`): every file and
    directory in it, sorted directories-first then by name. Never descends into a symlinked
    entry - not even to count its children, and not even to compute its own relative path:
    `Path.resolve()` follows symlinks, so a child's rel_path is built from `target_rel` and the
    entry's own name instead, never by resolving the symlink itself."""
    entries: list[Entry] = []
    with os.scandir(target) as it:
        for de in it:
            try:
                st = de.stat(follow_symlinks=False)
            except OSError:
                continue
            is_symlink = de.is_symlink()
            is_dir = de.is_dir(follow_symlinks=False)
            item_count = None
            if is_dir and not is_symlink:
                try:
                    with os.scandir(de.path) as inner:
                        item_count = sum(1 for _ in inner)
                except OSError:
                    item_count = None
            entries.append(
                Entry(
                    name=de.name,
                    rel_path=f"{target_rel}/{de.name}" if target_rel else de.name,
                    is_dir=is_dir,
                    size_bytes=None if is_dir else st.st_size,
                    mtime=datetime.fromtimestamp(st.st_mtime, tz=UTC),
                    item_count=item_count,
                )
            )
    entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
    return entries


def breadcrumbs(rel_path: str) -> list[tuple[str, str]]:
    """[(label, rel_path), ...] from the backup root to `rel_path`, root first."""
    crumbs = [("backups", "")]
    if not rel_path:
        return crumbs
    parts = rel_path.split("/")
    for i, part in enumerate(parts):
        crumbs.append((part, "/".join(parts[: i + 1])))
    return crumbs


def get_dir_size(conn: sqlite3.Connection, rel_path: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM dir_sizes WHERE path = ?", (rel_path,)).fetchone()


def mark_calculating(conn: sqlite3.Connection, rel_path: str) -> None:
    conn.execute(
        "INSERT INTO dir_sizes (path, bytes, files, computed_at, state) VALUES (?, NULL, NULL, NULL, 'calculating') "
        "ON CONFLICT(path) DO UPDATE SET state = 'calculating'",
        (rel_path,),
    )


def store_size(conn: sqlite3.Connection, rel_path: str, total_bytes: int, files: int) -> None:
    conn.execute(
        "INSERT INTO dir_sizes (path, bytes, files, computed_at, state) VALUES (?, ?, ?, ?, 'done') "
        "ON CONFLICT(path) DO UPDATE SET bytes = excluded.bytes, files = excluded.files, "
        "computed_at = excluded.computed_at, state = 'done'",
        (rel_path, total_bytes, files, _now()),
    )


def compute_size(path: Path) -> tuple[int, int]:
    """Total bytes and file count under `path`, each inode counted once.

    Snapshots share unchanged files with the generation before them through hard links
    (`rsync --link-dest`, see snapshots.py); without deduplicating by (st_dev, st_ino), the same
    physical bytes would be added once for every snapshot that still references them. Symlinks
    are never followed, matching every other walk in this module.
    """
    seen: set[tuple[int, int]] = set()
    total = 0
    files = 0
    for dirpath, _dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            fpath = os.path.join(dirpath, name)
            try:
                st = os.lstat(fpath)
            except OSError:
                continue
            if not os.path.isfile(fpath) or os.path.islink(fpath):
                continue
            key = (st.st_dev, st.st_ino)
            if key in seen:
                continue
            seen.add(key)
            total += st.st_size
            files += 1
    return total, files


def run_compute(connect: Callable[[], sqlite3.Connection], root: Path, rel_path: str) -> None:
    """Resolve `rel_path` again (defence in depth: a task argument is a trust boundary of its
    own, whether it arrived through a thread or through Huey, which persists it to disk) and
    write its size into the cache. A path that no longer resolves is simply left uncached - the
    directory it named may have been removed since the recalculate button was pressed."""
    target = resolve_within_root(root, rel_path)
    if target is None:
        return
    total_bytes, files = compute_size(target)
    with closing(connect()) as conn:
        store_size(conn, rel_path, total_bytes, files)
