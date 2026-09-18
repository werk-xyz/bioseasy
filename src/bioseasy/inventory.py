# SPDX-License-Identifier: GPL-3.0-or-later
"""Read an iTunes/Finder-format backup directory without the backup password.

A backup directory is named after the device UDID and holds Info.plist, Manifest.plist,
Status.plist and Manifest.db. The completeness rule mirrors libimobiledevice's own check in
tools/idevicebackup2.c (mb2_status_check_snapshot_state): Status.plist SnapshotState must be
"finished".
"""

from __future__ import annotations

import plistlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

SQLITE_HEADER = b"SQLite format 3\x00"


@dataclass(frozen=True)
class BackupInfo:
    path: Path
    udid: str
    device_name: str | None = None
    product_type: str | None = None
    os_version: str | None = None
    serial: str | None = None
    encrypted: bool | None = None
    is_full: bool | None = None
    snapshot_state: str | None = None
    last_backup: datetime | None = None
    size_bytes: int = 0
    problems: tuple[str, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        return not self.problems


def _load_plist(path: Path, problems: list[str]) -> dict | None:
    if not path.is_file():
        problems.append(f"{path.name} missing")
        return None
    try:
        with path.open("rb") as fh:
            data = plistlib.load(fh)
    except (plistlib.InvalidFileException, ValueError, OSError) as exc:
        problems.append(f"{path.name} unreadable: {exc.__class__.__name__}")
        return None
    if not isinstance(data, dict):
        problems.append(f"{path.name} has no dictionary at its root")
        return None
    return data


def _as_utc(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    # plistlib returns naive datetimes that are UTC by definition of the plist format.
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _dir_size(path: Path) -> int:
    total = 0
    for entry in path.rglob("*"):
        try:
            if entry.is_file() and not entry.is_symlink():
                total += entry.stat().st_size
        except OSError:
            continue
    return total


def read_backup(path: Path, *, with_size: bool = True) -> BackupInfo:
    problems: list[str] = []
    info = _load_plist(path / "Info.plist", problems) or {}
    manifest = _load_plist(path / "Manifest.plist", problems) or {}
    status = _load_plist(path / "Status.plist", problems) or {}

    state = status.get("SnapshotState")
    if status and state != "finished":
        problems.append(f"snapshot state is {state!r}, not 'finished'")

    encrypted = manifest.get("IsEncrypted") if manifest else None
    db = path / "Manifest.db"
    if not db.is_file() or db.stat().st_size == 0:
        problems.append("Manifest.db missing or empty")
    elif encrypted is False:
        # Only the unencrypted case is checked for the SQLite header; for encrypted backups the
        # header check is left out because we cannot confirm the file layout without the key.
        with db.open("rb") as fh:
            if fh.read(len(SQLITE_HEADER)) != SQLITE_HEADER:
                problems.append("Manifest.db is not an SQLite database")

    udid = info.get("Unique Identifier") or info.get("Target Identifier") or path.name
    if udid.lower() != path.name.lower():
        problems.append(f"directory name {path.name} does not match device UDID {udid}")

    return BackupInfo(
        path=path,
        udid=udid,
        device_name=info.get("Device Name") or info.get("Display Name"),
        product_type=info.get("Product Type"),
        os_version=info.get("Product Version"),
        serial=info.get("Serial Number"),
        encrypted=encrypted if isinstance(encrypted, bool) else None,
        is_full=status.get("IsFullBackup") if isinstance(status.get("IsFullBackup"), bool) else None,
        snapshot_state=state,
        last_backup=_as_utc(status.get("Date")) or _as_utc(info.get("Last Backup Date")),
        size_bytes=_dir_size(path) if with_size else 0,
        problems=tuple(problems),
    )


def scan(root: Path, *, with_size: bool = True) -> list[BackupInfo]:
    """Every direct subdirectory that looks like a backup (has any of the three plists)."""
    if not root.is_dir():
        return []
    found = []
    for child in sorted(root.iterdir()):
        if child.is_dir() and any((child / n).exists() for n in ("Info.plist", "Manifest.plist", "Status.plist")):
            found.append(read_backup(child, with_size=with_size))
    return found
