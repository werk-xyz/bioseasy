# SPDX-License-Identifier: GPL-3.0-or-later
"""Inventory, snapshot and password-check behaviour against a realistic Finder-format backup tree
(see tests/fixtures.py for the exact layout and its sources).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fixtures import DEFAULT_FILES, BackupFile, write_realistic_backup
from test_password_check import BACKUP_PASSWORD, write_encrypted_manifest

from bioseasy import password_check, snapshots
from bioseasy.engine.demo import DEMO_DEVICES
from bioseasy.inventory import read_backup

PHONE = DEMO_DEVICES[0]


# ---- inventory completeness against the realistic tree --------------------------------------


def test_finished_realistic_backup_is_complete(tmp_path):
    path = tmp_path / PHONE.udid
    write_realistic_backup(path, PHONE, encrypted=False, snapshot_state="finished")
    info = read_backup(path)
    assert info.complete, info.problems
    assert info.snapshot_state == "finished"
    assert info.device_name == PHONE.name


def test_partial_snapshot_state_is_reported_incomplete(tmp_path):
    path = tmp_path / PHONE.udid
    write_realistic_backup(path, PHONE, encrypted=False, snapshot_state="new")
    info = read_backup(path)
    assert not info.complete
    assert any("not 'finished'" in p for p in info.problems)


def test_missing_manifest_db_is_reported(tmp_path):
    path = tmp_path / PHONE.udid
    write_realistic_backup(path, PHONE, encrypted=False, write_manifest_db=False)
    info = read_backup(path)
    assert not info.complete
    assert "Manifest.db missing or empty" in info.problems


def test_missing_hashed_file_referenced_by_manifest_db_is_not_flagged(tmp_path):
    """Real finding, not a bug: `inventory.read_backup` (src/bioseasy/inventory.py) never opens
    Manifest.db's Files table at all -- it only checks that Manifest.db exists, is non-empty and
    (for unencrypted backups) starts with the SQLite header. A hashed payload file referenced by
    a Files row but missing from disk is therefore invisible to today's completeness check. This
    documents the actual behaviour rather than the behaviour that was assumed.
    """
    path = tmp_path / PHONE.udid
    backup = write_realistic_backup(path, PHONE, encrypted=False)
    victim = backup.files[0]
    hashed_path = backup.hashed_file_path(victim)
    assert hashed_path.is_file()
    hashed_path.unlink()

    info = read_backup(path)
    assert info.complete, info.problems  # current behaviour: the missing payload is not detected


# ---- snapshots against the realistic tree, across two generations ---------------------------


def test_realistic_backup_snapshot_is_byte_identical(tmp_path):
    root = tmp_path / "backups"
    live = root / PHONE.udid
    write_realistic_backup(live, PHONE, encrypted=False)

    snap = snapshots.take(root, PHONE.udid, datetime.now(UTC), hardlinks=True)

    for name in ("Info.plist", "Manifest.plist", "Status.plist", "Manifest.db"):
        assert (snap / name).read_bytes() == (live / name).read_bytes()
    for backup_file in DEFAULT_FILES:
        rel = f"{backup_file.file_id[:2]}/{backup_file.file_id}"
        assert (snap / rel).read_bytes() == (live / rel).read_bytes() == backup_file.content


def test_unchanged_realistic_files_are_hardlinked_across_two_generations(tmp_path):
    root = tmp_path / "backups"
    live = root / PHONE.udid
    write_realistic_backup(live, PHONE, encrypted=False)

    first = snapshots.take(root, PHONE.udid, datetime.now(UTC), hardlinks=True)
    # Nothing in the live directory changes between generations (a device that had nothing new).
    second = snapshots.take(root, PHONE.udid, datetime.now(UTC) + timedelta(seconds=1), hardlinks=True)

    for name in ("Info.plist", "Manifest.db"):
        first_stat = (first / name).stat()
        second_stat = (second / name).stat()
        live_stat = (live / name).stat()
        assert (first_stat.st_dev, first_stat.st_ino) == (second_stat.st_dev, second_stat.st_ino)
        assert (first_stat.st_dev, first_stat.st_ino) != (live_stat.st_dev, live_stat.st_ino)
    for backup_file in DEFAULT_FILES:
        rel = f"{backup_file.file_id[:2]}/{backup_file.file_id}"
        first_stat = (first / rel).stat()
        second_stat = (second / rel).stat()
        assert (first_stat.st_dev, first_stat.st_ino) == (second_stat.st_dev, second_stat.st_ino)


def test_changed_hashed_file_breaks_the_hardlink_in_the_new_generation(tmp_path):
    """A device that replaced one photo: rsync must re-copy only that hashed file, and the older
    snapshot must keep the old bytes under the same inode it always had."""
    root = tmp_path / "backups"
    live = root / PHONE.udid
    changed = BackupFile("CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.JPG", b"jpeg-bytes")
    write_realistic_backup(live, PHONE, encrypted=False, files=(changed,))

    first = snapshots.take(root, PHONE.udid, datetime.now(UTC), hardlinks=True)
    rel = f"{changed.file_id[:2]}/{changed.file_id}"
    (live / rel).write_bytes(b"a-new-photo-replaced-the-old-one")
    second = snapshots.take(root, PHONE.udid, datetime.now(UTC) + timedelta(seconds=1), hardlinks=True)

    assert (first / rel).read_bytes() == b"jpeg-bytes"
    assert (second / rel).read_bytes() == b"a-new-photo-replaced-the-old-one"
    first_stat = (first / rel).stat()
    second_stat = (second / rel).stat()
    assert (first_stat.st_dev, first_stat.st_ino) != (second_stat.st_dev, second_stat.st_ino)


# ---- password check against the realistic, encrypted tree -----------------------------------


def test_password_check_against_realistic_encrypted_backup(tmp_path):
    path = tmp_path / PHONE.udid
    write_realistic_backup(path, PHONE, encrypted=True)
    write_encrypted_manifest(path, BACKUP_PASSWORD)  # overwrites Manifest.plist with a real keybag

    result = password_check.check(path, BACKUP_PASSWORD)
    assert result.outcome == "correct"
    # The realistic Info/Status/Manifest.db shape around it is still intact and still inventories.
    info = read_backup(path)
    assert info.complete, info.problems
