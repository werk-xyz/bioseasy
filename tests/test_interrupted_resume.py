# SPDX-License-Identifier: GPL-3.0-or-later
"""Interrupted and resumed runs, simulating the engine writing into the live backup directory
while an earlier snapshot exists.

This is the scenario snapshots.py's own module docstring gives as the reason snapshots are only
ever `--link-dest`ed against an older *snapshot*, never against the live directory: the real
engine rewrites live files with `open(path, "wb")`, which truncates in place. If a snapshot's
files were hard-linked to the live directory instead of to the previous snapshot, that truncation
would corrupt the "old" generation too, mid-restore. These tests reproduce that write pattern
directly against the real filesystem (real rsync via snapshots.take, real inodes) rather than
asserting it from the module docstring.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fixtures import DEFAULT_FILES, BackupFile, write_realistic_backup

from bioseasy import snapshots
from bioseasy.engine.demo import DEMO_DEVICES

PHONE = DEMO_DEVICES[0]


def test_truncating_rewrite_of_a_live_file_does_not_reach_the_older_snapshot(tmp_path):
    """The engine's real write pattern: open(path, "wb") on an existing live file, which
    truncates it in place before writing new bytes -- the exact hazard link-dest-against-live
    would expose."""
    root = tmp_path / "backups"
    live = root / PHONE.udid
    changed = BackupFile("HomeDomain", "Library/SMS/sms.db", b"sms-generation-one")
    write_realistic_backup(live, PHONE, encrypted=False, files=(changed,))
    rel = f"{changed.file_id[:2]}/{changed.file_id}"

    older = snapshots.take(root, PHONE.udid, datetime.now(UTC), hardlinks=True)
    older_stat_before = (older / rel).stat()

    # Simulate the engine mid-transfer: truncate-and-rewrite the live file in place, exactly like
    # a real incoming backup stream would (quoted in snapshots.py).
    with (live / rel).open("wb") as fh:
        fh.write(b"partial-bytes-still-arri")  # the write is interrupted before it completes

    assert (older / rel).read_bytes() == b"sms-generation-one"
    older_stat_after = (older / rel).stat()
    assert (older_stat_before.st_dev, older_stat_before.st_ino) == (older_stat_after.st_dev, older_stat_after.st_ino)
    assert (older / rel).stat().st_size == len(b"sms-generation-one")


def test_snapshot_taken_after_an_interrupted_write_captures_the_partial_state_only_in_the_new_generation(tmp_path):
    """A snapshot taken right after the simulated interruption reflects the partial live state,
    while every earlier generation stays exactly as it was."""
    root = tmp_path / "backups"
    live = root / PHONE.udid
    changed = BackupFile("HomeDomain", "Library/SMS/sms.db", b"sms-generation-one")
    write_realistic_backup(live, PHONE, encrypted=False, files=(changed,))
    rel = f"{changed.file_id[:2]}/{changed.file_id}"

    older = snapshots.take(root, PHONE.udid, datetime.now(UTC), hardlinks=True)

    partial_bytes = b"half-written-interrupted-transfer"
    with (live / rel).open("wb") as fh:
        fh.write(partial_bytes)

    newer = snapshots.take(root, PHONE.udid, datetime.now(UTC) + timedelta(seconds=1), hardlinks=True)

    assert (older / rel).read_bytes() == b"sms-generation-one"
    assert (newer / rel).read_bytes() == partial_bytes
    assert (live / rel).read_bytes() == partial_bytes


def test_unchanged_files_around_the_interrupted_one_are_still_hardlinked_forward(tmp_path):
    """Only the actively-rewritten file breaks its hardlink; every other file in the same backup
    (unaffected by the interrupted transfer) still shares its inode with the previous generation,
    confirming rsync's --link-dest does its normal per-file job around the hazard."""
    root = tmp_path / "backups"
    live = root / PHONE.udid
    write_realistic_backup(live, PHONE, encrypted=False, files=DEFAULT_FILES)
    changed_rel = f"{DEFAULT_FILES[0].file_id[:2]}/{DEFAULT_FILES[0].file_id}"

    older = snapshots.take(root, PHONE.udid, datetime.now(UTC), hardlinks=True)
    with (live / changed_rel).open("wb") as fh:
        fh.write(b"only-this-one-file-changed")
    newer = snapshots.take(root, PHONE.udid, datetime.now(UTC) + timedelta(seconds=1), hardlinks=True)

    changed_before = (older / changed_rel).stat()
    changed_after = (newer / changed_rel).stat()
    assert (changed_before.st_dev, changed_before.st_ino) != (changed_after.st_dev, changed_after.st_ino)

    for backup_file in DEFAULT_FILES[1:]:
        rel = f"{backup_file.file_id[:2]}/{backup_file.file_id}"
        older_stat = (older / rel).stat()
        newer_stat = (newer / rel).stat()
        assert (older_stat.st_dev, older_stat.st_ino) == (newer_stat.st_dev, newer_stat.st_ino)
