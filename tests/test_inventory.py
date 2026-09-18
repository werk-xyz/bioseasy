# SPDX-License-Identifier: GPL-3.0-or-later
import plistlib

from bioseasy.engine.demo import DEMO_DEVICES, write_backup
from bioseasy.inventory import read_backup, scan

PHONE = DEMO_DEVICES[0]


def test_finished_backup_is_complete(tmp_path):
    write_backup(tmp_path / PHONE.udid, PHONE, encrypted=False)
    info = read_backup(tmp_path / PHONE.udid)
    assert info.complete, info.problems
    assert info.device_name == "Demo iPhone"
    assert info.os_version == "18.6"
    assert info.encrypted is False
    assert info.last_backup is not None and info.last_backup.tzinfo is not None
    assert info.size_bytes > 0


def test_unfinished_snapshot_is_reported(tmp_path):
    write_backup(tmp_path / PHONE.udid, PHONE, state="new")
    info = read_backup(tmp_path / PHONE.udid)
    assert not info.complete
    assert any("not 'finished'" in p for p in info.problems)


def test_missing_and_corrupt_files_are_reported(tmp_path):
    path = tmp_path / PHONE.udid
    write_backup(path, PHONE, encrypted=False)
    (path / "Status.plist").unlink()
    (path / "Manifest.db").write_bytes(b"not a database at all")
    info = read_backup(path)
    assert "Status.plist missing" in info.problems
    assert "Manifest.db is not an SQLite database" in info.problems


def test_directory_must_match_udid(tmp_path):
    write_backup(tmp_path / "wrong-name", PHONE)
    assert any("does not match" in p for p in read_backup(tmp_path / "wrong-name").problems)


def test_scan_ignores_unrelated_directories(tmp_path):
    write_backup(tmp_path / PHONE.udid, PHONE)
    (tmp_path / "Photos").mkdir()
    (tmp_path / "junk.plist").write_bytes(plistlib.dumps({}))
    assert [b.udid for b in scan(tmp_path)] == [PHONE.udid]
    assert scan(tmp_path / "does-not-exist") == []
