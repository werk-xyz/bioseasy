# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure logic behind the storage browse view (src/bioseasy/browse.py): path resolution against
the backup root, and the hard-link-aware size computation the background task uses.
"""

import os

import pytest

from bioseasy import browse


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "backups"
    r.mkdir()
    (r / "DEV1").mkdir()
    (r / "DEV1" / "Manifest.db").write_bytes(b"x" * 10)
    return r


def test_resolve_root_itself(root):
    assert browse.resolve_within_root(root, "") == root.resolve()
    assert browse.resolve_within_root(root, None) == root.resolve()


def test_resolve_a_real_subdirectory(root):
    assert browse.resolve_within_root(root, "DEV1") == (root / "DEV1").resolve()


@pytest.mark.parametrize(
    "bad",
    ["..", "../etc", "DEV1/../..", "/etc", "/etc/passwd", "DEV1/../../etc"],
)
def test_traversal_attempts_are_rejected(root, bad):
    assert browse.resolve_within_root(root, bad) is None


def test_nonexistent_path_is_rejected(root):
    assert browse.resolve_within_root(root, "does-not-exist") is None


def test_a_file_is_rejected_not_a_directory(root):
    assert browse.resolve_within_root(root, "DEV1/Manifest.db") is None


def test_symlinked_directory_itself_is_rejected(root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "evil").symlink_to(outside)
    assert browse.resolve_within_root(root, "evil") is None


def test_symlink_partway_through_the_path_is_rejected(root, tmp_path):
    outside = tmp_path / "outside"
    (outside / "sub").mkdir(parents=True)
    (root / "link").symlink_to(outside)
    # Even though "link/sub" would resolve back outside cleanly, the symlink in the middle must
    # reject the whole path, not just a final-resolution check.
    assert browse.resolve_within_root(root, "link/sub") is None


def test_null_byte_is_rejected(root):
    assert browse.resolve_within_root(root, "DEV1\x00/etc") is None


def test_compute_size_counts_each_hard_linked_inode_once(root):
    live = root / "DEV1"
    os.link(live / "Manifest.db", live / "Manifest-copy.db")
    (live / "unique.bin").write_bytes(b"y" * 20)
    total_bytes, files = browse.compute_size(live)
    # 10 bytes shared by the hard-linked pair (counted once) + 20 bytes unique = 30.
    assert total_bytes == 30
    assert files == 2


def test_compute_size_does_not_follow_symlinks(root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "big.bin").write_bytes(b"z" * 1000)
    (root / "DEV1" / "escape").symlink_to(outside)
    total_bytes, _files = browse.compute_size(root / "DEV1")
    assert total_bytes == 10  # only Manifest.db; the symlinked directory is never descended into


def test_breadcrumbs_from_root_to_a_nested_path():
    assert browse.breadcrumbs("") == [("backups", "")]
    assert browse.breadcrumbs("DEV1/snapshots/20260101T000000Z") == [
        ("backups", ""),
        ("DEV1", "DEV1"),
        ("snapshots", "DEV1/snapshots"),
        ("20260101T000000Z", "DEV1/snapshots/20260101T000000Z"),
    ]


def test_list_directory_sorts_directories_first_then_by_name(root):
    (root / "DEV1" / "b_file.txt").write_bytes(b"1")
    (root / "DEV1" / "a_dir").mkdir()
    (root / "DEV1" / "z_dir").mkdir()
    entries = browse.list_directory(root / "DEV1", "DEV1")
    names = [e.name for e in entries]
    assert names == ["a_dir", "z_dir", "b_file.txt", "Manifest.db"]
    assert all(e.is_dir for e in entries[:2])
    assert not any(e.is_dir for e in entries[2:])


def test_list_directory_gives_a_symlinked_entry_no_item_count(root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "inner").mkdir()
    (root / "DEV1" / "link_dir").symlink_to(outside)
    entries = {e.name: e for e in browse.list_directory(root / "DEV1", "DEV1")}
    assert entries["link_dir"].item_count is None
