# SPDX-License-Identifier: GPL-3.0-or-later
"""storage.check() against real filesystem conditions, not mocks: a volume with no hard-link
support, a mount point swapped out from under the backup root, and a root that is genuinely not
writable. Uses the real `storage.initialise`/`storage.check` functions as they are.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from datetime import UTC, datetime

import pytest

from bioseasy import snapshots, storage


def _hdiutil_available() -> bool:
    return shutil.which("hdiutil") is not None


requires_hdiutil = pytest.mark.skipif(
    not _hdiutil_available(), reason="hdiutil not available (macOS-only disk image tooling)"
)


@pytest.fixture
def fat_volume(tmp_path):
    """A small FAT16 disk image, mounted for the test and detached afterwards.

    FAT has no hard-link support at all, unlike APFS/ext4/most real backup targets -- exactly the
    case `storage.check`'s `hardlinks` field exists to report, and the case where `snapshots.take`
    must fall back to a plain copy (hardlinks=False) instead of --link-dest.
    """
    image = tmp_path / "fat.dmg"
    mount_point = tmp_path / "fatmnt"
    mount_point.mkdir()
    created = subprocess.run(  # noqa: S603
        ["hdiutil", "create", "-size", "16m", "-fs", "MS-DOS FAT16", "-volname", "BIOSEASYTEST", str(image)],  # noqa: S607
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip(f"hdiutil create failed in this environment: {created.stderr.strip()}")
    attached = subprocess.run(  # noqa: S603
        ["hdiutil", "attach", str(image), "-mountpoint", str(mount_point), "-nobrowse"],  # noqa: S607
        capture_output=True,
        text=True,
    )
    if attached.returncode != 0:
        pytest.skip(f"hdiutil attach failed in this environment: {attached.stderr.strip()}")
    try:
        yield mount_point
    finally:
        subprocess.run(["hdiutil", "detach", str(mount_point), "-force"], capture_output=True, text=True)  # noqa: S603, S607


@requires_hdiutil
def test_storage_check_reports_no_hardlink_support_on_a_real_fat_volume(fat_volume):
    root_id = storage.initialise(fat_volume)
    result = storage.check(fat_volume, root_id, 0)
    # FAT genuinely cannot hard-link; the probe (`os.link`) must have hit a real OSError, and the
    # check must still be otherwise usable (writable, marker present) rather than failing outright.
    assert result.hardlinks is False
    assert result.ok, result.problems


@requires_hdiutil
def test_snapshot_falls_back_to_a_plain_copy_when_the_real_volume_cannot_hardlink(fat_volume, monkeypatch):
    """The engine is expected to pass `hardlinks=storage_check.hardlinks` into snapshots.take();
    prove that path against a volume that genuinely cannot hard-link, not a fake or a monkeypatch
    of os.link."""
    udid = "00008110-FATVOLUMETEST01"
    live = fat_volume / udid
    live.mkdir()
    (live / "Info.plist").write_bytes(b"info-v1")

    root_id = storage.initialise(fat_volume)
    check = storage.check(fat_volume, root_id, 0)
    assert check.hardlinks is False

    snap = snapshots.take(fat_volume, udid, datetime.now(UTC), hardlinks=check.hardlinks)
    assert (snap / "Info.plist").read_bytes() == b"info-v1"


def test_marker_missing_after_the_mount_point_is_swapped_for_an_empty_directory(tmp_path):
    """The scenario storage.py's own module docstring names: the configured path still exists (an
    empty local directory took the mount point's place) but it is not the volume that was
    initialised, so the marker the backup root was stamped with is gone. Simulated by physically
    replacing the directory tree at the same path, not by deleting one file.
    """
    root = tmp_path / "backups"
    root.mkdir()
    root_id = storage.initialise(root)
    assert storage.check(root, root_id, 0).ok

    # Simulate an unmount: the real volume goes away and something else (or nothing but an empty
    # directory created by the OS/container) now sits at the same path.
    shutil.rmtree(root)
    root.mkdir()

    result = storage.check(root, root_id, 0)
    assert not result.ok
    assert "Marker file missing: is the volume mounted?" in result.problems


def test_marker_belongs_to_a_different_root_after_the_swap(tmp_path):
    """A variant of the same swap where the replacement directory *is* a bioseasy backup root --
    just a different one (e.g. the wrong disk got mounted at this path). The marker is present but
    stamped with someone else's id, which must be caught too."""
    root = tmp_path / "backups"
    root.mkdir()
    expected_id = storage.initialise(root)

    shutil.rmtree(root)
    root.mkdir()
    storage.initialise(root)  # a different, unrelated root now lives at the same path

    result = storage.check(root, expected_id, 0)
    assert not result.ok
    assert "Marker belongs to a different backup root" in result.problems


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores directory permissions, so a read-only root cannot be simulated (CI runs as root)",
)
def test_storage_check_reports_a_genuinely_read_only_root(tmp_path):
    """Real permissions, not a monkeypatched os.link/tempfile: chmod the root to read-only after
    initialising it, then let `storage.check`'s own write probe hit the real EACCES/EPERM."""
    root = tmp_path / "backups"
    root.mkdir()
    root_id = storage.initialise(root)
    assert storage.check(root, root_id, 0).ok

    # storage._probe_write_and_links() creates its tempfile inside root/.bioseasy, not root
    # itself (`work = root / MARKER.parent`), so that is the directory that actually has to be
    # locked down for the probe to hit a real permission error -- chmodding `root` alone leaves
    # the already-created, separately-permissioned `.bioseasy` subdirectory writable.
    work_dir = root / storage.MARKER.parent
    original_mode = work_dir.stat().st_mode
    os.chmod(work_dir, stat.S_IRUSR | stat.S_IXUSR)  # r-x for the owner: readable, not writable
    try:
        result = storage.check(root, root_id, 0)
        assert not result.ok
        assert "Backup root is not writable" in result.problems
    finally:
        # Restore write access so tmp_path's own cleanup can remove the directory afterwards.
        os.chmod(work_dir, original_mode)
