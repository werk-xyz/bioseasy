# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure parsing of /proc/self/mountinfo for the storage page (src/bioseasy/mountinfo.py).

Sample lines are hand-written in the real mountinfo format (man 5 proc), not captured from a
live system - none of the environments this suite runs in has an NFS or SMB mount to read.
"""

from bioseasy import mountinfo

ROOT_OVERLAY = "123 456 0:78 / / rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b,workdir=/c"


def test_nfs_mount_renders_as_nfs_share():
    content = "\n".join(
        [
            ROOT_OVERLAY,
            "125 456 0:45 / /backups rw,relatime shared:100 - nfs4 nas:/export/backups rw,vers=4.2",
        ]
    )
    mount = mountinfo.find_mount(content, "/backups")
    assert mount is not None
    assert mountinfo.describe(mount) == ("NFS share nas:/export/backups", False)


def test_cifs_mount_renders_as_smb_share():
    content = "\n".join(
        [
            ROOT_OVERLAY,
            "126 456 0:46 / /backups rw,relatime - smb3 //nas/backups rw,vers=3.1.1",
        ]
    )
    mount = mountinfo.find_mount(content, "/backups")
    assert mount is not None
    assert mountinfo.describe(mount) == ("SMB share //nas/backups", False)


def test_whole_block_device_renders_as_local_disk():
    content = "\n".join(
        [
            ROOT_OVERLAY,
            "127 456 8:1 / /backups rw,relatime - ext4 /dev/sda1 rw",
        ]
    )
    mount = mountinfo.find_mount(content, "/backups")
    assert mount is not None
    assert mountinfo.describe(mount) == ("Local disk (ext4, /dev/sda1)", False)


def test_bind_mount_of_a_host_subdirectory_renders_as_docker_volume_or_bind_mount():
    content = "\n".join(
        [
            ROOT_OVERLAY,
            "128 456 8:1 /var/lib/docker/volumes/bioseasy_backups/_data /backups rw,relatime - ext4 /dev/sda1 rw",
        ]
    )
    mount = mountinfo.find_mount(content, "/backups")
    assert mount is not None
    assert mountinfo.describe(mount) == ("Docker volume or bind mount on the host (ext4)", False)


def test_no_separate_mount_renders_as_a_warning():
    # /backups has no entry of its own; the longest match is the overlay root "/" itself.
    mount = mountinfo.find_mount(ROOT_OVERLAY, "/backups")
    assert mount is not None
    assert mount.mount_point == "/"
    assert mountinfo.describe(mount) == (
        "Not a separate mount: inside the container filesystem (overlay)",
        True,
    )


def test_longest_matching_mount_point_wins_over_a_shorter_ancestor():
    # /backups is its own ext4 mount nested under /data, which is itself a separate mount; the
    # more specific one must be picked, not the shallower ancestor.
    content = "\n".join(
        [
            ROOT_OVERLAY,
            "129 456 8:2 / /data rw,relatime - ext4 /dev/sdb1 rw",
            "130 456 8:1 / /data/backups rw,relatime - ext4 /dev/sda1 rw",
        ]
    )
    mount = mountinfo.find_mount(content, "/data/backups")
    assert mount is not None
    assert mount.source == "/dev/sda1"


def test_content_none_means_mount_details_unavailable():
    assert mountinfo.backup_root_mount(None, "/backups") is None


def test_backup_root_mount_combines_find_and_describe():
    content = "\n".join(
        [
            ROOT_OVERLAY,
            "125 456 0:45 / /backups rw,relatime - nfs nas:/export/backups rw",
        ]
    )
    assert mountinfo.backup_root_mount(content, "/backups") == ("NFS share nas:/export/backups", False)
