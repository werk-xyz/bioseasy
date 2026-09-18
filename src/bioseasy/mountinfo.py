# SPDX-License-Identifier: GPL-3.0-or-later
"""Where the backup root actually lives, read from /proc/self/mountinfo.

Pure parsing only: every function here takes the file's content as a string, never touches the
filesystem or shells out to `mount`/`df`, so it is fully testable with hand-written sample lines.
The storage page (app.py) is the only caller that actually reads /proc/self/mountinfo, and only
on Linux; everywhere else (macOS dev, a container runtime that hides it) this module reports
"unavailable" instead of guessing.

Format: man 5 proc, the mountinfo section. Each line looks like

    36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue

before the single " - " separator: mount ID, parent ID, major:minor, root (the bind-mounted
subtree within the filesystem), mount point, mount options, zero or more optional fields; after
it: filesystem type, mount source, superblock options. The optional fields before "-" are why a
line cannot be split on whitespace by fixed position.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

NFS_FSTYPES = {"nfs", "nfs4"}
SMB_FSTYPES = {"cifs", "smb3"}


@dataclass(frozen=True)
class Mount:
    mount_point: str
    fstype: str
    source: str
    root: str  # the root-within-source field (mountinfo's 4th field before " - ")


def _parse_line(line: str) -> Mount | None:
    left, sep, right = line.partition(" - ")
    if not sep:
        return None
    left_fields = left.split()
    right_fields = right.split()
    if len(left_fields) < 5 or len(right_fields) < 2:
        return None
    return Mount(
        mount_point=posixpath.normpath(left_fields[4]),
        fstype=right_fields[0],
        source=right_fields[1],
        root=left_fields[3],
    )


def find_mount(content: str, path: str) -> Mount | None:
    """The longest (most specific) mount point in `content` that covers `path`.

    "Covers" means the mount point is `path` itself or one of its parent directories - the same
    rule the kernel itself uses to resolve which mount a path belongs to. Returns None only when
    `content` has no line whose mount point is an ancestor of `path` at all, which should not
    happen for a real mountinfo (the root mount "/" always matches); a caller passing content that
    is not really mountinfo can still get None.
    """
    target = posixpath.normpath(path)
    best: Mount | None = None
    for line in content.splitlines():
        if not line.strip():
            continue
        mount = _parse_line(line)
        if mount is None:
            continue
        mp = mount.mount_point
        covers = target == mp or mp == "/" or target.startswith(mp.rstrip("/") + "/")
        if covers and (best is None or len(mp) > len(best.mount_point)):
            best = mount
    return best


def describe(mount: Mount) -> tuple[str, bool]:
    """Human-readable sentence for `mount`, plus whether it should render as a warning.

    The warning case is "no separate mount at all": the backup root sits on the same filesystem
    as the container root (mount point "/"), so a backup would land in the container's own
    writable layer and be lost on the next redeploy.

    Local disk vs. Docker volume/bind mount both show a block device as the mount source
    (mountinfo never names a volume by its Docker name), so they are told apart by the "root"
    field instead: "/" means the whole filesystem is mounted (a real, dedicated disk or
    partition), anything else means only a subdirectory of a larger host filesystem was bound in
    (a named volume or a bind mount), which is not on its own dedicated storage.
    """
    if mount.fstype in NFS_FSTYPES:
        return f"NFS share {mount.source}", False
    if mount.fstype in SMB_FSTYPES:
        return f"SMB share {mount.source}", False
    if mount.mount_point == "/":
        return f"Not a separate mount: inside the container filesystem ({mount.fstype})", True
    if mount.root == "/":
        return f"Local disk ({mount.fstype}, {mount.source})", False
    return f"Docker volume or bind mount on the host ({mount.fstype})", False


def backup_root_mount(content: str | None, path: str) -> tuple[str, bool] | None:
    """The full "where does the backup root live" sentence for the storage page.

    `content` is None (rather than an empty string) when /proc/self/mountinfo could not be read
    at all - not on Linux, or a runtime that hides it - which is the one case with no Mount to
    describe, so the caller shows "Mount details are only available on Linux" instead.
    """
    if content is None:
        return None
    mount = find_mount(content, path)
    if mount is None:
        return None
    return describe(mount)
